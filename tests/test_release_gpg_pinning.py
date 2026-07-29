from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from distroforge.cli import build_parser, main
from distroforge.core.command import CommandResult, CommandSpec
from distroforge.core.hashing import sha256_file
from distroforge.core.project import Project
from distroforge.core.release_signing import (
    SIGNING_KEYRING,
    full_fingerprint,
    sign_release_bundle,
    validsig_fingerprints,
    verify_detached_signature,
)
from distroforge.core.release_verification import (
    _verify_gate,
    _verify_signatures,
    verify_release_bundle,
)

FINGERPRINT = "4248DCA20A9407BBFA31818518BC560A874C3C7F"
OTHER_FINGERPRINT = "0000000000000000000000000000000000000000"


def test_release_verification_propagates_a_blocked_gate() -> None:
    items = []

    _verify_gate(
        {
            "status": "blocked",
            "blocked": True,
            "items": [
                {
                    "code": "package-inputs",
                    "status": "blocked",
                    "detail": "filesystem causality is unverified",
                }
            ],
        },
        {"gate_status": "blocked"},
        items,
    )

    assert len(items) == 1
    assert items[0].code == "gate-status"
    assert items[0].status == "blocked"


def test_release_verification_rejects_a_false_ready_gate_aggregate() -> None:
    items = []

    _verify_gate(
        {
            "status": "ready",
            "blocked": False,
            "items": [
                {
                    "code": "package-inputs",
                    "status": "blocked",
                    "detail": "not closed",
                }
            ],
        },
        {"gate_status": "ready"},
        items,
    )

    assert len(items) == 1
    assert items[0].status == "blocked"
    assert "contradicts" in items[0].detail


def _ready_bundle(tmp_path: Path, name: str = "Pinned") -> tuple[Project, Path]:
    project = Project.create(name, tmp_path / name.lower(), "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    iso = bundle / f"{name}-26.04.iso"
    iso.write_bytes(b"iso")
    (bundle / "SHA256SUMS").write_text(
        f"{sha256_file(iso)}  {iso.name}\n",
        encoding="utf-8",
    )
    (bundle / "RELEASE-GATE.json").write_text(
        '{"status":"ready","items":[]}\n',
        encoding="utf-8",
    )
    return project, bundle


def test_executed_signing_without_a_complete_fingerprint_is_blocked(tmp_path: Path) -> None:
    project, bundle = _ready_bundle(tmp_path)

    report = sign_release_bundle(project, bundle_dir=bundle, execute=True)

    assert report.status == "blocked"
    assert any("complete OpenPGP signer fingerprint" in item for item in report.skipped)
    assert not list(bundle.glob("*.asc"))


def test_executed_signing_without_an_explicit_public_keyring_is_blocked(
    tmp_path: Path,
) -> None:
    project, bundle = _ready_bundle(tmp_path)

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
    )

    assert report.status == "blocked"
    assert any("explicit filtered public GPG keyring" in item for item in report.skipped)
    assert not list(bundle.glob("*.asc"))


def test_signing_plan_does_not_probe_or_copy_key_material(tmp_path: Path) -> None:
    project, bundle = _ready_bundle(tmp_path)
    missing_keyring = tmp_path / "not-present.gpg"

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=False,
        gpg_key=FINGERPRINT,
        gpg_keyring=missing_keyring,
    )

    assert report.status == "planned"
    assert report.signer_fingerprint == FINGERPRINT
    assert report.verification_keyring is None
    assert not (bundle / SIGNING_KEYRING).exists()


def test_short_key_ids_are_not_release_fingerprints() -> None:
    assert full_fingerprint(FINGERPRINT) == FINGERPRINT
    assert full_fingerprint(f"0x{FINGERPRINT.lower()}") == FINGERPRINT
    assert full_fingerprint(FINGERPRINT[-16:]) is None


def test_release_cli_exposes_external_fingerprint_and_keyring_inputs(
    tmp_path: Path,
) -> None:
    parser = build_parser()
    keyring = tmp_path / "filtered.gpg"
    sign = parser.parse_args(
        [
            "sign-release",
            str(tmp_path),
            "--gpg-key",
            FINGERPRINT,
            "--gpg-keyring",
            str(keyring),
            "--execute",
        ]
    )
    verify = parser.parse_args(
        [
            "verify-release",
            str(tmp_path),
            "--gpg-fingerprint",
            FINGERPRINT,
        ]
    )

    assert sign.gpg_key == FINGERPRINT
    assert sign.gpg_keyring == keyring
    assert verify.gpg_fingerprint == FINGERPRINT


def test_executed_release_cli_propagates_blocked_sign_and_verify_status(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = Project.create("BlockedCli", tmp_path / "blocked-cli", "26.04")

    with pytest.raises(SystemExit) as sign_exit:
        main(
            [
                "sign-release",
                str(project.root),
                "--execute",
                "--json",
            ]
        )
    assert sign_exit.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"

    with pytest.raises(SystemExit) as verify_exit:
        main(["verify-release", str(project.root), "--json"])
    assert verify_exit.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


def test_validsig_parser_records_signing_and_primary_fingerprints() -> None:
    signing_subkey = "1111111111111111111111111111111111111111"
    status = (
        "[GNUPG:] VALIDSIG "
        f"{signing_subkey} 2026-07-29 1785300000 0 4 0 22 10 00 {FINGERPRINT}\n"
    )

    assert validsig_fingerprints(status) == (signing_subkey, FINGERPRINT)


class _StatusRunner:
    def __init__(self, stdout: str, returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.history: list[CommandSpec] = []

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        return CommandResult(spec, self.returncode, self.stdout, "")


def test_rc_zero_without_validsig_is_never_accepted(tmp_path: Path) -> None:
    keyring = tmp_path / "trusted.gpg"
    keyring.write_bytes(b"not inspected by the fake runner")
    signature = tmp_path / "payload.asc"
    signature.write_text("signature\n", encoding="utf-8")
    payload = tmp_path / "payload"
    payload.write_text("payload\n", encoding="utf-8")
    runner = _StatusRunner("[GNUPG:] GOODSIG 1234 signer\n")

    with pytest.raises(ValueError, match="no VALIDSIG"):
        verify_detached_signature(  # type: ignore[arg-type]
            runner,
            signature,
            payload,
            keyring,
            FINGERPRINT,
        )

    argv = runner.history[0].argv
    assert "--no-options" in argv
    assert "--no-default-keyring" in argv
    assert "--no-auto-key-retrieve" in argv
    assert "--status-fd" in argv


def test_release_verification_rejects_a_symlinked_signature(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    outside = tmp_path / "outside.asc"
    outside.write_text("not bundle evidence\n", encoding="utf-8")
    (bundle / "SHA256SUMS.asc").symlink_to(outside)
    items = []

    _verify_signatures(
        bundle,
        {"planned": ["SHA256SUMS.asc"]},
        items,
        FINGERPRINT,
    )

    assert any(item.code == "signature-path" and item.status == "blocked" for item in items)


def test_release_verification_rejects_a_forged_partial_signed_report(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "partial"
    bundle.mkdir()
    (bundle / "SHA256SUMS").write_text("payload\n", encoding="utf-8")
    (bundle / "SHA256SUMS.asc").write_text("signature\n", encoding="utf-8")
    items = []

    _verify_signatures(
        bundle,
        {
            "status": "signed",
            "execute": True,
            "signed": ["SHA256SUMS.asc"],
            "planned": [],
            "skipped": [],
        },
        items,
        FINGERPRINT,
    )

    assert any(
        item.code == "signature-contract" and item.status == "blocked"
        for item in items
    )


gpg_binary = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is not installed")


@pytest.fixture
def release_signers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[str, str, Path, Path]:
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("GNUPGHOME", str(home))
    base = ("gpg", "--batch", "--quiet", "--passphrase", "")
    identities = (
        "DistroForge Probe A <probe@distroforge.invalid>",
        "DistroForge Probe B <probe@distroforge.invalid>",
    )
    fingerprints: list[str] = []
    keyrings: list[Path] = []
    for identity in identities:
        subprocess.run(
            (
                *base,
                "--quick-generate-key",
                identity,
                "ed25519",
                "sign",
                "never",
            ),
            check=True,
            capture_output=True,
        )
        listing = subprocess.run(
            ("gpg", "--batch", "--with-colons", "--fingerprint", "--list-keys", identity),
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        fingerprints.append(
            next(
                line.split(":")[9]
                for line in listing.splitlines()
                if line.startswith("fpr:")
            )
        )
        keyring = tmp_path / f"signer-{len(keyrings) + 1}.gpg"
        subprocess.run(
            (
                "gpg",
                "--batch",
                "--output",
                str(keyring),
                "--export-options",
                "export-minimal",
                "--export",
                fingerprints[-1],
            ),
            check=True,
            capture_output=True,
        )
        keyrings.append(keyring)
    return fingerprints[0], fingerprints[1], keyrings[0], keyrings[1]


@gpg_binary
def test_release_verification_accepts_only_the_externally_pinned_signer(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, other_valid_signer, signer_keyring, _ = release_signers
    project, bundle = _ready_bundle(tmp_path, "RealPinned")
    signing = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=signer_keyring,
    )

    assert signing.status == "signed"
    assert signing.signer_fingerprint == signer
    assert signing.verification_keyring == SIGNING_KEYRING
    assert signing.verification_keyring_sha256 == sha256_file(
        bundle / SIGNING_KEYRING
    )
    manifest = json.loads(
        (bundle / "RELEASE-MANIFEST.json").read_text(encoding="utf-8")
    )
    keyring_entry = next(
        entry for entry in manifest["files"] if entry["name"] == SIGNING_KEYRING
    )
    assert keyring_entry["sha256"] == signing.verification_keyring_sha256
    accepted = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_signer_fingerprint=signer,
    )
    assert all(
        item.status == "ready"
        for item in accepted.items
        if item.code in {"signature", "signature-fingerprint", "signature-keyring"}
    )
    assert any(
        item.code == "signature" and "VALIDSIG" in item.detail
        for item in accepted.items
    )

    # Simulate an attacker replacing the unsigned operational report so that it names
    # another perfectly valid key. The externally supplied pin still controls trust,
    # and the cryptographic VALIDSIG from the real signature does not match it.
    report_path = bundle / "SIGNING-REPORT.json"
    tampered = json.loads(report_path.read_text(encoding="utf-8"))
    tampered["signer_fingerprint"] = other_valid_signer
    report_path.write_text(json.dumps(tampered), encoding="utf-8")
    rejected = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_signer_fingerprint=other_valid_signer,
    )
    assert any(
        item.code == "signature"
        and item.status == "blocked"
        and "not" in item.detail
        for item in rejected.items
    )


@gpg_binary
def test_release_verification_blocks_when_external_fingerprint_is_absent(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, _, signer_keyring, _ = release_signers
    project, bundle = _ready_bundle(tmp_path, "MissingPin")
    signing = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=signer_keyring,
    )
    assert signing.status == "signed"

    report = verify_release_bundle(project, bundle_dir=bundle)

    assert any(
        item.code == "signature-fingerprint" and item.status == "blocked"
        for item in report.items
    )


@gpg_binary
def test_signing_rejects_a_public_keyring_for_another_valid_key(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, _, _, other_keyring = release_signers
    project, bundle = _ready_bundle(tmp_path, "WrongKeyring")

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=other_keyring,
    )

    assert report.status == "blocked"
    assert any(
        "must contain only the pinned primary key" in item
        for item in report.skipped
    )
    assert not list(bundle.glob("*.asc"))


@gpg_binary
def test_verification_rejects_a_keyring_whose_digest_changed(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, _, signer_keyring, _ = release_signers
    project, bundle = _ready_bundle(tmp_path, "ChangedKeyring")
    signing = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=signer_keyring,
    )
    assert signing.status == "signed"
    with (bundle / SIGNING_KEYRING).open("ab") as handle:
        handle.write(b"tampered")

    report = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_signer_fingerprint=signer,
    )

    assert any(
        item.code == "signature-keyring" and item.status == "blocked"
        for item in report.items
    )
