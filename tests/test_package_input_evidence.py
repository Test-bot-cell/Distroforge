from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from distroforge.core.bootstrap import BootstrapOptions, BootstrapService
from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.package_evidence import (
    PACKAGE_INPUTS_SCHEMA,
    PACKAGE_TRANSACTION_SCHEMA,
    PackageEvidenceService,
    PackageEvidenceValidation,
    PackageSourcePolicy,
    _capture_hook_config,
    _capture_hook_script,
    _inside_root,
    _packages_records,
    _stable_digest,
    package_apt_command_argv_sha256,
    package_source_policy_sha256,
    validate_package_evidence_payload,
)
from distroforge.core.project import Project
from distroforge.core.release_gate import _command_argv_ledger

FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
BUILD_TIME = "2026-07-29T12:00:00+00:00"
SAFE_APT_COMMANDS = (("apt-get", "update"),)


def test_release_gate_apt_ledger_uses_the_complete_final_command_log(
    tmp_path: Path,
) -> None:
    command_log = tmp_path / "commands.jsonl"
    events = (
        {"event": "start", "argv": ["mmdebstrap", "proof"]},
        {"event": "finish", "argv": ["mmdebstrap", "proof"], "returncode": 0},
        {"event": "start", "argv": ["xorriso", "-as", "mkisofs"]},
        {"event": "start", "argv": ["apt-get", "install", "late-package"]},
    )
    command_log.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    assert _command_argv_ledger(command_log) == (
        ("mmdebstrap", "proof"),
        ("xorriso", "-as", "mkisofs"),
        ("apt-get", "install", "late-package"),
    )


def test_release_gate_apt_ledger_rejects_malformed_or_symlinked_logs(
    tmp_path: Path,
) -> None:
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_text('{"event":"start","argv":[]}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="malformed argv"):
        _command_argv_ledger(malformed)

    target = tmp_path / "target.jsonl"
    target.write_text('{"event":"start","argv":["apt-get","update"]}\n', encoding="utf-8")
    linked = tmp_path / "linked.jsonl"
    linked.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        _command_argv_ledger(linked)


def _identity(path: Path, run_dir: Path, **extra: object) -> dict[str, object]:
    digest, size = _stable_digest(path)
    return {
        "path": str(path.relative_to(run_dir)),
        "size": size,
        "sha256": digest,
        **extra,
    }


def _capture_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    index_targets: str = "",
    archive_keyring: Path | None = None,
    archive_keyring_sha256: str | None = None,
) -> tuple[PackageEvidenceService, Project]:
    project = Project.create("Confinement", tmp_path / "project", "26.04")
    project.squashfs_root.mkdir(parents=True)
    runner = CommandRunner(dry_run=False)

    def fake_run(spec: CommandSpec, check: bool = True) -> CommandResult:
        del check
        argv = spec.argv
        if "apt-config" in argv:
            stdout = (
                "lists='/var/lib/apt/lists'\n"
                "archives='/var/cache/apt/archives'\n"
            )
        elif "indextargets" in argv:
            stdout = index_targets
        else:
            stdout = ""
        return CommandResult(
            spec=spec,
            returncode=0,
            stdout=stdout,
            stderr="",
        )

    monkeypatch.setattr(runner, "run", fake_run)
    service = PackageEvidenceService(
        runner,
        project,
        project.squashfs_root,
        {
            "run_id": "confinement-run",
            "mode": "execute",
            "created_at": BUILD_TIME,
        },
        use_sudo=False,
        archive_keyring=archive_keyring,
        archive_keyring_sha256=archive_keyring_sha256,
    )
    return service, project


def _assert_bytes_absent(root: Path, forbidden: bytes) -> None:
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            assert forbidden not in path.read_bytes()


def _minimal_deb(tmp_path: Path) -> tuple[Path, str, int]:
    tree = tmp_path / "deb-tree"
    (tree / "DEBIAN").mkdir(parents=True)
    (tree / "DEBIAN/control").write_text(
        "\n".join(
            [
                "Package: proof-package",
                "Version: 1.2.3-1",
                "Architecture: all",
                "Maintainer: DistroForge <github@distroforge.anonaddy.com>",
                "Description: package-input evidence fixture",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tree / "usr/share/proof").mkdir(parents=True)
    (tree / "usr/share/proof/payload").write_bytes(b"installed bytes\n")
    deb = tmp_path / "proof-package_1.2.3-1_all.deb"
    subprocess.run(
        ("dpkg-deb", "--build", str(tree), str(deb)),
        check=True,
        capture_output=True,
        text=True,
    )
    digest, size = _stable_digest(deb)
    return deb, digest, size


def _valid_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, object], Path, Path, str]:
    run_dir = tmp_path / "run"
    blobs = run_dir / "apt/blobs"
    for kind in ("source", "keyring", "release", "index", "deb"):
        (blobs / kind).mkdir(parents=True, exist_ok=True)

    built_deb, deb_sha, deb_size = _minimal_deb(tmp_path)
    sealed_deb = blobs / "deb" / f"{deb_sha}.deb"
    sealed_deb.write_bytes(built_deb.read_bytes())
    packages_text = "\n".join(
        [
            "Package: proof-package",
            "Version: 1.2.3-1",
            "Architecture: all",
            f"Size: {deb_size}",
            f"SHA256: {deb_sha}",
            "Filename: pool/main/p/proof-package/proof-package_1.2.3-1_all.deb",
            "",
        ]
    )
    packages = blobs / "index" / "packages"
    packages.write_text(packages_text, encoding="utf-8")
    packages_sha, packages_size = _stable_digest(packages)
    release_payload = "\n".join(
        [
            "Origin: Fixture",
            "Suite: proof",
            "Codename: proof",
            "Date: Wed, 29 Jul 2026 10:00:00 +0000",
            "Valid-Until: Thu, 30 Jul 2026 10:00:00 +0000",
            "Architectures: all",
            "Components: main",
            "SHA256:",
            f" {packages_sha} {packages_size} main/binary-all/Packages",
            "",
        ]
    )
    inrelease = blobs / "release" / "inrelease"
    inrelease.write_text("signed fixture bytes\n", encoding="utf-8")
    keyring = blobs / "keyring" / "archive.gpg"
    keyring.write_bytes(b"fixture trust anchor\n")
    source = blobs / "source" / "sources.list"
    source.write_text(
        "deb [signed-by=/usr/share/keyrings/archive.gpg] https://repo.invalid proof main\n",
        encoding="utf-8",
    )
    keyring_sha256 = _stable_digest(keyring)[0]
    source_policy = PackageSourcePolicy(
        policy_id="fixture-archive",
        base_uri="https://repo.invalid",
        suites=("proof",),
        codenames=("proof",),
        components=("main",),
        architectures=("all",),
        signer_fingerprints=(FINGERPRINT,),
        keyring_sha256=(keyring_sha256,),
        max_release_age_seconds=24 * 60 * 60,
        require_valid_until=True,
    )

    records = [
        _identity(
            source,
            run_dir,
            kind="source",
            source_path="/etc/apt/sources.list",
            extra="",
        ),
        _identity(
            keyring,
            run_dir,
            kind="keyring",
            source_path="/usr/share/keyrings/archive.gpg",
            extra="host-bootstrap",
        ),
        _identity(
            inrelease,
            run_dir,
            kind="release",
            source_path="/var/lib/apt/lists/repo_proof_InRelease",
            extra="",
        ),
        _identity(
            packages,
            run_dir,
            kind="index",
            source_path="/var/lib/apt/lists/repo_proof_main_binary-all_Packages",
            extra="https://repo.invalid/dists/proof/main/binary-all/Packages",
        ),
        _identity(
            sealed_deb,
            run_dir,
            kind="deb",
            source_path="/var/cache/apt/archives/proof-package_1.2.3-1_all.deb",
            extra="",
        ),
    ]
    transaction = {
        "schema": PACKAGE_TRANSACTION_SCHEMA,
        "run_id": "proof-run",
        "id": "bootstrap",
        "kind": "bootstrap",
        "fresh_rootfs": True,
        "records": records,
        "inventory": [
            {
                "package": "proof-package",
                "version": "1.2.3-1",
                "architecture": "all",
            }
        ],
        "complete": True,
        "issues": [],
    }
    transaction_path = run_dir / "apt/transactions/bootstrap.json"
    transaction_path.parent.mkdir(parents=True)
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    final_state = {
        "schema": PACKAGE_TRANSACTION_SCHEMA,
        "run_id": "proof-run",
        "id": "final-apt-state",
        "kind": "apt-state",
        "fresh_rootfs": True,
        "records": [record for record in records if record["kind"] != "deb"],
        "inventory": [],
        "complete": True,
        "issues": [],
    }
    final_state_path = run_dir / "apt/transactions/final-apt-state.json"
    final_state_path.write_text(
        json.dumps(final_state, indent=2) + "\n",
        encoding="utf-8",
    )
    payload = {
        "schema": PACKAGE_INPUTS_SCHEMA,
        "run_id": "proof-run",
        "scope": "target-root",
        "source_mode": "bootstrap",
        "capture_mode": "dpkg-pre-install-sealed-copy",
        "fresh_rootfs": True,
        "archive_keyring": {
            "source": "/usr/share/keyrings/archive.gpg",
            "expected_sha256": keyring_sha256,
        },
        "allowed_signer_fingerprints": [FINGERPRINT],
        "source_policy_sha256": package_source_policy_sha256([source_policy]),
        "verification_time": BUILD_TIME,
        "apt_command_argv_sha256": package_apt_command_argv_sha256(
            SAFE_APT_COMMANDS
        ),
        "transactions": [
            _identity(transaction_path, run_dir),
            _identity(final_state_path, run_dir),
        ],
        "baseline_inventory": [],
        "final_inventory": [
            {
                "package": "proof-package",
                "version": "1.2.3-1",
                "architecture": "all",
            }
        ],
    }
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            release_payload,
            f"[GNUPG:] VALIDSIG {FINGERPRINT} 0 0 0 4 0 1 10 01 {FINGERPRINT}\n",
        ),
    )
    return payload, run_dir, sealed_deb, release_payload


def _validate(
    payload: dict[str, object],
    run_dir: Path,
    *,
    apt_command_argv: tuple[tuple[str, ...], ...] = SAFE_APT_COMMANDS,
    signer_fingerprints: tuple[str, ...] = (FINGERPRINT,),
) -> PackageEvidenceValidation:
    keyring = payload["archive_keyring"]
    assert isinstance(keyring, dict)
    expected_keyring_sha256 = keyring["expected_sha256"]
    assert isinstance(expected_keyring_sha256, str)
    source_policy = PackageSourcePolicy(
        policy_id="fixture-archive",
        base_uri="https://repo.invalid",
        suites=("proof",),
        codenames=("proof",),
        components=("main",),
        architectures=("all",),
        signer_fingerprints=signer_fingerprints,
        keyring_sha256=(expected_keyring_sha256,),
        max_release_age_seconds=24 * 60 * 60,
        require_valid_until=True,
    )
    return validate_package_evidence_payload(
        payload,
        run_dir,
        run_gpg=True,
        expected_source_mode="bootstrap",
        expected_signer_fingerprints=signer_fingerprints,
        expected_keyring_sha256=expected_keyring_sha256,
        expected_source_policies=[source_policy],
        expected_verification_time=BUILD_TIME,
        apt_command_argv=apt_command_argv,
    )


def test_bootstrap_tools_retain_inputs_and_pin_an_explicit_keyring(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create("Proof", tmp_path / "project", "26.04")
    keyring = tmp_path / "archive.gpg"
    options = BootstrapOptions(archive_keyring=keyring)

    mm_runner = CommandRunner(dry_run=True)
    monkeypatch.setattr(mm_runner, "has_binary", lambda name: name == "mmdebstrap")
    BootstrapService(
        mm_runner,
        project.release,
        project.squashfs_root,
        project.iso_root,
        options,
        use_sudo=False,
    ).create_rootfs()
    mm_argv = next(
        spec.argv for spec in mm_runner.history if spec.argv[:1] == ("mmdebstrap",)
    )
    assert f"--keyring={keyring}" in mm_argv
    assert "--skip=essential/unlink" in mm_argv
    assert "--skip=cleanup/apt/lists" in mm_argv
    assert "--skip=cleanup/apt/cache" in mm_argv

    debootstrap_runner = CommandRunner(dry_run=True)
    monkeypatch.setattr(debootstrap_runner, "has_binary", lambda _name: False)
    BootstrapService(
        debootstrap_runner,
        project.release,
        project.squashfs_root,
        project.iso_root,
        options,
        use_sudo=False,
    ).create_rootfs()
    debootstrap_argv = next(
        spec.argv
        for spec in debootstrap_runner.history
        if spec.argv[:1] == ("debootstrap",)
    )
    assert "--force-check-sig" in debootstrap_argv
    assert f"--keyring={keyring}" in debootstrap_argv


def test_preinstall_hook_captures_all_chain_bytes_before_dpkg() -> None:
    script = _capture_hook_script()
    config = _capture_hook_config()

    assert "DPkg::Pre-Install-Pkgs" in config
    assert 'APT::Keep-Downloaded-Packages "true"' in config
    for kind in ("source", "config", "keyring", "release", "index", "deb"):
        assert f"seal_file {kind}" in script
    assert "apt-get indextargets" in script
    assert "sha256sum --" in script
    assert "bytes changed during capture" in script


def test_offline_validator_recomputes_release_packages_and_deb_chain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)

    validation = _validate(payload, run_dir)

    assert validation.ok is True
    assert "1 archive .deb inputs" in validation.detail
    assert validation.filesystem_causality == "unverified"
    assert validation.release_ready is False


def test_offline_validator_rejects_a_tampered_deb(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, deb, _release = _valid_payload(tmp_path, monkeypatch)
    deb.write_bytes(deb.read_bytes() + b"tamper")

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "changed" in validation.detail


def test_offline_validator_rejects_a_different_valid_signer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    other = "1" * 40
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            release_payload,
            f"[GNUPG:] VALIDSIG {other} 0 0 0 4 0 1 10 01 {other}\n",
        ),
    )

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "policy-bound" in validation.detail


def test_offline_validator_rejects_an_insecure_source_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    transactions = payload["transactions"]
    assert isinstance(transactions, list)
    transaction_ref = transactions[0]
    assert isinstance(transaction_ref, dict)
    transaction_path = run_dir / str(transaction_ref["path"])
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    source_record = next(
        record for record in transaction["records"] if record["kind"] == "source"
    )
    source = run_dir / source_record["path"]
    source.write_text(
        "deb [trusted=yes] https://repo.invalid proof main\n",
        encoding="utf-8",
    )
    source_record.update(_identity(source, run_dir))
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    transaction_ref.update(_identity(transaction_path, run_dir))

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "insecure APT override" in validation.detail


def test_bootstrap_cannot_exempt_an_injected_baseline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    payload["baseline_inventory"] = [
        {
            "package": "unsigned-injection",
            "version": "9",
            "architecture": "all",
        }
    ]
    baseline_inventory = payload["baseline_inventory"]
    assert isinstance(baseline_inventory, list)
    payload["final_inventory"] = list(baseline_inventory)

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "cannot exempt" in validation.detail


def test_bootstrap_transaction_must_capture_its_own_inventory_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    transactions = payload["transactions"]
    assert isinstance(transactions, list)
    transaction_ref = transactions[0]
    assert isinstance(transaction_ref, dict)
    transaction_path = run_dir / str(transaction_ref["path"])
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    transaction["inventory"].append(
        {
            "package": "missing-bootstrap-byte",
            "version": "1",
            "architecture": "all",
        }
    )
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    transaction_ref.update(_identity(transaction_path, run_dir))

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "bootstrap package has no captured input bytes" in validation.detail


def test_payload_cannot_replace_the_external_signer_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    payload["allowed_signer_fingerprints"] = ["1" * 40]

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "per-source policy" in validation.detail


def test_policy_accepts_explicit_primary_fingerprint_for_a_signing_subkey(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    signing_subkey = "A" * 40
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            release_payload,
            (
                f"[GNUPG:] VALIDSIG {signing_subkey} "
                f"0 0 0 4 0 1 10 01 {FINGERPRINT}\n"
            ),
        ),
    )

    validation = _validate(payload, run_dir)

    assert validation.ok is True


def test_policy_rejects_a_signed_release_with_the_wrong_suite(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            release_payload.replace("Suite: proof", "Suite: other"),
            f"[GNUPG:] VALIDSIG {FINGERPRINT} 0 0 0 4 0 1 10 01 {FINGERPRINT}\n",
        ),
    )

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "Release Suite" in validation.detail


def test_policy_rejects_an_expired_signed_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    expired = release_payload.replace(
        "Valid-Until: Thu, 30 Jul 2026 10:00:00 +0000",
        "Valid-Until: Wed, 29 Jul 2026 11:00:00 +0000",
    )
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            expired,
            f"[GNUPG:] VALIDSIG {FINGERPRINT} 0 0 0 4 0 1 10 01 {FINGERPRINT}\n",
        ),
    )

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "expired" in validation.detail


def test_policy_rejects_a_future_dated_signed_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    future = release_payload.replace(
        "Date: Wed, 29 Jul 2026 10:00:00 +0000",
        "Date: Thu, 30 Jul 2026 10:00:00 +0000",
    ).replace(
        "Valid-Until: Thu, 30 Jul 2026 10:00:00 +0000",
        "Valid-Until: Fri, 31 Jul 2026 10:00:00 +0000",
    )
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            future,
            f"[GNUPG:] VALIDSIG {FINGERPRINT} 0 0 0 4 0 1 10 01 {FINGERPRINT}\n",
        ),
    )

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "in the future" in validation.detail


def test_explicit_snapshot_checks_release_freshness_at_snapshot_time(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    keyring = payload["archive_keyring"]
    assert isinstance(keyring, dict)
    keyring_sha256 = str(keyring["expected_sha256"])
    policy = PackageSourcePolicy(
        policy_id="fixture-archive",
        base_uri="https://repo.invalid",
        suites=("proof",),
        codenames=("proof",),
        components=("main",),
        architectures=("all",),
        signer_fingerprints=(FINGERPRINT,),
        keyring_sha256=(keyring_sha256,),
        snapshot_at="2026-07-01T12:00:00+00:00",
        max_release_age_seconds=24 * 60 * 60,
        require_valid_until=True,
    )
    payload["source_policy_sha256"] = package_source_policy_sha256([policy])
    snapshot_release = release_payload.replace(
        "Date: Wed, 29 Jul 2026 10:00:00 +0000",
        "Date: Wed, 01 Jul 2026 10:00:00 +0000",
    ).replace(
        "Valid-Until: Thu, 30 Jul 2026 10:00:00 +0000",
        "Valid-Until: Thu, 02 Jul 2026 10:00:00 +0000",
    )
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            snapshot_release,
            f"[GNUPG:] VALIDSIG {FINGERPRINT} 0 0 0 4 0 1 10 01 {FINGERPRINT}\n",
        ),
    )

    validation = validate_package_evidence_payload(
        payload,
        run_dir,
        run_gpg=True,
        expected_source_mode="bootstrap",
        expected_signer_fingerprints=[FINGERPRINT],
        expected_keyring_sha256=keyring_sha256,
        expected_source_policies=[policy],
        expected_verification_time=BUILD_TIME,
        apt_command_argv=SAFE_APT_COMMANDS,
    )

    assert validation.ok is True


@pytest.mark.parametrize(
    "apt_command_argv",
    [
        (
            (
                "apt-get",
                "update",
                "-o",
                "Acquire::Check-Valid-Until=false",
            ),
        ),
        (("sh", "-c", "apt-get update --allow-insecure-repositories"),),
        (
            (
                "mmdebstrap",
                "--aptopt=APT::Get::AllowUnauthenticated=true",
                "proof",
            ),
        ),
        (("debootstrap", "--no-check-gpg", "proof", "/target"),),
    ],
)
def test_policy_rejects_command_line_authentication_overrides(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    apt_command_argv: tuple[tuple[str, ...], ...],
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)

    validation = _validate(
        payload,
        run_dir,
        apt_command_argv=apt_command_argv,
    )

    assert validation.ok is False
    assert "insecure APT command-line" in validation.detail


def test_index_uri_must_belong_to_its_external_repository_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    transactions = payload["transactions"]
    assert isinstance(transactions, list)
    transaction_ref = transactions[0]
    assert isinstance(transaction_ref, dict)
    transaction_path = run_dir / str(transaction_ref["path"])
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    index_record = next(
        record for record in transaction["records"] if record["kind"] == "index"
    )
    index_record["extra"] = (
        "https://other.invalid/dists/proof/main/binary-all/Packages"
    )
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    transaction_ref.update(_identity(transaction_path, run_dir))

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "external policy" in validation.detail


def test_index_is_joined_to_the_release_in_its_apt_cache_namespace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    transactions = payload["transactions"]
    assert isinstance(transactions, list)
    transaction_ref = transactions[0]
    assert isinstance(transaction_ref, dict)
    transaction_path = run_dir / str(transaction_ref["path"])
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    release_record = next(
        record for record in transaction["records"] if record["kind"] == "release"
    )
    release_record["source_path"] = (
        "/var/lib/apt/lists/unrelated_proof_InRelease"
    )
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    transaction_ref.update(_identity(transaction_path, run_dir))

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "unique policy-bound signed Release" in validation.detail


@pytest.mark.parametrize(
    ("tool", "magic"),
    [
        ("lz4", b"\x04\x22\x4d\x18"),
        ("zstd", b"\x28\xb5\x2f\xfd"),
    ],
)
def test_lz4_and_zstd_packages_use_command_runner_bound_decompressors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    tool: str,
    magic: bytes,
) -> None:
    packages_text = "\n".join(
        [
            "Package: compressed-proof",
            "Version: 1",
            "Architecture: all",
            "Size: 1",
            f"SHA256: {'0' * 64}",
            "Filename: pool/main/c/compressed-proof.deb",
            "",
        ]
    ).encode()
    compressed = tmp_path / f"Packages.{tool}"
    compressed.write_bytes(magic + packages_text)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / tool
    executable.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                "set -eu",
                'if [ "$#" -eq 4 ]; then',
                "    input=$3",
                "    output=$4",
                "else",
                "    output=$5",
                "    input=$6",
                "fi",
                'tail -c +5 -- "$input" > "$output"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv(
        "PATH",
        f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
    )
    runner = CommandRunner(dry_run=False)

    records = _packages_records(compressed, runner=runner)

    assert records[0]["Package"] == "compressed-proof"
    assert runner.history[0].argv[0] == tool
    assert runner.execution_identities[0]["available"] is True


def test_lz4_packages_fail_closed_without_the_external_tool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    compressed = tmp_path / "Packages.lz4"
    compressed.write_bytes(b"\x04\x22\x4d\x18not-a-real-frame")
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))

    with pytest.raises(ValueError, match="lz4 decompressor is unavailable"):
        _packages_records(compressed, runner=CommandRunner(dry_run=False))


def test_real_zstd_packages_round_trip_through_the_bound_cli(
    tmp_path: Path,
) -> None:
    if not CommandRunner.has_binary("zstd"):
        pytest.skip("zstd is not installed in this test environment")
    plain = tmp_path / "Packages"
    plain.write_text(
        "\n".join(
            [
                "Package: zstd-proof",
                "Version: 1",
                "Architecture: all",
                "Size: 1",
                f"SHA256: {'0' * 64}",
                "Filename: pool/main/z/zstd-proof.deb",
                "",
            ]
        ),
        encoding="utf-8",
    )
    compressed = tmp_path / "Packages.zst"
    subprocess.run(
        ("zstd", "--quiet", "--force", "-o", str(compressed), str(plain)),
        check=True,
    )
    runner = CommandRunner(dry_run=False)

    records = _packages_records(compressed, runner=runner)

    assert records[0]["Package"] == "zstd-proof"
    assert runner.history[0].argv[:4] == (
        "zstd",
        "--decompress",
        "--force",
        "--quiet",
    )
    assert runner.execution_identities[0]["available"] is True


@pytest.mark.parametrize("escaped_directory", ["lists", "archives"])
def test_apt_cache_ancestor_symlink_cannot_copy_outside_rootfs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    escaped_directory: str,
) -> None:
    service, project = _capture_service(tmp_path, monkeypatch)
    root = project.squashfs_root
    outside = tmp_path / "outside"
    outside.mkdir()
    forbidden = b"OUTSIDE-APT-BYTES-MUST-NEVER-BE-SEALED"
    if escaped_directory == "lists":
        (outside / "lists").mkdir()
        (outside / "lists/repo_InRelease").write_bytes(forbidden)
        (root / "var/lib").mkdir(parents=True)
        (root / "var/lib/apt").symlink_to(
            outside,
            target_is_directory=True,
        )
        (root / "var/cache/apt/archives").mkdir(parents=True)
    else:
        (root / "var/lib/apt/lists").mkdir(parents=True)
        (outside / "archives").mkdir()
        (outside / "archives/outside.deb").write_bytes(forbidden)
        (root / "var/cache").mkdir(parents=True)
        (root / "var/cache/apt").symlink_to(
            outside,
            target_is_directory=True,
        )

    with pytest.raises(ValueError, match="symlink"):
        service._current_apt_records(include_host_keyring=False)

    _assert_bytes_absent(project.output_dir, forbidden)


def test_physically_confined_apt_inputs_are_copied_from_open_descriptors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    index_targets = (
        "Packages\t/var/lib/apt/lists/repo_Packages\t"
        "https://repo.invalid/dists/proof/main/binary-amd64/Packages\n"
    )
    service, project = _capture_service(
        tmp_path,
        monkeypatch,
        index_targets=index_targets,
    )
    root = project.squashfs_root
    lists = root / "var/lib/apt/lists"
    archives = root / "var/cache/apt/archives"
    lists.mkdir(parents=True)
    archives.mkdir(parents=True)
    (lists / "repo_Packages").write_bytes(b"Package: confined\n")
    (lists / "repo_InRelease").write_bytes(b"signed release bytes\n")
    (archives / "confined.deb").write_bytes(b"deb bytes\n")
    source = root / "etc/apt/sources.list"
    source.parent.mkdir(parents=True)
    source.write_text(
        "deb https://repo.invalid proof main\n",
        encoding="utf-8",
    )
    keyring = root / "usr/share/keyrings/archive.gpg"
    keyring.parent.mkdir(parents=True)
    keyring.write_bytes(b"keyring bytes\n")

    records = service._current_apt_records(include_host_keyring=False)

    assert {"source", "keyring", "release", "index", "deb"} <= {
        str(record["kind"]) for record in records
    }
    for record in records:
        sealed = service._run_dir / str(record["path"])
        assert sealed.is_file()
        record_size = record["size"]
        assert isinstance(record_size, int)
        assert _stable_digest(sealed) == (
            str(record["sha256"]),
            record_size,
        )


def test_apt_index_ancestor_symlink_cannot_copy_outside_rootfs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    index_targets = (
        "Packages\t/var/lib/apt/lists/escape/Packages\t"
        "https://repo.invalid/dists/proof/main/binary-amd64/Packages\n"
    )
    service, project = _capture_service(
        tmp_path,
        monkeypatch,
        index_targets=index_targets,
    )
    root = project.squashfs_root
    (root / "var/lib/apt/lists").mkdir(parents=True)
    (root / "var/cache/apt/archives").mkdir(parents=True)
    outside = tmp_path / "outside-index"
    outside.mkdir()
    forbidden = b"OUTSIDE-PACKAGES-INDEX"
    (outside / "Packages").write_bytes(forbidden)
    (root / "var/lib/apt/lists/escape").symlink_to(
        outside,
        target_is_directory=True,
    )

    with pytest.raises(ValueError, match="symlink"):
        service._current_apt_records(include_host_keyring=False)

    _assert_bytes_absent(project.output_dir, forbidden)


@pytest.mark.parametrize(
    "relative",
    [
        "etc/apt/sources.list",
        "etc/apt/apt.conf",
        "etc/apt/trusted.gpg",
    ],
)
def test_apt_configuration_final_symlink_is_a_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    relative: str,
) -> None:
    service, project = _capture_service(tmp_path, monkeypatch)
    root = project.squashfs_root
    (root / "var/lib/apt/lists").mkdir(parents=True)
    (root / "var/cache/apt/archives").mkdir(parents=True)
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / f"outside-{target.name}"
    forbidden = f"OUTSIDE-{relative}".encode()
    outside.write_bytes(forbidden)
    target.symlink_to(outside)

    with pytest.raises(ValueError, match="symlink"):
        service._current_apt_records(include_host_keyring=False)

    _assert_bytes_absent(project.output_dir, forbidden)


def test_inside_root_rejects_a_descendant_mountpoint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    target = root / "var/lib/apt/lists"
    target.mkdir(parents=True)
    monkeypatch.setattr(
        "distroforge.core.package_evidence._linux_mountpoints",
        lambda: {target},
    )

    with pytest.raises(ValueError, match="mount boundary"):
        _inside_root(root, "/var/lib/apt/lists", expected="directory")


def test_inside_root_rejects_a_symlinked_rootfs_itself(
    tmp_path: Path,
) -> None:
    physical = tmp_path / "physical-root"
    (physical / "var/lib/apt/lists").mkdir(parents=True)
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(physical, target_is_directory=True)

    with pytest.raises(ValueError, match="rootfs.*symlink"):
        _inside_root(
            linked_root,
            "/var/lib/apt/lists",
            expected="directory",
        )


def test_inside_root_rejects_a_non_regular_index(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    index = root / "var/lib/apt/lists/Packages"
    index.parent.mkdir(parents=True)
    os.mkfifo(index)

    with pytest.raises(ValueError, match="not a regular file"):
        _inside_root(
            root,
            "/var/lib/apt/lists/Packages",
            expected="regular",
        )


def test_unsealed_external_host_bootstrap_keyring_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    keyring = tmp_path / "outside-bootstrap.gpg"
    forbidden = b"EXTERNAL-UNSEALED-KEYRING"
    keyring.write_bytes(forbidden)
    digest, _size = _stable_digest(keyring)
    service, project = _capture_service(
        tmp_path,
        monkeypatch,
        archive_keyring=keyring,
        archive_keyring_sha256=digest,
    )

    with pytest.raises(ValueError, match="sealed run copy"):
        service._seal_source(
            "keyring",
            keyring,
            extra="host-bootstrap",
        )

    _assert_bytes_absent(project.output_dir, forbidden)


def test_only_the_content_addressed_host_bootstrap_copy_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original = tmp_path / "outside-bootstrap.gpg"
    original.write_bytes(b"PINNED-BOOTSTRAP-KEYRING")
    digest, size = _stable_digest(original)
    service, _project = _capture_service(
        tmp_path,
        monkeypatch,
        archive_keyring=original,
        archive_keyring_sha256=digest,
    )
    sealed = service._run_dir / "apt/blobs/keyring" / digest
    sealed.parent.mkdir(parents=True)
    sealed.write_bytes(original.read_bytes())
    service.archive_keyring = sealed

    record = service._seal_source(
        "keyring",
        sealed,
        extra="host-bootstrap",
    )

    assert record["sha256"] == digest
    assert record["size"] == size
    assert record["path"] == f"apt/blobs/keyring/{digest}"
