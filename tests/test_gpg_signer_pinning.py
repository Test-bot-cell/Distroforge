from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from distroforge.core.command import CommandRunner
from distroforge.core.gpg import (
    assert_signer,
    normalize_fingerprint,
    signer_fingerprints,
    verify_argv,
)
from distroforge.core.integrity import IntegrityOptions, IntegrityService
from distroforge.core.rollback import RestoreRequest, RollbackService
from distroforge.core.snapshots import SnapshotOptions, SnapshotService
from distroforge.core.trust import TrustOptions, TrustService

FINGERPRINT = "4248DCA20A9407BBFA31818518BC560A874C3C7F"
LONG_KEY_ID = FINGERPRINT[-16:]
OTHER = "0000000000000000000000000000000000000000"

# Captured from a real `gpg --status-fd 1 --verify`. The pinned fingerprint used
# to be emitted as a virtual command marker, and CommandRunner answers virtual
# commands with rc=0 in execute mode too, so the value was compared to nothing.
STATUS_OUTPUT = f"""[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED {FINGERPRINT} 0
[GNUPG:] GOODSIG {LONG_KEY_ID} DistroForge Probe <probe@distroforge.invalid>
[GNUPG:] VALIDSIG {FINGERPRINT} 2026-07-26 1785085260 0 4 0 22 10 00 {FINGERPRINT}
[GNUPG:] TRUST_ULTIMATE 0 pgp
"""


def test_verify_argv_asks_gpg_for_the_status_channel() -> None:
    argv = verify_argv(Path("a.sig"), Path("a.iso"))

    assert argv == ("gpg", "--status-fd", "1", "--verify", "a.sig", "a.iso")
    assert verify_argv(Path("a.sig"), Path("a.iso"), "ring.gpg")[:3] == (
        "gpg",
        "--no-default-keyring",
        "--keyring",
    )


def test_signer_fingerprints_reads_validsig() -> None:
    assert signer_fingerprints(STATUS_OUTPUT) == (FINGERPRINT,)
    assert signer_fingerprints("[GNUPG:] BADSIG deadbeef nobody") == ()


def test_normalize_fingerprint_accepts_the_shapes_users_paste() -> None:
    assert normalize_fingerprint("4248 dca2 0a94 07bb") == "4248DCA20A9407BB"
    assert normalize_fingerprint(f"0x{FINGERPRINT.lower()}") == FINGERPRINT


def test_assert_signer_accepts_the_pinned_signer() -> None:
    assert_signer(STATUS_OUTPUT, FINGERPRINT, "the source ISO")
    # gpg resolves short and long key ids against the end of the fingerprint.
    assert_signer(STATUS_OUTPUT, LONG_KEY_ID, "the source ISO")


def test_assert_signer_rejects_another_signer() -> None:
    with pytest.raises(ValueError, match="not from the pinned fingerprint"):
        assert_signer(STATUS_OUTPUT, OTHER, "the source ISO")


def test_assert_signer_rejects_a_missing_validsig() -> None:
    with pytest.raises(ValueError, match="no valid signature"):
        assert_signer("[GNUPG:] BADSIG deadbeef nobody", FINGERPRINT, "the source ISO")


# The first check in this suite that runs a real external tool. Offline, rootless
# and sub-second: gpg generates an ed25519 key in a throwaway GNUPGHOME in about
# 30 ms. It exists because the unit tests above parse a captured status line, and
# only real gpg can prove that line is the one gpg still emits.
gpg_binary = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is not installed")


@pytest.fixture
def signed_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, str]:
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("GNUPGHOME", str(home))
    base = ("gpg", "--batch", "--quiet", "--passphrase", "")
    subprocess.run(
        (
            *base,
            "--quick-generate-key",
            "DistroForge Probe <probe@distroforge.invalid>",
            "ed25519",
            "sign",
            "never",
        ),
        check=True,
        capture_output=True,
    )
    listing = subprocess.run(
        ("gpg", "--batch", "--with-colons", "--list-keys"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    fingerprint = next(
        line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
    )
    payload = tmp_path / "source.iso"
    payload.write_bytes(b"a payload worth signing")
    signature = tmp_path / "source.iso.sig"
    subprocess.run(
        (*base, "--detach-sign", "--output", str(signature), str(payload)),
        check=True,
        capture_output=True,
    )
    return signature, payload, fingerprint


@gpg_binary
def test_real_signature_passes_the_pinned_fingerprint(
    signed_payload: tuple[Path, Path, str],
) -> None:
    signature, payload, fingerprint = signed_payload
    service = IntegrityService(
        CommandRunner(dry_run=False), IntegrityOptions(fingerprint=fingerprint)
    )

    service.verify_gpg(signature, payload, "the source ISO")


@gpg_binary
def test_real_signature_from_another_key_is_refused(
    signed_payload: tuple[Path, Path, str],
) -> None:
    signature, payload, _ = signed_payload
    service = IntegrityService(CommandRunner(dry_run=False), IntegrityOptions(fingerprint=OTHER))

    with pytest.raises(ValueError, match="not from the pinned fingerprint"):
        service.verify_gpg(signature, payload, "the source ISO")


@gpg_binary
def test_real_executing_source_trust_closes_sha_signature_and_full_pin(
    signed_payload: tuple[Path, Path, str],
) -> None:
    signature, payload, fingerprint = signed_payload
    options = TrustOptions(
        source_sha256=hashlib.sha256(payload.read_bytes()).hexdigest(),
        source_signature=signature,
        source_gpg_fingerprint=fingerprint,
    )

    report = TrustService().enforce_source_iso(
        payload,
        options,
        CommandRunner(dry_run=False),
    )

    assert report.ok


# One restore path. RollbackService used to run tar with no sudo() wrapper over a
# tree that unsquashfs created as root, so a real restore died with EACCES on the
# first entry -- while SnapshotService did the same job correctly a few lines away.
def test_cli_restore_and_snapshot_service_emit_the_same_argv(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    cli_runner = CommandRunner(dry_run=True)
    RollbackService(cli_runner).restore(RestoreRequest(root, "after-apt"))

    service_runner = CommandRunner(dry_run=True)
    work = root / "work"
    SnapshotService(
        service_runner, work / "filesystem", work / "snapshots", SnapshotOptions()
    ).restore("after-apt")

    assert [spec.argv for spec in cli_runner.history] == [
        spec.argv for spec in service_runner.history
    ]
    assert cli_runner.history[0].argv[0] == "sudo"
    assert cli_runner.history[0].needs_root is True
