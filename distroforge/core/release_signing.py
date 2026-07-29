from __future__ import annotations

import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .evidence_run import copy_immutable_file
from .hashing import sha256_file
from .host_artifacts import write_host_artifact
from .project import Project

SIGN_TARGETS = ("SHA256SUMS", "RELEASE-GATE.json", "RELEASE-MANIFEST.json")
SIGNING_KEYRING = "RELEASE-SIGNING-KEYRING.gpg"

_FULL_FINGERPRINT = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})")
_VALIDSIG = "[GNUPG:] VALIDSIG "


@dataclass(frozen=True)
class ReleaseManifestEntry:
    name: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class ReleaseSigningReport:
    project: Path
    bundle_dir: Path
    manifest: Path
    status: str
    execute: bool
    signer_fingerprint: str | None
    verification_keyring: str | None
    verification_keyring_sha256: str | None
    signed: tuple[str, ...]
    planned: tuple[str, ...]
    skipped: tuple[str, ...]
    manifest_entries: tuple[ReleaseManifestEntry, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "bundle_dir": str(self.bundle_dir),
            "manifest": str(self.manifest),
            "status": self.status,
            "execute": self.execute,
            "signer_fingerprint": self.signer_fingerprint,
            "verification_keyring": self.verification_keyring,
            "verification_keyring_sha256": self.verification_keyring_sha256,
            "signed": list(self.signed),
            "planned": list(self.planned),
            "skipped": list(self.skipped),
            "manifest_entries": [entry.to_dict() for entry in self.manifest_entries],
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Maintainer release signing",
            f"Project: {self.project}",
            f"Bundle: {self.bundle_dir}",
            f"Manifest: {self.manifest}",
            f"Status: {self.status.upper()}",
            f"Mode: {'execute' if self.execute else 'plan'}",
            f"Signer fingerprint: {self.signer_fingerprint or 'not pinned in plan'}",
            f"Verification keyring: {self.verification_keyring or 'not generated'}",
            (
                "Verification keyring SHA256: "
                f"{self.verification_keyring_sha256 or 'not generated'}"
            ),
            "",
            "Manifest entries:",
            *[f"- {entry.name}: {entry.sha256}" for entry in self.manifest_entries],
            "",
            "Signed:",
            *([f"- {item}" for item in self.signed] or ["- none"]),
            "",
            "Planned:",
            *([f"- {item}" for item in self.planned] or ["- none"]),
            "",
            "Skipped:",
            *([f"- {item}" for item in self.skipped] or ["- none"]),
        ]
        return "\n".join(lines)


def sign_release_bundle(
    project: Project,
    *,
    bundle_dir: Path | None = None,
    execute: bool = False,
    gpg_key: str | None = None,
    gpg_keyring: Path | None = None,
) -> ReleaseSigningReport:
    bundle_dir = bundle_dir or project.output_dir / "publish"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = bundle_dir / "RELEASE-MANIFEST.json"
    skipped: list[str] = []
    signed: list[str] = []
    planned: list[str] = []
    signer_fingerprint = full_fingerprint(gpg_key)
    verification_keyring: str | None = None
    verification_keyring_sha256: str | None = None
    unsafe = [
        path.relative_to(bundle_dir).as_posix()
        for path in bundle_dir.rglob("*")
        if path.is_symlink()
    ]
    gate_status = _gate_status(bundle_dir / "RELEASE-GATE.json")
    iso_paths = [
        path
        for path in bundle_dir.rglob("*.iso")
        if path.is_file() and not path.is_symlink()
    ]
    blocked = False
    if unsafe:
        skipped.append("Bundle contains unsafe symlinks: " + ", ".join(unsafe))
        blocked = True
    elif execute and len(iso_paths) != 1:
        skipped.append(
            f"Bundle must contain exactly one ISO, found {len(iso_paths)}."
        )
        blocked = True
    elif execute and gate_status == "blocked":
        skipped.append("RELEASE-GATE.json is BLOCKED; signing was refused.")
        blocked = True
    elif gpg_key and signer_fingerprint is None:
        skipped.append(
            "The artifact signing key must be a complete 40- or 64-hex-digit "
            "OpenPGP fingerprint."
        )
        blocked = True
    elif execute and signer_fingerprint is None:
        skipped.append(
            "Executed release signing requires a complete OpenPGP signer fingerprint."
        )
        blocked = True
    elif execute and gpg_keyring is None:
        skipped.append(
            "Executed release signing requires an explicit filtered public GPG keyring."
        )
        blocked = True
    elif execute and not CommandRunner.has_binary("gpg"):
        skipped.append(
            "gpg is missing; install GnuPG or rerun without --execute for a signing plan."
        )
        blocked = True

    runner = CommandRunner(dry_run=not execute)
    keyring_path = bundle_dir / SIGNING_KEYRING
    if execute and not blocked:
        assert signer_fingerprint is not None
        assert gpg_keyring is not None
        try:
            _prepare_verification_keyring(
                runner,
                signer_fingerprint,
                gpg_keyring,
                keyring_path,
            )
        except (OSError, ValueError) as exc:
            skipped.append(f"GPG signing preflight failed: {exc}")
            blocked = True
        else:
            verification_keyring = SIGNING_KEYRING
            verification_keyring_sha256 = sha256_file(keyring_path)

    # The caller-supplied filtered verification key belongs to the signed payload.
    # Seal its immutable copy before the manifest, never afterwards.
    entries = _write_manifest(project, bundle_dir, manifest_path)
    if not blocked:
        for name in SIGN_TARGETS:
            target = bundle_dir / name
            if not target.exists():
                skipped.append(f"{name} is missing.")
                continue
            asc = target.with_name(f"{target.name}.asc")
            if execute:
                assert signer_fingerprint is not None
                assert verification_keyring is not None
                result = runner.run(
                    CommandSpec(
                        argv=(
                            "gpg",
                            "--batch",
                            "--no-options",
                            "--yes",
                            "--status-fd",
                            "1",
                            "--armor",
                            "--detach-sign",
                            "--local-user",
                            signer_fingerprint,
                            "--output",
                            str(asc),
                            str(target),
                        ),
                        description=f"Sign release file {name}",
                    ),
                    check=False,
                )
                if result.returncode != 0 or not asc.is_file():
                    skipped.append(f"{name} failed GPG signing.")
                    continue
                try:
                    verify_detached_signature(
                        runner,
                        asc,
                        target,
                        keyring_path,
                        signer_fingerprint,
                    )
                except (OSError, ValueError) as exc:
                    skipped.append(f"{name} signature identity check failed: {exc}")
                    continue
                signed.append(asc.name)
            else:
                planned.append(asc.name)
    if (
        execute
        and verification_keyring_sha256 is not None
        and (
            not keyring_path.is_file()
            or sha256_file(keyring_path) != verification_keyring_sha256
        )
    ):
        skipped.append("The sealed release verification keyring changed during signing.")
    status = (
        "signed"
        if execute and signed and not skipped
        else "planned"
        if planned and not blocked
        else "blocked"
    )
    report = ReleaseSigningReport(
        project.root,
        bundle_dir,
        manifest_path,
        status,
        execute,
        signer_fingerprint,
        verification_keyring,
        verification_keyring_sha256,
        tuple(signed),
        tuple(planned),
        tuple(skipped),
        entries,
    )
    write_host_artifact(
        bundle_dir / "SIGNING-REPORT.json",
        report.render_json() + "\n",
        "Write SIGNING-REPORT.json",
    )
    return report


def full_fingerprint(value: str | None) -> str | None:
    """Return a canonical complete OpenPGP fingerprint, never a key ID."""
    if value is None:
        return None
    normalized = "".join(value.split())
    if normalized[:2].lower() == "0x":
        normalized = normalized[2:]
    normalized = normalized.upper()
    return normalized if _FULL_FINGERPRINT.fullmatch(normalized) else None


def validsig_fingerprints(status_output: str) -> tuple[str, ...]:
    """Read signing and primary-key fingerprints from machine-readable VALIDSIG."""
    fingerprints: list[str] = []
    for line in status_output.splitlines():
        if not line.startswith(_VALIDSIG):
            continue
        fields = line[len(_VALIDSIG) :].split()
        candidates = fields[:1]
        if len(fields) >= 10:
            candidates.append(fields[9])
        for candidate in candidates:
            fingerprint = full_fingerprint(candidate)
            if fingerprint and fingerprint not in fingerprints:
                fingerprints.append(fingerprint)
    return tuple(fingerprints)


def verify_detached_signature(
    runner: CommandRunner,
    signature: Path,
    payload: Path,
    keyring: Path,
    expected_fingerprint: str,
) -> tuple[str, ...]:
    """Verify through only the supplied keyring and require a matching VALIDSIG."""
    expected = full_fingerprint(expected_fingerprint)
    if expected is None:
        raise ValueError("the expected signer is not a complete OpenPGP fingerprint")
    if keyring.is_symlink() or not keyring.is_file():
        raise ValueError("the explicit verification keyring is missing or unsafe")
    with tempfile.TemporaryDirectory(prefix="distroforge-gpg-verify-") as home_name:
        home = Path(home_name)
        home.chmod(0o700)
        isolated_keyring = home / "trustedkeys.gpg"
        shutil.copyfile(keyring, isolated_keyring)
        result = runner.run(
            CommandSpec(
                argv=(
                    "gpg",
                    "--batch",
                    "--no-options",
                    "--no-auto-key-retrieve",
                    "--homedir",
                    str(home),
                    "--no-default-keyring",
                    "--keyring",
                    str(isolated_keyring),
                    "--status-fd",
                    "1",
                    "--verify",
                    str(signature),
                    str(payload),
                ),
                description=f"Verify release signature {signature.name}",
            ),
            check=False,
        )
    seen = validsig_fingerprints(result.stdout)
    if result.returncode != 0:
        raise ValueError(f"{signature.name} failed GPG verification")
    if not seen:
        raise ValueError(f"{signature.name} produced no VALIDSIG status")
    if expected not in seen:
        raise ValueError(
            f"{signature.name} was signed by {', '.join(seen)}, not {expected}"
        )
    return seen


def _prepare_verification_keyring(
    runner: CommandRunner,
    signer_fingerprint: str,
    source_keyring: Path,
    keyring_path: Path,
) -> None:
    listing = runner.run(
        CommandSpec(
            argv=(
                "gpg",
                "--batch",
                "--no-options",
                "--with-colons",
                "--fingerprint",
                "--list-secret-keys",
                signer_fingerprint,
            ),
            description="Resolve release signing secret key fingerprint",
        ),
        check=False,
    )
    secret_fingerprints = _primary_fingerprints(listing.stdout, "sec")
    if listing.returncode != 0 or signer_fingerprint not in secret_fingerprints:
        raise ValueError(
            f"no secret primary key exactly matches {signer_fingerprint}"
        )
    if source_keyring.is_symlink() or not source_keyring.is_file():
        raise ValueError("the explicit public keyring is missing or unsafe")
    source_before = _stable_file_identity(source_keyring)
    if source_before is None:
        raise ValueError("the explicit public keyring cannot be read")
    try:
        copy_immutable_file(source_keyring, keyring_path)
    except FileExistsError as exc:
        raise ValueError(
            f"{SIGNING_KEYRING} already exists; refuse to replace sealed key material"
        ) from exc
    source_after = _stable_file_identity(source_keyring)
    if (
        source_after != source_before
        or sha256_file(keyring_path) != source_before["sha256"]
    ):
        raise ValueError("the explicit public keyring changed while it was copied")
    public_fingerprints = _isolated_keyring_fingerprints(runner, keyring_path)
    if set(public_fingerprints) != {signer_fingerprint}:
        raise ValueError(
            "the supplied verification keyring must contain only the pinned primary key"
        )


def _stable_file_identity(path: Path) -> dict[str, object] | None:
    try:
        before = path.stat()
        digest = sha256_file(path)
        after = path.stat()
    except OSError:
        return None
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        return None
    return {
        "device": after.st_dev,
        "inode": after.st_ino,
        "size": after.st_size,
        "mtime_ns": after.st_mtime_ns,
        "sha256": digest,
    }


def _isolated_keyring_fingerprints(
    runner: CommandRunner,
    keyring_path: Path,
) -> tuple[str, ...]:
    with tempfile.TemporaryDirectory(prefix="distroforge-gpg-list-") as home_name:
        home = Path(home_name)
        home.chmod(0o700)
        isolated_keyring = home / "trustedkeys.gpg"
        shutil.copyfile(keyring_path, isolated_keyring)
        listing = runner.run(
            CommandSpec(
                argv=(
                    "gpg",
                    "--batch",
                    "--no-options",
                    "--homedir",
                    str(home),
                    "--no-default-keyring",
                    "--keyring",
                    str(isolated_keyring),
                    "--with-colons",
                    "--fingerprint",
                    "--list-keys",
                ),
                description="Inspect pinned release verification keyring",
            ),
            check=False,
        )
    if listing.returncode != 0:
        return ()
    return _primary_fingerprints(listing.stdout, "pub")


def _primary_fingerprints(colon_output: str, record_type: str) -> tuple[str, ...]:
    fingerprints: list[str] = []
    awaiting_primary = False
    for line in colon_output.splitlines():
        fields = line.split(":")
        kind = fields[0] if fields else ""
        if kind == record_type:
            awaiting_primary = True
            continue
        if kind in {"pub", "sec", "sub", "ssb"}:
            awaiting_primary = False
            continue
        if awaiting_primary and kind == "fpr":
            fingerprint = full_fingerprint(fields[9] if len(fields) > 9 else "")
            if fingerprint:
                fingerprints.append(fingerprint)
            awaiting_primary = False
    return tuple(fingerprints)


def _write_manifest(project: Project, bundle_dir: Path, manifest_path: Path) -> tuple[ReleaseManifestEntry, ...]:
    entries = tuple(
        ReleaseManifestEntry(
            path.relative_to(bundle_dir).as_posix(),
            path.stat().st_size,
            sha256_file(path),
        )
        for path in sorted(bundle_dir.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and path.relative_to(bundle_dir).as_posix()
        not in {
            "RELEASE-MANIFEST.json",
            "SIGNING-REPORT.json",
            "VERIFY-REPORT.json",
            "RELEASE-PIPELINE.json",
        }
        and not path.name.endswith(".asc")
    )
    gate_status = _gate_status(bundle_dir / "RELEASE-GATE.json")
    write_host_artifact(
        manifest_path,
        json.dumps(
            {
                "generated_at": datetime.now(UTC).isoformat(),
                "project": project.name,
                "bundle_dir": str(bundle_dir),
                "gate_status": gate_status,
                "files": [entry.to_dict() for entry in entries],
            },
            indent=2,
        )
        + "\n",
        "Write RELEASE-MANIFEST.json",
    )
    return entries


def _gate_status(path: Path) -> str:
    if not path.exists():
        return "unknown"
    try:
        return str(json.loads(path.read_text(encoding="utf-8")).get("status", "unknown"))
    except json.JSONDecodeError:
        return "unknown"
