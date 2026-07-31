from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType

from .artifact_verification import (
    ArtifactHandle,
    ArtifactIdentity,
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .command import CommandError, CommandResult, CommandRunner, CommandSpec
from .evidence_run import (
    ImmutableCopyReceipt,
    StableParentIdentity,
    _rename_directory_noreplace,
    copy_immutable_file,
    copy_immutable_file_descriptor,
    owned_temporary_directory,
    publish_regular_text,
)
from .hashing import MAX_SHA256_SUMS_BYTES, parse_sha256_sums
from .project import Project
from .release_contract import (
    SIGN_TARGETS,
    SIGNING_KEYRING,
    release_gate_code_problem,
    release_gate_report_problem,
)

_FULL_FINGERPRINT = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})")
_VALIDSIG = "[GNUPG:] VALIDSIG "
_SIGNING_JSON_MAX_BYTES = 16 * 1024 * 1024
_SIGNING_KEYRING_MAX_BYTES = 64 * 1024 * 1024
_SIGNING_LIMITS = ArtifactLimits(
    max_open_files=4096,
    max_file_bytes=64 * 1024 * 1024 * 1024,
    max_buffered_bytes=256 * 1024 * 1024,
    max_hashed_bytes=256 * 1024 * 1024 * 1024,
    max_json_nodes=2_000_000,
    max_closing_fds=8192,
)
# A manifest verdict may retain one descriptor binding per inventory entry.
# Deriving the traversal budget from the session budget guarantees that an
# accepted inventory cannot exhaust the later descriptor-bound snapshot.
_SIGNING_INVENTORY_MAX_ENTRIES = _SIGNING_LIMITS.max_open_files
OPERATIONAL_BUNDLE_FILES = frozenset(
    {
        "PUBLISH-DRILL-BASELINE-REFUSAL.json",
        "PUBLISH-DRILL-BASELINE.json",
        "PUBLISH-DRILL.json",
        "PUBLISH-DRILL.previous.json",
        "RELEASE-EXPLAIN.md",
        "RELEASE-MANIFEST.json",
        "RELEASE-PIPELINE.json",
        "SIGNING-REPORT.json",
        "VERIFY-REPORT.json",
    }
)
_MANIFEST_EXCLUDED = {
    *OPERATIONAL_BUNDLE_FILES,
}


@dataclass(frozen=True)
class _SigningInventory:
    anchor_identity: ArtifactIdentity
    entries: tuple[tuple[str, ArtifactIdentity], ...]

    def by_name(self) -> dict[str, ArtifactIdentity]:
        return dict(self.entries)


@dataclass(frozen=True)
class _SigningPreflight:
    anchor_identity: ArtifactIdentity
    gate_status: str
    gate_review_codes: tuple[str, ...]
    iso_names: tuple[str, ...]
    existing_signatures: tuple[str, ...]


@dataclass(frozen=True)
class _ManifestSnapshot:
    anchor_identity: ArtifactIdentity
    entries: tuple[ReleaseManifestEntry, ...]
    gate_status: str
    gate_review_codes: tuple[str, ...]
    operational_names: tuple[str, ...]
    manifest_size: int | None = None
    manifest_sha256: str | None = None


@dataclass(frozen=True)
class _StagedSignature:
    name: str
    descriptor: int
    identity: ArtifactIdentity
    sha256: str


@dataclass(frozen=True)
class _StagedKeyring:
    session: ArtifactVerificationSession
    handle: ArtifactHandle
    receipt: ImmutableCopyReceipt


@dataclass(frozen=True)
class _OwnedRegularFile:
    name: str
    descriptor: int
    identity: ArtifactIdentity
    sha256: str


@dataclass
class _SigningStageGuard:
    """Convert owned signing-stage lifecycle failures into a reportable state."""

    bundle_dir: Path
    enabled: bool
    error: Exception | None = None
    _inner: AbstractContextManager[Path] | None = None

    def __enter__(self) -> Path:
        try:
            self._inner = (
                owned_temporary_directory(prefix="distroforge-signing-stage-")
                if self.enabled
                else nullcontext(self.bundle_dir)
            )
            return self._inner.__enter__()
        except (
            ArtifactVerificationError,
            CommandError,
            OSError,
            UnicodeError,
            TypeError,
            ValueError,
        ) as exc:
            self.error = exc
            self._inner = None
            return self.bundle_dir

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if self._inner is None:
            return False
        try:
            return bool(self._inner.__exit__(exc_type, exc, traceback))
        except (
            ArtifactVerificationError,
            CommandError,
            OSError,
            UnicodeError,
            TypeError,
            ValueError,
        ) as lifecycle_error:
            self.error = lifecycle_error
            # Preserve a primary body exception. A lifecycle-only failure is
            # consumed here and converted into a blocked signing report below.
            return exc is None


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
            (f"Verification keyring SHA256: {self.verification_keyring_sha256 or 'not generated'}"),
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
    expected_bundle_identity: StableParentIdentity | ArtifactIdentity | None = None,
    expected_product_iso: Path | None = None,
    expected_product_output_dir: Path | None = None,
    publish_artifacts: bool | None = None,
) -> ReleaseSigningReport:
    if publish_artifacts is None:
        # A public dry-run is a true plan and must not consume the immutable
        # authoritative filenames needed by a later executing invocation.
        publish_artifacts = execute
    bundle_dir = Path(os.path.abspath(bundle_dir or project.output_dir / "publish"))
    expected_product_iso = (
        Path(os.path.abspath(expected_product_iso))
        if expected_product_iso is not None
        else None
    )
    expected_product_output_dir = Path(
        os.path.abspath(
            expected_product_output_dir
            if expected_product_output_dir is not None
            else (
                expected_product_iso.parent
                if expected_product_iso is not None
                else project.output_dir
            )
        )
    )
    manifest_path = bundle_dir / "RELEASE-MANIFEST.json"
    try:
        bundle_identity = bundle_dir.lstat()
    except FileNotFoundError:
        return ReleaseSigningReport(
            project.root,
            bundle_dir,
            manifest_path,
            "blocked",
            execute,
            full_fingerprint(gpg_key),
            None,
            None,
            (),
            (),
            ("Publish bundle is missing; signing cannot create a partial bundle.",),
            (),
        )
    if not stat.S_ISDIR(bundle_identity.st_mode):
        return ReleaseSigningReport(
            project.root,
            bundle_dir,
            manifest_path,
            "blocked",
            execute,
            full_fingerprint(gpg_key),
            None,
            None,
            (),
            (),
            ("Publish bundle is not a safe directory.",),
            (),
        )
    skipped: list[str] = []
    signed: list[str] = []
    planned: list[str] = []
    signer_fingerprint = full_fingerprint(gpg_key)
    verification_keyring: str | None = None
    verification_keyring_sha256: str | None = None
    blocked = False
    if execute and not publish_artifacts:
        skipped.append(
            "Executed signing cannot suppress immutable manifest and report publication."
        )
        blocked = True
    preflight: _SigningPreflight | None = None
    try:
        preflight = _signing_preflight(
            bundle_dir,
            expected_project=project.root,
            expected_product_iso=expected_product_iso,
            expected_product_output_dir=expected_product_output_dir,
            expected_bundle_identity=expected_bundle_identity,
        )
    except (
        ArtifactVerificationError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
    ) as exc:
        skipped.append(f"Bundle signing preflight failed closed: {exc}")
        blocked = True
    if preflight is not None and preflight.existing_signatures:
        skipped.append(
            "Existing detached signatures are immutable and will not be replaced: "
            + ", ".join(preflight.existing_signatures)
        )
        blocked = True
    if execute and preflight is not None and len(preflight.iso_names) != 1:
        skipped.append(f"Bundle must contain exactly one ISO, found {len(preflight.iso_names)}.")
        blocked = True
    if execute and preflight is not None and preflight.gate_status == "blocked":
        skipped.append("RELEASE-GATE.json is BLOCKED; signing was refused.")
        blocked = True
    elif execute and preflight is not None and not release_gate_authorizes_executed_signing(
        preflight.gate_status,
        preflight.gate_review_codes,
    ):
        skipped.append(
            "Executed signing requires a ready RELEASE-GATE.json or the sole "
            "pre-signing publish-signing review."
        )
        blocked = True
    if gpg_key and signer_fingerprint is None:
        skipped.append(
            "The artifact signing key must be a complete 40- or 64-hex-digit OpenPGP fingerprint."
        )
        blocked = True
    elif execute and signer_fingerprint is None:
        skipped.append("Executed release signing requires a complete OpenPGP signer fingerprint.")
        blocked = True
    elif execute and gpg_keyring is None:
        skipped.append("Executed release signing requires an explicit filtered public GPG keyring.")
        blocked = True
    elif execute and not CommandRunner.has_binary("gpg"):
        skipped.append(
            "gpg is missing; install GnuPG or rerun without --execute for a signing plan."
        )
        blocked = True

    runner = CommandRunner(dry_run=not execute)
    keyring_path = bundle_dir / SIGNING_KEYRING
    entries: tuple[ReleaseManifestEntry, ...] = ()
    snapshot: _ManifestSnapshot | None = None
    published_signature_set: tuple[_OwnedRegularFile, ...] = ()
    staging_context = _SigningStageGuard(
        bundle_dir=bundle_dir,
        enabled=execute and not blocked,
    )
    with staging_context as staging:
        if staging_context.error is not None:
            blocked = True
        staged_keyring = staging / SIGNING_KEYRING
        if execute and not blocked:
            assert preflight is not None
            assert signer_fingerprint is not None
            assert gpg_keyring is not None
            keyring_snapshot: _StagedKeyring | None = None
            try:
                keyring_snapshot = _prepare_verification_keyring(
                    runner,
                    signer_fingerprint,
                    gpg_keyring,
                    staged_keyring,
                )
                keyring_receipt = keyring_snapshot.receipt
                published_receipt = _publish_or_reuse_verification_keyring(
                    keyring_snapshot.handle.fileno,
                    keyring_path,
                    keyring_receipt,
                    expected_bundle_identity=preflight.anchor_identity,
                )
                if published_receipt != keyring_receipt:
                    raise ArtifactVerificationError(
                        "published verification keyring differs from its validated "
                        "descriptor snapshot"
                    )
                keyring_snapshot.session.seal()
            except (
                ArtifactVerificationError,
                CommandError,
                OSError,
                UnicodeError,
                TypeError,
                ValueError,
            ) as exc:
                skipped.append(f"GPG signing preflight failed: {exc}")
                blocked = True
            else:
                verification_keyring = SIGNING_KEYRING
                verification_keyring_sha256 = keyring_receipt.sha256
            finally:
                if keyring_snapshot is not None:
                    keyring_snapshot.session.close()

        if not blocked:
            assert preflight is not None
            try:
                snapshot = _capture_manifest_snapshot(
                    bundle_dir,
                    expected_project=project.root,
                    expected_product_iso=expected_product_iso,
                    expected_product_output_dir=expected_product_output_dir,
                    expected_bundle_identity=preflight.anchor_identity,
                )
                if execute and not release_gate_authorizes_executed_signing(
                    snapshot.gate_status,
                    snapshot.gate_review_codes,
                ):
                    raise ArtifactVerificationError(
                        "release gate no longer authorizes executed signing at "
                        "the manifest snapshot"
                    )
                entries = snapshot.entries
                if publish_artifacts:
                    manifest_content = _manifest_content(
                        project,
                        bundle_dir,
                        snapshot.gate_status,
                        entries,
                    )
                    manifest_receipt = publish_regular_text(
                        manifest_path,
                        manifest_content,
                        max_bytes=_SIGNING_JSON_MAX_BYTES,
                        expected_parent_identity=preflight.anchor_identity,
                    )
                    snapshot = replace(
                        snapshot,
                        manifest_size=manifest_receipt.size,
                        manifest_sha256=manifest_receipt.sha256,
                    )
                    _verify_manifest_publication_snapshot(
                        bundle_dir,
                        snapshot,
                        expected_bundle_identity=preflight.anchor_identity,
                    )
            except (
                ArtifactVerificationError,
                OSError,
                UnicodeError,
                TypeError,
                ValueError,
            ) as exc:
                skipped.append(f"Release manifest snapshot failed closed: {exc}")
                blocked = True

        if not blocked and not execute:
            planned.extend(f"{name}.asc" for name in SIGN_TARGETS)
        elif not blocked:
            assert signer_fingerprint is not None
            assert verification_keyring is not None
            assert snapshot is not None
            staged_signatures: tuple[_StagedSignature, ...] = ()
            published_during_attempt: list[_OwnedRegularFile] = []
            try:
                staged_signatures = _stage_descriptor_bound_signatures(
                    runner,
                    bundle_dir,
                    staging,
                    snapshot,
                    signer_fingerprint,
                    verification_keyring_sha256,
                )
                try:
                    _publish_signature_set(
                        bundle_dir,
                        snapshot,
                        staged_signatures,
                        published_during_attempt,
                    )
                    published_signature_set = tuple(published_during_attempt)
                finally:
                    for staged_signature in staged_signatures:
                        os.close(staged_signature.descriptor)
                _verify_published_signature_snapshot(
                    runner,
                    bundle_dir,
                    snapshot,
                    signer_fingerprint,
                    verification_keyring_sha256,
                )
            except (
                ArtifactVerificationError,
                CommandError,
                OSError,
                UnicodeError,
                TypeError,
                ValueError,
            ) as exc:
                assert preflight is not None
                published_signature_set = tuple(published_during_attempt)
                cleanup_problem = _rollback_signature_set(
                    bundle_dir,
                    published_signature_set,
                    expected_bundle_identity=preflight.anchor_identity,
                )
                _close_owned_regular_files(published_signature_set)
                published_signature_set = ()
                skipped.append(f"Descriptor-bound release signing failed: {exc}")
                if cleanup_problem is not None:
                    skipped.append(cleanup_problem)
                blocked = True
            else:
                signed.extend(f"{name}.asc" for name in SIGN_TARGETS)
    if staging_context.error is not None:
        lifecycle_failures = [
            "Release signing staging lifecycle failed closed: "
            f"{staging_context.error}"
        ]
        if preflight is not None and published_signature_set:
            cleanup_problem = _rollback_signature_set(
                bundle_dir,
                published_signature_set,
                expected_bundle_identity=preflight.anchor_identity,
            )
            if cleanup_problem is not None:
                lifecycle_failures.append(cleanup_problem)
        _close_owned_regular_files(published_signature_set)
        published_signature_set = ()
        skipped.extend(lifecycle_failures)
        signed.clear()
        planned.clear()
        blocked = True
    status = (
        "signed"
        if execute and len(signed) == len(SIGN_TARGETS) and not skipped
        else "planned"
        if len(planned) == len(SIGN_TARGETS) and not blocked
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
    if preflight is None or not publish_artifacts:
        return report
    try:
        publish_regular_text(
            bundle_dir / "SIGNING-REPORT.json",
            report.render_json() + "\n",
            max_bytes=_SIGNING_JSON_MAX_BYTES,
            expected_parent_identity=preflight.anchor_identity,
        )
    except (
        ArtifactVerificationError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
    ) as exc:
        cleanup_problem = _rollback_signature_set(
            bundle_dir,
            published_signature_set,
            expected_bundle_identity=preflight.anchor_identity,
        )
        report_failures = [
            *report.skipped,
            f"SIGNING-REPORT.json publication failed closed: {exc}",
        ]
        if cleanup_problem is not None:
            report_failures.append(cleanup_problem)
        return ReleaseSigningReport(
            report.project,
            report.bundle_dir,
            report.manifest,
            "blocked",
            report.execute,
            report.signer_fingerprint,
            report.verification_keyring,
            report.verification_keyring_sha256,
            (),
            (),
            tuple(report_failures),
            report.manifest_entries,
        )
    finally:
        _close_owned_regular_files(published_signature_set)
    return report


def _signing_preflight(
    bundle_dir: Path,
    *,
    expected_project: Path,
    expected_product_iso: Path | None,
    expected_product_output_dir: Path,
    expected_bundle_identity: StableParentIdentity | ArtifactIdentity | None = None,
) -> _SigningPreflight:
    session = ArtifactVerificationSession(
        bundle_dir,
        label="release signing preflight",
        limits=_SIGNING_LIMITS,
    )
    try:
        if expected_bundle_identity is not None and not _same_bundle_anchor(
            session.anchor_identity,
            expected_bundle_identity,
        ):
            raise ArtifactVerificationError(
                "release signing bundle differs from the published bundle identity"
            )
        opening = _descriptor_tree_inventory(
            bundle_dir,
            expected_anchor=session.anchor_identity,
        )
        _require_regular_inventory(opening)
        by_name = opening.by_name()
        iso_names = tuple(
            sorted(
                name
                for name, identity in opening.entries
                if stat.S_ISREG(identity.mode) and name.endswith(".iso")
            )
        )
        gate_identity = by_name.get("RELEASE-GATE.json")
        if gate_identity is None or not stat.S_ISREG(gate_identity.mode):
            raise ArtifactVerificationError(
                "release signing requires one regular RELEASE-GATE.json"
            )
        gate_handle = session.file(
            Path("RELEASE-GATE.json"),
            label="release gate signing input",
            max_bytes=_SIGNING_JSON_MAX_BYTES,
        )
        if gate_handle.identity != gate_identity:
            raise ArtifactVerificationError("RELEASE-GATE.json changed after signing inventory")
        gate = gate_handle.json_object()
        gate_status, gate_review_codes = _strict_signing_gate_status(
            gate,
            expected_project=expected_project,
            expected_product_iso=expected_product_iso,
            expected_product_output_dir=expected_product_output_dir,
            session=session,
            inventory=opening,
            iso_names=iso_names,
        )
        existing_signatures = tuple(
            sorted(
                name
                for name, identity in opening.entries
                if stat.S_ISREG(identity.mode) and name.endswith(".asc")
            )
        )
        closing = _descriptor_tree_inventory(
            bundle_dir,
            expected_anchor=session.anchor_identity,
        )
        if closing != opening:
            raise ArtifactVerificationError(
                "release bundle changed during signing preflight inventory"
            )
        session.seal()
        return _SigningPreflight(
            session.anchor_identity,
            gate_status,
            gate_review_codes,
            iso_names,
            existing_signatures,
        )
    finally:
        session.close()


def _same_bundle_anchor(
    first: ArtifactIdentity,
    second: StableParentIdentity | ArtifactIdentity,
) -> bool:
    first_stable: StableParentIdentity = (
        first.dev,
        first.ino,
        stat.S_IFMT(first.mode),
        first.uid,
        first.gid,
        first.nlink,
        first.rdev,
    )
    if isinstance(second, tuple):
        return (
            len(second) == 7
            and all(isinstance(item, int) for item in second)
            and first_stable == second
        )
    second_stable: StableParentIdentity = (
        second.dev,
        second.ino,
        stat.S_IFMT(second.mode),
        second.uid,
        second.gid,
        second.nlink,
        second.rdev,
    )
    return first_stable == second_stable


def _strict_signing_gate_status(
    gate: dict[str, object],
    *,
    expected_project: Path,
    expected_product_iso: Path | None,
    expected_product_output_dir: Path,
    session: ArtifactVerificationSession,
    inventory: _SigningInventory,
    iso_names: tuple[str, ...],
) -> tuple[str, tuple[str, ...]]:
    code_problem = release_gate_report_problem(
        gate,
        expected_project=expected_project,
        expected_iso=expected_product_iso,
        expected_iso_name=iso_names[0] if len(iso_names) == 1 else None,
        expected_output_dir=expected_product_output_dir,
    )
    if code_problem is not None:
        raise ArtifactVerificationError(
            f"RELEASE-GATE.json {code_problem}"
        )
    status = gate.get("status")
    if not isinstance(status, str) or status not in {
        "ready",
        "review",
        "blocked",
    }:
        raise ArtifactVerificationError("RELEASE-GATE.json has no strict aggregate status")
    blocked = gate.get("blocked")
    if not isinstance(blocked, bool) or blocked is not (status == "blocked"):
        raise ArtifactVerificationError("RELEASE-GATE.json blocked flag contradicts its status")
    raw_items = gate.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise ArtifactVerificationError(
            "RELEASE-GATE.json must contain non-empty typed item verdicts"
        )
    items: dict[str, dict[str, object]] = {}
    for raw_item in raw_items:
        if not isinstance(raw_item, dict):
            raise ArtifactVerificationError("RELEASE-GATE.json contains a non-object item verdict")
        code = raw_item.get("code")
        item_status = raw_item.get("status")
        detail = raw_item.get("detail")
        if (
            not isinstance(code, str)
            or not code
            or code in items
            or item_status not in {"ready", "review", "blocked"}
            or not isinstance(detail, str)
            or not detail
        ):
            raise ArtifactVerificationError(
                "RELEASE-GATE.json items require unique non-empty codes and "
                "strict status/detail strings"
            )
        items[code] = raw_item
    derived_status = (
        "blocked"
        if any(item["status"] == "blocked" for item in items.values())
        else "review"
        if any(item["status"] == "review" for item in items.values())
        else "ready"
    )
    if derived_status != status:
        raise ArtifactVerificationError("RELEASE-GATE.json aggregate contradicts its item verdicts")
    code_problem = release_gate_code_problem(set(items))
    if code_problem is not None:
        raise ArtifactVerificationError(
            f"RELEASE-GATE.json {code_problem}"
        )
    if len(iso_names) != 1:
        raise ArtifactVerificationError(
            f"release signing requires exactly one ISO, found {len(iso_names)}"
        )
    iso_name = iso_names[0]
    gate_iso = gate.get("iso")
    if (
        not isinstance(gate_iso, str)
        or not gate_iso
        or "\x00" in gate_iso
        or ".." in Path(gate_iso).parts
        or Path(gate_iso).name != iso_name
    ):
        raise ArtifactVerificationError(
            "RELEASE-GATE.json does not identify the unique bundled ISO"
        )
    iso_identity = inventory.by_name().get(iso_name)
    if iso_identity is None or not stat.S_ISREG(iso_identity.mode):
        raise ArtifactVerificationError("release signing ISO is not a regular file")
    iso_handle = session.file(
        Path(iso_name),
        label=f"release signing ISO {iso_name}",
    )
    if iso_handle.identity != iso_identity:
        raise ArtifactVerificationError("release signing ISO changed after bundle inventory")
    iso_digest = iso_handle.digest()
    iso_item = items.get("iso")
    sha_item = items.get("sha256")
    if (
        iso_item is None
        or iso_item.get("status") != "ready"
        or iso_item.get("detail") != f"{iso_identity.size} bytes"
        or sha_item is None
        or sha_item.get("status") != "ready"
        or sha_item.get("detail") != iso_digest
    ):
        raise ArtifactVerificationError(
            "RELEASE-GATE.json ISO/SHA256 items do not bind the bundled ISO"
        )
    sums_identity = inventory.by_name().get("SHA256SUMS")
    if sums_identity is None or not stat.S_ISREG(sums_identity.mode):
        raise ArtifactVerificationError("release signing requires one regular SHA256SUMS")
    sums_handle = session.file(
        Path("SHA256SUMS"),
        label="release signing SHA256SUMS",
        max_bytes=MAX_SHA256_SUMS_BYTES,
    )
    if sums_handle.identity != sums_identity:
        raise ArtifactVerificationError("SHA256SUMS changed after bundle inventory")
    sums = parse_sha256_sums(sums_handle.read_bytes())
    if set(sums) != {iso_name} or sums[iso_name] != iso_digest:
        raise ArtifactVerificationError("SHA256SUMS does not bind exactly the unique bundled ISO")
    review_codes = tuple(
        sorted(
            code
            for code, item in items.items()
            if item["status"] == "review"
        )
    )
    return status, review_codes


def release_gate_authorizes_executed_signing(
    status: str,
    review_codes: tuple[str, ...],
) -> bool:
    return status == "ready" or (
        status == "review"
        and review_codes == ("publish-signing",)
    )


def _capture_manifest_snapshot(
    bundle_dir: Path,
    *,
    expected_project: Path,
    expected_product_iso: Path | None,
    expected_product_output_dir: Path,
    expected_bundle_identity: ArtifactIdentity,
) -> _ManifestSnapshot:
    session = ArtifactVerificationSession(
        bundle_dir,
        label="release manifest snapshot",
        limits=_SIGNING_LIMITS,
    )
    try:
        if not _same_bundle_anchor(
            session.anchor_identity,
            expected_bundle_identity,
        ):
            raise ArtifactVerificationError(
                "release manifest bundle differs from the signing preflight anchor"
            )
        opening = _descriptor_tree_inventory(
            bundle_dir,
            expected_anchor=expected_bundle_identity,
        )
        _require_regular_inventory(opening)
        by_name = opening.by_name()
        existing_signatures = sorted(
            name
            for name, identity in opening.entries
            if stat.S_ISREG(identity.mode) and name.endswith(".asc")
        )
        if existing_signatures:
            raise ArtifactVerificationError(
                "existing detached signatures cannot be mixed into a new manifest: "
                + ", ".join(existing_signatures)
            )
        iso_names = tuple(
            sorted(
                name
                for name, identity in opening.entries
                if stat.S_ISREG(identity.mode) and name.endswith(".iso")
            )
        )
        gate_identity = by_name.get("RELEASE-GATE.json")
        if gate_identity is None or not stat.S_ISREG(gate_identity.mode):
            raise ArtifactVerificationError(
                "release manifest requires one regular RELEASE-GATE.json"
            )
        gate_handle = session.file(
            Path("RELEASE-GATE.json"),
            label="manifest release gate",
            max_bytes=_SIGNING_JSON_MAX_BYTES,
        )
        if gate_handle.identity != gate_identity:
            raise ArtifactVerificationError("RELEASE-GATE.json changed after manifest inventory")
        gate = gate_handle.json_object()
        gate_status, gate_review_codes = _strict_signing_gate_status(
            gate,
            expected_project=expected_project,
            expected_product_iso=expected_product_iso,
            expected_product_output_dir=expected_product_output_dir,
            session=session,
            inventory=opening,
            iso_names=iso_names,
        )

        entries: list[ReleaseManifestEntry] = []
        operational_names: list[str] = []
        for name, identity in opening.entries:
            if _manifest_excluded(name):
                if not stat.S_ISREG(identity.mode):
                    raise ArtifactVerificationError(
                        f"operational release artifact is not regular: {name}"
                    )
                operational_names.append(name)
                continue
            if not stat.S_ISREG(identity.mode):
                continue
            handle = session.file(
                Path(name),
                label=f"release manifest artifact {name}",
                max_bytes=_SIGNING_LIMITS.max_file_bytes,
                allow_empty=True,
            )
            if handle.identity != identity:
                raise ArtifactVerificationError(
                    f"release manifest artifact changed after inventory: {name}"
                )
            entries.append(
                ReleaseManifestEntry(
                    name,
                    handle.identity.size,
                    handle.digest(),
                )
            )
        snapshot = _ManifestSnapshot(
            expected_bundle_identity,
            tuple(entries),
            gate_status,
            gate_review_codes,
            tuple(
                sorted(
                    {
                        *operational_names,
                        "RELEASE-MANIFEST.json",
                    }
                )
            ),
        )
        _require_exact_snapshot_inventory(
            opening,
            snapshot,
            operational_names=tuple(sorted(operational_names)),
            signature_names=(),
        )
        closing = _descriptor_tree_inventory(
            bundle_dir,
            expected_anchor=expected_bundle_identity,
        )
        if closing != opening:
            raise ArtifactVerificationError(
                "release bundle changed while its manifest snapshot was captured"
            )
        session.seal()
        return snapshot
    finally:
        session.close()


def _manifest_content(
    project: Project,
    bundle_dir: Path,
    gate_status: str,
    entries: tuple[ReleaseManifestEntry, ...],
) -> str:
    return (
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
        + "\n"
    )


def _verify_manifest_publication_snapshot(
    bundle_dir: Path,
    snapshot: _ManifestSnapshot,
    *,
    expected_bundle_identity: ArtifactIdentity,
) -> None:
    session = ArtifactVerificationSession(
        bundle_dir,
        label="published release manifest snapshot",
        limits=_SIGNING_LIMITS,
    )
    try:
        if not _same_bundle_anchor(
            session.anchor_identity,
            expected_bundle_identity,
        ):
            raise ArtifactVerificationError(
                "published release manifest bundle differs from the signing preflight anchor"
            )
        if not _same_bundle_anchor(
            snapshot.anchor_identity,
            expected_bundle_identity,
        ):
            raise ArtifactVerificationError(
                "release manifest snapshot lost the signing preflight anchor"
            )
        opening = _descriptor_tree_inventory(
            bundle_dir,
            expected_anchor=expected_bundle_identity,
        )
        _require_regular_inventory(opening)
        _require_exact_snapshot_inventory(
            opening,
            snapshot,
            operational_names=snapshot.operational_names,
            signature_names=(),
        )
        handles = _bind_manifest_snapshot(session, opening, snapshot.entries)
        manifest_handle = session.file(
            Path("RELEASE-MANIFEST.json"),
            label="published release manifest",
            max_bytes=_SIGNING_JSON_MAX_BYTES,
        )
        _require_manifest_payload(
            manifest_handle,
            snapshot,
            handles.get("RELEASE-GATE.json"),
        )
        closing = _descriptor_tree_inventory(
            bundle_dir,
            expected_anchor=expected_bundle_identity,
        )
        if closing != opening:
            raise ArtifactVerificationError(
                "published release manifest snapshot changed during validation"
            )
        session.seal()
    finally:
        session.close()


def _stage_descriptor_bound_signatures(
    runner: CommandRunner,
    bundle_dir: Path,
    staging: Path,
    snapshot: _ManifestSnapshot,
    signer_fingerprint: str,
    keyring_digest: str | None,
) -> tuple[_StagedSignature, ...]:
    if keyring_digest is None:
        raise ArtifactVerificationError("descriptor-bound signing has no validated keyring digest")
    session = ArtifactVerificationSession(
        bundle_dir,
        label="release signature input snapshot",
        limits=_SIGNING_LIMITS,
    )
    staged: list[_StagedSignature] = []
    try:
        if not _same_bundle_anchor(
            session.anchor_identity,
            snapshot.anchor_identity,
        ):
            raise ArtifactVerificationError(
                "release signature input bundle differs from the signing preflight anchor"
            )
        opening = _descriptor_tree_inventory(
            bundle_dir,
            expected_anchor=snapshot.anchor_identity,
        )
        _require_regular_inventory(opening)
        _require_exact_snapshot_inventory(
            opening,
            snapshot,
            operational_names=snapshot.operational_names,
            signature_names=(),
        )
        handles = _bind_manifest_snapshot(session, opening, snapshot.entries)
        manifest_handle = session.file(
            Path("RELEASE-MANIFEST.json"),
            label="signed release manifest",
            max_bytes=_SIGNING_JSON_MAX_BYTES,
        )
        _require_manifest_payload(
            manifest_handle,
            snapshot,
            handles.get("RELEASE-GATE.json"),
        )
        handles["RELEASE-MANIFEST.json"] = manifest_handle
        keyring_handle = handles.get(SIGNING_KEYRING)
        if keyring_handle is None or keyring_handle.digest() != keyring_digest:
            raise ArtifactVerificationError(
                "validated signing keyring differs from the manifest snapshot"
            )
        for name in SIGN_TARGETS:
            payload = handles.get(name)
            if payload is None:
                raise ArtifactVerificationError(
                    f"required signing target is missing from the held snapshot: {name}"
                )
            signature_name = f"{name}.asc"
            signature_path = staging / signature_name
            try:
                signature_path.lstat()
            except FileNotFoundError:
                pass
            else:
                raise ArtifactVerificationError(
                    f"signature staging target already exists: {signature_name}"
                )
            result = runner.run(
                CommandSpec(
                    argv=(
                        "gpg",
                        "--batch",
                        "--no-options",
                        "--status-fd",
                        "1",
                        "--armor",
                        "--detach-sign",
                        "--local-user",
                        signer_fingerprint,
                        "--output",
                        str(signature_path),
                        f"/proc/self/fd/{payload.fileno}",
                    ),
                    description=f"Sign release file {name}",
                    pass_fds=(payload.fileno,),
                ),
                check=False,
            )
            if result.returncode != 0:
                raise ValueError(f"{name} failed GPG signing")
            signature_fd, signature_identity = _open_regular_file_nofollow(
                signature_path,
                max_bytes=_SIGNING_JSON_MAX_BYTES,
                label=signature_name,
            )
            try:
                verify_detached_signature(
                    runner,
                    signature_path,
                    bundle_dir / name,
                    bundle_dir / SIGNING_KEYRING,
                    signer_fingerprint,
                    signature_fd=signature_fd,
                    payload_fd=payload.fileno,
                    keyring_fd=keyring_handle.fileno,
                )
                if ArtifactIdentity.from_stat(os.fstat(signature_fd)) != signature_identity:
                    raise ArtifactVerificationError(
                        f"staged signature changed during verification: {signature_name}"
                    )
            except BaseException:
                os.close(signature_fd)
                raise
            staged.append(
                _StagedSignature(
                    signature_name,
                    signature_fd,
                    signature_identity,
                    _descriptor_sha256(signature_fd, signature_identity),
                )
            )
        closing = _descriptor_tree_inventory(
            bundle_dir,
            expected_anchor=snapshot.anchor_identity,
        )
        if closing != opening:
            raise ArtifactVerificationError(
                "release signing inputs changed while GPG consumed their descriptors"
            )
        session.seal()
        return tuple(staged)
    except BaseException:
        for signature in staged:
            try:
                os.close(signature.descriptor)
            except OSError:
                pass
        raise
    finally:
        session.close()


def _publish_signature_set(
    bundle_dir: Path,
    snapshot: _ManifestSnapshot,
    staged_signatures: tuple[_StagedSignature, ...],
    published: list[_OwnedRegularFile],
) -> None:
    for staged_signature in staged_signatures:
        try:
            receipt = copy_immutable_file_descriptor(
                staged_signature.descriptor,
                bundle_dir / staged_signature.name,
                expected_parent_identity=snapshot.anchor_identity,
            )
        except BaseException:
            # A lower layer can report a late fsync failure after the no-replace
            # link became visible.  Retain a descriptor only when the visible
            # leaf still reproduces the staged bytes; rollback will additionally
            # bind removal to this inode.
            try:
                owned = _hold_published_signature(
                    bundle_dir,
                    staged_signature,
                    expected_bundle_identity=snapshot.anchor_identity,
                )
            except (ArtifactVerificationError, OSError):
                pass
            else:
                published.append(owned)
            raise
        if (
            receipt.size != staged_signature.identity.size
            or receipt.sha256 != staged_signature.sha256
        ):
            raise ArtifactVerificationError(
                f"published signature receipt differs from its staged descriptor: "
                f"{staged_signature.name}"
            )
        published.append(
            _hold_published_signature(
                bundle_dir,
                staged_signature,
                expected_bundle_identity=snapshot.anchor_identity,
            )
        )
        inventory = _descriptor_tree_inventory(
            bundle_dir,
            expected_anchor=snapshot.anchor_identity,
        )
        _require_regular_inventory(inventory)
        _require_exact_snapshot_inventory(
            inventory,
            snapshot,
            operational_names=snapshot.operational_names,
            signature_names=tuple(item.name for item in published),
        )


def _hold_published_signature(
    bundle_dir: Path,
    staged_signature: _StagedSignature,
    *,
    expected_bundle_identity: ArtifactIdentity,
) -> _OwnedRegularFile:
    directory_fd, directory_identity = _open_absolute_directory_nofollow(bundle_dir)
    if not _same_bundle_anchor(
        directory_identity,
        expected_bundle_identity,
    ):
        os.close(directory_fd)
        raise ArtifactVerificationError(
            "published detached signature bundle differs from the signing preflight anchor"
        )
    try:
        descriptor, identity = _open_regular_file_at_nofollow(
            directory_fd,
            staged_signature.name,
            max_bytes=_SIGNING_JSON_MAX_BYTES,
            label=f"published detached signature {staged_signature.name}",
        )
    finally:
        os.close(directory_fd)
    try:
        digest = _descriptor_sha256(descriptor, identity)
        if identity.size != staged_signature.identity.size or digest != staged_signature.sha256:
            raise ArtifactVerificationError(
                f"published detached signature differs from its staged descriptor: "
                f"{staged_signature.name}"
            )
        return _OwnedRegularFile(
            staged_signature.name,
            descriptor,
            identity,
            digest,
        )
    except BaseException:
        os.close(descriptor)
        raise


def _verify_published_signature_snapshot(
    runner: CommandRunner,
    bundle_dir: Path,
    snapshot: _ManifestSnapshot,
    signer_fingerprint: str,
    keyring_digest: str | None,
) -> None:
    if keyring_digest is None:
        raise ArtifactVerificationError("published signatures have no validated keyring digest")
    session = ArtifactVerificationSession(
        bundle_dir,
        label="published release signature snapshot",
        limits=_SIGNING_LIMITS,
    )
    try:
        if not _same_bundle_anchor(
            session.anchor_identity,
            snapshot.anchor_identity,
        ):
            raise ArtifactVerificationError(
                "published signature bundle differs from the signing preflight anchor"
            )
        opening = _descriptor_tree_inventory(
            bundle_dir,
            expected_anchor=snapshot.anchor_identity,
        )
        _require_regular_inventory(opening)
        required_signatures = tuple(f"{name}.asc" for name in SIGN_TARGETS)
        _require_exact_snapshot_inventory(
            opening,
            snapshot,
            operational_names=snapshot.operational_names,
            signature_names=required_signatures,
        )
        handles = _bind_manifest_snapshot(session, opening, snapshot.entries)
        manifest_handle = session.file(
            Path("RELEASE-MANIFEST.json"),
            label="published signed release manifest",
            max_bytes=_SIGNING_JSON_MAX_BYTES,
        )
        _require_manifest_payload(
            manifest_handle,
            snapshot,
            handles.get("RELEASE-GATE.json"),
        )
        handles["RELEASE-MANIFEST.json"] = manifest_handle
        keyring_handle = handles.get(SIGNING_KEYRING)
        if keyring_handle is None or keyring_handle.digest() != keyring_digest:
            raise ArtifactVerificationError(
                "published verification keyring differs from its validated snapshot"
            )
        for name in SIGN_TARGETS:
            payload = handles.get(name)
            if payload is None:
                raise ArtifactVerificationError(f"published signing target is missing: {name}")
            signature_name = f"{name}.asc"
            signature = session.file(
                Path(signature_name),
                label=f"published detached signature {signature_name}",
                max_bytes=_SIGNING_JSON_MAX_BYTES,
            )
            verify_detached_signature(
                runner,
                bundle_dir / signature_name,
                bundle_dir / name,
                bundle_dir / SIGNING_KEYRING,
                signer_fingerprint,
                signature_fd=signature.fileno,
                payload_fd=payload.fileno,
                keyring_fd=keyring_handle.fileno,
            )
        closing = _descriptor_tree_inventory(
            bundle_dir,
            expected_anchor=snapshot.anchor_identity,
        )
        if closing != opening:
            raise ArtifactVerificationError(
                "published signing snapshot changed during final verification"
            )
        session.seal()
    finally:
        session.close()


def _bind_manifest_snapshot(
    session: ArtifactVerificationSession,
    inventory: _SigningInventory,
    entries: tuple[ReleaseManifestEntry, ...],
) -> dict[str, ArtifactHandle]:
    by_name = inventory.by_name()
    handles: dict[str, ArtifactHandle] = {}
    for entry in entries:
        identity = by_name.get(entry.name)
        if identity is None or not stat.S_ISREG(identity.mode):
            raise ArtifactVerificationError(
                f"manifest-bound signing artifact is missing: {entry.name}"
            )
        handle = session.file(
            Path(entry.name),
            label=f"manifest-bound signing artifact {entry.name}",
            max_bytes=_SIGNING_LIMITS.max_file_bytes,
            allow_empty=True,
        )
        if entry.name == "RELEASE-GATE.json":
            handle.json_object()
        if (
            handle.identity != identity
            or handle.identity.size != entry.size
            or handle.digest() != entry.sha256
        ):
            raise ArtifactVerificationError(
                f"manifest-bound signing artifact changed: {entry.name}"
            )
        handles[entry.name] = handle
    return handles


def _require_manifest_payload(
    handle: ArtifactHandle,
    snapshot: _ManifestSnapshot,
    gate_handle: ArtifactHandle | None,
) -> None:
    manifest = handle.json_object()
    if (
        snapshot.manifest_size is None
        or snapshot.manifest_sha256 is None
        or handle.identity.size != snapshot.manifest_size
        or handle.digest() != snapshot.manifest_sha256
    ):
        raise ArtifactVerificationError(
            "published RELEASE-MANIFEST.json differs from its durable publication receipt"
        )
    if manifest.get("files") != [
        entry.to_dict() for entry in snapshot.entries
    ]:
        raise ArtifactVerificationError(
            "published RELEASE-MANIFEST.json does not reproduce the held snapshot"
        )
    if gate_handle is None:
        raise ArtifactVerificationError("published RELEASE-MANIFEST.json has no held release gate")
    gate = gate_handle.json_object()
    gate_status = gate.get("status")
    if (
        gate_status
        not in {
            "ready",
            "review",
            "blocked",
        }
        or manifest.get("gate_status") != gate_status
    ):
        raise ArtifactVerificationError(
            "published RELEASE-MANIFEST.json gate status differs from the held RELEASE-GATE.json"
        )


def _require_exact_snapshot_inventory(
    inventory: _SigningInventory,
    snapshot: _ManifestSnapshot,
    *,
    operational_names: tuple[str, ...],
    signature_names: tuple[str, ...],
) -> None:
    manifest_names = {entry.name for entry in snapshot.entries}
    operational = set(operational_names)
    signatures = set(signature_names)
    if not operational <= OPERATIONAL_BUNDLE_FILES:
        raise ArtifactVerificationError(
            "release signing snapshot contains an unnamed operational artifact"
        )
    allowed_signatures = {f"{target}.asc" for target in SIGN_TARGETS}
    if not signatures <= allowed_signatures:
        raise ArtifactVerificationError(
            "release signing snapshot contains an unexpected detached signature"
        )
    parents: set[str] = set()
    for name in (*manifest_names, *operational, *signatures):
        relative = Path(name)
        if (
            relative.is_absolute()
            or relative == Path(".")
            or relative.as_posix() != name
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ArtifactVerificationError(
                f"release signing snapshot contains an unsafe path: {name!r}"
            )
        for parent in relative.parents:
            if parent == Path("."):
                break
            parents.add(parent.as_posix())
    expected = manifest_names | operational | signatures | parents
    by_name = inventory.by_name()
    actual = set(by_name)
    unexpected = sorted(actual - expected)
    missing = sorted(expected - actual)
    if unexpected or missing:
        details: list[str] = []
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        if missing:
            details.append("missing " + ", ".join(missing))
        raise ArtifactVerificationError(
            "release signing inventory is not exact: " + "; ".join(details)
        )
    for name in manifest_names | operational | signatures:
        if not stat.S_ISREG(by_name[name].mode):
            raise ArtifactVerificationError(
                f"release signing snapshot requires a regular file: {name}"
            )
    for name in parents:
        if not stat.S_ISDIR(by_name[name].mode):
            raise ArtifactVerificationError(
                f"release signing snapshot requires a parent directory: {name}"
            )


def _manifest_excluded(name: str) -> bool:
    return name in _MANIFEST_EXCLUDED or name.endswith(".asc")


def _require_regular_inventory(inventory: _SigningInventory) -> None:
    for name, identity in inventory.entries:
        if any(
            part.startswith(".")
            and (".cleanup-" in part or ".tmp-" in part)
            for part in Path(name).parts
        ):
            raise ArtifactVerificationError(
                "release bundle contains an internal temporary or quarantine "
                f"entry: {name}"
            )
        if stat.S_ISDIR(identity.mode) or stat.S_ISREG(identity.mode):
            continue
        raise ArtifactVerificationError(
            f"release bundle contains a symlink or special entry: {name}"
        )


def _descriptor_tree_inventory(
    directory: Path,
    *,
    expected_anchor: StableParentIdentity | ArtifactIdentity | None = None,
) -> _SigningInventory:
    if _SIGNING_INVENTORY_MAX_ENTRIES > _SIGNING_LIMITS.max_open_files:
        raise ArtifactVerificationError(
            "release signing inventory entry limit exceeds its descriptor-session open-file budget"
        )
    descriptor, opening_identity = _open_absolute_directory_nofollow(directory)
    entries: dict[str, ArtifactIdentity] = {}
    counter = [0]
    try:
        if expected_anchor is not None and not _same_bundle_anchor(
            opening_identity,
            expected_anchor,
        ):
            raise ArtifactVerificationError(
                "release signing inventory differs from the signing preflight anchor"
            )
        _inventory_directory_descriptor(
            descriptor,
            Path(),
            entries,
            counter,
            depth=0,
        )
        if ArtifactIdentity.from_stat(os.fstat(descriptor)) != opening_identity:
            raise ArtifactVerificationError(
                "release signing bundle anchor changed during inventory"
            )
        closing_descriptor, closing_identity = _open_absolute_directory_nofollow(directory)
        try:
            if closing_identity != opening_identity:
                raise ArtifactVerificationError(
                    "release signing bundle path changed during inventory"
                )
        finally:
            os.close(closing_descriptor)
    finally:
        os.close(descriptor)
    return _SigningInventory(
        opening_identity,
        tuple(sorted(entries.items())),
    )


def _inventory_directory_descriptor(
    directory_fd: int,
    prefix: Path,
    entries: dict[str, ArtifactIdentity],
    counter: list[int],
    *,
    depth: int,
) -> None:
    if depth > _SIGNING_LIMITS.max_path_components:
        raise ArtifactVerificationError("release signing inventory exceeds its path-depth limit")
    opening_identity = ArtifactIdentity.from_stat(os.fstat(directory_fd))
    names: list[str] = []
    with os.scandir(directory_fd) as iterator:
        for entry in iterator:
            counter[0] += 1
            if counter[0] > _SIGNING_INVENTORY_MAX_ENTRIES:
                raise ArtifactVerificationError(
                    "release signing bundle exceeds its inventory entry limit"
                )
            names.append(_strict_filesystem_name(entry.name))
    names.sort()
    immediate: dict[str, ArtifactIdentity] = {}
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    for name in names:
        identity = ArtifactIdentity.from_stat(
            os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        )
        relative = prefix / name
        relative_name = relative.as_posix()
        entries[relative_name] = identity
        immediate[name] = identity
        if not stat.S_ISDIR(identity.mode):
            continue
        child_fd = os.open(
            name,
            directory_flags,
            dir_fd=directory_fd,
        )
        try:
            if ArtifactIdentity.from_stat(os.fstat(child_fd)) != identity:
                raise ArtifactVerificationError(
                    f"release signing directory changed while opening: {relative_name}"
                )
            _inventory_directory_descriptor(
                child_fd,
                relative,
                entries,
                counter,
                depth=depth + 1,
            )
            if ArtifactIdentity.from_stat(os.fstat(child_fd)) != identity:
                raise ArtifactVerificationError(
                    f"release signing directory changed during inventory: {relative_name}"
                )
        finally:
            os.close(child_fd)
    for name, expected in immediate.items():
        current = ArtifactIdentity.from_stat(
            os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        )
        if current != expected:
            raise ArtifactVerificationError(
                f"release signing inventory entry changed during traversal: {name}"
            )
    if ArtifactIdentity.from_stat(os.fstat(directory_fd)) != opening_identity:
        raise ArtifactVerificationError(
            f"release signing directory changed during traversal: {prefix or '.'}"
        )


def _open_absolute_directory_nofollow(
    directory: Path,
) -> tuple[int, ArtifactIdentity]:
    absolute = Path(os.path.abspath(directory))
    if "\x00" in str(directory) or ".." in directory.parts:
        raise ArtifactVerificationError(
            f"release signing directory path is not canonical: {directory}"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open("/", flags)
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        identity = ArtifactIdentity.from_stat(os.fstat(descriptor))
        if not stat.S_ISDIR(identity.mode):
            raise ArtifactVerificationError(
                f"release signing bundle is not a directory: {directory}"
            )
        return descriptor, identity
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _strict_filesystem_name(value: str) -> str:
    if value in {"", ".", ".."} or "/" in value or "\x00" in value:
        raise ArtifactVerificationError(
            f"release signing bundle contains an unsafe entry name: {value!r}"
        )
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ArtifactVerificationError(
            "release signing bundle contains a non-UTF-8 entry name"
        ) from exc
    return value


def _open_regular_file_nofollow(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> tuple[int, ArtifactIdentity]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        identity = ArtifactIdentity.from_stat(os.fstat(descriptor))
        if not stat.S_ISREG(identity.mode) or identity.size <= 0 or identity.size > max_bytes:
            raise ArtifactVerificationError(f"{label} is not a bounded non-empty regular file")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _open_regular_file_at_nofollow(
    directory_fd: int,
    name: str,
    *,
    max_bytes: int,
    label: str,
) -> tuple[int, ArtifactIdentity]:
    _strict_filesystem_name(name)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        identity = ArtifactIdentity.from_stat(os.fstat(descriptor))
        if not stat.S_ISREG(identity.mode) or identity.size <= 0 or identity.size > max_bytes:
            raise ArtifactVerificationError(f"{label} is not a bounded non-empty regular file")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _descriptor_sha256(
    descriptor: int,
    expected: ArtifactIdentity,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < expected.size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, expected.size - offset),
            offset,
        )
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    if offset != expected.size or ArtifactIdentity.from_stat(os.fstat(descriptor)) != expected:
        raise ArtifactVerificationError("staged signature changed while its digest was measured")
    return digest.hexdigest()


def _rollback_signature_set(
    bundle_dir: Path,
    published: tuple[_OwnedRegularFile, ...],
    *,
    expected_bundle_identity: ArtifactIdentity,
) -> str | None:
    if not published:
        return None
    try:
        directory_fd, directory_identity = _open_absolute_directory_nofollow(bundle_dir)
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        return (
            "Detached signature rollback was refused because the bundle anchor "
            f"could not be reopened: {exc}"
        )
    if not _same_bundle_anchor(
        directory_identity,
        expected_bundle_identity,
    ):
        os.close(directory_fd)
        return (
            "Detached signature rollback was refused because the bundle path "
            "no longer names the signing preflight anchor."
        )
    problems: list[str] = []
    try:
        for signature in reversed(published):
            try:
                _remove_owned_regular_name(
                    directory_fd,
                    signature,
                    label=f"detached signature {signature.name}",
                )
            except (ArtifactVerificationError, OSError, ValueError) as exc:
                problems.append(f"{signature.name} rollback refused: {exc}")
    finally:
        os.close(directory_fd)
    if problems:
        return "Detached signature rollback was incomplete: " + "; ".join(problems)
    return None


def _remove_owned_regular_name(
    directory_fd: int,
    owned: _OwnedRegularFile,
    *,
    label: str,
) -> None:
    held_identity = ArtifactIdentity.from_stat(os.fstat(owned.descriptor))
    if (
        held_identity.dev != owned.identity.dev
        or held_identity.ino != owned.identity.ino
        or stat.S_IFMT(held_identity.mode) != stat.S_IFMT(owned.identity.mode)
        or held_identity.uid != owned.identity.uid
        or held_identity.gid != owned.identity.gid
        or held_identity.rdev != owned.identity.rdev
        or held_identity.size != owned.identity.size
        or held_identity.mtime_ns != owned.identity.mtime_ns
        or not stat.S_ISREG(held_identity.mode)
        or _descriptor_sha256(owned.descriptor, held_identity) != owned.sha256
    ):
        raise ArtifactVerificationError(f"{label} held descriptor changed before cleanup")
    quarantine_name = f".{owned.name}.cleanup-{uuid.uuid4().hex}"
    _rename_directory_noreplace(
        directory_fd,
        owned.name,
        quarantine_name,
    )
    quarantine_fd = -1
    try:
        quarantine_fd = os.open(
            quarantine_name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
        quarantine_identity = ArtifactIdentity.from_stat(os.fstat(quarantine_fd))
        held_after_rename = ArtifactIdentity.from_stat(os.fstat(owned.descriptor))
        if (
            quarantine_identity != held_after_rename
            or quarantine_identity.dev != owned.identity.dev
            or quarantine_identity.ino != owned.identity.ino
            or not stat.S_ISREG(quarantine_identity.mode)
            or _descriptor_sha256(quarantine_fd, quarantine_identity) != owned.sha256
        ):
            _restore_quarantined_regular_name(
                directory_fd,
                quarantine_name,
                owned.name,
            )
            raise ArtifactVerificationError(
                f"{label} pathname no longer identifies the held owned inode"
            )
        # POSIX has no atomic unlink-by-held-file-descriptor operation.  A final
        # stat(name) followed by unlink(name) would therefore reopen a race in
        # which a substituted inode could be deleted.  Removing the operational
        # signature name through an identity-checked no-replace rename is the
        # terminal safe state: retain the proven inode under its unpredictable
        # quarantine name and never unlink by name here.
        os.fsync(directory_fd)
        raise ArtifactVerificationError(
            f"{label} was retained safely as {quarantine_name}; "
            "rollback requires maintainer cleanup"
        )
    except BaseException:
        if quarantine_fd < 0:
            try:
                _restore_quarantined_regular_name(
                    directory_fd,
                    quarantine_name,
                    owned.name,
                )
            except BaseException:
                pass
        raise
    finally:
        if quarantine_fd >= 0:
            os.close(quarantine_fd)


def _restore_quarantined_regular_name(
    directory_fd: int,
    quarantine_name: str,
    original_name: str,
) -> None:
    _rename_directory_noreplace(
        directory_fd,
        quarantine_name,
        original_name,
    )
    os.fsync(directory_fd)


def _close_owned_regular_files(files: tuple[_OwnedRegularFile, ...]) -> None:
    for item in files:
        try:
            os.close(item.descriptor)
        except OSError:
            pass


def _publish_or_reuse_verification_keyring(
    staged_keyring_fd: int,
    keyring_path: Path,
    expected: ImmutableCopyReceipt,
    *,
    expected_bundle_identity: ArtifactIdentity,
) -> ImmutableCopyReceipt:
    try:
        return copy_immutable_file_descriptor(
            staged_keyring_fd,
            keyring_path,
            expected_parent_identity=expected_bundle_identity,
        )
    except FileExistsError:
        session = ArtifactVerificationSession(
            keyring_path.parent,
            label="existing release verification keyring",
            limits=ArtifactLimits(
                max_open_files=4,
                max_file_bytes=_SIGNING_KEYRING_MAX_BYTES,
                max_buffered_bytes=_SIGNING_KEYRING_MAX_BYTES,
                max_hashed_bytes=2 * _SIGNING_KEYRING_MAX_BYTES,
                max_json_nodes=1,
                max_closing_fds=32,
            ),
        )
        try:
            if not _same_bundle_anchor(
                session.anchor_identity,
                expected_bundle_identity,
            ):
                raise ArtifactVerificationError(
                    "existing release verification keyring bundle differs from "
                    "the signing preflight anchor"
                )
            handle = session.file(
                Path(keyring_path.name),
                label="existing sealed release verification keyring",
                max_bytes=_SIGNING_KEYRING_MAX_BYTES,
            )
            if handle.identity.size != expected.size or handle.digest() != expected.sha256:
                raise ArtifactVerificationError(
                    f"{SIGNING_KEYRING} already exists with a different identity; "
                    "refuse replacement"
                )
            session.seal()
            return expected
        finally:
            session.close()


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
    *,
    signature_fd: int | None = None,
    payload_fd: int | None = None,
    keyring_fd: int | None = None,
) -> tuple[str, ...]:
    """Verify only the pinned keyring and require a matching machine VALIDSIG.

    Optional descriptors bind GPG to already-held artifact inodes.  Their original
    offsets are untouched; the child receives explicit ``/proc/self/fd`` paths and
    only the matching descriptors through ``pass_fds``.
    """
    expected = full_fingerprint(expected_fingerprint)
    if expected is None:
        raise ValueError("the expected signer is not a complete OpenPGP fingerprint")
    if keyring_fd is None and (keyring.is_symlink() or not keyring.is_file()):
        raise ValueError("the explicit verification keyring is missing or unsafe")
    with owned_temporary_directory(
        prefix="distroforge-gpg-verify-"
    ) as home:
        isolated_keyring = home / "trustedkeys.gpg"
        if keyring_fd is None:
            copy_immutable_file(keyring, isolated_keyring)
        else:
            copy_immutable_file_descriptor(keyring_fd, isolated_keyring)
        signature_argument = (
            f"/proc/self/fd/{signature_fd}" if signature_fd is not None else str(signature)
        )
        payload_argument = f"/proc/self/fd/{payload_fd}" if payload_fd is not None else str(payload)
        pass_fds = tuple(
            sorted(
                {descriptor for descriptor in (signature_fd, payload_fd) if descriptor is not None}
            )
        )
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
                    signature_argument,
                    payload_argument,
                ),
                description=f"Verify release signature {signature.name}",
                pass_fds=pass_fds,
            ),
            check=False,
        )
    seen = validsig_fingerprints(result.stdout)
    if result.returncode != 0:
        raise ValueError(f"{signature.name} failed GPG verification")
    if not seen:
        raise ValueError(f"{signature.name} produced no VALIDSIG status")
    if expected not in seen:
        raise ValueError(f"{signature.name} was signed by {', '.join(seen)}, not {expected}")
    return seen


def _prepare_verification_keyring(
    runner: CommandRunner,
    signer_fingerprint: str,
    source_keyring: Path,
    staged_keyring: Path,
) -> _StagedKeyring:
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
        raise ValueError(f"no secret primary key exactly matches {signer_fingerprint}")
    source_absolute = Path(os.path.abspath(source_keyring))
    session = ArtifactVerificationSession(
        source_absolute.parent,
        label="release signing source keyring",
        limits=ArtifactLimits(
            max_open_files=4,
            max_file_bytes=_SIGNING_KEYRING_MAX_BYTES,
            max_buffered_bytes=_SIGNING_KEYRING_MAX_BYTES,
            max_hashed_bytes=2 * _SIGNING_KEYRING_MAX_BYTES,
            max_json_nodes=1,
            max_closing_fds=512,
        ),
    )
    try:
        source_handle = session.file(
            Path(source_absolute.name),
            label="explicit release verification keyring",
            max_bytes=_SIGNING_KEYRING_MAX_BYTES,
        )
        with owned_temporary_directory(
            prefix="distroforge-gpg-keyring-import-"
        ) as home:
            imported = runner.run(
                CommandSpec(
                    argv=(
                        "gpg",
                        "--batch",
                        "--no-options",
                        "--homedir",
                        str(home),
                        "--status-fd",
                        "1",
                        "--import",
                        f"/proc/self/fd/{source_handle.fileno}",
                    ),
                    description="Import held release verification key material",
                    pass_fds=(source_handle.fileno,),
                ),
                check=False,
            )
            if imported.returncode != 0:
                raise ValueError("the explicit verification keyring could not be imported")
            imported_listing = runner.run(
                CommandSpec(
                    argv=(
                        "gpg",
                        "--batch",
                        "--no-options",
                        "--homedir",
                        str(home),
                        "--with-colons",
                        "--fingerprint",
                        "--list-keys",
                    ),
                    description="Inspect imported release verification keys",
                ),
                check=False,
            )
            if imported_listing.returncode != 0 or signer_fingerprint not in _primary_fingerprints(
                imported_listing.stdout, "pub"
            ):
                raise ValueError(
                    "the supplied verification keyring must contain only the pinned primary key"
                )
            exported = runner.run(
                CommandSpec(
                    argv=(
                        "gpg",
                        "--batch",
                        "--no-options",
                        "--homedir",
                        str(home),
                        "--output",
                        str(staged_keyring),
                        "--export-options",
                        "export-minimal",
                        "--export",
                        signer_fingerprint,
                    ),
                    description="Export minimal public release verification keyring",
                ),
                check=False,
            )
            if exported.returncode != 0:
                raise ValueError("the pinned public release verification key could not be exported")
        session.seal()
    finally:
        session.close()
    staged_session = ArtifactVerificationSession(
        Path(os.path.abspath(staged_keyring.parent)),
        label="staged release verification keyring",
        limits=ArtifactLimits(
            max_open_files=4,
            max_file_bytes=_SIGNING_KEYRING_MAX_BYTES,
            max_buffered_bytes=_SIGNING_KEYRING_MAX_BYTES,
            max_hashed_bytes=2 * _SIGNING_KEYRING_MAX_BYTES,
            max_json_nodes=1,
            max_closing_fds=32,
        ),
    )
    try:
        staged_handle = staged_session.file(
            Path(staged_keyring.name),
            label="staged release verification keyring",
            max_bytes=_SIGNING_KEYRING_MAX_BYTES,
        )
        receipt = ImmutableCopyReceipt(
            staged_handle.identity.size,
            staged_handle.digest(),
        )
        public_fingerprints = _isolated_keyring_fingerprints(
            runner,
            staged_keyring,
            keyring_fd=staged_handle.fileno,
        )
        if public_fingerprints != (signer_fingerprint,):
            raise ValueError(
                "the supplied verification keyring must contain only the pinned primary key"
            )
        keyring_records = _isolated_keyring_record_types(
            runner,
            staged_keyring,
            keyring_fd=staged_handle.fileno,
        )
        if {"sec", "ssb"} & set(keyring_records):
            raise ArtifactVerificationError(
                "the staged release verification keyring contains secret key packets"
            )
        return _StagedKeyring(staged_session, staged_handle, receipt)
    except BaseException:
        staged_session.close()
        raise


def _isolated_keyring_fingerprints(
    runner: CommandRunner,
    keyring_path: Path,
    *,
    keyring_fd: int | None = None,
) -> tuple[str, ...]:
    listing = _show_keyring_packets(
        runner,
        keyring_path,
        keyring_fd=keyring_fd,
    )
    if listing.returncode != 0:
        return ()
    return _primary_fingerprints(listing.stdout, "pub")


def _isolated_keyring_record_types(
    runner: CommandRunner,
    keyring_path: Path,
    *,
    keyring_fd: int | None = None,
) -> tuple[str, ...]:
    listing = _show_keyring_packets(
        runner,
        keyring_path,
        keyring_fd=keyring_fd,
    )
    if listing.returncode != 0:
        raise ValueError("the staged release verification keyring cannot be parsed")
    return tuple(
        fields[0]
        for line in listing.stdout.splitlines()
        if (fields := line.split(":")) and fields[0]
    )


def _show_keyring_packets(
    runner: CommandRunner,
    keyring_path: Path,
    *,
    keyring_fd: int | None,
) -> CommandResult:
    owned_descriptor = -1
    if keyring_fd is None:
        owned_descriptor, _identity = _open_regular_file_nofollow(
            keyring_path,
            max_bytes=_SIGNING_KEYRING_MAX_BYTES,
            label="release verification keyring",
        )
        keyring_fd = owned_descriptor
    try:
        return runner.run(
            CommandSpec(
                argv=(
                    "gpg",
                    "--batch",
                    "--no-options",
                    "--with-colons",
                    "--fingerprint",
                    "--import-options",
                    "show-only",
                    "--dry-run",
                    "--import",
                    f"/proc/self/fd/{keyring_fd}",
                ),
                description="Inspect held release verification keyring packets",
                pass_fds=(keyring_fd,),
            ),
            check=False,
        )
    finally:
        if owned_descriptor >= 0:
            os.close(owned_descriptor)


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
