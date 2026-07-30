from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .artifact_verification import (
    ArtifactHandle,
    ArtifactIdentity,
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .command import CommandError, CommandRunner
from .evidence_run import StableParentIdentity, is_safe_run_id, publish_regular_text
from .hashing import MAX_SHA256_SUMS_BYTES, parse_sha256_sums
from .prebuild_vm import validate_qemu_report
from .project import Project
from .release_contract import (
    release_gate_code_problem,
    release_gate_report_problem,
    release_manifest_problem,
    release_signing_report_problem,
)
from .release_signing import (
    OPERATIONAL_BUNDLE_FILES,
    SIGN_TARGETS,
    SIGNING_KEYRING,
    full_fingerprint,
    verify_detached_signature,
)

_JSON_MAX_BYTES = 16 * 1024 * 1024
_SIDECAR_MAX_BYTES = 1024 * 1024
_SIGNATURE_MAX_BYTES = 16 * 1024 * 1024
_KEYRING_MAX_BYTES = 64 * 1024 * 1024
_VERIFY_LIMITS = ArtifactLimits(
    max_open_files=1024,
    max_buffered_bytes=512 * 1024 * 1024,
    max_closing_fds=4096,
)
# The verifier keeps every manifest-bound regular inode open until the verdict
# seals.  Refuse an inventory that could never fit that descriptor contract
# instead of traversing up to 100k entries and failing much later.
_INVENTORY_MAX_ENTRIES = _VERIFY_LIMITS.max_open_files


@dataclass(frozen=True)
class _BundleInventory:
    anchor_identity: ArtifactIdentity
    entries: tuple[tuple[str, ArtifactIdentity], ...]

    def by_name(self) -> dict[str, ArtifactIdentity]:
        return dict(self.entries)

    def top_level_names(self) -> set[str]:
        return {name for name, _identity in self.entries if "/" not in name}

    def non_directory_entries(self, prefix: str = "") -> set[str]:
        result: set[str] = set()
        for name, identity in self.entries:
            if not name.startswith(prefix) or stat.S_ISDIR(identity.mode):
                continue
            result.add(name.removeprefix(prefix))
        return result


@dataclass(frozen=True)
class ReleaseVerifyItem:
    code: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "status": self.status, "detail": self.detail}


@dataclass(frozen=True)
class ReleaseVerifyReport:
    project: Path
    bundle_dir: Path
    status: str
    items: tuple[ReleaseVerifyItem, ...]
    bundle_identity: StableParentIdentity | None = None

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "bundle_dir": str(self.bundle_dir),
            "status": self.status,
            "blocked": self.blocked,
            "items": [item.to_dict() for item in self.items],
            "bundle_identity": (
                list(self.bundle_identity)
                if self.bundle_identity is not None
                else None
            ),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Maintainer release verification",
            f"Project: {self.project}",
            f"Bundle: {self.bundle_dir}",
            f"Status: {self.status.upper()}",
            "",
        ]
        lines.extend(f"[{item.status}] {item.code}: {item.detail}" for item in self.items)
        return "\n".join(lines)


def verify_release_bundle(
    project: Project,
    *,
    bundle_dir: Path | None = None,
    expected_signer_fingerprint: str | None = None,
    expected_bundle_identity: StableParentIdentity | None = None,
    expected_product_iso: Path | None = None,
    expected_product_output_dir: Path | None = None,
    publish_report: bool = True,
) -> ReleaseVerifyReport:
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
    items: list[ReleaseVerifyItem] = []
    opening_inventory: _BundleInventory | None = None
    publish_mode: str | None = None
    verified_bundle_identity: StableParentIdentity | None = None
    try:
        session = ArtifactVerificationSession(
            bundle_dir,
            label="release bundle verification",
            limits=_VERIFY_LIMITS,
        )
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        items.append(
            ReleaseVerifyItem(
                "artifact-session",
                "blocked",
                f"Release bundle cannot be anchored safely: {exc}",
            )
        )
    else:
        try:
            if (
                expected_bundle_identity is not None
                and _stable_directory_identity(session.anchor_identity)
                != expected_bundle_identity
            ):
                raise ArtifactVerificationError(
                    "release verification bundle differs from the published receipt"
                )
            candidate_inventory = _descriptor_tree_inventory(bundle_dir)
            if candidate_inventory.anchor_identity != session.anchor_identity:
                raise ArtifactVerificationError(
                    "release verification inventory differs from its primary "
                    "descriptor-session anchor"
                )
            opening_inventory = candidate_inventory
            publish_mode = _verify_report_publish_mode(
                opening_inventory,
                session,
                items,
            )
            manifest = _read_json(
                bundle_dir / "RELEASE-MANIFEST.json",
                items,
                "manifest",
                session=session,
            )
            gate = _read_json(
                bundle_dir / "RELEASE-GATE.json",
                items,
                "release-gate",
                session=session,
            )
            signing = _read_json(
                bundle_dir / "SIGNING-REPORT.json",
                items,
                "signing-report",
                session=session,
            )
            # Capture semantic bytes before the manifest requests standalone
            # digests. ArtifactVerificationSession deliberately rejects a later
            # parse after a digest-only pass.
            _verify_sha256sums(
                bundle_dir,
                items,
                session=session,
                inventory=opening_inventory,
            )
            _verify_runtime_evidence(
                bundle_dir,
                items,
                session=session,
                inventory=opening_inventory,
                gate=gate,
            )
            manifest_problem = release_manifest_problem(
                manifest,
                expected_project_name=project.name,
                expected_bundle_dir=bundle_dir,
            )
            if manifest_problem is not None:
                items.append(
                    ReleaseVerifyItem(
                        "manifest-contract",
                        "blocked",
                        "RELEASE-MANIFEST.json is not authoritative: "
                        + manifest_problem,
                    )
                )
            _verify_gate(
                gate,
                manifest,
                items,
                project_root=project.root,
                expected_product_iso=expected_product_iso,
                expected_product_output_dir=expected_product_output_dir,
            )
            signing_contract_valid = _validate_signing_report_contract(
                signing,
                manifest,
                project_root=project.root,
                bundle_dir=bundle_dir,
                items=items,
            )
            if signing_contract_valid:
                _verify_signatures(
                    bundle_dir,
                    signing,
                    items,
                    expected_signer_fingerprint,
                    session=session,
                    inventory=opening_inventory,
                )
            _verify_manifest_files(
                bundle_dir,
                manifest,
                items,
                session=session,
                inventory=opening_inventory,
            )
            if signing_contract_valid:
                _resolve_pre_signing_gate_review(
                    gate,
                    signing,
                    items,
                )
        except (ArtifactVerificationError, OSError, ValueError, TypeError) as exc:
            items.append(
                ReleaseVerifyItem(
                    "artifact-session",
                    "blocked",
                    f"Release bundle verification failed closed: {exc}",
                )
            )
        if opening_inventory is not None:
            try:
                closing_inventory = _descriptor_tree_inventory(bundle_dir)
            except (ArtifactVerificationError, OSError, ValueError) as exc:
                items.append(
                    ReleaseVerifyItem(
                        "bundle-inventory",
                        "blocked",
                        f"Release bundle closing inventory failed: {exc}",
                    )
                )
            else:
                if (
                    closing_inventory.anchor_identity
                    != session.anchor_identity
                    or closing_inventory != opening_inventory
                ):
                    items.append(
                        ReleaseVerifyItem(
                            "bundle-inventory",
                            "blocked",
                            "Release bundle entries changed during verification.",
                        )
                    )
        try:
            metrics = session.seal()
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            items.append(
                ReleaseVerifyItem(
                    "artifact-session",
                    "blocked",
                    f"Release bundle descriptor closure failed: {exc}",
                )
            )
        else:
            verified_bundle_identity = _stable_directory_identity(
                session.anchor_identity
            )
            items.append(
                ReleaseVerifyItem(
                    "artifact-session",
                    "ready",
                    "Descriptor session sealed "
                    f"{metrics.files_opened} files; "
                    f"{metrics.bytes_hashed} bytes hashed; "
                    f"{metrics.digest_reuse} digest reuses.",
                )
            )
        finally:
            session.close()
    status = _aggregate_status(items)
    report = ReleaseVerifyReport(
        project.root,
        bundle_dir,
        status,
        tuple(items),
        verified_bundle_identity,
    )
    if (
        publish_report
        and
        publish_mode is not None
        and opening_inventory is not None
        and verified_bundle_identity is not None
    ):
        try:
            publish_regular_text(
                bundle_dir / "VERIFY-REPORT.json",
                report.render_json() + "\n",
                expected_parent_identity=verified_bundle_identity,
            )
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            items.append(
                ReleaseVerifyItem(
                    "verify-report",
                    "blocked",
                    f"VERIFY-REPORT.json could not be published safely: {exc}",
                )
            )
            report = ReleaseVerifyReport(
                project.root,
                bundle_dir,
                "blocked",
                tuple(items),
                verified_bundle_identity,
            )
    return report


def _aggregate_status(items: list[ReleaseVerifyItem]) -> str:
    if any(item.status == "blocked" for item in items):
        return "blocked"
    if any(item.status == "review" for item in items):
        return "review"
    return "ready"


def _stable_directory_identity(
    identity: ArtifactIdentity,
) -> StableParentIdentity:
    return (
        identity.dev,
        identity.ino,
        stat.S_IFMT(identity.mode),
        identity.uid,
        identity.gid,
        identity.nlink,
        identity.rdev,
    )


def _read_json(
    path: Path,
    items: list[ReleaseVerifyItem],
    code: str,
    *,
    session: ArtifactVerificationSession,
) -> dict[str, object]:
    try:
        data = session.file_path(
            path,
            label=path.name,
            max_bytes=_JSON_MAX_BYTES,
        ).json_object()
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        items.append(
            ReleaseVerifyItem(
                code,
                "blocked",
                f"{path.name} is missing, unsafe, or invalid: {exc}",
            )
        )
        return {}
    items.append(ReleaseVerifyItem(code, "ready", str(path)))
    return data


def _verify_manifest_files(
    bundle_dir: Path,
    manifest: dict[str, object],
    items: list[ReleaseVerifyItem],
    *,
    session: ArtifactVerificationSession,
    inventory: _BundleInventory,
) -> None:
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        items.append(
            ReleaseVerifyItem(
                "manifest-files",
                "blocked",
                "RELEASE-MANIFEST.json has no file entries.",
            )
        )
        return
    seen: set[str] = set()
    for raw_entry in raw_files:
        if not isinstance(raw_entry, dict):
            items.append(
                ReleaseVerifyItem(
                    "manifest-file",
                    "blocked",
                    "RELEASE-MANIFEST.json contains a non-object file entry.",
                )
            )
            continue
        entry = raw_entry
        name_value = entry.get("name")
        name = name_value if isinstance(name_value, str) else ""
        relative = _canonical_relative_name(name)
        if relative is None or name in seen:
            items.append(
                ReleaseVerifyItem(
                    "manifest-path",
                    "blocked",
                    f"Unsafe or duplicate manifest path: {name or '<unnamed>'}.",
                )
            )
            continue
        seen.add(name)
        try:
            handle = session.file(
                relative,
                label=f"manifest artifact {name}",
            )
            actual_sha = handle.digest()
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            items.append(
                ReleaseVerifyItem(
                    "manifest-file",
                    "blocked",
                    f"{name} is missing, unsafe, or unreadable: {exc}",
                )
            )
            continue
        expected_size = entry.get("size")
        expected_sha = entry.get("sha256")
        actual_size = handle.identity.size
        if not isinstance(expected_size, int) or isinstance(expected_size, bool):
            items.append(
                ReleaseVerifyItem(
                    "manifest-file",
                    "blocked",
                    f"{name} has a malformed size identity.",
                )
            )
            continue
        if expected_size != actual_size:
            items.append(
                ReleaseVerifyItem(
                    "manifest-size",
                    "blocked",
                    f"{name} size mismatch: {actual_size} != {expected_size}.",
                )
            )
        elif not _is_sha256(expected_sha):
            items.append(
                ReleaseVerifyItem(
                    "manifest-sha256",
                    "blocked",
                    f"{name} has a malformed SHA256 identity.",
                )
            )
        elif expected_sha != actual_sha:
            items.append(
                ReleaseVerifyItem(
                    "manifest-sha256",
                    "blocked",
                    f"{name} SHA256 mismatch.",
                )
            )
        else:
            items.append(ReleaseVerifyItem("manifest-file", "ready", f"{name} verified."))
    allowed_unmanifested = set(OPERATIONAL_BUNDLE_FILES)
    inventory_by_name = inventory.by_name()
    unsafe_operational = sorted(
        name
        for name in allowed_unmanifested
        if name in inventory_by_name and not stat.S_ISREG(inventory_by_name[name].mode)
    )
    if unsafe_operational:
        items.append(
            ReleaseVerifyItem(
                "manifest-extra",
                "blocked",
                "Operational bundle paths must be regular files: " + ", ".join(unsafe_operational),
            )
        )
    extras = sorted(
        name
        for name in inventory.non_directory_entries()
        if name not in seen
        and name not in allowed_unmanifested
        and name not in {f"{target}.asc" for target in SIGN_TARGETS}
    )
    if extras:
        items.append(
            ReleaseVerifyItem(
                "manifest-extra",
                "blocked",
                "Unmanifested bundle files: " + ", ".join(extras),
            )
        )
    allowed_directories: set[str] = set()
    for name in seen:
        for parent in Path(name).parents:
            if parent == Path("."):
                break
            allowed_directories.add(parent.as_posix())
    unexpected_directories = sorted(
        name
        for name, identity in inventory.entries
        if stat.S_ISDIR(identity.mode) and name not in allowed_directories
    )
    if unexpected_directories:
        items.append(
            ReleaseVerifyItem(
                "manifest-extra",
                "blocked",
                "Unmanifested bundle directories: "
                + ", ".join(unexpected_directories),
            )
        )


def _verify_sha256sums(
    bundle_dir: Path,
    items: list[ReleaseVerifyItem],
    *,
    session: ArtifactVerificationSession,
    inventory: _BundleInventory,
) -> None:
    iso_names = sorted(name for name in inventory.top_level_names() if name.endswith(".iso"))
    if len(iso_names) != 1:
        items.append(
            ReleaseVerifyItem(
                "sha256sums",
                "blocked",
                f"Expected exactly one ISO for SHA256SUMS verification, found {len(iso_names)}.",
            )
        )
        return
    iso_name = iso_names[0]
    try:
        sums_handle = session.file(
            Path("SHA256SUMS"),
            label="SHA256SUMS",
            max_bytes=MAX_SHA256_SUMS_BYTES,
        )
        sums_entries = parse_sha256_sums(sums_handle.read_bytes())
        iso_handle = session.file(
            Path(iso_name),
            label=f"release ISO {iso_name}",
        )
        actual = iso_handle.digest()
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        items.append(
            ReleaseVerifyItem(
                "sha256sums",
                "blocked",
                f"SHA256SUMS or its ISO is missing, unsafe, or invalid: {exc}",
            )
        )
        return
    if set(sums_entries) != {iso_name}:
        items.append(
            ReleaseVerifyItem(
                "sha256sums",
                "blocked",
                "SHA256SUMS must contain exactly the single bundled ISO.",
            )
        )
    elif sums_entries[iso_name] != actual:
        items.append(
            ReleaseVerifyItem(
                "sha256sums",
                "blocked",
                f"SHA256SUMS does not match {iso_name}.",
            )
        )
    else:
        items.append(
            ReleaseVerifyItem(
                "sha256sums",
                "ready",
                f"{iso_name} matches SHA256SUMS.",
            )
        )


def _verify_runtime_evidence(
    bundle_dir: Path,
    items: list[ReleaseVerifyItem],
    *,
    session: ArtifactVerificationSession,
    inventory: _BundleInventory,
    gate: dict[str, object],
) -> None:
    names = inventory.top_level_names()
    iso_names = sorted(name for name in names if name.endswith(".iso"))
    if len(iso_names) != 1:
        items.append(
            ReleaseVerifyItem(
                "runtime-evidence",
                "blocked",
                "Runtime evidence needs exactly one bundled ISO.",
            )
        )
        return
    iso = bundle_dir / iso_names[0]
    gate_build_run_id = gate.get("build_run_id")
    gate_boot_run_id = gate.get("boot_run_id")
    if not is_safe_run_id(gate_build_run_id) or not is_safe_run_id(
        gate_boot_run_id
    ):
        items.append(
            ReleaseVerifyItem(
                "runtime-evidence",
                "blocked",
                "Release gate has no safe immutable build/boot run selection.",
            )
        )
        return
    assert isinstance(gate_build_run_id, str)
    assert isinstance(gate_boot_run_id, str)
    try:
        iso_handle = session.file(
            Path(iso.name),
            label=f"runtime ISO {iso.name}",
        )
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        items.append(
            ReleaseVerifyItem(
                "runtime-evidence",
                "blocked",
                f"Bundled ISO is missing or unsafe: {exc}",
            )
        )
        return
    proof_path = bundle_dir / "boot-proof.json"
    proof: dict[str, object] = {}
    proof_handle: ArtifactHandle | None = None
    immutable_proof: Path | None = None
    if proof_path.name in names:
        try:
            proof_handle = session.file(
                Path(proof_path.name),
                label="bundled boot proof",
                max_bytes=_JSON_MAX_BYTES,
            )
            proof = proof_handle.json_object()
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            items.append(
                ReleaseVerifyItem(
                    "runtime-evidence",
                    "blocked",
                    f"boot-proof.json is missing, unsafe, or invalid: {exc}",
                )
            )
            return
        run_id = proof.get("run_id")
        qemu_name = proof.get("qemu_report")
        if (
            proof.get("schema") != "distroforge.boot-proof.v2"
            or proof.get("status") != "ready"
            or proof.get("proof_level") != "runtime"
            or proof.get("selected_backend") != "qemu"
            or not is_safe_run_id(run_id)
            or run_id != gate_boot_run_id
            or proof.get("build_run_id") != gate_build_run_id
            or not isinstance(qemu_name, str)
            or _safe_single_name(qemu_name) is None
            or proof.get("iso_sha256") != iso_handle.digest()
        ):
            items.append(
                ReleaseVerifyItem(
                    "runtime-evidence",
                    "blocked",
                    "Boot proof does not bind a ready QEMU run to the bundled ISO.",
                )
            )
            return
        assert isinstance(run_id, str)
        run_dir = bundle_dir / "evidence" / "runs" / run_id
        immutable_proof = run_dir / "boot-proof.json"
        qemu_path = bundle_dir / qemu_name
        immutable_qemu = run_dir / qemu_name
        try:
            # Parse the QEMU alias before any digest-only alias comparison.
            qemu_handle = session.file_path(
                qemu_path,
                label="bundled QEMU report",
                max_bytes=_JSON_MAX_BYTES,
            )
            qemu_handle.json_object()
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            items.append(
                ReleaseVerifyItem(
                    "runtime-evidence",
                    "blocked",
                    f"Bundled QEMU report is missing, unsafe, or invalid: {exc}",
                )
            )
            return
    else:
        items.append(
            ReleaseVerifyItem(
                "runtime-evidence",
                "blocked",
                "Release gate selected a boot run but boot-proof.json is absent "
                "from the bundle.",
            )
        )
        return

    validation = validate_qemu_report(qemu_path, iso, session=session)
    if not validation.ok:
        items.append(
            ReleaseVerifyItem(
                "runtime-evidence",
                "blocked",
                validation.detail,
            )
        )
        return
    if proof_path.name in names:
        assert proof_handle is not None
        assert immutable_proof is not None
        try:
            immutable_proof_handle = session.file_path(
                immutable_proof,
                label="immutable boot proof",
                max_bytes=_JSON_MAX_BYTES,
            )
            immutable_qemu_handle = session.file_path(
                immutable_qemu,
                label="immutable QEMU report",
                max_bytes=_JSON_MAX_BYTES,
            )
            if (
                immutable_proof_handle.digest() != proof_handle.digest()
                or immutable_qemu_handle.digest() != qemu_handle.digest()
                or proof.get("qemu_report_sha256") != immutable_qemu_handle.digest()
            ):
                items.append(
                    ReleaseVerifyItem(
                        "runtime-evidence",
                        "blocked",
                        "Bundled boot/QEMU aliases differ from their run evidence.",
                    )
                )
                return
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            items.append(
                ReleaseVerifyItem(
                    "runtime-evidence",
                    "blocked",
                    f"Bundled boot/QEMU aliases are missing or unsafe: {exc}",
                )
            )
            return
    try:
        manifest_error = _relocated_run_manifest_error(
            run_dir,
            iso_handle,
            session=session,
            inventory=inventory,
            expected_boot_run_id=gate_boot_run_id,
            expected_build_run_id=gate_build_run_id,
        )
    except (ArtifactVerificationError, OSError, ValueError, TypeError) as exc:
        manifest_error = f"Bundled runtime manifest verification blocked: {exc}"
    items.append(
        ReleaseVerifyItem(
            "runtime-evidence",
            "blocked" if manifest_error else "ready",
            manifest_error or validation.detail,
        )
    )


def _relocated_run_manifest_error(
    run_dir: Path,
    iso: ArtifactHandle,
    *,
    session: ArtifactVerificationSession,
    inventory: _BundleInventory,
    expected_boot_run_id: str,
    expected_build_run_id: str,
) -> str | None:
    manifest_path = run_dir / "RUN-MANIFEST.json"
    sidecar = run_dir / "RUN-MANIFEST.json.sha256"
    manifest_handle = session.file_path(
        manifest_path,
        label="bundled runtime manifest",
        max_bytes=_JSON_MAX_BYTES,
    )
    manifest = manifest_handle.json_object()
    sidecar_text = session.file_path(
        sidecar,
        label="bundled runtime manifest SHA256 sidecar",
        max_bytes=_SIDECAR_MAX_BYTES,
    ).read_text()
    if (
        manifest.get("schema") != "distroforge.boot-proof-run-manifest.v1"
        or run_dir.name != expected_boot_run_id
        or manifest.get("run_id") != expected_boot_run_id
        or manifest.get("build_run_id") != expected_build_run_id
        or manifest.get("mode") != "execute"
        or sidecar_text != f"{manifest_handle.digest()}  {manifest_path.name}\n"
    ):
        return "Bundled runtime manifest identity or sidecar is inconsistent."
    files = manifest.get("files")
    if not isinstance(files, list):
        return "Bundled runtime manifest has no file identities."
    marker = f"/evidence/runs/{run_dir.name}/"
    recorded_local: set[str] = set()
    iso_bound = False
    for entry in files:
        if not isinstance(entry, dict):
            return "Bundled runtime manifest contains a malformed entry."
        original_value = entry.get("path")
        if not isinstance(original_value, str):
            return "Bundled runtime manifest contains a malformed artifact path."
        original = original_value
        if marker in original:
            relative_value = original.split(marker, 1)[1]
            relative = _canonical_relative_name(relative_value)
            if relative is None:
                return (
                    "Bundled runtime manifest contains an unsafe run artifact "
                    f"path: {relative_value}."
                )
            path = run_dir / relative
            handle = session.file_path(
                path,
                label=f"bundled runtime artifact {relative.as_posix()}",
            )
            if (
                entry.get("size") != handle.identity.size
                or not _is_sha256(entry.get("sha256"))
                or entry.get("sha256") != handle.digest()
            ):
                return f"Bundled runtime artifact mismatch: {relative.as_posix()}."
            recorded_local.add(relative.as_posix())
        elif (
            Path(original).name == iso.logical_path.name
            and entry.get("size") == iso.identity.size
            and entry.get("sha256") == iso.digest()
        ):
            iso_bound = True
    run_prefix = f"evidence/runs/{run_dir.name}/"
    actual_local = inventory.non_directory_entries(run_prefix) - {
        manifest_path.name,
        sidecar.name,
    }
    if actual_local - recorded_local:
        return "Bundled runtime run contains unmanifested files: " + ", ".join(
            sorted(actual_local - recorded_local)
        )
    if not iso_bound:
        return "Bundled runtime manifest does not bind the bundled ISO."
    return None


def _verify_gate(
    gate: dict[str, object],
    manifest: dict[str, object],
    items: list[ReleaseVerifyItem],
    *,
    project_root: Path,
    expected_product_iso: Path | None = None,
    expected_product_output_dir: Path | None = None,
) -> None:
    raw_manifest_files = manifest.get("files")
    manifest_iso_names = (
        [
            str(entry["name"])
            for entry in raw_manifest_files
            if isinstance(entry, dict)
            and isinstance(entry.get("name"), str)
            and str(entry["name"]).endswith(".iso")
        ]
        if isinstance(raw_manifest_files, list)
        else []
    )
    gate_problem = release_gate_report_problem(
        gate,
        expected_project=project_root,
        expected_iso=expected_product_iso,
        expected_iso_name=(
            manifest_iso_names[0] if len(manifest_iso_names) == 1 else None
        ),
        expected_output_dir=(
            expected_product_output_dir
            if expected_product_output_dir is not None
            else project_root / "dist"
        ),
    )
    if gate_problem is not None:
        items.append(
            ReleaseVerifyItem(
                "gate-status",
                "blocked",
                f"Release gate is not authoritative: {gate_problem}.",
            )
        )
        return
    gate_status_value = gate.get("status")
    manifest_status_value = manifest.get("gate_status")
    gate_status = gate_status_value if isinstance(gate_status_value, str) else "unknown"
    manifest_status = (
        manifest_status_value
        if isinstance(manifest_status_value, str)
        else "unknown"
    )
    if gate_status not in {"ready", "review", "blocked"}:
        items.append(
            ReleaseVerifyItem(
                "gate-status",
                "blocked",
                "Release gate status is missing or invalid.",
            )
        )
        return
    if manifest_status != gate_status:
        items.append(
            ReleaseVerifyItem(
                "gate-status",
                "blocked",
                f"Manifest gate status {manifest_status} does not match {gate_status}.",
            )
        )
        return
    blocked_flag = gate.get("blocked")
    if (
        not isinstance(blocked_flag, bool)
        or blocked_flag is not (gate_status == "blocked")
    ):
        items.append(
            ReleaseVerifyItem(
                "gate-status",
                "blocked",
                "Release gate blocked flag contradicts its status.",
            )
        )
        return
    raw_gate_items = gate.get("items")
    if not isinstance(raw_gate_items, list) or not raw_gate_items:
        items.append(
            ReleaseVerifyItem(
                "gate-status",
                "blocked",
                "Release gate must contain non-empty typed item verdicts.",
            )
        )
        return
    gate_items: dict[str, dict[str, object]] = {}
    for raw_item in raw_gate_items:
        if not isinstance(raw_item, dict):
            items.append(
                ReleaseVerifyItem(
                    "gate-status",
                    "blocked",
                    "Release gate contains malformed item verdicts.",
                )
            )
            return
        code = raw_item.get("code")
        status = raw_item.get("status")
        detail = raw_item.get("detail")
        if (
            not isinstance(code, str)
            or not code
            or code in gate_items
            or status not in {"ready", "review", "blocked"}
            or not isinstance(detail, str)
            or not detail
        ):
            items.append(
                ReleaseVerifyItem(
                    "gate-status",
                    "blocked",
                    "Release gate items require unique non-empty codes and "
                    "strict status/detail strings.",
                )
            )
            return
        gate_items[code] = raw_item
    item_statuses = [str(item["status"]) for item in gate_items.values()]
    derived_status = (
        "blocked"
        if "blocked" in item_statuses
        else "review"
        if "review" in item_statuses
        else "ready"
    )
    if derived_status != gate_status:
        items.append(
            ReleaseVerifyItem(
                "gate-status",
                "blocked",
                "Release gate aggregate status contradicts its item verdicts.",
            )
        )
        return
    code_problem = release_gate_code_problem(set(gate_items))
    if code_problem is not None:
        items.append(
            ReleaseVerifyItem(
                "gate-status",
                "blocked",
                f"Release gate {code_problem}.",
            )
        )
        return
    if gate_status in {"ready", "review"}:
        binding_problem = _ready_gate_iso_binding_problem(
            gate,
            manifest,
            gate_items,
        )
        if binding_problem is not None:
            items.append(
                ReleaseVerifyItem(
                    "gate-status",
                    "blocked",
                    binding_problem,
                )
            )
            return
    items.append(
        ReleaseVerifyItem(
            "gate-status",
            gate_status,
            f"Release gate is {gate_status}.",
        )
    )


def _resolve_pre_signing_gate_review(
    gate: dict[str, object],
    signing: dict[str, object],
    items: list[ReleaseVerifyItem],
) -> None:
    """Resolve only the self-referential pre-signing review after real verification."""
    if gate.get("status") != "review":
        return
    raw_gate_items = gate.get("items")
    if not isinstance(raw_gate_items, list):
        return
    review_codes = {
        item.get("code")
        for item in raw_gate_items
        if isinstance(item, dict) and item.get("status") == "review"
    }
    if review_codes != {"publish-signing"} or any(
        isinstance(item, dict) and item.get("status") == "blocked"
        for item in raw_gate_items
    ):
        return
    required_signatures = {f"{name}.asc" for name in SIGN_TARGETS}
    signed = signing.get("signed")
    if (
        signing.get("status") != "signed"
        or signing.get("execute") is not True
        or not isinstance(signed, list)
        or not all(isinstance(name, str) for name in signed)
        or set(signed) != required_signatures
        or signing.get("planned") != []
        or signing.get("skipped") != []
    ):
        return
    signature_items = [item for item in items if item.code == "signature"]
    if (
        len(signature_items) != len(required_signatures)
        or any(item.status != "ready" for item in signature_items)
        or not any(
            item.code == "signature-fingerprint" and item.status == "ready"
            for item in items
        )
        or not any(
            item.code == "signature-keyring" and item.status == "ready"
            for item in items
        )
    ):
        return
    for index, item in enumerate(items):
        if item.code == "gate-status" and item.status == "review":
            items[index] = ReleaseVerifyItem(
                "gate-status",
                "ready",
                "The sole pre-signing publish review is resolved by the exact "
                "descriptor-bound signature set verified in this verdict.",
            )
            return


def _ready_gate_iso_binding_problem(
    gate: dict[str, object],
    manifest: dict[str, object],
    gate_items: dict[str, dict[str, object]],
) -> str | None:
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        return "Ready release gate has no manifest file snapshot."
    iso_entries = [
        entry
        for entry in raw_files
        if isinstance(entry, dict)
        and isinstance(entry.get("name"), str)
        and str(entry["name"]).endswith(".iso")
    ]
    if len(iso_entries) != 1:
        return (
            "Ready release gate must bind exactly one manifest ISO; "
            f"found {len(iso_entries)}."
        )
    iso_entry = iso_entries[0]
    iso_name = iso_entry.get("name")
    iso_size = iso_entry.get("size")
    iso_digest = iso_entry.get("sha256")
    gate_iso = gate.get("iso")
    if (
        not isinstance(iso_name, str)
        or _canonical_relative_name(iso_name) != Path(iso_name)
        or len(Path(iso_name).parts) != 1
        or not isinstance(iso_size, int)
        or isinstance(iso_size, bool)
        or iso_size <= 0
        or not _is_sha256(iso_digest)
        or not isinstance(gate_iso, str)
        or not gate_iso
        or "\x00" in gate_iso
        or ".." in Path(gate_iso).parts
        or Path(gate_iso).name != iso_name
    ):
        return "Ready release gate has an invalid or mismatched ISO identity."
    iso_item = gate_items["iso"]
    sha_item = gate_items["sha256"]
    if (
        iso_item.get("status") != "ready"
        or iso_item.get("detail") != f"{iso_size} bytes"
        or sha_item.get("status") != "ready"
        or sha_item.get("detail") != iso_digest
    ):
        return (
            "Ready release gate ISO/SHA256 verdicts do not match the "
            "manifest-bound ISO."
        )
    return None


def _validate_signing_report_contract(
    signing: dict[str, object],
    manifest: dict[str, object],
    *,
    project_root: Path,
    bundle_dir: Path,
    items: list[ReleaseVerifyItem],
) -> bool:
    """Validate the complete persisted signing report before trusting its claims."""

    problem = release_signing_report_problem(
        signing,
        manifest,
        expected_project=project_root,
        expected_bundle_dir=bundle_dir,
    )
    if problem is None:
        return True
    items.append(
        ReleaseVerifyItem(
            "signature-contract",
            "blocked",
            f"SIGNING-REPORT.json is not authoritative: {problem}",
        )
    )
    return False
def _verify_signatures(
    bundle_dir: Path,
    signing: dict[str, object],
    items: list[ReleaseVerifyItem],
    expected_signer_fingerprint: str | None,
    *,
    session: ArtifactVerificationSession | None = None,
    inventory: _BundleInventory | None = None,
) -> None:
    if session is not None:
        try:
            active_inventory = inventory or _descriptor_tree_inventory(bundle_dir)
            _verify_signatures_in_session(
                bundle_dir,
                signing,
                items,
                expected_signer_fingerprint,
                session=session,
                inventory=active_inventory,
            )
        except (
            ArtifactVerificationError,
            CommandError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            items.append(
                ReleaseVerifyItem(
                    "signature-session",
                    "blocked",
                    f"Detached signature verification failed closed: {exc}",
                )
            )
        return
    absolute_bundle = Path(os.path.abspath(bundle_dir))
    try:
        owned_session = ArtifactVerificationSession(
            absolute_bundle,
            label="detached signature verification",
            limits=_VERIFY_LIMITS,
        )
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        items.append(
            ReleaseVerifyItem(
                "signature-session",
                "blocked",
                f"Detached signatures cannot be anchored safely: {exc}",
            )
        )
        return
    opening_inventory: _BundleInventory | None = None
    try:
        try:
            opening_inventory = _descriptor_tree_inventory(absolute_bundle)
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            items.append(
                ReleaseVerifyItem(
                    "signature-session",
                    "blocked",
                    f"Detached signature inventory failed: {exc}",
                )
            )
        try:
            if opening_inventory is not None:
                _verify_signatures_in_session(
                    absolute_bundle,
                    signing,
                    items,
                    expected_signer_fingerprint,
                    session=owned_session,
                    inventory=opening_inventory,
                )
        except (ArtifactVerificationError, OSError, ValueError, TypeError) as exc:
            items.append(
                ReleaseVerifyItem(
                    "signature-session",
                    "blocked",
                    f"Detached signature verification failed closed: {exc}",
                )
            )
        if opening_inventory is not None:
            try:
                closing_inventory = _descriptor_tree_inventory(absolute_bundle)
            except (ArtifactVerificationError, OSError, ValueError) as exc:
                items.append(
                    ReleaseVerifyItem(
                        "signature-session",
                        "blocked",
                        f"Detached signature closing inventory failed: {exc}",
                    )
                )
            else:
                if closing_inventory != opening_inventory:
                    items.append(
                        ReleaseVerifyItem(
                            "signature-session",
                            "blocked",
                            "Detached signature bundle changed during verification.",
                        )
                    )
        try:
            owned_session.seal()
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            items.append(
                ReleaseVerifyItem(
                    "signature-session",
                    "blocked",
                    f"Detached signature descriptor closure failed: {exc}",
                )
            )
    finally:
        owned_session.close()


def _verify_signatures_in_session(
    bundle_dir: Path,
    signing: dict[str, object],
    items: list[ReleaseVerifyItem],
    expected_signer_fingerprint: str | None,
    *,
    session: ArtifactVerificationSession,
    inventory: _BundleInventory,
) -> None:
    planned = {str(name) for name in signing.get("planned", []) if isinstance(name, str)}
    signed = {str(name) for name in signing.get("signed", []) if isinstance(name, str)}
    bundle_names = inventory.top_level_names()
    actual_names = {name for name in bundle_names if name.endswith(".asc")}
    required = {f"{name}.asc" for name in SIGN_TARGETS}
    execution_claimed = (
        bool(signed or actual_names)
        or signing.get("status") == "signed"
        or signing.get("execute") is True
    )
    if execution_claimed:
        skipped = signing.get("skipped")
        if (
            signing.get("status") != "signed"
            or signing.get("execute") is not True
            or signed != required
            or planned
            or skipped != []
            or actual_names != required
        ):
            items.append(
                ReleaseVerifyItem(
                    "signature-contract",
                    "blocked",
                    "Executed signing must contain exactly the detached signatures "
                    "for SHA256SUMS, RELEASE-GATE.json and RELEASE-MANIFEST.json, "
                    "with no skipped or merely planned target.",
                )
            )
        targets = sorted(planned | signed | actual_names | required)
    else:
        targets = sorted(planned)
    if not targets:
        items.append(
            ReleaseVerifyItem("signatures", "review", "No detached signatures are recorded.")
        )
        return
    unsafe = [name for name in targets if Path(name).name != name or not name.endswith(".asc")]
    if unsafe:
        items.append(
            ReleaseVerifyItem(
                "signature-path",
                "blocked",
                "Unsafe detached signature paths: " + ", ".join(unsafe),
            )
        )
        return
    actual = [name for name in targets if name in actual_names]
    signature_handles: dict[str, ArtifactHandle] = {}
    for asc_name in actual:
        try:
            signature_handles[asc_name] = session.file(
                Path(asc_name),
                label=f"detached signature {asc_name}",
                max_bytes=_SIGNATURE_MAX_BYTES,
            )
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            items.append(
                ReleaseVerifyItem(
                    "signature-path",
                    "blocked",
                    f"Detached signature {asc_name} is unsafe or unreadable: {exc}",
                )
            )
            return
    if not actual:
        for asc_name in targets:
            status = "blocked" if asc_name in signed else "review"
            detail = (
                f"{asc_name} is recorded as signed but is missing."
                if status == "blocked"
                else f"{asc_name} is planned but not present."
            )
            items.append(ReleaseVerifyItem("signature", status, detail))
        return

    expected = full_fingerprint(expected_signer_fingerprint)
    if expected is None:
        items.append(
            ReleaseVerifyItem(
                "signature-fingerprint",
                "blocked",
                "Detached signature verification requires a trusted external "
                "complete OpenPGP fingerprint.",
            )
        )
        return
    recorded_value = signing.get("signer_fingerprint")
    recorded = full_fingerprint(recorded_value if isinstance(recorded_value, str) else None)
    if recorded != expected:
        items.append(
            ReleaseVerifyItem(
                "signature-fingerprint",
                "blocked",
                f"SIGNING-REPORT.json does not record the externally pinned signer {expected}.",
            )
        )
        return
    keyring_value = signing.get("verification_keyring")
    keyring_digest = signing.get("verification_keyring_sha256")
    if keyring_value != SIGNING_KEYRING or not isinstance(keyring_digest, str):
        items.append(
            ReleaseVerifyItem(
                "signature-keyring",
                "blocked",
                "SIGNING-REPORT.json has no explicit verification keyring identity.",
            )
        )
        return
    keyring = bundle_dir / SIGNING_KEYRING
    if SIGNING_KEYRING not in bundle_names:
        items.append(
            ReleaseVerifyItem(
                "signature-keyring",
                "blocked",
                "The explicit verification keyring is missing, unsafe, or has a different SHA256.",
            )
        )
        return
    try:
        keyring_handle = session.file(
            Path(SIGNING_KEYRING),
            label="release verification keyring",
            max_bytes=_KEYRING_MAX_BYTES,
        )
        actual_keyring_digest = keyring_handle.digest()
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        items.append(
            ReleaseVerifyItem(
                "signature-keyring",
                "blocked",
                f"The explicit verification keyring is unsafe or unreadable: {exc}",
            )
        )
        return
    if actual_keyring_digest != keyring_digest:
        items.append(
            ReleaseVerifyItem(
                "signature-keyring",
                "blocked",
                "The explicit verification keyring has a different SHA256.",
            )
        )
        return
    if not CommandRunner.has_binary("gpg"):
        items.append(
            ReleaseVerifyItem(
                "signatures",
                "blocked",
                "Detached signatures exist but gpg is not available.",
            )
        )
        return

    items.append(
        ReleaseVerifyItem(
            "signature-fingerprint",
            "ready",
            f"Externally pinned complete signer fingerprint: {expected}.",
        )
    )
    items.append(
        ReleaseVerifyItem(
            "signature-keyring",
            "ready",
            f"{SIGNING_KEYRING} matches SHA256 {keyring_digest}.",
        )
    )
    runner = CommandRunner(dry_run=False)
    for asc_name in targets:
        asc = bundle_dir / asc_name
        signed_file = bundle_dir / asc_name.removesuffix(".asc")
        if asc_name not in actual_names:
            status = "blocked" if asc_name in signed else "review"
            detail = (
                f"{asc_name} is recorded as signed but is missing."
                if status == "blocked"
                else f"{asc_name} is planned but not present."
            )
            items.append(ReleaseVerifyItem("signature", status, detail))
            continue
        if signed_file.name not in bundle_names:
            items.append(
                ReleaseVerifyItem(
                    "signature",
                    "blocked",
                    f"{asc_name} has no matching signed file.",
                )
            )
            continue
        try:
            signature_handle = signature_handles[asc_name]
            payload_handle = session.file(
                Path(signed_file.name),
                label=f"signed payload {signed_file.name}",
            )
            verify_detached_signature(
                runner,
                asc,
                signed_file,
                keyring,
                expected,
                signature_fd=signature_handle.fileno,
                payload_fd=payload_handle.fileno,
                keyring_fd=keyring_handle.fileno,
            )
        except (
            ArtifactVerificationError,
            CommandError,
            OSError,
            ValueError,
        ) as exc:
            items.append(
                ReleaseVerifyItem(
                    "signature",
                    "blocked",
                    f"{asc_name} failed pinned GPG verification: {exc}",
                )
            )
        else:
            items.append(
                ReleaseVerifyItem(
                    "signature",
                    "ready",
                    f"{asc_name} has VALIDSIG from {expected}.",
                )
            )


def _canonical_relative_name(value: str) -> Path | None:
    if not value or "\x00" in value or "\\" in value:
        return None
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        return None
    relative = Path(value)
    if (
        relative.is_absolute()
        or relative == Path(".")
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != value
    ):
        return None
    return relative


def _safe_single_name(value: str) -> str | None:
    relative = _canonical_relative_name(value)
    if relative is None or len(relative.parts) != 1:
        return None
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _strict_filesystem_name(value: str) -> str:
    if value in {"", ".", ".."} or "/" in value or "\x00" in value:
        raise ValueError(f"unsafe filesystem entry name: {value!r}")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("bundle contains a non-UTF-8 filesystem name") from exc
    return value


def _verify_report_publish_mode(
    inventory: _BundleInventory,
    session: ArtifactVerificationSession,
    items: list[ReleaseVerifyItem],
) -> str | None:
    identity = inventory.by_name().get("VERIFY-REPORT.json")
    if identity is None:
        return "create"
    if not stat.S_ISREG(identity.mode):
        items.append(
            ReleaseVerifyItem(
                "verify-report",
                "blocked",
                "Existing VERIFY-REPORT.json is not a regular file; "
                "it will not be followed or replaced.",
            )
        )
        return None
    previous_session: ArtifactVerificationSession | None = None
    try:
        previous_session = ArtifactVerificationSession(
            session.anchor_path,
            label="previous release verification report",
            limits=ArtifactLimits(
                max_open_files=2,
                max_file_bytes=_JSON_MAX_BYTES,
                max_buffered_bytes=_JSON_MAX_BYTES,
                max_hashed_bytes=2 * _JSON_MAX_BYTES,
                max_json_depth=256,
                max_json_nodes=1_000_000,
                max_closing_fds=16,
            ),
        )
        if previous_session.anchor_identity != session.anchor_identity:
            raise ArtifactVerificationError(
                "previous verification report belongs to a different bundle anchor"
            )
        previous_session.file(
            Path("VERIFY-REPORT.json"),
            label="previous VERIFY-REPORT.json",
            max_bytes=_JSON_MAX_BYTES,
        ).json_object()
        previous_session.seal()
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        items.append(
            ReleaseVerifyItem(
                "verify-report",
                "blocked",
                f"Existing VERIFY-REPORT.json is invalid or unstable: {exc}",
            )
        )
        return None
    finally:
        if previous_session is not None:
            previous_session.close()
    return "reuse"


def _descriptor_tree_inventory(directory: Path) -> _BundleInventory:
    descriptor, opening_identity = _open_absolute_directory_nofollow(directory)
    entries: dict[str, ArtifactIdentity] = {}
    counter = [0]
    try:
        _inventory_directory_descriptor(
            descriptor,
            Path(),
            entries,
            counter,
            depth=0,
        )
        if ArtifactIdentity.from_stat(os.fstat(descriptor)) != opening_identity:
            raise ArtifactVerificationError(
                "release bundle anchor changed during descriptor inventory"
            )
        closing_descriptor, closing_identity = _open_absolute_directory_nofollow(directory)
        try:
            if closing_identity != opening_identity:
                raise ArtifactVerificationError(
                    "release bundle anchor path changed during descriptor inventory"
                )
        finally:
            os.close(closing_descriptor)
    except OSError as exc:
        raise ArtifactVerificationError(
            f"release bundle descriptor inventory failed: {exc}"
        ) from exc
    finally:
        os.close(descriptor)
    return _BundleInventory(
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
    if depth > _VERIFY_LIMITS.max_path_components:
        raise ArtifactVerificationError("release bundle inventory exceeds its path-depth limit")
    opening_identity = ArtifactIdentity.from_stat(os.fstat(directory_fd))
    names: list[str] = []
    with os.scandir(directory_fd) as iterator:
        for entry in iterator:
            counter[0] += 1
            if counter[0] > _INVENTORY_MAX_ENTRIES:
                raise ArtifactVerificationError(
                    "bundle exceeds its structural inventory entry limit"
                )
            names.append(_strict_filesystem_name(entry.name))
    names.sort()
    immediate: dict[str, ArtifactIdentity] = {}
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    for name in names:
        try:
            identity = ArtifactIdentity.from_stat(
                os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            )
        except OSError as exc:
            raise ArtifactVerificationError(
                f"bundle inventory entry changed before identification: {name}"
            ) from exc
        relative = prefix / name
        relative_name = relative.as_posix()
        entries[relative_name] = identity
        immediate[name] = identity
        if not stat.S_ISDIR(identity.mode):
            continue
        child_fd = -1
        try:
            child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
            if ArtifactIdentity.from_stat(os.fstat(child_fd)) != identity:
                raise ArtifactVerificationError(
                    f"bundle directory changed while opening: {relative_name}"
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
                    f"bundle directory changed during inventory: {relative_name}"
                )
        except OSError as exc:
            raise ArtifactVerificationError(
                f"bundle directory cannot be traversed safely: {relative_name}"
            ) from exc
        finally:
            if child_fd >= 0:
                os.close(child_fd)
    for name, expected in immediate.items():
        try:
            current = ArtifactIdentity.from_stat(
                os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            )
        except OSError as exc:
            raise ArtifactVerificationError(
                f"bundle inventory entry disappeared during traversal: {name}"
            ) from exc
        if current != expected:
            raise ArtifactVerificationError(
                f"bundle inventory entry changed during traversal: {name}"
            )
    if ArtifactIdentity.from_stat(os.fstat(directory_fd)) != opening_identity:
        raise ArtifactVerificationError(
            f"bundle directory identity changed during traversal: {prefix or '.'}"
        )


def _open_absolute_directory_nofollow(
    directory: Path,
) -> tuple[int, ArtifactIdentity]:
    if not directory.is_absolute() or "\x00" in str(directory) or ".." in directory.parts:
        raise ArtifactVerificationError(f"bundle directory path is not canonical: {directory}")
    absolute = Path(os.path.abspath(directory))
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
            raise ArtifactVerificationError(f"bundle directory is not a directory: {directory}")
        return descriptor, identity
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ArtifactVerificationError(
            f"bundle directory contains a symlink or unreadable component: {directory}"
        ) from exc
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
