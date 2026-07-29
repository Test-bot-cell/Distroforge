from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .hashing import sha256_file, sha256_from_sums
from .host_artifacts import write_host_artifact
from .prebuild_vm import validate_qemu_report
from .project import Project


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


def verify_release_bundle(project: Project, *, bundle_dir: Path | None = None) -> ReleaseVerifyReport:
    bundle_dir = bundle_dir or project.output_dir / "publish"
    items: list[ReleaseVerifyItem] = []
    manifest = _read_json(bundle_dir / "RELEASE-MANIFEST.json", items, "manifest")
    gate = _read_json(bundle_dir / "RELEASE-GATE.json", items, "release-gate")
    signing = _read_json(bundle_dir / "SIGNING-REPORT.json", items, "signing-report")
    _verify_manifest_files(bundle_dir, manifest, items)
    _verify_sha256sums(bundle_dir, items)
    _verify_runtime_evidence(bundle_dir, items)
    _verify_gate(gate, manifest, items)
    _verify_signatures(bundle_dir, signing, items)
    status = "blocked" if any(item.status == "blocked" for item in items) else "review" if any(item.status == "review" for item in items) else "ready"
    report = ReleaseVerifyReport(project.root, bundle_dir, status, tuple(items))
    write_host_artifact(bundle_dir / "VERIFY-REPORT.json", report.render_json() + "\n", "Write VERIFY-REPORT.json")
    return report


def _read_json(path: Path, items: list[ReleaseVerifyItem], code: str) -> dict[str, object]:
    if not path.exists():
        items.append(ReleaseVerifyItem(code, "blocked", f"{path.name} is missing."))
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        items.append(ReleaseVerifyItem(code, "blocked", f"{path.name} is not valid JSON."))
        return {}
    if not isinstance(data, dict):
        items.append(ReleaseVerifyItem(code, "blocked", f"{path.name} must contain a JSON object."))
        return {}
    items.append(ReleaseVerifyItem(code, "ready", str(path)))
    return data


def _verify_manifest_files(bundle_dir: Path, manifest: dict[str, object], items: list[ReleaseVerifyItem]) -> None:
    files = [entry for entry in manifest.get("files", []) if isinstance(entry, dict)]
    if not files:
        items.append(ReleaseVerifyItem("manifest-files", "blocked", "RELEASE-MANIFEST.json has no file entries."))
        return
    seen: set[str] = set()
    bundle_root = bundle_dir.resolve()
    for entry in files:
        name = str(entry.get("name", ""))
        relative = Path(name)
        if (
            not name
            or relative.is_absolute()
            or ".." in relative.parts
            or name in seen
        ):
            items.append(
                ReleaseVerifyItem(
                    "manifest-path",
                    "blocked",
                    f"Unsafe or duplicate manifest path: {name or '<unnamed>'}.",
                )
            )
            continue
        seen.add(name)
        path = bundle_dir / relative
        try:
            resolved = path.resolve()
            resolved.relative_to(bundle_root)
        except (OSError, ValueError):
            items.append(
                ReleaseVerifyItem(
                    "manifest-path",
                    "blocked",
                    f"Manifest path escapes the bundle: {name}.",
                )
            )
            continue
        if path.is_symlink():
            items.append(
                ReleaseVerifyItem(
                    "manifest-path",
                    "blocked",
                    f"Manifest path is a symlink: {name}.",
                )
            )
            continue
        if not path.is_file():
            items.append(ReleaseVerifyItem("manifest-file", "blocked", f"{name or '<unnamed>'} is missing."))
            continue
        expected_size = entry.get("size")
        expected_sha = entry.get("sha256")
        actual_size = path.stat().st_size
        actual_sha = sha256_file(path)
        if expected_size != actual_size:
            items.append(ReleaseVerifyItem("manifest-size", "blocked", f"{name} size mismatch: {actual_size} != {expected_size}."))
        elif expected_sha != actual_sha:
            items.append(ReleaseVerifyItem("manifest-sha256", "blocked", f"{name} SHA256 mismatch."))
        else:
            items.append(ReleaseVerifyItem("manifest-file", "ready", f"{name} verified."))
    allowed_unmanifested = {
        "RELEASE-MANIFEST.json",
        "SIGNING-REPORT.json",
        "VERIFY-REPORT.json",
        "RELEASE-PIPELINE.json",
    }
    extras = [
        path.relative_to(bundle_dir).as_posix()
        for path in bundle_dir.rglob("*")
        if (path.is_file() or path.is_symlink())
        and path.relative_to(bundle_dir).as_posix() not in seen
        and path.relative_to(bundle_dir).as_posix() not in allowed_unmanifested
        and not path.name.endswith(".asc")
    ]
    if extras:
        items.append(
            ReleaseVerifyItem(
                "manifest-extra",
                "blocked",
                "Unmanifested bundle files: " + ", ".join(extras),
            )
        )


def _verify_sha256sums(bundle_dir: Path, items: list[ReleaseVerifyItem]) -> None:
    sums = bundle_dir / "SHA256SUMS"
    if not sums.exists():
        items.append(ReleaseVerifyItem("sha256sums", "blocked", "SHA256SUMS is missing."))
        return
    iso_paths = sorted(bundle_dir.glob("*.iso"))
    if len(iso_paths) != 1:
        items.append(
            ReleaseVerifyItem(
                "sha256sums",
                "blocked",
                f"Expected exactly one ISO for SHA256SUMS verification, found {len(iso_paths)}.",
            )
        )
        return
    expected = sha256_from_sums(sums, iso_paths[0].name)
    actual = sha256_file(iso_paths[0])
    if expected != actual:
        items.append(ReleaseVerifyItem("sha256sums", "blocked", f"SHA256SUMS does not match {iso_paths[0].name}."))
    else:
        items.append(ReleaseVerifyItem("sha256sums", "ready", f"{iso_paths[0].name} matches SHA256SUMS."))


def _verify_runtime_evidence(
    bundle_dir: Path,
    items: list[ReleaseVerifyItem],
) -> None:
    iso_paths = sorted(bundle_dir.glob("*.iso"))
    if len(iso_paths) != 1:
        items.append(
            ReleaseVerifyItem(
                "runtime-evidence",
                "blocked",
                "Runtime evidence needs exactly one bundled ISO.",
            )
        )
        return
    iso = iso_paths[0]
    proof_path = bundle_dir / "boot-proof.json"
    proof: dict[str, object] = {}
    if proof_path.is_file():
        try:
            loaded = json.loads(proof_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            items.append(
                ReleaseVerifyItem(
                    "runtime-evidence",
                    "blocked",
                    f"boot-proof.json is invalid: {exc}",
                )
            )
            return
        if not isinstance(loaded, dict):
            items.append(
                ReleaseVerifyItem(
                    "runtime-evidence",
                    "blocked",
                    "boot-proof.json is not an object.",
                )
            )
            return
        proof = loaded
        run_id = proof.get("run_id")
        qemu_name = proof.get("qemu_report")
        if (
            proof.get("schema") != "distroforge.boot-proof.v2"
            or proof.get("status") != "ready"
            or proof.get("proof_level") != "runtime"
            or proof.get("selected_backend") != "qemu"
            or not isinstance(run_id, str)
            or Path(run_id).name != run_id
            or not isinstance(qemu_name, str)
            or Path(qemu_name).name != qemu_name
            or proof.get("iso_sha256") != sha256_file(iso)
        ):
            items.append(
                ReleaseVerifyItem(
                    "runtime-evidence",
                    "blocked",
                    "Boot proof does not bind a ready QEMU run to the bundled ISO.",
                )
            )
            return
        run_dir = bundle_dir / "evidence" / "runs" / run_id
        immutable_proof = run_dir / "boot-proof.json"
        qemu_path = bundle_dir / qemu_name
        immutable_qemu = run_dir / qemu_name
        if (
            not immutable_proof.is_file()
            or sha256_file(immutable_proof) != sha256_file(proof_path)
            or not immutable_qemu.is_file()
            or proof.get("qemu_report_sha256") != sha256_file(immutable_qemu)
        ):
            items.append(
                ReleaseVerifyItem(
                    "runtime-evidence",
                    "blocked",
                    "Bundled boot/QEMU aliases differ from their run evidence.",
                )
            )
            return
    else:
        qemu_candidates = []
        for path in bundle_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict) and data.get("schema") == "distroforge.qemu-lab.v2":
                qemu_candidates.append(path)
        if len(qemu_candidates) != 1:
            items.append(
                ReleaseVerifyItem(
                    "runtime-evidence",
                    "blocked",
                    f"Expected one QEMU report, found {len(qemu_candidates)}.",
                )
            )
            return
        qemu_path = qemu_candidates[0]
        qemu_payload = json.loads(qemu_path.read_text(encoding="utf-8"))
        run_id = qemu_payload.get("run_id")
        if not isinstance(run_id, str) or Path(run_id).name != run_id:
            items.append(
                ReleaseVerifyItem(
                    "runtime-evidence",
                    "blocked",
                    "QEMU report has no safe run identity.",
                )
            )
            return
        run_dir = bundle_dir / "evidence" / "runs" / run_id
    validation = validate_qemu_report(qemu_path, iso)
    if not validation.ok:
        items.append(
            ReleaseVerifyItem(
                "runtime-evidence",
                "blocked",
                validation.detail,
            )
        )
        return
    manifest_error = _relocated_run_manifest_error(run_dir, iso)
    items.append(
        ReleaseVerifyItem(
            "runtime-evidence",
            "blocked" if manifest_error else "ready",
            manifest_error or validation.detail,
        )
    )


def _relocated_run_manifest_error(run_dir: Path, iso: Path) -> str | None:
    manifest_path = run_dir / "RUN-MANIFEST.json"
    sidecar = run_dir / "RUN-MANIFEST.json.sha256"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        sidecar_text = sidecar.read_text(encoding="utf-8").strip()
    except (OSError, json.JSONDecodeError) as exc:
        return f"Bundled runtime manifest is missing or unreadable: {exc}"
    if (
        not isinstance(manifest, dict)
        or manifest.get("run_id") != run_dir.name
        or manifest.get("mode") != "execute"
        or sidecar_text
        != f"{sha256_file(manifest_path)}  {manifest_path.name}"
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
        original = str(entry.get("path", ""))
        if marker in original:
            relative = original.split(marker, 1)[1]
            path = run_dir / relative
            if (
                path.is_symlink()
                or not path.is_file()
                or entry.get("size") != path.stat().st_size
                or entry.get("sha256") != sha256_file(path)
            ):
                return f"Bundled runtime artifact mismatch: {relative}."
            recorded_local.add(relative)
        elif (
            Path(original).name == iso.name
            and entry.get("size") == iso.stat().st_size
            and entry.get("sha256") == sha256_file(iso)
        ):
            iso_bound = True
    actual_local = {
        path.relative_to(run_dir).as_posix()
        for path in run_dir.rglob("*")
        if path.is_file() and path not in {manifest_path, sidecar}
    }
    if actual_local - recorded_local:
        return "Bundled runtime run contains unmanifested files: " + ", ".join(
            sorted(actual_local - recorded_local)
        )
    if not iso_bound:
        return "Bundled runtime manifest does not bind the bundled ISO."
    return None


def _verify_gate(gate: dict[str, object], manifest: dict[str, object], items: list[ReleaseVerifyItem]) -> None:
    gate_status = str(gate.get("status", "unknown"))
    manifest_status = str(manifest.get("gate_status", "unknown"))
    if gate_status == "unknown":
        items.append(ReleaseVerifyItem("gate-status", "blocked", "Release gate status is missing."))
    elif manifest_status not in {"unknown", gate_status}:
        items.append(ReleaseVerifyItem("gate-status", "blocked", f"Manifest gate status {manifest_status} does not match {gate_status}."))
    else:
        items.append(ReleaseVerifyItem("gate-status", "ready" if gate_status == "ready" else "review", f"Release gate is {gate_status}."))


def _verify_signatures(bundle_dir: Path, signing: dict[str, object], items: list[ReleaseVerifyItem]) -> None:
    planned = {str(name) for name in signing.get("planned", []) if isinstance(name, str)}
    signed = {str(name) for name in signing.get("signed", []) if isinstance(name, str)}
    targets = sorted(planned | signed | {path.name for path in bundle_dir.glob("*.asc")})
    if not targets:
        items.append(ReleaseVerifyItem("signatures", "review", "No detached signatures are recorded."))
        return
    gpg_available = CommandRunner.has_binary("gpg")
    runner = CommandRunner(dry_run=False)
    for asc_name in targets:
        asc = bundle_dir / asc_name
        signed_file = bundle_dir / asc_name.removesuffix(".asc")
        if not asc.exists():
            items.append(ReleaseVerifyItem("signature", "review", f"{asc_name} is planned but not present."))
        elif not signed_file.exists():
            items.append(ReleaseVerifyItem("signature", "blocked", f"{asc_name} has no matching signed file."))
        elif not gpg_available:
            items.append(ReleaseVerifyItem("signature", "review", f"{asc_name} exists but gpg is not available."))
        else:
            result = runner.run(CommandSpec(argv=("gpg", "--verify", str(asc), str(signed_file)), description=f"Verify {asc_name}"), check=False)
            status = "ready" if result.returncode == 0 else "blocked"
            detail = f"{asc_name} verified." if result.returncode == 0 else f"{asc_name} failed GPG verification."
            items.append(ReleaseVerifyItem("signature", status, detail))
