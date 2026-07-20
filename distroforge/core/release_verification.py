from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .host_artifacts import write_host_artifact
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
    for entry in files:
        name = str(entry.get("name", ""))
        path = bundle_dir / name
        if not name or not path.exists():
            items.append(ReleaseVerifyItem("manifest-file", "blocked", f"{name or '<unnamed>'} is missing."))
            continue
        expected_size = entry.get("size")
        expected_sha = entry.get("sha256")
        actual_size = path.stat().st_size
        actual_sha = _sha256(path)
        if expected_size != actual_size:
            items.append(ReleaseVerifyItem("manifest-size", "blocked", f"{name} size mismatch: {actual_size} != {expected_size}."))
        elif expected_sha != actual_sha:
            items.append(ReleaseVerifyItem("manifest-sha256", "blocked", f"{name} SHA256 mismatch."))
        else:
            items.append(ReleaseVerifyItem("manifest-file", "ready", f"{name} verified."))


def _verify_sha256sums(bundle_dir: Path, items: list[ReleaseVerifyItem]) -> None:
    sums = bundle_dir / "SHA256SUMS"
    if not sums.exists():
        items.append(ReleaseVerifyItem("sha256sums", "blocked", "SHA256SUMS is missing."))
        return
    iso_paths = sorted(bundle_dir.glob("*.iso"))
    if not iso_paths:
        items.append(ReleaseVerifyItem("sha256sums", "blocked", "No ISO found for SHA256SUMS verification."))
        return
    expected = _sha_from_sums(sums, iso_paths[0].name)
    actual = _sha256(iso_paths[0])
    if expected != actual:
        items.append(ReleaseVerifyItem("sha256sums", "blocked", f"SHA256SUMS does not match {iso_paths[0].name}."))
    else:
        items.append(ReleaseVerifyItem("sha256sums", "ready", f"{iso_paths[0].name} matches SHA256SUMS."))


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


def _sha_from_sums(path: Path, name: str) -> str | None:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and Path(parts[-1]).name == name:
            return parts[0]
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
