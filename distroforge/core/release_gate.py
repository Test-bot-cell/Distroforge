from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .artifact_paths import default_artifact_paths
from .build import BuildOptions
from .diff_preview import DiffPreviewService
from .packaging import packaging_policy_report
from .project import Project
from .provenance import CYCLONEDX_FILENAME, SPDX_FILENAME
from .release_readiness import ReleaseReadinessService
from .trust import TrustService
from .vulnscan import VulnScanService


@dataclass(frozen=True)
class ReleaseGateItem:
    code: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "status": self.status, "detail": self.detail}


@dataclass
class ReleaseGateReport:
    project: Path
    iso: Path
    output_dir: Path
    items: list[ReleaseGateItem] = field(default_factory=list)

    @property
    def status(self) -> str:
        if any(item.status == "blocked" for item in self.items):
            return "blocked"
        if any(item.status == "review" for item in self.items):
            return "review"
        return "ready"

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "output_dir": str(self.output_dir),
            "status": self.status,
            "blocked": self.blocked,
            "items": [item.to_dict() for item in self.items],
        }

    def render_text(self) -> str:
        lines = [
            "Release gate",
            f"Project: {self.project}",
            f"ISO: {self.iso}",
            f"Output: {self.output_dir}",
            f"Status: {self.status.upper()}",
            "",
        ]
        lines.extend(f"[{item.status}] {item.code}: {item.detail}" for item in self.items)
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class ReleaseGateService:
    def check(
        self,
        project: Project,
        options: BuildOptions,
        *,
        iso: Path | None = None,
        output_dir: Path | None = None,
    ) -> ReleaseGateReport:
        paths = default_artifact_paths(project)
        iso = iso or options.output_iso or paths.output_iso
        output_dir = output_dir or iso.parent
        report = ReleaseGateReport(project.root, iso, output_dir)
        _check_source_trust(report, project, options)
        _check_vuln_policy(report, project, options)
        _check_iso_and_checksums(report, iso, output_dir)
        _check_release_files(report, output_dir, options)
        _check_boot_proof(report, output_dir, options)
        _check_release_readiness(report, iso, output_dir)
        _check_packaging_policy(report, project.root)
        _check_publish_signing(report, project.root, options)
        return report


def _check_source_trust(report: ReleaseGateReport, project: Project, options: BuildOptions) -> None:
    if project.source_iso:
        trust = TrustService().check_source_iso(project.source_iso, options.trust, strict=options.policy.strict)
        if not trust.ok:
            report.items.append(ReleaseGateItem("source-trust", "blocked", trust.render_text().splitlines()[-1]))
            return
        if not options.trust.source_sha256 and not options.trust.require_source_checksum:
            report.items.append(ReleaseGateItem("source-trust", "review", "Source ISO has no SHA256 requirement."))
            return
        report.items.append(ReleaseGateItem("source-trust", "ready", "Source ISO trust checks are configured."))
        return
    if project.source_mode == "bootstrap" or project.source_starter:
        report.items.append(ReleaseGateItem("source-trust", "ready", "Source starter/bootstrap path is explicit."))
    else:
        report.items.append(ReleaseGateItem("source-trust", "blocked", "No source ISO, starter or bootstrap path."))


def _check_vuln_policy(report: ReleaseGateReport, project: Project, options: BuildOptions) -> None:
    if not options.vuln_scan.enabled:
        report.items.append(ReleaseGateItem("vuln-scan", "review", "CVE scanning is not enabled."))
        return
    packages = DiffPreviewService().preview(project, options).install
    scan = VulnScanService(options.vuln_scan).scan(packages)
    counts = scan.counts
    summary = f"policy={scan.policy} db={scan.database} critical={counts['critical']} high={counts['high']}"
    if not scan.ok:
        report.items.append(ReleaseGateItem("vuln-scan", "blocked", f"CVE policy violated: {summary}"))
    elif scan.findings:
        report.items.append(ReleaseGateItem("vuln-scan", "review", f"Known advisories present (non-blocking): {summary}"))
    else:
        report.items.append(ReleaseGateItem("vuln-scan", "ready", f"No known advisories matched: {summary}"))


def _check_iso_and_checksums(report: ReleaseGateReport, iso: Path, output_dir: Path) -> None:
    if not iso.exists():
        report.items.append(ReleaseGateItem("iso", "blocked", "Final ISO is missing."))
        report.items.append(ReleaseGateItem("sha256", "blocked", "Cannot verify SHA256 without an ISO."))
        return
    report.items.append(ReleaseGateItem("iso", "ready", f"{iso.stat().st_size} bytes"))
    sums = output_dir / "SHA256SUMS"
    if not sums.exists():
        report.items.append(ReleaseGateItem("sha256", "blocked", "SHA256SUMS is missing."))
        return
    expected = _sha_from_sums(sums, iso.name)
    actual = _sha256(iso)
    if expected != actual:
        report.items.append(ReleaseGateItem("sha256", "blocked", "SHA256SUMS does not match the ISO."))
        return
    report.items.append(ReleaseGateItem("sha256", "ready", actual))


def _check_release_files(report: ReleaseGateReport, output_dir: Path, options: BuildOptions) -> None:
    sbom_format = options.provenance.sbom_format
    sbom_filename = (
        SPDX_FILENAME if sbom_format == "spdx" else CYCLONEDX_FILENAME if sbom_format == "cyclonedx" else None
    )
    for code, filename, enabled in (
        ("buildinfo", "BUILDINFO", options.release_artifacts.enabled),
        ("provenance", "distroforge-provenance.json", options.provenance.enabled),
        ("sbom", sbom_filename, options.provenance.enabled and sbom_filename is not None),
        ("html-report", options.html_report.filename, options.html_report.enabled),
    ):
        if filename is None:
            report.items.append(ReleaseGateItem(code, "review", "Standard-format SBOM export is not enabled."))
            continue
        path = output_dir / filename
        if path.exists():
            report.items.append(ReleaseGateItem(code, "ready", str(path)))
        elif enabled:
            report.items.append(ReleaseGateItem(code, "blocked", f"Expected release file is missing: {filename}"))
        else:
            report.items.append(ReleaseGateItem(code, "review", f"{filename} is not enabled."))


def _check_boot_proof(report: ReleaseGateReport, output_dir: Path, options: BuildOptions) -> None:
    qemu_report = output_dir / options.prebuild_vm.report_name
    proof = output_dir / "boot-proof.json"
    if qemu_report.exists():
        report.items.append(ReleaseGateItem("boot-proof", "ready", f"runtime proof: {qemu_report}"))
    elif proof.exists() and _boot_proof_summary(proof)["status"] == "ready":
        summary = _boot_proof_summary(proof)
        report.items.append(ReleaseGateItem("boot-proof", "ready", f"{summary['proof_level']} proof via {summary['selected_backend']}: {proof}"))
    elif proof.exists():
        summary = _boot_proof_summary(proof)
        report.items.append(ReleaseGateItem("boot-proof", "blocked", f"Boot proof report is not ready: {summary['status']} via {summary['selected_backend']}."))
    elif options.prebuild_vm.enabled or options.bootcheck.enabled or options.qa.scenarios:
        report.items.append(ReleaseGateItem("boot-proof", "blocked", "Boot proof is configured but no executed proof report exists."))
    else:
        report.items.append(ReleaseGateItem("boot-proof", "blocked", "No QEMU, bootcheck or QA proof configured."))


def _check_release_readiness(report: ReleaseGateReport, iso: Path, output_dir: Path) -> None:
    readiness = ReleaseReadinessService().check(iso, output_dir)
    report.items.append(
        ReleaseGateItem(
            "release-readiness",
            "blocked" if readiness.blocked else "review",
            "Release readiness report is available; review non-blocking evidence items.",
        )
    )


def _check_packaging_policy(report: ReleaseGateReport, root: Path) -> None:
    if not (root / "debian/control").exists():
        report.items.append(ReleaseGateItem("packaging-policy", "review", "No Debian source package metadata in project root."))
        return
    policy = packaging_policy_report(root)
    if policy.blocked:
        report.items.append(ReleaseGateItem("packaging-policy", "blocked", "Packaging policy is blocked."))
        return
    autopkgtest_status = policy.autopkgtest_policy.status if policy.autopkgtest_policy else "undeclared"
    status = "ready" if autopkgtest_status == "declared and meaningful" else "review"
    report.items.append(ReleaseGateItem("packaging-policy", status, f"Autopkgtest: {autopkgtest_status}."))


def _check_publish_signing(report: ReleaseGateReport, root: Path, options: BuildOptions) -> None:
    if not options.release_artifacts.sign:
        return
    bundle = root / "dist" / "publish"
    required = ("RELEASE-MANIFEST.json", "SIGNING-REPORT.json", "SHA256SUMS.asc", "RELEASE-GATE.json.asc", "RELEASE-MANIFEST.json.asc")
    missing = [name for name in required if not (bundle / name).exists()]
    if missing:
        report.items.append(ReleaseGateItem("publish-signing", "review", f"Missing publish signing evidence: {', '.join(missing)}"))
    else:
        report.items.append(ReleaseGateItem("publish-signing", "ready", str(bundle)))


def _sha_from_sums(path: Path, name: str) -> str | None:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and Path(parts[-1]).name == name:
            return parts[0]
    return None


def _boot_proof_summary(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"status": "invalid", "selected_backend": "unknown", "proof_level": "none"}
    if not isinstance(data, dict):
        return {"status": "invalid", "selected_backend": "unknown", "proof_level": "none"}
    return {
        "status": str(data.get("status", "unknown")),
        "selected_backend": str(data.get("selected_backend", data.get("backend", "unknown"))),
        "proof_level": str(data.get("proof_level", "none")),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
