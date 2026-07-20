from __future__ import annotations

import json

import pytest

import distroforge.core.bootstrap as bootstrap_module
from distroforge.core.apt import PackagePlan
from distroforge.core.bootstrap import BootstrapOptions, BootstrapService, host_dpkg_arch
from distroforge.core.build import BuildOptions, BuildOrchestrator, BuildPhase
from distroforge.core.command import CommandRunner
from distroforge.core.project import Project
from distroforge.core.provenance import (
    CYCLONEDX_FILENAME,
    SPDX_FILENAME,
    ProvenanceOptions,
    ProvenanceService,
)
from distroforge.core.releases import get_release
from distroforge.core.vulnscan import VulnScanOptions, VulnScanService


def _bootstrap_project(tmp_path, name: str) -> Project:
    project = Project.create(name, tmp_path / name.lower(), "26.04")
    project.source_mode = "bootstrap"
    return project


# --------------------------------------------------------------------------- #
# #1 CVE / vulnerability scanning
# --------------------------------------------------------------------------- #


def test_vuln_scan_matches_bundled_advisory_by_name() -> None:
    report = VulnScanService(VulnScanOptions(enabled=True, policy="warn")).scan(["curl", "vim"])

    assert report.scanned == 2
    assert [finding.cve for finding in report.findings] == ["CVE-2023-38545"]
    finding = report.findings[0]
    assert finding.package == "curl" and finding.severity == "high"
    assert finding.level == "warning" and report.ok is True


def test_vuln_policy_block_high_promotes_high_to_error() -> None:
    report = VulnScanService(VulnScanOptions(enabled=True, policy="block-high")).scan(["curl"])

    assert report.findings[0].level == "error"
    assert report.ok is False


def test_vuln_policy_block_critical_ignores_high_but_blocks_critical() -> None:
    service = VulnScanService(VulnScanOptions(enabled=True, policy="block-critical"))

    high_only = service.scan(["curl"])
    assert high_only.findings[0].level == "warning"
    assert high_only.ok is True

    with_critical = service.scan(["curl", "libwebp"])
    levels = {finding.package: finding.level for finding in with_critical.findings}
    assert levels["curl"] == "warning"
    assert levels["libwebp"] == "error"
    assert with_critical.ok is False
    # Findings are ordered by descending severity, so critical comes first.
    assert with_critical.findings[0].package == "libwebp"


def test_vuln_scan_disabled_returns_empty_report() -> None:
    report = VulnScanService(VulnScanOptions(enabled=False)).scan(["curl", "sudo"])

    assert report.findings == []
    assert report.ok is True
    assert "disabled" in report.render_text()


def test_vuln_scan_missing_custom_db_reports_unavailable(tmp_path) -> None:
    options = VulnScanOptions(enabled=True, policy="block-critical", db_path=tmp_path / "nope.json")

    report = VulnScanService(options).scan(["curl"])

    assert [finding.cve for finding in report.findings] == ["DB-UNAVAILABLE"]
    # A database we cannot read is a warning, never a silent pass to "error".
    assert report.findings[0].level == "warning"
    assert report.ok is True


def test_vuln_enforce_records_command_and_raises_on_error() -> None:
    runner = CommandRunner(dry_run=True)
    service = VulnScanService(VulnScanOptions(enabled=True, policy="block-critical"))

    with pytest.raises(ValueError, match="CVE policy"):
        service.enforce(["xz-utils"], runner)

    assert ("vuln-report", "blocked", "1") in [spec.argv for spec in runner.history]


def test_vuln_enforce_passes_clean_package_set() -> None:
    runner = CommandRunner(dry_run=True)
    service = VulnScanService(VulnScanOptions(enabled=True, policy="block-high"))

    report = service.enforce(["vim", "htop"], runner)

    assert report.ok is True
    assert ("vuln-report", "ok", "0") in [spec.argv for spec in runner.history]


def test_build_blocks_on_cve_policy_in_dry_run(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "CveGate")
    options = BuildOptions(
        use_sudo=False,
        package_plan=PackagePlan(install=["curl"]),
        vuln_scan=VulnScanOptions(enabled=True, policy="block-high"),
    )
    runner = CommandRunner(dry_run=True)

    with pytest.raises(ValueError, match="CVE policy"):
        BuildOrchestrator(project, runner, options).run()

    assert ("vuln-report", "blocked", "1") in [spec.argv for spec in runner.history]


def test_build_warn_policy_records_report_without_blocking(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "CveWarn")
    options = BuildOptions(
        use_sudo=False,
        package_plan=PackagePlan(install=["curl"]),
        vuln_scan=VulnScanOptions(enabled=True, policy="warn"),
    )
    runner = CommandRunner(dry_run=True)

    report = BuildOrchestrator(project, runner, options).run()

    assert ("vuln-report", "ok", "1") in [spec.argv for spec in runner.history]
    assert BuildPhase.VULN_SCAN in {step.phase for step in report.steps}


# --------------------------------------------------------------------------- #
# #2 Standard SBOM export (SPDX / CycloneDX)
# --------------------------------------------------------------------------- #


def test_spdx_document_lists_packages_with_purls(tmp_path) -> None:
    project = Project.create("SpdxDoc", tmp_path / "spdx-doc", "26.04")
    service = ProvenanceService(CommandRunner(dry_run=True), project, ProvenanceOptions())

    doc = service.spdx_document(["curl", "vim"])

    assert doc["spdxVersion"] == "SPDX-2.3"
    names = {pkg["name"] for pkg in doc["packages"]}
    assert names == {"curl", "vim"}
    curl = next(pkg for pkg in doc["packages"] if pkg["name"] == "curl")
    assert curl["versionInfo"] == "NOASSERTION"
    assert curl["externalRefs"][0]["referenceLocator"].endswith("/curl")
    assert all(rel["relationshipType"] == "DESCRIBES" for rel in doc["relationships"])


def test_cyclonedx_document_has_os_root_and_library_components(tmp_path) -> None:
    project = Project.create("CdxDoc", tmp_path / "cdx-doc", "26.04")
    service = ProvenanceService(CommandRunner(dry_run=True), project, ProvenanceOptions())

    doc = service.cyclonedx_document(["curl"])

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["metadata"]["component"]["type"] == "operating-system"
    assert doc["components"][0]["purl"].endswith("/curl")


def test_provenance_dry_run_plans_spdx_target(tmp_path) -> None:
    project = Project.create("SpdxPlan", tmp_path / "spdx-plan", "26.04")
    runner = CommandRunner(dry_run=True)
    options = ProvenanceOptions(enabled=True, sbom_format="spdx")

    ProvenanceService(runner, project, options).write(project.output_dir / "x.iso", ["curl"])

    written = [spec.argv[1] for spec in runner.history if spec.argv[0] == "write-file"]
    assert str(project.output_dir / SPDX_FILENAME) in written
    assert str(project.output_dir / "distroforge-provenance.json") in written


def test_provenance_dry_run_plans_cyclonedx_target(tmp_path) -> None:
    project = Project.create("CdxPlan", tmp_path / "cdx-plan", "26.04")
    runner = CommandRunner(dry_run=True)
    options = ProvenanceOptions(enabled=True, sbom_format="cyclonedx")

    ProvenanceService(runner, project, options).write(project.output_dir / "x.iso", ["curl"])

    written = [spec.argv[1] for spec in runner.history if spec.argv[0] == "write-file"]
    assert str(project.output_dir / CYCLONEDX_FILENAME) in written


def test_provenance_native_format_writes_only_provenance(tmp_path) -> None:
    project = Project.create("NativePlan", tmp_path / "native-plan", "26.04")
    runner = CommandRunner(dry_run=True)
    options = ProvenanceOptions(enabled=True, sbom_format="native")

    ProvenanceService(runner, project, options).write(project.output_dir / "x.iso", ["curl"])

    written = [spec.argv[1] for spec in runner.history if spec.argv[0] == "write-file"]
    assert written == [str(project.output_dir / "distroforge-provenance.json")]


def test_provenance_writes_valid_spdx_to_disk(tmp_path) -> None:
    project = Project.create("SpdxDisk", tmp_path / "spdx-disk", "26.04")
    options = ProvenanceOptions(enabled=True, sbom_format="spdx")

    ProvenanceService(CommandRunner(dry_run=False), project, options).write(
        project.output_dir / "x.iso", ["curl", "vim"]
    )

    doc = json.loads((project.output_dir / SPDX_FILENAME).read_text(encoding="utf-8"))
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert {pkg["name"] for pkg in doc["packages"]} == {"curl", "vim"}


# --------------------------------------------------------------------------- #
# #3 True cross-arch bootstrap (arm64 on amd64)
# --------------------------------------------------------------------------- #


def test_host_dpkg_arch_maps_machine_names(monkeypatch) -> None:
    monkeypatch.setattr(bootstrap_module.platform, "machine", lambda: "x86_64")
    assert host_dpkg_arch() == "amd64"
    monkeypatch.setattr(bootstrap_module.platform, "machine", lambda: "aarch64")
    assert host_dpkg_arch() == "arm64"


def _bootstrap_service(tmp_path, arch: str) -> BootstrapService:
    return BootstrapService(
        CommandRunner(dry_run=True),
        get_release("26.04"),
        tmp_path / "root",
        tmp_path / "iso",
        BootstrapOptions(arch=arch),
        use_sudo=False,
    )


def test_bootstrap_grub_packages_are_arch_aware(tmp_path) -> None:
    amd64 = _bootstrap_service(tmp_path, "amd64")._base_packages()
    arm64 = _bootstrap_service(tmp_path, "arm64")._base_packages()

    assert "grub-pc-bin" in amd64
    assert "grub-efi-amd64-bin" in amd64
    assert "grub-pc-bin" not in arm64
    assert "grub-efi-arm64-bin" in arm64


def test_bootstrap_kernel_meta_package_is_arch_independent_on_ubuntu(tmp_path) -> None:
    arm64 = _bootstrap_service(tmp_path, "arm64")._base_packages()
    assert "linux-generic" in arm64


def test_cross_arch_build_requires_qemu_and_skips_bios(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(bootstrap_module, "host_dpkg_arch", lambda: "amd64")
    project = _bootstrap_project(tmp_path, "ArmRemix")
    options = BuildOptions(use_sudo=False, bootstrap=BootstrapOptions(arch="arm64"))
    runner = CommandRunner(dry_run=True)

    BuildOrchestrator(project, runner, options).run()

    commands = [spec.argv for spec in runner.history]
    assert ("qemu-user-static-required", "arm64", "amd64") in commands
    assert ("bootstrap-bios-skip", "arm64") in commands


def test_native_amd64_build_does_not_require_qemu(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(bootstrap_module, "host_dpkg_arch", lambda: "amd64")
    project = _bootstrap_project(tmp_path, "Amd64Remix")
    options = BuildOptions(use_sudo=False, bootstrap=BootstrapOptions(arch="amd64"))
    runner = CommandRunner(dry_run=True)

    BuildOrchestrator(project, runner, options).run()

    commands = [spec.argv for spec in runner.history]
    assert not any(argv[0] == "qemu-user-static-required" for argv in commands)
    assert not any(argv == ("bootstrap-bios-skip", "amd64") for argv in commands)
    # amd64 is a BIOS arch, so the El Torito image is planned rather than skipped.
    assert any(
        argv[0] == "write-file" and argv[1].endswith("i386-pc/eltorito.img") for argv in commands
    )
