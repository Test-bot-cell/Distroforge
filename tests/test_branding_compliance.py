from __future__ import annotations

import json

import pytest

from distroforge.cli import main
from distroforge.core.branding import BrandingOptions
from distroforge.core.branding_compliance import BrandingComplianceService
from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.debrand import DebrandService
from distroforge.core.profiles import load_profiles
from distroforge.core.project import Project


class RecordingExecuteRunner(CommandRunner):
    def __init__(self) -> None:
        super().__init__(dry_run=False)

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        return CommandResult(spec=spec, returncode=0, stdout="", stderr="")


def test_branding_compliance_scans_all_visible_fields(tmp_path) -> None:
    project = Project.create("Planetfall", tmp_path / "planetfall", "26.04")
    options = BrandingOptions(
        name="Planetfall",
        vendor="Canonical",
        grub_distributor="Ubuntu",
        icon_name="ubuntu-logo",
        issue_text="Welcome to Ubuntu",
    )

    report = BrandingComplianceService().audit(project, options, "redistributable")

    fields = {finding.field for finding in report.findings}
    assert {"vendor", "grub_distributor", "icon_name", "issue_text"}.issubset(fields)
    assert report.status == "blocked"
    assert all(finding.severity == "error" for finding in report.findings)


def test_branding_clearance_writes_json(tmp_path) -> None:
    project = Project.create("Planetfall", tmp_path / "planetfall", "26.04")

    report = BrandingComplianceService().write_clearance(
        project,
        BrandingOptions(name="Planetfall"),
        mode="redistributable",
    )

    payload = json.loads((project.output_dir / "TRADEMARK-CLEARANCE.json").read_text(encoding="utf-8"))
    assert report.status == "clear"
    assert payload["status"] == "clear"
    assert payload["mode"] == "redistributable"


def test_debrand_scan_finds_source_identity_traces(tmp_path) -> None:
    project = Project.create("Planetfall", tmp_path / "planetfall", "26.04")
    grub = project.iso_root / "boot/grub/grub.cfg"
    issue = project.squashfs_root / "etc/issue"
    grub.parent.mkdir(parents=True)
    issue.parent.mkdir(parents=True)
    grub.write_text('menuentry "Try Ubuntu without installing" {}\n', encoding="utf-8")
    issue.write_text("Ubuntu 26.04 LTS\n", encoding="utf-8")

    report = DebrandService().scan(project, BrandingOptions(name="Planetfall"))

    paths = {finding.path for finding in report.findings}
    assert "boot/grub/grub.cfg" in paths
    assert "etc/issue" in paths
    assert report.status == "needs-debranding"


def test_debrand_apply_replaces_text_and_keeps_plan_report(tmp_path) -> None:
    project = Project.create("Planetfall", tmp_path / "planetfall", "26.04")
    grub = project.iso_root / "boot/grub/grub.cfg"
    grub.parent.mkdir(parents=True)
    grub.write_text('set distributor="Ubuntu"\n', encoding="utf-8")

    report = DebrandService(CommandRunner(dry_run=False)).apply(
        project,
        BrandingOptions(name="Planetfall"),
        strict=True,
    )

    assert report.status == "applied"
    assert report.findings
    assert 'set distributor="Planetfall"' in grub.read_text(encoding="utf-8")


def test_debrand_apply_uses_privileged_write_for_locked_text_files(tmp_path) -> None:
    project = Project.create("Planetfall", tmp_path / "planetfall", "26.04")
    os_release = project.squashfs_root / "etc/os-release"
    os_release.parent.mkdir(parents=True)
    os_release.write_text('NAME="Ubuntu"\n', encoding="utf-8")
    os_release.chmod(0o444)
    runner = RecordingExecuteRunner()

    try:
        report = DebrandService(runner).apply(
            project,
            BrandingOptions(name="Planetfall"),
            use_sudo=True,
        )
    finally:
        os_release.chmod(0o644)

    assert report.status == "applied"
    commands = [spec.argv for spec in runner.history]
    assert any(command[:4] == ("sudo", "-A", "sh", "-c") or command[:3] == ("sudo", "sh", "-c") for command in commands)


def test_debrand_does_not_rename_kernel_module_paths(tmp_path) -> None:
    project = Project.create("Planetfall", tmp_path / "planetfall", "26.04")
    module = (
        project.squashfs_root
        / "usr/lib/modules/7.0.0-15-generic/kernel/ubuntu/ubuntu-host/ubuntu-host.ko.zst"
    )
    module.parent.mkdir(parents=True)
    module.write_bytes(b"module")

    report = DebrandService(CommandRunner(dry_run=False)).apply(
        project,
        BrandingOptions(name="Planetfall"),
        strict=True,
    )

    assert report.status == "applied"
    assert module.exists()
    assert not (
        project.squashfs_root
        / "usr/lib/modules/7.0.0-15-generic/kernel/planetfall/planetfall-host/planetfall-host.ko.zst"
    ).exists()


def test_debrand_uses_privileged_rename_for_locked_branding_paths(tmp_path) -> None:
    project = Project.create("Planetfall", tmp_path / "planetfall", "26.04")
    theme = project.squashfs_root / "usr/share/plymouth/themes/ubuntu-logo"
    theme.mkdir(parents=True)
    theme.parent.chmod(0o555)
    runner = RecordingExecuteRunner()

    try:
        report = DebrandService(runner).apply(
            project,
            BrandingOptions(name="Planetfall"),
            use_sudo=True,
        )
    finally:
        theme.parent.chmod(0o755)

    assert report.status == "applied"
    commands = [spec.argv for spec in runner.history]
    assert any(command[:3] == ("sudo", "-A", "mv") or command[:2] == ("sudo", "mv") for command in commands)


def test_cli_branding_validate_blocks_redistributable_marks(tmp_path, capsys) -> None:
    project = Project.create("Planetfall", tmp_path / "planetfall", "26.04")
    definition = tmp_path / "brand.json"
    definition.write_text(
        json.dumps({"branding": {"name": "Planetfall", "vendor": "Canonical"}}),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc:
        main(["branding", "validate", str(project.root), "--definition", str(definition)])

    assert exc.value.code == 2
    assert "canonical-trademark-branding" in capsys.readouterr().out


def test_cli_branding_compliance_alias_runs_audit(tmp_path, capsys) -> None:
    project = Project.create("Planetfall", tmp_path / "planetfall", "26.04")
    project.save()

    main(["branding", "compliance", str(project.root)])

    assert "Branding compliance: clear" in capsys.readouterr().out


def test_cli_branding_preview_and_export_identity(tmp_path, capsys) -> None:
    project = Project.create("Planetfall", tmp_path / "planetfall", "26.04")
    project.save()

    main(["branding", "preview", str(project.root)])
    output = capsys.readouterr().out

    assert "Brand identity preview" in output
    assert (project.output_dir / "branding-preview" / "grub.cfg").exists()
    assert (project.output_dir / "branding-preview" / "os-release").exists()

    main(["branding", "export", str(project.root)])
    payload = json.loads((project.output_dir / "BRANDING-MANIFEST.json").read_text(encoding="utf-8"))
    assert payload["short_name"] == "Planetfall"


def test_profiles_cover_target_distro_families_and_cli_output(tmp_path, capsys) -> None:
    expected = {"desktop", "developer", "gaming", "education", "enterprise", "privacy", "lightweight"}
    assert expected.issubset(load_profiles())

    project = Project.create("Planetfall", tmp_path / "planetfall", "26.04")
    project.save()
    main(["profile", "diff", str(project.root), "gaming"])

    output = capsys.readouterr().out
    assert "Profile: gaming" in output
    assert "Install:" in output
    assert "steam-installer" in output


def test_profile_diff_accepts_json_output(tmp_path, capsys) -> None:
    project = Project.create("Planetfall", tmp_path / "planetfall-diff", "26.04")
    project.save()

    main(["profile", "diff", str(project.root), "gaming", "--json"])
    explicit = json.loads(capsys.readouterr().out)
    assert explicit["metadata"]["profile"] == "gaming"
    assert explicit["metadata"]["profile_label"] == "Gaming"
