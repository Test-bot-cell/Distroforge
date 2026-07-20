from __future__ import annotations

import pytest

from distroforge.cli import main
from distroforge.core.project import Project


def test_cli_doctor_python(capsys) -> None:
    main(["doctor", "--python"])

    output = capsys.readouterr().out
    assert "Python Dependencies" in output or "pydantic" in output


def test_cli_releases(capsys) -> None:
    main(["releases"])

    output = capsys.readouterr().out
    assert "26.04" in output


def test_cli_build_phases_renders_full_catalog(capsys) -> None:
    main(["build-phases"])

    output = capsys.readouterr().out
    assert "DistroForge build phase contracts" in output
    assert "[run_preflight]" in output
    assert "[assemble_iso]" in output
    assert "snapshot" in output
    assert "rollback:   after-apt, after-customize, after-sanitize" in output
    assert "privileged: yes" in output


def test_cli_build_phases_stage_filter_scopes_output(capsys) -> None:
    main(["build-phases", "--stage", "assemble_iso"])

    output = capsys.readouterr().out
    assert "[assemble_iso]" in output
    assert "[customize_target]" not in output


def test_cli_build_phases_rejects_unknown_stage(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["build-phases", "--stage", "bogus"])

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "invalid choice: 'bogus'" in err
    assert "Traceback" not in err


def test_cli_missing_project_is_user_facing(capsys, tmp_path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["ux-audit", str(tmp_path / "missing")])

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "distroforge: error:" in err
    assert "No DistroForge project found" in err
    assert "Traceback" not in err


def test_cli_invalid_definition_is_user_facing(capsys, tmp_path) -> None:
    project = Project.create("BadDef", tmp_path / "bad-def", "26.04")
    project.source_mode = "bootstrap"
    project.save()
    definition = tmp_path / "bad.yaml"
    definition.write_text("kernel:\n  unknown: true\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["build", str(project.root), "--definition", str(definition)])

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "distroforge: error:" in err
    assert "unknown" in err
    assert "Traceback" not in err


def test_cli_broken_yaml_is_user_facing(capsys, tmp_path) -> None:
    project = Project.create("BrokenYaml", tmp_path / "broken-yaml", "26.04")
    project.source_mode = "bootstrap"
    project.save()
    definition = tmp_path / "broken.yaml"
    definition.write_text("source_mode: [\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["build", str(project.root), "--definition", str(definition)])

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "distroforge: error:" in err
    assert "Traceback" not in err


def test_cli_dry_run_report_writes_output_file(capsys, tmp_path) -> None:
    project = Project.create("Reportable", tmp_path / "reportable", "26.04")
    project.source_mode = "bootstrap"
    project.save()
    output = tmp_path / "dry-run.txt"

    main(["dry-run-report", str(project.root), "--no-command-simulation", "--output", str(output)])

    assert f"Wrote {output}" in capsys.readouterr().out
    assert "Dry-run report:" in output.read_text(encoding="utf-8")


def test_cli_plan_reports_sanitized_legacy_desktop_packages(capsys, tmp_path) -> None:
    project = Project.create("PlanSanitize", tmp_path / "plan-sanitize", "26.04")
    project.source_mode = "bootstrap"
    project.customization.desktop = "ubuntu"
    project.packages = ["kubuntu-desktop", "vim", "xubuntu-desktop"]
    project.save()

    main(["plan", str(project.root)])

    out = capsys.readouterr().out
    assert "Sanitized legacy desktop packages from project metadata:" in out
    assert "kubuntu-desktop" in out
    assert "xubuntu-desktop" in out


@pytest.mark.parametrize(
    "desktop,expected",
    [
        ("ubuntu", "ubuntu-desktop"),
        ("ubuntu_minimal", "ubuntu-desktop-minimal"),
        ("xubuntu", "xubuntu-desktop"),
    ],
)
def test_cli_build_dry_run_respects_selected_desktop_package(capsys, tmp_path, desktop, expected) -> None:
    project = Project.create(f"DesktopPlan-{desktop}", tmp_path / f"desktop-plan-{desktop}", "26.04")
    project.source_mode = "bootstrap"
    project.save()

    main([
        "build",
        str(project.root),
        "--desktop",
        desktop,
        "--no-sanitize",
        "--no-prune-obsolete-packages",
    ])

    out = capsys.readouterr().out
    install_lines = [line for line in out.splitlines() if "apt-get -y install" in line]
    assert install_lines
    desktop_line = next(line for line in install_lines if expected in line)
    assert expected in desktop_line
    packages = set(desktop_line.split())
    desktop_tokens = {
        token
        for token in packages
        if token in {
            "ubuntu-desktop",
            "ubuntu-desktop-minimal",
            "xubuntu-desktop",
            "kubuntu-desktop",
            "lubuntu-desktop",
            "ubuntu-mate-desktop",
            "ubuntu-budgie-desktop",
            "ubuntu-unity-desktop",
            "gnome-core",
            "task-gnome-desktop",
            "task-xfce-desktop",
            "task-kde-desktop",
            "task-lxqt-desktop",
            "task-mate-desktop",
            "task-cinnamon-desktop",
            "budgie-desktop",
        }
    }
    assert expected in desktop_tokens
    assert desktop_tokens == {expected}


def test_cli_dry_run_report_reports_sanitized_legacy_desktop_packages(capsys, tmp_path) -> None:
    project = Project.create("DryRunSanitize", tmp_path / "dryrun-sanitize", "26.04")
    project.source_mode = "bootstrap"
    project.customization.desktop = "ubuntu"
    project.packages = ["xubuntu-desktop", "vim", "kubuntu-desktop"]
    project.save()
    output = tmp_path / "dry-run-report.txt"

    main(["dry-run-report", str(project.root), "--no-command-simulation", "--output", str(output)])

    out = capsys.readouterr().out
    assert "Sanitized legacy desktop packages from project metadata:" in out
    assert "kubuntu-desktop" in out
    assert "xubuntu-desktop" in out
    assert f"Wrote {output}" in out
    assert "Dry-run report:" in output.read_text(encoding="utf-8")


def test_cli_build_blocks_on_cve_policy(capsys, tmp_path, monkeypatch) -> None:
    # main() persists --no-sudo as os.environ["DISTROFORGE_PRIVILEGE"]; let monkeypatch
    # restore it on teardown so the privilege backend does not leak into later tests.
    monkeypatch.setenv("DISTROFORGE_PRIVILEGE", "none")
    project = Project.create("CveCli", tmp_path / "cve-cli", "26.04")
    project.source_mode = "bootstrap"
    project.save()

    with pytest.raises(SystemExit) as exc:
        main(
            [
                "build",
                str(project.root),
                "--no-sudo",
                "--install",
                "curl",
                "--vuln-scan",
                "--vuln-policy",
                "block-high",
                "--sbom-format",
                "spdx",
            ]
        )

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "distroforge: error:" in err
    assert "CVE policy" in err
    assert "Traceback" not in err


def test_cli_host_lists_capabilities(capsys) -> None:
    main(["host"])

    out = capsys.readouterr().out
    assert "real-build" in out
    assert "xorriso" in out
    assert "nspawn-terminal" in out


def test_cli_host_json_lists_capabilities(capsys) -> None:
    main(["host", "--json"])

    out = capsys.readouterr().out
    assert '"name": "nspawn-terminal"' in out
    assert '"available":' in out


def test_cli_chroot_backends_lists_backends(capsys) -> None:
    main(["chroot-backends"])

    out = capsys.readouterr().out
    assert "auto" in out
    assert "chroot" in out
    assert "nspawn" in out


def test_cli_chroot_backends_json_lists_selection(capsys) -> None:
    main(["chroot-backends", "--json"])

    out = capsys.readouterr().out
    assert '"name": "auto"' in out
    assert '"selected": true' in out
    assert '"active":' in out


def test_cli_summary_json_outputs_are_parseable(capsys, tmp_path) -> None:
    import json

    project = Project.create("JsonCli", tmp_path / "json-cli", "26.04")
    project.source_mode = "bootstrap"
    project.save()
    iso = tmp_path / "missing.iso"
    commands = (
        ["host", "--json"],
        ["chroot-backends", "--json"],
        ["artifact-paths", str(project.root), "--json"],
        ["qemu-smoke-plan", "--iso", str(iso), "--json"],
    )
    for command in commands:
        main(command)
        json.loads(capsys.readouterr().out)


def test_cli_profiles_lists_builtin_profiles(capsys) -> None:
    main(["profiles"])

    out = capsys.readouterr().out
    assert "General desktop" in out
    assert "Developer workstation" in out
    assert " - " in out


def test_cli_personas_lists_workflow_levels(capsys) -> None:
    main(["personas"])

    out = capsys.readouterr().out
    assert "Beginner" in out
    assert "Maintainer" in out
    assert "qa=live-bios" in out


def test_cli_desktops_lists_source_and_packages(capsys) -> None:
    main(["desktops"])

    out = capsys.readouterr().out
    assert "dm=gdm3" in out
    assert "ubuntu=[ubuntu-desktop]" in out
    assert "debian=[" in out


def test_cli_branding_palettes_lists_palettes_and_generate_hint(capsys) -> None:
    main(["branding-palettes"])

    out = capsys.readouterr().out
    assert "forge" in out
    assert "generate     Generate a deterministic palette from --brand-palette-seed" in out


def test_cli_autoinstall_templates_lists_names(capsys) -> None:
    main(["autoinstall-templates"])

    out = capsys.readouterr().out
    assert "direct" in out
    assert "encrypted" in out
    assert "oem" in out


def test_cli_autoinstall_templates_render_emits_template(capsys) -> None:
    main(["autoinstall-templates", "--render", "direct"])

    out = capsys.readouterr().out
    assert "storage" in out
    assert "direct" in out


def test_cli_restore_snapshot_dry_run_emits_plan(capsys, tmp_path) -> None:
    main(["restore-snapshot", str(tmp_path / "proj"), "snap1"])

    out = capsys.readouterr().out
    assert "- tar --zstd -xpf" in out
    assert "snap1.tar.zst" in out


def test_cli_secureboot_assist_dry_run_emits_plan(capsys, tmp_path) -> None:
    main(["secureboot-assist", str(tmp_path / "keys")])

    out = capsys.readouterr().out
    assert "- openssl req" in out
    assert "mokutil --import" in out
    assert "MOK.der" in out


def test_cli_explain_prints_plan(capsys, tmp_path) -> None:
    project = Project.create("ExplainStrict", tmp_path / "explain-strict", "26.04")
    project.source_mode = "broken"
    project.save()

    main(["explain", str(project.root)])

    assert "DistroForge build explanation" in capsys.readouterr().out
