from __future__ import annotations

import json

import pytest
import yaml

from distroforge.cli import main
from distroforge.core.capture import InstalledSystemCaptureService
from distroforge.core.live_build import LiveBuildPlanner
from distroforge.core.systemd_image import SystemdImagePlan
from distroforge.core.upgrade_media import UpgradeMediaPreflight


def _fake_root(tmp_path):
    root = tmp_path / "target"
    (root / "etc/apt/sources.list.d").mkdir(parents=True)
    (root / "var/lib/dpkg").mkdir(parents=True)
    (root / "etc/default").mkdir(parents=True)
    (root / "etc/systemd/system/multi-user.target.wants").mkdir(parents=True)
    (root / "etc/os-release").write_text(
        'ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\nPRETTY_NAME="Ubuntu 26.04 LTS"\n',
        encoding="utf-8",
    )
    (root / "var/lib/dpkg/status").write_text(
        "Package: vim\nStatus: install ok installed\n\n"
        "Package: curl\nStatus: install ok installed\n\n",
        encoding="utf-8",
    )
    (root / "etc/apt/sources.list").write_text(
        "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu resolute main\n",
        encoding="utf-8",
    )
    (root / "etc/default/locale").write_text("LANG=fr_FR.UTF-8\n", encoding="utf-8")
    (root / "etc/default/keyboard").write_text('XKBLAYOUT="fr"\n', encoding="utf-8")
    (root / "etc/timezone").write_text("Europe/Paris\n", encoding="utf-8")
    (root / "etc/hostname").write_text("forgebox\n", encoding="utf-8")
    (root / "etc/systemd/system/multi-user.target.wants/ssh.service").write_text("", encoding="utf-8")
    return root


def test_capture_installed_system_profile_is_rebuildable(tmp_path) -> None:
    root = _fake_root(tmp_path)

    profile = InstalledSystemCaptureService().capture(root)
    data = profile.to_dict()

    assert data["source_mode"] == "bootstrap"
    assert data["packages"] == ["curl", "vim"]
    assert data["customization"]["locale"] == "fr_FR.UTF-8"
    assert data["customization"]["timezone"] == "Europe/Paris"
    assert data["customization"]["keyboard_layout"] == "fr"
    assert data["sanitize"]["ssh_host_keys"] is True
    assert data["capture"]["report"]["counts"]["dangerous"] >= 1
    assert data["capture_config_files"][0]["path"] == "/etc/default/keyboard"
    assert data["capture_config_files"][0]["sha256"]


def test_capture_config_globs_embed_whitelisted_files_and_exclude_secrets(tmp_path) -> None:
    root = _fake_root(tmp_path)
    (root / "etc/distroforge").mkdir()
    (root / "etc/distroforge/profile.conf").write_text("CHANNEL=stable\n", encoding="utf-8")
    (root / "etc/distroforge/token.conf").write_text("TOKEN=secret\n", encoding="utf-8")

    profile = InstalledSystemCaptureService().capture(
        root,
        include_config_globs=["/etc/distroforge/*.conf"],
    )
    data = profile.to_dict()

    paths = {item["path"] for item in data["capture_config_files"]}
    assert "/etc/distroforge/profile.conf" in paths
    assert "/etc/distroforge/token.conf" not in paths
    assert any(
        finding["path"] == "/etc/distroforge/token.conf" and finding["status"] == "dangerous"
        for finding in data["capture"]["report"]["findings"]
    )


def test_cli_capture_and_rebuild_from_capture(tmp_path, capsys) -> None:
    root = _fake_root(tmp_path)
    (root / "etc/distroforge").mkdir()
    (root / "etc/distroforge/profile.conf").write_text("CHANNEL=stable\n", encoding="utf-8")
    profile = tmp_path / "captured.yaml"
    project_root = tmp_path / "rebuild"

    main([
        "capture",
        str(root),
        "--output",
        str(profile),
        "--include-config-glob",
        "/etc/distroforge/*.conf",
    ])
    assert profile.exists()
    assert "Wrote" in capsys.readouterr().out
    assert "/etc/distroforge/profile.conf" in profile.read_text(encoding="utf-8")

    main(["rebuild-from-capture", str(profile), str(project_root)])
    output = capsys.readouterr().out
    assert "Created" in output
    assert (project_root / "project.json").exists()
    assert (project_root / "captured-profile.yaml").exists()


def test_live_build_plan_writes_reviewable_config(tmp_path) -> None:
    profile = tmp_path / "captured.yaml"
    profile.write_text(
        yaml.safe_dump(
            {
                "packages": ["vim", "curl"],
                "capture_config_files": [
                    {
                        "path": "/etc/distroforge/profile.conf",
                        "mode": "0o644",
                        "sha256": "abc",
                        "size": 15,
                        "content": "CHANNEL=stable\n",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "live-build"

    planner = LiveBuildPlanner()
    plan = planner.plan(profile, output)
    planner.write_plan(plan)

    assert "vim" in (output / "config/package-lists/distroforge.list.chroot").read_text(encoding="utf-8")
    assert (
        output / "config/includes.chroot/etc/distroforge/profile.conf"
    ).read_text(encoding="utf-8") == "CHANNEL=stable\n"
    assert (output / "distroforge-live-build-plan.yaml").exists()


def test_upgrade_preflight_is_read_only_and_blocks_execution(tmp_path) -> None:
    root = _fake_root(tmp_path)

    report = UpgradeMediaPreflight().check(root, "26.04", "26.10")

    assert report.blocked
    assert any(check.name == "execution" and check.status == "blocked" for check in report.checks)


def test_systemd_image_plan_is_plan_only() -> None:
    payload = json.loads(SystemdImagePlan("appliance", update_strategy="ab").render_json())

    assert payload["backend"] == "systemd-repart/sysupdate"
    assert payload["status"] == "plan-only"


def test_cli_upgrade_media_blocks_by_default(tmp_path) -> None:
    root = _fake_root(tmp_path)

    with pytest.raises(SystemExit) as exc:
        main(["upgrade-media", "--target", str(root), "--from", "26.04", "--to", "26.10"])

    assert exc.value.code == 2
