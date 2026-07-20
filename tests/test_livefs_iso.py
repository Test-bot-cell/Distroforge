from __future__ import annotations

import yaml

from distroforge.cli import main
from distroforge.core.livefs_iso import LivefsIsoPlanner


def _profile(tmp_path):
    path = tmp_path / "captured.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "metadata": {
                    "name": "Captured Workshop",
                    "codename": "resolute",
                },
                "packages": ["vim", "curl"],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_livefs_iso_plan_models_ubuntu_isobuild_steps(tmp_path) -> None:
    profile = _profile(tmp_path)
    plan = LivefsIsoPlanner().plan(
        profile,
        tmp_path / "work",
        tmp_path / "out.iso",
        arch="amd64",
    )

    assert plan.to_dict()["backend"] == "ubuntu-livefs-isobuild"
    assert [step["name"] for step in plan.steps] == [
        "init",
        "setup-apt",
        "generate-pool",
        "generate-sources",
        "add-live-filesystem",
        "make-bootable",
        "make-iso",
    ]
    assert plan.package_list == ["curl", "vim"]
    assert plan.series == "resolute"


def test_livefs_iso_write_creates_reviewable_workspace(tmp_path) -> None:
    profile = _profile(tmp_path)
    work_dir = tmp_path / "work"
    plan = LivefsIsoPlanner().plan(profile, work_dir, tmp_path / "out.iso")

    LivefsIsoPlanner().write_plan(plan)

    assert (work_dir / "iso-root/.disk/info").read_text(encoding="utf-8")
    assert "curl" in (work_dir / "package-list.txt").read_text(encoding="utf-8")
    assert "URIs: file:/cdrom" in (work_dir / "cdrom.sources").read_text(encoding="utf-8")
    assert "make-iso" in (work_dir / "isobuild-commands.txt").read_text(encoding="utf-8")
    assert (work_dir / "iso-root/README.diskdefines").exists()
    assert (work_dir / "iso-root/dists/resolute/Release").exists()
    assert (work_dir / "iso-root/boot/grub/grub.cfg").exists()
    assert "Manual gates" in (work_dir / "manual-gates.txt").read_text(encoding="utf-8")
    assert (work_dir / "distroforge-livefs-iso-plan.yaml").exists()


def test_cli_livefs_iso_build_requires_write_then_writes(tmp_path, capsys) -> None:
    profile = _profile(tmp_path)
    work_dir = tmp_path / "work"

    main(["livefs-iso-build", str(profile), "--work-dir", str(work_dir), "--dest", str(tmp_path / "out.iso")])
    assert "Pass --write" in capsys.readouterr().out
    assert not work_dir.exists()

    main([
        "livefs-iso-build",
        str(profile),
        "--work-dir",
        str(work_dir),
        "--dest",
        str(tmp_path / "out.iso"),
        "--write",
    ])
    assert "Ubuntu livefs ISO plan" in capsys.readouterr().out
    assert (work_dir / "distroforge-livefs-iso-plan.yaml").exists()
