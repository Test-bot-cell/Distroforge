from __future__ import annotations

from distroforge.core.autoinstall import AutoinstallOptions
from distroforge.core.branding import BrandingOptions
from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.command import CommandRunner
from distroforge.core.network import NetworkOptions
from distroforge.core.ppa import PpaOptions, PpaSpec
from distroforge.core.project import Project
from distroforge.core.snaps import SnapOptions, SnapSpec
from distroforge.core.users import UserOptions, UserSpec


def test_build_dry_run_records_high_value_option_commands(tmp_path) -> None:
    project = Project.create("DryRunOptions", tmp_path / "dry-run-options", "26.04")
    project.source_mode = "bootstrap"
    options = BuildOptions(
        use_sudo=False,
        branding=BrandingOptions(
            name="Acme OS",
            pretty_name="Acme OS 26.04",
            palette_colors=("#112233", "#445566"),
        ),
        snaps=SnapOptions([SnapSpec("hello-world", channel="stable", classic=True)]),
        ppa=PpaOptions(
            [PpaSpec("graphics-drivers", "ppa", "ABCDEF1234567890")],
            auto_fetch_fingerprint=False,
        ),
        autoinstall=AutoinstallOptions(
            enabled=True,
            username="forge",
            realname="Forge User",
            packages=["curl"],
        ),
        users=UserOptions([UserSpec("forge", groups=["sudo", "video"])]),
        network=NetworkOptions(
            netplan_dhcp=True,
            dns=["1.1.1.1", "9.9.9.9"],
            apt_proxy="http://proxy.local:3142",
        ),
    )
    runner = CommandRunner(dry_run=True)

    BuildOrchestrator(project, runner, options).run()

    commands = [spec.argv for spec in runner.history]
    assert ("write-file", str(project.squashfs_root / "etc/lsb-release")) in commands
    assert (
        "gpg",
        "--no-default-keyring",
        "--keyring",
        str(project.squashfs_root / "usr/share/keyrings/distroforge-graphics-drivers-ppa.gpg"),
        "--keyserver",
        "hkps://keyserver.ubuntu.com",
        "--recv-keys",
        "ABCDEF1234567890",
    ) in commands
    assert (
        "chroot",
        str(project.squashfs_root),
        "snap",
        "install",
        "hello-world",
        "--channel=stable",
        "--classic",
    ) in commands
    assert (
        "chroot",
        str(project.squashfs_root),
        "useradd",
        "-m",
        "-s",
        "/bin/bash",
        "-G",
        "sudo,video",
        "forge",
    ) in commands
    assert ("write-file", str(project.iso_root / "autoinstall.yaml")) in commands
    assert ("write-file", str(project.squashfs_root / "etc/netplan/01-distroforge.yaml")) in commands
    assert (
        "write-file",
        str(project.squashfs_root / "etc/apt/apt.conf.d/01distroforge-proxy"),
    ) in commands
