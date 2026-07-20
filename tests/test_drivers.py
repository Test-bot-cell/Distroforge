from __future__ import annotations

from pathlib import Path

from distroforge.core.command import CommandRunner
from distroforge.core.drivers import DriverOptions, DriverService

ROOT = Path("/build/rootfs")


def _argvs(runner: CommandRunner) -> list[tuple[str, ...]]:
    return [spec.argv for spec in runner.history]


def test_auto_drivers_calls_install_not_removed_autoinstall() -> None:
    runner = CommandRunner(dry_run=True)
    DriverService(
        runner, ROOT, DriverOptions(auto=True, install_common=True), use_sudo=False
    ).install()

    argvs = _argvs(runner)
    assert ("chroot", str(ROOT), "ubuntu-drivers", "install") in argvs
    assert ("chroot", str(ROOT), "apt-get", "-y", "install", "ubuntu-drivers-common") in argvs
    # autoinstall was dropped from ubuntu-drivers-common (>=26.04); emitting it aborts the build.
    assert not any("autoinstall" in part for argv in argvs for part in argv)


def test_install_common_false_skips_common_package() -> None:
    runner = CommandRunner(dry_run=True)
    DriverService(
        runner, ROOT, DriverOptions(auto=True, install_common=False), use_sudo=False
    ).install()

    argvs = _argvs(runner)
    assert ("chroot", str(ROOT), "ubuntu-drivers", "install") in argvs
    assert all("ubuntu-drivers-common" not in part for argv in argvs for part in argv)


def test_auto_disabled_emits_no_commands() -> None:
    runner = CommandRunner(dry_run=True)
    DriverService(runner, ROOT, DriverOptions(auto=False), use_sudo=False).install()

    assert runner.history == []
