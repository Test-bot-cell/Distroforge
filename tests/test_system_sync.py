"""Unit tests for :mod:`distroforge.core.system_sync`.

System sync either runs an upgrade in the chroot at build time or installs a
post-install helper that runs it later. The two upgrade strategies, the fallback
recovery block, and package holds all shape the shell the target will run, so the
generated commands are pinned here rather than only the fact that something ran.
"""

from __future__ import annotations

from pathlib import Path

from distroforge.core.command import CommandRunner
from distroforge.core.system_sync import SystemSyncOptions, SystemSyncService


def _service(tmp_path: Path, options: SystemSyncOptions) -> tuple[CommandRunner, SystemSyncService]:
    runner = CommandRunner(dry_run=True)
    return runner, SystemSyncService(runner, tmp_path, options, use_sudo=False)


def test_summary_disabled() -> None:
    assert SystemSyncOptions(enabled=False).summary() == "disabled"


def test_summary_lists_active_flags() -> None:
    summary = SystemSyncOptions(
        enabled=True,
        strategy="safe",
        fallback=True,
        run_during_build=True,
        post_install_tool=True,
        hold_packages=["grub-pc", "linux-image-generic"],
    ).summary()

    assert summary == "safe, fallback, build, post-install-tool, hold=2"


def test_disabled_run_records_skip(tmp_path: Path) -> None:
    runner, service = _service(tmp_path, SystemSyncOptions(enabled=False))

    service.run()

    assert [spec.argv for spec in runner.history] == [("system-sync-skip", str(tmp_path))]


def test_post_install_only_writes_helper_and_skips_build(tmp_path: Path) -> None:
    runner, service = _service(
        tmp_path,
        SystemSyncOptions(enabled=True, post_install_tool=True, run_during_build=False),
    )

    service.run()

    argvs = [spec.argv for spec in runner.history]
    helper = tmp_path / "usr" / "local" / "sbin" / "distroforge-system-sync"
    assert ("write-file", str(helper)) in argvs
    assert ("system-sync-build-skip", str(tmp_path)) in argvs


def test_build_time_run_updates_then_upgrades(tmp_path: Path) -> None:
    runner, service = _service(
        tmp_path,
        SystemSyncOptions(enabled=True, post_install_tool=False, run_during_build=True),
    )

    service.run()

    # An apt update runs in the chroot before the upgrade.
    assert any("update" in spec.argv for spec in runner.history)
    shell = next(spec for spec in runner.history if "-lc" in spec.argv)
    command = shell.argv[shell.argv.index("-lc") + 1]
    assert "full-upgrade" in command


def test_safe_strategy_uses_with_new_pkgs_upgrade(tmp_path: Path) -> None:
    _, service = _service(tmp_path, SystemSyncOptions(enabled=True, strategy="safe"))

    assert service._action() == "--with-new-pkgs upgrade"


def test_sync_command_without_fallback_has_no_recovery_block(tmp_path: Path) -> None:
    _, service = _service(tmp_path, SystemSyncOptions(enabled=True, fallback=False))

    command = service._sync_command()

    assert command.startswith("set -e; apt-get -s full-upgrade;")
    assert "apt-get -f -y install" not in command


def test_sync_command_with_fallback_recovers(tmp_path: Path) -> None:
    _, service = _service(tmp_path, SystemSyncOptions(enabled=True, fallback=True))

    command = service._sync_command()

    assert "if ! apt-get -y full-upgrade; then" in command
    assert "apt-get -f -y install" in command
    assert "dpkg --configure -a" in command


def test_hold_packages_are_quoted_in_sync_command(tmp_path: Path) -> None:
    _, service = _service(
        tmp_path,
        SystemSyncOptions(enabled=True, hold_packages=["weird pkg", "grub-pc"]),
    )

    command = service._sync_command()

    assert "apt-mark hold 'weird pkg' grub-pc" in command


def test_post_install_script_is_root_reexecuting_and_holds(tmp_path: Path) -> None:
    _, service = _service(
        tmp_path,
        SystemSyncOptions(enabled=True, hold_packages=["grub-pc"], fallback=False),
    )

    script = service._script()

    assert script.startswith("#!/bin/sh")
    assert 'exec sudo "$0" "$@"' in script
    assert "apt-mark hold grub-pc" in script
    assert "apt-get -y full-upgrade" in script


def test_post_install_action_with_fallback_chains_recovery(tmp_path: Path) -> None:
    _, service = _service(tmp_path, SystemSyncOptions(enabled=True, fallback=True))

    action = service._post_install_action()

    assert action.startswith("apt-get -y full-upgrade || (")
    assert "dpkg --configure -a" in action
