from __future__ import annotations

from dataclasses import fields
from pathlib import Path

from distroforge.core.command import CommandRunner
from distroforge.core.sanitize import SanitizeOptions, SanitizeService

RESOLVER_BACKUP = "/etc/.resolv.conf.systemd-resolved.bak"


def _sanitize(root: Path, options: SanitizeOptions) -> CommandRunner:
    runner = CommandRunner(dry_run=True)
    SanitizeService(runner, root, options, use_sudo=False).run()
    return runner


def _removes_resolver_backup(runner: CommandRunner) -> bool:
    return any(
        spec.argv[-3:] == ("rm", "-f", RESOLVER_BACKUP) for spec in runner.history
    )


def test_sanitize_drops_the_backup_that_carries_the_build_machine_resolver(tmp_path) -> None:
    """The ISO must not ship the nameserver and search domain of the machine that built it.

    systemd-resolved's postinst moves whatever /etc/resolv.conf it finds aside before
    installing its symlink, and what it finds is mmdebstrap's copy of the build machine's own
    resolver. Measured in a real desktop rootfs: 929 bytes ending in `nameserver 127.0.0.53`
    and `search mshome.net`, sitting on the persistent rootfs where the squashfs picks it up.
    """
    runner = _sanitize(tmp_path / "rootfs", SanitizeOptions())

    assert _removes_resolver_backup(runner)


def test_the_resolver_backup_goes_even_with_every_sanitize_option_turned_off(tmp_path) -> None:
    # Deliberately not one of the options: keeping a build machine's DNS out of a delivered
    # image is not a preference, and every other removal here is one.
    everything_off = SanitizeOptions(
        **{field.name: False for field in fields(SanitizeOptions) if field.name != "enabled"}
    )

    assert _removes_resolver_backup(_sanitize(tmp_path / "rootfs", everything_off))


def test_a_disabled_sanitize_phase_still_does_nothing_at_all(tmp_path) -> None:
    # The boundary of the paragraph above: `enabled: False` means the phase is not run, and
    # that stays true rather than growing an exception that surprises whoever disabled it.
    runner = _sanitize(tmp_path / "rootfs", SanitizeOptions(enabled=False))

    assert not _removes_resolver_backup(runner)
    assert [spec.argv[0] for spec in runner.history] == ["sanitize-skip"]
