from __future__ import annotations

from pathlib import Path

import pytest

from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.command import CommandRunner, CommandSpec
from distroforge.core.project import Project

# No test injected a failure in the middle of a build, so the two contracts that
# only matter when a build dies had never run: the finally that unmounts the host
# bind mounts out of the target root, and the auto-restore of the last snapshot.
# Both are the difference between a failed build and a machine left with the host
# /dev, /proc, /sys and /run still mounted under a work directory.


class _FailingRunner(CommandRunner):
    """Dry-run runner that raises the first time a chosen command is planned."""

    def __init__(self, fail_when: str) -> None:
        super().__init__(dry_run=True)
        self.fail_when = fail_when
        self.failed = False

    def run(self, spec: CommandSpec, check: bool = True) -> object:
        if not self.failed and any(self.fail_when in part for part in spec.argv):
            self.failed = True
            self.history.append(spec)
            raise RuntimeError(f"injected failure at {self.fail_when}")
        return super().run(spec, check=check)

    def run_streaming(self, spec: CommandSpec, on_line, check: bool = True) -> object:
        if not self.failed and any(self.fail_when in part for part in spec.argv):
            self.failed = True
            self.history.append(spec)
            raise RuntimeError(f"injected failure at {self.fail_when}")
        return super().run_streaming(spec, on_line, check=check)


def _project(tmp_path: Path, name: str) -> Project:
    project = Project.create(name, tmp_path / name.lower(), "26.04")
    project.source_mode = "bootstrap"
    return project


def _unmounted(runner: CommandRunner) -> list[str]:
    return [
        spec.argv[-1]
        for spec in runner.history
        if "umount" in spec.argv or (len(spec.argv) > 1 and spec.argv[1] == "umount")
    ]


@pytest.mark.parametrize("phase_marker", ["apt-get", "mksquashfs"])
def test_a_failure_mid_build_still_unmounts_the_host_bind_mounts(
    tmp_path: Path, phase_marker: str
) -> None:
    runner = _FailingRunner(phase_marker)
    orchestrator = BuildOrchestrator(_project(tmp_path, f"Crash{phase_marker[:3]}"), runner, BuildOptions())

    with pytest.raises(RuntimeError, match="injected failure"):
        orchestrator.run()

    assert runner.failed, "the injected command was never planned, the test proves nothing"
    unmounted = _unmounted(runner)
    # All five bind mounts, in reverse order, exactly as unmount_runtime emits them.
    assert unmounted, "the target root was left with the host bind mounts in place"
    for target in ("run", "sys", "proc", "dev/pts", "dev"):
        assert any(entry.endswith(target) for entry in unmounted), target


def test_the_service_start_block_is_removed_when_a_build_dies(tmp_path: Path) -> None:
    runner = _FailingRunner("mksquashfs")
    orchestrator = BuildOrchestrator(_project(tmp_path, "CrashPolicy"), runner, BuildOptions())

    with pytest.raises(RuntimeError):
        orchestrator.run()

    # policy-rc.d exits 101 to stop daemons starting in the chroot. Left behind, it
    # would silently break service starts in the delivered image.
    removed = [
        spec.argv
        for spec in runner.history
        if spec.argv[0] in {"rm", "rm-tree"} and "policy-rc.d" in spec.argv[-1]
    ]
    assert removed, "policy-rc.d was left in the target root"


def test_auto_restore_runs_the_privileged_restore_after_a_failed_build(tmp_path: Path) -> None:
    from distroforge.core.snapshots import SnapshotOptions, SnapshotService

    project = _project(tmp_path, "AutoRestore")
    snapshots = project.workdir / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)
    (snapshots / "after-apt.tar.zst").write_bytes(b"snapshot")
    options = SnapshotOptions(enabled=True, auto_restore_on_failure=True)
    runner = CommandRunner(dry_run=True)

    SnapshotService(runner, project.squashfs_root, snapshots, options).restore_latest()

    assert runner.history, "restore_latest emitted nothing"
    argv = runner.history[-1].argv
    assert argv[0] == "sudo", "the restore must be privileged: the tree is root-owned"
    assert "tar" in argv and "-xpf" in argv
    assert str(snapshots / "after-apt.tar.zst") in argv


def test_auto_restore_picks_the_latest_available_phase(tmp_path: Path) -> None:
    from distroforge.core.snapshots import SnapshotOptions, SnapshotService

    project = _project(tmp_path, "RestoreOrder")
    snapshots = project.workdir / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)
    for name in ("after-apt", "after-customize"):
        (snapshots / f"{name}.tar.zst").write_bytes(b"snapshot")
    runner = CommandRunner(dry_run=True)

    SnapshotService(
        runner, project.squashfs_root, snapshots, SnapshotOptions(enabled=True)
    ).restore_latest()

    # phases run after-apt then after-customize, so the later one is restored.
    assert str(snapshots / "after-customize.tar.zst") in runner.history[-1].argv


def test_auto_restore_is_silent_when_no_snapshot_was_taken(tmp_path: Path) -> None:
    from distroforge.core.snapshots import SnapshotOptions, SnapshotService

    project = _project(tmp_path, "NoSnapshot")
    snapshots = project.workdir / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True)
    runner = CommandRunner(dry_run=True)

    SnapshotService(
        runner, project.squashfs_root, snapshots, SnapshotOptions(enabled=True)
    ).restore_latest()

    assert runner.history == []
