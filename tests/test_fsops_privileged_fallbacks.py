"""The eight paths where DistroForge escalates to root, and what it runs there.

``FileSystemOps`` tries every operation unprivileged first and falls back to a
privileged command on ``PermissionError`` -- which is what happens constantly against
an extracted, root-owned squashfs. Not one of those eight fallbacks had a test, so the
argv that runs as root on the maintainer's machine was unverified: a wrong ``sh -c``
positional shifts which path gets truncated, and ``rm -rf`` with the arguments
transposed removes the wrong tree.

The tests drive a *real* ``PermissionError`` from a mode-0500 directory, so the
fallback is reached the way production reaches it, and hand it a runner that records
the command instead of executing it. Nothing here runs sudo.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.fsops import FileSystemOps

# Running the suite as root removes the very condition under test: every operation
# would succeed unprivileged and the fallback would never be reached. Rootless is the
# supported configuration -- debian/control declares Rules-Requires-Root: no.
pytestmark = pytest.mark.skipif(
    os.geteuid() == 0, reason="the fallbacks only exist for a user who cannot write the target"
)


class RecordingRunner(CommandRunner):
    """Not dry-run -- so the real filesystem attempt happens -- but never executes."""

    def __init__(self) -> None:
        super().__init__(dry_run=False)
        self.executed: list[CommandSpec] = []

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.executed.append(spec)
        return CommandResult(spec=spec, returncode=0, stdout="", stderr="")


@pytest.fixture
def locked(tmp_path: Path) -> Path:
    """A directory this user cannot write into, restored so pytest can clean up."""
    target = tmp_path / "rootfs"
    target.mkdir()
    target.chmod(0o500)
    yield target
    target.chmod(0o700)


def _only(runner: RecordingRunner) -> tuple[str, ...]:
    assert len(runner.executed) == 1, f"expected one privileged command, got {runner.executed}"
    spec = runner.executed[0]
    assert spec.needs_root, "the fallback must declare that it needs root"
    assert spec.argv[0] == "sudo", spec.argv
    return spec.argv


def test_mkdir_falls_back_to_install_d(locked: Path) -> None:
    runner = RecordingRunner()

    FileSystemOps(runner).mkdir(locked / "etc" / "skel")

    assert _only(runner)[-3:] == ("install", "-d", str(locked / "etc/skel"))


def test_write_text_hands_the_content_on_stdin_and_keeps_the_paths_in_order(locked: Path) -> None:
    runner = RecordingRunner()
    target = locked / "etc" / "hostname"

    FileSystemOps(runner).write_text(target, "forge\n", mode="0644")

    argv = _only(runner)
    # sh -c SCRIPT $0 $1 $2 $3: the parent is created, the content is written to the
    # file, and the mode is applied to the file -- not to the directory.
    assert argv[-4:] == ("distroforge-write-text", str(target.parent), str(target), "0644")
    assert 'install -d "$1" && cat > "$2"' in argv[argv.index("-c") + 1]
    assert runner.executed[0].stdin == "forge\n"


def test_write_text_reraises_instead_of_escalating_when_sudo_is_refused(locked: Path) -> None:
    runner = RecordingRunner()

    with pytest.raises(PermissionError):
        FileSystemOps(runner, use_sudo=False).write_text(locked / "etc" / "hostname", "forge\n")

    assert runner.executed == []


def test_copy_file_installs_with_the_requested_mode(locked: Path, tmp_path: Path) -> None:
    source = tmp_path / "policy-rc.d"
    source.write_text("#!/bin/sh\nexit 101\n", encoding="utf-8")
    runner = RecordingRunner()

    FileSystemOps(runner).copy_file(source, locked / "usr/sbin/policy-rc.d", mode="0755")

    argv = _only(runner)
    assert argv[-5:] == ("-D", "-m", "0755", str(source), str(locked / "usr/sbin/policy-rc.d"))


def test_copy_file_can_go_privileged_without_trying_the_local_copy_first(tmp_path: Path) -> None:
    # prefer_sudo skips the unprivileged attempt entirely: the caller already knows the
    # destination is root-owned, and a failed local copy2 can leave a partial file.
    source = tmp_path / "sources.list"
    source.write_text("deb http://example.invalid noble main\n", encoding="utf-8")
    runner = RecordingRunner()

    FileSystemOps(runner).copy_file(source, tmp_path / "etc/apt/sources.list", prefer_sudo=True)

    assert _only(runner)[-2:] == (str(source), str(tmp_path / "etc/apt/sources.list"))
    assert not (tmp_path / "etc/apt/sources.list").exists()


def test_copy_tree_removes_the_target_before_copying_and_not_the_source(locked: Path, tmp_path: Path) -> None:
    source = tmp_path / "skel"
    (source / "sub").mkdir(parents=True)
    runner = RecordingRunner()
    target = locked / "etc" / "skel"

    FileSystemOps(runner).copy_tree(source, target)

    argv = _only(runner)
    script = argv[argv.index("-c") + 1]
    # $1 source, $2 target parent, $3 target. Transposing $1 and $3 would rm -rf the
    # source tree, so the order is asserted, not just the presence of the arguments.
    assert script == 'install -d "$2" && rm -rf "$3" && cp -a "$1" "$3"'
    assert argv[-4:] == ("distroforge-copy-tree", str(source), str(target.parent), str(target))
    assert source.is_dir(), "the source tree must still be there"


# The remaining four operations cannot be denied by directory mode alone, and that is
# a fact about the kernel rather than about this code: rename and unlink of a name that
# does not exist return ENOENT before the write permission is consulted, and chmod is
# governed by ownership, not by the mode -- the owner of a 0500 directory may always
# chmod it. Producing a genuine denial there needs a root-owned target, which this suite
# must never create. The denial is therefore raised from the exact stdlib call the
# fallback guards, which still leaves the argv -- the thing under test -- untouched.
def _deny(monkeypatch: pytest.MonkeyPatch, target: object, name: str) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(target, name, refuse)


def test_rename_move_uses_no_target_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stale, fresh = tmp_path / "old", tmp_path / "new"
    runner = RecordingRunner()
    _deny(monkeypatch, Path, "rename")

    FileSystemOps(runner).rename(stale, fresh)

    # -T so a move onto an existing directory replaces it instead of nesting inside it.
    assert _only(runner)[-4:] == ("mv", "-T", str(stale), str(fresh))


def test_remove_escalates_with_the_right_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    doomed = tmp_path / "policy-rc.d"
    runner = RecordingRunner()
    _deny(monkeypatch, Path, "unlink")

    FileSystemOps(runner).remove(doomed)

    assert _only(runner)[-3:] == ("rm", "-f", str(doomed))


def test_remove_tree_escalates_recursively(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    doomed = tmp_path / "squashfs-root"
    (doomed / "usr").mkdir(parents=True)
    runner = RecordingRunner()
    monkeypatch.setattr(
        "distroforge.core.fsops.shutil.rmtree",
        lambda *_a, **_k: (_ for _ in ()).throw(PermissionError(13, "Permission denied")),
    )

    FileSystemOps(runner).remove_tree(doomed)

    assert _only(runner)[-3:] == ("rm", "-rf", str(doomed))


def test_remove_tree_is_silent_when_the_tree_is_already_gone(tmp_path: Path) -> None:
    runner = RecordingRunner()

    FileSystemOps(runner).remove_tree(tmp_path / "never-existed")

    assert runner.executed == [], "removing nothing must not ask for root"


def test_chmod_escalates_with_the_symbolic_mode_untouched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = RecordingRunner()
    _deny(monkeypatch, Path, "chmod")

    FileSystemOps(runner).chmod(tmp_path, "0755")

    # The mode stays the octal string the caller passed: int(mode, 8) is for the local
    # path, chmod(1) wants the text, and converting twice would turn 0755 into 493.
    assert _only(runner)[-3:] == ("chmod", "0755", str(tmp_path))


def test_every_fallback_refuses_to_escalate_when_sudo_is_off(
    locked: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One table, so a ninth fallback added without a --no-sudo path shows up here.
    ops = FileSystemOps(RecordingRunner(), use_sudo=False)
    source = tmp_path / "file"
    source.write_text("x", encoding="utf-8")
    tree = tmp_path / "tree"
    tree.mkdir()
    for attribute in ("rename", "unlink", "chmod"):
        _deny(monkeypatch, Path, attribute)
    monkeypatch.setattr(
        "distroforge.core.fsops.shutil.rmtree",
        lambda *_a, **_k: (_ for _ in ()).throw(PermissionError(13, "Permission denied")),
    )
    cases = (
        lambda: ops.mkdir(locked / "sub"),
        lambda: ops.write_text(locked / "f", "x"),
        lambda: ops.copy_file(source, locked / "f"),
        lambda: ops.copy_tree(source.parent, locked / "tree"),
        lambda: ops.rename(tmp_path / "a", tmp_path / "b"),
        lambda: ops.remove(tmp_path / "f"),
        lambda: ops.remove_tree(tree),
        lambda: ops.chmod(tmp_path, "0644"),
    )

    for index, case in enumerate(cases):
        with pytest.raises(PermissionError):
            case()
        assert ops.runner.executed == [], f"case {index} escalated with sudo disabled"
