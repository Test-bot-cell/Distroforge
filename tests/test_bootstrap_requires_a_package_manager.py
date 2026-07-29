"""A bootstrap tool exiting 0 is a claim about the tool, not about the tree.

The first real golden-path run took the claim. mmdebstrap returned 0 after 23 seconds,
the identity stamp was written, and the build ran five more phases -- apt overlays, the
live base install -- before a chroot answered
``env: 'apt-get': No such file or directory``, exit 127. By then the tool's own output,
which would have said what it declined to install, was gone: the runner keeps output
only for commands that fail, and this one had not failed.

Worse, the tree that broke the build was *reusable*. ``rootfs_verdict`` graded
completeness on two paths, a dpkg status file and an os-release, both of which that tree
had. A re-run would have skipped the bootstrap and gone straight back to the same
missing apt-get, and the second failure would have looked identical to the first with no
bootstrap in the log to blame.

So this file pins both ranges of the same defect: the bootstrap must be checked where it
happens, and a tree with no package manager must never be graded reusable.

That run's cause is no longer open, and the last group of tests here pins it. ``minbase``
names two different package sets: debootstrap(8) defines it as "required packages and
apt" and adds apt itself, while mmdebstrap(1) defines required/minbase as the essential
set plus Priority:required, which never mentions apt. This code passes the same variant
string to whichever tool ``has_binary`` finds, so what got installed depended on that.

It looked equivalent because package sets also pull "the direct and indirect hard
dependencies" (mmdebstrap(1), VARIANTS), so apt kept arriving as somebody else's
dependency -- which is why a local simulate resolved 129 packages including
``apt (3.2.0)`` while the golden path's tree had none. In the resolute index apt is
Priority:important, so minbase excludes it by definition and included it only by
accident. The fix is to ask for it by name; these tests pin that it is asked for whichever
tool runs.

The checks in the first group stay regardless. A tool exiting 0 over a tree that cannot
host the next phase is a class of bug, not one instance of it, and they are the only
place that compares what a bootstrap claimed against what it left.
"""

from __future__ import annotations

import json

import pytest
from conftest import make_rootfs

from distroforge.core.bootstrap import (
    BootstrapOptions,
    BootstrapService,
    bootstrap_identity,
    bootstrap_stamp_path,
    missing_rootfs_requirements,
    rootfs_verdict,
)
from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.project import Project
from distroforge.core.releases import get_release


class _BootstrapThatLeavesOutApt(CommandRunner):
    """Reproduces the run: exit 0, a tree that looks Debian-ish, and no package manager.

    Everything the golden path's tree had is here -- ``env`` was in it, so coreutils was
    unpacked -- and the one binary the next phase invokes is not.
    """

    def __init__(self, root, include_dpkg: bool = True) -> None:
        super().__init__(dry_run=False)
        self.root = root
        self.include_dpkg = include_dpkg

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        if spec.argv and spec.argv[0] in {"mmdebstrap", "debootstrap"}:
            make_rootfs(self.root)
            (self.root / "usr/bin/apt-get").unlink()
            if not self.include_dpkg:
                (self.root / "usr/bin/dpkg").unlink()
        return CommandResult(spec=spec, returncode=0, stdout="", stderr="")


def _service(project, runner, options: BootstrapOptions | None = None) -> BootstrapService:
    return BootstrapService(
        runner,
        project.release,
        project.squashfs_root,
        project.iso_root,
        options or BootstrapOptions(),
        use_sudo=False,
    )


def test_a_bootstrap_that_exits_zero_with_no_apt_is_refused_where_it_happens(tmp_path) -> None:
    project = Project.create("NoApt", tmp_path / "no-apt", "26.04")
    runner = _BootstrapThatLeavesOutApt(project.squashfs_root)

    with pytest.raises(ValueError) as caught:
        _service(project, runner).create_rootfs()

    message = str(caught.value)
    # The tool, because two of them can run here and they disagree about the variant.
    assert "mmdebstrap" in message or "debootstrap" in message, message
    # The variant and the suite, because that pair is what the reader has to change.
    assert "minbase" in message and "resolute" in message, message
    # And what is actually absent, rather than "incomplete".
    assert "apt-get" in message, message


def test_the_refusal_leaves_no_stamp_claiming_a_base_for_the_broken_tree(tmp_path) -> None:
    # Otherwise the refusal would be self-defeating: the stamp is the strongest evidence
    # rootfs_verdict has, so a stamped broken tree would be graded against the identity
    # it claims and reused for the very build that just refused it.
    project = Project.create("NoStamp", tmp_path / "no-stamp", "26.04")
    runner = _BootstrapThatLeavesOutApt(project.squashfs_root)

    with pytest.raises(ValueError):
        _service(project, runner).create_rootfs()

    assert not bootstrap_stamp_path(project.squashfs_root).exists()


def test_the_refusal_names_every_missing_requirement_not_only_the_first(tmp_path) -> None:
    project = Project.create("NoDpkgEither", tmp_path / "no-dpkg-either", "26.04")
    runner = _BootstrapThatLeavesOutApt(project.squashfs_root, include_dpkg=False)

    with pytest.raises(ValueError) as caught:
        _service(project, runner).create_rootfs()

    message = str(caught.value)
    assert "dpkg" in message and "apt-get" in message, message


def test_a_tree_with_no_package_manager_is_not_reusable(tmp_path) -> None:
    """The half that would have made the second run lie.

    This is the tree the golden path left behind, graded by the code that decides whether
    to bootstrap again. It used to come back ``reusable``.
    """
    project = Project.create("Stale", tmp_path / "stale", "26.04")
    make_rootfs(project.squashfs_root)
    (project.squashfs_root / "usr/bin/apt-get").unlink()
    # With the stamp in place, so the identity leg would have passed and could not have
    # caught this: the tree really was bootstrapped for this build's base.
    bootstrap_stamp_path(project.squashfs_root).write_text(
        json.dumps(bootstrap_identity(get_release("26.04"), BootstrapOptions())),
        encoding="utf-8",
    )

    verdict = rootfs_verdict(project.squashfs_root, project.release, BootstrapOptions())

    assert verdict.state == "incomplete"
    assert "apt-get" in verdict.reason, verdict.reason


def test_a_tree_that_has_everything_is_still_reusable(tmp_path) -> None:
    # The negative control. A completeness test that refused everything would pass every
    # assertion above and break every real reuse.
    project = Project.create("Fine", tmp_path / "fine", "26.04")
    make_rootfs(project.squashfs_root, codename="resolute")

    verdict = rootfs_verdict(project.squashfs_root, project.release, BootstrapOptions())

    assert verdict.state == "reusable", verdict.reason


def test_a_dry_run_does_not_invent_a_missing_rootfs(tmp_path) -> None:
    # A planned build creates nothing, so every requirement is absent and the check would
    # refuse every dry run on every machine -- the failure mode of guarding on the
    # filesystem instead of on what was actually attempted.
    project = Project.create("Planned", tmp_path / "planned", "26.04")

    _service(project, CommandRunner(dry_run=True)).create_rootfs()


class _RecordingBootstrap(CommandRunner):
    """Runs nothing, remembers the argv, and decides which tool is on the host.

    ``tool`` is what has_binary should answer for, because the branch under test is
    exactly the one that picks between mmdebstrap and debootstrap.
    """

    def __init__(self, root, tool: str) -> None:
        super().__init__(dry_run=False)
        self.root = root
        self.tool = tool

    def has_binary(self, name: str) -> bool:  # type: ignore[override]
        return name == self.tool

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        if spec.argv and spec.argv[0] in {"mmdebstrap", "debootstrap"}:
            make_rootfs(self.root)
        return CommandResult(spec=spec, returncode=0, stdout="", stderr="")


def _bootstrap_argv(runner: _RecordingBootstrap) -> tuple[str, ...]:
    for spec in runner.history:
        if spec.argv and spec.argv[0] in {"mmdebstrap", "debootstrap"}:
            return spec.argv
    raise AssertionError(f"no bootstrap command was run: {[s.argv for s in runner.history]}")


@pytest.mark.parametrize("tool", ["mmdebstrap", "debootstrap"])
def test_apt_is_asked_for_by_name_whichever_tool_runs(tmp_path, tool: str) -> None:
    """The cause of the golden path's missing apt-get.

    minbase means "essential plus Priority:required" to mmdebstrap and "required packages
    and apt" to debootstrap. apt is Priority:important in resolute, so the mmdebstrap
    reading excludes it, and it had been arriving only as another package's indirect
    dependency. Asking by name is a no-op for debootstrap and the whole point for
    mmdebstrap -- which is why this is parametrized rather than written once.
    """
    project = Project.create("Named", tmp_path / f"named-{tool}", "26.04")
    runner = _RecordingBootstrap(project.squashfs_root, tool)

    _service(project, runner).create_rootfs()

    argv = _bootstrap_argv(runner)
    assert argv[0] == tool, argv
    includes = [arg for arg in argv if arg.startswith("--include=")]
    assert len(includes) == 1, f"one include list, not {includes}"
    named = includes[0].removeprefix("--include=").split(",")
    assert "apt" in named, f"apt has to be requested, not hoped for: {argv}"
    # The CA store stays for its own reason: an https archive and a chroot with no trust
    # anchors. Losing it here would trade one broken phase for another.
    assert "ca-certificates" in named, argv


def test_the_two_tools_are_asked_for_the_same_packages(tmp_path) -> None:
    """The invariant behind the fix, not just its two instances.

    The defect was never "mmdebstrap is wrong"; it was that the request depended on which
    binary happened to be installed. If a future include list diverges per tool, that
    dependence is back and only one of the two paths gets exercised on any given host.
    """
    asked = {}
    for tool in ("mmdebstrap", "debootstrap"):
        project = Project.create("Same", tmp_path / f"same-{tool}", "26.04")
        runner = _RecordingBootstrap(project.squashfs_root, tool)
        _service(project, runner).create_rootfs()
        argv = _bootstrap_argv(runner)
        asked[tool] = sorted(
            arg.removeprefix("--include=") for arg in argv if arg.startswith("--include=")
        )

    assert asked["mmdebstrap"] == asked["debootstrap"], asked


def test_the_shared_rootfs_helper_satisfies_the_real_requirements(tmp_path) -> None:
    # conftest.make_rootfs builds its tree from _ROOTFS_REQUIREMENTS, so this asserts the
    # derivation still holds. Four test files used to spell the paths out by hand and all
    # four broke, in unrelated assertions, the day a requirement was added.
    assert missing_rootfs_requirements(make_rootfs(tmp_path / "tree")) == ()
    assert missing_rootfs_requirements(tmp_path / "nothing-here") != ()
