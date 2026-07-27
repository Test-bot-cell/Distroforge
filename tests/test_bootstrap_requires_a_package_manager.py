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

Note what is *not* claimed here. The cause of that run's missing apt is still open.
``minbase`` does not mean the same thing to the two tools this code can call --
debootstrap(8) says "required packages and apt", mmdebstrap(1) says the essential set
plus Priority:required, which does not mention apt -- but measured on a resolute host,
``mmdebstrap --simulate --verbose --variant=minbase --include=ca-certificates resolute``
resolves 129 packages including ``apt (3.2.0)``, so with mmdebstrap 1.5.7 the two agree
in practice. The run that broke used 1.4.3-6, from noble, against a resolute suite. These
tests are deliberately indifferent to which explanation wins: whatever the cause, the
build has to stop at the phase that produced the tree.
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


def test_the_shared_rootfs_helper_satisfies_the_real_requirements(tmp_path) -> None:
    # conftest.make_rootfs builds its tree from _ROOTFS_REQUIREMENTS, so this asserts the
    # derivation still holds. Four test files used to spell the paths out by hand and all
    # four broke, in unrelated assertions, the day a requirement was added.
    assert missing_rootfs_requirements(make_rootfs(tmp_path / "tree")) == ()
    assert missing_rootfs_requirements(tmp_path / "nothing-here") != ()
