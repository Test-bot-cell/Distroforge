"""The reuse decision for an existing bootstrap tree.

There was no test here at all, and that is why the defect these tests describe
survived: ``_rootfs_ready()`` answered "may this tree be reused?" by checking that
three paths existed -- a dpkg status file and an os-release. Three paths that exist
say the tree is a Debian-family rootfs. They do not say it is *this* build's rootfs.
Nothing else checked either: the target is a fixed ``work/filesystem`` with no suite
in the path, nothing cleans it between runs, and no code compared the tree's release
to the project's. Retarget a project at another release, rebuild, and the previous
suite's tree was silently reused and shipped inside the image.

Every test below states the wrong behaviour it forbids, because a test that only
describes the new code cannot tell anyone why the code is shaped this way.
"""

from __future__ import annotations

import json

import pytest

from distroforge.core.bootstrap import (
    BootstrapOptions,
    BootstrapService,
    bootstrap_identity,
    bootstrap_stamp_path,
    rootfs_verdict,
)
from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.dry_run_report import generate_dry_run_report
from distroforge.core.project import Project
from distroforge.core.releases import get_release, read_os_release


class _Recorder(CommandRunner):
    """Executes nothing, remembers everything, in order.

    Local rather than shared: what these tests assert about is the *sequence* the
    service emits, so the recorder has to be trivially auditable from here.
    """

    def __init__(self) -> None:
        super().__init__(dry_run=False)

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        return CommandResult(spec=spec, returncode=0, stdout="", stderr="")


def _tree(root, codename: str | None = None, vendor_only: bool = False) -> None:
    """A tree with the two markers the old check was satisfied by, and nothing more."""
    (root / "var/lib/dpkg").mkdir(parents=True, exist_ok=True)
    (root / "var/lib/dpkg/status").write_text("", encoding="utf-8")
    body = "ID=ubuntu\n" + (f"VERSION_CODENAME={codename}\n" if codename else "")
    target = root / ("usr/lib/os-release" if vendor_only else "etc/os-release")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")


def _stamp(root, **overrides) -> None:
    identity = dict(bootstrap_identity(get_release("26.04"), BootstrapOptions()))
    identity.update(overrides)
    bootstrap_stamp_path(root).write_text(json.dumps(identity), encoding="utf-8")


def _findings(project) -> list:
    """The dry-run findings for a bootstrap-sourced project.

    ``source_mode`` is set here rather than in each caller because the bootstrap
    findings are only collected for that mode -- a test that forgot it would assert
    against an empty set and pass for the wrong reason.
    """
    project.source_mode = "bootstrap"
    return generate_dry_run_report(project, BuildOptions(), run_orchestrator=False).findings


def _service(project, options: BootstrapOptions | None = None) -> BootstrapService:
    return BootstrapService(
        _Recorder(),
        project.release,
        project.squashfs_root,
        project.iso_root,
        options,
    )


def test_a_tree_from_another_suite_is_refused_instead_of_silently_reused(tmp_path) -> None:
    """The defect, reproduced: this used to reuse a noble tree for a resolute build.

    Both markers the old check looked at are present, so it said "valid, reuse". The
    tree says in its own os-release that it is something else. The refusal has to name
    both names, because "clean your work directory" without saying what is wrong with
    it is an instruction to guess.
    """
    project = Project.create("Retargeted", tmp_path / "retargeted", "26.04")
    _tree(project.squashfs_root, codename="noble")

    with pytest.raises(ValueError) as caught:
        _service(project).create_rootfs()

    message = str(caught.value)
    assert "noble" in message and "resolute" in message, message
    assert "different base" in message, message


def test_the_matching_suite_is_still_reused(tmp_path) -> None:
    """The control. A check that refuses everything is not a check.

    Without this, the test above passes just as well against code that never reuses
    anything, which would trade a silent wrong image for a guaranteed slow one.
    """
    project = Project.create("Matching", tmp_path / "matching", "26.04")
    _tree(project.squashfs_root, codename="resolute")
    service = _service(project)

    service.create_rootfs()

    assert ("bootstrap-rootfs-reuse", str(project.squashfs_root)) in [
        spec.argv for spec in service.runner.history
    ]


def test_the_recorded_base_catches_what_a_tree_cannot_be_asked_about(tmp_path) -> None:
    """os-release carries the suite and nothing else that matters here.

    A tree bootstrapped for another architecture, another variant or from another
    mirror declares exactly the same codename as the right one, so the suite check
    cannot see any of those. That is what the record beside the tree is for, and each
    field is checked here rather than one standing in for the rest.
    """
    project = Project.create("Recorded", tmp_path / "recorded", "26.04")
    root = project.squashfs_root
    _tree(root, codename="resolute")

    for field_name, wrong in (
        ("arch", "arm64"),
        ("variant", "buildd"),
        ("mirror", "https://example.invalid/ubuntu"),
        ("family", "debian"),
        ("codename", "noble"),
    ):
        _stamp(root, **{field_name: wrong})
        verdict = rootfs_verdict(root, project.release, BootstrapOptions())
        assert verdict.state == "mismatch", f"{field_name}={wrong} was accepted"
        assert field_name in verdict.reason and repr(wrong) in verdict.reason, verdict.reason


def test_a_record_that_agrees_on_every_field_is_a_clean_reuse(tmp_path) -> None:
    """And it carries no caveat, which is what separates it from the fallback below."""
    project = Project.create("Agreeing", tmp_path / "agreeing", "26.04")
    _tree(project.squashfs_root, codename="resolute")
    _stamp(project.squashfs_root)

    verdict = rootfs_verdict(project.squashfs_root, project.release, BootstrapOptions())

    assert verdict.state == "reusable"
    assert verdict.reason == "", verdict.reason


def test_a_record_this_code_cannot_read_falls_back_rather_than_deciding(tmp_path) -> None:
    """Unreadable, not JSON, not an object, or another stamp version: all the same.

    Each of them means the record cannot be *compared*, and a comparison against a
    schema this code does not know is not a comparison. Degrading to the declared
    codename keeps the check that matters; treating it as agreement would invent one.
    """
    project = Project.create("Unreadable", tmp_path / "unreadable", "26.04")
    root = project.squashfs_root
    _tree(root, codename="noble")
    stamp = bootstrap_stamp_path(root)

    for content in ("{not json", "[]", '"a string"', '{"stamp_version": 99, "codename": "noble"}'):
        stamp.write_text(content, encoding="utf-8")
        verdict = rootfs_verdict(root, project.release, BootstrapOptions())
        assert verdict.state == "mismatch", f"{content!r} short-circuited the suite check"
        assert "noble" in verdict.reason, verdict.reason


def test_a_tree_that_declares_nothing_is_reused_and_says_it_was_not_verified(tmp_path) -> None:
    """The one leg that lets an unverified tree through, and it admits it.

    Refusing here would break every hand-assembled tree that carries no codename, to
    guard against a case no evidence points at. Returning a bare pass would claim a
    check that did not happen. So it passes with the reason attached, and the dry-run
    report turns that reason into a warning -- see the report test below.
    """
    project = Project.create("Silent", tmp_path / "silent", "26.04")
    _tree(project.squashfs_root)

    verdict = rootfs_verdict(project.squashfs_root, project.release, BootstrapOptions())

    assert verdict.state == "reusable"
    assert "unverified" in verdict.reason, verdict.reason


def test_the_identity_is_read_from_the_vendor_copy_too(tmp_path) -> None:
    """os-release(5) has two locations, and a tree may ship only the vendor one.

    Two divergent readers existed before this: one that looked in both places and one
    that looked only in ``/etc``. Under the second, a vendor-only tree has no identity
    at all -- which is precisely the answer that lets a wrong-suite tree pass for the
    right one. Consolidated on the reader that finds both.
    """
    project = Project.create("VendorOnly", tmp_path / "vendor-only", "26.04")
    _tree(project.squashfs_root, codename="noble", vendor_only=True)

    assert read_os_release(project.squashfs_root)["VERSION_CODENAME"] == "noble"
    assert rootfs_verdict(project.squashfs_root, project.release, BootstrapOptions()).state == (
        "mismatch"
    )


def test_the_record_is_written_only_after_the_tool_that_earns_it_ran(tmp_path) -> None:
    """A record written first would outlive a bootstrap that failed halfway.

    The next run would then find a partial tree with a record swearing it is the right
    base -- worse than no record, because the suite fallback would never be consulted.
    Order asserted, not assumed.
    """
    project = Project.create("Ordered", tmp_path / "ordered", "26.04")
    # A dry run, because that is the mode in which FileSystemOps routes writes through
    # the runner instead of performing them, which is what makes the order observable.
    service = BootstrapService(
        CommandRunner(dry_run=True),
        project.release,
        project.squashfs_root,
        project.iso_root,
    )

    service.create_rootfs()

    # argv[0] is the privilege wrapper, not the tool, so the tool is looked for
    # anywhere in the command line rather than at its head.
    argv = [spec.argv for spec in service.runner.history]
    tool = next(i for i, spec in enumerate(argv) if {"mmdebstrap", "debootstrap"} & set(spec))
    stamp = str(bootstrap_stamp_path(project.squashfs_root))
    written = [i for i, spec in enumerate(argv) if stamp in spec]

    assert written, f"no command wrote the record: {argv}"
    assert min(written) > tool, f"the record was written before the bootstrap: {argv}"


def test_a_bootstrap_that_failed_leaves_no_record_claiming_it_succeeded(tmp_path) -> None:
    """The other half of the ordering, stated as the consequence rather than the order.

    A record beside a half-bootstrapped tree is worse than no record: the next run
    would compare against it, find every field agreeing, and skip the suite fallback
    entirely -- reusing a tree the tool never finished writing.
    """

    class _Failing(CommandRunner):
        def __init__(self) -> None:
            super().__init__(dry_run=False)

        def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
            if {"mmdebstrap", "debootstrap"} & set(spec.argv):
                raise RuntimeError("bootstrap tool failed")
            self.history.append(spec)
            return CommandResult(spec=spec, returncode=0, stdout="", stderr="")

    project = Project.create("Failed", tmp_path / "failed", "26.04")
    service = BootstrapService(
        _Failing(), project.release, project.squashfs_root, project.iso_root
    )

    with pytest.raises(RuntimeError):
        service.create_rootfs()

    assert not bootstrap_stamp_path(project.squashfs_root).exists()


def test_the_record_lands_beside_the_tree_and_never_inside_it(tmp_path) -> None:
    """Inside the tree, it would ship into the image.

    This project has already had to undo shipping build bookkeeping into an image
    once, for customization hooks. Beside the tree, the record also shares the fate of
    what it describes: whatever removes the rootfs removes the claim about it.
    """
    project = Project.create("Beside", tmp_path / "beside", "26.04")
    stamp = project.bootstrap_stamp

    assert stamp == bootstrap_stamp_path(project.squashfs_root)
    assert project.squashfs_root not in stamp.parents
    assert stamp.parent == project.workdir


def test_the_dry_run_report_asks_the_build_instead_of_re_deriving_the_answer(tmp_path) -> None:
    """A dry run that re-implements the test can disagree with the build it describes.

    It did: the report carried its own copy of the three-path check. Both now call one
    verdict function, so the states and the findings cannot drift apart. Checked in
    both directions -- the report must announce the refusal the build will make, and
    must not announce a reuse the build will refuse.
    """
    project = Project.create("Reported", tmp_path / "reported", "26.04")
    _tree(project.squashfs_root, codename="noble")

    codes = {finding.code for finding in _findings(project)}

    assert "bootstrap-rootfs-mismatch" in codes, sorted(codes)
    assert "bootstrap-rootfs-reuse" not in codes, sorted(codes)


def test_the_report_warns_about_the_reuse_it_could_not_fully_justify(tmp_path) -> None:
    """An "info: will be reused" line reads like a completed check. Here it wasn't."""
    project = Project.create("Caveat", tmp_path / "caveat", "26.04")
    _tree(project.squashfs_root)

    by_code = {finding.code: finding for finding in _findings(project)}

    assert "bootstrap-rootfs-reuse" in by_code, sorted(by_code)
    assert by_code["bootstrap-rootfs-unverified"].level == "warning"


def test_a_fully_recorded_reuse_carries_no_warning(tmp_path) -> None:
    """The control for the warning: it must be absent when the check did complete."""
    project = Project.create("Quiet", tmp_path / "quiet", "26.04")
    _tree(project.squashfs_root, codename="resolute")
    _stamp(project.squashfs_root)

    codes = {finding.code for finding in _findings(project)}

    assert "bootstrap-rootfs-reuse" in codes, sorted(codes)
    assert "bootstrap-rootfs-unverified" not in codes, sorted(codes)


def test_the_states_that_predate_this_change_still_answer_the_same_way(tmp_path) -> None:
    """Absent, empty and incomplete are not regressions waiting to happen.

    The verdict function replaced three ad-hoc path tests with one, so the three
    answers that were already right have to be shown to still be right.
    """
    project = Project.create("Existing", tmp_path / "existing", "26.04")
    root = project.squashfs_root
    options = BootstrapOptions()

    assert rootfs_verdict(root, project.release, options).state == "absent"
    root.mkdir(parents=True, exist_ok=True)
    assert rootfs_verdict(root, project.release, options).state == "empty"
    (root / "partial").write_text("", encoding="utf-8")
    assert rootfs_verdict(root, project.release, options).state == "incomplete"

    with pytest.raises(ValueError) as caught:
        _service(project).create_rootfs()
    assert "non-empty but incomplete" in str(caught.value)
