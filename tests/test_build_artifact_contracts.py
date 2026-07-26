from __future__ import annotations

import hashlib
import re
from pathlib import Path

from distroforge.core.artifact_paths import default_output_iso
from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.command import CommandRunner
from distroforge.core.project import Project
from distroforge.core.release_artifacts import ReleaseArtifactOptions, ReleaseArtifactService

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "distroforge"

# REPACK_FILESYSTEM repacks squashfs_root with no exclusions, so anything left
# in the target root ships inside filesystem.squashfs of every ISO. Staged
# project hooks can carry credentials, which is why they must be removed the
# same way policy-rc.d is.
HOOK_STAGE_DIR = "distroforge-hooks"


def _bootstrap_project(tmp_path: Path, name: str) -> Project:
    project = Project.create(name, tmp_path / name.lower(), "26.04")
    project.source_mode = "bootstrap"
    return project


def test_staged_chroot_hooks_are_removed_before_the_filesystem_is_repacked(tmp_path: Path) -> None:
    project = _bootstrap_project(tmp_path, "HookLeak")
    hooks = project.root / "hooks" / "chroot"
    hooks.mkdir(parents=True, exist_ok=True)
    (hooks / "50-provision.sh").write_text("#!/bin/sh\necho secret-token\n", encoding="utf-8")
    runner = CommandRunner(dry_run=True)

    BuildOrchestrator(project, runner, BuildOptions()).run()

    argv_list = [spec.argv for spec in runner.history]
    staged = _index_of(argv_list, lambda argv: argv[0] == "stage-chroot-hooks")
    # chroot.run wraps argv, so the tool name is not argv[0].
    ran = _index_of(argv_list, lambda argv: "run-parts" in argv)
    removed = _index_of(
        argv_list, lambda argv: argv[0] == "rm-tree" and argv[-1].endswith(HOOK_STAGE_DIR)
    )
    repacked = _index_of(argv_list, lambda argv: any("mksquashfs" in part for part in argv))

    assert staged is not None, "hooks were never staged, the test proves nothing"
    assert ran is not None
    assert removed is not None, "staged hooks are still shipped inside the ISO"
    assert staged < ran < removed
    if repacked is not None:
        assert removed < repacked


def test_staged_hooks_are_removed_even_when_a_hook_fails(tmp_path: Path) -> None:
    project = _bootstrap_project(tmp_path, "HookFail")
    hooks = project.root / "hooks" / "chroot"
    hooks.mkdir(parents=True, exist_ok=True)
    (hooks / "50-fails.sh").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    runner = CommandRunner(dry_run=True)
    real_run = runner.run
    failures: list[str] = []

    def _run(spec, **kwargs):
        if "run-parts" in spec.argv:
            failures.append("boom")
            raise RuntimeError("hook failed")
        return real_run(spec, **kwargs)

    runner.run = _run  # type: ignore[method-assign]
    try:
        BuildOrchestrator(project, runner, BuildOptions()).run()
    except RuntimeError:
        pass

    assert failures, "the hook run was never reached, the test proves nothing"
    argv_list = [spec.argv for spec in runner.history]
    assert _index_of(
        argv_list, lambda argv: argv[0] == "rm-tree" and argv[-1].endswith(HOOK_STAGE_DIR)
    ) is not None


def _index_of(argv_list, predicate) -> int | None:
    for index, argv in enumerate(argv_list):
        if predicate(argv):
            return index
    return None


# --output-iso accepts any path. Hashing from output_dir made the build fail
# after the ISO had been written, or published the digest of a stale namesake.
def test_sha256sums_hashes_the_iso_wherever_output_iso_points(tmp_path: Path) -> None:
    output_dir = tmp_path / "dist"
    output_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    iso = elsewhere / "remix.iso"
    iso.write_bytes(b"the real iso")
    # A stale namesake in output_dir is what used to be hashed by mistake.
    (output_dir / "remix.iso").write_bytes(b"a stale namesake")

    ReleaseArtifactService(
        CommandRunner(dry_run=False), output_dir, iso, ReleaseArtifactOptions()
    ).write()

    sums = (output_dir / "SHA256SUMS").read_text(encoding="utf-8")
    assert hashlib.sha256(b"the real iso").hexdigest() in sums
    assert hashlib.sha256(b"a stale namesake").hexdigest() not in sums


def test_default_output_iso_carries_the_release_version(tmp_path: Path) -> None:
    project = _bootstrap_project(tmp_path, "Versioned")

    assert default_output_iso(project) == project.output_dir / "Versioned-26.04.iso"


# The builder writes {name}-{version}.iso. Every consumer that invented its own
# unversioned fallback reported a missing ISO for an ISO that existed. One
# helper now owns the name; these modules still hold their own copy and are
# rewritten by the pending responsiveness work.
PENDING_UNVERSIONED_FALLBACKS = {
    "distroforge/ui/artifacts_page.py": "moved to a worker by the responsiveness fix",
    "distroforge/ui/artifacts_actions.py": "moved to a worker by the responsiveness fix",
    "distroforge/ui/main_window.py": "moved to a worker by the responsiveness fix",
    "distroforge/core/evidence.py": "memoised by the responsiveness fix",
}

_UNVERSIONED = re.compile(r"""\{\s*(?:\w+\.)*name\s*\}\.iso""")
# The module that owns the canonical name describes the old shape in its docstring.
_NAME_OWNER = "distroforge/core/artifact_paths.py"


def test_no_module_invents_its_own_unversioned_iso_fallback() -> None:
    offenders = {}
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if rel in PENDING_UNVERSIONED_FALLBACKS or rel == _NAME_OWNER:
            continue
        hits = _UNVERSIONED.findall(path.read_text(encoding="utf-8"))
        if hits:
            offenders[rel] = len(hits)

    assert offenders == {}, f"use default_output_iso instead: {offenders}"


def test_the_pending_list_stays_honest() -> None:
    # An entry that no longer offends must be removed, or the list becomes a lie.
    for rel in PENDING_UNVERSIONED_FALLBACKS:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert _UNVERSIONED.search(text), f"{rel} is fixed, drop it from the pending list"
