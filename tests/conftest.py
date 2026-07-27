"""Session-wide test environment.

The Qt platform plugin is set here rather than in individual modules. It used to
depend on whichever Qt-touching module happened to import first calling
`os.environ.setdefault`, so the suite passed for a reason that had nothing to do
with intent: run a single Qt test on its own, or reorder the files, and it would
try to reach a real display.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from distroforge.core import qemu_invocation
from distroforge.core.bootstrap import _ROOTFS_REQUIREMENTS

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# Qt reads XDG_RUNTIME_DIR at startup and warns when it is unset or wrong-moded;
# offscreen does not need it, and the warning is noise in every CI log.
os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")


def make_rootfs(root: Path, codename: str | None = None) -> Path:
    """Materialise the smallest tree ``rootfs_verdict`` will accept as a rootfs.

    Built *from* ``_ROOTFS_REQUIREMENTS`` rather than from a hand-copied list of paths,
    because the hand-copied version already cost four test files. When a package manager
    joined the requirements, every test that had spelled out "dpkg status plus an
    os-release" started failing on the new entry before reaching what it was written to
    check -- none of them was about completeness, they all just needed a plausible tree.
    Deriving it means adding a fifth requirement updates them all, and
    ``test_the_shared_rootfs_helper_satisfies_the_real_requirements`` fails loudly here
    if this ever drifts from the production definition instead of quietly in four places.

    The first alternative of each requirement is the one created: os-release(5) allows
    two locations and a real Ubuntu tree uses ``/etc``.
    """
    for _label, paths in _ROOTFS_REQUIREMENTS:
        target = root / paths[0]
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_text("", encoding="utf-8")
    body = "ID=ubuntu\n" + (f"VERSION_CODENAME={codename}\n" if codename else "")
    (root / "etc/os-release").write_text(body, encoding="utf-8")
    return root


@pytest.fixture(scope="session", autouse=True)
def _isolated_config_home(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Give the whole session a throwaway XDG_CONFIG_HOME.

    The suite must never read or write the user's live
    ``~/.config/distroforge/ui.json``; `distroforge.ui.preferences` resolves that
    path from this variable. Six modules used to arrange it for themselves, at
    import time, with

        os.environ.setdefault("XDG_CONFIG_HOME", tempfile.mkdtemp())

    which leaked a directory per module per run. `setdefault` evaluates its second
    argument before it decides whether to use it, so all six calls to `mkdtemp`
    ran and five of the six directories were created, never used, and never
    removed -- and the sixth, the one that won, was not removed either. Measured
    2026-07-27: 1425 had piled up under /tmp, 241 of them holding a `ui.json`.

    `tmp_path_factory` puts this under pytest's own base directory, which pytest
    rotates (it keeps the last three runs), so nothing accumulates.

    Two details are deliberate:

    - `setenv`, not `setdefault`. The old form skipped the redirection entirely
      for anyone who exports XDG_CONFIG_HOME -- a legitimate thing to do -- and
      pointed the suite straight at their real configuration. The isolation this
      fixture exists for cannot be conditional on the developer's environment.
    - Session scope with autouse, rather than the import-time statement it
      replaces. `preferences.config_dir()` reads the variable on every call and
      no module reads it while importing, so setting it at fixture time is early
      enough; pytest orders session-scoped autouse fixtures ahead of the
      module-scoped `qt_app` fixtures, so QApplication is still built under it.

    Tests that want their own config home keep overriding it with
    `monkeypatch.setenv`, which nests inside this one and restores to it.
    """
    config_home = tmp_path_factory.mktemp("xdg-config")
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("XDG_CONFIG_HOME", str(config_home))
        yield


@pytest.fixture(scope="session", autouse=True)
def _unaccelerated_qemu() -> Iterator[None]:
    """Decide QEMU acceleration for the suite instead of letting the host decide it.

    Every service that launches QEMU asks `qemu_invocation.kvm_is_usable()`, which
    reads a real device node. Left alone, the argv a test asserts against would carry
    `-enable-kvm` on a developer's machine and not on a CI runner -- the same test,
    two outcomes, neither of them about the code. Pointing the probe at a path that
    cannot exist makes emulation the answer everywhere.

    The probe itself is tested in `test_qemu_invocation.py` against files it creates,
    and the two tests that assert the accelerated argv point this at one of those.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(qemu_invocation, "KVM_DEVICE", Path("/nonexistent/dev/kvm"))
        yield


def pytest_collection_modifyitems(items) -> None:
    """Skip the mode-locked-path tests when the suite runs as root.

    Those tests lock a directory to 0500 and assert that DistroForge falls back to a
    privileged command. Root -- and the owner of the directory -- can write it anyway,
    so the PermissionError never arrives and the assertion fails for a reason that has
    nothing to do with the code. Rootless is the supported configuration: debian/control
    declares Rules-Requires-Root: no and ci.yml's distro-dependencies job runs the suite as
    an unprivileged user for exactly this reason. It is the only job that does: the golden
    path builds the package as the container's root, because autopkgtest's null backend has
    to install what it built, so these tests skip there and that job is not where they are
    covered.
    """
    if os.geteuid() != 0:
        return
    skip = pytest.mark.skip(reason="running as root: a mode-locked path is still writable")
    for item in items:
        if "unprivileged" in item.keywords:
            item.add_marker(skip)
