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

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# Qt reads XDG_RUNTIME_DIR at startup and warns when it is unset or wrong-moded;
# offscreen does not need it, and the warning is noise in every CI log.
os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")


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


def pytest_collection_modifyitems(items) -> None:
    """Skip the mode-locked-path tests when the suite runs as root.

    Those tests lock a directory to 0500 and assert that DistroForge falls back to a
    privileged command. Root -- and the owner of the directory -- can write it anyway,
    so the PermissionError never arrives and the assertion fails for a reason that has
    nothing to do with the code. Rootless is the supported configuration: debian/control
    declares Rules-Requires-Root: no and the CI job that uses the distribution's own
    interpreter runs the suite as an unprivileged user for exactly this reason.
    """
    if os.geteuid() != 0:
        return
    skip = pytest.mark.skip(reason="running as root: a mode-locked path is still writable")
    for item in items:
        if "unprivileged" in item.keywords:
            item.add_marker(skip)
