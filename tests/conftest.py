"""Session-wide test environment.

The Qt platform plugin is set here rather than in individual modules. It used to
depend on whichever Qt-touching module happened to import first calling
`os.environ.setdefault`, so the suite passed for a reason that had nothing to do
with intent: run a single Qt test on its own, or reorder the files, and it would
try to reach a real display.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# Qt reads XDG_RUNTIME_DIR at startup and warns when it is unset or wrong-moded;
# offscreen does not need it, and the warning is noise in every CI log.
os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")


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
