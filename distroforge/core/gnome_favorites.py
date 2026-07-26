"""Pin or unpin the DistroForge launcher in the GNOME dock, on the user's word.

From 0.3.4-4 to 0.3.5-2 this lived in ``debian/distroforge.postinst``: root walked
every account with a live session bus and drove ``gsettings`` through ``runuser``.
It never ran once -- the embedded ``python3 -c`` payload was a SyntaxError -- and it
should not have been attempted at all. ``org.gnome.shell favorite-apps`` is the
user's own dock, an install is not consent, and dpkg cannot undo a dconf write it
never recorded. So the dock preference is set from the GUI, by the user, inside the
user's own session, and it is just as removable as it is settable.

Everything here goes through :class:`CommandRunner`, which means dry-run mode plans
the change instead of performing it, and no call path ever escalates privilege.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path

from distroforge.core.command import CommandRunner, CommandSpec

SCHEMA = "org.gnome.shell"
KEY = "favorite-apps"
# The installed launcher, from debian/distroforge.install. Renaming it would drop
# every existing user's pin on the floor, so the name is a contract, not a detail.
LAUNCHER = "distroforge.desktop"


@dataclass(frozen=True)
class FavoritesState:
    """What the dock currently holds, or why DistroForge could not find out."""

    available: bool
    reason: str
    entries: tuple[str, ...] = ()

    @property
    def pinned(self) -> bool:
        return LAUNCHER in self.entries

    def summary(self) -> str:
        if not self.available:
            return f"Dock not available: {self.reason}"
        return "DistroForge is pinned to the dock." if self.pinned else "DistroForge is not pinned to the dock."


def session_environment() -> dict[str, str] | None:
    """The environment ``gsettings`` needs, or ``None`` outside a user session.

    Read from the running process, never reconstructed for somebody else: this code
    only ever addresses the session it is already inside.
    """
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    address = os.environ.get("DBUS_SESSION_BUS_ADDRESS") or f"unix:path={runtime_dir}/bus"
    socket = address.partition("unix:path=")[2].partition(",")[0]
    if socket and not Path(socket).is_socket():
        return None
    environment = dict(os.environ)
    environment["XDG_RUNTIME_DIR"] = runtime_dir
    environment["DBUS_SESSION_BUS_ADDRESS"] = address
    return environment


def read_favorites(runner: CommandRunner) -> FavoritesState:
    """Read the dock of the current user.

    A dry-run runner reports unavailable instead of an empty dock. ``gsettings get``
    would hand back nothing under dry-run, and appending the launcher to nothing
    would erase every entry the user actually has -- the read has to be real or the
    write must not happen at all.
    """
    if runner.dry_run:
        return FavoritesState(False, "dry-run planning does not read the dock")
    environment = session_environment()
    if environment is None:
        return FavoritesState(False, "no D-Bus session bus for this user")
    if not runner.has_binary("gsettings"):
        return FavoritesState(False, "gsettings is not installed")
    spec = CommandSpec(
        argv=("gsettings", "get", SCHEMA, KEY),
        env=environment,
        description="Read the GNOME dock favorites of the current user",
    )
    result = runner.run(spec, check=False)
    if result.returncode != 0:
        return FavoritesState(False, f"gsettings get {SCHEMA} {KEY} failed")
    return FavoritesState(True, "", parse_favorites(result.stdout))


def parse_favorites(raw: str) -> tuple[str, ...]:
    """Decode the GVariant array literal gsettings prints, tolerating anything else."""
    try:
        entries = ast.literal_eval(raw.strip())
    except (SyntaxError, ValueError):
        return ()
    if not isinstance(entries, list | tuple):
        return ()
    return tuple(str(item) for item in entries if isinstance(item, str))


def pin_launcher(runner: CommandRunner) -> FavoritesState:
    """Append the launcher to the dock. Idempotent, and a no-op when already pinned."""
    state = read_favorites(runner)
    if not state.available or state.pinned:
        return state
    return _write_favorites(runner, (*state.entries, LAUNCHER))


def unpin_launcher(runner: CommandRunner) -> FavoritesState:
    """Remove the launcher from the dock, leaving every other entry in place."""
    state = read_favorites(runner)
    if not state.available or not state.pinned:
        return state
    return _write_favorites(runner, tuple(item for item in state.entries if item != LAUNCHER))


def _write_favorites(runner: CommandRunner, entries: tuple[str, ...]) -> FavoritesState:
    environment = session_environment()
    if environment is None:
        return FavoritesState(False, "no D-Bus session bus for this user")
    spec = CommandSpec(
        argv=("gsettings", "set", SCHEMA, KEY, render_favorites(entries)),
        env=environment,
        description="Write the GNOME dock favorites of the current user",
    )
    result = runner.run(spec, check=False)
    if result.returncode != 0:
        return FavoritesState(False, f"gsettings set {SCHEMA} {KEY} failed")
    # dry-run reports the plan, so echo the intent rather than re-reading dconf.
    return FavoritesState(True, "", entries)


def render_favorites(entries: tuple[str, ...]) -> str:
    """Serialize to the GVariant array literal gsettings expects on input.

    The entries are whatever the user's dock already held, so a desktop-file name
    carrying an apostrophe or a backslash must be escaped rather than closing the
    literal early: gsettings would reject the whole array and the write would take
    the rest of the dock down with it.
    """
    quoted = [item.replace("\\", "\\\\").replace("'", "\\'") for item in entries]
    return "[" + ", ".join(f"'{item}'" for item in quoted) + "]"
