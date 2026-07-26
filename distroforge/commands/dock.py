"""``distroforge dock`` -- the CLI half of the GNOME dock preference.

The First Run dialog owns the same setting, and parity is a release requirement, so
the pin is reachable without a display. Both halves call
:mod:`distroforge.core.gnome_favorites`, which never escalates privilege and only
ever addresses the session bus of the user running it -- unlike the root postinst
this replaced, which reached into other people's sessions and could not ask anyone.

``--dry-run`` prints the ``gsettings`` command instead of running it, so the plan is
reviewable the same way every other DistroForge command is.
"""

from __future__ import annotations

from distroforge.core.command import CommandRunner
from distroforge.core.gnome_favorites import (
    FavoritesState,
    pin_launcher,
    read_favorites,
    unpin_launcher,
)
from distroforge.ui.preferences import load_dock_pin_choice, save_dock_pin_choice


def register_dock_commands(sub) -> None:
    parser = sub.add_parser("dock", help="Pin or unpin the DistroForge launcher in the GNOME dock")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--pin", action="store_true", help="Add the launcher to the dock favorites")
    action.add_argument("--unpin", action="store_true", help="Remove the launcher from the dock favorites")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the gsettings command instead of changing the dock",
    )


def render_dock_command(args) -> str | None:
    if args.command != "dock":
        return None
    runner = CommandRunner(dry_run=args.dry_run)
    # Reading is not a change, so it executes even under --dry-run: a plan built on an
    # unread dock would propose replacing every favorite with a single entry.
    reader = CommandRunner(dry_run=False)
    if args.pin or args.unpin:
        # The answer is recorded whether or not the write can happen, so a headless
        # run still tells the GUI the question has been answered.
        if not args.dry_run:
            save_dock_pin_choice(bool(args.pin))
        state = pin_launcher(runner, reader) if args.pin else unpin_launcher(runner, reader)
    else:
        state = read_favorites(reader)
    return _render(state, runner, remembered=load_dock_pin_choice())


def _render(state: FavoritesState, runner: CommandRunner, remembered: bool | None) -> str:
    lines = ["GNOME dock favorites", "====================", state.summary()]
    if state.available and state.entries:
        lines.append("Favorites: " + ", ".join(state.entries))
    lines.append(
        "Remembered answer: "
        + ("not answered yet" if remembered is None else "pinned" if remembered else "not pinned")
    )
    planned = [spec.display() for spec in runner.history]
    if planned:
        lines.append("Commands:")
        lines.extend(f"  {command}" for command in planned)
    return "\n".join(lines)
