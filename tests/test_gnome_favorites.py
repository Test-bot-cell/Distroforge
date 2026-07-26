"""The dock hook, now that it lives somewhere it can be tested.

While it sat in ``debian/distroforge.postinst`` it had no test at all -- which is how
a payload that raised ``SyntaxError`` on every single invocation shipped through five
releases and was announced in the changelog of 0.3.4-4 as a working feature.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from distroforge.core.command import CommandResult, CommandRunner
from distroforge.core.gnome_favorites import (
    KEY,
    LAUNCHER,
    SCHEMA,
    FavoritesState,
    parse_favorites,
    pin_launcher,
    read_favorites,
    render_favorites,
    session_environment,
    unpin_launcher,
)
from distroforge.ui import preferences

DOCK = "['org.gnome.Nautilus.desktop', 'firefox_firefox.desktop']"


class FakeGsettingsRunner:
    """Answers `gsettings get` from an in-memory dock and records every write."""

    dry_run = False

    def __init__(self, dock: str = DOCK, returncode: int = 0, available: bool = True) -> None:
        self.dock = dock
        self.returncode = returncode
        self.available = available
        self.history: list = []

    def has_binary(self, name: str) -> bool:
        return self.available and name == "gsettings"

    def run(self, spec, check: bool = True):
        self.history.append(spec)
        if spec.argv[:2] == ("gsettings", "get"):
            return CommandResult(spec, self.returncode, self.dock, "")
        if spec.argv[:2] == ("gsettings", "set"):
            self.dock = spec.argv[4]
            return CommandResult(spec, self.returncode, "", "")
        raise AssertionError(f"unexpected command: {spec.argv}")


@pytest.fixture
def session(tmp_path, monkeypatch):
    bus = tmp_path / "bus"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", f"unix:path={bus}")
    monkeypatch.setattr(Path, "is_socket", lambda self: self.name == "bus")
    return bus


class _Args:
    """The argparse namespace ``distroforge dock`` receives."""

    command = "dock"

    def __init__(self, pin: bool = False, unpin: bool = False, dry_run: bool = False) -> None:
        self.pin = pin
        self.unpin = unpin
        self.dry_run = dry_run


def test_the_cli_half_reports_the_dock_without_changing_it(session, tmp_path, monkeypatch, capsys) -> None:
    # Parity is a release requirement, so the setting the First Run dialog owns has to
    # be reachable without a display -- and reading it must stay a read.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    runner = FakeGsettingsRunner()
    monkeypatch.setattr("distroforge.commands.dock.CommandRunner", lambda dry_run=True: runner)

    from distroforge.commands.dock import render_dock_command

    output = render_dock_command(_Args())

    assert "not pinned to the dock" in output
    assert "not answered yet" in output
    assert [spec.argv[:2] for spec in runner.history] == [("gsettings", "get")]


def test_the_cli_half_plans_the_write_under_dry_run(session, tmp_path, monkeypatch) -> None:
    # A dry-run built on an unread dock would propose replacing every favorite with a
    # single entry, so the read executes and only the write is planned.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    real = FakeGsettingsRunner()
    planned = CommandRunner(dry_run=True)
    monkeypatch.setattr(
        "distroforge.commands.dock.CommandRunner",
        lambda dry_run=True: planned if dry_run else real,
    )

    from distroforge.commands.dock import render_dock_command

    output = render_dock_command(_Args(pin=True, dry_run=True))

    assert "gsettings set" in output
    assert LAUNCHER in output
    assert "org.gnome.Nautilus.desktop" in output
    # Nothing was written and nothing was remembered: a plan is not an answer.
    assert [spec.argv[:2] for spec in real.history] == [("gsettings", "get")]
    assert preferences.load_dock_pin_choice() is None


def test_the_cli_half_records_the_answer_when_it_acts(session, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    runner = FakeGsettingsRunner()
    monkeypatch.setattr("distroforge.commands.dock.CommandRunner", lambda dry_run=True: runner)

    from distroforge.commands.dock import render_dock_command

    render_dock_command(_Args(pin=True))
    assert preferences.load_dock_pin_choice() is True

    render_dock_command(_Args(unpin=True))
    assert preferences.load_dock_pin_choice() is False


def test_pin_appends_without_disturbing_the_existing_dock(session) -> None:
    runner = FakeGsettingsRunner()

    state = pin_launcher(runner)

    assert state.available
    assert state.pinned
    assert state.entries == ("org.gnome.Nautilus.desktop", "firefox_firefox.desktop", LAUNCHER)
    written = next(spec.argv for spec in runner.history if spec.argv[:2] == ("gsettings", "set"))
    assert written[2:4] == (SCHEMA, KEY)
    assert "org.gnome.Nautilus.desktop" in written[4]


def test_pin_is_idempotent_and_writes_nothing_when_already_pinned(session) -> None:
    runner = FakeGsettingsRunner(dock=f"['{LAUNCHER}']")

    state = pin_launcher(runner)

    assert state.pinned
    assert [spec.argv[:2] for spec in runner.history] == [("gsettings", "get")]


def test_unpin_is_symmetric_and_keeps_the_other_entries(session) -> None:
    runner = FakeGsettingsRunner(dock=f"['nautilus.desktop', '{LAUNCHER}', 'firefox.desktop']")

    state = unpin_launcher(runner)

    assert not state.pinned
    assert state.entries == ("nautilus.desktop", "firefox.desktop")


def test_unpin_writes_nothing_when_the_launcher_is_absent(session) -> None:
    runner = FakeGsettingsRunner()

    unpin_launcher(runner)

    assert [spec.argv[:2] for spec in runner.history] == [("gsettings", "get")]


def test_no_session_bus_is_reported_not_guessed(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", f"unix:path={tmp_path / 'absent'}")
    runner = FakeGsettingsRunner()

    state = read_favorites(runner)

    assert session_environment() is None
    assert not state.available
    assert "session bus" in state.reason
    assert runner.history == []


def test_missing_gsettings_is_reported_not_guessed(session) -> None:
    runner = FakeGsettingsRunner(available=False)

    state = read_favorites(runner)

    assert not state.available
    assert "gsettings" in state.reason


def test_a_dry_run_runner_refuses_to_read_so_it_cannot_erase_the_dock(session) -> None:
    """A planned read returns nothing; appending to nothing would wipe the dock."""
    runner = CommandRunner(dry_run=True)

    state = pin_launcher(runner)

    assert not state.available
    assert "dry-run" in state.reason
    assert runner.history == []


def test_a_failed_gsettings_get_is_not_read_as_an_empty_dock(session) -> None:
    runner = FakeGsettingsRunner(returncode=1)

    state = read_favorites(runner)

    assert not state.available
    assert state.entries == ()


def test_the_command_never_escalates_privilege(session) -> None:
    runner = FakeGsettingsRunner()

    pin_launcher(runner)

    for spec in runner.history:
        assert spec.argv[0] == "gsettings"
        assert not spec.needs_root
        assert spec.env["DBUS_SESSION_BUS_ADDRESS"].endswith("/bus")


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        ("['a.desktop', 'b.desktop']", ("a.desktop", "b.desktop")),
        ("[]", ()),
        ("@as []", ()),
        ("not a variant", ()),
        ("{'a': 1}", ()),
    ),
)
def test_parse_favorites_tolerates_anything_gsettings_may_print(raw: str, expected: tuple[str, ...]) -> None:
    assert parse_favorites(raw) == expected


def test_render_round_trips_through_parse() -> None:
    entries = ("nautilus.desktop", LAUNCHER)

    assert parse_favorites(render_favorites(entries)) == entries
    assert render_favorites(()) == "[]"


def test_render_escapes_a_quote_instead_of_closing_the_array_early() -> None:
    # The entries come back from the user's own dock, so one apostrophe would have
    # made gsettings reject the array and the write would drop every other pin.
    entries = ("it's-mine.desktop", "back\\slash.desktop", LAUNCHER)

    rendered = render_favorites(entries)

    assert rendered == "['it\\'s-mine.desktop', 'back\\\\slash.desktop', 'distroforge.desktop']"
    assert parse_favorites(rendered) == entries


def test_state_summary_names_the_three_outcomes() -> None:
    assert "not available" in FavoritesState(False, "no D-Bus session bus for this user").summary()
    assert "is pinned" in FavoritesState(True, "", (LAUNCHER,)).summary()
    assert "not pinned" in FavoritesState(True, "", ()).summary()


def test_the_dock_answer_is_remembered_as_three_states(tmp_path, monkeypatch) -> None:
    """Unanswered is not the same as no, which is what the postinst could not express."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    assert preferences.load_dock_pin_choice() is None
    preferences.save_dock_pin_choice(False)
    assert preferences.load_dock_pin_choice() is False
    preferences.save_dock_pin_choice(True)
    assert preferences.load_dock_pin_choice() is True
    # The answer lives beside the other UI preferences, under the user's XDG config.
    assert (tmp_path / "distroforge/ui.json").is_file()
