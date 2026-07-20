from __future__ import annotations

from distroforge.core.build import BuildPhase
from distroforge.ui.icons import _COMMAND_ICONS, _FALLBACK, _PHASE_ICONS, _THEME_NAMES


def test_every_build_phase_has_a_logical_icon() -> None:
    missing = [phase.value for phase in BuildPhase if phase not in _PHASE_ICONS]
    assert missing == []


def test_every_used_logical_icon_resolves_to_a_theme_name() -> None:
    used = set(_PHASE_ICONS.values()) | set(_COMMAND_ICONS.values()) | {_FALLBACK}
    unmapped = sorted(name for name in used if name not in _THEME_NAMES)
    assert unmapped == []


def test_theme_names_are_freedesktop_symbolic() -> None:
    # GNOME-native: every glyph defers to the desktop's symbolic icon theme, so
    # the app bundles no private icon set of its own.
    non_symbolic = sorted(n for n, t in _THEME_NAMES.items() if not t.endswith("-symbolic"))
    assert non_symbolic == []
