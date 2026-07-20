from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

LAUNCHER_ICON = Path("debian/distroforge.svg")
DESKTOP_ENTRY = Path("debian/distroforge.desktop")
GUI_APP = Path("distroforge/ui/app.py")


def test_launcher_icon_is_valid_square_svg() -> None:
    root = ET.parse(LAUNCHER_ICON).getroot()
    assert root.tag.endswith("svg")
    view_box = root.get("viewBox")
    assert view_box is not None
    _, _, width, height = (float(value) for value in view_box.split())
    # A launcher icon must be square so the shell never letterboxes or crops it.
    assert width == height


def test_desktop_entry_points_at_themed_icon() -> None:
    text = DESKTOP_ENTRY.read_text(encoding="utf-8")
    assert "Icon=distroforge" in text


def test_gui_window_inherits_launcher_icon() -> None:
    source = GUI_APP.read_text(encoding="utf-8")
    assert 'setDesktopFileName("distroforge")' in source
    assert 'setWindowIcon(QIcon.fromTheme("distroforge"))' in source


def test_gui_pins_adwaita_icon_theme() -> None:
    # Functional glyphs are GNOME-native: the app pins the Adwaita icon theme
    # rather than bundling its own set.
    source = GUI_APP.read_text(encoding="utf-8")
    assert 'setThemeName("Adwaita")' in source
