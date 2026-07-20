from __future__ import annotations

from . import palette
from .qt import QApplication

# Explicit Adwaita neutral tokens. Mirrors the forced Adwaita Sans typography and the
# forced Adwaita icon theme: the GUI renders the genuine GNOME surfaces on every host
# instead of inheriting the desktop's Qt palette, so the sober look is identical
# everywhere -- one source of truth -- and the page no longer drifts into "too much
# gray" on whatever neutral palette the host happens to ship. Values are libadwaita's
# named UI colors (window / view / headerbar / card + shades); the translucent shades
# are pre-blended onto their backing surface so the QSS stays solid-hex (no alpha
# compositing artefacts on rounded corners).
#
# The accent and the success / warning / error signals are NOT host-derived either:
# they come from the autonomous DistroForge identity in ``palette`` (GNOME Blue plus
# the GNOME palette's own green / amber / red), so the product reads as a GNOME-native
# tool of its own -- never as a Canonical / Vanilla-framework derivative. Only the
# light/dark *scheme* still follows the host, via app.palette() below.
_LIGHT = {
    "window": "#fafafb",  # window_bg
    "surface": "#ffffff",  # view / card / headerbar (all white in light Adwaita)
    "field": "#ffffff",  # view_bg (text inputs)
    "text": "#333338",  # window_fg (~80% black) pre-blended on white
    "muted": "#737378",  # dim label (~55%) pre-blended on white
    "border": "#e1e1e5",  # card shade -- faint hairline
    "border_strong": "#d6d6db",  # headerbar shade
    "hover": "#efeff2",  # faint neutral hover wash
    "trough": "#ececef",  # sidebar tint -- progress track
}
_DARK = {
    "window": "#222226",  # window_bg
    "surface": "#2e2e33",  # headerbar / card surface
    "field": "#1d1d20",  # view_bg (recessed text inputs)
    "text": "#ffffff",  # window_fg
    "muted": "#9c9ca2",  # dim label (~55% white) pre-blended on window
    "border": "#3a3a40",  # faint light hairline
    "border_strong": "#46464d",  # headerbar shade
    "hover": "#3a3a41",  # faint light hover wash
    "trough": "#1b1b1e",  # recessed progress track
}


def _is_dark(app: QApplication) -> bool:
    # Honour the host's light/dark preference by deriving only the *scheme* from the
    # Qt palette (its window luminance), then pick the matching Adwaita token set. We
    # read the palette but never use its grays -- that split is what keeps the sober
    # surfaces while still flipping to dark when the desktop is dark.
    color = app.palette().window().color()
    luminance = (0.299 * color.red() + 0.587 * color.green() + 0.114 * color.blue()) / 255
    return luminance < 0.5


def apply_theme(app: QApplication) -> None:
    tokens = _DARK if _is_dark(app) else _LIGHT
    window = tokens["window"]
    surface = tokens["surface"]
    field = tokens["field"]
    text = tokens["text"]
    muted = tokens["muted"]
    border = tokens["border"]
    border_strong = tokens["border_strong"]
    hover = tokens["hover"]
    trough = tokens["trough"]

    # Autonomous GNOME-palette identity (host-independent). The reserved state hues
    # are never used as the accent, so the accent can never read as a status signal.
    accent = palette.PRIMARY
    accent_hover = palette.PRIMARY_HOVER
    on_accent = palette.ON_ACCENT
    success = palette.SUCCESS
    warning = palette.WARNING
    error = palette.ERROR

    app.setStyleSheet(
        f"""
        QWidget {{
            background: {window};
            color: {text};
            font-family: "Adwaita Sans";
            font-size: 10.5pt;
        }}
        QMainWindow, QStackedWidget, QScrollArea, QScrollArea > QWidget > QWidget {{
            background: {window};
        }}
        #AppHeader {{
            background: {surface};
            border-bottom: 1px solid {border_strong};
        }}
        #AppTitle {{
            font-size: 13pt;
            font-weight: 650;
            color: {text};
        }}
        #ProjectState {{
            color: {muted};
        }}
        #JourneySummary {{
            color: {muted};
            font-size: 9pt;
        }}
        #JourneyStep {{
            background: {surface};
            border: 1px solid {border};
            border-radius: 7px;
        }}
        #JourneyStep:hover {{
            border-color: {accent};
        }}
        #JourneyStep[journeyStatus="active"] {{
            border: 2px solid {accent};
        }}
        #JourneyStep[journeyStatus="done"] {{
            border-color: {success};
        }}
        #JourneyStep[journeyStatus="review"] {{
            border-color: {warning};
        }}
        #JourneyStepMarker {{
            background: transparent;
            font-size: 12pt;
        }}
        #JourneyStepTitle {{
            background: transparent;
            font-weight: 600;
        }}
        #JourneyStepHint {{
            background: transparent;
            color: {muted};
            font-size: 9pt;
        }}
        #StepFocus {{
            background: {surface};
            border: 1px solid {border};
            border-left: 3px solid {accent};
            border-radius: 8px;
        }}
        #StepFocus[focusStatus="ok"] {{
            border-left-color: {success};
        }}
        #StepFocus[focusStatus="warning"] {{
            border-left-color: {warning};
        }}
        #StepFocus[focusStatus="error"] {{
            border-left-color: {error};
        }}
        #StepFocusEyebrow {{
            background: transparent;
            color: {muted};
            font-size: 9pt;
            font-weight: 650;
            letter-spacing: 1px;
        }}
        #StepFocusTitle {{
            background: transparent;
            font-size: 13pt;
            font-weight: 700;
        }}
        #StepFocusWhy {{
            background: transparent;
            color: {text};
        }}
        #StepFocusStatus {{
            background: transparent;
            color: {muted};
            font-size: 9pt;
        }}
        #Section, #Stat {{
            background: {surface};
            border: 1px solid {border};
            border-radius: 8px;
        }}
        #JourneyCard {{
            background: {surface};
            border: 1px solid {border};
            border-radius: 8px;
        }}
        #JourneyCard[journeyStatus="active"] {{
            border: 2px solid {accent};
        }}
        #JourneyCard[journeyStatus="done"] {{
            border-color: {success};
        }}
        #JourneyCard[journeyStatus="review"] {{
            border-color: {warning};
        }}
        #GoalCard {{
            background: {surface};
            border: 1px solid {border};
            border-radius: 8px;
        }}
        #GoalCard:hover {{
            border-color: {accent};
        }}
        #SectionTitle, #StatValue, #StatLabel {{
            background: transparent;
        }}
        #SectionTitle {{
            font-size: 10.5pt;
            font-weight: 650;
        }}
        #GroupLabel {{
            background: transparent;
            color: {muted};
            font-size: 9pt;
            font-weight: 650;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 2px;
        }}
        #Stat {{
            padding: 8px;
        }}
        #StatValue {{
            font-size: 12pt;
            font-weight: 650;
        }}
        #StatLabel {{
            color: {muted};
            font-size: 9pt;
        }}
        #JourneyCardTitle {{
            font-weight: 650;
        }}
        #JourneyCardStatus, #JourneyCardMeta, #JourneyCardCheck {{
            color: {muted};
            font-size: 9pt;
        }}
        #JourneyCardCheck {{
            color: {text};
        }}
        QLineEdit, QPlainTextEdit, QComboBox {{
            background: {field};
            border: 1px solid {border};
            border-radius: 6px;
            padding: 6px;
            selection-background-color: {accent};
            selection-color: {on_accent};
        }}
        QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{
            border: 1px solid {accent};
        }}
        QPushButton {{
            background: transparent;
            border: 1px solid {border};
            border-radius: 6px;
            padding: 7px 12px;
        }}
        QPushButton:hover {{
            background: {hover};
            border-color: {accent};
        }}
        QPushButton#PrimaryButton {{
            background: {accent};
            border-color: {accent};
            color: {on_accent};
            font-weight: 700;
        }}
        QPushButton#PrimaryButton:hover {{
            background: {accent_hover};
            border-color: {accent_hover};
        }}
        QToolBar {{
            background: {surface};
            border-bottom: 1px solid {border_strong};
            spacing: 6px;
            padding: 4px;
        }}
        QProgressBar {{
            background: {trough};
            border: 1px solid {border};
            border-radius: 5px;
            min-height: 8px;
            max-height: 8px;
            text-align: center;
        }}
        QProgressBar::chunk {{
            background: {accent};
            border-radius: 4px;
        }}
        """
    )
