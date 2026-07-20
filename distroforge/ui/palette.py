from __future__ import annotations

# The GNOME Human Interface Guidelines color palette, transcribed verbatim from
# https://developer.gnome.org/hig/reference/palette.html
#
# DistroForge draws its whole visual identity from these named colors so the
# product reads as a GNOME-native, *autonomous* tool -- deliberately not a
# Canonical / Vanilla-framework derivative. The accent is GNOME Blue (never the
# Ubuntu orange, never the aubergine), and the status signals are the palette's
# own green / amber / red rather than ad-hoc values. One palette, one source of
# truth -- the same reliability discipline already applied to the neutral
# Adwaita surfaces in ``theme``.

# -- Named families (1 = lightest tint ... 5 = darkest shade) -----------------
BLUE_1, BLUE_2, BLUE_3, BLUE_4, BLUE_5 = "#99c1f1", "#62a0ea", "#3584e4", "#1c71d8", "#1a5fb4"
GREEN_1, GREEN_2, GREEN_3, GREEN_4, GREEN_5 = "#8ff0a4", "#57e389", "#33d17a", "#2ec27e", "#26a269"
YELLOW_1, YELLOW_2, YELLOW_3, YELLOW_4, YELLOW_5 = "#f9f06b", "#f8e45c", "#f6d32d", "#f5c211", "#e5a50a"
ORANGE_1, ORANGE_2, ORANGE_3, ORANGE_4, ORANGE_5 = "#ffbe6f", "#ffa348", "#ff7800", "#e66100", "#c64600"
RED_1, RED_2, RED_3, RED_4, RED_5 = "#f66151", "#ed333b", "#e01b24", "#c01c28", "#a51d2d"
PURPLE_1, PURPLE_2, PURPLE_3, PURPLE_4, PURPLE_5 = "#dc8add", "#c061cb", "#9141ac", "#813d9c", "#613583"
BROWN_1, BROWN_2, BROWN_3, BROWN_4, BROWN_5 = "#cdab8f", "#b5835a", "#986a44", "#865e3c", "#63452c"
LIGHT_1, LIGHT_2, LIGHT_3, LIGHT_4, LIGHT_5 = "#ffffff", "#f6f5f4", "#deddda", "#c0bfbc", "#9a9996"
DARK_1, DARK_2, DARK_3, DARK_4, DARK_5 = "#77767b", "#5e5c64", "#3d3846", "#241f31", "#000000"

# -- Semantic identity --------------------------------------------------------
# DistroForge identity = GNOME Blue. The reserved state hues (green / yellow /
# red) are never used as the accent, so PRIMARY can never be mistaken for a
# success / warning / error signal. ON_ACCENT is the foreground for text and
# icons painted on a filled accent surface (the primary button, progress fill).
PRIMARY = BLUE_3        # accent: focus, selection, links, primary fill
PRIMARY_HOVER = BLUE_4  # one darker step -- hover / pressed feedback on the fill
SECONDARY = BLUE_5      # deeper companion for secondary emphasis
SUCCESS = GREEN_5       # done / ready / passed
WARNING = YELLOW_5      # review / caution
ERROR = RED_4           # destructive / failed
INFO = BLUE_2           # neutral information, lighter than the accent
ON_ACCENT = LIGHT_1     # foreground on a filled accent surface


def semantic_tokens() -> dict[str, str]:
    """DistroForge's semantic color set, every value sourced from the GNOME palette."""
    return {
        "primary": PRIMARY,
        "primary_hover": PRIMARY_HOVER,
        "secondary": SECONDARY,
        "success": SUCCESS,
        "warning": WARNING,
        "error": ERROR,
        "info": INFO,
        "on_accent": ON_ACCENT,
    }
