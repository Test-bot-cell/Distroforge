"""DistroForge's colour identity is the GNOME HIG palette, faithfully and autonomously.

These are pure-data contracts (no Qt, no QApplication): the palette module must
transcribe the GNOME families exactly, every semantic role must resolve to one of
those named colours, and the chosen identity must stay GNOME Blue -- never the
Ubuntu orange or the Canonical aubergine.
"""

from __future__ import annotations

import re

from distroforge.ui import palette

_FAMILY = re.compile(r"^(BLUE|GREEN|YELLOW|ORANGE|RED|PURPLE|BROWN|LIGHT|DARK)_[1-5]$")


def _named_palette() -> dict[str, str]:
    return {name: value for name, value in vars(palette).items() if _FAMILY.match(name)}


def test_palette_transcribes_the_gnome_hig_families() -> None:
    named = _named_palette()
    # Nine families x five shades = the full HIG palette.
    assert len(named) == 45
    assert all(re.fullmatch(r"#[0-9a-f]{6}", value) for value in named.values())
    # Anchor a few values straight from the HIG so a transcription typo can't drift.
    assert palette.BLUE_3 == "#3584e4"
    assert palette.GREEN_5 == "#26a269"
    assert palette.YELLOW_5 == "#e5a50a"
    assert palette.RED_4 == "#c01c28"


def test_semantic_tokens_are_all_drawn_from_the_palette() -> None:
    named_values = set(_named_palette().values())
    for role, value in palette.semantic_tokens().items():
        assert value in named_values, f"semantic {role} ({value}) is not a named GNOME colour"


def test_identity_is_gnome_blue_and_never_canonical() -> None:
    # Chosen identity: GNOME Blue. The accent family stays blue end to end.
    assert palette.PRIMARY == palette.BLUE_3
    assert palette.PRIMARY_HOVER == palette.BLUE_4
    assert palette.SECONDARY == palette.BLUE_5
    # Never the Ubuntu orange or the Canonical aubergine.
    canonical_hues = {"#e95420", "#2c001e", "#772953"}
    assert canonical_hues.isdisjoint(set(palette.semantic_tokens().values()))
    # The accent must never read as a status signal.
    assert palette.PRIMARY not in {palette.SUCCESS, palette.WARNING, palette.ERROR}
