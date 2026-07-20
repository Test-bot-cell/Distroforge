from __future__ import annotations

import random
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files


@dataclass(frozen=True)
class BrandingPalette:
    key: str
    label: str
    colors: tuple[str, ...]

    @property
    def main_color(self) -> str:
        return self.colors[0] if self.colors else "#2e3436"

    def summary(self) -> str:
        return f"{self.label}: {', '.join(self.colors)}"


def parse_palette_colors(value: str) -> tuple[str, ...]:
    colors = tuple(part.strip() for part in value.replace(";", ",").split(",") if part.strip())
    invalid = [color for color in colors if not valid_hex_color(color)]
    if invalid:
        raise ValueError(f"Invalid palette color(s): {', '.join(invalid)}")
    return colors


def generate_palette(seed: str | None = None, count: int = 5) -> tuple[str, ...]:
    rng = random.Random(seed or "distroforge")
    hue = rng.random()
    offsets = (0.0, 0.08, 0.16, 0.52, 0.68)
    colors = [_hsl_to_hex((hue + offsets[index % len(offsets)]) % 1.0, 0.58, 0.46) for index in range(count)]
    return tuple(colors)


@lru_cache(maxsize=1)
def load_branding_palettes() -> dict[str, BrandingPalette]:
    path = files("distroforge.data").joinpath("branding_palettes.toml")
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    palettes: dict[str, BrandingPalette] = {}
    for key, data in raw["palettes"].items():
        palettes[key] = BrandingPalette(
            key=key,
            label=data["label"],
            colors=tuple(data["colors"]),
        )
    return palettes


def valid_hex_color(value: str) -> bool:
    text = value.strip()
    if not text.startswith("#") or len(text) != 7:
        return False
    return all(char in "0123456789abcdefABCDEF" for char in text[1:])


def _hsl_to_hex(hue: float, saturation: float, lightness: float) -> str:
    if saturation == 0:
        channel = round(lightness * 255)
        return f"#{channel:02x}{channel:02x}{channel:02x}"
    q = lightness * (1 + saturation) if lightness < 0.5 else lightness + saturation - lightness * saturation
    p = 2 * lightness - q
    red = _hue_to_rgb(p, q, hue + 1 / 3)
    green = _hue_to_rgb(p, q, hue)
    blue = _hue_to_rgb(p, q, hue - 1 / 3)
    return f"#{round(red * 255):02x}{round(green * 255):02x}{round(blue * 255):02x}"


def _hue_to_rgb(p: float, q: float, t: float) -> float:
    if t < 0:
        t += 1
    if t > 1:
        t -= 1
    if t < 1 / 6:
        return p + (q - p) * 6 * t
    if t < 1 / 2:
        return q
    if t < 2 / 3:
        return p + (q - p) * (2 / 3 - t) * 6
    return p
