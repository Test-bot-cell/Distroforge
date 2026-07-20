from __future__ import annotations

import argparse
from pathlib import Path

from distroforge.core.presets import list_presets, write_preset


def run_presets(args: argparse.Namespace) -> None:
    if args.export:
        target = args.output or Path(f"{args.export}.forge.json")
        write_preset(args.export, target)
        print(f"Wrote {target}")
        return
    for preset in list_presets():
        print(f"{preset.key:12} {preset.label}")
