from __future__ import annotations

import sys
from pathlib import Path


def run() -> None:
    if __package__ in {None, ""}:
        package_dir = Path(__file__).resolve().parent
        src_dir = package_dir.parent
        if str(src_dir) not in sys.path:
            sys.path.insert(0, str(src_dir))
        from distroforge.cli import main
    else:
        from .cli import main

    main()


if __name__ == "__main__":
    run()
