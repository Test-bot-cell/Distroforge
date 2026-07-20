from __future__ import annotations

from distroforge.core.releases import load_releases
from distroforge.core.rich_console import TableData, print_table, rows


def run_releases() -> None:
    releases = load_releases().values()
    table = TableData(
        "Build Releases",
        ("Version", "Family", "Codename", "State", "Label"),
        rows(
            (
                release.version,
                release.family,
                release.codename,
                "supported" if release.supported else "planned",
                release.label,
            )
            for release in releases
        ),
    )
    if not print_table(table):
        for release in load_releases().values():
            state = "supported" if release.supported else "planned"
            print(f"{release.version:12} {release.family:8} {release.codename:12} {state:9} {release.label}")
