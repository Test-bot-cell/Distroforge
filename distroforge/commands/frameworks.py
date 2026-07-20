from __future__ import annotations

from distroforge.core.plugins import pluggy_status
from distroforge.core.rich_console import TableData, print_table, rich_status, rows
from distroforge.core.schema import pydantic_status


def _typer_available() -> bool:
    try:
        import typer  # noqa: F401
    except ImportError:
        return False
    return True


def run_frameworks() -> None:
    statuses = [
        ("Pydantic", *pydantic_status()),
        ("Rich", *rich_status()),
        ("Pluggy", *pluggy_status()),
        ("Typer", _typer_available(), "Typer facade available" if _typer_available() else "Typer is not installed"),
    ]
    table = TableData(
        "Framework Integrations",
        ("Framework", "State", "Detail"),
        rows((name, "enabled" if enabled else "missing", detail) for name, enabled, detail in statuses),
    )
    if not print_table(table):
        for name, enabled, detail in statuses:
            state = "enabled" if enabled else "missing"
            print(f"{name:10} {state:8} {detail}")
