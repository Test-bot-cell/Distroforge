from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:  # pragma: no cover - minimal runtime fallback.
    Console = None  # type: ignore[assignment]
    Table = None  # type: ignore[assignment]


RICH_AVAILABLE = Console is not None and Table is not None


@dataclass(frozen=True)
class TableData:
    title: str
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]


def print_table(data: TableData) -> bool:
    if not RICH_AVAILABLE:
        return False
    table = Table(title=data.title)
    for column in data.columns:
        table.add_column(column)
    for row in data.rows:
        table.add_row(*row)
    Console().print(table)
    return True


def print_status(message: str, style: str = "bold") -> bool:
    if not RICH_AVAILABLE:
        return False
    Console().print(message, style=style)
    return True


def rows(values: Iterable[Iterable[object]]) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(str(item) for item in row) for row in values)


def rich_status() -> tuple[bool, str]:
    if RICH_AVAILABLE:
        return True, "Rich terminal output enabled"
    return False, "Rich is not installed; using plain terminal output"
