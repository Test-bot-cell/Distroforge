"""Lenient parsers for numeric values typed into GUI text fields.

The build-options mapper turns free-typed text back into ``BuildOptions``; a
blank or malformed field must fall back to a sensible default rather than raise
mid-collection. These two readers encode that rule once instead of once per
call site.
"""

from __future__ import annotations


def int_or_default(value: str, default: int) -> int:
    """The integer in ``value``, or ``default`` when it is blank or malformed."""
    try:
        return int(value)
    except ValueError:
        return default


def optional_int(value: str) -> int | None:
    """The integer in ``value``, or ``None`` when the field is empty."""
    text = value.strip()
    if not text:
        return None
    return int_or_default(text, 0)
