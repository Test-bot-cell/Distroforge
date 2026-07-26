"""Canonical readers for the JSON sidecars the release chain writes.

Six modules carried a private `_read_json`, in three different shapes: four were
byte-identical and swallowed every problem into an empty dict, one raised on a
non-object, and one reported into a caller-supplied item list. Three answers to
the same question in one package is how a reader ends up guessing which one it is
looking at, so the two general shapes live here and are named for what they do.

The reporting variant stays local to release_verification: it does not answer
"what is in this file", it appends a verdict to a report, which is a different
contract rather than a third opinion on the same one.
"""

from __future__ import annotations

import json
from pathlib import Path


def read_json_object(path: Path) -> dict[str, object]:
    """The object in ``path``, or an empty dict if it is missing or unusable.

    For sidecars whose absence is a normal state -- a stage that has not run yet
    reports "not present", not "corrupt".
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def require_json_object(path: Path) -> dict[str, object]:
    """The object in ``path``, raising if it is absent or not an object.

    For inputs the caller named explicitly: staying quiet there would compare a
    baseline against nothing and call the result a match.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data
