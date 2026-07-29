"""Offline commit-subject policy shared by Git history and ``commit-msg`` gates."""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from pathlib import Path

COMMIT_TYPES = (
    "build",
    "chore",
    "ci",
    "docs",
    "feat",
    "fix",
    "perf",
    "refactor",
    "revert",
    "style",
    "test",
)
SUBJECT_PATTERN = re.compile(
    rf"^({'|'.join(COMMIT_TYPES)})(\([a-z0-9][a-z0-9./_-]*\))?!?: \S"
)


def subject_is_conforming(subject: str) -> bool:
    """Return whether ``subject`` carries one admitted Conventional Commits type."""

    return bool(SUBJECT_PATTERN.match(subject))


def _message_subject(path: Path) -> str:
    try:
        message = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read commit message {path}: {exc}") from exc
    lines = message.splitlines()
    return lines[0] if lines else ""


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print("usage: python3 -m distroforge.core.commit_subject COMMIT_EDITMSG", file=sys.stderr)
        return 2
    try:
        subject = _message_subject(Path(arguments[0]))
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    if subject_is_conforming(subject):
        return 0
    admitted = ", ".join(f"{value}:" for value in COMMIT_TYPES)
    print(
        f"commit subject {subject!r} has no admitted type; expected one of: {admitted}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
