"""Host-owned build-memory corpus.

The advisory agent gets sharper by remembering real builds, not by shipping a
neural network (``docs/advisory-agent.md``). This is the one canonical, local,
host-owned corpus: every recorded build attempt -- success or failure -- is
appended as one auditable JSON line, and failures carry the canonical category
from :mod:`distroforge.core.build_diagnosis`, so the agent can cite "3 of your
last 5 builds failed at squashfs" instead of guessing.

It stays offline and rootless and never raises into the build path. Callers
inject a :class:`BuildMemory` the way they inject ``CommandRunner`` or
``FileSystemOps``; :func:`default_corpus_path` is resolved only when the
production CLI/GUI wires it, so tests run against temp paths and never touch the
real home directory.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


def default_corpus_path() -> Path:
    """The host-owned corpus file, under the XDG *state* base (build history)."""
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "distroforge" / "build-memory.jsonl"


def options_signature(payload: dict[str, object]) -> str:
    """A short, stable digest grouping similar builds without storing raw config."""
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]


@dataclass(frozen=True)
class BuildAttempt:
    timestamp: str  # UTC ISO-8601
    project: str  # project name (auditable; not the absolute path)
    outcome: str  # "completed" | "failed" | "blocked" | ...
    options_signature: str
    category: str = ""  # canonical diagnosis code; "" when not a failure
    title: str = ""  # human-readable diagnosis title; "" when not a failure

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "project": self.project,
            "outcome": self.outcome,
            "options_signature": self.options_signature,
            "category": self.category,
            "title": self.title,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> BuildAttempt:
        return cls(
            str(data.get("timestamp", "")),
            str(data.get("project", "")),
            str(data.get("outcome", "")),
            str(data.get("options_signature", "")),
            str(data.get("category", "")),
            str(data.get("title", "")),
        )


@dataclass(frozen=True)
class BuildMemorySummary:
    total: int  # attempts in the whole corpus
    window: int  # attempts this summary covers (the recent slice)
    failures: int  # failures within the window
    by_outcome: dict[str, int]
    by_category: dict[str, int]
    citation: str  # e.g. "3 of your last 5 builds failed at squashfs."

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "window": self.window,
            "failures": self.failures,
            "by_outcome": self.by_outcome,
            "by_category": self.by_category,
            "citation": self.citation,
        }

    def render_text(self) -> str:
        lines = [
            "Build memory",
            self.citation,
            f"Recorded attempts: {self.total} (showing last {self.window})",
        ]
        if self.by_outcome:
            lines.append("By outcome: " + ", ".join(f"{key}={value}" for key, value in sorted(self.by_outcome.items())))
        if self.by_category:
            lines.append("Failure categories: " + ", ".join(f"{key}={value}" for key, value in sorted(self.by_category.items())))
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class BuildMemory:
    """Append-only reader/writer over one host-owned corpus file."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def record(self, attempt: BuildAttempt) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(attempt.to_dict(), sort_keys=True) + "\n")
        except OSError:
            # The corpus is advisory: a write failure must never break a build.
            pass

    def attempts(self) -> list[BuildAttempt]:
        try:
            text = self._path.read_text(encoding="utf-8")
        except OSError:
            return []
        result: list[BuildAttempt] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except ValueError:
                continue  # tolerate a torn or hand-edited line
            if isinstance(data, dict):
                result.append(BuildAttempt.from_dict(data))
        return result

    def recent(self, limit: int) -> list[BuildAttempt]:
        attempts = self.attempts()
        return attempts[-limit:] if limit and limit > 0 else attempts

    def summarize(self, limit: int = 5) -> BuildMemorySummary:
        attempts = self.attempts()
        window = attempts[-limit:] if limit and limit > 0 else attempts
        failures = [attempt for attempt in window if attempt.outcome == "failed"]
        by_category = Counter(attempt.category for attempt in failures if attempt.category)
        return BuildMemorySummary(
            total=len(attempts),
            window=len(window),
            failures=len(failures),
            by_outcome=dict(Counter(attempt.outcome for attempt in window)),
            by_category=dict(by_category),
            citation=_citation(len(attempts), len(window), failures, by_category),
        )


def _citation(total: int, window: int, failures: list[BuildAttempt], by_category: Counter[str]) -> str:
    if total == 0:
        return "No builds recorded yet."
    plural = "" if window == 1 else "s"
    if not failures:
        return f"Your last {window} recorded build{plural} all succeeded."
    if by_category:
        category, count = by_category.most_common(1)[0]
        return f"{count} of your last {window} builds failed at {category}."
    return f"{len(failures)} of your last {window} builds failed."
