from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .definition import write_definition
from .project import Project


@dataclass(frozen=True)
class HistoryEntry:
    id: str
    timestamp: str
    kind: str
    summary: str
    command: str
    definition: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "kind": self.kind,
            "summary": self.summary,
            "command": self.command,
            "definition": self.definition,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> HistoryEntry:
        definition = data.get("definition", {})
        return cls(
            id=str(data.get("id", "")),
            timestamp=str(data.get("timestamp", "")),
            kind=str(data.get("kind", "")),
            summary=str(data.get("summary", "")),
            command=str(data.get("command", "")),
            definition=definition if isinstance(definition, dict) else {},
        )


def history_path(project: Project) -> Path:
    return project.root / ".distroforge" / "history.jsonl"


def append_history(project: Project, *, kind: str, summary: str, command: str, definition: dict[str, object]) -> HistoryEntry:
    timestamp = datetime.now(UTC).isoformat()
    digest = hashlib.sha256(
        json.dumps({"timestamp": timestamp, "kind": kind, "definition": definition}, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:12]
    entry = HistoryEntry(digest, timestamp, kind, summary, command, definition)
    path = history_path(project)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
    return entry


def list_history(project: Project) -> list[HistoryEntry]:
    path = history_path(project)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries: list[HistoryEntry] = []
    for line in lines:
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if isinstance(data, dict):
            entries.append(HistoryEntry.from_dict(data))
    return entries


def render_history(project: Project, *, json_output: bool = False) -> str:
    entries = list_history(project)
    if json_output:
        return json.dumps({"project": str(project.root), "history": [entry.to_dict() for entry in entries]}, indent=2) + "\n"
    lines = ["DistroForge build history", f"Project: {project.root}"]
    if not entries:
        lines.append("No local history entries yet.")
        return "\n".join(lines) + "\n"
    for entry in entries:
        lines.append(f"- {entry.id} {entry.timestamp} {entry.kind}: {entry.summary}")
        if entry.command:
            lines.append(f"  replay: distroforge history replay {project.root} {entry.id}")
    return "\n".join(lines) + "\n"


def replay_history(project: Project, entry_id: str, *, output: Path | None = None, json_output: bool = False) -> str:
    entries = list_history(project)
    if entry_id == "latest":
        if not entries:
            raise ValueError("No history entries available for replay.")
        entry = entries[-1]
    else:
        entry = next((item for item in entries if item.id == entry_id), None)
    if entry is None:
        known = ", ".join(item.id for item in entries) or "none"
        raise ValueError(f"Unknown history entry {entry_id!r}. Use 'latest' or one of: {known}")
    output = output or project.root / f"replay-{entry.id}.yaml"
    write_definition(entry.definition, output)
    payload = {
        "project": str(project.root),
        "entry": entry.to_dict(),
        "output": str(output),
        "next_command": f"distroforge build {project.root} --definition {output}",
    }
    if json_output:
        return json.dumps(payload, indent=2) + "\n"
    return "\n".join(
        [
            "DistroForge history replay",
            f"Project: {project.root}",
            f"Entry: {entry.id}",
            f"Wrote: {output}",
            "Next:",
            payload["next_command"],
        ]
    ) + "\n"
