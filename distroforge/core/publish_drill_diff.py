from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PublishDrillDiffReport:
    old: Path
    new: Path
    verdict: str
    status_change: str
    gate_change: str
    boot_change: str
    manifest_added: tuple[str, ...]
    manifest_removed: tuple[str, ...]
    manifest_changed: tuple[str, ...]
    signing_changed: tuple[str, ...]
    blockers_added: tuple[str, ...]
    blockers_removed: tuple[str, ...]
    review_added: tuple[str, ...]
    next_commands_added: tuple[str, ...]
    next_commands_removed: tuple[str, ...]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "old": str(self.old),
            "new": str(self.new),
            "verdict": self.verdict,
            "status_change": self.status_change,
            "gate_change": self.gate_change,
            "boot_change": self.boot_change,
            "manifest_added": list(self.manifest_added),
            "manifest_removed": list(self.manifest_removed),
            "manifest_changed": list(self.manifest_changed),
            "signing_changed": list(self.signing_changed),
            "blockers_added": list(self.blockers_added),
            "blockers_removed": list(self.blockers_removed),
            "review_added": list(self.review_added),
            "next_commands_added": list(self.next_commands_added),
            "next_commands_removed": list(self.next_commands_removed),
            "reasons": list(self.reasons),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Publish drill diff",
            f"Old: {self.old}",
            f"New: {self.new}",
            f"Verdict: {self.verdict.upper()}",
            f"Status: {self.status_change}",
            f"Gate: {self.gate_change}",
            f"Boot proof: {self.boot_change}",
            "",
            "Manifest:",
            *([f"- added: {item}" for item in self.manifest_added] or []),
            *([f"- removed: {item}" for item in self.manifest_removed] or []),
            *([f"- changed: {item}" for item in self.manifest_changed] or ["- unchanged"]),
            "",
            "Signing:",
            *([f"- {item}" for item in self.signing_changed] or ["- unchanged"]),
            "",
            "New blockers:",
            *([f"- {item}" for item in self.blockers_added] or ["- none"]),
            "",
            "Reasons:",
            *([f"- {item}" for item in self.reasons] or ["- no material changes"]),
        ]
        return "\n".join(lines)


def diff_publish_drills(old_path: Path, new_path: Path) -> PublishDrillDiffReport:
    old = _read_json(old_path)
    new = _read_json(new_path)
    old_status = str(old.get("status", "unknown"))
    new_status = str(new.get("status", "unknown"))
    old_gate = _gate_status(old)
    new_gate = _gate_status(new)
    old_boot = _boot_level(old)
    new_boot = _boot_level(new)
    old_manifest = _manifest_files(old)
    new_manifest = _manifest_files(new)
    old_blockers = _items(old, "blocked_items")
    new_blockers = _items(new, "blocked_items")
    old_review = _items(old, "review")
    new_review = _items(new, "review")
    old_commands = set(_list(old.get("explanation", {}), "next_commands"))
    new_commands = set(_list(new.get("explanation", {}), "next_commands"))
    added = tuple(sorted(set(new_manifest) - set(old_manifest)))
    removed = tuple(sorted(set(old_manifest) - set(new_manifest)))
    changed = tuple(sorted(name for name in set(old_manifest) & set(new_manifest) if old_manifest[name] != new_manifest[name]))
    signing_changed = _signing_changed(old, new)
    blockers_added = tuple(sorted(new_blockers - old_blockers))
    blockers_removed = tuple(sorted(old_blockers - new_blockers))
    review_added = tuple(sorted(new_review - old_review))
    reasons = _reasons(old_status, new_status, old_gate, new_gate, old_boot, new_boot, removed, changed, blockers_added)
    verdict = _verdict(reasons, old_status, new_status, blockers_removed)
    return PublishDrillDiffReport(
        old_path,
        new_path,
        verdict,
        f"{old_status} -> {new_status}",
        f"{old_gate} -> {new_gate}",
        f"{old_boot} -> {new_boot}",
        added,
        removed,
        changed,
        signing_changed,
        blockers_added,
        blockers_removed,
        review_added,
        tuple(sorted(new_commands - old_commands)),
        tuple(sorted(old_commands - new_commands)),
        tuple(reasons),
    )


def _reasons(old_status: str, new_status: str, old_gate: str, new_gate: str, old_boot: str, new_boot: str, removed: tuple[str, ...], changed: tuple[str, ...], blockers_added: tuple[str, ...]) -> list[str]:
    reasons: list[str] = []
    if _rank_status(new_status) < _rank_status(old_status):
        reasons.append(f"status regressed: {old_status} -> {new_status}")
    if _rank_status(new_gate) < _rank_status(old_gate):
        reasons.append(f"release gate regressed: {old_gate} -> {new_gate}")
    if _rank_boot(new_boot) < _rank_boot(old_boot):
        reasons.append(f"boot proof regressed: {old_boot} -> {new_boot}")
    reasons.extend(f"new blocker: {item}" for item in blockers_added)
    reasons.extend(f"manifest file removed: {item}" for item in removed)
    reasons.extend(f"manifest file changed: {item}" for item in changed)
    return reasons


def _verdict(reasons: list[str], old_status: str, new_status: str, blockers_removed: tuple[str, ...]) -> str:
    if reasons:
        return "regressed"
    if _rank_status(new_status) > _rank_status(old_status) or blockers_removed:
        return "improved"
    return "unchanged"


def _rank_status(status: str) -> int:
    return {"blocked": 0, "review_required": 1, "review": 1, "ready_to_publish": 2, "ready": 2}.get(status, 0)


def _rank_boot(level: str) -> int:
    return {"none": 0, "missing": 0, "structural": 1, "runtime": 2}.get(level, 0)


def _gate_status(data: dict[str, object]) -> str:
    gate = _evidence(data, "release_gate")
    return str(gate.get("status", "unknown"))


def _boot_level(data: dict[str, object]) -> str:
    explanation = data.get("explanation", {})
    boot = explanation.get("boot_proof", {}) if isinstance(explanation, dict) else {}
    return str(boot.get("proof_level", "none")) if isinstance(boot, dict) else "none"


def _manifest_files(data: dict[str, object]) -> dict[str, str]:
    manifest = _evidence(data, "manifest")
    files: dict[str, str] = {}
    for item in manifest.get("files", []):
        if isinstance(item, dict):
            files[str(item.get("name", ""))] = f"{item.get('size')}:{item.get('sha256')}"
    return files


def _signing_changed(old: dict[str, object], new: dict[str, object]) -> tuple[str, ...]:
    changes: list[str] = []
    for key in ("planned", "signed", "skipped"):
        old_values = set(_list(_evidence(old, "signing"), key))
        new_values = set(_list(_evidence(new, "signing"), key))
        if old_values != new_values:
            changes.append(f"{key}: {sorted(old_values)} -> {sorted(new_values)}")
    return tuple(changes)


def _items(data: dict[str, object], key: str) -> set[str]:
    explanation = data.get("explanation", {})
    return set(_list(explanation, key)) if isinstance(explanation, dict) else set()


def _evidence(data: dict[str, object], key: str) -> dict[str, object]:
    evidence = data.get("evidence", {})
    item = evidence.get(key, {}) if isinstance(evidence, dict) else {}
    return item if isinstance(item, dict) else {}


def _list(data: object, key: str) -> list[str]:
    if not isinstance(data, dict):
        return []
    values = data.get(key, [])
    return [str(item) for item in values] if isinstance(values, list) else []


def _read_json(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data
