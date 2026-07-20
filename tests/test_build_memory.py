from __future__ import annotations

import json
from pathlib import Path

from distroforge.cli import main
from distroforge.core.beginner_iso import prepare_beginner_iso_path
from distroforge.core.build_memory import (
    BuildAttempt,
    BuildMemory,
    default_corpus_path,
    options_signature,
)
from distroforge.core.project import Project


def _attempt(outcome: str, *, category: str = "", title: str = "", signature: str = "sig") -> BuildAttempt:
    return BuildAttempt(
        timestamp="2026-05-31T00:00:00+00:00",
        project="Demo",
        outcome=outcome,
        options_signature=signature,
        category=category,
        title=title,
    )


def test_default_corpus_path_lives_under_xdg_state(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state-home"))
    assert default_corpus_path() == tmp_path / "state-home" / "distroforge" / "build-memory.jsonl"

    # State, not config: build history belongs under ~/.local/state by default.
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    fallback = default_corpus_path()
    assert fallback.name == "build-memory.jsonl"
    assert fallback.parent.name == "distroforge"
    assert fallback.parent.parent.parts[-2:] == (".local", "state")


def test_options_signature_is_short_stable_and_payload_sensitive() -> None:
    payload = {"name": "Demo", "release": "26.04", "source_mode": "iso"}
    signature = options_signature(payload)
    assert signature == options_signature(dict(reversed(list(payload.items()))))  # key order independent
    assert len(signature) == 12
    assert all(character in "0123456789abcdef" for character in signature)
    assert signature != options_signature({**payload, "source_mode": "starter"})


def test_corpus_records_and_reads_back_each_attempt(tmp_path: Path) -> None:
    memory = BuildMemory(tmp_path / "build-memory.jsonl")
    memory.record(_attempt("completed"))
    memory.record(_attempt("failed", category="squashfs", title="Squashfs failed"))

    attempts = memory.attempts()
    assert [attempt.outcome for attempt in attempts] == ["completed", "failed"]
    assert attempts[1].category == "squashfs"
    assert memory.recent(1) == attempts[-1:]
    # One auditable JSON object per line.
    lines = (tmp_path / "build-memory.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["category"] == "squashfs"


def test_summary_cites_the_dominant_failure_category(tmp_path: Path) -> None:
    memory = BuildMemory(tmp_path / "build-memory.jsonl")
    memory.record(_attempt("completed"))
    for _ in range(3):
        memory.record(_attempt("failed", category="squashfs", title="Squashfs failed"))
    memory.record(_attempt("failed", category="iso-assembly", title="ISO assembly failed"))

    summary = memory.summarize(limit=5)
    assert summary.total == 5
    assert summary.window == 5
    assert summary.failures == 4
    assert summary.by_category == {"squashfs": 3, "iso-assembly": 1}
    assert summary.citation == "3 of your last 5 builds failed at squashfs."
    text = summary.render_text()
    assert "Build memory" in text
    assert summary.citation in text
    assert json.loads(summary.render_json())["citation"] == summary.citation


def test_summary_handles_empty_and_all_succeeded(tmp_path: Path) -> None:
    memory = BuildMemory(tmp_path / "build-memory.jsonl")
    assert memory.summarize().citation == "No builds recorded yet."
    assert memory.summarize().total == 0

    memory.record(_attempt("completed"))
    memory.record(_attempt("completed"))
    assert memory.summarize().citation == "Your last 2 recorded builds all succeeded."


def test_corpus_tolerates_torn_or_hand_edited_lines(tmp_path: Path) -> None:
    path = tmp_path / "build-memory.jsonl"
    path.write_text(
        json.dumps(_attempt("completed").to_dict())
        + "\n{ this is not valid json\n\n"
        + json.dumps(_attempt("failed", category="squashfs").to_dict())
        + "\n",
        encoding="utf-8",
    )
    attempts = BuildMemory(path).attempts()
    assert [attempt.outcome for attempt in attempts] == ["completed", "failed"]


def test_record_never_raises_when_the_corpus_is_unwritable(tmp_path: Path) -> None:
    # The corpus is advisory: a write failure must never break a build. A path that
    # is itself a directory makes the append fail with OSError, which is swallowed.
    blocked = tmp_path / "occupied"
    blocked.mkdir()
    memory = BuildMemory(blocked)
    memory.record(_attempt("completed"))  # must not raise
    assert memory.attempts() == []


def test_beginner_iso_execute_records_a_completed_attempt(tmp_path: Path, monkeypatch) -> None:
    project = Project.create("BeginnerMem", tmp_path / "beginner-mem", "26.04")
    memory = BuildMemory(tmp_path / "corpus.jsonl")

    class SuccessfulOrchestrator:
        def __init__(self, project, runner, options, progress=None) -> None:
            self.options = options

        def run(self) -> None:
            return None

    monkeypatch.setattr("distroforge.core.beginner_iso.BuildOrchestrator", SuccessfulOrchestrator)

    report = prepare_beginner_iso_path(
        project, apply_safe_defaults=True, dry_run=True, execute=True, memory=memory
    )

    assert report.build_status == "completed"
    attempts = memory.attempts()
    assert len(attempts) == 1
    assert attempts[0].outcome == "completed"
    assert attempts[0].category == ""
    assert attempts[0].project == "BeginnerMem"
    assert attempts[0].options_signature == options_signature(project.to_dict())


def test_beginner_iso_failure_records_canonical_category(tmp_path: Path, monkeypatch) -> None:
    project = Project.create("BeginnerFail", tmp_path / "beginner-fail", "26.04")
    memory = BuildMemory(tmp_path / "corpus.jsonl")
    log = tmp_path / "build-commands.jsonl"

    class FailingOrchestrator:
        def __init__(self, project, runner, options, progress=None) -> None:
            self.options = options

        def run(self) -> None:
            log.write_text(
                '{"event":"finish","command":"mksquashfs root filesystem.squashfs","returncode":1}\n',
                encoding="utf-8",
            )
            raise RuntimeError("mksquashfs failed")

    monkeypatch.setattr("distroforge.core.beginner_iso.BuildOrchestrator", FailingOrchestrator)

    report = prepare_beginner_iso_path(
        project,
        apply_safe_defaults=True,
        dry_run=True,
        execute=True,
        command_log_path=log,
        memory=memory,
    )

    assert report.build_status == "failed"
    attempts = memory.attempts()
    assert len(attempts) == 1
    assert attempts[0].outcome == "failed"
    assert attempts[0].category == "squashfs"
    assert attempts[0].title


def test_beginner_iso_without_injected_memory_records_nothing(tmp_path: Path, monkeypatch) -> None:
    # Dependency-injection discipline: with no corpus injected, the build path writes
    # to no corpus at all (so tests on tmp paths never pollute the real home).
    project = Project.create("BeginnerNone", tmp_path / "beginner-none", "26.04")
    untouched = BuildMemory(tmp_path / "untouched.jsonl")

    class SuccessfulOrchestrator:
        def __init__(self, project, runner, options, progress=None) -> None:
            pass

        def run(self) -> None:
            return None

    monkeypatch.setattr("distroforge.core.beginner_iso.BuildOrchestrator", SuccessfulOrchestrator)

    report = prepare_beginner_iso_path(project, apply_safe_defaults=True, dry_run=True, execute=True)

    assert report.build_status == "completed"
    assert not (tmp_path / "untouched.jsonl").exists()
    assert untouched.attempts() == []


def test_cli_forgeadvisor_memory_summarizes_corpus(tmp_path: Path, monkeypatch, capsys) -> None:
    corpus = tmp_path / "corpus.jsonl"
    memory = BuildMemory(corpus)
    memory.record(_attempt("completed"))
    memory.record(_attempt("failed", category="squashfs", title="Squashfs failed"))
    # run_forgeadvisor imports default_corpus_path from the core module at call time.
    monkeypatch.setattr("distroforge.core.build_memory.default_corpus_path", lambda: corpus)

    main(["forgeadvisor", "memory", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["total"] == 2
    assert payload["failures"] == 1
    assert payload["by_category"] == {"squashfs": 1}
    assert "squashfs" in payload["citation"]


def test_cli_beginner_iso_execute_appends_to_corpus(tmp_path: Path, monkeypatch) -> None:
    corpus = tmp_path / "corpus.jsonl"
    project = Project.create("CliMem", tmp_path / "cli-mem", "26.04")

    class SuccessfulOrchestrator:
        def __init__(self, project, runner, options, progress=None) -> None:
            pass

        def run(self) -> None:
            return None

    monkeypatch.setattr("distroforge.core.beginner_iso.BuildOrchestrator", SuccessfulOrchestrator)
    monkeypatch.setattr("distroforge.commands.beginner_iso.default_corpus_path", lambda: corpus)

    main(["beginner-iso", str(project.root), "--apply-safe-defaults", "--dry-run", "--execute"])

    attempts = BuildMemory(corpus).attempts()
    assert len(attempts) == 1
    assert attempts[0].outcome == "completed"
    assert attempts[0].project == "CliMem"


def test_cli_beginner_iso_dry_run_only_records_nothing(tmp_path: Path, monkeypatch) -> None:
    corpus = tmp_path / "corpus.jsonl"
    project = Project.create("CliDry", tmp_path / "cli-dry", "26.04")
    monkeypatch.setattr("distroforge.commands.beginner_iso.default_corpus_path", lambda: corpus)

    main(["beginner-iso", str(project.root), "--apply-safe-defaults", "--dry-run"])

    assert not corpus.exists()


def test_gui_show_build_memory_surfaces_the_corpus(tmp_path: Path, monkeypatch) -> None:
    from distroforge.ui.command_center_page import show_build_memory

    corpus = tmp_path / "corpus.jsonl"
    BuildMemory(corpus).record(_attempt("failed", category="squashfs", title="Squashfs failed"))
    monkeypatch.setattr("distroforge.ui.command_center_page.default_corpus_path", lambda: corpus)

    captured: dict[str, str] = {}

    class _View:
        def setPlainText(self, text: str) -> None:
            captured["text"] = text

    class _Window:
        def __init__(self) -> None:
            self.command_center_view = _View()

        def _log(self, message: str) -> None:
            captured["log"] = message

    show_build_memory(_Window())

    assert "Build memory" in captured["text"]
    assert "squashfs" in captured["text"]
    assert "failed at squashfs" in captured["log"]
