from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("XDG_CONFIG_HOME", tempfile.mkdtemp())

from distroforge.ai.backend import (  # noqa: E402
    AdvisorContext,
    LlamaBackend,
    OfflineBackend,
    OllamaBackend,
    available_backends,
    backend_names,
    select_backend,
)
from distroforge.ai.forgeadvisor import ForgeAdvisor  # noqa: E402
from distroforge.cli import build_parser, main  # noqa: E402
from distroforge.core.build_memory import BuildAttempt, BuildMemory  # noqa: E402


def _context(**overrides) -> AdvisorContext:
    base: dict[str, object] = {
        "title": "t",
        "verdict": "review",
        "findings": ("squashfs: Squashfs failed",),
        "corpus_citation": "",
    }
    base.update(overrides)
    return AdvisorContext(**base)  # type: ignore[arg-type]


def _record_failures(memory: BuildMemory, count: int) -> None:
    for _ in range(count):
        memory.record(
            BuildAttempt(
                timestamp="2026-05-31T00:00:00+00:00",
                project="Demo",
                outcome="failed",
                options_signature="sig",
                category="squashfs",
                title="Squashfs failed",
            )
        )


def test_offline_backend_is_always_available_and_deterministic() -> None:
    backend = OfflineBackend()
    assert backend.name == "offline"
    assert backend.available() is True
    status = backend.status()
    assert status.available and status.name == "offline"
    context = _context()
    first = backend.narrate(context)
    assert first is not None
    assert first == backend.narrate(context)  # deterministic; no model, no randomness
    assert "review" in first


def test_backend_registry_lists_offline_first() -> None:
    assert backend_names() == ["offline", "llama", "ollama"]
    assert [backend.name for backend in available_backends()] == ["offline", "llama", "ollama"]


def test_select_backend_default_and_unknown_fall_back_to_offline() -> None:
    assert select_backend(None).name == "offline"
    assert select_backend("offline").name == "offline"
    assert select_backend("does-not-exist").name == "offline"
    assert select_backend("llama").name == "llama"
    assert select_backend("ollama").name == "ollama"


def test_shell_backend_degrades_when_binary_is_missing(monkeypatch) -> None:
    monkeypatch.setattr("distroforge.ai.backend.shutil.which", lambda _binary: None)
    backend = OllamaBackend()
    assert backend.available() is False
    assert backend.status().available is False
    assert backend.narrate(_context()) is None


def test_shell_backend_degrades_on_subprocess_failure(monkeypatch) -> None:
    monkeypatch.setattr("distroforge.ai.backend.shutil.which", lambda _binary: "/usr/bin/ollama")

    def _boom(*_args, **_kwargs):
        raise OSError("no such process")

    monkeypatch.setattr("distroforge.ai.backend.subprocess.run", _boom)
    assert OllamaBackend().narrate(_context()) is None


def test_shell_backend_returns_stripped_stdout_when_available(monkeypatch) -> None:
    monkeypatch.setattr("distroforge.ai.backend.shutil.which", lambda _binary: "/usr/bin/ollama")

    def _run(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="  narrated text \n", stderr="")

    monkeypatch.setattr("distroforge.ai.backend.subprocess.run", _run)
    assert OllamaBackend().narrate(_context()) == "narrated text"


def test_llama_backend_needs_a_model_even_when_installed(monkeypatch) -> None:
    monkeypatch.setattr("distroforge.ai.backend.shutil.which", lambda _binary: "/usr/bin/llama-cli")
    monkeypatch.delenv("DISTROFORGE_LLAMA_MODEL", raising=False)
    backend = LlamaBackend()
    assert backend.available() is True  # the binary is present...
    assert backend.narrate(_context()) is None  # ...but with no model it degrades


def test_forgeadvisor_grounds_explanations_in_the_corpus(tmp_path) -> None:
    memory = BuildMemory(tmp_path / "corpus.jsonl")
    _record_failures(memory, 3)
    citation = memory.summarize().citation
    assert "squashfs" in citation

    log = tmp_path / "build.log"
    log.write_text("nothing notable here\n", encoding="utf-8")
    report = ForgeAdvisor(memory=memory).explain_log(log)

    assert [note for note in report.notes if note.startswith("Build memory:")] == [
        f"Build memory: {citation}"
    ]
    assert report.backend == "offline"
    assert any(note.startswith("Narrative (offline):") for note in report.notes)


def test_forgeadvisor_without_memory_adds_no_corpus_note(tmp_path) -> None:
    log = tmp_path / "build.log"
    log.write_text("nothing notable here\n", encoding="utf-8")
    report = ForgeAdvisor().explain_log(log)
    assert not any(note.startswith("Build memory:") for note in report.notes)
    assert report.backend == "offline"


def test_forgeadvisor_falls_back_to_offline_when_backend_cannot_narrate(tmp_path) -> None:
    class _SilentLlama:
        name = "llama"

        def narrate(self, _context) -> None:
            return None

    log = tmp_path / "build.log"
    log.write_text("nothing notable\n", encoding="utf-8")
    report = ForgeAdvisor(backend=_SilentLlama()).explain_log(log)

    assert report.backend == "offline"
    assert any("fell back to offline" in note for note in report.notes)
    assert any(note.startswith("Narrative (offline):") for note in report.notes)


def test_forgeadvisor_doctor_reports_each_backend_and_active() -> None:
    report = ForgeAdvisor().doctor()
    assert report.backend == "offline"
    assert {finding.code for finding in report.findings} == {
        "backend-offline",
        "backend-llama",
        "backend-ollama",
    }
    assert any(note == "Active backend: offline." for note in report.notes)


def test_cli_forgeadvisor_doctor_ai_backend_offline_json(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "distroforge.core.build_memory.default_corpus_path", lambda: tmp_path / "corpus.jsonl"
    )
    main(["forgeadvisor", "doctor-ai", "--backend", "offline", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["backend"] == "offline"
    codes = {finding["code"] for finding in payload["findings"]}
    assert {"backend-offline", "backend-llama", "backend-ollama"} <= codes


def test_cli_forgeadvisor_rejects_unknown_backend() -> None:
    with pytest.raises(SystemExit):
        main(["forgeadvisor", "doctor-ai", "--backend", "bogus"])


def test_cli_backend_choices_match_registry() -> None:
    parser = build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    forge_sub = next(
        a for a in sub.choices["forgeadvisor"]._actions if isinstance(a, argparse._SubParsersAction)
    )
    for name in (
        "explain-log",
        "triage-log",
        "explain-evidence",
        "fix-plan",
        "review-definition",
        "search-local",
        "copilot",
        "review-build",
        "propose-fixes",
        "doctor-ai",
    ):
        backend_action = next(a for a in forge_sub.choices[name]._actions if a.dest == "backend")
        assert list(backend_action.choices) == backend_names()
        assert backend_action.default == "offline"


@pytest.fixture(scope="module")
def qt_app():
    from distroforge.ui.qt import QApplication

    return QApplication.instance() or QApplication([])


def test_gui_maintainer_backend_combo_matches_registry(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    combo = window.advisor_backend_combo
    data = [combo.itemData(i) for i in range(combo.count())]
    assert data == backend_names()
