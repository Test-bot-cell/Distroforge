from __future__ import annotations

import argparse
import json
import os
import tempfile

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("XDG_CONFIG_HOME", tempfile.mkdtemp())

from distroforge.ai.backend import OfflineBackend  # noqa: E402
from distroforge.ai.forgeadvisor import (  # noqa: E402
    AdvisorCitation,
    AdvisorFinding,
    ForgeAdvisor,
    _glossary_terms_in,
)
from distroforge.ai.registers import (  # noqa: E402
    DEFAULT_REGISTER_LEVEL,
    REGISTERS,
    get_register,
    register_keys,
    select_register,
)
from distroforge.cli import build_parser, main  # noqa: E402
from distroforge.core.workflows import LEVEL_KEYS  # noqa: E402


def _squashfs_log(tmp_path) -> object:
    log = tmp_path / "build.log"
    log.write_text("mksquashfs: failed to create squashfs filesystem\n", encoding="utf-8")
    return log


def test_register_vocabulary_is_exactly_the_canonical_levels() -> None:
    # The register set is a projection of the single level source, never a parallel taxonomy.
    assert register_keys() == LEVEL_KEYS
    assert tuple(REGISTERS) == LEVEL_KEYS
    for key, register in REGISTERS.items():
        assert register.level == key
    assert DEFAULT_REGISTER_LEVEL == LEVEL_KEYS[0] == "beginner"


def test_get_register_resolves_and_rejects() -> None:
    assert get_register("developer").voice == "Senior Debian/Canonical"
    assert get_register("beginner").expand_jargon is True
    with pytest.raises(ValueError, match="Unknown advisory register"):
        get_register("not-a-register")


def test_select_register_is_silent_default_and_overridable() -> None:
    assert select_register(None).level == "beginner"
    assert select_register("does-not-exist").level == "beginner"
    assert select_register("maintainer").level == "maintainer"
    assert select_register("developer").voice == "Senior Debian/Canonical"


def test_glossary_terms_only_returns_present_whole_tokens() -> None:
    findings = [
        AdvisorFinding(
            "warning",
            "squashfs",
            "Squashfs packaging issue",
            "The isolated step left the rootfs unreadable.",
            "Check squashfs-tools and rootfs permissions.",
            (AdvisorCitation("build.log", 1, "mksquashfs failed"),),
        )
    ]
    terms = _glossary_terms_in(findings)
    assert "squashfs" in terms
    assert "rootfs" in terms
    # "iso" must not fire inside "isolated"; no ISO term appears in the text.
    assert "iso" not in terms


def test_beginner_register_expands_jargon_and_does_not_push_cli(tmp_path) -> None:
    report = ForgeAdvisor(OfflineBackend(), level="beginner").explain_log(_squashfs_log(tmp_path))
    assert report.register == "Beginner"
    assert any(note.startswith("Plain language - squashfs:") for note in report.notes)
    assert any("you do not need the command line" in note for note in report.notes)
    assert "Register: Beginner" in report.render_text()


def test_developer_register_applies_debian_lens_without_jargon_expansion(tmp_path) -> None:
    report = ForgeAdvisor(OfflineBackend(), level="developer").explain_log(_squashfs_log(tmp_path))
    assert report.register == "Senior Debian/Canonical"
    assert not any(note.startswith("Plain language - ") for note in report.notes)
    assert any("Debian/Canonical lens" in note for note in report.notes)
    assert "Register: Senior Debian/Canonical" in report.render_text()


def test_register_defaults_to_beginner_when_unspecified(tmp_path) -> None:
    log = tmp_path / "quiet.log"
    log.write_text("nothing notable here\n", encoding="utf-8")
    report = ForgeAdvisor().explain_log(log)
    assert report.register == "Beginner"
    # No findings means no jargon to expand, but the register voice is still stamped.
    assert not any(note.startswith("Plain language - ") for note in report.notes)


def test_report_serializes_the_active_register(tmp_path) -> None:
    report = ForgeAdvisor(OfflineBackend(), level="maintainer").explain_log(_squashfs_log(tmp_path))
    payload = json.loads(report.render_json())
    assert payload["register"] == "Maintainer"


def test_doctor_reports_active_register() -> None:
    report = ForgeAdvisor(level="developer").doctor()
    assert report.register == "Senior Debian/Canonical"
    assert any(note == "Active register: Senior Debian/Canonical." for note in report.notes)


def test_cli_register_choices_match_registry() -> None:
    parser = build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    forge_sub = next(
        a for a in sub.choices["forgeadvisor"]._actions if isinstance(a, argparse._SubParsersAction)
    )
    for name in ("explain-log", "review-build", "doctor-ai"):
        register_action = next(a for a in forge_sub.choices[name]._actions if a.dest == "register")
        assert list(register_action.choices) == list(register_keys())
        assert register_action.default is None


def test_cli_forgeadvisor_register_override_json(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "distroforge.core.build_memory.default_corpus_path", lambda: tmp_path / "corpus.jsonl"
    )
    main(["forgeadvisor", "doctor-ai", "--register", "developer", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["register"] == "Senior Debian/Canonical"


@pytest.fixture(scope="module")
def qt_app():
    from distroforge.ui.qt import QApplication

    return QApplication.instance() or QApplication([])


def test_gui_advisor_register_combo_matches_registry(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    combo = window.advisor_register_combo
    data = [combo.itemData(i) for i in range(combo.count())]
    assert data == list(register_keys())
