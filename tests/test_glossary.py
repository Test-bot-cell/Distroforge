from __future__ import annotations

import os
from pathlib import Path

import pytest

from distroforge.core.build import BuildOptions
from distroforge.core.education import GLOSSARY, render_glossary
from distroforge.core.project import Project
from distroforge.core.ux_audit import audit_experience

EXPECTED_TERMS = frozenset(
    {
        "autoinstall",
        "bios",
        "casper",
        "chroot",
        "deb822",
        "debootstrap",
        "dkms",
        "dry-run",
        "gpg",
        "iso",
        "kernel-module",
        "kiosk",
        "live-build",
        "mirror",
        "mok",
        "oem",
        "persona",
        "policy",
        "ppa",
        "provenance",
        "reproducible",
        "rootfs",
        "sanitize",
        "sbom",
        "secure-boot",
        "seed",
        "sha256",
        "snap",
        "snapshot",
        "squashfs",
        "subiquity",
        "transaction",
        "uefi",
    }
)


def test_glossary_covers_the_canonical_vocabulary() -> None:
    assert set(GLOSSARY) == EXPECTED_TERMS


def test_glossary_entries_are_well_formed() -> None:
    for term, definition in GLOSSARY.items():
        assert term == term.strip().lower(), term
        assert definition.strip(), term
        assert definition.rstrip().endswith("."), term


def test_render_glossary_resolves_every_term() -> None:
    for term in GLOSSARY:
        assert render_glossary(term).startswith(f"{term}:")


def test_render_glossary_lists_every_term_sorted() -> None:
    listing = render_glossary()
    keys = [line.split(maxsplit=1)[0] for line in listing.splitlines()]
    assert keys == sorted(GLOSSARY)


def test_render_glossary_rejects_unknown_term() -> None:
    with pytest.raises(KeyError, match="Unknown glossary term"):
        render_glossary("not-a-real-term")


def test_glossary_defines_terms_shown_in_audit_text(tmp_path) -> None:
    # Every domain word DistroForge puts in front of users must have a definition.
    project = Project.create("GlossaryShown", tmp_path / "glossary-shown", "26.04")
    options = BuildOptions()
    options.sanitize.enabled = False
    options.snapshots.enabled = False
    options.release_artifacts.enabled = False
    options.provenance.enabled = False
    options.plugins.plugins_dir = tmp_path / "plugins"
    options.import_scripts.scripts = [tmp_path / "legacy.sh"]
    options.desktop_source.enabled = True
    options.desktop_source.require_sha256 = False
    options.reproducible.enabled = False
    corpus = audit_experience(project, options).render_text().lower()
    shown = {
        "iso",
        "sanitize",
        "snapshot",
        "reproducible",
        "provenance",
        "sbom",
        "uefi",
        "bios",
        "rootfs",
    }
    for term in shown:
        assert term in corpus, f"{term} not shown in audit text"
        assert term in GLOSSARY, f"{term} shown but not defined"


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from distroforge.ui.qt import QApplication

    return QApplication.instance() or QApplication([])


def test_first_run_dialog_exposes_the_glossary(qt_app) -> None:
    from distroforge.ui.first_run import FirstRunDialog

    dialog = FirstRunDialog()
    text = dialog.glossary_view.toPlainText()
    assert text == render_glossary()
    assert "snapshot" in text
    assert GLOSSARY["snapshot"] in text


def test_first_run_source_exposes_glossary() -> None:
    source = Path("distroforge/ui/first_run.py").read_text(encoding="utf-8")
    assert "render_glossary" in source
    assert "glossary_view" in source
