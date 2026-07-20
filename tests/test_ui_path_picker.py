from __future__ import annotations

import hashlib
import io
import os
import zipfile
from pathlib import Path

import pytest

from distroforge.ui import path_actions
from distroforge.ui.qt import QLineEdit, QWidget


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from distroforge.ui.qt import QApplication

    return QApplication.instance() or QApplication([])


class _FakeDialog:
    """Stand-in for QFileDialog: returns canned picks and records its args.

    Keeps the test fully offline -- no native dialog, no event loop, no I/O.
    """

    open_result: tuple[str, str] = ("/picked/file.iso", "")
    save_result: tuple[str, str] = ("/picked/out.jsonl", "")
    dir_result: str = "/picked/dir"
    last: dict[str, object] = {}

    @staticmethod
    def getOpenFileName(parent, caption, directory="", filter=""):  # noqa: A002
        _FakeDialog.last = {"mode": "open", "caption": caption, "directory": directory, "filter": filter}
        return _FakeDialog.open_result

    @staticmethod
    def getSaveFileName(parent, caption, directory="", filter=""):  # noqa: A002
        _FakeDialog.last = {"mode": "save", "caption": caption, "directory": directory, "filter": filter}
        return _FakeDialog.save_result

    @staticmethod
    def getExistingDirectory(parent, caption, directory=""):
        _FakeDialog.last = {"mode": "dir", "caption": caption, "directory": directory}
        return _FakeDialog.dir_result


class _FakeInputDialog:
    """Stand-in for QInputDialog: returns one canned text value."""

    last: dict[str, object] = {}
    next_result: tuple[str, bool] = ("", False)

    @staticmethod
    def getText(parent, title, prompt, text=""):  # noqa: A002
        _FakeInputDialog.last = {
            "title": title,
            "prompt": prompt,
            "text": text,
        }
        return _FakeInputDialog.next_result


class _FakeResponse:
    def __init__(self, data: bytes, content_type: str) -> None:
        self._stream = io.BytesIO(data)
        self.headers = {"Content-Type": content_type}

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def close(self) -> None:
        return None


class _FakeMessageBox:
    """Stand-in for QMessageBox.warning."""

    last_warning: dict[str, object] | None = None

    @staticmethod
    def warning(parent, title, text) -> None:  # noqa: A002
        _FakeMessageBox.last_warning = {"title": title, "text": text}


class _FakeBrowser:
    last_open: list[str] = []

    @staticmethod
    def open(url: str) -> None:
        _FakeBrowser.last_open.append(url)


@pytest.fixture
def patched_dialog(monkeypatch):
    monkeypatch.setattr(path_actions, "QFileDialog", _FakeDialog)
    _FakeDialog.last = {}
    return _FakeDialog


@pytest.fixture
def patched_input_dialog(monkeypatch):
    monkeypatch.setattr(path_actions, "QInputDialog", _FakeInputDialog)
    _FakeInputDialog.last = {}
    return _FakeInputDialog


@pytest.fixture
def patched_message_box(monkeypatch):
    monkeypatch.setattr(path_actions, "QMessageBox", _FakeMessageBox)
    _FakeMessageBox.last_warning = None
    return _FakeMessageBox


def _make_fake_urlopen(data: bytes = b"\x89PNG", content_type: str = "image/png"):
    def _fake_urlopen(_request, timeout: int = 20):
        return _FakeResponse(data=data, content_type=content_type)

    return _fake_urlopen


def _fake_grub_theme_archive_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("mytheme/theme.txt", "title-text: \"DistroForge\"")
        zf.writestr("mytheme/something.pf2", "placeholder")
    return buffer.getvalue()


def _fake_grub_theme_archive_no_assets() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("mytheme/theme.txt", "title-text: \"DistroForge\"")
    return buffer.getvalue()


def test_open_mode_fills_field(qt_app, patched_dialog) -> None:
    parent, edit = QWidget(), QLineEdit()
    path_actions.browse_into(parent, edit, title="Pick ISO", file_filter="ISO (*.iso)")
    assert edit.text() == "/picked/file.iso"
    assert patched_dialog.last["mode"] == "open"
    assert patched_dialog.last["filter"] == "ISO (*.iso)"


def test_save_mode_fills_field(qt_app, patched_dialog) -> None:
    parent, edit = QWidget(), QLineEdit()
    path_actions.browse_into(parent, edit, title="Pick log", mode="save", file_filter="JSONL (*.jsonl)")
    assert edit.text() == "/picked/out.jsonl"
    assert patched_dialog.last["mode"] == "save"


def test_dir_mode_fills_field(qt_app, patched_dialog) -> None:
    parent, edit = QWidget(), QLineEdit()
    path_actions.browse_into(parent, edit, title="Pick dir", mode="dir")
    assert edit.text() == "/picked/dir"
    assert patched_dialog.last["mode"] == "dir"


def test_cancel_leaves_field_unchanged(qt_app, patched_dialog) -> None:
    patched_dialog.open_result = ("", "")
    parent, edit = QWidget(), QLineEdit()
    edit.setText("/already/typed/path")
    path_actions.browse_into(parent, edit, title="Pick", file_filter="*")
    assert edit.text() == "/already/typed/path"
    patched_dialog.open_result = ("/picked/file.iso", "")


def test_dialog_opens_at_current_text(qt_app, patched_dialog) -> None:
    parent, edit = QWidget(), QLineEdit()
    edit.setText("/seed/here")
    path_actions.browse_into(parent, edit, title="Pick", mode="dir")
    assert patched_dialog.last["directory"] == "/seed/here"


def test_picker_is_a_select_button_wired_to_browse(qt_app, patched_dialog) -> None:
    parent, edit = QWidget(), QLineEdit()
    btn = path_actions.picker(parent, edit, title="Pick ISO", file_filter="ISO (*.iso)")
    # Canonical, uniform label across every path field (recognition over recall).
    assert btn.text() == "Select"
    btn.click()
    assert edit.text() == "/picked/file.iso"


def test_picker_save_mode_defaults_to_save_button(qt_app, patched_dialog) -> None:
    parent, edit = QWidget(), QLineEdit()
    btn = path_actions.picker(parent, edit, title="Pick log", mode="save")
    assert btn.text() == "Select"
    btn.click()
    assert edit.text() == "/picked/out.jsonl"


def test_image_url_picker_saves_cached_image(qt_app, patched_input_dialog, patched_message_box, monkeypatch, tmp_path) -> None:
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(path_actions, "_project_cache_dir", lambda _window: cache_dir)
    monkeypatch.setattr(path_actions, "urlopen", _make_fake_urlopen())
    _FakeInputDialog.next_result = ("https://example.com/test.png", True)
    parent, edit = QWidget(), QLineEdit()
    path_actions.browse_image_from_url(
        parent,
        edit,
        title="Import image",
        prompt="Image URL:",
    )
    assert edit.text().endswith(".png")
    assert cache_dir in Path(edit.text()).parents


def test_image_url_picker_keeps_field_when_import_fails(qt_app, patched_input_dialog, patched_message_box, monkeypatch) -> None:
    monkeypatch.setattr(path_actions, "_project_cache_dir", lambda _window: Path("/tmp"))
    monkeypatch.setattr(path_actions, "urlopen", _make_fake_urlopen(content_type="text/html"))
    _FakeInputDialog.next_result = ("https://example.com/not-an-image", True)
    parent, edit = QWidget(), QLineEdit()
    edit.setText("/already/had/a/value")
    path_actions.browse_image_from_url(
        parent,
        edit,
        title="Import image",
        prompt="Image URL:",
    )
    assert edit.text() == "/already/had/a/value"
    assert _FakeMessageBox.last_warning is not None


def test_unsplash_picker_opens_site_then_imports_url(
    qt_app,
    patched_input_dialog,
    patched_message_box,
    monkeypatch,
    tmp_path,
) -> None:
    cache_dir = tmp_path / "cache"
    _FakeBrowser.last_open = []
    monkeypatch.setattr(path_actions, "_project_cache_dir", lambda _window: cache_dir)
    monkeypatch.setattr(path_actions, "urlopen", _make_fake_urlopen(content_type="image/jpeg"))
    monkeypatch.setattr(path_actions, "webbrowser", _FakeBrowser)
    _FakeInputDialog.next_result = ("https://example.com/wallpaper.jpg", True)
    edit = QLineEdit()
    button = path_actions.unsplash_picker(
        QWidget(),
        edit,
        title="Import from Unsplash",
        prompt="URL",
    )
    button.click()
    assert _FakeBrowser.last_open == [path_actions._UNSPLASH_SEARCH_URL]
    assert edit.text().endswith(".jpg")


def test_grub_theme_url_import_unpacks_to_theme_root(qt_app, patched_input_dialog, patched_message_box, monkeypatch, tmp_path) -> None:
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(path_actions, "_project_cache_dir", lambda _window: cache_dir)
    monkeypatch.setattr(path_actions, "urlopen", _make_fake_urlopen(_fake_grub_theme_archive_bytes(), "application/zip"))
    _FakeInputDialog.next_result = ("https://example.com/theme.zip", True)
    edit = QLineEdit("/keep")
    path_actions.browse_grub_theme_from_url(
        QWidget(),
        edit,
        title="Import GRUB theme from URL",
        prompt="URL",
    )
    assert edit.text() != "/keep"
    assert edit.text().endswith("mytheme")
    assert (Path(edit.text()) / "theme.txt").exists()


def test_grub_theme_url_import_prefers_project_theme_dir(qt_app, patched_input_dialog, patched_message_box, monkeypatch, tmp_path) -> None:
    cache_dir = tmp_path / "cache"
    workdir = tmp_path / "project" / "work"
    monkeypatch.setattr(
        path_actions,
        "_project_cache_dir",
        lambda _window: cache_dir,
    )
    monkeypatch.setattr(
        path_actions,
        "urlopen",
        _make_fake_urlopen(_fake_grub_theme_archive_bytes(), "application/zip"),
    )
    _FakeInputDialog.next_result = ("https://example.com/theme.zip", True)
    edit = QLineEdit("/keep")
    window = QWidget()
    window.project = type("Project", (), {"workdir": workdir})()
    path_actions.browse_grub_theme_from_url(
        window,
        edit,
        title="Import GRUB theme from URL",
        prompt="URL",
    )
    digest = hashlib.sha256(b"https://example.com/theme.zip").hexdigest()[:8]
    assert edit.text().endswith(f"distroforge-{digest}")
    assert edit.text().startswith(str(workdir / "assets" / "themes" / "grub"))
    assert (Path(edit.text()) / "theme.txt").exists()


def test_grub_theme_url_keeps_field_when_not_archive(qt_app, patched_input_dialog, patched_message_box, monkeypatch, tmp_path) -> None:
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(path_actions, "_project_cache_dir", lambda _window: cache_dir)
    monkeypatch.setattr(path_actions, "urlopen", _make_fake_urlopen(b"not-an-archive", "text/html"))
    _FakeInputDialog.next_result = ("https://example.com/theme", True)
    edit = QLineEdit("/keep")
    path_actions.browse_grub_theme_from_url(
        QWidget(),
        edit,
        title="Import GRUB theme from URL",
        prompt="URL",
    )
    assert edit.text() == "/keep"
    assert _FakeMessageBox.last_warning is not None


def test_grub_theme_url_rejects_incomplete_theme_payload(
    qt_app,
    patched_input_dialog,
    patched_message_box,
    monkeypatch,
    tmp_path,
) -> None:
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(path_actions, "_project_cache_dir", lambda _window: cache_dir)
    monkeypatch.setattr(
        path_actions,
        "urlopen",
        _make_fake_urlopen(_fake_grub_theme_archive_no_assets(), "application/zip"),
    )
    _FakeInputDialog.next_result = ("https://example.com/incomplete.zip", True)
    edit = QLineEdit("/keep")
    path_actions.browse_grub_theme_from_url(
        QWidget(),
        edit,
        title="Import GRUB theme from URL",
        prompt="URL",
    )
    assert edit.text() == "/keep"
    assert _FakeMessageBox.last_warning is not None


def test_clear_field_button_resets_text(qt_app) -> None:
    edit = QLineEdit("/some/existing/value")
    button = path_actions.clear_field_button(edit)
    assert button.text() == "None"
    button.click()
    assert edit.text() == ""


def test_plymouth_spinner_gallery_button_opens_spinner_catalog(
    qt_app,
    monkeypatch,
) -> None:
    _FakeBrowser.last_open = []
    monkeypatch.setattr(path_actions, "webbrowser", _FakeBrowser)
    button = path_actions.browse_spinner_gallery(QWidget())
    button.click()
    assert _FakeBrowser.last_open == [path_actions._PLYMOUTH_SPINNER_GALLERY_URL]


def test_grub_theme_gallery_button_opens_theme_catalog(
    qt_app,
    monkeypatch,
) -> None:
    _FakeBrowser.last_open = []
    monkeypatch.setattr(path_actions, "webbrowser", _FakeBrowser)
    button = path_actions.browse_grub_theme_gallery(QWidget())
    button.click()
    assert _FakeBrowser.last_open == [path_actions._GRUB_THEME_GALLERY_URL]
