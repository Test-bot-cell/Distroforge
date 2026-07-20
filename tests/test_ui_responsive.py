from __future__ import annotations

import os
from pathlib import Path

import pytest

from distroforge.ui.qt import QApplication, QLabel, QScrollArea, QSize, QWidget
from distroforge.ui.widgets import ResponsiveRow

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text()


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    return QApplication.instance() or QApplication([])


class _FixedWidget(QWidget):
    """A child whose width hints are deterministic, independent of font/style."""

    def __init__(self, width: int) -> None:
        super().__init__()
        self._w = width

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(self._w, 20)

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        return QSize(self._w, 20)


def test_gui_responsive_guardrails_are_wired() -> None:
    main = _read("distroforge/ui/main_window.py")
    widgets = _read("distroforge/ui/widgets.py")
    theme = _read("distroforge/ui/theme.py")
    app = _read("distroforge/ui/app.py")

    assert "def resizeEvent" in main
    assert "_apply_responsive_shell" in main
    assert "_rail_width_compact" in main
    assert "_rail_width_expanded" in main
    assert "_scroll_page(page)" in main
    assert "QFormLayout()" not in main
    assert "QHBoxLayout()" not in main

    assert "class ResponsiveRow" in widgets
    assert "QFormLayout.RowWrapPolicy.WrapLongRows" in widgets
    assert "Qt.ScrollBarPolicy.ScrollBarAsNeeded" in widgets
    assert "def minimumSizeHint" in widgets
    assert "def tame_combo" in widgets

    assert "app.palette()" in theme
    # Autonomous GNOME-palette identity: the accent and status hues come from the
    # canonical palette module, not a per-desktop value, and never the Ubuntu/
    # Canonical accent. Only the light/dark scheme still follows the host palette.
    assert "import palette" in theme
    assert "palette.PRIMARY" in theme
    assert "#e95420" not in theme

    assert "primaryScreen()" in app
    assert "availableGeometry()" in app
    assert "window.resize(1280, 820)" not in app


def test_prominent_labels_are_constrained() -> None:
    widgets = _read("distroforge/ui/widgets.py")
    theme = _read("distroforge/ui/theme.py")

    assert "class ElidingLabel" in widgets
    assert "elidedText" in widgets
    assert "QSizePolicy.Policy.Ignored" in widgets
    assert "value.setWordWrap(False)" in widgets
    assert "font-size: 15pt" not in theme
    assert "font-size: 18pt" not in theme


def test_identity_fields_offer_common_choices() -> None:
    main = _read("distroforge/ui/main_window.py")
    window_widgets = _read("distroforge/ui/window_widgets.py")

    assert "LOCALE_CHOICES" in window_widgets
    assert "TIMEZONE_CHOICES" in window_widgets
    assert "KEYBOARD_CHOICES" in window_widgets
    assert "window.locale_combo = _editable_choice_combo" in window_widgets
    assert "window.timezone_combo = _editable_choice_combo" in window_widgets
    assert "window.keyboard_combo = _editable_choice_combo" in window_widgets
    assert "fr_FR.UTF-8" in window_widgets
    assert "Europe/Paris" in window_widgets
    assert '"fr"' in window_widgets
    assert "custom.locale = _combo_value(self.locale_combo)" in main
    assert "_set_editable_combo_value(self.timezone_combo" in main


def test_output_iso_is_host_selectable_in_gui() -> None:
    main = _read("distroforge/ui/main_window.py")
    advanced = _read("distroforge/ui/advanced_page.py")

    assert '"Output ISO"' in advanced
    assert "self.output_iso_edit" in main
    assert "_browse_output_iso" in main
    assert "getSaveFileName" in main
    assert "Select output ISO on host" in main


def test_advanced_page_offers_plymouth_spinner_url_and_gallery_options() -> None:
    advanced = _read("distroforge/ui/advanced_page.py")

    assert "Plymouth spinner" in advanced
    assert "Import Plymouth spinner from URL" in advanced
    assert "Import Plymouth spinner from Unsplash" in advanced
    assert "browse_spinner_gallery" in advanced
    assert "browse_grub_theme_gallery" in advanced
    assert "Import GRUB theme from URL" in advanced


def test_build_page_iso_button_runs_executing_build_flow() -> None:
    build_page = _read("distroforge/ui/build_page.py")

    assert 'button("ISO Build"' in build_page
    assert "window._run_build(True)" in build_page
    assert "run_iso_build(window.project, window._build_options(), execute=False)" not in build_page


def test_build_guidance_names_user_levels_and_safety_states() -> None:
    main = _read("distroforge/ui/main_window.py")
    guidance = _read("distroforge/ui/build_guidance.py")
    workflows = _read("distroforge/core/workflows.py")
    window_widgets = _read("distroforge/ui/window_widgets.py")

    assert "WORKFLOW_LEVEL_STATUS_TEXT" in window_widgets
    for label in ("Beginner", "Power user", "Maintainer", "Developer"):
        assert label in workflows
    assert "workflow_level_status_text()" in guidance
    assert "SNAPSHOT_STATUS_TEXT" in window_widgets
    assert "privilege_status_text" in main


def test_start_page_is_guided_journey_entrypoint() -> None:
    project_page = _read("distroforge/ui/project_page.py")
    main = _read("distroforge/ui/main_window.py")
    cards = _read("distroforge/ui/journey_cards.py")
    theme = _read("distroforge/ui/theme.py")

    assert "Build Journey" in project_page
    assert "build_start_journey_panel" in project_page
    assert "Open current step" in cards
    assert "Apply current step" in cards
    assert "Prepare beginner ISO path" in cards
    assert "Prepare power user ISO path" in cards
    assert "Build beginner ISO" in cards
    assert "Repair release artifacts" in cards
    assert "Run boot proof" in cards
    assert "Publish bundle" in cards
    assert "prepare_beginner_iso_from_start" in cards
    assert "prepare_poweruser_iso_from_start" in cards
    assert "execute_beginner_iso_from_start" in cards
    assert "repair_beginner_release_artifacts_from_start" in cards
    assert "run_beginner_boot_proof_from_start" in cards
    assert "Run readiness" in cards
    assert "Install missing tools" in _read("distroforge/ui/command_center_page.py")
    assert "install_missing" in _read("distroforge/ui/command_center_page.py")
    assert "explain_beginner_iso_failure" in _read("distroforge/ui/command_center_page.py")
    assert "repair_beginner_iso_release_artifacts" in _read("distroforge/ui/command_center_page.py")
    assert "run_beginner_iso_boot_proof" in _read("distroforge/ui/command_center_page.py")
    assert "create_publish_bundle" in _read("distroforge/ui/command_center_page.py")
    artifacts = _read("distroforge/ui/artifacts_page.py")
    assert "Plan Sign Release" in artifacts
    assert "sign_release_from_artifacts" in artifacts
    assert "release_notes_from_artifacts" in _read("distroforge/ui/artifacts_page.py")
    assert "verify_release_from_artifacts" in _read("distroforge/ui/artifacts_page.py")
    assert "explain_release_from_artifacts" in _read("distroforge/ui/artifacts_page.py")
    assert "publish_drill_from_artifacts" in _read("distroforge/ui/artifacts_page.py")
    assert "promote_drill_from_artifacts" in _read("distroforge/ui/artifacts_page.py")
    assert "compare_drill_from_artifacts" in _read("distroforge/ui/artifacts_page.py")
    assert "release_pipeline_from_artifacts" in _read("distroforge/ui/artifacts_page.py")
    assert "boot_proof_from_artifacts" in _read("distroforge/ui/artifacts_page.py")
    assert "refresh_start_journey_cards" in main
    assert "start the guided build journey" in main
    assert "#JourneyCard" in theme
    assert 'journeyStatus="active"' in theme


def test_gui_action_labels_match_execution_mode() -> None:
    main = _read("distroforge/ui/main_window.py")
    build_page = _read("distroforge/ui/build_page.py")
    command_center = _read("distroforge/ui/command_center_page.py")
    cards = _read("distroforge/ui/journey_cards.py")
    theme = _read("distroforge/ui/theme.py")
    window_widgets = _read("distroforge/ui/window_widgets.py")

    assert "Plan Demo ISO" in build_page
    assert "run_demo_iso(window.project.root, execute=False)" in build_page
    assert "run_beginner_iso_boot_proof(window.project, options, execute=True)" in command_center
    assert "boot_proof_backend_combo" in window_widgets
    assert "refresh_start_journey_cards(self)" in main
    assert "class JourneyCardsGrid" in cards
    assert "JourneyCard" in cards
    assert 'button("Check"' in cards
    assert "check_journey_step" in cards
    assert "JourneyCardCheck" in cards
    assert "journeyStatus" in theme


def test_responsive_row_flows_columns_from_available_width(qt_app) -> None:
    # Column slot = child width (100) + grid spacing (10) = 110.
    row = ResponsiveRow(*[_FixedWidget(100) for _ in range(4)])

    row._relayout(100)  # room for one slot
    assert row._columns == 1
    row._relayout(210)  # room for two
    assert row._columns == 2
    row._relayout(440)  # room for all four
    assert row._columns == 4
    row._relayout(5000)  # never more columns than children
    assert row._columns == 4
    row._relayout(40)  # never collapses below a single column
    assert row._columns == 1


def test_responsive_row_minimum_is_one_column_regardless_of_layout(qt_app) -> None:
    row = ResponsiveRow(*[_FixedWidget(100) for _ in range(4)])

    row._relayout(5000)
    assert row._columns == 4
    # The clamp that lets an enclosing scroll area shrink the page: the row's
    # minimum width stays a single column even while laid out multi-column.
    assert row.minimumSizeHint().width() == 100


def test_every_page_inner_fits_a_narrow_viewport(qt_app) -> None:
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    pages = window._pages
    assert pages.count() == 15

    # Each page is wrapped by scroll_page(); the scroll area's inner widget must
    # report a minimum width small enough that the page always shrinks to fit a
    # narrow viewport rather than clipping its right edge (the GNOME bug). The
    # widest observed inner minimum after the responsive fix is ~414px (Advanced);
    # 700px leaves headroom while still proving no page latches wide.
    offenders = []
    for index in range(pages.count()):
        scroll = pages.widget(index).findChild(QScrollArea)
        if scroll is None:
            continue
        inner = scroll.widget()
        min_w = inner.minimumSizeHint().width()
        if min_w > 700:
            offenders.append((index, min_w))
    assert offenders == []


def test_heavy_action_bars_are_split_into_labelled_groups() -> None:
    widgets = _read("distroforge/ui/widgets.py")
    theme = _read("distroforge/ui/theme.py")

    # The shared captioned-cluster helper and its style hook must exist.
    assert "def button_group" in widgets
    assert "#GroupLabel" in theme

    # Each heavy page splits its flat row into labelled groups (layout only -- the
    # button labels themselves are unchanged and asserted elsewhere).
    assert '"Boot and build proof"' in _read("distroforge/ui/artifacts_page.py")
    assert '"Drills and pipeline"' in _read("distroforge/ui/artifacts_page.py")
    assert '"Plan and check"' in _read("distroforge/ui/build_page.py")
    assert '"Build and run"' in _read("distroforge/ui/build_page.py")
    assert '"Current step"' in _read("distroforge/ui/journey_cards.py")
    assert '"Release and verify"' in _read("distroforge/ui/journey_cards.py")
    assert '"AI advisor"' in _read("distroforge/ui/maintainer_page.py")
    assert '"Build presets"' in _read("distroforge/ui/recipes_page.py")


def _settle(app) -> None:
    # A couple of processEvents passes fully resolve nested layout under the
    # offscreen platform (verified empirically: a single pass already yields
    # faithful geometry). Bounded by construction, so it can never hang the
    # suite -- unlike an unbounded "process until idle" loop.
    for _ in range(3):
        app.processEvents()


def test_no_single_line_label_is_clipped_under_adwaita_metrics(qt_app, monkeypatch) -> None:
    """No non-wrapping label may render text wider than its own frame.

    Adwaita Sans has wider metrics than the prior fallback, which made a plain
    QLabel value like "Ubuntu 26.04 skeleton" overflow (hard-clip, no ellipsis)
    inside the project Source tile. Dynamic single-line labels are ElidingLabel
    now, and stat tiles carry a width floor so typical values show in full; this
    test locks both so the regression cannot return in any page or at any width.
    """
    from distroforge.ui.main_window import MainWindow

    # Neutralize the modal first-run dialog for every MainWindow. This test is the
    # first to pump the shared event loop, so it also drains the 250ms first-run
    # timers queued by windows built in earlier tests (those have
    # _first_run_shown=False); their exec() would block the bounded processEvents
    # passes below forever under offscreen.
    monkeypatch.setattr(MainWindow, "_show_first_run", lambda self: None)

    window = MainWindow()

    # Representative worst-case dynamic content, including the reported case.
    worst = {
        "header_project_label": "/home/ubunturaph/Projects/my-custom-ubuntu-2604-remix",
        "project_label": "my-custom-ubuntu-2604-remix · 26.04 · ready to build",
        "summary_release": "26.04",
        "summary_source": "Ubuntu 26.04 skeleton",
        "summary_packages": "128",
        "summary_desktop": "ubuntu-gnome",
        "source_starter_summary": "Ubuntu 26.04 skeleton — minimal skeleton for the selected release",
        "terminal_status": "Chroot terminal idle",
    }
    for attr, text in worst.items():
        getattr(window, attr).setText(text)

    window.show()
    pages = window._pages

    def page0_inner():
        return pages.widget(0).findChild(QScrollArea).widget()

    # Fidelity guard: the scroll inner must actually track the viewport width
    # across a resize. If it does not (stale layout), the clip sweep below would
    # silently pass on frozen geometry -- so prove the layout responds first.
    window.resize(820, 900)
    pages.setCurrentIndex(0)
    _settle(qt_app)
    narrow_inner = page0_inner().width()
    window.resize(1280, 900)
    pages.setCurrentIndex(0)
    _settle(qt_app)
    wide_inner = page0_inner().width()
    assert wide_inner > narrow_inner, (
        f"layout did not respond to resize (narrow={narrow_inner}, wide={wide_inner}); "
        "the clip sweep would be measuring stale geometry"
    )

    # Sweep every page at narrow/normal/wide viewports for hard clips.
    offenders = []
    for width in (820, 1000, 1280):
        window.resize(width, 900)
        for index in range(pages.count()):
            pages.setCurrentIndex(index)
            _settle(qt_app)
            page = pages.widget(index)
            for lbl in page.findChildren(QLabel):
                if lbl.wordWrap() or not lbl.isVisible():
                    continue
                text = lbl.text()
                if not text:
                    continue
                advance = lbl.fontMetrics().horizontalAdvance(text)
                avail = lbl.contentsRect().width()
                if avail > 0 and advance > avail + 1:
                    offenders.append(
                        (index, width, lbl.objectName() or type(lbl).__name__, text)
                    )
    assert offenders == [], f"clipped labels: {offenders}"

    # Lock the reported case directly: at a normal window the Source stat value
    # is shown in full (not elided), proving the stat-tile width floor keeps the
    # wider Adwaita metrics inside the frame.
    window.resize(1000, 900)
    pages.setCurrentIndex(0)
    _settle(qt_app)
    assert window.summary_source.text() == "Ubuntu 26.04 skeleton"


def test_jargon_fields_carry_explanatory_tooltips() -> None:
    window_widgets = _read("distroforge/ui/window_widgets.py")

    # The misleading literal "devel" default is gone: the field is empty with a
    # placeholder and resolves to the release codename (see _track_suite).
    assert 'devel_suite_edit = QLineEdit("devel")' not in window_widgets
    assert "window.devel_suite_edit.setPlaceholderText(" in window_widgets
    assert "debootstrap alias" in window_widgets

    # Jargon-heavy fields get hover help so beginners are not stranded.
    assert "MOK (Machine Owner Key)" in window_widgets
    assert "OVMF firmware code" in window_widgets
    assert "QMP (QEMU Machine Protocol)" in window_widgets
    assert "APT pin priority" in window_widgets
    assert "livefs (casper) build" in window_widgets
    assert "network-free" in window_widgets
