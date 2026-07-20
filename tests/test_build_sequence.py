from __future__ import annotations

import pytest

from distroforge.core.build import BuildOptions, BuildOrchestrator, BuildProgress
from distroforge.core.build_phases import BuildPhase
from distroforge.core.build_sequence import build_phase_sequence, total_weight
from distroforge.core.command import CommandRunner
from distroforge.core.project import Project

_MODES = ("iso", "bootstrap")
_PREVIEW = (False, True)


def _project(tmp_path, mode: str, preview: bool) -> Project:
    project = Project.create("SeqParity", tmp_path / f"{mode}-{preview}", "26.04")
    project.source_mode = mode
    if mode == "iso":
        src = tmp_path / f"source-{preview}.iso"
        src.write_bytes(b"\x00" * 16)
        project.source_iso = src
    return project


def _rich_options(preview: bool) -> BuildOptions:
    options = BuildOptions(run_preview=preview)
    for name in ("snapshots", "reproducible", "size_analysis", "vuln_scan",
                 "bootcheck", "qemu_screenshot", "prebuild_vm"):
        getattr(options, name).enabled = True
    options.kernel_module.enabled = True
    options.kernel_module.module_subdir = "drivers/probe"
    options.drivers.auto = True
    return options


def _emit(project: Project, options: BuildOptions) -> list[BuildProgress]:
    runner = CommandRunner(dry_run=True)
    events: list[BuildProgress] = []
    BuildOrchestrator(project, runner, options, progress=events.append).run()
    return events


@pytest.mark.parametrize("mode", _MODES)
@pytest.mark.parametrize("preview", _PREVIEW)
def test_plan_is_derived_from_canonical_sequence(tmp_path, mode: str, preview: bool) -> None:
    options = BuildOptions(run_preview=preview)
    orch = BuildOrchestrator(_project(tmp_path, mode, preview), CommandRunner(dry_run=True), options)
    sequence = build_phase_sequence(source_mode=mode, run_preview=preview)
    assert [(s.phase, s.title, s.detail) for s in orch.plan()] == [
        (s.phase, s.title, s.detail) for s in sequence
    ]


@pytest.mark.parametrize("mode", _MODES)
@pytest.mark.parametrize("preview", _PREVIEW)
def test_run_emits_exactly_the_planned_sequence(tmp_path, mode: str, preview: bool) -> None:
    # The P1 regression: plan() length, the emitted-step count and the canonical
    # sequence are one and the same. Before the single-source-of-truth refactor,
    # plan() under-counted run()'s emissions (missing the debrand BRANDING step and
    # two of the three rollback SNAPSHOT points).
    options = BuildOptions(run_preview=preview)
    project = _project(tmp_path, mode, preview)
    orch = BuildOrchestrator(project, CommandRunner(dry_run=True), options)
    planned = orch.plan()
    events = _emit(_project(tmp_path, mode, preview), options)
    step_entries = [e for e in events if e.phase_fraction == 0.0]
    assert len(step_entries) == len(planned)
    assert [(e.step.phase, e.step.title) for e in step_entries] == [
        (s.phase, s.title) for s in planned
    ]


@pytest.mark.parametrize("mode", _MODES)
def test_sequence_is_independent_of_optional_features(tmp_path, mode: str) -> None:
    # Every orch._step() fires unconditionally, so toggling optional phases must not
    # change which steps are emitted -- only their internal behavior.
    def extract(events: list[BuildProgress]) -> list[tuple[BuildPhase, str]]:
        return [(e.step.phase, e.step.title) for e in events if e.phase_fraction == 0.0]

    plain = _emit(_project(tmp_path, mode, False), BuildOptions())
    rich = _emit(_project(tmp_path, mode, False), _rich_options(False))
    assert extract(plain) == extract(rich)


def test_guard_raises_on_phase_title_drift(tmp_path) -> None:
    orch = BuildOrchestrator(_project(tmp_path, "bootstrap", False), CommandRunner(dry_run=True))
    with pytest.raises(AssertionError, match="build sequence drift"):
        orch._step(BuildPhase.VALIDATE, "Not the planned title", "x")


def test_guard_raises_when_more_steps_than_planned(tmp_path) -> None:
    orch = BuildOrchestrator(_project(tmp_path, "bootstrap", False), CommandRunner(dry_run=True))
    for planned in orch.plan():
        orch._step(planned.phase, planned.title, planned.detail)
    with pytest.raises(AssertionError, match="more steps than planned"):
        orch._step(BuildPhase.PREVIEW, "Preview ISO", "x")


@pytest.mark.parametrize("mode", _MODES)
@pytest.mark.parametrize("preview", _PREVIEW)
def test_progress_indices_and_totals(tmp_path, mode: str, preview: bool) -> None:
    options = BuildOptions(run_preview=preview)
    events = _emit(_project(tmp_path, mode, preview), options)
    sequence = build_phase_sequence(source_mode=mode, run_preview=preview)
    step_entries = [e for e in events if e.phase_fraction == 0.0]
    assert [e.index for e in step_entries] == list(range(1, len(sequence) + 1))
    assert all(e.total == len(sequence) for e in step_entries)


@pytest.mark.parametrize("mode", _MODES)
@pytest.mark.parametrize("preview", _PREVIEW)
def test_fraction_is_weighted_monotonic_and_band_aligned(tmp_path, mode: str, preview: bool) -> None:
    options = BuildOptions(run_preview=preview)
    events = _emit(_project(tmp_path, mode, preview), options)
    sequence = build_phase_sequence(source_mode=mode, run_preview=preview)
    total = total_weight(sequence)

    fractions = [e.fraction for e in events]
    assert fractions[0] == 0.0
    assert all(later >= earlier for earlier, later in zip(fractions, fractions[1:], strict=False))
    assert all(0.0 <= f <= 1.0 for f in fractions)

    # Each step opens its band at the cumulative weight of every prior step.
    expected = []
    cumulative = 0.0
    for step in sequence:
        expected.append(cumulative / total)
        cumulative += step.weight
    step_entries = [e for e in events if e.phase_fraction == 0.0]
    assert [pytest.approx(e.fraction) for e in step_entries] == expected
    assert cumulative == pytest.approx(total)


# Golden snapshot for the iso/no-preview path -- the mode whose plan() once
# under-counted run() (47 planned vs 50 emitted). Pinning the per-mille band-start
# fraction of every step locks both the step set (P1) and the phase weights (P2):
# any weight edit or added/removed step fails here and must be updated deliberately.
# Per-mille matches the GUI's 0..1000 progress-bar scale.
_ISO_NO_PREVIEW_GOLDEN = (
    (1, 0, "validate", "Validate project"),
    (2, 6, "consistency", "Check remix consistency"),
    (3, 12, "policy", "Apply beginner-safe policy"),
    (4, 19, "compatibility", "Check release compatibility"),
    (5, 25, "import_scripts", "Import legacy scripts"),
    (6, 31, "diff_preview", "Preview changes"),
    (7, 37, "prepare", "Prepare workspace"),
    (8, 43, "extract_iso", "Extract ISO"),
    (9, 93, "unpack_filesystem", "Unpack live filesystem"),
    (10, 185, "branding", "Debrand source identity"),
    (11, 198, "configure_apt", "Configure repositories"),
    (12, 210, "apt_cache", "Configure apt cache"),
    (13, 216, "ppa", "Configure verified PPAs"),
    (14, 228, "release_track", "Configure release track"),
    (15, 235, "system_sync", "Sync system packages"),
    (16, 259, "autodrivers", "Auto-install drivers"),
    (17, 278, "apply_packages", "Apply package plan"),
    (18, 401, "desktop_source", "Build desktop from source"),
    (19, 438, "install_snaps", "Install snaps"),
    (20, 463, "size_analysis", "Analyze image size"),
    (21, 469, "vuln_scan", "Scan packages for known CVEs"),
    (22, 475, "snapshot", "Create rollback snapshot"),
    (23, 494, "customize_system", "Apply ISO personalization"),
    (24, 506, "branding", "Apply branding"),
    (25, 519, "users", "Configure users and groups"),
    (26, 525, "systemd", "Configure systemd services"),
    (27, 531, "network", "Configure network"),
    (28, 537, "kiosk", "Configure kiosk mode"),
    (29, 543, "oem", "Configure OEM mode"),
    (30, 549, "snapshot", "Create rollback snapshot"),
    (31, 568, "kernel_module", "Build kernel payload"),
    (32, 599, "secure_boot", "Secure Boot workflow"),
    (33, 611, "reproducible", "Apply reproducible build hints"),
    (34, 617, "run_hooks", "Run customization hooks"),
    (35, 630, "sanitize_target", "Sanitize target"),
    (36, 648, "snapshot", "Create rollback snapshot"),
    (37, 667, "health", "Beginner-safe health report"),
    (38, 673, "autoinstall", "Generate autoinstall"),
    (39, 679, "seeds", "Write seeds"),
    (40, 685, "update_metadata", "Update ISO metadata"),
    (41, 698, "repack_filesystem", "Repack live filesystem"),
    (42, 809, "update_checksums", "Update ISO checksums"),
    (43, 821, "rebuild_iso", "Rebuild ISO"),
    (44, 883, "prebuild_vm", "Run prebuild VM lab"),
    (45, 907, "release_artifacts", "Write release artifacts"),
    (46, 920, "bootcheck", "Boot smoke test"),
    (47, 944, "qemu_screenshot", "Capture QEMU screenshot"),
    (48, 957, "provenance", "Write SBOM/provenance"),
    (49, 963, "html_report", "Write HTML report"),
    (50, 969, "qa_matrix", "Run QA boot matrix"),
)


def test_iso_no_preview_weighted_fraction_golden(tmp_path) -> None:
    events = _emit(_project(tmp_path, "iso", False), BuildOptions(run_preview=False))
    step_entries = [e for e in events if e.phase_fraction == 0.0]
    observed = tuple(
        (e.index, round(e.fraction * 1000), e.step.phase.value, e.step.title)
        for e in step_entries
    )
    assert observed == _ISO_NO_PREVIEW_GOLDEN
