from __future__ import annotations

from distroforge.core.autoinstall import AutoinstallOptions
from distroforge.core.branding import BrandingOptions
from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.build_phases import PIPELINE_PHASES, BuildPhase
from distroforge.core.command import CommandRunner
from distroforge.core.network import NetworkOptions
from distroforge.core.phase_contracts import (
    PHASE_CONTRACTS,
    PIPELINE_STAGES,
    contract_for,
    privileged_phases,
    render_phase_contracts,
    rollback_phases,
)
from distroforge.core.ppa import PpaOptions, PpaSpec
from distroforge.core.project import Project
from distroforge.core.snaps import SnapOptions, SnapSpec
from distroforge.core.users import UserOptions, UserSpec

_ROLLBACK_DESC = "Create rollback snapshot "


def _rich_options() -> BuildOptions:
    options = BuildOptions(use_sudo=True, run_preview=True)
    for name in ("snapshots", "reproducible", "size_analysis", "vuln_scan",
                 "bootcheck", "qemu_screenshot", "prebuild_vm"):
        getattr(options, name).enabled = True
    options.kernel_module.enabled = True
    options.kernel_module.module_subdir = "drivers/probe"
    options.drivers.auto = True
    options.branding = BrandingOptions(name="Acme OS", pretty_name="Acme OS 26.04")
    options.snaps = SnapOptions([SnapSpec("hello-world", channel="stable", classic=True)])
    options.ppa = PpaOptions(
        [PpaSpec("graphics-drivers", "ppa", "ABCDEF1234567890")],
        auto_fetch_fingerprint=False,
    )
    options.autoinstall = AutoinstallOptions(enabled=True, username="forge", realname="Forge User")
    options.users = UserOptions([UserSpec("forge", groups=["sudo", "video"])])
    options.network = NetworkOptions(netplan_dhcp=True, dns=["1.1.1.1"])
    return options


def _segment_run(project: Project, options: BuildOptions) -> dict[BuildPhase, dict[str, object]]:
    """Run a dry-run and attribute each command to the phase whose step preceded it."""
    runner = CommandRunner(dry_run=True)
    boundaries: list[tuple[BuildPhase, int]] = []

    def on_progress(update) -> None:
        if update.phase_fraction:
            return
        boundaries.append((update.step.phase, len(runner.history)))

    BuildOrchestrator(project, runner, options, progress=on_progress).run()

    squashfs = str(project.squashfs_root)
    iso = str(project.iso_root)
    observed: dict[BuildPhase, dict[str, object]] = {}
    for index, (phase, start) in enumerate(boundaries):
        end = boundaries[index + 1][1] if index + 1 < len(boundaries) else len(runner.history)
        agg = observed.setdefault(phase, {"privileged": False, "rollback_names": set()})
        for spec in runner.history[start:end]:
            touches = any((squashfs in arg) or (iso in arg) for arg in spec.argv)
            wrapped = spec.argv[:1] in (("sudo",), ("pkexec",))
            if spec.needs_root or wrapped or touches:
                agg["privileged"] = True
            if spec.description.startswith(_ROLLBACK_DESC):
                names: set[str] = agg["rollback_names"]  # type: ignore[assignment]
                names.add(spec.description[len(_ROLLBACK_DESC):])
    return observed


def test_catalog_matches_pipeline_taxonomy() -> None:
    assert tuple(c.phase for c in PHASE_CONTRACTS) == tuple(s.phase for s in PIPELINE_PHASES)
    assert tuple(c.title for c in PHASE_CONTRACTS) == tuple(s.title for s in PIPELINE_PHASES)
    phases = [c.phase for c in PHASE_CONTRACTS]
    assert len(phases) == len(set(phases))


def test_every_contract_has_metadata_and_known_stage() -> None:
    for contract in PHASE_CONTRACTS:
        assert contract.stage in PIPELINE_STAGES
        assert contract.stage != "build_services"
        assert contract.title
        assert contract.inputs
        assert contract.artifacts


def test_stage_grouping_is_contiguous_and_in_pipeline_order() -> None:
    # The catalog stage for each phase must appear in canonical pipeline-stage order
    # with no interleaving, mirroring the BuildServices boundary in build_pipeline.py.
    order = {stage: rank for rank, stage in enumerate(PIPELINE_STAGES)}
    ranks = [order[c.stage] for c in PHASE_CONTRACTS]
    assert ranks == sorted(ranks)


def test_render_lists_every_phase_under_its_stage() -> None:
    text = render_phase_contracts()
    assert "DistroForge build phase contracts" in text
    for contract in PHASE_CONTRACTS:
        assert contract.phase.value in text
    for stage in PIPELINE_STAGES:
        if stage == "build_services":
            assert f"[{stage}]" not in text
        else:
            assert f"[{stage}]" in text


def test_render_stage_filter_scopes_output() -> None:
    text = render_phase_contracts("assemble_iso")
    assert "[assemble_iso]" in text
    assert "[customize_target]" not in text
    assert BuildPhase.REBUILD_ISO.value in text
    assert BuildPhase.SYSTEM_SYNC.value not in text


def test_real_dry_run_phases_all_have_contracts(tmp_path) -> None:
    project = Project.create("ContractCover", tmp_path / "cover", "26.04")
    project.source_mode = "bootstrap"
    runner = CommandRunner(dry_run=True)
    report = BuildOrchestrator(project, runner, BuildOptions()).run()
    contract_phases = {c.phase for c in PHASE_CONTRACTS}
    for step in report.steps:
        assert step.phase in contract_phases


def test_privilege_flag_never_under_or_over_claims(tmp_path) -> None:
    declared = set(privileged_phases())

    boot = Project.create("ContractBoot", tmp_path / "boot", "26.04")
    boot.source_mode = "bootstrap"
    observed = _segment_run(boot, _rich_options())

    iso_project = Project.create("ContractIso", tmp_path / "iso", "26.04")
    iso_project.source_mode = "iso"
    src = tmp_path / "source.iso"
    src.write_bytes(b"\x00" * 16)
    iso_project.source_iso = src
    for phase, data in _segment_run(iso_project, _rich_options()).items():
        agg = observed.setdefault(phase, {"privileged": False, "rollback_names": set()})
        agg["privileged"] = bool(agg["privileged"]) or bool(data["privileged"])

    observed_privileged = {phase for phase, data in observed.items() if data["privileged"]}
    # never under-claim: any phase that actually touches protected state is declared privileged
    assert observed_privileged <= declared, sorted(p.value for p in observed_privileged - declared)
    # never over-claim a host-only phase: declared-not-privileged phases never touch protected state
    for phase, data in observed.items():
        if phase not in declared:
            assert data["privileged"] is False, phase.value
    # the check is non-vacuous: the privileged path is genuinely exercised
    assert len(observed_privileged) >= 15


def test_gui_command_center_surfaces_phase_contracts() -> None:
    # Strict CLI/GUI parity: the Command Center button renders the same catalog the
    # `build-phases` CLI command prints, via the shared render_phase_contracts().
    from distroforge.ui.command_center_page import show_phase_contracts

    captured: dict[str, str] = {}

    class _View:
        def setPlainText(self, text: str) -> None:
            captured["text"] = text

    class _Window:
        def __init__(self) -> None:
            self.command_center_view = _View()

        def _log(self, message: str) -> None:
            captured["log"] = message

    show_phase_contracts(_Window())
    assert captured["text"] == render_phase_contracts()
    assert "DistroForge build phase contracts" in captured["text"]
    assert "[customize_target]" in captured["text"]
    assert BuildPhase.SNAPSHOT.value in captured["text"]
    assert "phase contracts" in captured["log"]


def test_rollback_points_match_observed_snapshots(tmp_path) -> None:
    project = Project.create("ContractRollback", tmp_path / "rollback", "26.04")
    project.source_mode = "bootstrap"
    observed = _segment_run(project, _rich_options())

    observed_rollback = {phase for phase, data in observed.items() if data["rollback_names"]}
    assert observed_rollback == set(rollback_phases())
    assert observed_rollback == {BuildPhase.SNAPSHOT, BuildPhase.KERNEL_MODULE}
    for phase in observed_rollback:
        contract = contract_for(phase)
        declared_names = {name.strip() for name in contract.rollback.split(",")}
        assert observed[phase]["rollback_names"] == declared_names
