from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .apt import PackagePlan
from .apt_cache import AptCacheOptions
from .autoinstall import AutoinstallOptions
from .bootcheck import BootCheckOptions
from .bootstrap import BootstrapOptions
from .branding import BrandingOptions
from .build_phases import PIPELINE_PHASES as PIPELINE_PHASES
from .build_phases import BuildPhase, BuildStep
from .build_pipeline import (
    acquire_source,
    assemble_iso,
    build_services,
    configure_repositories,
    customize_target,
    run_preflight,
)
from .build_sequence import build_phase_sequence, total_weight
from .command import CommandRunner, CommandSpec
from .customize import desktop_conflicting_packages, desktop_package_plan, split_desktop_packages
from .desktop_source import DesktopSourceOptions
from .drivers import DriverOptions
from .fsops import FileSystemOps
from .html_report import HtmlReportOptions
from .importer import ImportOptions
from .kernel import KernelModuleOptions
from .kiosk import KioskOptions
from .mirrors import MirrorOptions
from .network import NetworkOptions
from .oem import OemOptions
from .plugins import PluginOptions
from .policy import PolicyOptions
from .ppa import PpaOptions
from .prebuild_vm import PrebuildVmOptions
from .project import Project
from .provenance import ProvenanceOptions
from .qa import QaOptions
from .qemu_screenshot import QemuScreenshotOptions
from .release_artifacts import ReleaseArtifactOptions
from .release_track import ReleaseTrackOptions
from .reproducible import ReproducibleOptions
from .sanitize import SanitizeOptions
from .secureboot import SecureBootOptions
from .seeds import SeedOptions
from .size_analysis import SizeAnalysisOptions
from .snaps import SnapOptions
from .snapshots import SnapshotOptions
from .system_sync import SystemSyncOptions
from .systemd import SystemdOptions
from .trust import TrustOptions
from .users import UserOptions
from .vulnscan import VulnScanOptions


@dataclass
class BuildOptions:
    output_iso: Path | None = None
    package_plan: PackagePlan = field(default_factory=PackagePlan)
    run_preview: bool = False
    run_synaptic: bool = False
    clean_apt_cache: bool = True
    use_sudo: bool = True
    sanitize: SanitizeOptions = field(default_factory=SanitizeOptions)
    bootstrap: BootstrapOptions = field(default_factory=BootstrapOptions)
    kernel_module: KernelModuleOptions = field(default_factory=KernelModuleOptions)
    autoinstall: AutoinstallOptions = field(default_factory=AutoinstallOptions)
    seeds: SeedOptions = field(default_factory=SeedOptions)
    snaps: SnapOptions = field(default_factory=SnapOptions)
    drivers: DriverOptions = field(default_factory=DriverOptions)
    branding: BrandingOptions = field(default_factory=BrandingOptions)
    secure_boot: SecureBootOptions = field(default_factory=SecureBootOptions)
    provenance: ProvenanceOptions = field(default_factory=ProvenanceOptions)
    qa: QaOptions = field(default_factory=QaOptions)
    release_track: ReleaseTrackOptions = field(default_factory=ReleaseTrackOptions)
    system_sync: SystemSyncOptions = field(default_factory=SystemSyncOptions)
    ppa: PpaOptions = field(default_factory=PpaOptions)
    apt_cache: AptCacheOptions = field(default_factory=AptCacheOptions)
    snapshots: SnapshotOptions = field(default_factory=SnapshotOptions)
    oem: OemOptions = field(default_factory=OemOptions)
    systemd: SystemdOptions = field(default_factory=SystemdOptions)
    users: UserOptions = field(default_factory=UserOptions)
    network: NetworkOptions = field(default_factory=NetworkOptions)
    mirrors: MirrorOptions = field(default_factory=MirrorOptions)
    kiosk: KioskOptions = field(default_factory=KioskOptions)
    bootcheck: BootCheckOptions = field(default_factory=BootCheckOptions)
    plugins: PluginOptions = field(default_factory=PluginOptions)
    release_artifacts: ReleaseArtifactOptions = field(default_factory=ReleaseArtifactOptions)
    import_scripts: ImportOptions = field(default_factory=lambda: ImportOptions([]))
    policy: PolicyOptions = field(default_factory=PolicyOptions)
    html_report: HtmlReportOptions = field(default_factory=HtmlReportOptions)
    size_analysis: SizeAnalysisOptions = field(default_factory=SizeAnalysisOptions)
    reproducible: ReproducibleOptions = field(default_factory=ReproducibleOptions)
    qemu_screenshot: QemuScreenshotOptions = field(default_factory=QemuScreenshotOptions)
    desktop_source: DesktopSourceOptions = field(default_factory=DesktopSourceOptions)
    prebuild_vm: PrebuildVmOptions = field(default_factory=PrebuildVmOptions)
    trust: TrustOptions = field(default_factory=TrustOptions)
    vuln_scan: VulnScanOptions = field(default_factory=VulnScanOptions)


@dataclass
class BuildReport:
    steps: list[BuildStep] = field(default_factory=list)

    def add(self, phase: BuildPhase, title: str, detail: str) -> None:
        self.steps.append(BuildStep(phase=phase, title=title, detail=detail))


@dataclass(frozen=True)
class BuildProgress:
    """One progress emission from BuildOrchestrator.run().

    ``fraction`` is the overall weighted completion in [0, 1]; ``phase_fraction`` is
    progress within the current step's weight band (0 at step start, advanced by live
    sub-progress from heavy commands). ``index`` is 1-based over ``total`` steps.
    """

    step: BuildStep
    index: int
    total: int
    fraction: float
    phase_fraction: float = 0.0


ProgressCallback = Callable[[BuildProgress], None]


@dataclass(frozen=True)
class BuildContext:
    project: Project
    runner: CommandRunner
    options: BuildOptions

    @property
    def execute(self) -> bool:
        return not self.runner.dry_run


class BuildOrchestrator:
    def __init__(
        self,
        project: Project,
        runner: CommandRunner,
        options: BuildOptions | None = None,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.project = project
        self.runner = runner
        self.options = options or BuildOptions()
        self.context = BuildContext(project, runner, self.options)
        self.progress = progress
        self.report = BuildReport()
        self._sequence = build_phase_sequence(
            source_mode=project.source_mode,
            run_preview=self.options.run_preview,
        )
        self._total_weight = total_weight(self._sequence)
        self._seq_index = 0
        self._completed_weight = 0.0
        self._cur_band_start = 0.0
        self._cur_band_width = 0.0

    def plan(self) -> list[BuildStep]:
        return [BuildStep(step.phase, step.title, step.detail) for step in self._sequence]

    def run(self) -> BuildReport:
        run_preflight(self)
        services = build_services(self)
        acquire_source(self, services)
        configure_repositories(self, services)
        customize_target(self, services)
        assemble_iso(self, services)
        return self.report

    def _stage_chroot_hooks(self) -> bool:
        source = self.project.root / "hooks" / "chroot"
        if not source.exists():
            return False
        target = self.project.squashfs_root / "distroforge-hooks"
        if self.runner.dry_run:
            self.runner.run(
                CommandSpec(
                    argv=("stage-chroot-hooks", str(source), str(target)),
                    description="Stage chroot hooks in target root",
                )
            )
            return True
        fs = FileSystemOps(self.runner, self.options.use_sudo)
        fs.mkdir(target, "Stage chroot hooks in target root")
        for script in sorted(source.iterdir()):
            if script.is_file():
                fs.copy_file(script, target / script.name, f"Stage chroot hook {script.name}", mode="0755")
        return True

    def _merged_package_plan(self) -> PackagePlan:
        desktop_plan = desktop_package_plan(self.project.customization, family=self.project.release.family)
        project_packages, project_conflicts = split_desktop_packages(
            self.project.customization,
            self.project.packages,
            family=self.project.release.family,
        )
        option_packages, option_conflicts = split_desktop_packages(
            self.project.customization,
            self.options.package_plan.install,
            family=self.project.release.family,
        )
        return PackagePlan(
            install=[
                *desktop_plan.install,
                *project_packages,
                *option_packages,
            ],
            remove=[
                *self.project.remove_packages,
                *self.options.package_plan.remove,
                *project_conflicts,
                *option_conflicts,
            ],
            purge=self.options.package_plan.purge,
        ).normalized()

    def _desktop_conflict_packages(self, family: str) -> set[str]:
        return desktop_conflicting_packages(self.project.customization, family=family)

    def _planned_packages(self) -> list[str]:
        return list(self._merged_package_plan().install)

    def _customization_text(self) -> str:
        custom = self.project.customization
        parts = []
        if custom.desktop:
            parts.append(f"desktop={custom.desktop}")
        if custom.display_manager:
            parts.append(f"dm={custom.display_manager}")
        if custom.autologin_user:
            parts.append(f"autologin={custom.autologin_user}")
        if custom.wallpaper:
            parts.append("wallpaper=yes")
        if custom.hostname:
            parts.append(f"hostname={custom.hostname}")
        if custom.locale:
            parts.append(f"locale={custom.locale}")
        if custom.timezone:
            parts.append(f"timezone={custom.timezone}")
        return " ".join(parts) if parts else "no high-level customization"

    def _package_plan_text(self) -> str:
        plan = self._merged_package_plan()
        return f"install={len(plan.install)} remove={len(plan.remove)} purge={plan.purge}"

    def _filesystem_image(self) -> Path:
        return self.project.iso_root / self.project.release.livefs / "filesystem.squashfs"

    def _output_iso(self) -> Path:
        if self.options.output_iso:
            return self.options.output_iso
        return self.project.output_dir / f"{self.project.name}-{self.project.release.version}.iso"

    def _require_source_iso(self) -> Path:
        if not self.project.source_iso:
            raise ValueError("Project has no source ISO configured")
        return self.project.source_iso

    def _source_iso_text(self) -> str:
        return str(self.project.source_iso) if self.project.source_iso else "<missing source ISO>"

    def _step(self, phase: BuildPhase, title: str, detail: str) -> None:
        if self._seq_index >= len(self._sequence):
            raise AssertionError(
                "build sequence drift: run() emitted more steps than planned "
                f"(extra {phase.value}/{title!r} at index {self._seq_index})"
            )
        expected = self._sequence[self._seq_index]
        if (expected.phase, expected.title) != (phase, title):
            raise AssertionError(
                f"build sequence drift at index {self._seq_index}: run() emitted "
                f"{phase.value}/{title!r}, sequence expects "
                f"{expected.phase.value}/{expected.title!r}"
            )
        self._cur_band_start = self._completed_weight / self._total_weight
        self._cur_band_width = expected.weight / self._total_weight
        self._completed_weight += expected.weight
        self._seq_index += 1
        self.report.add(phase, title, detail)
        if self.progress:
            self.progress(
                BuildProgress(
                    step=self.report.steps[-1],
                    index=self._seq_index,
                    total=len(self._sequence),
                    fraction=self._cur_band_start,
                )
            )

    def _phase_progress(self, phase_fraction: float) -> None:
        """Emit live sub-progress within the current step's weight band.

        Heavy commands (unsquashfs/apt/mksquashfs/xorriso) call this with a 0..1
        completion ratio; the overall ``fraction`` advances inside the band opened
        by the last ``_step`` and never crosses into the next step's band.
        """
        if not self.progress or self._seq_index == 0:
            return
        clamped = 0.0 if phase_fraction < 0.0 else 1.0 if phase_fraction > 1.0 else phase_fraction
        self.progress(
            BuildProgress(
                step=self.report.steps[-1],
                index=self._seq_index,
                total=len(self._sequence),
                fraction=self._cur_band_start + clamped * self._cur_band_width,
                phase_fraction=clamped,
            )
        )
