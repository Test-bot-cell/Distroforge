from __future__ import annotations

from dataclasses import dataclass

from .diff_preview import DiffPreviewService
from .project import Project

try:
    from .build import BuildOptions
except ImportError:  # pragma: no cover
    BuildOptions = object  # type: ignore[misc,assignment]


@dataclass(frozen=True)
class BuildExplanation:
    title: str
    lines: tuple[str, ...]
    warnings: tuple[str, ...] = ()

    def render_text(self) -> str:
        sections = [self.title, "", *self.lines]
        if self.warnings:
            sections.extend(["", "Warnings:", *[f"- {item}" for item in self.warnings]])
        return "\n".join(sections)


def explain_build(project: Project, options: BuildOptions) -> BuildExplanation:
    preview = DiffPreviewService().preview(project, options)
    custom = project.customization
    warnings: list[str] = []
    lines = [
        f"Project: {project.name}",
        f"Release: {project.release.label}",
        f"Source mode: {project.source_mode}",
        f"Source ISO: {project.source_iso or '<from scratch / not selected>'}",
        f"Output: {project.output_dir / f'{project.name}-{project.release.version}.iso'}",
        f"Install packages: {len(preview.install)}",
        f"Remove packages: {len(preview.remove)}",
        f"Snaps: {len(preview.snaps)}",
        f"Desktop: {custom.desktop or 'keep source default'}",
        f"Display manager: {custom.display_manager or 'auto/default'}",
        f"Autologin: {custom.autologin_user or 'disabled'}",
        f"Wallpaper: {'yes' if custom.wallpaper else 'no'}",
        f"Sanitize: {options.sanitize.summary()}",
        f"Release track: {options.release_track.summary()}",
        f"System sync: {options.system_sync.summary()}",
        f"QEMU preview: {'enabled' if options.run_preview else 'disabled'}",
        f"Synaptic package stage: {'enabled' if options.run_synaptic else 'disabled'}",
        f"Apt cache/proxy: {options.apt_cache.proxy_url or options.apt_cache.cache_dir or 'disabled'}",
        f"Snapshots: {'enabled' if options.snapshots.enabled else 'disabled'}",
        f"Desktop source: {options.desktop_source.summary()}",
        f"Kernel: {options.kernel_module.summary()}",
    ]
    if options.release_track.mode != "stable":
        warnings.append("Release track is experimental and should be tested in QEMU before redistribution.")
    if options.system_sync.enabled and options.system_sync.strategy == "full" and not options.snapshots.enabled:
        warnings.append("Full system sync should enable snapshots for rollback.")
    if options.sanitize.enabled and not options.sanitize.package_autoremove:
        warnings.append("Sanitize is enabled but obsolete package pruning is disabled.")
    if options.kernel_module.enabled and not options.kernel_module.prune_obsolete_kernels:
        warnings.append("Kernel mode is enabled without automatic obsolete-kernel pruning.")
    if options.kernel_module.enabled and options.kernel_module.build_mode == "full-deb" and not options.snapshots.enabled:
        warnings.append("Full kernel .deb builds should enable snapshots for rollback.")
    if options.desktop_source.enabled and not options.desktop_source.components:
        warnings.append("Desktop source catalog mode is a planning stub until component URLs are pinned.")
    if project.source_mode == "iso" and not project.source_iso:
        warnings.append("No source ISO is selected.")
    return BuildExplanation("DistroForge build explanation", tuple(lines), tuple(warnings))
