from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from distroforge.core.artifact_paths import default_output_iso


@dataclass(frozen=True)
class ArtifactReleasePaths:
    """One coherent product and publication selection for every UI surface."""

    iso: Path
    product_output_dir: Path
    bundle_dir: Path
    build_run_id: str | None = None
    boot_run_id: str | None = None


def resolve_artifact_release_paths(window) -> ArtifactReleasePaths:
    """Resolve the Artifacts fields without treating Reports as product output.

    The release gate binds an ISO to its parent directory.  ``Reports dir`` only
    selects the publication bundle location; it must never silently change that
    product identity.
    """

    project = getattr(window, "project", None)
    default_iso = (
        default_output_iso(project)
        if project is not None
        else Path("/tmp/distroforge.iso")
    )
    iso = _absolute(
        Path(
            window.artifacts_output_iso_edit.text().strip()
            or window.output_iso_edit.text().strip()
            or default_iso
        )
    )
    product_output_dir = iso.parent

    raw_reports = window.artifacts_reports_dir_edit.text().strip()
    if not raw_reports:
        bundle_dir = (
            Path(project.output_dir) / "publish"
            if project is not None
            else product_output_dir / "publish"
        )
    else:
        reports_dir = _absolute(Path(raw_reports))
        project_output_dir = (
            _absolute(Path(project.output_dir))
            if project is not None
            else None
        )
        if reports_dir.name == "publish":
            bundle_dir = reports_dir
        elif reports_dir in {
            product_output_dir,
            project_output_dir,
        }:
            bundle_dir = reports_dir / "publish"
        else:
            bundle_dir = reports_dir.parent / "publish"

    build_run_id, boot_run_id = resolve_artifact_run_ids(window)
    return ArtifactReleasePaths(
        iso=iso,
        product_output_dir=product_output_dir,
        bundle_dir=_absolute(bundle_dir),
        build_run_id=build_run_id,
        boot_run_id=boot_run_id,
    )


def resolve_artifact_run_ids(window) -> tuple[str | None, str | None]:
    """Freeze the two release identities before work leaves the UI thread."""

    return (
        _optional_line_edit(window, "artifacts_build_run_id_edit"),
        _optional_line_edit(window, "artifacts_boot_run_id_edit"),
    )


def store_artifact_run_ids(
    window,
    build_run_id: str | None,
    boot_run_id: str | None,
) -> None:
    """Expose only identities returned by a verified core report."""

    for widget_name, value in (
        ("artifacts_build_run_id_edit", build_run_id),
        ("artifacts_boot_run_id_edit", boot_run_id),
    ):
        widget = getattr(window, widget_name, None)
        if widget is None:
            continue
        if value:
            widget.setText(value)
        else:
            widget.clear()


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _optional_line_edit(window, name: str) -> str | None:
    widget = getattr(window, name, None)
    if widget is None:
        return None
    value = widget.text().strip()
    return value or None
