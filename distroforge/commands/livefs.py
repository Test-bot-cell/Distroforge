from __future__ import annotations

from pathlib import Path

from distroforge.core.live_build import LiveBuildPlanner
from distroforge.core.livefs_iso import LivefsIsoPlanner


def render_live_build_plan(profile: Path, output_dir: Path, *, write: bool = False, json_output: bool = False) -> str:
    planner = LiveBuildPlanner()
    plan = planner.plan(profile, output_dir)
    if write:
        planner.write_plan(plan)
    return plan.render_json() if json_output else plan.render_text()


def render_livefs_iso(
    profile: Path,
    work_dir: Path,
    dest: Path,
    *,
    command: str,
    write: bool = False,
    json_output: bool = False,
    series: str | None = None,
    arch: str = "amd64",
    mirror: str = "http://archive.ubuntu.com/ubuntu",
    components: list[str] | None = None,
    disk_id: str | None = None,
    project: str | None = None,
    volume_id: str | None = None,
) -> str:
    planner = LivefsIsoPlanner()
    plan = planner.plan(
        profile,
        work_dir,
        dest,
        series=series,
        arch=arch,
        mirror=mirror,
        components=components,
        disk_id=disk_id,
        project=project,
        volume_id=volume_id,
    )
    # Nothing but the document. The "pass --write" advisory used to be concatenated here,
    # which appended an English sentence to the JSON and made `livefs-iso-build --json`
    # unparseable; it is a message for a human, so the CLI now sends it to stderr and
    # stdout stays a document in both modes.
    if command == "livefs-iso-build" and write:
        planner.write_plan(plan)
    return plan.render_json() if json_output else plan.render_text()
