from __future__ import annotations

from pathlib import Path

from distroforge.core.capture_diff import CaptureDiff
from distroforge.core.live_build import LiveBuildPlan
from distroforge.core.livefs_iso import LivefsIsoPlan

# Six report sections extended a list and then, on the same logical line, fell
# through to appending a placeholder. list.extend returns None, so that fallback
# fired unconditionally and a stray dash followed every populated section, while
# an empty section looked identical. The placeholder now shows up only when the
# section really is empty, spelled "- none" like the other report modules.
PLACEHOLDER = "- none"


def _livefs_plan(packages: list[str]) -> LivefsIsoPlan:
    return LivefsIsoPlan(
        profile=Path("profile.yaml"),
        work_dir=Path("work"),
        dest=Path("out.iso"),
        series="resolute",
        arch="amd64",
        mirror="http://archive.ubuntu.com/ubuntu",
        components=["main"],
        disk_id="disk",
        project="remix",
        volume_id="REMIX",
        package_list=packages,
    )


def test_live_build_sections_have_no_stray_placeholder() -> None:
    plan = LiveBuildPlan(
        profile=Path("profile.yaml"),
        output_dir=Path("dist"),
        package_lists=["desktop"],
        hooks=["50-provision.sh"],
        includes=["etc/skel"],
        config_files=[{"path": "etc/hosts"}],
    )

    lines = plan.render_text().splitlines()

    # A line reduced to a bare dash is the signature of the defect.
    assert "-" not in lines
    assert PLACEHOLDER not in lines
    assert "- desktop" in lines
    assert "- 50-provision.sh" in lines
    assert "- etc/skel" in lines
    assert "- etc/hosts" in lines


def test_live_build_empty_sections_show_the_placeholder() -> None:
    plan = LiveBuildPlan(profile=Path("profile.yaml"), output_dir=Path("dist"))

    lines = plan.render_text().splitlines()

    # One placeholder per empty section: package lists, hooks, includes, configs.
    assert lines.count(PLACEHOLDER) == 4


def test_livefs_iso_package_pool_has_no_stray_placeholder() -> None:
    lines = _livefs_plan(["ubuntu-desktop"]).render_text().splitlines()

    assert "-" not in lines
    assert PLACEHOLDER not in lines
    assert "- ubuntu-desktop" in lines


def test_livefs_iso_empty_package_pool_shows_the_placeholder() -> None:
    assert _livefs_plan([]).render_text().splitlines().count(PLACEHOLDER) == 1


def test_capture_diff_config_files_have_no_stray_placeholder() -> None:
    diff = CaptureDiff(
        packages=2,
        config_files=["etc/hosts"],
        captured=1,
        ignored=0,
        dangerous=0,
        not_reproducible=0,
    )

    lines = diff.render_text().splitlines()

    assert "-" not in lines
    assert PLACEHOLDER not in lines
    assert "- etc/hosts" in lines


def test_capture_diff_without_config_files_shows_the_placeholder() -> None:
    diff = CaptureDiff(
        packages=0,
        config_files=[],
        captured=0,
        ignored=0,
        dangerous=0,
        not_reproducible=0,
    )

    assert diff.render_text().splitlines().count(PLACEHOLDER) == 1
