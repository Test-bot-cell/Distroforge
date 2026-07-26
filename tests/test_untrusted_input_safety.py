from __future__ import annotations

import io
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

from distroforge.core.command import CommandRunner
from distroforge.core.desktop_source import (
    DesktopSourceComponent,
    DesktopSourceOptions,
    DesktopSourceService,
)

# Values that carry shell meaning without containing whitespace. A quoting
# helper that only reacts to spaces lets every one of them through raw.
HOSTILE_TOKENS = ("$(id)", "*", "~root", "a`id`b", "x;y", "$HOME")
INJECTION_SUFFIX = "dforge; touch /tmp/distroforge-injection-canary #"


# Downloaded GRUB theme archives are untrusted input. Auditing member.name is
# not enough: a symlink member carries its target in linkname, which extractall
# follows. The stdlib "data" filter is the backstop; the explicit linkname check
# keeps the project's own error message for the common cases.
def test_tar_absolute_symlink_cannot_escape_the_destination(tmp_path: Path) -> None:
    from distroforge.ui import path_actions

    outside = tmp_path / "outside"
    outside.mkdir()
    destination = tmp_path / "destination"
    destination.mkdir()
    archive = tmp_path / "theme.tar"

    with tarfile.open(archive, "w") as handle:
        link = tarfile.TarInfo("theme")
        link.type = tarfile.SYMTYPE
        link.linkname = str(outside)
        handle.addfile(link)
        payload = b"escaped\n"
        member = tarfile.TarInfo("theme/theme.txt")
        member.size = len(payload)
        handle.addfile(member, io.BytesIO(payload))

    with pytest.raises(ValueError):
        path_actions._safe_extract_tar(archive, destination)
    assert not (outside / "theme.txt").exists()


def test_tar_relative_symlink_cannot_escape_the_destination(tmp_path: Path) -> None:
    from distroforge.ui import path_actions

    destination = tmp_path / "destination"
    destination.mkdir()
    archive = tmp_path / "theme.tar"

    with tarfile.open(archive, "w") as handle:
        link = tarfile.TarInfo("theme")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        handle.addfile(link)

    with pytest.raises(ValueError):
        path_actions._safe_extract_tar(archive, destination)


@pytest.fixture(scope="module")
def qt_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from distroforge.ui.qt import QApplication

    return QApplication.instance() or QApplication([])


# The Command Center offers this string for copy-paste into a shell, so the
# oracle has to be a real shell round-trip. A shlex.split oracle would pass
# even when the string expands, because shlex performs no expansion at all.
# The preview now renders every build option, so the window has to be the real
# one: a hand-written stand-in would only cover the fields it happened to define.
def test_cli_equivalent_survives_a_shell_round_trip(tmp_path: Path, qt_app) -> None:
    from distroforge.core.project import Project
    from distroforge.ui.cli_equivalent import build_cli_equivalent
    from distroforge.ui.main_window import MainWindow

    window = MainWindow()
    window.project = Project.create("Hostile", tmp_path / "project", "26.04")
    window.install_edit.setPlainText("\n".join(HOSTILE_TOKENS))
    # Hostile text also has to survive the fields the preview used to drop.
    window.kiosk_check.setChecked(True)
    window.kiosk_url_edit.setText(HOSTILE_TOKENS[0])
    window.brand_pretty_name_edit.setText(HOSTILE_TOKENS[3])
    window.snap_specs_edit.setPlainText(HOSTILE_TOKENS[1])
    rendered = build_cli_equivalent(window)

    # Give the shell a directory with files so an unquoted "*" would expand.
    workdir = tmp_path / "glob"
    workdir.mkdir()
    (workdir / "expanded-by-the-shell").touch()
    result = subprocess.run(
        ("bash", "-c", f'printf "%s\\n" {rendered}'),
        cwd=workdir,
        capture_output=True,
        text=True,
        check=True,
    )
    observed = result.stdout.splitlines()

    assert observed[0] == "distroforge"
    for token in HOSTILE_TOKENS:
        assert token in observed, f"the shell altered {token!r}: {observed}"
    assert "expanded-by-the-shell" not in observed
    assert "uid=" not in result.stdout


# distroforge-debwrap never existed in the tree, so the autotools and meson
# branches could not succeed outside dry-run. The .deb is now assembled with
# dpkg-deb from the DESTDIR tree.
@pytest.mark.parametrize("build_system", ["meson", "autotools"])
def test_desktop_source_builds_the_deb_without_a_missing_helper(
    tmp_path: Path, build_system: str
) -> None:
    runner = CommandRunner(dry_run=True)
    component = DesktopSourceComponent(
        name="hostile",
        version="1.0",
        source_url="https://example.invalid/hostile-1.0.tar.xz",
        build_system=build_system,
        configure_args=("-Dfoo=$(id)",),
    )
    options = DesktopSourceOptions(enabled=True, components=[component])
    service = DesktopSourceService(runner, tmp_path / "root", tmp_path / "work", options)

    service._build_deb(component, service._source_dir(component))
    command = runner.history[-1].argv[-1]

    assert "debwrap" not in command
    assert "dpkg-deb --build" in command
    # The generated line has to be valid shell, not just plausible text.
    subprocess.run(("bash", "-n", "-c", command), check=True)


# The component fields reach a root /bin/bash -lc inside the chroot. The proof
# that quoting holds is the control file the shell actually writes: the hostile
# suffix must land there verbatim, and its embedded command must never run.
def test_desktop_source_component_fields_cannot_inject_a_root_command(tmp_path: Path) -> None:
    canary = tmp_path / "canary"
    runner = CommandRunner(dry_run=True)
    component = DesktopSourceComponent(
        name="hostile",
        version="1.0",
        source_url="https://example.invalid/hostile-1.0.tar.xz",
    )
    options = DesktopSourceOptions(
        enabled=True,
        components=[component],
        local_suffix=f"dforge; touch {canary} #",
    )
    service = DesktopSourceService(runner, tmp_path / "root", tmp_path / "work", options)

    assemble = service._assemble_deb_command(component)
    workdir = tmp_path / "build"
    workdir.mkdir()
    subprocess.run(("bash", "-c", assemble), cwd=workdir, capture_output=True, check=False)

    control = (workdir / "debroot" / "DEBIAN" / "control").read_text(encoding="utf-8")
    assert f"Version: 1.0+dforge; touch {canary} #" in control
    assert not canary.exists()
