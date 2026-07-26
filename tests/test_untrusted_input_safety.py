from __future__ import annotations

import io
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


class _Text:
    def __init__(self, value: str = "") -> None:
        self._value = value

    def toPlainText(self) -> str:
        return self._value

    def text(self) -> str:
        return self._value


class _Check:
    def __init__(self, checked: bool = False) -> None:
        self._checked = checked

    def isChecked(self) -> bool:
        return self._checked


class _Combo:
    def __init__(self, data: object = None) -> None:
        self._data = data

    def currentData(self) -> object:
        return self._data


class _Project:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.source_iso: Path | None = None
        self.source_mode = "iso"


class _Window:
    """Minimal stand-in for the Command Center window."""

    def __init__(self, root: Path, install: str) -> None:
        self.project = _Project(root)
        self.install_edit = _Text(install)
        self.remove_edit = _Text()
        self.desktop_combo = _Combo()
        self.source_iso_sha256_edit = _Text()
        self.source_iso_signature_edit = _Text()
        self.source_iso_gpg_fingerprint_edit = _Text()
        self.require_source_checksum_check = _Check()
        self.require_source_signature_check = _Check()
        self.mirrors_check = _Check()
        self.mirror_archive_edit = _Text()
        self.mirror_security_edit = _Text()
        self.mirror_country_edit = _Text()
        self.mirror_allow_http_check = _Check()
        self.mirror_override_security_check = _Check()
        self.policy_strict_check = _Check()
        self.brand_compliance_mode_combo = _Combo("advisory")

    def _sync_project_from_ui(self) -> None:
        return None


# The Command Center offers this string for copy-paste into a shell, so the
# oracle has to be a real shell round-trip. A shlex.split oracle would pass
# even when the string expands, because shlex performs no expansion at all.
def test_cli_equivalent_survives_a_shell_round_trip(tmp_path: Path) -> None:
    from distroforge.ui.cli_equivalent import build_cli_equivalent

    window = _Window(tmp_path / "project", "\n".join(HOSTILE_TOKENS))
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
