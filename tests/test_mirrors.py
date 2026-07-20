from __future__ import annotations

import json

import pytest

from distroforge.cli import main
from distroforge.core.command import CommandRunner
from distroforge.core.mirrors import MirrorOptions, MirrorService
from distroforge.core.project import Project


def test_mirror_doctor_and_deb822_render_default_ubuntu(tmp_path) -> None:
    project = Project.create("Mirrors", tmp_path / "mirrors", "26.04")
    service = MirrorService(CommandRunner(dry_run=True), project, MirrorOptions(enabled=True))

    report = service.doctor()
    rendered = service.render_sources()

    assert report.status == "ok"
    assert report.base == "ubuntu"
    assert "URIs: https://archive.ubuntu.com/ubuntu" in rendered
    assert "URIs: https://security.ubuntu.com/ubuntu" in rendered
    assert "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" in rendered
    assert "resolute-updates" in rendered


def test_mirror_apply_backs_up_and_restores_sources(tmp_path) -> None:
    project = Project.create("Mirrors", tmp_path / "mirrors", "26.04")
    sources = project.squashfs_root / "etc/apt/sources.list"
    sources.parent.mkdir(parents=True)
    sources.write_text("deb https://old.example/ubuntu resolute main\n", encoding="utf-8")

    service = MirrorService(CommandRunner(dry_run=False), project, MirrorOptions(enabled=True))
    service.apply(strict=True)

    assert (project.squashfs_root / "etc/apt/sources.list.d/distroforge.sources").exists()
    assert "Managed by DistroForge mirror layer" in sources.read_text(encoding="utf-8")

    service.restore()

    assert sources.read_text(encoding="utf-8") == "deb https://old.example/ubuntu resolute main\n"


def test_mirror_doctor_blocks_http_when_https_required(tmp_path) -> None:
    project = Project.create("Mirrors", tmp_path / "mirrors", "26.04")
    service = MirrorService(
        CommandRunner(dry_run=True),
        project,
        MirrorOptions(enabled=True, archive_mirror="http://mirror.example/ubuntu"),
    )

    report = service.doctor()

    assert report.status == "blocked"
    assert report.issues[0].code == "mirror-http"


def test_cli_mirrors_render_and_doctor_json(tmp_path, capsys) -> None:
    project = Project.create("Mirrors", tmp_path / "mirrors", "26.04")
    project.save()

    main(["mirrors", "render", str(project.root)])
    assert "Types: deb" in capsys.readouterr().out

    main(["mirrors", "doctor", str(project.root), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"


def test_cli_mirrors_strict_rejects_http(tmp_path) -> None:
    project = Project.create("Mirrors", tmp_path / "mirrors", "26.04")
    project.save()

    with pytest.raises(SystemExit) as exc:
        main(["mirrors", "doctor", str(project.root), "--archive", "http://mirror.example/ubuntu", "--strict"])

    assert exc.value.code == 2
