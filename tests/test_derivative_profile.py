from __future__ import annotations

import yaml

from distroforge.cli import main
from distroforge.core.derivative_profile import DerivativeProfileService, parse_dockerfile_hints


def test_derivative_profile_exports_mint_like_definition(tmp_path) -> None:
    target = tmp_path / "mint.yaml"

    plan = DerivativeProfileService().write_definition("mint-ubuntu", target)
    data = yaml.safe_load(target.read_text(encoding="utf-8"))

    assert plan.profile.installer == "ubiquity"
    assert data["derivative_profile"]["base_family"] == "ubuntu"
    assert data["derivative_profile"]["installer"] == "ubiquity"
    assert "linuxmint-keyring" in data["packages"]
    assert any("packages.linuxmint.com" in repo for repo in data["repositories"])
    assert data["branding"]["os_id"] == "distroforge-mint"


def test_lmde_profile_uses_debian_live_installer_intent() -> None:
    plan = DerivativeProfileService().plan("lmde")
    data = plan.definition()

    assert data["derivative_profile"]["base_family"] == "debian"
    assert data["derivative_profile"]["installer"] == "live-installer"
    assert data["derivative_profile"]["validation"]
    assert "debian-system-adjustments" in data["packages"]


def test_derivative_profile_reads_dockerfile_hints(tmp_path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM ubuntu:24.04\n"
        "RUN apt-get update && apt-get install -y mint-dev-tools build-essential devscripts\n"
        "RUN echo 'deb https://packages.linuxmint.com zena main' > /etc/apt/sources.list.d/mint.list\n",
        encoding="utf-8",
    )

    hints = parse_dockerfile_hints(dockerfile)

    assert hints.base_image == "ubuntu:24.04"
    assert "mint-dev-tools" in hints.apt_packages
    assert hints.repositories == ("deb https://packages.linuxmint.com zena main' > /etc/apt/sources.list.d/mint.list",)


def test_cli_derivative_profile_plan_and_export(tmp_path, capsys) -> None:
    target = tmp_path / "edge.yaml"

    main(["derivative-profile", "plan", "mint-edge"])
    assert "Hardware channel: edge" in capsys.readouterr().out

    main(["derivative-profile", "export", "mint-edge", "--output", str(target)])
    output = capsys.readouterr().out

    assert "Wrote" in output
    assert "linux-generic-hwe-24.04" in target.read_text(encoding="utf-8")


def test_cli_derivative_create_project_and_validate(tmp_path, capsys) -> None:
    root = tmp_path / "mint-project"

    main(["derivative-profile", "validate", "mint-ubuntu"])
    assert "Validation:" in capsys.readouterr().out

    main(["derivative-profile", "create-project", "mint-ubuntu", "--root", str(root)])
    output = capsys.readouterr().out

    assert "Created" in output
    assert (root / "project.json").exists()
    assert (root / "mint-ubuntu-derivative.yaml").exists()
