# Debian, Ubuntu, and Canonical Compliance

DistroForge is maintained as a Debian-policy-oriented Python application that can target
Ubuntu and Debian live ISO workflows without presenting itself as an Ubuntu product.

## Golden Rule

**Every change to DistroForge must be strictly Debian-policy compliant and aligned with
Canonical Ltd best practices.** This is a standing, non-negotiable requirement for all
work — code, tests, packaging, and documentation alike — not a per-task option. When a
design choice is open, choose the path that keeps the project compliant; when in doubt,
consult this document and the Debian Policy Manual referenced below before proceeding.
This document is the single source of truth for that rule; other docs point here rather
than restating it.

## Required Project Rules

- Public application name: `DistroForge`.
- Debian source and binary package name: `distroforge`.
- Main command: `distroforge`.
- Python import package: `distroforge`.
- Legacy names based on Ubuntu trademarks must not reappear.
- Ubuntu may be mentioned only as a supported target platform, not as the product name.
- The project must not imply endorsement by Canonical or the Ubuntu project.
- Every public CLI command must have a GUI-equivalent workflow and long-running workflows
  must expose progress in the GUI.

## Packaging Baseline

- Source package format: `3.0 (quilt)`.
- Build system: `dh` with `pybuild-plugin-pyproject`.
- `Rules-Requires-Root: no`.
- Machine-readable `debian/copyright`.
- Autopkgtest smoke coverage for the installed CLI.
- CI must run Ruff, pytest, and the policy guard tests.
- During alpha development, package build artifacts must not be produced unless
  the maintainer explicitly authorizes a package build in the current task.

## GUI Theming Dependencies

- The Qt GUI presents a GNOME-native look: Adwaita Sans typography, Adwaita symbolic
  icons resolved through `QIcon.fromTheme`, and sober Adwaita light/dark surfaces.
- The package therefore recommends `fonts-adwaita-sans` (the Adwaita Sans family the
  stylesheet names), `adwaita-icon-theme`, and `qt6-svg-plugins`. The Adwaita symbolic
  icons are SVG, so `qt6-svg-plugins` supplies the Qt SVG icon engine that renders them;
  without it `QIcon.fromTheme` cannot draw the glyphs. These are `Recommends`, not
  `Depends`: the GUI degrades gracefully to the host default font and icon set when they
  are absent, matching the optional `python3-pyqt6` GUI tier.
- The GUI is PyQt6, not GTK, so it neither links nor requires `libadwaita`. The
  surface colours are baked-in Adwaita hex values, carrying no runtime GTK dependency.

## References

- Debian Policy Manual: https://www.debian.org/doc/debian-policy/
- Debian machine-readable copyright format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
- Ubuntu package format documentation: https://documentation.ubuntu.com/project/how-ubuntu-is-made/concepts/package-format/
- Canonical trademarks and IP policy: https://canonical.com/legal/trademarks and https://canonical.com/legal/intellectual-property-policy
