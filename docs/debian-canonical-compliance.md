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
- Autopkgtest smoke coverage for the installed CLI, plus a GUI import test that declares
  `python3-pyqt6` explicitly rather than riding on `@`: the Qt bindings are a `Recommends`,
  so the installed package does not necessarily have them and the build-time suite cannot
  speak for that case. Every autopkgtest writes into `$AUTOPKGTEST_TMP`, never a fixed
  `/tmp` name that a local user could pre-empt with a symlink.
- CI must run Ruff and pytest on Python 3.11 through 3.14 against both Qt bindings; the
  policy guard tests are part of that pytest run and are additionally named as their own
  step so a collection error there cannot hide in the noise of a full matrix.
- `debian/rules` runs the test phase against the staged build tree, not the checkout:
  `PYBUILD_TEST_ARGS` passes `-o pythonpath={build_dir}` so `import distroforge` resolves
  to what the `.deb` will ship. A data file dropped from `package-data` therefore fails
  the build instead of passing it against the source tree. Tests keep reading the source
  files they assert on -- `debian/control`, `docs/`, `pyproject.toml` -- because they
  anchor at `Path(__file__).resolve().parents[1]`, never at the working directory.
- During alpha development, package build artifacts must not be produced unless
  the maintainer explicitly authorizes a package build in the current task.

## What Is Not Yet Enforced

Compliance is a standing requirement, but only part of it is currently automated. Stating
the gap is part of the rule, not an exception to it:

- `lintian` is a maintainer action, never a gate. `debian-package --execute` runs it to
  produce `LINTIAN.txt`, `doctor --debian-dev` audits its presence, and `debian/control`
  lists it under `Suggests`; but no CI step runs it on a real `.deb`, `debian/rules` does
  not run it, and the rendered `sbuild` command passes `--no-run-lintian`. What *is*
  enforced is the shape of the invocation: the profile is pinned to a vendor
  (`lintian --profile debian`), because a profile is a vendor and never a suite --
  `--profile resolute` does not exist -- and an unpinned run would take its verdict from
  whichever vendor the host happens to be. CI asserts no such suite name is ever passed.
  The verdict is read from the emitted tags rather than the exit code, since `lintian`
  exits 0 on a package that carries warnings.
- Tags are fixed, never overridden. The package ships no
  `usr/share/lintian/overrides/distroforge` and must not: silencing a tag is not the same
  thing as being clean, so a warning surfaces as `review required` with every tag kept in
  the reason string.
- Maintainer scripts are held to two rules, both executable. They may not spell a command
  with an absolute path, and they may not reach into a user session -- no `gsettings`,
  `dconf`, `runuser`, `/home`, `XDG_RUNTIME_DIR` or `DBUS_SESSION_BUS_ADDRESS`: a script
  running as root cannot ask the user for consent, and `dpkg` cannot undo a write it never
  recorded. Anything a user must agree to belongs in the application, where the user is
  present and can revoke it; `distroforge dock` and the First Run checkbox are the pattern.
- `mypy`, `pre-commit` and `shellcheck` now run on this tree: `make check` is the single
  entry point (`ruff`, `mypy` against a shrinking debt list, `pytest`, `shellcheck`, and
  `tools/check-maintainer-scripts.py`), `.pre-commit-config.yaml` is deliberately offline
  -- every hook is `repo: local` with `language: system` or `pygrep`, so nothing clones
  and nothing pip-installs -- and CI runs the same gates. The packaging shell in
  `debian/tests/*` is linted by `shellcheck`, and the `python3` payloads embedded in those
  scripts are handed to `compile()`, which nothing else checks: dpkg runs the script, the
  interpreter dies, and the surrounding `2>/dev/null` plus `|| true` swallow the traceback.
- The test suite never executes an external build tool, so nothing verifies that a real
  package or a real ISO is produced. Package-build conformance is confirmed by a
  maintainer running the hermetic build path, not by the suite.

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
