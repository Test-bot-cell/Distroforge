# Debian/Ubuntu Python Policy Notes

DistroForge targets the distribution `python3` interpreter rather than a pinned
minor interpreter.

## Runtime Target

- Project floor: Python 3.11.
- CI policy: test Python 3.11, 3.12, and 3.13.
- Local development may use newer interpreters, but code must remain compatible with
  the declared floor and Ruff `py311` target.

This matches the Debian/Ubuntu convention that packages should depend on `python3`
and use the distribution-supported Python 3 versions instead of requiring a locally
installed upstream interpreter.

## Standalone Development

For standalone development, use a local virtual environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev,typer,pyqt6]"
```

This is intentionally separate from a system package install. Do not install project
dependencies into `/usr` with pip.

## Debian Package Direction

The `.deb` packaging layer uses:

- `dh-sequence-python3` / `dh_python3`
- `pybuild`
- `/usr/bin/python3` shebang rewriting from Debian helpers
- Debian package dependencies such as `python3-pydantic`, `python3-yaml`,
  `python3-rich`, `python3-pluggy`, `python3-typer`, and `python3-pyqt6`

The Python package metadata in `pyproject.toml` is suitable for standalone/pip
development, but the Debian source package should express dependencies in
`debian/control`.

During the alpha development cycle, Debian package builds are not part of the
default workflow. Keep the tree clean with lint, tests, imports and static
packaging review; run package build tooling only when the maintainer explicitly
asks for it in the current task.

This package carries the MIT license, so the source license is suitable for
redistribution review. Debian/Ubuntu upload readiness still depends on normal
packaging review, naming, dependencies, tests, and any trademark constraints.
