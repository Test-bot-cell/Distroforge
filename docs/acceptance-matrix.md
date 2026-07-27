# Acceptance Matrix Source

This matrix is the final source-tree green light before a Debian package rebuild.
It does not build a `.deb`, boot QEMU, fetch network resources, or require a
privilege prompt. It proves that the source checkout can exercise real user
workflows in plan, dry-run, and offline advisory mode.

## Scope

The matrix creates a disposable project under the test `tmp_path` and drives the
public CLI entry points:

- `new`, `plan`, `validate`, `readiness`, and `dry-run-report`;
- `release-gate`, `publish-drill`, and `release-pipeline` without signing or boot
  execution;
- `packaging-policy` and `hermetic-build-plan` against the source checkout;
- `forgeadvisor doctor-ai`, `review-build`, and `propose-fixes` with the
  deterministic `offline` backend.

The GUI smoke opens the Start, Build, Artifacts, and Maintainer surfaces in Qt
offscreen mode. It checks that release and maintainer buttons are present and
that project-required actions route to the existing "create or open a project"
guard instead of starting a long job.

## Safety Contract

The acceptance test blocks direct subprocess execution, streaming subprocesses,
`sudo`, `pkexec`, QEMU binaries, standard-library network calls, and shell escape
helpers. The allowed writes are limited to the disposable project created under
`tmp_path`; user state is isolated with temporary XDG config and state roots.

ForgeAdvisor is exercised only through the offline backend. Optional local model
backends may still be reported by `doctor-ai`, but the matrix does not configure
model paths, keys, network access, or a cloud backend.

## Release Use

Run this matrix as part of the normal source suite:

```bash
python3 -m pytest -q
```

If it passes together with Ruff, `packaging-policy`, and the hermetic build plan,
the source tree has cleared its dry-run and maintainer workflow gate. The next
step may be a clean Debian package build in the environment selected by
`hermetic-build-plan`. Per-push CI runs Ruff, mypy, pytest, `shellcheck`, the embedded
payload compile and every `pre-commit` ratchet; `packaging-policy` and
`hermetic-build-plan` stay maintainer commands. This sentence used to say "only Ruff and
pytest run in CI", which had been wrong since mypy, shellcheck and pre-commit were wired.

## What This Matrix Does Not Prove

The whole suite, this matrix included, is unit and offline plan/dry-run testing
only. No test has ever executed `debootstrap`, `mksquashfs`, `unsquashfs`,
`xorriso`, `apt`, `qemu`, `sbuild` or `autopkgtest`: the progress fixtures under
`tests/fixtures/progress/` exist precisely so those tools stay out of the suite.
Nothing here verifies that a real ISO builds, boots, or installs, or that a real
`.deb` passes `lintian`, and that is the honest boundary of *this* gate.

It is no longer the boundary of the project. That confirmation used to be a manual
maintainer step and nothing else; it now also runs weekly, outside the suite, in
`.github/workflows/golden-path.yml` — a real bootstrap, a real ISO, a real UEFI boot and a
real `.deb` through `lintian` and its own autopkgtest suite. See `docs/golden-path.md`.
Install-media verification on real hardware is still a manual maintainer step.

Line coverage is 74.7% overall (21351 of 28586 statements). `distroforge/ui/` is
the weakest surface at 58.6%: the GUI is held by offscreen reachability,
responsiveness and parity contracts rather than by exhaustive widget tests.
