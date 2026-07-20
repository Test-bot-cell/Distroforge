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
`hermetic-build-plan`.
