# Platform Refactor Audit

This audit records the current structural debt and the target refactor path. It is not a claim that the platform is already clean; it is the engineering contract for getting there without hiding new patches inside old monoliths.

## Current Shape

Each surface below records what it is today and the live risk. These entries were once a
three-column table, but the cells grew into paragraphs: a Markdown table row cannot be
wrapped, so they became single lines over a thousand characters wide — unreadable in an
editor and flagged by `lintian` as a source line long enough to hide anything.

### CLI entrypoint

**Current state:** `distroforge/cli.py` is about 972 lines after build option extraction
and command-handler extraction into `distroforge/commands/*`, including the
catalog-listing, advisory, and privileged-plan adapters and a single
`commands/output_policy.py` helper for dry-run command-history output.

**Risk:** routing delegates per command; the remaining inline handlers are thin core
delegations, so new command families must land as `commands/*` adapters rather than
re-growing the router.

### GUI shell

**Current state:** `distroforge/ui/main_window.py` is about 1143 lines after Build &
Release page, build controller, build option mapper, CLI-equivalent extraction,
workflow-level centralization, the extraction of every remaining domain page (ISO,
customization, recipes, plugins, logs, advanced, maintainer, quality, virtualization) into
`distroforge/ui/*_page.py`, the move of shared widget construction into the
`distroforge/ui/window_widgets.py` factory, and the extraction of every domain action
handler (terminal, capture, artifacts, mirror, branding, profile, recipe, project,
advisor, service, recommendation) into `distroforge/ui/*_actions.py` modules.

**Risk:** the shell now owns only its Track-3 surface — navigation, shared state, job
dispatch and global logs — plus the thin delegators that wire those page and
`*_actions.py` handlers back onto the page and toolbar surfaces; widget construction is
delegated to the `window_widgets` factory while the shell keeps the shared-state
references, and job dispatch stays shell-owned on the reusable `ServiceRunnerMixin`
boundary rather than being a further extraction target; the live risk is keeping new
features from re-growing the shell.

### Build core

**Current state:** `distroforge/core/build.py` is about 317 lines after the source-to-ISO
path moved to `distroforge/core/build_pipeline.py` (about 741 lines).

**Risk:** `BuildOrchestrator.run` now delegates ordered stages; per-phase declarative
metadata now lives in `distroforge/core/phase_contracts.py`.

### Protected writes

**Current state:** centralized through `FileSystemOps` and the sudo-wrapped
ISO/squashfs/snapshot services, with the in-build host-side report/preview writers
centralized through the `HostArtifactWriter` boundary.

**Risk:** audited: every protected rootfs/ISO mutation flows through these boundaries, and
the in-build host-side reports/previews flow through `HostArtifactWriter`; raw writes
remain allowed only for host-side reports, plans, previews and output scaffolding, and
each boundary stays dry-run-pure — now locked by a test that plans a full build and
asserts zero host filesystem side effects.

### Rollback

**Current state:** now transactional in `SnapshotService`.

**Risk:** must remain part of the reliability contract, not a cosmetic option.

### Docs

**Current state:** broad but scattered.

**Risk:** product architecture, user levels, module gates, and parity need one canonical
source.

## Non-Negotiable Contracts

1. Public workflows keep strict CLI/GUI parity.
2. Long-running workflows expose progress in both CLI and GUI.
3. Beginner, power-user, maintainer, and developer flows are designed intentionally, not
   as one giant advanced panel.
4. Protected rootfs/ISO state is mutated only through approved boundaries.
5. Dry-run output is a first-class artifact, not a side effect of execution code.
6. Snapshots are atomic and privileged when the rootfs requires it.
7. AI remains advisory, cited, and non-mutating unless the user explicitly starts a real
   workflow.
8. Documentation and tests land with each architecture change.

## Refactor Tracks

### 1. Source-To-ISO Kernel

The canonical source-to-ISO path now lives in `distroforge/core/build_pipeline.py`.
`BuildOrchestrator.run` is a thin driver that calls the extracted stages in order over a
shared `BuildServices` boundary:

- `run_preflight` — validation, consistency, policy, compatibility, legacy-script import
  and diff preview;
- `build_services` — construct the shared services (ISO, squashfs, apt, chroot, hooks,
  Casper, snapshots, plugins, release track);
- `acquire_source` — bootstrap from scratch or extract/unpack a source ISO;
- `configure_repositories` — debrand, apt sources, apt cache, verified PPAs and release
  track;
- `customize_target` — the mounted-chroot phases with rollback snapshots and a guaranteed
  `unmount` in `finally`; the chroot runtime is hardened on entry — bind mounts detached
  with `--make-rslave` against host namespace leaks, a `policy-rc.d` service-start block,
  and noninteractive APT — and the block is removed on exit;
- `assemble_iso` — health, autoinstall, seeds, metadata, repack, checksums, rebuild and
  the post-build report/verification phases.

Every stage emits the same dry-run command history and the same `plan()` step sequence, so
CLI/GUI parity and the dry-run contract are unchanged. Each phase now carries declarative
metadata on top of this boundary, catalogued in `distroforge/core/phase_contracts.py`:

- phase name and user-facing title;
- required inputs;
- generated artifacts;
- privilege requirements;
- dry-run events;
- rollback point before/after if relevant.

`distroforge build-phases [--stage STAGE]` renders this catalog, and the GUI **Command
Center** surfaces the same text through **Show build phase contracts**. The catalog is
honesty-tested against a real dry-run: every phase that mutates protected rootfs/ISO state
is declared privileged, and the only declared rollback points — `snapshot` and
`kernel_module` — match the snapshots observed in the dry-run.

### 2. CLI Command Adapters

Move option mapping out of `cli.py` into `commands/*` modules. `cli.py` should become a
thin router that registers commands and delegates parsing/handling. New command families
must not grow the monolith.

### 3. GUI Page Architecture

Move domain pages out of `main_window.py` until the shell only owns navigation, shared
state, job dispatch, and global logs. Pages should own their widgets and expose typed
option mappers back to the shell. Domain action handlers move the same way: each page's
button logic now lives in a `distroforge/ui/*_actions.py` module as `xxx_action(window)`
free functions, and the shell keeps only thin delegators so page and toolbar wiring stays
valid.

### 4. UX Levels

The GUI must present different depths without hiding capability:

- beginner path: source, desktop, identity, packages, output, readiness;
- power-user path: repos, mirrors, PPAs, services, snapshots, autoinstall;
- maintainer path: policy, trademark, provenance, QEMU, release artifacts;
- developer path: hooks, plugins, source builds, diagnostics, dry-run command history.

### 5. Test Gates

The test suite should keep the refactor honest:

- command registry equals public CLI commands;
- build options map to GUI widgets or documented exceptions;
- build option contracts classify every `distroforge build` flag by user level and GUI
  surface;
- Python sources stay one statement per line — no `E701`/`E702` packing — so monoliths stay reviewable while extraction proceeds;
- protected rootfs/ISO writes use explicit boundaries and the in-build host-side report
  writers use the `HostArtifactWriter` boundary, and those boundaries stay dry-run-pure —
  a test plans a build and asserts planning a build creates no host filesystem side
  effects;
- docs referenced by `debian/docs` exist;
- platform architecture docs use product language, not script/remix framing.

### 6. Known gaps in the gates

The gates above are honest about what they prove, so they must also be honest
about what they do not:

- **The suite is entirely L0/L1.** Every test is a pure unit test or an offline
  plan/dry-run test: no external tool (`debootstrap`, `mksquashfs`, `xorriso`,
  `qemu`, `apt`, `sbuild`, `autopkgtest`) has ever been executed by it, and no
  network call, privilege prompt or real artifact is involved. The progress
  fixtures under `tests/fixtures/progress/` exist precisely so heavy tools stay
  out of the suite. That boundary is permanent and is what lets the same suite run
  under buildd and autopkgtest.
- **The L2 harness is wired, but has not passed the full chain.**
  `.github/workflows/golden-path.yml` executes real tools weekly and never on push;
  `tests/test_golden_path.py` proves that workflow contract by refusing a removed
  schedule, `--dry-run`, or a boot-proof fallback. Those source assertions do not
  prove the workflow's outcome. Current evidence observes the minbase-to-ISO journey,
  blocks the reference UEFI path, and reaches shim but not GRUB on an audit variant.
  Kernel/login, installation and desktop runtime remain unproved; see
  `docs/golden-path.md` and `docs/iso-build-proof-ledger.md`.
- **Line coverage is 74.7% overall** (21351 of 28586 statements), and
  `distroforge/ui/` is the weakest surface at 58.6%. The GUI is covered by
  offscreen reachability, responsiveness and parity contracts rather than by
  exhaustive widget tests.
- **`mypy`, `pre-commit` and `shellcheck` are wired now.** This entry used to
  record the opposite, and stayed behind when they landed. `make check` is the
  single entry point (`ruff`, `mypy`, `pytest`, `shellcheck` and
  `tools/check-maintainer-scripts.py`), `.pre-commit-config.yaml` is deliberately
  offline — every hook is `repo: local` with `language: system` or `pygrep`, so
  nothing clones and nothing pip-installs — and CI runs the same gates. See
  `docs/debian-canonical-compliance.md`, which is the source of truth for what is
  and is not enforced.
- **`lintian` is configured as a weekly package gate.** This entry used to say it
  never ran in one.
  `debian-package --execute` invokes it to produce `LINTIAN.txt`,
  `doctor --debian-dev` audits its presence, `debian/control` lists it under
  `Suggests`, and the golden path accepts `passed` or `review required` and nothing
  else. The first executing attempt produced a real `.deb` and a lintian verdict,
  but its declared autopkgtest failed. `debian/rules` still does not run lintian and
  the rendered `sbuild` command still passes `--no-run-lintian`. Per-push CI still
  does not lint a `.deb`; it checks the shape of the invocation instead, because
  there is no `.deb` on a push to lint.

## First Extraction Targets

1. Build options and CLI option mapping into `commands/build_options.py` and follow-on
   command modules. The build argument registration has been extracted, along with the
   catalog-listing, advisory, and privileged-plan command adapters; dry-run command-history
   output now flows through one `commands/output_policy.py` helper. The remaining inline
   handlers are thin core delegations rather than monolith debt.
2. Build and release page widgets into a dedicated GUI page module. Build guidance copy
   for workflow levels, privilege behavior and snapshots has moved to `ui/build_guidance.py`;
   the page layout itself now lives in `ui/build_page.py`.
   Plan/build execution dispatch now lives in `ui/build_controller.py`, keeping the shell
   focused on navigation and shared widgets.
   GUI widget to `BuildOptions` mapping now lives in `ui/build_options_mapper.py`, matching
   the CLI argument to `BuildOptions` adapter shape.
   GUI-to-CLI command rendering now lives in `ui/cli_equivalent.py`, keeping command
   preview text outside the window shell.
3. Build phase execution into declarative phase adapters. The source-to-ISO path now lives
   in `core/build_pipeline.py` as ordered stage functions (`run_preflight`,
   `build_services`, `acquire_source`, `configure_repositories`, `customize_target`,
   `assemble_iso`) over a shared `BuildServices` boundary; per-phase declarative metadata
   now lives in `core/phase_contracts.py`, surfaced by `distroforge build-phases` and the
   Command Center.
4. Artifact/report writers behind a host-artifact writer boundary. The in-build host-side
   writers — diff preview and compatibility report (`core/build_reports.py`),
   provenance/SBOM (`core/provenance.py`), the HTML report (`core/html_report.py`), the
   integrity manifest (`core/integrity.py`), `BUILDINFO` (`core/release_artifacts.py`)
   and the package size report (`core/size_analysis.py`) — now route their writes through
   the `HostArtifactWriter` boundary in
   `core/host_artifacts.py`, the host analogue of `FileSystemOps`: each write is recorded
   in command history and performed only when the runner is executing. A test plans a full
   build and asserts zero host filesystem side effects, so the dry-run-purity contract is
   verified rather than asserted. The standalone artifact writers — the publish bundle
   (`core/publish_bundle.py`), the publish drill and its baseline (`core/publish_drill.py`,
   `core/publish_drill_baseline.py`), the release pipeline, notes, signing and verification
   reports (`core/release_pipeline.py`, `core/release_notes.py`, `core/release_signing.py`,
   `core/release_verification.py`) and the recipe and preset exports (`core/recipe.py`,
   `core/presets.py`) — now route through the same boundary via the `write_host_artifact`
   helper. They run on explicit maintainer commands rather than inside a build dry-run, so
   they always write when their command runs, but every host artifact still flows through
   one canonical host-owned write path.
5. Rootfs/ISO mutators behind `FileSystemOps` or named privileged services.

## Definition Of Done

A refactor slice is done only when code, CLI mapping, GUI mapping, docs, and tests move
together. A green unit test suite without updated UX/docs is not enough; a polished GUI
without core contracts is not enough either.
