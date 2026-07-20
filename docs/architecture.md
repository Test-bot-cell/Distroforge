# Architecture

DistroForge is split into small service modules around a single build pipeline. The
target product architecture is defined in `docs/distroforge-platform-architecture.md`:
a reliable source-to-ISO reference path first, then optional advanced modules that
preserve the same contracts. The current structural debt and extraction tracks are
tracked in `docs/platform-refactor-audit.md`. Every layer below is bound by the golden
rule in `docs/debian-canonical-compliance.md`: all work stays strictly Debian-policy and
Canonical-best-practices compliant.

## Layers

- `cli.py`: legacy argparse entrypoint and command routing.
- `typer_cli.py`: optional Typer facade for common commands.
- `core/`: domain services, validation, build orchestration, project model, and artifacts.
- `core/readiness.py`, `core/trust.py`, `core/dry_run_report.py`: structured audit reports used by CLI, GUI, ForgeAdvisor, and local AI review.
- `ai/forgeadvisor.py`: local-first advisory layer for explaining logs and build findings with citations.
- `ai/backend.py`: pluggable local-first advisor backend seam — the always-available `OfflineBackend` default plus optional `llama`/`ollama` shell-out adapters that degrade to offline; ships no model weights in the core package.
- `core/build_diagnosis.py`: the single canonical failure taxonomy (one rule table); the beginner-iso explainer, ForgeAdvisor, and the build-memory corpus all classify through it.
- `core/build_memory.py`: the host-owned, append-only build-memory corpus (one JSONL line per build attempt) that grounds advisory citations such as "3 of your last 5 builds failed at squashfs".
- `commands/`: lightweight command renderers used by CLI facades.
- `ui/`: Qt desktop application.
- `data/`: bundled TOML catalogs for releases, desktops, profiles, derivative profiles, personas, and branding palettes.
- `tests/`: regression tests for core behavior and command smoke checks.

## Build Flow

`core.build.BuildOrchestrator` owns execution. It emits `BuildStep` records for planning,
progress, provenance, and reports. The plan is deliberately dry-run friendly: callers can
inspect the full build sequence without touching root-owned ISO content.

`BuildOrchestrator.run` is a thin driver: the source-to-ISO stages live in
`core/build_pipeline.py` (`run_preflight`, `build_services`, `acquire_source`,
`configure_repositories`, `customize_target`, `assemble_iso`) and share a `BuildServices`
boundary. The extraction preserves the dry-run command history and the `plan()` step
sequence verbatim, so CLI/GUI parity is unchanged.

The high-risk services share the same rules:

- Accept explicit option dataclasses.
- Use `CommandRunner` for system commands.
- Respect `runner.dry_run`.
- Keep filesystem writes scoped to the project root, workdir, output dir, or target rootfs.

Extracted rootfs and ISO trees are permission boundaries. Services that write inside
`work/filesystem` or `work/iso` must use `core/fsops.py` instead of direct
`Path.write_text`, `Path.mkdir`, `shutil.copy*`, `Path.rename`, `chmod`, or tree removal.
`FileSystemOps` keeps dry-runs inspectable with virtual command events and, during
execution, retries protected writes through the configured privilege helper. This is a
cross-cutting architecture rule, not a per-service convenience.

Services that currently rely on `FileSystemOps` include APT sources, mirror policy,
release track, PPA sources/keyring directories, branding, debranding, customization,
network, kiosk, OEM, reproducible hints, system sync helpers, autoinstall, seeds,
Casper metadata, bootstrap ISO scaffolding, chroot bind-mount targets, and staged chroot
hooks. Host-only artifacts such as reports, recipes, release artifacts, and GUI profile
exports may still use normal host filesystem writes.

The maintainer terminal has two host backends. The classic `chroot` backend remains the
build default for compatibility with package operations and existing dry-run contracts.
When the host provides `systemd-nspawn` from `systemd-container`, the terminal can use an
optional `nspawn` backend for a stronger interactive shell. That backend is host tooling:
it must not be installed into the target rootfs or used to mutate hermetic build chroots
unless an explicit future workflow asks for it. `distroforge chroot-backends` exposes the
configured mode and the resolved active backend for scripts and the Maintainer cockpit.

Rollback snapshots are part of the same reliability boundary. `SnapshotService` prepares
`work/snapshots`, writes archives to `.part`, publishes only after `tar` succeeds, and
uses the configured privilege helper when reading or restoring protected rootfs content.
Snapshots are not a cosmetic feature; they are the recovery contract around risky phases.

Maintainer evidence is modeled as read-only status data before it becomes a release
artifact. `distroforge evidence-status` aggregates host capabilities, chroot backend
resolution, packaging policy, planned QEMU scenarios and existing artifact files without
building, installing or booting anything. The Maintainer cockpit uses the same model so
CLI and GUI review the same evidence state. Evidence bundle contracts are validated by
`distroforge evidence-verify`, keeping contract parsing and missing-file checks in one
source-only path shared by CLI and GUI.

## Extension Points

- Local scripts under project `hooks/`.
- Local plugins under project `plugins/`.
- Optional Pluggy plugin hooks when `pluggy` is installed.
- JSON/YAML image definitions for reproducible presets.

## Capture and Image Workflows

Installed-system capture is a separate read-only workflow. It scans a target root,
extracts reproducible intent into a YAML profile, and records what was captured,
ignored, dangerous, or not reproducible. The profile can then be rebuilt through the
normal builder instead of cloning the source system.

Related modules:

- `core/capture.py`
- `core/capture_sources.py`
- `core/capture_sanitize.py`
- `core/capture_report.py`
- `core/capture_schema.py`
- `core/live_build.py`
- `core/livefs_iso.py`
- `core/upgrade_media.py`
- `core/systemd_image.py`

The GUI surface is **Capture & Images** and must remain in parity with the CLI commands
registered in `core/command_registry.py`.

## Derivative Profiles

Derivative profiles describe downstream distribution intent without pretending to mirror
a private vendor ISO pipeline. They record base family/release, repositories, keyrings,
identity packages, installer, live session, hardware channel, branding, and optional
Dockerfile build hints.

Related modules:

- `core/derivative_profile.py`
- `data/derivatives.toml`

The GUI surface is **Packages** and must remain in parity with `derivative-profiles` and
`derivative-profile`.

## Artifacts and Release Review

Release readiness is intentionally separate from build execution. It summarizes host
artifact paths, checksums, release manifests, QEMU smoke coverage, trademark review, and
repository trust warnings.

Related modules:

- `core/artifact_paths.py`
- `core/buildinfo.py`
- `core/packaging.py`
- `core/release_readiness.py`
- `core/qemu_smoke.py`
- `core/capture_diff.py`

The GUI surface is **Artifacts** and must remain in parity with `artifact-paths`,
`release-readiness`, `qemu-smoke-plan`, `buildinfo-report`, `packaging-policy`, and
`hermetic-build-plan`.

Recent entrypoints are split into small command/page adapters:

- `commands/artifacts.py`
- `commands/capture.py`
- `commands/derivative.py`
- `commands/livefs.py`
- `commands/packaging.py`
- `ui/artifacts_page.py`
- `ui/capture_page.py`
- `ui/packages_page.py`

## Supply Chain and Cross-Architecture

CVE scanning, standard SBOM export, and cross-architecture bootstrap are optional build
modules that satisfy the same module gates as the rest of the pipeline: deterministic
option dataclasses, validation before execution, dry-run command history, no direct
protected rootfs/ISO writes, a CLI flag with a matching GUI widget, and regression tests.

Related modules:

- `core/vulnscan.py`
- `core/provenance.py`
- `core/bootstrap.py`
- `data/vulndb.json`

CVE scanning runs as the `VULN_SCAN` phase and fails closed under a blocking policy. SBOM
export writes SPDX-2.3 or CycloneDX 1.5 next to the native provenance document.
Cross-architecture bootstrap requires `qemu-user-static` when the target arch differs from
the host. See `docs/build-pipeline.md`.

## Refactor Direction

The codebase is being moved toward thinner entrypoints and domain-specific option mappers.
New features should prefer `core/` services plus small command adapters instead of growing
`cli.py` or `ui/main_window.py`. Optional modules must be gated by validation, dry-run
history, CLI/GUI parity, documentation, and regression tests before they are treated as
part of the reliable source-to-ISO path.

## GUI Parity

Every public CLI command must have a matching GUI surface for the same workflow.
Long-running workflows must expose GUI progress, and build/dry-run progress should follow
the `BuildOrchestrator` step cycle. See `docs/gui-parity.md`.

Every build option should either map to a GUI widget or have a documented exception. The
Command Center shows the current GUI-to-CLI equivalent so users can learn the CLI while
using the desktop app.

## Responsive Layout

The desktop shell must stay usable on every desktop environment and at narrow window
widths; no controls may be clipped off the right edge. Each page is wrapped by
`ui/widgets.scroll_page`, and rows of actions or fields use `ResponsiveRow`, which flows
its children onto as many columns as the *given* width allows and reports a single-column
minimum width. That minimum lets the enclosing scroll area always shrink a page to the
viewport instead of latching wide and clipping content; the horizontal scrollbar is a
last-resort safety net (`ScrollBarAsNeeded`). Heavy action bars are split into captioned
`button_group` clusters so dense pages stay scannable without renaming any action.
Jargon-heavy fields carry explanatory tooltips, and the development-suite field is left
empty with a placeholder because it resolves to the target release codename. These
guarantees are locked by `tests/test_ui_responsive.py`.

## AI Boundary

The local AI layer is advisory only. It may suggest schema-validated definitions, explain
risks, review readiness/dry-run reports, and cite log lines through ForgeAdvisor, but it
must not execute builds or mutate the host without an explicit user action outside the
assistant layer.

ForgeAdvisor defaults to the always-available `offline` backend: deterministic local
heuristics over logs, readiness, and dry-run findings, grounded in the host-owned
build-memory corpus (citations are read from it, never invented). Optional `llama` and
`ollama` backends are thin shell-out shims that only *rephrase* that context into a short
narrative; they ship no model weights, and any missing binary, missing model, error, or
timeout degrades them back to offline. Future `llama.cpp`, Ollama, embeddings, or ONNX
backends must preserve the same citation-first contract and remain optional.
