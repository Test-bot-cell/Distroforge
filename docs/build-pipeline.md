# Build Pipeline

Use `distroforge iso-doctor PROJECT` when the immediate question is why an ISO has not
been produced yet. It checks source selection, host tools, the output ISO target and the
current build posture, then returns one next command.

Use `distroforge iso-build PROJECT --execute --boot-proof auto` for the guarded
one-command ISO path. Without `--execute`, it remains a dry-run and writes
`dist/ISO-BUILD.json`.

Executed ISO builds are marked `built` only when the configured output ISO exists, is
non-empty, and has a recorded SHA-256 digest. A completed build attempt without that
artifact stays `blocked`; dry-runs stay `planned`.

Use `distroforge iso-accept PROJECT --iso dist/Image.iso` after a real build to get the
publication verdict. It accepts only an ISO that matches `ISO-BUILD.json`, has a ready
boot proof, and passes the release gate; otherwise it writes `ISO-ACCEPTANCE.json` with
the next command to run.

Use `distroforge demo-iso PROJECT --execute` to create or reuse a minimal skeleton
project and try the shortest local ISO path on the current host. Without `--execute`, it
writes `DEMO-ISO.json` as a dry-run guide; with `--execute`, it runs doctor, ISO build,
boot proof, and acceptance when host tools allow it.

Use `distroforge iso-toolchain` when `iso-doctor` or `demo-iso` reports missing host
tools. It checks only the ISO build toolchain and prints one apt command; `--install`
runs that installation explicitly.

The build pipeline is ordered to fail early, keep dry-runs useful, and leave auditable
artifacts at the end.

The final ISO is a host artifact. CLI users can pass `--output-iso`; GUI users select the
same path from **Advanced Modules** with **Output ISO**, including a host save-file chooser.
When unset, DistroForge falls back to the project output defaults.

Build options are governed by `commands/build_contracts.py`. Each option is assigned to
Beginner, Power user, Maintainer, or Developer level, plus an expected GUI surface. The
contract is tested against the parser and GUI so the build cycle remains explicit instead
of accumulating hidden flags.

Release review is exposed separately from build execution:

```bash
distroforge artifact-paths /path/to/project
distroforge release-readiness --iso /path/to/image.iso --output-dir /path/to/output
distroforge qemu-smoke-plan --iso /path/to/image.iso
```

The GUI **Artifacts** page presents the same host paths, release readiness summary, and
QEMU online/offline install smoke matrix.

1. Resolve the source starter: skeleton, official ISO/netboot, local ISO, or previous project.
2. Validate project, host, and option contracts.
3. Check source trust metadata, consistency, safety policy, and release compatibility.
   Execution writes `out/compatibility-report.txt`; dry-runs record the same report as a
   virtual command event.
4. Plan a transaction id, import legacy scripts and preview the requested diff.
5. Prepare workspace and source rootfs by skeleton bootstrap or ISO extraction.
   Locked rootfs boot artifacts are copied into `casper/` through the configured
   privilege helper so root-owned or `0600` kernel files do not break execution.
   Existing valid bootstrap rootfs directories are reused on retry; non-empty incomplete
   rootfs directories stop with a cleanup message instead of rerunning debootstrap into
   stale files.
   Cross-architecture bootstrap is supported through `--bootstrap-arch`. When the target
   arch differs from the host, the build requires `qemu-user-static` so foreign binaries
   run during debootstrap; non-BIOS arches such as arm64 skip the El Torito BIOS image.
   GUI builds use `sudo` by default. When no terminal is attached, DistroForge uses
   graphical `sudo -A` if an askpass helper such as `ssh-askpass-gnome` is available;
   otherwise preflight stops before the first privileged command with setup guidance.
   `pkexec` remains an advanced opt-in backend because long builds may trigger repeated
   polkit prompts or dismissed authorization requests.
   When `pkexec` is selected, helper commands are resolved to absolute paths such as
   `/usr/bin/install` before polkit authorization.
6. Configure APT, cache, PPAs, release track, and system sync.
   Files written inside the extracted rootfs use the shared `FileSystemOps` layer. This
   includes `etc/apt/sources.list`, deb822 mirror files, PPA source lists, release-track
   pins, apt proxy/cache snippets, and post-install sync helpers. Direct Python writes are
   reserved for host artifacts, not rootfs state.
   Each managed overlay is rewritten as a pure function of the current options: the release
   track, apt cache, apt proxy and PPA services shed their own previously written files before
   (re)writing, so a reused rootfs or unsquashed ISO tree cannot inherit a dropped option's
   config — a removed PPA, a disabled cache, or a stale `APT::Default-Release "devel"` pin can
   no longer resurrect to fail the next build. On bootstrap reuse the rootfs additionally sheds
   every DistroForge apt overlay before the live-base install runs apt.
   The chroot runtime that hosts these phases is hardened on entry: each `/dev`, `/dev/pts`,
   `/proc`, `/sys` and `/run` bind mount is detached with `mount --make-rslave` so a later
   unmount cannot leak into the host mount namespace, and a `policy-rc.d` that exits 101
   stops package postinst from starting daemons against a chroot with no real init. APT runs
   with `DEBIAN_FRONTEND=noninteractive` so debconf never blocks on a prompt. The block is
   removed and the binds are lazily unmounted on exit, so `policy-rc.d` never ships in the
   image.
7. Apply packages, snaps, drivers, desktop source builds, size reports, and CVE scanning.
8. Create rollback snapshots around risky phases when enabled. Snapshot archives are
   written to `work/snapshots/*.tar.zst.part` and promoted to `*.tar.zst` only after
   `tar` succeeds; creating and restoring snapshots uses the configured privilege helper
   because the rootfs may contain files that the normal user cannot read or overwrite.
9. Apply customization, branding, users, systemd, network, kiosk, OEM, kernel, and Secure Boot.
   Debranding scans identity text such as `etc/os-release`; protected rootfs files are
   rewritten through the configured privilege helper instead of direct Python writes.
   Branding, wallpaper, locale, hostname, Netplan, kiosk autostart, OEM markers,
   autoinstall, seeds, Casper metadata, and staged chroot hooks follow the same rule.
10. Run hooks/plugins, sanitize target, and produce health status.
11. Generate autoinstall, seeds, metadata, squashfs, checksums, and ISO.
12. Produce release artifacts, boot checks, screenshots, provenance, HTML report, and QA matrix.

Dry-run builds should produce command history and findings only. The dry-run report checks
validation, required host tools, source trust, policy, dirty artifact directories, bootstrap
rootfs reuse/incompleteness, locked boot artifacts and privilege-helper intent. If a service
needs to write during dry-run, that write should be represented as a `CommandSpec` such as
`write-file` instead.

Before execution, `distroforge readiness` should be clean enough for the selected mode:
source SHA/GPG state, host tools, policy findings, transaction paths, timeline and diff
preview must all be reviewable without producing package artifacts.

Source starters are a first-level product entry. Ubuntu 26.04 and Debian 13.5 both expose
minimal skeleton starters for CLI-only seed images, plus official ISO/netboot choices whose
download and checksum locations are visible before injection into a project. Local ISO and
previous-project starters keep the selected path in `project.json` so the source is never
hidden in an advanced build option.

The QEMU lab is the virtualization gate for build confidence. It runs QEMU under QMP
control, writes a serial log, optional screenshot, pid file, QMP socket path, artifact
checksums, and a `qemu-lab-report.json` summary. UEFI uses a writable OVMF variables
copy, TPM mode starts `swtpm`, and success markers are checked from the serial log before
release artifacts are trusted.

Every QEMU command line — the lab, the boot screenshot, the interactive preview, the
install smoke matrix, the boot-check and the QA matrix — is built from one canonical
`QemuInvocation` in `core/qemu_invocation.py`, so the argv stays auditable and consistent
instead of drifting across call sites.

The interactive preview is the drivable, human-facing counterpart to the headless lab.
`distroforge preview PROJECT` plans the session as a dry-run and prints the exact QEMU
command; `--execute` actually launches it. `--display` selects `gtk`, `spice`, or `none`:
`spice` maps to QEMU `-display spice-app`, which starts a SPICE server and opens the
bundled viewer, so the host needs `virt-viewer`; `none` is the headless, QMP-driven mode.
Every session is daemonized with a QMP socket and a pid file so it stays drivable and
stoppable, writes a serial log, and records a JSON `preview-session.json` transcript plus a
`PREVIEW-INTEGRITY` manifest so the run is traceable. The GUI **Virtualization** page
exposes the same surface through the **Preview ISO** action and the **Preview display**
selector, and the in-build `--preview` option reuses the same service once the ISO is
assembled.

Declarative interaction plans turn a QEMU session into scenario-as-data.
`distroforge qemu-interaction PROJECT --plan PLAN` plans a headless, QMP-driven run as a
dry-run and prints the exact command plus every step; `--execute` launches it. A plan is a
typed list of steps — `wait-serial`, `wait`, `screendump`, `sendkey`, `query-status`,
`quit` — carried as JSON so it stays auditable and reproducible. `--plan` resolves a JSON
file, a built-in plan (`boot-capture`, `headless-status`), or a smoke-matrix scenario by
name; `--list` prints every available plan. The same canonical `QmpControl` drives the
headless lab, the boot screenshot, and the interaction service, so there is one QMP engine
instead of divergent copies. This is what makes the QEMU install smoke matrix executable: each smoke scenario
maps to an interaction plan that boots the ISO, proves it reaches a login prompt, captures
the screen, and shuts down. The run records a deterministic `qemu-interaction-report.json`
and an `INTERACTION-INTEGRITY` manifest. The GUI **Virtualization** page exposes the same
surface through the **Run interaction** action and the **Interaction plan** selector.

## Phase contracts

`BuildOrchestrator.run` drives the source-to-ISO path as ordered stages over a shared
`BuildServices` boundary: `run_preflight`, `build_services`, `acquire_source`,
`configure_repositories`, `customize_target`, and `assemble_iso`. `build_services` only
constructs the shared services and emits no user-facing phase, so it carries no contract.

Every phase over that boundary has a declarative contract in
`distroforge/core/phase_contracts.py`:

- **title** — the user-facing phase name shared with `plan()` and progress events;
- **stage** — the pipeline stage that owns the phase;
- **inputs** — what the phase consumes;
- **artifacts** — what the phase produces;
- **privileged** — whether the phase mutates protected rootfs/ISO state (the squashfs root
  or ISO tree) or otherwise needs the privilege helper when active;
- **rollback** — the snapshot points the phase creates, when any.

Render the catalog with `distroforge build-phases`; `--stage STAGE` scopes the output to a
single stage (`run_preflight`, `acquire_source`, `configure_repositories`,
`customize_target`, or `assemble_iso`). The GUI **Command Center** surfaces the same text
through **Show build phase contracts**, so the CLI and GUI read from one renderer.

Only two phases declare rollback points, matching step 8 above: `snapshot` creates
`after-apt`, `after-customize`, and `after-sanitize`, and `kernel_module` creates
`before-kernel` and `after-kernel` when a module build is enabled. The catalog is
honesty-tested against a real dry-run: every phase that touches protected rootfs/ISO state
is declared privileged, host-only phases never are, and the observed snapshots match the
declared rollback points exactly.

## Progress model

The build steps come from one canonical sequence. `build_phase_sequence` in
`core/build_sequence.py` produces the ordered `PlannedStep` list for the active
`source_mode` and `run_preview` choice. `BuildOrchestrator.plan()` returns exactly that
sequence, and `run()` emits each step through the same list: `_step` checks the emitted
phase and title against the next expected `PlannedStep` and raises on any drift. The GUI
step list is therefore the run plan — they cannot diverge into different counts, which is
why the GUI denominator no longer inflates itself with a `max()` fallback.

Progress is weighted, not counted. Each `PlannedStep` carries a relative `weight`, and the
overall fraction is completed weight over `total_weight`, not step index over step count.
Heavy phases — source extraction, package application, squashfs pack, and ISO rebuild —
dominate the bar, while light host-only steps advance it only slightly, so the bar tracks
real work instead of jumping a fixed amount per step. The GUI bar runs on a fixed 0–1000
integer scale driven by that fraction; the CLI prints the same percentage next to the
`index/total` counter and a closing `100.0%` line.

Each step opens a weight band `[band_start, band_start + band_width)`. Heavy external
commands stream their output line by line through `CommandRunner.run_streaming`, and the
per-tool parsers in `core/progress_parsers.py` turn a recognized line into a 0–1 fraction
that fills the current band through `_phase_progress`. The progress shapes were captured
from the real tools (squashfs-tools 4.7.5, xorriso 1.5.6) over a pipe — the production
path — and pinned as fixtures under `tests/fixtures/progress/`, because how much a band
fills in practice depends entirely on what each tool actually emits:

- **apt** is the one heavy command that streams a true fraction. With `APT::Status-Fd=1`
  (added only when a progress callback is active in execute mode) it prints an explicit
  per-item percentage that fills the band smoothly.
- **mksquashfs / unsquashfs** print only the final `[===] N/M 100%` bar frame over a pipe
  (the live redraw is tty-gated), then emit closing statistics whose percentages are not
  progress. `squashfs_progress` reads only the bracketed bar — so those statistics cannot
  drive the bar backwards — which means the squashfs bands jump to full at completion
  rather than filling continuously.
- **xorriso** reports file and node counts (`64 files restored`), never `% done`, so the
  ISO extract and rebuild bands carry no sub-progress on this toolchain and simply complete
  at their step boundary.

Sub-progress is an execute-mode behavior: dry-runs and the no-callback path use the plain
`run()` so command history stays identical. Every parser returns `None` for anything it
does not recognize, so a future tool-format change degrades the bar to step-level
granularity rather than raising. The offline fixture tests lock these shapes against the
captured output without executing any tool, so the suite stays deterministic, network-free
and rootless under CI, buildd and autopkgtest. When the toolchain is upgraded, re-capture
the fixtures by hand (each fixture header records the tool, version and capture method) and
re-pin them — the suite never runs a heavy tool itself, by design.

## Boot record reproduction

The ISO rebuild does not guess how to make the image bootable. In execute mode it asks the
source ISO to describe its own boot setup with `xorriso -indev <source> -report_el_torito
as_mkisofs` and replays that description verbatim, overriding only the volume id, output
path and modification date. Because the report is xorriso's own faithful, round-trippable
account of the source's El Torito record, this reproduces whatever the source actually had
— BIOS isolinux/GRUB, a UEFI El Torito alt-boot entry, or a modern appended EFI System
Partition pulled straight from the source bytes via `--interval` — without DistroForge
needing to interpret those tokens. This is the Debian/xorriso-recommended remaster path and
it replaces the earlier brittle file-path guessing that silently dropped UEFI boot on
recent Ubuntu layouts.

A generic `BootLayout.detect()` scan remains as an explicit fallback for when there is no
source ISO to interrogate (bootstrap mode) or the source reports no boot record. The probe
runs only in execute mode, so dry-run plans build nothing and their rebuild command stays
byte-identical to the detection path.

Verification is honest about its boundary: offline tests pin a real (BIOS-only) `as_mkisofs`
capture and a UEFI-shaped forwarding case, proving the parser drops the options we own and
forwards every boot/partition token — including EFI/appended-partition tokens — verbatim.
Confirming a rebuilt ISO actually boots under UEFI on current releases is a maintainer step
on real hardware or a real target ISO, since the suite builds no artifact by design.

## Supply-Chain and Cross-Architecture Modules

Three optional modules extend the reference path without weakening it. Each can say
"disabled" cleanly in plan, dry-run, GUI, and docs, and each is governed by the build
option contract in `commands/build_contracts.py`.

### CVE scanning

`--vuln-scan` runs the `VULN_SCAN` phase after packages are resolved. `--vuln-policy`
selects the posture:

- `off` records findings only;
- `warn` (default) reports findings without blocking;
- `block-high` promotes high and critical findings to errors;
- `block-critical` blocks only critical findings and leaves high as a warning.

The scanner matches the planned package set by name against a bundled advisory database and
records a `vuln-report` virtual command event carrying the status and finding count, so
dry-runs stay inspectable and real builds never try to exec a `vuln-report` binary. The build fails closed: a blocking finding raises before any ISO is
produced. `--vuln-db PATH` points at a custom advisory JSON; a database that cannot be read
is surfaced as a `DB-UNAVAILABLE` warning, never a silent pass to clean.

### Standard SBOM export

`--sbom-format` selects the Software Bill of Materials emitted in the provenance phase:

- `native` (default) writes only `distroforge-provenance.json`;
- `spdx` also writes `distroforge-sbom.spdx.json` (SPDX-2.3 with package PURLs and
  `DESCRIBES` relationships);
- `cyclonedx` also writes `distroforge-sbom.cdx.json` (CycloneDX 1.5 with an
  operating-system root component and library components).

The standard SBOM is written next to the native provenance document, so a published bundle
can carry a vendor-neutral component inventory.

### True cross-architecture bootstrap

`--bootstrap-arch` builds a foreign-architecture image, such as arm64 on an amd64 host.
GRUB packages are architecture-aware: amd64 keeps `grub-pc-bin` plus `grub-efi-amd64-bin`,
while arm64 drops the BIOS package and uses `grub-efi-arm64-bin`. The kernel meta-package
stays `linux-generic` on Ubuntu. A cross-arch target requires `qemu-user-static`; native
builds add no qemu requirement.
