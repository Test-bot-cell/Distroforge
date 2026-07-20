# DistroForge Platform Architecture

DistroForge is an operating-system forge, not a remix script. Its core job is to take a
known source, apply policy-controlled changes, and produce a bootable, reviewable,
redistributable ISO through a pipeline that can be understood by beginners and trusted by
maintainers.

The product must keep one reliable reference path from source to ISO, then let advanced
modules plug into that path without weakening it.

The executable workflow map lives in `core/workflows.py`. The guided build journey lives
in `core/build_journey.py`. Together they are the product taxonomy used by readiness
diagnostics, next-action recommendations, CLI `journey`, and the GUI Command Center, so
feature purpose and user level are not only prose.

`WORKFLOW_LEVELS` in `core/workflows.py` is the single source of truth for the four
beginner→developer levels. The build journey (`core/build_journey.py`), the `journey
--level` CLI choices, and the GUI mode selector all derive their level vocabulary from it
instead of keeping a private copy. Each persona in `data/personas.toml` declares a
validated `level` that binds its build-option preset onto the same four levels (Beginner
and Balanced map to beginner, Power user to power-user, Maintainer to maintainer, and
Developer maintainer to developer), so persona, journey, and UX audit speak one coherent
level language.

## Product Levels

- **Beginner**: choose a source, desktop, language, branding preset, package profile, and
  output path. The GUI explains readiness, privilege state, snapshots, and final artifacts
  without requiring terminal log reading.
- **Power user**: edit repositories, mirrors, PPAs, snaps, users, services, autoinstall,
  OEM/kiosk/network modules, and rollback behavior. Every option is visible as a CLI
  equivalent.
- **Maintainer**: review policy, trademark clearance, release readiness, provenance,
  QEMU smoke plans, packaging reports, and ForgeAdvisor findings before publishing.
- **Developer**: extend source starters, services, plugins, tests, and page adapters
  while preserving the same build contracts.

The UX self-audit (`distroforge ux-audit` and the GUI UX audit panel) checks persona
friction across all four canonical levels, with one audit path per level keyed on the same
`WORKFLOW_LEVELS` vocabulary so no level is left unaudited. Beginner covers source/desktop
and sanitize safety; power-user covers rollback, system sync and kernel work; maintainer
covers release artifacts, provenance, QA and kernel integrity; developer covers the
extension surface — plugins and imported chroot hooks stay behind rollback snapshots, and
upstream desktop-source builds stay SHA256-pinned and reproducible.

## Build Journey

`distroforge journey PROJECT --level beginner|power-user|maintainer|developer` exposes
the same step model shown in the GUI Command Center. `distroforge journey PROJECT
--apply STEP` turns a journey step into a safe starter mutation or build definition.
It guides users through:

1. source selection;
2. desktop, profile, packages and identity;
3. dry-run/readiness review;
4. deployment behavior;
5. rollback for risky mutation;
6. boot proof;
7. release evidence;
8. maintainer publish gate;
9. extension contracts.

Beginner journeys stay short and didactic. The dry-run/readiness review step is honest, not
a free pass: it is satisfied only when the plan validates cleanly through the same
`validate_for_build` configuration check the readiness and dry-run reports use, so a beginner
is never told the plan was reviewed while a blocking configuration error (such as a missing
source) remains. Maintainer journeys add boot proof and release
evidence, then block on the publish gate until ISO, SHA256SUMS, source trust, boot proof
and policy evidence are present. The publish-gate step also weaves the maintainer
release-confidence ritual into its check and next action — `sign-release`, `verify-release`,
a `publish-drill-diff` against a promoted baseline, and the configured CVE scan policy —
reporting the real status of any existing signing, verification and baseline reports as
advisory guidance that never blocks the gate itself. Developer journeys keep hooks/plugins behind tests, docs
and parity contracts.
The GUI Command Center exposes the same contract through **Open current step** and
**Apply current step**, so the desktop app is not merely informational. The guided journey **spine** (the shell
home) is the primary user-facing journey surface: it renders the steps as a single ordered,
level-gated spine and routes each to its focused panel. Navigation is never level-gated —
the header palette enumerates every surface — so the **Start** page and **Command Center**
stay reachable at every level and still render the journey as visual Qt cards with per-step
open, apply and check actions.
`journey --check STEP` exposes the same card checks to CLI and CI callers. Command Center
remains the deeper audit surface for parity and capability maps.
`distroforge beginner-iso PROJECT --apply-safe-defaults --dry-run` prepares the beginner
source-to-ISO path. Adding `--execute` runs the same `BuildOrchestrator` as the normal
build command, writes a command log, and reports the maintainer release gate status after
the build attempt instead of pretending the ISO is publishable before artifacts exist.

## Core Invariants

1. **One pipeline owner**: `BuildOrchestrator` orders phases, emits `BuildStep` progress,
   and records enough context for CLI, GUI, provenance, and reports.
2. **One command boundary**: host commands go through `CommandRunner`; dry-runs record
   inspectable command intent instead of mutating state.
3. **One filesystem boundary**: anything under extracted `work/filesystem` or `work/iso`
   uses `FileSystemOps` or an explicit service contract that honors the same privilege
   backend.
4. **Snapshots are transactional**: rollback snapshots create their parent directory,
   write to `.part`, publish only after `tar` succeeds, and use the privilege helper when
   reading or restoring a protected rootfs.
5. **Host artifacts stay host-owned**: reports, manifests, provenance, release artifacts,
   docs, presets, and GUI exports use normal host writes.
6. **CLI/GUI parity is non-negotiable**: public workflows need a command mapping, a GUI
   surface, progress when long-running, and documentation.
7. **AI is advisory**: ForgeAdvisor can explain logs, readiness, risks, and recipes with
   citations, but it does not mutate the build without an explicit user action.

## Reference Source-To-ISO Path

The dependable reference path is intentionally explicit:

1. source starter or source ISO validation;
2. project and host preflight;
3. rootfs/ISO preparation;
4. APT source configuration;
5. package/customization/branding application;
6. rollback snapshots around risky phases;
7. sanitation and metadata refresh;
8. squashfs, checksums, ISO rebuild;
9. release artifacts, provenance, and readable report.

Anything outside this path is an optional module. Optional modules must be able to say
"disabled" cleanly in plan, dry-run, GUI, and docs.

## Module Gates

Advanced modules are allowed only when they satisfy all gates:

- option dataclass with deterministic defaults;
- validation errors before execution;
- dry-run command history;
- no direct protected rootfs/ISO writes;
- CLI flag and GUI widget or documented exception;
- at least one regression test for the module contract;
- docs updated in `architecture.md`, `build-pipeline.md`, or a focused module document.

## UX Rules

The GUI should teach by showing state, not by dumping logs. Build Controls must expose:

- privilege helper state;
- snapshot behavior;
- source trust and readiness;
- next recommended action for the current project state;
- current GUI-to-CLI equivalent;
- progress by build phase;
- final artifact paths and review status.

Logs remain available for diagnosis, but the main experience should guide a beginner
through decisions and give a maintainer enough proof to trust the output.

A beginner should never be blocked by unfamiliar vocabulary. DistroForge ships a didactic
glossary in `core/education.py`, reachable through `distroforge glossary [term]`, that
defines the ISO-build terms surfaced across the CLI, GUI and audit text — snapshot,
provenance, SBOM, reproducible, rootfs, debootstrap, Secure Boot, UEFI/BIOS, subiquity,
autoinstall and the rest of the domain language. Any term the product shows a user must
have a glossary entry, so the teaching surface stays honest as features grow.

Build guidance copy lives outside the shell window in `ui/build_guidance.py` so user-level
language, privilege explanations and snapshot safety text can be tested without growing the
main GUI monolith. The Build & Release page layout lives in `ui/build_page.py`; the shell
window owns navigation instead of owning that page's composition. Build execution dispatch
for plan, dry-run, execute, progress and snapshot recovery lives in `ui/build_controller.py`.

The GUI's colour identity is autonomous and GNOME-native. `ui/palette.py` transcribes the
official GNOME HIG palette (https://developer.gnome.org/hig/reference/palette.html) verbatim
and maps a single semantic set on top of it — primary/secondary accent, plus success,
warning, error and info — sourced entirely from those named colours. The accent is GNOME
Blue, never the Ubuntu orange or aubergine, so DistroForge reads as its own GNOME-native tool
rather than a Canonical / Vanilla-framework derivative; the reserved state hues (green/amber/
red) are never reused as the accent, so the accent can never be mistaken for a status signal.
`ui/theme.py` is the only consumer of that palette for window chrome and still follows the
host's light/dark *scheme* (via `app.palette()`) while keeping one palette as the source of
truth for the surfaces and signals themselves.
