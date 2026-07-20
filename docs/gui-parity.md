# CLI / GUI Parity Contract

DistroForge treats CLI and GUI parity as a release requirement.

Every public `distroforge` subcommand must have:

- a registered `CommandGuiMapping` in `core/command_registry.py`;
- a concrete GUI surface where the same workflow can be started, inspected, or reviewed;
- a progress bar or equivalent progress surface when the command can run long enough to need user feedback.

Build and dry-run flows use the `BuildOrchestrator` step cycle for determinate GUI progress.
Adding a CLI command without a GUI mapping must fail tests.

Build options must map to widgets where practical; documented exceptions are allowed only
for argparse help, execution confirmation, and workflows covered by import/export actions.
GUI screens should expose a readable CLI equivalent for the current settings.
The CLI `readiness` output and GUI Readiness panels must both include next recommended
actions from the same `core/workflows.py` recommendation engine.
The CLI `journey` output and GUI Command Center must both render the guided build journey
from `core/build_journey.py`. CLI `journey --apply STEP` and GUI **Apply current step**
must use the same `apply_journey_step` logic, while GUI **Open current step** navigates to
the matching surface. The GUI Command Center must also show CLI/GUI command parity and the
product workflow map so advanced features remain tied to their purpose and user level.
CLI `build-phases` maps to the Command Center **Show build phase contracts** action; both
render the per-phase contracts (inputs, artifacts, privileges, rollback points) from
`core/phase_contracts.py`, and `--stage STAGE` scopes the catalog to one pipeline stage.
The guided build journey **spine** is the primary user-facing journey surface: the shell
home (`ui/journey_shell.py`) renders the steps from `core/build_journey.py` as a single
ordered spine, level-gated for progressive disclosure, and routes each step to its focused
panel. Each panel leads with a step banner (`ui/step_focus.py`) stating that step's what,
why and live status plus a single **Apply this step**/**Check** pair, all sourced from
`core/build_journey.py`. Where several steps share one heavy surface — `rollback` rides the
Build & Release page, `publish-gate` rides the Artifacts page — that surface keeps one
banner that retargets to the routed step instead of stacking peer banners, so the panel
always shows the step the journey opened and plain navigation restores the surface's
canonical step. Navigation itself is never level-gated: the header "Open tool…" palette is a
keyboard-first action index — an editable, type-to-filter command palette (focus it with
**Ctrl+K**) that enumerates every surface *and* every guided journey step, routing surface
entries through the same surface router and journey entries to the step's focused, retargeted
banner. The router opens any of them at any level, so an advanced or CLI-fluent user always
reaches every surface — the level-independent escape hatch shared with the UX
cognitive-ergonomics pillar (`docs/ux-cognitive-ergonomics.md`). The **Start**
page and the **Command Center** remain journey surfaces and stay reachable at every level:
they render visual Qt cards for each step with status, level, goal, GUI/CLI target, and
per-step **Open**/**Apply**/**Check** actions, plus **Prepare beginner ISO path** and
**Build beginner ISO** actions for preparing or executing the safe source-to-ISO workflow. CLI `journey --check STEP` returns the same status used in the cards,
including JSON for automation. The maintainer journey must include `publish-gate`, which
delegates to `release-gate` and blocks publication until ISO, SHA256SUMS, source trust,
boot proof and policy evidence are valid. The `publish-gate` step also weaves the maintainer
release-confidence ritual into its check and next action — `sign-release`, `verify-release`, a
`publish-drill-diff` against a promoted baseline, and the configured CVE scan policy — as advisory
guidance that surfaces the real status of any existing signing, verification and baseline reports
without blocking the gate; CLI `journey --check publish-gate` and the Start-page card **Check**
render the identical findings from `core/build_journey.py`. Command Center is the auditor view that also
includes parity and capability maps, and opens with a **What do you want to achieve?** goal hub — one
card per product capability (`core/workflows.py`) that routes intent straight to the GUI surface the
capability declares in its `gui_surface`, from the same single source the CLI parity map reads, so a
user who thinks in goals reaches the backing surface without first knowing its name.

CLI `glossary [term]` maps to the **First Run / docs** dialog: its read-only glossary panel
renders the same `core/education.py` definitions a user gets on the command line, so the
ISO-build vocabulary is reachable in the GUI and not only from a terminal.

CLI `guided-recipe` (no name) maps to the **Presets page** *Guided recipes* button: both
render the same `core/education.py` catalog through `render_guided_recipes()`, including the
`[profile: NAME]` tag that binds a recipe to a deterministic `data/profiles.toml` package
profile. Every package profile is covered by a guided recipe, so the curated source-to-ISO
starting points stay in step with the package profiles on both surfaces. `guided-recipe NAME`
expands the recipe prompt through the constrained recipe assistant, matching the AI recipe
preview shown in the GUI.

CLI `beginner-iso PROJECT --apply-safe-defaults --dry-run` maps to the Start prepare action.
Adding `--execute` maps to **Build beginner ISO**: it records a command log, invokes the
same `BuildOrchestrator` as the normal build command, and reruns the release gate after
the build attempt. In the GUI this runs as a background `GuiJob` with host preflight,
progress events and cancel support through the shared toolbar job controls.
`beginner-iso PROJECT --doctor` exposes the same host readiness check. `--install-missing-tools`
is explicit and maps to the GUI **Install missing tools** confirmation when the beginner
build preflight finds missing required tools.
`beginner-iso PROJECT --explain-last-failure` reads the beginner command log, classifies
common failure areas, and maps to the Start job result shown after a failed beginner build.
`beginner-iso PROJECT --repair-release-artifacts` maps to **Repair release artifacts** on
Start. It regenerates only derivable files from an existing ISO: `SHA256SUMS`, `BUILDINFO`,
`distroforge-provenance.json`, and the HTML report. It does not invent boot proof.
`beginner-iso PROJECT --run-boot-proof` maps to **Run boot proof**. The release gate treats
boot proof as ready only when an executed proof report such as `qemu-lab-report.json`
or `boot-proof.json` exists.
`poweruser-iso PROJECT --apply-safe-defaults --dry-run` maps to **Prepare power user ISO
path**. It extends the same source-to-ISO path with guarded advanced modules: deb822 mirrors,
autoinstall, explicit systemd service intent, auto drivers and rollback snapshots.
`publish-bundle PROJECT` maps to **Publish Bundle** on Start and Artifacts. It writes
`dist/publish/` as an inspection bundle with the ISO, release evidence, boot proof when
present, `RELEASE-GATE.json`, and `README-PUBLISH.txt`; blocked bundles are labelled as
blocked instead of being treated as publishable.
`sign-release PROJECT` maps to **Plan Sign Release** on Artifacts. It writes
`RELEASE-MANIFEST.json` and `SIGNING-REPORT.json`; without `--execute` it only plans GPG
detached signatures for `SHA256SUMS`, `RELEASE-GATE.json`, and `RELEASE-MANIFEST.json`.
`release-notes PROJECT` maps to **Release Notes** on Artifacts. It reads the publish
bundle manifest, gate and signing report, then writes `RELEASE-NOTES.md` and
`CHANGELOG.txt` for maintainer review.
`verify-release PROJECT` maps to **Verify Release** on Artifacts. It checks the manifest,
file sizes, SHA-256 digests, `SHA256SUMS`, release gate status and detached signatures when
they are present and `gpg` is available.
`iso-toolchain` maps to **ISO Toolchain** on Build & Release. It checks the host tools
needed to produce an ISO and prints the explicit apt install command.
`iso-doctor PROJECT` maps to **ISO Doctor** on Build & Release. It diagnoses why the
project has not produced an ISO yet and returns one next command.
`iso-build PROJECT --execute` maps to **ISO Build** on Build & Release. The GUI button
uses the executing build flow with confirmation, preflight, progress and logs.
`iso-accept PROJECT` maps to **Accept ISO** on Build & Release. It checks the produced ISO
against `ISO-BUILD.json`, boot proof evidence and the release gate, then writes
`ISO-ACCEPTANCE.json`.
`demo-iso PROJECT` maps to **Plan Demo ISO** on Build & Release. The label is explicit
because the GUI action renders the non-executing demo report; CLI `--execute` is required
to run the shortest demonstrable path toward a real ISO.
`explain-release PROJECT` maps to **Explain Release** on Artifacts. It writes
`RELEASE-EXPLAIN.md` with ready, review and blocked evidence, boot proof level and next
maintainer commands.
`publish-drill PROJECT` maps to **Publish Drill** on Artifacts. It rehearses boot proof,
release pipeline, signing plan, verification and explanation, then writes
`PUBLISH-DRILL.json` without signing unless explicitly requested.
`publish-drill-diff OLD NEW` maps to **Compare Drill** on Artifacts. The GUI compares
`PUBLISH-DRILL.previous.json` and `PUBLISH-DRILL.json` in the selected publish bundle.
`publish-drill-baseline PROJECT` maps to **Promote Drill** on Artifacts. It promotes the
current drill as the previous baseline unless that drill is blocked.
`release-pipeline PROJECT` maps to **Release Pipeline** on Artifacts. It repairs derivable
artifacts when an ISO exists, creates the publish bundle, plans or executes signing,
writes notes, verifies the bundle and records `RELEASE-PIPELINE.json`.
`boot-proof PROJECT --iso PATH --backend auto` maps to **Boot Proof** on Artifacts. It
tries QEMU runtime proof first, falls back to structural `iso-scan` when QEMU is unavailable
or blocked, and writes a normalized `boot-proof.json`. The release gate only accepts that
proof when its status is `ready`, not merely `planned` or `review`.

The build option contract lives in `commands/build_contracts.py`. It classifies every
`distroforge build` option by UX level, GUI surface, GUI token, default and exception
reason. Tests compare that contract against the argparse parser and GUI source so CLI/GUI
parity cannot silently drift.

Build option parity:

- CLI `--output-iso` maps to the GUI **Output ISO** field in **Advanced Modules**.
- **Output ISO** must provide a host file chooser so users can select the final ISO path
  on the DistroForge host instead of relying on an implicit project output location.
- More generally, **every filesystem-path field offers a native "Select" chooser** through a
  single `ui/path_actions.py` helper, so any host path can be picked from the file manager
  instead of typed by hand — input fields (source ISO, detached signature, MOK key and cert,
  OVMF firmware, brand image and theme/slideshow paths) and output or destination fields
  (output ISO, apt cache dir, reports/livefs/live-build dirs, JSONL log) alike. The chooser is
  a GUI *input affordance* over an existing capability: the matching CLI verb already accepts
  the same path as an argument, so it adds no CLI surface and parity is unchanged. Identifier
  fields that merely look path-like (GPG key IDs, workdir-relative runtime names, name-or-path
  duals) deliberately get no chooser, because a file picker would be the wrong affordance.
- CLI `--privilege sudo` maps to the default GUI **Use sudo for system operations** path.
  GUI sudo uses graphical `sudo -A` when an askpass helper is available; otherwise
  preflight blocks with setup guidance. GUI `pkexec` is advanced opt-in only because long
  builds may dismiss repeated polkit prompts.
- The GUI **Build Controls** section must show a plain-language privilege status line so
  users understand whether protected rootfs and ISO writes will use sudo, pkexec, or no
  helper. This keeps the desktop flow didactic without requiring users to read raw build
  logs.
- The same section must explain rollback snapshot behavior: snapshots are created around
  risky phases, staged as temporary archives, and published only after a successful `tar`.
  Auto-restore uses the same privilege helper as the build.
- CLI `--vuln-scan`, `--vuln-policy`, and `--vuln-db` map to the GUI **Quality Lab** CVE
  controls: the "Scan packages for known CVEs" checkbox, the CVE policy selector
  (off, warn, block-high, block-critical), and the custom CVE database field.
- CLI `--sbom-format` maps to the GUI **Quality Lab** SBOM format selector
  (Native, SPDX 2.3, CycloneDX 1.5).
- CLI `--bootstrap-arch` maps to the GUI **Source page** **Bootstrap arch** field for
  cross-architecture builds on a foreign host.

The **Artifacts** page covers:

- `artifact-paths`
- `release-readiness`
- `release-gate`
- `qemu-smoke-plan`
- `buildinfo-report`
- `packaging-policy`
- `debian-package`
- `hermetic-build-plan`

Artifact parity:

- CLI `artifact-paths` maps to **Load Defaults**.
- CLI `release-readiness` maps to **Release Readiness**.
- CLI `release-gate` maps to **Release Gate** and blocks publication when ISO,
  SHA256SUMS, source trust, boot proof or packaging policy evidence is missing.
- CLI `qemu-smoke-plan` maps to **QEMU Smoke Plan**.
- CLI `buildinfo-report` and `packaging-policy` map to **Packaging Policy** with
  optional **Buildinfo** and **Changes** selectors.
- CLI `autopkgtest-doctor` maps to **Autopkgtest Doctor**. The GUI action renders the
  planned run and classification surface in the artifact report; the mutating `--execute
  --output` evidence run stays an explicit CLI command.
- CLI `hermetic-build-plan` maps to **Hermetic Build** with backend and suite controls.
- Host paths must remain visible together: output ISO, reports dir, livefs work dir,
  live-build dir, screenshot, and serial log.

The **Maintainer** page covers:

- `doctor --debian-dev`
- `ai-review`
- `forgeadvisor`

The Maintainer page also hosts a **Chroot Terminal** — a GUI-only affordance
(mount runtime / start / send / stop) for a live root shell inside the built rootfs.
The parity rule runs CLI → GUI, not the reverse, so a hands-on terminal needs no CLI
twin; it is reached by intent through the Command Center's **Maintainer console &
chroot terminal** goal card and by the command palette's *terminal* / *shell* search
aliases, so it is discoverable without already knowing it lives on the Maintainer page.

Maintainer advisory parity:

- CLI `doctor --debian-dev` maps to **Debian Dev Doctor**. It renders the grouped
  Debian/Ubuntu maintainer tooling audit in the maintainer AI panel and stays
  preview-only; installation remains an explicit CLI action.
- CLI `ai-review` maps to **AI review plan** and reviews readiness/dry-run state.
- CLI `forgeadvisor review-build` maps to **ForgeAdvisor** and renders the same advisory
  report in the maintainer AI panel. Like `propose-fixes`, it accepts `--no-sudo` to review a
  build that runs without the privilege helper (mirroring the GUI sudo toggle), so both verbs
  read findings from the same options on either surface.
- CLI `forgeadvisor propose-fixes` maps to **FA: propose fixes** and renders the same Ring 2
  proposal in the maintainer AI panel: an ordered remediation plan plus, where a present
  finding's own remediation unambiguously implies one, a previewable build-option diff (for
  example `use_sudo: False -> True` when the privilege helper is disabled). Both surfaces reach
  that disabled state the same way: the maintainer build **sudo** toggle drives the GUI, and
  `propose-fixes --no-sudo` drives the CLI, so the grounded option diff is reachable from either.
  The proposal is a preview only — every report is stamped `preview only - nothing is applied`,
  the steps and diff are grounded in the same findings `review-build` explains, and applying any
  change stays the user's explicit action. The heavy review runs off the UI thread through the worker.
- CLI `forgeadvisor explain-evidence`, `fix-plan`, `review-definition`, and
  `search-local` map to **FA: evidence**, **FA: fix plan**, **FA: review def**, and
  **FA: search local**. They explain the selected evidence profile, narrate preview
  commands, validate a definition/recipe and cite local knowledge without building,
  signing or applying anything.
- CLI `forgeadvisor copilot` maps to **Maintainer Copilot**. It renders the combined
  `explain-evidence -> fix-plan -> search-local` view in the maintainer AI panel so
  a maintainer sees status, next commands and citations together.
- CLI `forgeadvisor explain-log`, `triage-log`, and `doctor-ai` remain available in the
  command surface for targeted log/backend checks; they use the same local advisory module
  and must stay non-mutating. `triage-log` maps to **FA: triage log** while
  `explain-log` maps to **FA: explain log**.
- CLI `forgeadvisor memory` maps to the Command Center **Show build memory** readout. Both
  summarise the host-owned build-memory corpus
  (`$XDG_STATE_HOME/distroforge/build-memory.jsonl`, default under `~/.local/state`) and cite
  it identically (e.g. "3 of your last 5 builds failed at squashfs"). The corpus is appended
  only when a build actually runs (`beginner-iso --execute` / GUI **Build beginner ISO**); the
  readout itself is read-only and stays advisory.
- CLI `forgeadvisor --backend {offline,llama,ollama}` maps to the maintainer
  **AI narration backend** selector on every advisory subcommand except the read-only
  `memory` corpus summary. Both default to the
  always-available `offline` backend and silently fall back to it when an optional local model
  backend is unavailable. Every backend only rephrases the deterministic findings and the
  build-memory citation into prose, ships no model weights, and stays non-mutating.
- CLI `forgeadvisor --register {beginner,power-user,maintainer,developer}` maps to the
  maintainer **Advisory register** selector on the same advisory subcommands. The
  register is the agent's voice, and its keys are exactly the canonical workflow levels
  (`core/workflows.py`) — no parallel taxonomy. Both surfaces select it silently from the saved
  workflow level and let you override it; the beginner register expands jargon from the
  `core/education.py` glossary and the developer register applies a Debian/Canonical lens. The
  register only changes how findings are explained, never what the build does.

The **Packages** page covers:

- `profiles`
- `profile`
- `derivative-profiles`
- `derivative-profile`

Derivative profile parity:

- CLI `derivative-profile plan` maps to the GUI **Derivative Plan** action.
- CLI `derivative-profile validate` maps to the same plan surface and validation section.
- CLI `derivative-profile export` maps to the GUI **Export Derivative** action.
- CLI `derivative-profile create-project` maps to **Create Derivative Project**.
- CLI `--dockerfile` maps to the GUI **Dockerfile** field.
- Built-in derivative choices must remain available in both `derivative-profiles` and the
  GUI **Derivative** selector.

The **Capture & Images** page covers:

- `capture`
- `capture-diff`
- `rebuild-from-capture`
- `live-build-plan`
- `livefs-iso-plan`
- `livefs-iso-build`
- `upgrade-media`
- `image-plan`

These commands are review-first. Capture, live-build planning, upgrade preflight,
and OEM/systemd image planning must remain visible in both CLI and GUI whenever any
of them changes.

Capture-specific parity:

- CLI `--include-config` maps to the GUI **Include configs** field.
- CLI `--include-config-glob` maps to the GUI **Include config globs** field.
- CLI `capture-diff` maps to the captured profile review text in **Capture & Images**.
- Both surfaces must preserve the same read-only capture policy and the same generated
  profile schema.

Livefs ISO parity:

- CLI `livefs-iso-plan` maps to the GUI **Plan livefs ISO** action.
- CLI `livefs-iso-build --write` maps to the GUI **Write livefs ISO workspace** action.
- CLI `--work-dir`, `--dest`, `--series`, `--arch`, `--mirror`, `--component`,
  `--project`, and `--volume-id` are represented by fields in the **Ubuntu livefs ISO**
  GUI section.

Refactor parity:

- Recent CLI surfaces must live in small `commands/*` adapters rather than growing
  `cli.py`.
- Recent GUI surfaces must live in page modules such as `ui/capture_page.py`,
  `ui/artifacts_page.py`, and `ui/packages_page.py` rather than growing
  `ui/main_window.py`.
- GUI build option mapping must live in `ui/build_options_mapper.py`, mirroring
  `commands/build_options.py` for CLI argument mapping.
- GUI-to-CLI preview rendering must live in `ui/cli_equivalent.py` so the window
  shell only delegates the current settings preview.
