# Maintainer Copilot and AI Commands

DistroForge's AI layer is local-first and advisory. It reads evidence, logs,
definitions and local documentation, then produces explanations, citations and
preview commands. It never builds, signs, edits or applies a fix on its own.

## One-View Copilot

Use the Maintainer Copilot when you want the current release state, the next
commands, and local citations in one read-only report:

```bash
distroforge forgeadvisor copilot /path/to/project --profile package
distroforge forgeadvisor copilot /path/to/project --profile iso --query "boot proof"
distroforge forgeadvisor copilot /path/to/project --profile publish --limit 8 --json
```

The report follows this sequence:

1. `explain-evidence`: summarize `ready`, `review`, `blocked` and `invalid` evidence.
2. `fix-plan`: list suggested commands without running them.
3. `search-local`: cite local docs, tests, reports or source that match the query.

Example text output:

```text
ForgeAdvisor: maintainer copilot for /path/to/project
Backend: offline
Register: Maintainer
Verdict: review

Notes:
- Workflow: explain-evidence -> fix-plan -> search-local.
- Evidence [package]: review (ready=16 review=3 blocked=0 invalid=0).
- Maintainer toolchain: 47 Debian/Ubuntu maintainer tools available.
- Next action: Rebuild in a hermetic sbuild/pbuilder/mmdebstrap environment before publication.
- Next action: Create or verify a hermetic release bundle before package review.
- Next action: Run autopkgtest-doctor with a writable schroot/qemu backend and store the report.
- Fix command: distroforge hermetic-build-plan /path/to/project --backend sbuild --suite unstable
- Fix command: distroforge hermetic-release-bundle /path/to/project --output /path/to/project/dist
- Fix command: distroforge autopkgtest-doctor /path/to/project --backend schroot --execute --output /path/to/project/dist/AUTOPKGTEST-DOCTOR.json
- Local search query: evidence release readiness
- Preview only: 3 command(s) suggested, none executed.
```

In the GUI, the **Maintainer** page exposes the same workflow as
**Maintainer Copilot**. The **AI narration backend** selector can rephrase the
deterministic findings through `offline`, `llama` or `ollama`; unavailable local
model backends fall back to `offline`.

## Evidence Explanation

```bash
distroforge forgeadvisor explain-evidence /path/to/project --profile dev
distroforge forgeadvisor explain-evidence /path/to/project --profile package --json
distroforge forgeadvisor explain-evidence /path/to/project --profile iso --iso /path/to/image.iso
distroforge forgeadvisor explain-evidence /path/to/project --profile publish --output-dir /path/to/dist
```

Profiles scope the noise:

- `dev`: source tree and packaging sanity, no ISO expected.
- `package`: Debian maintainer toolchain, package artifacts, buildinfo taint,
  Lintian and bundle contract evidence.
- `iso`: ISO, checksum, QEMU plan, release readiness and release gate evidence.
- `publish`: package, ISO, signing, notes, verification and drill evidence.

## Fix Plan Narration

```bash
distroforge forgeadvisor fix-plan /path/to/project --profile iso
distroforge forgeadvisor fix-plan /path/to/project --profile publish --json
```

The fix plan is a preview. It prints commands such as `iso-build`,
`release-readiness`, `qemu-smoke-plan`, `release-gate`,
`hermetic-release-bundle` or `verify-release`, but it never executes them.

## Build Log Triage

```bash
distroforge forgeadvisor triage-log /path/to/build.log
distroforge forgeadvisor explain-log /path/to/build.log --json
```

Both commands use the canonical failure taxonomy in `core/build_diagnosis.py`.
`triage-log` emphasizes likely cause ordering; `explain-log` is the general log
explanation surface. Findings cite the matching log line.

## Definition Review

```bash
distroforge forgeadvisor review-definition maintainer.yaml
distroforge forgeadvisor review-definition recipe.json --json
```

The review validates the definition, flags advisory risks such as missing source
checksums or disabled release evidence, and recommends an evidence profile for
the next review step.

## Local Knowledge Search

```bash
distroforge forgeadvisor search-local /path/to/project "evidence profiles"
distroforge forgeadvisor search-local /path/to/project "boot proof" --limit 5 --json
```

Search covers local `docs/`, `debian/`, `tests/` and `distroforge/` files. It
returns short cited snippets and does not use the network.

## Backend and Register

Every ForgeAdvisor command above accepts:

```bash
--backend offline|llama|ollama
--register beginner|power-user|maintainer|developer
```

`offline` is deterministic and always available. Optional model backends only
narrate already-computed facts and degrade to `offline` when unavailable. The
register changes tone and disclosure level, not build behavior.
