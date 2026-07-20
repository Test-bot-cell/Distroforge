# DistroForge Advisory Agent Contract

> **Status: ratified and enforced.** This contract defines the agent's behaviour
> and intervention perimeter. It is wired into the Debian shipping manifest
> (`debian/docs` and the packaging policy report's `IMPORTANT_DOCS`) and backed by
> inviolable test teeth in `tests/test_advisory_agent_governance.py`. The agent
> remains **governed by the four founding pillars, not added as a fifth** (see
> *Status & standing*).

## Status & standing

The advisory agent is **governed by the four founding pillars**, not added as a
fifth: CLI/GUI parity (`docs/gui-parity.md`), UX cognitive-ergonomics
(`docs/ux-cognitive-ergonomics.md`), Debian-policy & Canonical compliance
(`docs/debian-canonical-compliance.md`), and velocity/responsiveness
(`docs/velocity-responsiveness.md`). An agent is a *subject* the pillars
constrain, not a constraint of its own. This document elevates the platform
invariant **"AI is advisory"** (architecture invariant #7) into a tested,
inviolable agent-governance contract.

## Prime directive — the hard wall

**The advisory agent is advisory, never autonomous.** It perceives, explains and
proposes; it **never mutates the build, the recipe or the ISO without an explicit
user action**. Every change to the deterministic engine crosses the same
explicit-action wall the rest of the product already uses (a GUI *Apply*, or a
CLI verb the user runs). The agent may make that action one click away; it may
never take the click.

This is what lets the brain be ambitious: freed from owning determinism, it can
plan, simulate, draft and critique as aggressively as useful, because the human —
not the agent — commits.

## Intervention perimeter — four rings

The agent works in four concentric rings and never leaves Ring 3 on its own:

- **Ring 0 — Perception (always on, silent).** Reads project state, the build
  journey, logs and the build-memory corpus, and selects its register. No side
  effects.
- **Ring 1 — Explanation (free, no approval).** Explains state, translates jargon
  (backed by the `core/education.py` glossary) and diagnoses failures.
  Read → text only.
- **Ring 2 — Proposal (drafts, never commits).** Produces multi-step plans,
  previewable option diffs and recipes — all as inspectable previews. Nothing is
  applied.
- **Ring 3 — Execution (only via the explicit-action wall).** The user applies a
  proposal through the existing *Apply* action or CLI verb. All heavy work runs
  off the UI thread through `GuiJob`.

## Adaptive registers — one brain, many voices

The agent presents a register matched to its interlocutor, from a first-time
beginner to a senior Debian/Canonical maintainer. **Register selection is silent
but always overridable** — this is *persona-only* silent adaptation: the agent
changes how it speaks and how much it discloses, never what it does to the build.

Registers derive from the **single source of truth** for levels —
`core/workflows.py` and `data/personas.toml` — with **no parallel taxonomy**. The
"multiple personalities" are voices over one shared brain and one shared corpus,
not separate agents.

- *Beginner register*: plain language, analogies, surfaces the questions a
  beginner does not yet know to ask. The CLI is never pushed at this register.
- *Power-user / maintainer registers*: repositories, rollback, provenance,
  release readiness, policy and trademark clearance.
- *Senior Debian/Canonical register*: actively applies the policy, lintian,
  Standards-Version and Canonical-guideline lens.

## Build memory — learning from real ISO builds

The agent gets sharper by remembering builds, not by shipping a neural network.

- **One canonical build-memory corpus**, local and **host-owned**, recording
  every build attempt — success or failure — with its options, signatures and log
  features. It is auditable and grows on the user's machine.
- **Deterministic classifiers and heuristics** over build logs (industrialising
  `beginner-iso --explain-last-failure`) turn raw logs into reproducible, testable
  failure diagnoses. They share **one canonical taxonomy** in
  `core/build_diagnosis.py`: the beginner-iso explainer and ForgeAdvisor both
  delegate to it, so a failure class means exactly one thing wherever it is shown
  or counted.
- The agent is **grounded by retrieval** over this corpus and **cites it**
  ("3 of your last 5 builds failed at squashfs on X"), so guidance is auditable
  rather than hallucinated.

## Maintainer Copilot workflow

The user-facing copilot is a read-only composition of existing advisory
surfaces, documented in `docs/maintainer-copilot.md`. It runs the sequence
`explain-evidence -> fix-plan -> search-local` in one report: first the current
evidence profile is explained, then preview commands are listed, then local docs,
tests, reports and source snippets are cited. This is still Ring 1/Ring 2 only:
the fix-plan commands are printed as text and no build, signing, verification or
filesystem mutation is started.

## Pluggable backend & offline degradation

- The reasoning backend is **pluggable and local-first**; no specific vendor is
  hard-wired.
- The agent **degrades to a fully offline grounded-heuristic mode**: with no
  backend available it still perceives, classifies and cites the corpus. It never
  breaks, never blocks, and never requires the network.
- **No model weights ship in the core `.deb`.** Any trained component is an
  opt-in module distributed separately — never a default, never inside the
  reproducible core package.

## Guarantees, per pillar

1. **CLI/GUI parity.** Every agent capability has both a CLI verb and a GUI
   surface; the agent is never CLI-only nor GUI-only. The parity registry and
   tests cover it like any other capability.
2. **UX cognitive-ergonomics.** The adaptive register is progressive disclosure
   made personal; it favours recognition over recall, teaches by showing state,
   and never forces the CLI on a beginner.
3. **Debian policy & Canonical compliance.** The advisory wall protects
   reproducibility, auditability and maintainer trust; the corpus is host-owned;
   the path degrades fully offline and rootless; no weights in the core package.
4. **Velocity / responsiveness.** Reasoning and retrieval run off the UI thread
   through `GuiJob`; perception stays light; the corpus is indexed; nothing blocks
   the per-frame path.

## Enforcement (the inviolable teeth)

Codified as tests in `tests/test_advisory_agent_governance.py`:

- **No silent mutation**: no agent code path reaches an engine mutation without
  passing through the explicit-action wall.
- **Offline degrade**: with no backend, the agent still answers from corpus +
  heuristics; offline and rootless test suites stay green.
- **Parity**: each agent capability has a CLI verb and a GUI surface.
- **Single-source register**: agent registers derive only from the canonical
  workflow levels, with no private level table.

## Non-goals

- No silent or autonomous mutation of the build, recipe or ISO.
- No deep neural network embedded in, or trained inside, the core package.
- No code path that requires the network to function.
- No parallel level/persona taxonomy.

## The four pillars

See `docs/distroforge-platform-architecture.md` for how the pipeline owner,
command boundary and GUI shell keep the agent advisory and the build
deterministic. The agent honours, and is bound by, all four pillar contracts
listed under *Status & standing*.
