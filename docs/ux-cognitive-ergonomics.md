# DistroForge UX Cognitive-Ergonomics Contract

**UX cognitive-ergonomics is non-negotiable.** This document is one of the four
founding pillar contracts of DistroForge, equal in standing to CLI/GUI parity
(`docs/gui-parity.md`), Debian-policy and Canonical-guideline compliance
(`docs/debian-canonical-compliance.md`), and velocity/responsiveness
(`docs/velocity-responsiveness.md`). If any pillar is breached, the user
experience is treated as a failed, deprecated refactor: the work restarts from
the engine features and is rewired until every pillar holds again.

The rule is simple to state and binding at every level: the GUI must be
**user-friendly for every user level**, from a first-time beginner to a Debian
maintainer, and that friendliness is grounded in recognized cognitive science,
not taste. The terminal is never the cost of entry — **the CLI is never forced
on a beginner**, yet (per the parity pillar) every CLI capability still has a
discoverable GUI surface.

## Grounding works

The invariants below are derived from established human-factors and HCI
literature, so design decisions can be argued from evidence rather than opinion:

- **Hick's Law** (Hick 1952; Hyman 1953): choice reaction time grows with the
  number of simultaneous options — so we limit visible choices per level.
- **Nielsen's usability heuristics** (Nielsen 1994): visibility of system
  status; match between system and the real world; user control and freedom;
  error prevention; and **recognition over recall**.
- **Miller's law** (Miller 1956, "The Magical Number Seven, Plus or Minus Two"):
  working memory is small — so we chunk steps and never present an
  undifferentiated wall of options.
- **Cognitive Load Theory** (Sweller 1988): minimize extraneous load so the
  user's effort goes to the intrinsic task, not to decoding the interface.
- **The Design of Everyday Things** (Norman 1988): affordances, signifiers,
  clear mapping, and immediate feedback for every action.
- **Information foraging / information scent** (Pirolli & Card 1999): each step
  advertises what it leads to, so users can navigate by scent toward their goal.

## Invariants

These are the testable, inviolable rules. Each ties to a concrete part of the
shell so it can be fact-checked, not merely asserted.

1. **One guided journey.** The home surface is a single ordered spine of the
   build journey the engine already models in `core/build_journey.py` — not a
   wall of peer pages. The spine reuses the engine's `title` and `next_action`
   verbatim, so the journey has one source of truth and the GUI cannot drift
   from the CLI's `journey` command.

2. **Progressive disclosure.** The chosen workflow level (beginner → developer,
   from `core/workflows.py`) gates how much of the spine is unlocked, so a
   beginner sees a short, didactic path and an expert sees the full surface.
   This is Hick's Law applied: fewer simultaneous choices, less decision cost.
   The level is chosen once, persisted, and switchable at any time.

3. **Recognition over recall.** Steps, actions, and state are shown with named
   markers, titles, and next-action hints; the user recognizes the next move
   instead of recalling a command. Domain vocabulary is backed by the didactic
   glossary (`core/education.py`), so no term is shown without a definition. The
   Command Center's **What do you want to achieve?** goal hub extends this to
   navigation: one card per product capability (`core/workflows.py`) lets a user
   pick by intent and routes to the backing surface, so they need not recall which
   tool to open. A **Maintainer console & chroot terminal** card, for instance,
   routes to the Maintainer surface, so the hands-on shell inside the built image is
   reachable by intent rather than only by already knowing where it lives. The same principle governs data entry: every filesystem-path field offers a
   native **Select** chooser (`ui/path_actions.py`) so a path is *recognized* by pointing at it
   in the file manager rather than *recalled* and typed from memory — the affordance-and-feedback
   pairing Norman describes. The chooser never replaces the field, so a power user, developer or
   maintainer can still type a path directly.

4. **Level-independent escape hatch.** Navigation has no level gate. The header
   "Open tool…" palette is a keyboard-first, type-to-filter action index (focus
   it with Ctrl+K) that enumerates **every** surface regardless of level — and
   every guided journey step — and the surface router opens any of them directly.
   Typing part of a goal surfaces the matching surface or step, so nothing must be
   recalled by name. The palette also carries plain-language search aliases, so a
   feature is found by the word a user reaches for rather than its formal surface
   name — typing *terminal* or *shell* routes to the Maintainer surface that hosts the
   chroot terminal. The level prunes only the guided spine, never reachability —
   this is the cognitive-ergonomics half of the CLI/GUI parity guarantee for
   advanced and CLI-fluent users. The palette is the keyboard, recall-leaning side
   of that escape hatch; its always-visible counterpart is a **Start** button that
   sits at the leading edge of the header bar (per the GNOME HIG convention of a
   back/home affordance at the start of the header) on every surface except Start
   itself, and returns to the project's Start surface in one click. Showing the way
   home rather than requiring it to be recalled is recognition over recall, and the
   permanent, reversible way back is Nielsen's *user control and freedom*.

5. **Teach by showing state.** The GUI teaches by surfacing readiness,
   privilege state, snapshot behavior, the current GUI-to-CLI equivalent, and
   the next recommended action — not by dumping logs. Logs stay available for
   diagnosis but are never the primary teaching surface.

6. **No control is ever clipped.** At any window width and on any desktop
   environment, every control stays reachable: panels reflow and scroll rather
   than truncate. A clipped or unreachable control is a contract breach, not a
   cosmetic bug.

## Enforcement

The teeth are structural and phrase-locked rather than subjective:

- The single-journey, progressive-disclosure, and escape-hatch invariants are
  proven at runtime by the offscreen reachability test (every surface reachable
  at every level; the palette enumerates all surfaces and routes both surface and
  journey-step entries; the goal hub routes every product capability to its
  declared surface) and by the level and parity test suites.
- The no-clip invariant is guarded by the responsive layout tests, which
  measure that page contents fit a narrow viewport without truncation and, under
  the real font metrics, that no single-line label renders wider than its own
  frame at any window width. Long dynamic values elide to an ellipsis with the
  full text in a tooltip rather than being cut off, so a wider desktop font
  (such as Adwaita Sans) can never clip a value inside its panel.
- This contract's existence and key phrases are locked by a phrase test, so the
  pillar cannot be silently deleted or watered down.

Felt ergonomics — whether the result actually *feels* humane — remains the
user's visual call, exactly as the founding pillars intend. The tests guarantee
the structure that makes a humane experience possible; they do not replace
human judgment of the result.

## The four pillars

DistroForge stands on four inviolable `.md` contracts, each honored fully:

1. **CLI/GUI parity** — `docs/gui-parity.md`: where there is CLI there must be
   GUI, but the CLI is never forced on a beginner.
2. **UX cognitive-ergonomics** — this document: user-friendly at every level,
   grounded in recognized cognitive science.
3. **Debian policy & Canonical compliance** — `docs/debian-canonical-compliance.md`:
   the founding contract, never abandoned at any price.
4. **Velocity / responsiveness** — `docs/velocity-responsiveness.md`: no
   avoidable latency, lag, or freeze, modulo the inherent size of the task.

See `docs/distroforge-platform-architecture.md` for how these pillars map onto
the build pipeline, the workflow levels, and the guided build journey.
