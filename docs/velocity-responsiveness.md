# DistroForge Velocity & Responsiveness Contract

**Velocity and responsiveness are non-negotiable.** This document is one of the
four founding pillar contracts of DistroForge, equal in standing to CLI/GUI
parity (`docs/gui-parity.md`), UX cognitive-ergonomics
(`docs/ux-cognitive-ergonomics.md`), and Debian-policy and Canonical-guideline
compliance (`docs/debian-canonical-compliance.md`). If any pillar is breached,
the work is treated as a failed, deprecated refactor: it restarts from the
engine features and is rewired until every pillar holds again.

The rule: all code produced for DistroForge, for any feature and any
compliance need, must favor execution speed. Its runtime must produce **no
avoidable latency, lag, or freeze** — **modulo the inherent complexity and
volume of the task in hand**. A real ISO build legitimately takes minutes; that
is bounded work with visible progress, not a freeze. The requirement is
**responsiveness during long work, not making long work instant**.

## What "responsive" means here

- The UI thread is never blocked by long or heavy work. A button press returns
  control to the event loop immediately; the heavy work happens elsewhere and
  reports back.
- Long operations are legible: they show weighted progress and a phase, and they
  can be cancelled. A user is never left staring at a frozen window wondering
  whether the app died.
- Per-frame and per-refresh code paths stay light. Drawing the journey spine,
  refreshing a step header, or relaying out on resize must not do synchronous
  disk or subprocess work.

## Invariants

These are the testable, inviolable rules.

1. **Heavy work runs off the UI thread.** Every long-running or potentially
   blocking operation (builds, dry-runs, scans, doctor, audits, snapshots) is
   dispatched through `GuiJob` in `ui/jobs.py`, which runs the target on a
   daemon thread and communicates with the UI exclusively through a
   `queue.Queue` of events. The UI thread only drains that queue; it never runs
   the heavy work itself.

2. **Cancellable, progress-bearing long work.** `GuiJob` exposes a cooperative
   cancel and emits weighted progress so the inherent cost of a real build is
   shown honestly as bounded progress, never as an unexplained hang.

3. **No blocking I/O on the per-frame path.** The hot paths — the main
   `_refresh()`, the journey-spine refresh, the step-focus header refresh, and
   responsive relayout — perform no synchronous disk or subprocess I/O. Work for
   surfaces the user has not opened is done lazily, not eagerly on every frame.

4. **No accidental quadratic.** Refresh and layout code must stay close to
   linear in the number of visible items; a redraw rebuilds a bounded spine, not
   an unbounded recomputation of the whole project state.

## Enforcement

The teeth are structural rather than wall-clock, on purpose:

- A structural test proves `GuiJob` runs its target off the calling (UI) thread
  and that the heavy GUI controllers dispatch through it.
- A source-level guard proves the per-frame refresh modules carry no synchronous
  subprocess or blocking-build calls.
- Non-regression budgets, where used, are deliberately **generous**: tight
  wall-clock assertions are flaky across hardware and CI, so we gate on
  structure (work is off-thread, the hot path is clean) and on generous bounds,
  not on millisecond targets. Felt velocity — whether the app actually *feels*
  snappy — remains the user's visual call, exactly as the UX pillar intends.

## The four pillars

DistroForge stands on four inviolable `.md` contracts, each honored fully:

1. **CLI/GUI parity** — `docs/gui-parity.md`.
2. **UX cognitive-ergonomics** — `docs/ux-cognitive-ergonomics.md`.
3. **Debian policy & Canonical compliance** — `docs/debian-canonical-compliance.md`.
4. **Velocity / responsiveness** — this document.

See `docs/distroforge-platform-architecture.md` for how the pipeline owner,
command boundary, and GUI shell keep heavy work off the interactive path.
