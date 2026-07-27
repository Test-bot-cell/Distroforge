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
   dispatched through one of the two canonical seams — `GuiJob` in `ui/jobs.py`
   for cancellable, progress-bearing builds, and `_run_in_worker` in
   `ui/service_runner.py` for one-shot service calls — both of which run the
   target on a daemon thread and communicate with the UI exclusively through a
   `queue.Queue` of events or a polling timer. The UI thread only drains that
   channel; it never runs the heavy work itself. A slot that hashes, copies or
   boots an ISO uses a seam, never the click handler.

2. **Cancellable, progress-bearing long work.** `GuiJob` exposes a cooperative
   cancel and emits weighted progress so the inherent cost of a real build is
   shown honestly as bounded progress, never as an unexplained hang.

3. **No blocking I/O on the per-frame path.** The hot paths — the main
   `_refresh()`, the journey-spine refresh, the step-focus header refresh, and
   responsive relayout — perform no synchronous disk or subprocess I/O. Work for
   surfaces the user has not opened is done lazily, not eagerly on every frame.
   The main `_refresh()` computes the journey report **once** and passes it to the
   spine, the command center and the Start cards; a per-refresh status never
   hashes a build artifact — it answers from the `SHA256SUMS` sidecar, and the
   verifying gate stays on the on-demand per-step check.

4. **No accidental quadratic.** Refresh and layout code must stay close to
   linear in the number of visible items; a redraw rebuilds a bounded spine, not
   an unbounded recomputation of the whole project state.

## Inherent cost stays honest, and stays the user's choice

Some work is simply expensive: compressing a two-and-a-half gigabyte rootfs, hashing
a finished ISO, booting it under emulation. The contract above forbids *avoidable*
latency, not the cost of the job itself. Where the cost is inherent, the rules are:

- **Never mistake someone else's cost for your own.** The 30-minute repack that first
  prompted this section turned out to be mksquashfs walking into a surviving `/proc`
  bind mount and compressing `/proc/kcore`, not xz being slow. The same pack, once the
  mount bug was fixed, takes 93 seconds. Attributing it to the compressor would have
  bought a redesign for a bug — so a velocity claim gets measured against the phase
  log before it gets acted on.
- **Price the alternatives, then expose the choice.** The live-filesystem compressor is
  a build option because the measured spread is large and the right point on it depends
  on what the run is for: `lz4` packs the same rootfs 24× faster than `xz` for 15% more
  bytes, which is the difference between iterating and waiting. The measured table lives
  in `docs/build-pipeline.md`.
- **Do not spend the user's runtime to save the maintainer's build time.** A knob that
  makes the build faster but the delivered image slower to read is not a velocity win,
  and stays unshipped until the runtime side is measured too.

## Enforcement

The teeth are structural rather than wall-clock, on purpose:

- A structural test proves `GuiJob` runs its target off the calling (UI) thread
  and that the heavy GUI controllers dispatch through it.
- A source-level guard proves the per-frame refresh modules carry no synchronous
  subprocess or blocking-build calls, and that the per-refresh journey status
  performs no artifact hashing.
- A counting test proves every heavy Artifacts, capture and release slot
  dispatches through a worker seam, and that a maintainer-level refresh reads the
  finished ISO at most once — never once per view.
- A handshake test proves `run_streaming` forwards a line that is already in the
  pipe immediately, without a wall-clock assertion.
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
