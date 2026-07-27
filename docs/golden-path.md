# The Golden Path

The golden path is the one chain this project walks for real: a rootfs bootstrapped from
the archive, packed, turned into an ISO, booted under UEFI firmware, and a `.deb` built,
linted and put through its own autopkgtest suite. It lives in
`.github/workflows/golden-path.yml`, it runs weekly on a schedule and on demand, and it
is the answer to a question the rest of the gates cannot answer: does the product work,
as opposed to does the plan agree with itself.

Everything else in this project is level 0 or level 1 — unit tests and offline
plan/dry-run tests, deliberately, so the suite stays offline, rootless and sub-second.
That boundary has not moved. What changed is that the level-2 question now has a place to
be asked on a cadence, outside the suite, instead of only when a maintainer happens to
run a build by hand.

## Why a schedule, and not every push

`docs/debian-canonical-compliance.md` requires that package build artifacts not be
produced unless the maintainer explicitly authorizes a build, and `CONTRIBUTING.md` says
never build to verify a change. Both remain in force. Committing this workflow *is* that
authorization: given once, for one named derivative, on a stated cadence. It is not a
build smuggled into every push, and a contributor still must not build to prove a change
— if a defect seems to need a real build to show it, that is a gap in the test design and
naming it is more useful than a one-off manual run.

`tests/test_golden_path.py` holds that line mechanically: it fails if the workflow ever
grows a `push` or `pull_request` trigger, and it fails if `ci.yml` ever grows a real
build.

Three properties of GitHub's `schedule` event shape this file, all documented by GitHub
and none of them fixable here:

- Scheduled workflows "run on the latest commit on the default branch", so the golden
  path always builds `main` — never `develop`.
- In a public repository they are "automatically disabled when no repository activity has
  occurred in 60 days". A quiet quarter silently ends the golden path, and the only
  symptom is an absence rather than a red run.
- The event "can be delayed during periods of high loads ... High load times include the
  start of every hour", and queued jobs "may be dropped". The cron is therefore 03:17,
  not 03:00.

`workflow_dispatch` is also declared, because GitHub honours it only "if the workflow
file exists on the default branch" — a golden path living only on `develop` cannot be
dispatched at all, and waiting for Sunday is not a way to iterate.

The workflow has its own concurrency group. `ci.yml` groups by
`${{ github.workflow }}-${{ github.ref }}` with `cancel-in-progress: true`, and a
scheduled run happens on `refs/heads/main` — the same ref a push to `main` uses. A shared
group would let an ordinary push kill an hour-long build, and a cancelled run reports as
*cancelled* rather than *failed*, so the week would read as quiet instead of broken.

## Valid YAML is not a valid workflow

The first push of this file produced a run with no jobs, no log, and one sentence: *"This
run likely failed because of a workflow file issue."* GitHub evaluates every workflow in
the repository on every push, so an unloadable one fails there regardless of its triggers
— the run was attributed to a `push` event this workflow does not declare.

`gh run list` also showed it under its path rather than its `name:`, which reads like part
of the same failure and is not. Measured afterwards: the path stayed the display name
through two green runs of a file Actions loaded without complaint, and turned into *Golden
path* the moment `main` carried the file — with no push of the workflow itself. GitHub
reads a workflow's display name from the copy on the default branch, so one living only on
a topic branch is listed by its path whether it is valid or not. Two independent facts
happened to appear together, and the tidier story was the wrong one.

The cause was one expression: `${{ runner.temp }}` in the job's `env:` block. GitHub's
context-availability table gives `jobs.<job_id>.env` exactly *"github, needs, strategy,
matrix, vars, secrets, inputs"*, and lists `runner` only from
`jobs.<job_id>.steps.<step_id>.env` onwards. Naming it above a step is not a value that
comes out empty at run time; it is an unrecognized named-value, and Actions refuses the
file whole. The path is now set by a step writing `$RUNNER_TEMP` into `$GITHUB_ENV`, which
is the same directory reached the way the rest of the file already reached it.

Fifteen sabotages of this workflow were each caught by a named test, and all fifteen
stepped straight over a file GitHub would not load, because every one of them asked
`yaml.safe_load` what the file said — a strictly weaker question than whether Actions will
run it. `tests/test_golden_path.py` now also checks that no job-level key outside `steps`
names a context that only exists once a step is running, with a negative control on the
extractor so the check cannot pass by finding nothing. It is scoped to the two table rows
that were read rather than to a transcription of the whole table.

## The reference derivative

`.github/golden-path/reference-derivative.yaml` is the definition the weekly run builds.
It is deliberately not one of `examples/*.yaml`:

- Both shipped examples set `qa.scenarios`, and that path cannot be used unattended.
  `QaMatrixService` builds its QEMU invocation with no timeout, so `CommandRunner.run`
  receives none either, and a guest that never reaches a login prompt runs until the
  job's six-hour ceiling. The bounded way to ask the same question is `boot-proof`, which
  polls the serial log to a deadline.
- Every choice in it is a CI compromise — `zstd` instead of the `xz` release default, no
  desktop, two small extra packages — and a shipped example should recommend, not
  compromise. `packaging-policy` would also report an undeclared `examples/*.yaml` as a
  finding, so putting it there would mean shipping those compromises to users.

The compromises, with the measurements behind them:

| choice | why | measured |
| --- | --- | --- |
| `source_mode: bootstrap` | the point is to build a rootfs, not remaster an ISO | — |
| two extra packages | an empty list leaves `APPLY_PACKAGES` nothing to do, so apt never runs inside the chroot | — |
| `squashfs.compression: zstd` | 2.5× faster than the `xz` default for 1.5% more image | 37.1 s / 1466 MiB against 93.4 s / 1443 MiB, `docs/build-pipeline.md` |
| no desktop | rootfs, squashfs and ISO already come to roughly 6 GB, against 14 GB of documented runner SSD | 2.6 GB minbase rootfs, `docs/build-pipeline.md` |

## What each leg proves, and what it refuses to accept

**The ISO build** runs on the runner host rather than in a container, because the build
mounts: it bind-mounts `/dev`, `/dev/pts`, `/proc` and `/sys` and puts a private tmpfs on
`/run`, with no fallback when `mount` fails. A job container gets Docker's default
capabilities, which exclude `CAP_SYS_ADMIN`, so the first bind mount would end the run.
Privilege comes from `sudo` rather than from running the whole job as root, because
`use_sudo` exists precisely so that only the privileged commands are privileged.

The build's report is asserted field by field — `status`, `execute`, `output_exists`,
`output_size` — and not only by exit status. `iso-build --execute` does exit 2 on a
blocked report, but an exit status proves the command agreed with itself, not that a file
exists.

**The boot proof** uses `--backend qemu`, never `--backend auto`. `auto` falls back to
`iso-scan` when QEMU is missing or refuses, and `iso-scan` reads the ISO's structure
without booting it — a green report about a file, from the one step whose subject is a
running kernel. Four claims are asserted separately, because `ready` alone does not
distinguish a boot from a scan: `status`, `proof_level == "runtime"`, `selected_backend
== "qemu"`, and `firmware == "uefi"`. The firmware matters on its own: a proof under BIOS
only confirms the half that already worked.

Whether the guest was accelerated is printed and not asserted. `/dev/kvm` is absent on
GitHub-hosted runners, so the guest is emulated, the boot takes wall clock rather than
CPU, and `--timeout 1200` replaces the 300-second default for that reason. TCG is a valid
answer here; what matters is that the log records which one it was.

Secure Boot is **not** part of the weekly run yet. It needs the `.secboot` firmware
paired with the `.ms` store of enrolled keys, and it is the rung above this one: the UEFI
leg has to come back green on a cadence before a flag that can only make it fail is added
to a job nobody watches live. Until then, an enforcing-Secure-Boot proof is a
maintainer-run step — see `docs/build-pipeline.md` for how the firmware pair is detected
and why `-M q35,smm=on` is required.

**The Debian package** leg runs in `container: ubuntu:26.04` — the suite
`debian/changelog` targets, named rather than inherited (see *Three suites where the
derivative names one*) — for the same reason `ci.yml`'s `distro-dependencies` job uses a
container at all: the archive's own Python packaging rather than pip's. Build dependencies
come from `mk-build-deps`, which reads `debian/control`, so the build's dependencies
cannot drift from the ones the package declares — a hand-written apt list here would be a
second copy of that field, and a second copy is the thing that goes stale.

One command does the whole chain, because `build_debian_package` already *is* the chain:
`dpkg-buildpackage -us -uc -b`, then `lintian` with the profile resolved from the
changelog suite, then `autopkgtest` against the built `.deb`. `debian/tests` has declared
a smoke suite and a GUI-import test since long before this workflow, and nothing had ever
executed either.

The verdicts it accepts are exact:

- `lintian` may be `passed` or `review required`, and nothing else. Any tag at all makes
  it review, and this package carries one pedantic tag on purpose, so demanding `passed`
  would fail a healthy artifact. `missing` and `skipped` are refused because they mean
  the tool or the `.deb` was absent, which here would mean the toolchain step lied. A new
  warning is not a failure but it is not invisible either: every tag is kept in the
  report's `reason` and printed.
- `autopkgtest` must be `passed`. Its other executed verdicts are `testbed-broken`,
  `test-failed` and `failed`, and none of them is acceptable on a host where the tool and
  a writable testbed are both present.

The leg runs as the container's root, which `autopkgtest`'s null backend needs in order to
install the `.deb` it just built. The cost is that `dpkg-buildpackage`'s own test phase
then runs as root, so the tests that lock a directory to `0500` and expect a
`PermissionError` skip instead of running. `ci.yml`'s `distro-dependencies` job runs the
same suite as an unprivileged builder, which is where those tests are covered.

## The evidence

Both jobs upload an evidence bundle. The ISO leg publishes everything `dist/` holds
except the images: `SHA256SUMS`, `BUILDINFO`, `INTEGRITY`, provenance, the HTML report,
`ISO-BUILD.json`, `boot-proof.json`, `qemu-lab-report.json`, the serial log the kernel
wrote, and the `publish-bundle` directory. The ISO itself and the copy `publish-bundle`
makes of it are excluded on purpose and named on the way out rather than dropped in
silence: they are roughly 1.5 GiB each, and a reader of a weekly run needs the digests
and the reports, from which the image is reproducible. The package leg publishes the
`.deb`, `.changes`, `.buildinfo` and the verdict JSON.

`evidence-status` is given `--output-dir` explicitly, because its default is
`dist/reports` while the build writes `dist`, so the default reports a successful build's
own artifacts as missing.

## What the first real run measured

Dispatched 2026-07-27, and it is the reason several numbers on this page are now facts
instead of quotes from documentation.

The runner is not what the definition assumed. `ubuntu-latest` resolves to **noble**
(24.04), with **145 GB** on `/` and **88 GB free** — not the 14 GB the Actions docs
state, which `.github/golden-path/reference-derivative.yaml` had cited as the reason to
skip a desktop. 4 CPUs, 15 GiB RAM. `sudo` authenticates with no prompt. Those figures
are the noble image's; the ISO leg has since moved to `ubuntu-26.04`, so the next run
re-measures them, which is why that step exists at all.

**`/dev/kvm` exists** — `crw-rw---- 1 root kvm 10, 232`. `core/qemu_invocation.py:74`
says "a host with no device — every GitHub runner — never gets the flag"; that
parenthesis is wrong and the boot proof on this runner can be accelerated.

Reclaimable if disk ever binds: dotnet 5.2 GB, the Android SDK 11 GB, hostedtoolcache
5.4 GB. The `du` that measures them costs 80 seconds of the run.

## A failure has to arrive as data

Both legs failed, and neither said why. That, not the two failures, was the finding.

The ISO leg died in the chroot — `env: 'apt-get': No such file or directory`, exit 127 —
and the log said `jq: Could not open file .../ISO-BUILD.json`. `run_iso_build` let the
`CommandError` out, so no report was written and the assertion failed on the absence of
the file rather than on the cause. The traceback did name the failing command, on stderr,
past `--json`. It now returns a report with `status: "failed"` and a `failure` object
carrying the command, its description, its exit code and the tail of its output;
`--execute` still exits non-zero, through `IsoBuildReport.failed` rather than through an
exception.

The package leg built a clean `.deb` — `lintian: passed` — and reported
`autopkgtest: test-failed` with the reason *"The autopkgtest test command ran and
failed."* That sentence is a classification, byte-identical for every failing test in
`debian/tests`. The doctor had already extracted the output lines that name which test
failed, into its report's `evidence`, and the one call site that asks the doctor built
its `PackageBuildCheck` without them. The check now carries the evidence and the
doctor's remediation.

And the workflow itself hid both. Each assertion step printed its summary *after* its
assertions, which under `sh -e` means only on the happy path: the run that stopped at
the status assertion never printed the verdict behind it, and reading it meant
downloading the artifact. All three assertion steps now report before they assert, and
`tests/test_golden_path.py` refuses a step that asserts first — excluding the
`jq -e … || jq -r` guard, which cannot abort and is how the ISO leg prints a failure
before asserting there was none.

Still open: **why** a `--variant=minbase` mmdebstrap produced a tree with `env` and no
`apt-get`, in 23 seconds, exiting 0.

One hypothesis was raised and refuted here rather than shipped. The two tools this code
can call disagree in writing about that variant: debootstrap(8) defines `minbase` as
"required packages **and apt**", while mmdebstrap(1) defines `required, minbase` as the
essential set plus `?priority(required)` and does not mention apt — and in resolute's
archive `apt` is `Priority: important`, neither `required` nor `Essential: yes`. So
`create_rootfs` passing one string to whichever tool it finds looked like the whole bug.
It is not: measured on a resolute host,

```
mmdebstrap --simulate --verbose --variant=minbase --include=ca-certificates resolute
```

resolves **129** packages, `Inst apt (3.2.0 Ubuntu:26.04/resolute)` and
`Inst ca-certificates` among them. With mmdebstrap 1.5.7 the two definitions agree in
practice. The run that broke used **1.4.3-6**, from noble, against a resolute suite —
which is what the section below is about, and why the pinned runner is the experiment
that answers this. Note that `--simulate` alone prints no package set at all
(`I: no essential packages -- skipping`); the list only appears with `--verbose`.

What does not depend on the answer is the refusal. A bootstrap tool exiting 0 is a claim
about the tool, not about the tree, and this build believed it twice over:

- nothing checked the tree the tool had just made, so the build ran five more phases
  before a chroot said `apt-get` was missing — by which point the tool's own output,
  which would have named what it declined to install, had been discarded, because the
  runner keeps output only for commands that *fail*;
- and `rootfs_verdict` graded that tree **reusable**, because completeness was
  `var/lib/dpkg/status` plus an `os-release`, both of which it had. A re-run would have
  skipped the bootstrap and hit the same missing `apt-get`, with no bootstrap left in the
  log to blame.

Completeness is now the list in `_ROOTFS_REQUIREMENTS` — a dpkg database, an os-release,
`dpkg`, `apt-get` — each with its accepted alternative locations, and the verdict says
which entries are absent instead of the bare word `incomplete`. `create_rootfs` checks
the same list immediately after the tool returns and **before** the identity stamp is
written, so a refused tree carries no record claiming a base. The message names the tool,
the variant and the suite, because that triple is what the reader has to change.
`tests/test_bootstrap_requires_a_package_manager.py` covers both ranges, and
`tests/conftest.py`'s `make_rootfs` builds its fixture *from* `_ROOTFS_REQUIREMENTS`:
four test files had hand-copied "dpkg status plus an os-release" and all four broke, in
assertions about something else entirely, the day a fifth requirement appeared.

## Three suites where the derivative names one

The first run built the derivative on one suite, packaged for a second, and targeted a
third. All three were measured in its log; nobody chose the arrangement, which is the
point — two labels named *whatever is current* and were never compared with the one label
that names a release.

| Leg | Label | What it resolved to |
| --- | --- | --- |
| ISO | `runs-on: ubuntu-latest` | **noble** (24.04), `mmdebstrap 1.4.3-6` |
| Package | `container: ubuntu:devel` | **stonking** (26.10) |
| The source itself | `--release 26.04`, `debian/changelog` | **resolute** (26.04) |

So the ISO leg asked 2024's mmdebstrap, apt and dpkg to assemble a suite from 2026, and
the package leg built, linted and autopkgtested a resolute package on the suite *after*
resolute — while a comment in both `golden-path.yml` and `ci.yml` said the container was
"the suite `debian/changelog` targets". It was, until 26.04 released and `devel` moved on.

Both labels now name the suite: `runs-on: ubuntu-26.04` (GitHub publishes it for x64,
`actions/runner-images#14226`, public preview) and `container: ubuntu:26.04`, in `ci.yml`
too. Because a preview label can be withdrawn and `-latest` migrates on GitHub's own
schedule, the names are not trusted — each leg checks itself before it spends the runner:

- the ISO leg compares `/etc/os-release` with the codename `distroforge/data/releases.toml`
  gives for `$DERIVATIVE_RELEASE`, read with `tomllib` before `pip` has run, so learning
  the job is pointless costs twenty seconds rather than ten minutes;
- the package leg compares `/etc/os-release` with `debian_changelog_suite()` — the
  function `lintian_vendor_for_suite` is already fed, so the image a package is built in
  and the profile it is graded against cannot disagree.

`tests/test_golden_path.py` holds the same coupling from the outside: no job may build in
`ubuntu:devel`, `ubuntu:rolling` or `ubuntu:latest`, every container must name the suite
`debian/changelog` targets, and the ISO job's `runs-on` must be `ubuntu-$DERIVATIVE_RELEASE`
with the creation step passing that variable instead of a second literal.

One thing this turned up on the way. `releases.toml` gave 26.10 the codename `next`,
which is not a codename but the word that stood in for one — and that field is what every
pocket, `sources.list` line and mmdebstrap suite for a release is built from, so a starter
pointing at 26.10 could only ever have asked the archive for a suite that does not exist.
Measured against `archive.ubuntu.com/ubuntu/dists/stonking/Release`: `Suite: stonking`,
`Version: 26.10`.

## Two figures that are headroom, not measurements

`timeout-minutes: 90` on the ISO job and `--timeout 1200` on the boot proof are both
generous guesses, stated as such. The run records the real wall clock in its own log and
the serial log settles the boot; both numbers should come down to what is measured rather
than stay at what was assumed.

## Related

- `docs/build-pipeline.md` — what each build phase does, the firmware detection, and the
  measured compressor table.
- `docs/packaging-release.md` — the exit-status rule these assertions rely on, and the
  lintian vendor resolution.
- `docs/acceptance-matrix.md` — the level 0/1 gate the suite provides, and its boundary.
- `docs/debian-canonical-compliance.md` — the standing rule this workflow is the single
  authorized exception to.
