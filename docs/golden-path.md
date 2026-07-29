# The Golden Path

The golden path is the one chain this project is intended to walk for real: a rootfs
bootstrapped from the archive, packed, turned into an ISO, booted under UEFI firmware,
and a `.deb` built, linted and put through its own autopkgtest suite. It lives in
`.github/workflows/golden-path.yml`, it runs weekly on a schedule and on demand, and it
is where the project asks a question the rest of the gates cannot answer: does the
product work, as opposed to does the plan agree with itself.

That is its required scope, not its current verdict. The first real run failed before
producing a complete ISO proof. The current local reference ISO is structurally valid but
does not boot under UEFI; an audit variant reaches shim and then fails while shim reads
`grubx64.efi`. No run has yet proved the full UEFI-to-login chain or the desktop. The
authoritative milestone table is
[iso-build-proof-ledger.md](iso-build-proof-ledger.md).

Everything else in this project is level 0 or level 1 — unit tests and offline
plan/dry-run tests over bounded fixtures, deliberately, so the suite stays offline and
rootless. Even tests that invoke real `mksquashfs`, `unsquashfs` and `xorriso` operate on
tiny synthetic trees; they are not product builds. That boundary has not moved. What
changed is that the level-2 question now has a place to be asked on a cadence, outside the
suite, instead of only when a maintainer happens to run a build by hand.

## Current hardening status

The 2026-07-29 source lot changes what the next Golden path run will demand; it does not
claim that run has happened. No new product ISO, live-archive transaction, product
SquashFS or QEMU boot was produced while making these changes.

- Every external action currently used by `ci.yml` and `golden-path.yml` is referenced by
  a full 40-hex commit SHA. The adjacent version comment is explanatory; it is not what
  Actions resolves. This closes mutable `@v4`, `@v5` or branch references in the workflow
  source, but only a later run can bind those workflow bytes to its output.
- The reference derivative supplies an external Ubuntu archive trust policy:
  `/usr/share/keyrings/ubuntu-archive-keyring.gpg`, SHA-256
  `80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31`,
  and the complete signer fingerprint
  `F6ECB3762474EDA9D21B7022871920D1991BC93C`. Separate policies own the release,
  updates/backports and security URI/suite namespaces and their freshness windows. A
  runner keyring update or archive key rotation therefore blocks until this definition is
  reviewed rather than silently redefining trust.
- Before any Golden-path build, the workflow verifies the exact checked-out commit in an
  ephemeral `GNUPGHOME`. The repository-pinned public key must hash to
  `a1b6ee870e2708571bc43cf42d12a0c315c58dd1dad7760a27f660db3162e0ab`, expose primary
  fingerprint `93D942241BECDD422606C36C4C0D75219B5506CF`, and make
  `git verify-commit HEAD` succeed. `PYTHONDONTWRITEBYTECODE=1` prevents imports from
  manufacturing ignored bytecode, and a targeted cleanup removes caches an editable
  install may have compiled before the opening builder identity is measured. This is a
  configured refusal rule; no post-change Golden-path run has yet exercised it.
  Because the key, its SHA and its fingerprint are all source-controlled, review and
  branch governance remain the external trust anchor for that policy.
- Executing source-ISO remasters now require stable regular ISO/signature files, an
  external SHA-256 and one exclusive full `VALIDSIG` signer, and extraction consumes the
  witnessed source descriptor. Publication still reports that source boundary as
  `review`, because the detached signature, verification status and keyring bytes are not
  yet sealed for offline replay. The reference derivative itself uses bootstrap mode.
- The evidence-assembly step now runs `release-gate` with that exact definition and
  requires its publication items to be `ready` before `publish-bundle`. The package item
  replays per-source signed `InRelease`/`Release` → `Packages` → `.deb`, freshness and the
  final APT command ledger offline; it is not satisfied by a field that merely says
  validation passed. It deliberately remains `blocked` while `.deb` payload bytes are not
  causally bound to every final rootfs path. The rootfs/ISO path now performs a semantic
  manifest check, descriptor-held SquashFS round-trip and authoritative replay from the
  final ISO, but only code and falsification tests have exercised that path.

A push to `develop` does run the ordinary `CI` workflow because `ci.yml` listens to
`push`. It does **not** execute `golden-path.yml`: that file deliberately has only
`schedule` and `workflow_dispatch`, and both use the workflow on the default branch.
While `main` is left unchanged, a scheduled run still builds `main`, and a version of the
workflow that exists only on `develop` cannot be manually dispatched through GitHub's
`workflow_dispatch` event. A green per-push CI on `develop` is therefore source/test
evidence, not a Golden path ISO result.

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

## What a completed, authenticated leg would prove, and what it refuses to accept

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

Each recognized executable entrypoint is also opened, hashed and dispatched through its
held `/proc/<pid>/fd/<fd>` descriptor, including recognized wrapper-selected targets.
The release gate requires that descriptor binding and the matching post-dispatch identity.
This closes an entrypoint path-swap race; it does not prove the transitive ELF interpreter
and shared-library graph. The next run must preserve the identity records, and the loader
and library closure remains a stated toolchain limit rather than an implied success.

**The boot proof** uses `--backend qemu`, never `--backend auto`. `auto` falls back to
`iso-scan` when QEMU is missing or refuses, and `iso-scan` reads the ISO's structure
without booting it — a green report about a file, from the one step whose subject is a
running kernel. Four claims are asserted separately, because `ready` alone does not
distinguish a boot from a scan: `status`, `proof_level == "runtime"`, `selected_backend
== "qemu"`, and `firmware == "uefi"`. The firmware matters on its own: a proof under BIOS
establishes BIOS only and says nothing about UEFI. The exact rebuilt ISO still requires
digest-linked v2 proofs for both firmware paths.

Whether the guest was accelerated is printed and not asserted. The first measured
GitHub-hosted runner exposed `/dev/kvm`; another image or runner class may not. The proof
therefore records acceleration instead of assuming it, and `--timeout 1200` keeps the TCG
case bounded. Either acceleration answer is valid; an unrecorded one is not.

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

Both jobs upload an evidence bundle. The ISO leg publishes the reports and append-only run
directory: `SHA256SUMS`, `BUILDINFO`, provenance, `PACKAGE-INPUTS.json` and its
content-addressed APT transactions, `ISO-BUILD.json`,
`boot-proof.json`, `qemu-lab-report.json`, serial output, command log and run manifest.
The ISO itself has historically been excluded because of its size. That means the bundle
can compare available ISO bytes with the recorded digest, but cannot reproduce or recover
an absent ISO from a digest. A writable local run directory is append-only only by
application policy; it is not cryptographically immutable or authenticated. That stronger
claim requires a verified manifest signature or a trusted WORM/content-addressed anchor.
Reproducibility remains unproved until two independent builds are compared, and historical
evidence preservation requires retaining the corresponding ISO or a content-addressed
artifact. The package leg publishes the `.deb`, `.changes`, `.buildinfo` and verdict JSON.

`evidence-status` is given `--output-dir` explicitly, because its default is
`dist/reports` while the build writes `dist`, so the default reports a successful build's
own artifacts as missing.

The command log now lives inside `dist/evidence/runs/<run_id>/commands.jsonl` (or
`plans/<run_id>` for a dry-run), beside the reports it explains. Every command, exit
status and bounded output tail is recorded by `RUN-MANIFEST.json`. That local closure is
not authentication until the manifest is signed and verified or WORM-anchored. A failing
run therefore keeps its own log without interleaving it with an earlier build.

Before this, there was no command log to stage. `run_iso_build` accepted a `log_path` and
both of its production callers passed nothing, so `_write_event` returned on its first line
and `distroforge iso-build --execute` recorded nothing at all. The default now lives in
`run_iso_build` rather than in each caller.

## What the first real run measured

Dispatched 2026-07-27, and it is the reason several numbers on this page are now facts
instead of quotes from documentation.

The runner was not what the definition assumed. That run inherited a floating
`ubuntu-latest`, an older LTS, and measured **145 GB** on `/` with **88 GB free** — not
the 14 GB the Actions docs state, which `.github/golden-path/reference-derivative.yaml`
had cited as the reason to skip a desktop. 4 CPUs, 15 GiB RAM. `sudo` authenticates with
no prompt. Those figures are the previous image's; **every job now names `ubuntu-26.04`**,
so the next run re-measures them, which is why that step exists at all.

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

Answered: a `--variant=minbase` mmdebstrap produced a tree with `env` and no `apt-get`, in
23 seconds, exiting 0, because **nothing had asked it for apt**.

The two tools this code can call disagree in writing about that variant. debootstrap(8)
defines `minbase` as "required packages **and apt**" and adds apt itself; mmdebstrap(1)
defines `required, minbase` as the essential set plus `?priority(required)`, and never
mentions apt. In resolute's archive `apt` is `Priority: important` — neither `required`
nor `Essential: yes` — so the mmdebstrap reading excludes it by definition. mmdebstrap
exited 0 because it installed precisely what it was asked for.

This was briefly written off here, on the grounds that a local simulate resolved **129**
packages including `Inst apt (3.2.0 Ubuntu:26.04/resolute)` anyway. That measurement was
real and the conclusion drawn from it was wrong. mmdebstrap(1)'s VARIANTS section says
every package set "also include[s] the direct and indirect hard dependencies", so apt was
arriving as some `Priority: required` package's dependency — an accident of the dependency
graph, not a request. The run that broke resolved a different graph — an inherited
`mmdebstrap` **1.4.3-6** against a resolute suite, which the pinned `ubuntu-26.04` runner
fixes for its own reasons — and the accident did not hold.

The fix is in `core/bootstrap.py`: the include list now reads `apt,ca-certificates`, so
neither the tool, its version, nor the archive's priority fields decide whether the next
phase has a package manager. Naming apt is a no-op for debootstrap, which had it already;
that is the point — one request that does not depend on which binary `has_binary` found.

No golden-path run has exercised this yet.

Note, for anyone repeating the simulate: `--simulate` alone prints no package set at all
(`I: no essential packages -- skipping`); the list only appears with `--verbose`.

What does not depend on the answer is the refusal. A bootstrap tool exiting 0 is a claim
about the tool, not about the tree, and this build believed it twice over:

- nothing checked the tree the tool had just made, so the build ran five more phases
  before a chroot said `apt-get` was missing — by which point the tool's own output,
  which would have named what it declined to install, had been discarded, because the
  runner then kept output only for commands that *failed*, and passed on no log path at
  all from this entry point. Both of those are fixed above, so the next run keeps the
  bootstrap's own words whatever it does with them;
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
| ISO | `runs-on: ubuntu-latest` | an older LTS, `mmdebstrap 1.4.3-6` |
| Package | `container: ubuntu:devel` | **stonking** (26.10) |
| The source itself | `--release 26.04`, `debian/changelog` | **resolute** (26.04) |

Every label in that table is now pinned: `runs-on: ubuntu-26.04` in every job of both
workflows, and `container: ubuntu:26.04` in the two that use one. **Resolute is this
project's development cycle and the only suite any leg may name.**

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
