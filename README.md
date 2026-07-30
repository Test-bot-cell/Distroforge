<p align="center">
  <img src="share/icons/distroforge.svg" width="128" height="128" alt="DistroForge logo">
</p>

<h1 align="center">DistroForge</h1>

<p align="center">
  <strong>Build Ubuntu and Debian live images with a workflow and evidence you
  can inspect and verify.</strong>
</p>

<p align="center">
  A safety-first Python toolkit and Qt desktop app for planning, validating,
  building, testing, and releasing customized Ubuntu/Debian live ISOs with
  dry-run workflows, reproducibility controls, and maintainer guardrails.
</p>

## From an idea to an auditable ISO

DistroForge brings the moving parts of live-image creation into one guided
workflow: source selection, packages, desktop environment, branding,
validation, ISO assembly, virtual-machine checks, and release evidence.

It is designed for newcomers who want a clear next step and maintainers who
need precise controls. The CLI and desktop application use the same underlying
services, so a project remains understandable whichever interface you prefer.

```mermaid
flowchart LR
    A["Choose a source"] --> B["Describe the image"]
    B --> C["Review readiness"]
    C --> D["Inspect the dry run"]
    D --> E["Build explicitly"]
    E --> F["Prove, verify, release"]
```

> [!CAUTION]
> DistroForge 0.3.5 is alpha software. Builds are dry-runs by default and real
> execution is always explicit. Use a dedicated build host or virtual machine,
> review the generated plan, and keep backups before privileged operations.

## Why DistroForge?

- **Inspect before building** — plans, readiness checks, risk explanations,
  and dry-run reports reveal what will happen before the host or image changes.
- **Start from a visible source** — choose a minimal skeleton, an official
  ISO or netboot source, a verified local ISO, or a previous project.
- **Keep customization coherent** — packages, desktop choices, branding,
  mirrors, users, services, and advanced modules share one validation model.
- **Capture intent, not a machine clone** — export a sanitized profile from an
  installed system without copying user homes, credentials, caches, or machine
  identity.
- **Build with evidence** — produce checksums, provenance, reports, optional
  SPDX or CycloneDX SBOMs, and release-readiness artifacts.
- **Test before publishing** — plan or run QEMU workflows, inspect boot
  evidence, and block incomplete releases through an explicit release gate.
- **Stay local-first** — ForgeAdvisor explains logs and findings with local
  evidence; optional local model adapters never gain build authority.
- **Extend without hiding work** — use project hooks, executable phase plugins,
  reusable profiles, and YAML or JSON definitions. Sealed ISO builds refuse
  in-process `plugin.py` loading so extension executables remain inside the recorded
  command boundary.

## Install

### From source

DistroForge requires Python 3.11 or newer.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev,typer,gui]"
```

System tools such as `debootstrap`, `xorriso`, `squashfs-tools`, and QEMU
remain distribution packages. Let DistroForge show what is available on the
host:

```bash
.venv/bin/distroforge doctor
```

The GUI extra installs PySide6. The Debian package instead integrates with the
distribution-provided PyQt6 stack and recommends the Adwaita font, icon, and
Qt SVG packages used by its GNOME-native presentation.

### From a Debian package

If you have a DistroForge release package:

```bash
sudo apt install ./distroforge_0.3.5-2_all.deb
```

The package installs the CLI, Qt launcher, manual pages, examples, and the core
host tools used by the ISO workflow.

## Quick start

Create a project and inspect the complete path without executing a build:

```bash
PROJECT="$HOME/DistroForge/MyDistro"

distroforge releases
distroforge source-starters --release 26.04
distroforge new MyDistro "$PROJECT" --release 26.04
distroforge plan "$PROJECT"
distroforge readiness "$PROJECT"
distroforge iso-doctor "$PROJECT"
distroforge iso-build "$PROJECT"
```

`iso-build` remains a dry-run until execution is requested explicitly. When
the project, source trust, host tools, output path, and privilege settings are
ready:

```bash
distroforge iso-build "$PROJECT" --execute --boot-proof auto
distroforge iso-accept "$PROJECT"
```

Launch the desktop application with either entry point:

```bash
distroforge-gui
# or
distroforge gui
```

The responsive Qt interface exposes the same project, build, capture,
virtualization, quality, and release workflows as the CLI. Its Command Center
also shows CLI equivalents, making it possible to learn the automation surface
while using the desktop app.

## Explore the workflows

### A guided first build

```bash
distroforge journey "$PROJECT"
distroforge beginner-iso "$PROJECT" --apply-safe-defaults --dry-run
```

Power users can inspect the wider option set without weakening the default
safety posture:

```bash
distroforge poweruser-iso "$PROJECT" --apply-safe-defaults --dry-run
distroforge build-phases
```

### Installed-system capture

```bash
distroforge capture / --output system-profile.yaml --sanitize strict
distroforge capture-diff system-profile.yaml
distroforge rebuild-from-capture system-profile.yaml /tmp/captured-rebuild
```

Capture is read-only: it extracts reviewable configuration intent instead of
cloning the running system.

### Derivative profiles

```bash
distroforge derivative-profiles
distroforge derivative-profile plan mint-ubuntu
distroforge derivative-profile validate mint-ubuntu
distroforge derivative-profile create-project mint-ubuntu --root /tmp/mint-forge
```

Built-in derivative profiles are transparent starting points, not claims of
reproducing private vendor build pipelines.

### Release confidence

```bash
distroforge boot-proof "$PROJECT" --iso /path/to/image.iso --backend auto
distroforge boot-proof "$PROJECT" --iso /path/to/image.iso --firmware uefi --secure-boot
distroforge release-readiness \
  --iso /path/to/image.iso \
  --output-dir "$PROJECT/out"
distroforge release-gate "$PROJECT" --iso /path/to/image.iso
distroforge publish-drill "$PROJECT" --iso /path/to/image.iso
```

Building, boot evidence, signing, verification, and publication decisions stay
separate and auditable.

## Safety model

DistroForge treats safety as a product feature:

- dry-run behavior is the default;
- execution and privileged actions require explicit intent;
- source ISO checksum and signature metadata can be enforced;
- protected rootfs and ISO writes cross one controlled filesystem boundary;
- preflight checks stop incomplete builds early;
- optional rollback snapshots protect risky phases;
- build history, reports, checksums, and provenance remain reviewable;
- ForgeAdvisor is advisory only and cannot execute a build on its own.

The open `0.3.5-17` audit keeps a deliberately narrower truth boundary. Source-ISO
execution is fail-closed on a regular source file, an external SHA-256, a detached
signature and one full signer fingerprint, but publication remains `review` until those
verification inputs can be replayed from sealed evidence. Package evidence closes
per-source signed metadata, freshness policy, command ledger and exact `.deb` inputs.
M3.1 adds `PACKAGE-FILESYSTEM-CAUSALITY.json`, schema
`distroforge.package-filesystem-causality.v1`. For a fresh bootstrap, an authoritative
refresh re-extracts those exact sealed package payloads and compares their objects with
`ROOTFS-MANIFEST.json` as `exact`, `modified`, `missing`, `unattributed`, `ambiguous`,
`structural`, `excluded` or `unsupported`. `payload_identity` is `verified` only when that
bootstrap map accounts for every supported in-scope member of the sealed
`PACKAGE-INPUTS.final_inventory` snapshot. That inventory is captured before arbitrary
post-host hooks; M3.1 does not re-snapshot dpkg state after them. M3.1
does not yet inspect payload blobs in ISO-remaster mode: without a semantic source-ISO
baseline it conservatively classifies the whole final manifest `unsupported` and records
`payload_identity: partial`. Unsupported objects and excluded payload paths also make a
bootstrap result `partial`. Either value is static identity, not evidence that APT, dpkg,
maintainer scripts, triggers, conffiles or another producer caused the final object.
The map's own scope is therefore `sealed-recorded-deb`, not self-authenticated input:
the release gate must first replay the separate signed package-input and external-policy
proof. Every M3.1 read and its one-time output creation is anchored below one
non-symlinked run-directory descriptor. JSON, package counts, tar bytes, physical
headers, extension chains, PAX metadata and both `dpkg-deb` streams have explicit
incremental refusal bounds, while evidence paths are byte/depth bounded before parsing
and must already be canonical; compressed or malformed filesystem tar streams are
rejected.
Those budgets are proved by hostile fixtures, not yet sized by a real desktop run; a
product build that exceeds one must stop and justify a measured schema/budget change.
Schema v1's `payload_identity` is enumeration coverage: `modified`, `missing` and
`ambiguous` remain separate comparison counts rather than silently changing that status.
M3.2a adds `PACKAGE-APT-ACTIONS.json`, schema
`distroforge.package-apt-actions.v1`, as a bounded, self-consistent replay of supplied APT
`DPkg::Pre-Install-Pkgs` version-3 transcripts and their bindings to the recorded
package/version/architecture identities. It does not authenticate APT as the origin:
the transcript, journal and CAS remain mutable inside the target rootfs until host
collection. Every report therefore records `capture_origin:
unverified-mutable-target-rootfs`, `filesystem_causality: unverified` and
`release_ready: false`; a non-empty replay records `apt_actions: self-consistent`, not
“executed by APT”. M3.2b must add a host-isolated one-shot witness acknowledged before
dpkg can run, then bind observed producer deltas, package scripts and dpkg
transformations. The release gate still blocks publication. The semantic rootfs manifest,
SquashFS round-trip, final-ISO replay, M3.1 map and M3.2a receipt are implemented and
tested with offline, rootless fixtures, not promoted to an executed build claim. No new
real APT transaction, dpkg operation, ISO or boot was produced by this hardening work; see
the [ISO build proof ledger](docs/iso-build-proof-ledger.md).

## Supported sources

The bundled catalog in 0.3.5 includes Ubuntu 24.04 LTS, Ubuntu 25.10, Ubuntu
26.04 LTS, and Debian 13.5 starters, with Ubuntu 26.10 marked as planned.
Run `distroforge releases` and `distroforge source-starters` for the exact
catalog shipped by your installation.

## Documentation

- [Architecture](docs/architecture.md)
- [Build pipeline](docs/build-pipeline.md)
- [Image definitions](docs/definitions.md)
- [Capture workflows](docs/capture-workflows.md)
- [Derivative profiles](docs/derivative-profiles.md)
- [Beginner, power-user, and trust workflow](docs/beginner-power-trust-trilogy.md)
- [Artifacts and release readiness](docs/artifacts-release-readiness.md)
- [CLI and GUI parity](docs/gui-parity.md)
- [Debian and Ubuntu Python policy](docs/debian-ubuntu-python-policy.md)
- [Packaging and release hygiene](docs/packaging-release.md)
- [Imported baseline provenance](PROVENANCE.md)

## Development

Install the development dependencies, then run every check per-push CI runs, on
Python 3.11 through 3.14 against both Qt bindings:

```bash
make check
```

That is `ruff`, `mypy`, `pytest`, `shellcheck` over the Debian maintainer scripts, and
`compile()` over the `python3` payloads embedded in them. This section used to name two
of the five and stop the Python list at 3.13, both of which had been wrong since the
matrix and the gates grew.

Before a package review, also run the source-only packaging verdict, which per-push CI
does not run:

```bash
.venv/bin/python -m distroforge packaging-policy .
```

The suite is offline and rootless by design, and never executes a product package or ISO
build. A bounded fixture subset does run installed `apt-config`, `dpkg-deb`, `gpg`,
`xorriso`, `mksquashfs`, `unsquashfs` and `tar --zstd` processes on synthetic or
repository-pinned inputs. `apt-config` parses the generated evidence-hook fragment, and a
controlled-root harness executes the generated shell pre/post state machine with
synthetic input and controlled helpers; neither runs a real apt/apt-get transaction or
dpkg operation. Non-Essential test dependencies are declared explicitly; `dpkg-deb`
comes from Essential package `dpkg`, while `apt-config` comes from the declared
`apt <!nocheck>` build dependency. The suite never runs `debootstrap`, QEMU or sbuild, so
a green result proves the plans and contracts, not that a real ISO boots.
Line coverage is 74.7% overall and 58.6% under `distroforge/ui/`.

The [golden path](docs/golden-path.md) is the authorized weekly execution harness
intended to prove that a real ISO boots; its existence is not that proof. Its current
verdict is blocked: the reference ISO has no usable GPT ESP, an audit variant reaches
shim but not GRUB, and no digest-linked v2 run has reached login or a desktop. `mypy`,
`shellcheck` and `pre-commit` gate every push. The package leg is configured to gate on
`lintian`, but the first executing attempt did not complete its declared autopkgtest.
See the [ISO build proof ledger](docs/iso-build-proof-ledger.md) for the exact milestones.

Focused bug reports and pull requests are welcome. New workflows should
preserve dry-run behavior, CLI/GUI parity, explicit privilege boundaries, test
coverage, and Debian/Ubuntu policy compliance.

Debian package builds are an explicit maintainer operation during alpha
development, with one standing exception: the weekly
[golden path](docs/golden-path.md), which is that authorization given once. See
[Packaging and release hygiene](docs/packaging-release.md) before producing package
artifacts.

## Project layout

```text
distroforge/   Application services, commands, data, and Qt interface
tests/         Regression, policy, CLI, and UI contract tests
examples/      Reviewable image definitions
docs/          Architecture, workflows, policy, and release guidance
debian/        Debian packaging and autopkgtest integration
```

## License and project identity

DistroForge is released under the [MIT License](LICENSE).

DistroForge is an independent project and is not affiliated with or endorsed by Canonical.
Ubuntu is mentioned solely as a compatible target distribution.
