<p align="center">
  <img src="debian/distroforge.svg" width="128" height="128" alt="DistroForge logo">
</p>

<h1 align="center">DistroForge</h1>

<p align="center">
  <strong>Build Ubuntu and Debian live images with a workflow you can inspect,
  reproduce, and trust.</strong>
</p>

<p align="center">
  A safety-first Python toolkit and Qt desktop app for planning, validating,
  building, testing, and releasing customized Ubuntu/Debian live ISOs with
  dry-run workflows, reproducible artifacts, and maintainer guardrails.
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
- **Extend without hiding work** — use project hooks, Pluggy integrations,
  reusable profiles, and YAML or JSON definitions.

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
sudo apt install ./distroforge_0.3.5-1_all.deb
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
- [Artifacts and release readiness](docs/artifacts-release-readiness.md)
- [CLI and GUI parity](docs/gui-parity.md)
- [Debian and Ubuntu Python policy](docs/debian-ubuntu-python-policy.md)
- [Packaging and release hygiene](docs/packaging-release.md)
- [Imported baseline provenance](PROVENANCE.md)

## Development

Install the development dependencies, then run the same checks used by CI:

```bash
.venv/bin/python -m ruff check .
.venv/bin/python -m pytest
.venv/bin/python -m distroforge packaging-policy .
```

Focused bug reports and pull requests are welcome. New workflows should
preserve dry-run behavior, CLI/GUI parity, explicit privilege boundaries, test
coverage, and Debian/Ubuntu policy compliance.

Debian package builds are an explicit maintainer operation during alpha
development. See [Packaging and release hygiene](docs/packaging-release.md)
before producing package artifacts.

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
