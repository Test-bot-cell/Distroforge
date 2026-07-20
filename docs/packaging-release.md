# Packaging and Release Hygiene

DistroForge alpha builds can be produced locally with:

```bash
dpkg-buildpackage -us -uc -b
```

Local builds are convenient smoke checks only. Publication builds should first render a
hermetic plan, then run the package build in a clean environment:

- `sbuild`;
- `pbuilder`;
- `mmdebstrap` plus a clean chroot;
- a disposable container or VM with only declared build dependencies installed.

## Buildinfo Taint

If `.buildinfo` contains:

- `usr-local-has-libraries`
- `usr-local-has-programs`

the build host has files in `/usr/local` that may influence the build. This is acceptable
for local alpha smoke testing, but a published package should be rebuilt in a hermetic
environment so provenance is easier to trust.

Use DistroForge's reports before publishing:

```bash
distroforge doctor --debian-dev
distroforge hermetic-build-plan . --backend sbuild --suite unstable
distroforge debian-package . --execute
distroforge buildinfo-report ../distroforge_VERSION_ARCH.buildinfo --changes ../distroforge_VERSION_ARCH.changes
distroforge packaging-policy . --buildinfo ../distroforge_VERSION_ARCH.buildinfo --changes ../distroforge_VERSION_ARCH.changes
distroforge autopkgtest-doctor . --execute --output dist/AUTOPKGTEST-DOCTOR.json
distroforge autopkgtest-doctor . --backend schroot --execute --output dist/AUTOPKGTEST-DOCTOR.json
distroforge evidence-status .
distroforge evidence-status . --verbose
distroforge evidence-status . --profile package --fix-plan
distroforge forgeadvisor copilot . --profile package
distroforge evidence-verify ../distroforge-VERSION-hermetic-release
distroforge hermetic-release-bundle . --output ../distroforge-VERSION-hermetic-release --suite resolute --autopkgtest-dir ../distroforge-VERSION-hermetic-release/AUTOPKGTEST --autopkgtest-report dist/AUTOPKGTEST-DOCTOR.json
```

`doctor --debian-dev` audits the maintainer workstation by group: Debian packaging,
clean-build QA, Python/source lint, ISO/live media tooling, publishing tools, native
build helpers, and documentation converters. With `--install`, it uses
`apt-get install --no-remove` for missing safe packages; tools that may change the
live/initramfs stack are reported separately for manual review.
`evidence-status --profile package` and `forgeadvisor copilot --profile package`
include this doctor signal, detect recent package artifacts from the source tree's
parent directory, and turn `/usr/local` buildinfo taint into a hermetic rebuild
next action.

`debian-package` is the maintainer wrapper around `dpkg-buildpackage -us -uc -b`.
Without `--execute` it renders the build and check plan. With `--execute` it collects
produced `.deb`, `.changes` and `.buildinfo` artifacts, records file sizes and SHA256
digests, runs `lintian` and `autopkgtest` when available, and embeds the packaging policy
verdict in one reviewable report.

Before running the normal test suite outside a package build, clean generated Debian
artifacts with:

```bash
debian/rules clean
python3 -m pytest -q
```

`debian/clean` must cover pybuild output, package staging directories, debhelper stamps,
substvars and other generated files so the source tree can return to a policy-reviewable
state without special test skips.

The GUI **Artifacts** page exposes the same checks through **Packaging Policy** and
**Hermetic Build**. **Hermetic Bundle** creates the local evidence bundle from already
produced artifacts, including checksums, manifest, a bundle contract, Lintian/buildinfo/
packaging reports, host/chroot backend JSON, optional autopkgtest logs, a local provenance
JSON file, an ISO validation plan and a redacted/no-value OpenAI key hygiene audit. If
`--version` is omitted, the bundle command uses the package version declared in
`debian/changelog`.

`evidence-status` is a source-only dashboard command. It does not build, install or boot
anything; it reads host capabilities, chroot backend status, declared package policy,
planned QEMU smoke scenarios and existing artifact files. It accepts both a normal
DistroForge project root and the DistroForge source tree itself. The default text output
is prioritized: counts, next actions and review/blocked items. Pass `--verbose` to show
ready evidence too. Use `--profile dev|package|iso|publish` to scope the dashboard to the
current lifecycle phase, and `--fix-plan` to print suggested commands without running
them. `forgeadvisor copilot` is the maintainer-facing companion: it explains the same
evidence, prints the preview fix plan, then cites local docs/tests/source snippets in one
advisory report. `evidence-verify` validates an evidence bundle contract such as
`BUNDLE-CONTRACT.json` and reports malformed contracts, missing artifacts or missing
evidence files.

## Autopkgtest Smoke

The Debian autopkgtest smoke must not be marked `superficial`. It must prove that the
installed package can:

- start the CLI with `distroforge --help`;
- list bundled release data with `distroforge releases`;
- report Python dependency health with `distroforge doctor --python`;
- report host build capabilities with `distroforge host`;
- render packaging policy and hermetic build plans from the source package;
- load bundled TOML and JSON package data through `importlib.resources`;
- load and schema-validate an installed YAML example from
  `/usr/share/doc/distroforge/examples/`.

`packaging-policy` distinguishes host capability from package quality:

- `unavailable on host`: the local `autopkgtest` binary is missing, but the package test
  is declared and meaningful;
- `undeclared`: Debian autopkgtest files are missing, which blocks packaging policy
  review;
- `declared but weak`: the test is superficial or misses required installed-package
  checks, which blocks packaging policy review;
- `declared and meaningful`: the host can run autopkgtest and the smoke covers CLI,
  package data and YAML examples.

`autopkgtest-doctor` classifies the real package test run separately from the policy
declaration. In plan mode it renders the exact command it would run. With `--execute`, it
writes a machine-readable report such as `dist/AUTOPKGTEST-DOCTOR.json` when `--output` is
provided. `evidence-status --profile package` consumes that report as `autopkgtest-run` so
maintainers can distinguish a broken local testbed (`testbed-broken`, for example a
read-only `null` backend) from a real package smoke failure (`test-failed`).

For a writable testbed, use `--backend schroot`. When `--testbed` is omitted, the doctor
asks `schroot -l` for available testbeds and prefers an `amd64` `sbuild` chroot such as
`resolute-amd64-sbuild`. If `schroot -l` fails, the report classifies the environment as
`schroot-testbed-unavailable` and includes the configuration error instead of treating the
package smoke as failed. A passed schroot/qemu run stores `status: passed` and makes the
package profile's `autopkgtest-run` evidence ready.

`hermetic-release-bundle` copies `AUTOPKGTEST-DOCTOR.json` when it exists in the artifact
directory, in `dist/`, or when passed with `--autopkgtest-report`. The bundle contract lists
that JSON as optional evidence, and `VERIFY-REPORT.txt` summarizes the status and
classification so release reviewers can tell whether autopkgtest passed or the local
testbed still needs repair.

Debian does not always put the publication suite in `.buildinfo`. When the suite is only
present in `.changes`, pass both files so the report can distinguish build-host taint from
release-channel metadata.

## Installed Documentation

The Debian package installs user-facing docs under:

```text
/usr/share/doc/distroforge/
```

Markdown files may be compressed by debhelper. README links point to source-tree paths for
developer convenience; the packaged copies live in the Debian doc directory.

## Bundled Data Files

Bundled TOML catalogs and JSON data, including `distroforge/data/vulndb.json`, are package
data and must be non-executable (`0644`). Executable data files are packaging noise and
should fail policy tests before beta/RC.
The packaging policy report parses every bundled `distroforge/data/*.toml` and
`distroforge/data/*.json`, and it checks that each file is declared in
`[tool.setuptools.package-data]`; malformed or undeclared data blocks release review because
it would make the installed package fail or silently lose a runtime database.

## YAML Examples and Presets

Human-authored examples under `examples/*.yaml` must load as mappings and pass the same
definition schema used by `--definition`. Every example must be listed in `debian/examples`
so the Debian package installs the documented preset material alongside the binary package.
Maintainer build presets exported by the GUI or CLI use the same schema and should stay
ASCII-safe YAML/JSON with deterministic keys.

## Distribution Channel

`debian/changelog` currently uses `unstable` for local Debian-style alpha builds. Before
publishing through a PPA, Ubuntu repository, Debian repository, or a private archive, set
the changelog distribution to the real target channel such as `noble`, `resolute`,
`trixie`, `experimental`, `unstable`, or the private archive suite.
