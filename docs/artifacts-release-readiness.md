# Artifacts and Release Readiness

DistroForge treats build outputs as host artifacts. Users should be able to see and select
where important files land before a build or release review starts.

## Host Artifact Paths

```bash
distroforge artifact-paths /path/to/project
```

The GUI **Artifacts** page exposes the same paths:

- output ISO;
- reports directory;
- livefs ISO work directory;
- Debian live-build directory;
- QEMU screenshot;
- QEMU serial log.

The **Advanced Modules** `Output ISO` field and CLI `--output-iso` remain the build option
source for the final ISO path.

## Release Readiness

```bash
distroforge release-readiness --iso /path/to/image.iso --output-dir /path/to/output
distroforge release-gate /path/to/project --iso /path/to/image.iso --output-dir /path/to/output
distroforge publish-bundle /path/to/project --iso /path/to/image.iso --output-dir /path/to/output
distroforge sign-release /path/to/project --bundle-dir /path/to/project/dist/publish
distroforge release-notes /path/to/project --bundle-dir /path/to/project/dist/publish
distroforge verify-release /path/to/project --bundle-dir /path/to/project/dist/publish
distroforge explain-release /path/to/project --iso /path/to/image.iso --bundle-dir /path/to/project/dist/publish
distroforge publish-drill /path/to/project --iso /path/to/image.iso
distroforge publish-drill-baseline /path/to/project
distroforge publish-drill-diff old/PUBLISH-DRILL.json new/PUBLISH-DRILL.json
distroforge release-pipeline /path/to/project --bundle-dir /path/to/project/dist/publish --run-boot-proof --boot-backend auto
distroforge boot-proof /path/to/project --iso /path/to/image.iso --backend auto
distroforge boot-proof /path/to/project --iso /path/to/image.iso --backend qemu --dry-run
distroforge boot-proof /path/to/project --iso /path/to/image.iso --backend iso-scan
```

The report summarizes the release surface:

- ISO path and size;
- SHA-256 when the ISO exists;
- `SHA256SUMS`, `BUILDINFO`, `INTEGRITY`, provenance and QEMU report presence;
- `compatibility-report.txt` release support summary;
- planned QEMU smoke coverage;
- trademark/redistribution review warning;
- repository trust warning.

Missing ISO is blocking. Missing reports are review items until the release pipeline writes
them.

`release-gate` is stricter: it is the maintainer publication stoplight. It blocks when the
final ISO, `SHA256SUMS` verification, source trust, boot proof, release files, release
readiness, or packaging policy evidence are missing. It returns `blocked`, `review`, or
`ready` in text or JSON.

`publish-bundle` creates `dist/publish/` for maintainer review. It copies the ISO,
`SHA256SUMS`, `BUILDINFO`, provenance, HTML report, executed boot proof when present, plus
`RELEASE-GATE.json` and `README-PUBLISH.txt`. A blocked release gate still produces an
inspection bundle, but the README marks it `BLOCKED` and lists the blocking items.

`sign-release` adds maintainer signing evidence to the bundle. It always writes
`RELEASE-MANIFEST.json` with file sizes and SHA-256 digests, then writes
`SIGNING-REPORT.json`. By default it is a plan: GPG commands are recorded but no signature
is made. Passing `--execute` signs `SHA256SUMS`, `RELEASE-GATE.json`, and
`RELEASE-MANIFEST.json` when `gpg` is available.

`release-notes` writes the human review layer: `RELEASE-NOTES.md` and `CHANGELOG.txt`.
The notes summarize status, ISO digest, included artifacts, boot proof, signing evidence,
blocking gate items and verification commands.

`verify-release` writes `VERIFY-REPORT.json`. It verifies every file listed in
`RELEASE-MANIFEST.json`, checks sizes and SHA-256 digests, verifies `SHA256SUMS` against
the ISO, compares the manifest and release-gate status, and attempts GPG verification for
present detached signatures when `gpg` is available. Missing planned signatures remain
review items; corrupted files block the bundle.

`explain-release` writes `RELEASE-EXPLAIN.md`. It reads the gate, boot proof, manifest and
verification reports, separates ready, review and blocked evidence, names the boot proof
level (`runtime` or `structural`), and prints the next maintainer commands to improve or
verify the bundle.

`publish-drill` runs the full safe maintainer rehearsal in one command: boot proof with
`auto`, release pipeline, signing plan, verification, explanation, and
`PUBLISH-DRILL.json`. It never signs by default; real signing requires explicit
`--execute-signing`.

`publish-drill-diff` compares two drill reports and returns `improved`, `unchanged`, or
`regressed`. It flags status or release-gate regressions, boot proof downgrades, new
blockers, manifest removals or SHA changes, signing changes, and next-command changes.

`publish-drill-baseline` promotes the current `PUBLISH-DRILL.json` to
`PUBLISH-DRILL.previous.json` for future comparisons. It refuses blocked drills unless
`--allow-blocked` is explicit, and writes `PUBLISH-DRILL-BASELINE.json`.

`release-pipeline` runs the maintainer sequence in one command: repair derivable artifacts
when an ISO exists, optionally run boot proof with `--run-boot-proof --boot-backend
auto|qemu|iso-scan`, create the publish bundle, generate signing evidence, write release notes,
refresh the manifest so the notes are covered, verify the bundle, and write
`RELEASE-PIPELINE.json`.

`boot-proof` is the normalized boot evidence command. In dry-run mode it writes
`boot-proof.json` with status `planned`. The default `auto` backend attempts QEMU runtime
proof first, then falls back to `iso-scan` when QEMU is missing or blocked by the host.
The report records `attempted_backends`, `selected_backend`, and `proof_level`. The `qemu`
backend requires QEMU, runs the configured boot smoke, captures `qemu-lab-report.json`,
and marks `boot-proof.json` ready only when the executed proof report exists. The
`iso-scan` backend is a headless fallback: it records ISO size, SHA-256, ISO9660 volume
metadata, El Torito boot catalog evidence and kernel/initrd or live payload markers. A
complete scan can mark `boot-proof.json` ready; partial structural evidence is `review`.
The release gate rejects planned or review proof as blocking evidence.

## Software Bill of Materials

Every build writes `distroforge-provenance.json`. When `--sbom-format` selects a standard
format, the build writes a portable SBOM next to it: `distroforge-sbom.spdx.json` for
SPDX-2.3 or `distroforge-sbom.cdx.json` for CycloneDX 1.5. Release readiness reports
provenance presence in the artifact summary, so a published bundle carries a
vendor-neutral component inventory alongside the native provenance document. The GUI
**Quality Lab** exposes the same SBOM format selector as the CLI `--sbom-format` flag.

## QEMU Install Smoke Plan

```bash
distroforge qemu-smoke-plan --iso /path/to/image.iso
```

The plan covers the maintainer matrix before publication:

- live BIOS offline boot;
- BIOS offline install;
- UEFI online install;
- UEFI Secure Boot live boot as planned coverage.

It is a plan, not an automatic install runner. Execution belongs in the QEMU lab once the
maintainer is ready to spend the time and disk space.

## Debian Package Polish

```bash
distroforge ci /path/to/project --debian-package
distroforge buildinfo-report ../distroforge_VERSION_ARCH.buildinfo --changes ../distroforge_VERSION_ARCH.changes
distroforge packaging-policy /path/to/project --buildinfo ../distroforge_VERSION_ARCH.buildinfo --changes ../distroforge_VERSION_ARCH.changes
distroforge autopkgtest-doctor /path/to/project --backend schroot --execute --output dist/AUTOPKGTEST-DOCTOR.json
distroforge hermetic-build-plan /path/to/project --backend sbuild --suite unstable
```

`ci --debian-package` adds Debian package checks to the CI plan. In dry-run mode it records
the package build, lintian, autopkgtest and packaging policy steps; with `--execute` it runs
through the normal command runner.

`buildinfo-report` parses `.buildinfo` files and can combine them with `.changes`
metadata when `--changes` is provided. It highlights:

- `usr-local-has-programs`;
- `usr-local-has-libraries`;
- `Distribution: unstable` from `.buildinfo` when present, or from `.changes` when
  Debian records the publication suite there.

`packaging-policy` checks package-data modes, required docs in `debian/docs`, YAML
examples declared for Debian install, autopkgtest smoke quality, optional lintian/tool
availability, optional buildinfo taint, and optional `.changes` publication-suite
metadata. Missing host `autopkgtest` is reported separately from weak or undeclared
package smoke tests.

`autopkgtest-doctor` records the executed package smoke result separately from declaration
quality. `--backend schroot` auto-selects a visible `sbuild`-style testbed when possible;
saved `AUTOPKGTEST-DOCTOR.json` evidence lets package dashboards distinguish a writable
testbed pass from a broken local backend.

`hermetic-build-plan` is the official clean-build path. It renders commands for `sbuild`,
`pbuilder`, or `mmdebstrap` without assuming the current workstation is clean enough for
publication.
