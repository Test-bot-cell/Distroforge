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

## Where the artifacts are looked for

`dpkg-buildpackage` writes the `.deb`, `.changes` and `.buildinfo` into the **parent of
the source tree**, so that is where `debian-package`, `evidence-status` and the hermetic
bundle look by default. Pass `--artifact-dir DIR` when the archive is kept somewhere else:

```bash
distroforge debian-package . --artifact-dir ~/packages/distroforge
distroforge evidence-status . --profile package --artifact-dir ~/packages/distroforge
distroforge hermetic-release-bundle . --output ../bundle --artifact-dir ~/packages/distroforge
```

Without it, a maintainer who moves the archive gets a report that looks clean because the
directory it read was empty — the one failure mode indistinguishable from success. The GUI
equivalent is the **Package artifact dir** field on the Artifacts page, empty by default.
`packaging-policy` deliberately has no such flag: `--buildinfo` and `--changes` already
name the files it reads, and a second way to say the same thing is a second thing to keep
in agreement.

`debian-package` is the maintainer wrapper around `dpkg-buildpackage -us -uc -b`.
Without `--execute` it renders the build and check plan. With `--execute` it collects
produced `.deb`, `.changes` and `.buildinfo` artifacts, records file sizes and SHA256
digests, runs `lintian` and `autopkgtest` when available, and embeds the packaging policy
verdict in one reviewable report.

`lintian` is always invoked as `lintian --profile debian --no-tag-display-limit`. The
profile is pinned because a lintian profile is a **vendor**, never a suite: there is no
`resolute` profile, and an unpinned run takes its verdict from whichever vendor the host
happens to be, so the same `.dsc` could pass on one machine and fail on the next. The
display limit is lifted because a truncated report cannot be turned into a reason string.
The verdict is graded from the tags rather than the exit code — `lintian` exits 0 on a
package carrying warnings — so any tag reads as `review required` with every tag kept in
the reason, an `E:` tag as `failed`, and `127` as `missing`. `--fail-on warning` is the
wrong lever here: it turns the exit code into 2 for a healthy artifact without blocking
anything and still says nothing about which tag to fix. Tags get fixed, never overridden:
the package ships no `lintian/overrides/distroforge`, because silencing a tag is not the
same thing as being clean.

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

`debian/changelog` currently uses `resolute` — the Ubuntu 26.04 series — for every stanza
from `0.3.4-2` onward; `unstable` was last used for `0.3.4-1`. Before publishing through a
PPA, Ubuntu repository, Debian repository, or a private archive, confirm that the changelog
distribution names the real target channel (`noble`, `resolute`, `trixie`, `experimental`,
`unstable`, or the private archive suite) rather than the one that happened to fit the last
local build.

## Publishing the Signing Key

Nothing in this tool exports a public key, and that is worth stating because the exposure
it would create is not visible from the code. `sign_release_bundle` produces detached
signatures only (`gpg --armor --detach-sign`), and a detached signature carries the key id,
never the key's user ids. The one keyring DistroForge writes into an image belongs to a
third party: `core/ppa.py` fetches a PPA key from a keyserver by fingerprint into
`/usr/share/keyrings/distroforge-<slug>.gpg` and points a `signed-by=` at it. The
maintainer's own key is never exported by any code path.

It becomes a question the day this project publishes an apt repository, because a
`signed-by=` keyring has to be published for anyone to verify it, and a full export
carries every user id on the key. The signing key here,
`93D942241BECDD422606C36C4C0D75219B5506CF`, carries two: the GitHub noreply used as the
commit author identity, and a personal mailbox. Exporting it whole would publish the
personal one to everyone who ever installs from the repository.

Export the published identities only:

```
gpg --export \
    --export-filter 'keep-uid=uid =~ noreply.github.com || uid =~ distroforge.anonaddy.com' \
    93D942241BECDD422606C36C4C0D75219B5506CF > distroforge-archive-keyring.gpg
```

Measured 2026-07-27: the whole key exports as 2927 bytes carrying both user ids, the
filtered form as 2278 bytes carrying one. Imported into an empty `GNUPGHOME`, the filtered
export verifies a real signature made by that key -- `gpg --verify` returns 0 and reports a
good signature -- so dropping the user id costs nothing an archive needs. Verification uses
the key material, not the labels on it.

Two things the filter cannot do. It governs one export and not a key already uploaded
somewhere: a keyserver that has the key with its personal user id will not forget it, and
neither will anyone who fetched it. Checked 2026-07-27 -- `keys.openpgp.org` and
`keyserver.ubuntu.com` both answer 404 for that fingerprint, so nothing personal is
published yet and this stays a precaution rather than a repair. And it cannot add what is
missing: the `Maintainer` field names `github@distroforge.anonaddy.com` while the key has no
user id for that address, so a keyring exported today authenticates the archive without
naming the maintainer it belongs to. Adding that user id to the key is a change to the
maintainer's own keyring and needs their passphrase; the filter above already accepts it, so
it needs no change here once added.

Two tests hold the parts of this a machine can check. One rejects any mailbox appearing in
the tree that is not a published identity -- an allowlist, deliberately, because a denylist
would have to spell out the address it is protecting, in a public repository. The other
rejects a documented `gpg --export` without `--export-filter`, since this document is the
only place the export exists.
