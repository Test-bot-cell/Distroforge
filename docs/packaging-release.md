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

## Release Tags

`debian/changelog` reached 46 versions with this repository holding no tags at all, local
or remote, and no GitHub release. Nothing recorded which commit any of those versions was.
A changelog says a version existed; only a tag says where.

The name is DEP-14's and is pinned in `debian/gbp.conf` rather than inherited:
`debian-tag = debian/%(version)s`, so version `0.3.5-16` is tag `debian/0.3.5-16`. DEP-14
mangles what Git will not accept in a ref -- `:` becomes `%`, `~` becomes `_`, `..` becomes
`.#.` -- which no version here has needed yet. `sign-tags = True` is pinned in the same
file for a reason that is easy to miss: gbp does not defer to Git on this.
`gbp/git/repository.py` passes `--no-sign` when the option is unset, which overrides
`tag.gpgsign = true` in the repository config, so leaving it out produces an unsigned
release tag over commits that are every one of them signed.

Cut a tag with `make tag`, which runs `tools/release-tag.sh`. It refuses more than it does:
an `UNRELEASED` changelog entry, a dirty working tree, a branch other than the one
`gbp.conf` calls `debian-branch`, a `HEAD` whose own signature does not verify, a version
already tagged here or on the remote, and a `HEAD` that is not what `origin` already holds
-- there is deliberately no offline path around that last one, because a tag naming a
commit nobody else can resolve means nothing to anyone. It asks gbp itself what the tag
should be called instead of reimplementing the mangling, then checks after the fact that
what gbp created is annotated, is named what was announced, and carries a good signature.

It stops there. Publishing is `git push origin refs/tags/<tag>`, typed separately, because
a tag that has been pushed must not be moved afterwards and that should not happen as a
side effect of asking for a tag.

The first tag under this convention is `debian/0.3.5-16` on `38217da`, cut and pushed
2026-07-27. Annotated: `git cat-file -t` answers `tag`. Signed: `git verify-tag` reports a
good signature, and GitHub's `GET /repos/{owner}/{repo}/git/tags/{sha}` answers
`"verified": true` with `"reason": "valid"`.

Signing needs the key's passphrase, which makes `make tag` a command to run where somebody
is watching. `gpg-agent` launches pinentry, and an unanswered dialog does not report itself
as an unanswered dialog: the sign fails with a timeout whose error source is `<Pinentry>`,
visible as `command 'PKSIGN' failed` in `journalctl --user`. That message names a person who
was not there and not a broken agent -- worth knowing, because it looks like the second
thing. Whether the dialog appears at all is a separate question with a separate answer, and
the agent will tell you which one you have: `gpg-connect-agent 'KEYINFO --list' /bye` prints
`1` in its seventh field for a key whose passphrase is cached and `-` for one that will
prompt.

Versions released before the convention existed are not retro-tagged. The tags that would
have to be invented for them are claims about which commit was uploaded when, and this
repository's history begins at an imported 0.3.5-1 baseline -- most of those 46 versions
have no commit here to point at. Anchoring starts where the mechanism does.

## Branch and Tag Protection

Two repository rulesets, created 2026-07-27. Tag protection is rulesets and not the older
per-repository "tag protection rules", which GitHub fully deprecated on 2024-08-30 and
whose three REST endpoints are closing down. Rulesets have no `enforce_admins` field; an
empty `bypass_actors` is what means nobody is exempt, including the repository owner, who
is the only person who pushes here. An exemption for the owner would have made all of this
decorative.

`main` and `develop` carry four rules: `deletion`, `non_fast_forward`,
`required_linear_history`, `required_signatures`. `refs/tags/debian/*` carries three:
`deletion`, `non_fast_forward`, `update`. The third is the one that is easy to leave out
and matters most for a tag -- `non_fast_forward` only refuses to rewind a ref, so moving a
release tag forward onto a descendant commit would sail through it, and `update` is what
makes the tag immutable rather than merely un-rewindable. The consequence is deliberate:
a mistagged `debian/*` tag cannot be removed without disabling the ruleset on purpose,
which is the correct cost, since the answer to a bad tag is the next version and not a
quiet correction of the last one.

`required_signatures` is on the branches and deliberately not on the tags. GitHub's
documentation describes that rule only in terms of commits on a branch and says nothing
about whether it is enforced on a tag push; the REST enum accepts it for any target, which
is not the same as it doing anything. A rule whose effect cannot be verified is worse than
no rule, because it reads like protection -- so the tag signature is asserted where it can
be checked, by the test that reads the tag object and requires a PGP signature block in it.

Two protections a GitHub repository would normally also carry are deliberately absent, for
one shared reason. This project's release step is a true fast-forward: `main` and `develop`
hold the identical commit SHA, signed by the maintainer's key and Verified on GitHub.
GitHub offers no fast-forward merge for pull requests -- the merge-method enum is closed at
merge, squash and rebase in the REST endpoint, the repository settings, the ruleset rule and
the merge queue alike, and "Rebase and merge" is documented to always create new commit
SHAs and to land commits without their signatures. Routing `main` through a pull request
would therefore trade an identical signed SHA for a rewritten unsigned one. Required status checks fall to the same argument from the other side: GitHub
evaluates them against the commit being pushed, a new commit has no results yet, so
requiring them forecloses direct pushes and forces exactly that pull-request flow. There is
one documented exception, and it does not help here: a locally created merge commit may be
pushed unchecked if its content matches the merge GitHub generated for an up-to-date green
pull request -- still the pull-request flow, and a merge commit, which
`required_linear_history` refuses on these branches anyway.

What stands in their place is that CI runs on every push to `develop`, and `main` is
fast-forwarded only to a `develop` that is green -- the same condition, checked before the
push instead of at it. `required_signatures` is the part that does move server-side,
because a signature is checkable at push time without waiting for anything to run.

A ruleset's `fnmatch` does not let `*` cross a `/`, so `refs/tags/debian/*` covers every name
DEP-14 produces from a Debian version and nothing below another slash.

Enforcement was read back rather than assumed: `GET /repos/{owner}/{repo}/rules/branches/`
returns all four rules for both branches when asked with the owner's own token, and
returns nothing for a branch the ruleset does not cover. A rejected force-push would be
the stronger evidence and has not been run.

One scope question was settled by doing it instead of reading about it. The tag ruleset
carries `update` and `deletion` but not `creation`, and GitHub's documentation does not say
in so many words whether the first three together leave a new tag pushable. Pushing
`debian/0.3.5-16` answered it: exit 0, `* [new tag]`. These rules freeze a tag that exists
without standing in the way of the next one.

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
`93D942241BECDD422606C36C4C0D75219B5506CF`, carries three: the project alias named in the
`Maintainer` field, the GitHub noreply used as the commit author identity, and a personal
mailbox. Exporting it whole would publish the personal one to everyone who ever installs
from the repository.

Export the published identities only:

```
gpg --export \
    --export-filter 'keep-uid=uid =~ noreply.github.com || uid =~ distroforge.anonaddy.com' \
    93D942241BECDD422606C36C4C0D75219B5506CF > distroforge-archive-keyring.gpg
```

Measured 2026-07-27: the whole key exports as 3579 bytes carrying all three user ids, the
filtered form as 2930 bytes carrying the two published ones. Imported into an empty
`GNUPGHOME`, the filtered export verifies real signatures made by that key -- `git
verify-commit` returns 0 on two real commits and gpg reports a good signature -- while the
same command against a keyring with nothing imported returns 1, which is what makes the 0
evidence about the export rather than about an ambient keyring. Dropping a user id costs
nothing an archive needs: verification uses the key material, not the labels on it.

What the filter cannot do: it governs one export, not a copy that is already published
somewhere else. A keyserver that holds the key with its personal user id will not forget it,
and neither will anyone who fetched it.

Measured 2026-07-27, and the answer is not the reassuring one. `keys.openpgp.org` and
`keyserver.ubuntu.com` both answer 404 for this fingerprint, but

```
curl https://github.com/Test-bot-cell.gpg   ->  HTTP 200, 4043 bytes, no authentication
```

serves the key with the personal user id on it. GitHub publishes every GPG key uploaded to
an account at `https://github.com/<login>.gpg`, by design and without asking. So the
personal address was public before this filter was written, and the filter repairs one
channel rather than covering all of them. An earlier revision of this section concluded the
opposite from the two 404s alone; two keyservers not holding a key is no evidence that
nothing holds it, and the account was never asked.

The remaining channel is not in this repository and no change here can close it. Removing
the key from the account (Settings -> SSH and GPG keys) is the only lever, and what that
does to the Verified badge on the commits already signed with it has to be measured before
it is pulled rather than discovered afterwards. That has not been measured here.

The gap it could not close is now closed. The `Maintainer` field names
`github@distroforge.anonaddy.com` and the key had no user id for that address, so a keyring
exported before 2026-07-27 would have authenticated the archive without naming the
maintainer it belongs to. `gpg --quick-add-uid <fingerprint> 'DistroForge maintainers
<github@distroforge.anonaddy.com>'` added it, and the filter above already accepted the
address, so nothing in this procedure changed. One consequence to know about: gpg treats the
most recently self-signed user id as primary, so that alias is now the identity gpg prints
for a signature made by this key. The copy GitHub holds is unaffected -- it stores what was
uploaded, the noreply user id is still on it, and commit verification there is unchanged.
That is also the copy served at the URL above, which is why adding the alias here did not
add it there, and why the personal user id served there is still the one that was uploaded.

Two tests hold the parts of this a machine can check. One rejects any mailbox appearing in
the tree that is not a published identity -- an allowlist, deliberately, because a denylist
would have to spell out the address it is protecting, in a public repository. The other
rejects a documented `gpg --export` without `--export-filter`, since this document is the
only place the export exists.
