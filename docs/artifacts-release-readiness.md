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

The canonical default ISO name is `dist/{name}-{version}.iso` — the only accepted default
form.
Every project-scoped release command whose ISO is optional resolves it through the single
helper `default_output_iso(project)` in `core/artifact_paths.py`, so producer and consumers
cannot drift; there is no unversioned `dist/{name}.iso` fallback. Commands such as
`release-readiness` that have no project argument require the ISO explicitly. Project
commands also accept `--iso` for an ISO that sits somewhere else.

For every release contract, the authoritative product output directory is exactly the
canonical parent of that selected ISO. Thus `--iso /srv/product/image.iso` pairs with
`--output-dir /srv/product`; any other value is refused. The GUI **Reports dir** is a
separate presentation/bundle selector (the default `dist/reports` maps to
`dist/publish`) and never changes the product output directory. `release-gate`,
`publish-bundle` and every downstream consumer receive that selected bundle explicitly:
a signed default `dist/publish` cannot satisfy a gate evaluating another bundle. Before
reporting missing evidence as `review`, the gate opens the selected bundle component by
component without following links; a symlinked, non-directory or unreadable component is
`blocked`.

## Release Readiness

```bash
distroforge release-readiness --iso /path/to/output/image.iso --output-dir /path/to/output
distroforge release-gate /path/to/project --iso /path/to/output/image.iso \
  --output-dir /path/to/output --bundle-dir /path/to/project/dist/publish
distroforge publish-bundle /path/to/project --iso /path/to/output/image.iso \
  --output-dir /path/to/output --bundle-dir /path/to/project/dist/publish
distroforge sign-release /path/to/project --iso /path/to/output/image.iso \
  --output-dir /path/to/output --bundle-dir /path/to/project/dist/publish
distroforge release-notes /path/to/project --bundle-dir /path/to/project/dist/publish
distroforge verify-release /path/to/project \
  --iso /path/to/output/image.iso --output-dir /path/to/output \
  --bundle-dir /path/to/project/dist/publish --gpg-fingerprint FULL_FINGERPRINT
distroforge explain-release /path/to/project --iso /path/to/output/image.iso \
  --bundle-dir /path/to/project/dist/publish --gpg-fingerprint FULL_FINGERPRINT
distroforge publish-drill /path/to/project --iso /path/to/output/image.iso \
  --bundle-dir /path/to/project/dist/publish
distroforge publish-drill-baseline /path/to/project \
  --bundle-dir /path/to/project/dist/publish --iso /path/to/output/image.iso \
  --output-dir /path/to/output --gpg-fingerprint FULL_FINGERPRINT
distroforge publish-drill-diff old/PUBLISH-DRILL.json new/PUBLISH-DRILL.json
distroforge release-pipeline /path/to/project --iso /path/to/output/image.iso \
  --output-dir /path/to/output --bundle-dir /path/to/project/dist/publish \
  --run-boot-proof --boot-backend auto
distroforge boot-proof /path/to/project --iso /path/to/image.iso --backend auto
distroforge boot-proof /path/to/project --iso /path/to/image.iso --backend qemu --dry-run
distroforge boot-proof /path/to/project --iso /path/to/image.iso --backend iso-scan
distroforge boot-proof /path/to/project --iso /path/to/image.iso --backend qemu --firmware uefi
distroforge boot-proof /path/to/project --iso /path/to/image.iso --backend qemu --firmware uefi --secure-boot
```

`--firmware` picks the machine the proof runs on, and the report names it. On a BIOS host
that is essential context: a BIOS result establishes BIOS only and says nothing about UEFI.
The exact rebuilt ISO still requires digest-linked v2 proofs for both firmware paths.
Omitting the flag keeps the project's own choice.
`--secure-boot` needs `--firmware uefi` and the `.secboot` firmware paired with the `.ms`
store of enrolled keys; both are refused before QEMU starts rather than reported afterwards.
See `docs/build-pipeline.md` for how the firmware pair is detected.

The report summarizes the release surface:

- ISO path and size;
- SHA-256 when the ISO exists;
- presence of `SHA256SUMS`, `BUILDINFO`, `INTEGRITY`, `PROVENANCE.json` and
  `qemu-lab-report.json` in the output directory;
- planned QEMU smoke coverage;
- trademark/redistribution review warning;
- repository trust warning.

Missing ISO is blocking. Missing reports are review items until the release pipeline writes
them.

Two known limits of this report, both to be read as defects rather than as behaviour to
rely on. Its provenance item probes the literal name `PROVENANCE.json`, while the build
writes provenance as `distroforge-provenance.json`, so that item stays a review item even
for a project that has provenance. And the release support summary from
`compatibility-report.txt` is *not* part of this report: that file is written by the build
into the project output directory and is read by the dry-run and build reports instead.

`release-gate` is stricter: it is the maintainer publication stoplight. It re-hashes the
ISO and does not accept a report merely because a file exists. Build provenance must use
the v2 schema, carry `attestation_kind: build`, match the ISO, and link to an append-only
application run whose manifest, sidecar and every recorded file still verify. QEMU evidence
must be a completed v2 pass for the same ISO through at least `login_prompt`, with serial
and screenshot digests recorded in the run manifest and no terminal refusal anywhere in
the final log. A structural scan never satisfies this runtime publication gate. The gate
returns `blocked`, `review`, or `ready`.

One release-gate invocation now owns one bounded artifact-verification session. The ISO,
provenance alias and run file, command log, package/rootfs/ISO reports, manifests, sidecars
and delegated replay inputs are opened descriptor-relatively without following any path
component and remain held until the verdict closes. Digest, JSON and expensive replay
reuse is permitted only inside that session; a later gate starts from the filesystem
again. Closing re-hashes held inodes and revalidates their logical paths and bounded tree
inventories, so a same-size/same-mtime replacement cannot inherit an earlier answer.

For `source_mode: iso`, an executing remaster has already required the source and detached
signature to be stable regular files, the source bytes to match an external SHA-256, and
GPG's `VALIDSIG` output to name one externally supplied full fingerprint exclusively.
That strict live check is still only `review` at publication: the current run evidence does
not seal the detached signature, verification status and exact keyring bytes in a form the
gate can replay offline. A locally successful ambient-keyring verification must not be
rewritten as an authenticated release claim.

The same run must contain `PACKAGE-INPUTS.json`. On an authoritative gate refresh, the
validator does not trust that file's recorded verdict: it re-hashes its transaction and
CAS files, verifies the captured `InRelease`/`Release.gpg` using captured explicit
keyrings, binds each `Packages` index to the signed Release checksums, binds each `.deb`
digest, size and internal identity to a package stanza, and reconciles the final dpkg
inventory. Repository authority is per-source, not global: the effective definition pins
each namespace's base URI, suites/codenames, components, architectures, full signer
fingerprints, keyring digests and Release freshness window. `Date`, optional
`Valid-Until`, maximum age and future skew are evaluated at the provenance run instant.
The validator also re-derives the APT-affecting argv digest from the complete final command
ledger, including commands after the aggregate was first written.

Those policies, the expected source mode and bootstrap keyring SHA-256 come from the
effective definition passed to the gate, so package evidence cannot self-authorize a
different trust policy. A locally built `.deb` with no independent producer attestation
blocks the input closure.

M3.2a also requires the same run and its provenance to bind
`PACKAGE-APT-ACTIONS.json`, schema `distroforge.package-apt-actions.v1`. An authoritative
refresh binds the bounded journal, raw protocol copy, transaction records, recorder and
generated configuration to the same verification session, then recomputes the supplied
version-3 action transcript and the one-to-one package/version/architecture binding for
every unpack action from those held bytes. The stored status cannot authorize itself, and
missing, malformed, incomplete, oversized, drifting or forged inputs block the package
item.

That replay establishes internal consistency only. Before host collection, the
transcript, journal and CAS live in the mutable target rootfs, so matching their hashes
afterward cannot prove that APT produced them. A non-empty valid receipt therefore says
`apt_actions: self-consistent`, while an empty post-bootstrap capture says
`apt_actions: not-observed`; both preserve `capture_origin:
unverified-mutable-target-rootfs`, `filesystem_causality: unverified` and
`release_ready: false`. A post marker closes the capture interval but is not evidence of
dpkg success. M3.2b must use a host-isolated one-shot witness whose acknowledgement is a
precondition for dpkg.

M3.2a.1 hardens this local proof plumbing without promoting that status. Immutable text
artifacts are fully written and file-synced under an exclusive temporary name before a
same-directory no-replace link publishes them; the parent directory is synced before and
after temporary-name cleanup. Existing destinations, including symlinks, remain
refusals. A failed file sync publishes nothing, while a later directory-sync failure can
leave only the complete target. A crash may leave a partial or complete temporary name,
but that name is never the published target. The writer does not recursively sync newly
created ancestors and publishes by linking the random temporary name rather than its
held descriptor, so a hostile same-directory writer is outside this precise durability
contract; this is not a filesystem or power-loss attestation.

The authoritative package-input path now bounds every hash/read pass for
`PACKAGE-INPUTS.json` and its transaction JSON through confined descriptors before
decoding, including growth after the opening size check. The release gate pins one
bounded provenance snapshot across its package, rootfs, ISO, manifest and provenance
items and rejects an alias changed before closure. Its package preview also bounds
package inputs, APT actions and the static filesystem map; invalid Unicode, malformed
JSON, oversized files, FIFOs and unstable reads become blocked items. The controlled-root
hook harness uses an allowlisted environment and closed
tool directory, journals only its expected `apt-config`/`apt-get` shims and traps
unexpected APT/dpkg-family resolution. This proves the synthetic test did not fall
through to those host package tools. It neither authenticates InfoFD nor closes the
mutable-rootfs race described above.

M3.2a.2 closes the remaining artifact-reader boundary, not the producer boundary.
Low-level SHA-256 calculation has no persistent pathname cache. A verification session
pins canonical regular files with no-follow, non-blocking descriptor opens, retains their
full host identity, parses JSON once and memoizes semantic validation and external replay
only inside the verdict. At closure it first re-hashes the held descriptors, repeats
bounded tree inventories as the last content observation and only then repins names from
each leaf back through its ancestors to the anchor.
Rootfs manifests and packing reports, ISO assembly, QEMU reports, serial/captures,
firmware, boot proof, command/run manifests, `SHA256SUMS`, bundle signing and standalone
verification now participate in that contract. Alias comparisons use descriptors held in
the same session rather than independently reopening either name late in the verdict.
Every producer and reader validates `run_id` before composing a path: it is one canonical
strict-UTF-8 component, not empty, `.` or `..`, contains no slash, backslash, NUL,
control/DEL or invalid Unicode, and is limited to 255 encoded bytes.

The release verdict additionally carries an explicit immutable build selection B and boot
selection C. A non-blocked gate cannot omit either selection. Ready provenance and SBOM
items must name canonical files under `evidence/runs/B`; a ready boot item must name the
proof and QEMU report under `evidence/runs/C`. Standalone verification then requires
`boot-proof.run_id == C`, `boot-proof.build_run_id == B` and the same B/C pair in the boot
run manifest. Malformed optional paths are refusals, not null values. Pipeline, drill,
acceptance, beginner, CLI and GUI surfaces propagate only IDs returned by that verdict.
If B already embeds a valid boot run D, a direct or orchestrated boot request revalidates
and reuses D without starting another VM or exposing a conflicting C. The `iso-accept`
boot remediation uses one `release-pipeline` invocation so the newly produced run is
consumed in the same orchestration; it never emits a literal placeholder run ID.

Binary files and evidence trees use a separate durable-copy primitive: the source remains
held while size and SHA-256 are computed during the copy. Regular text and binary files
are written and synced through an anonymous same-filesystem `O_TMPFILE`, then exposed by
one no-replace link. No regular temporary pathname exists, no target is exchanged or
replaced, and an idempotent collision is accepted only after the existing held regular
inode proves the exact expected size and SHA-256. A failure before the link exposes
nothing; a later failure may retain only the complete measured target because
pathname-based deletion would reintroduce the substitution race.

Evidence trees still require a named staging directory for atomic no-replace rename.
Owned failed trees are moved only while the name identifies the held inode. This durable
detach is a separate verdict from the subsequent bounded, no-follow, best-effort scrub:
single-link regular contents may be truncated and synced, but external hard links are
never damaged. The unpredictable quarantine remains physically present in every case.
`scrub_complete` means only that the bounded traversal ended without error and found no
remaining regular-file bytes; the ISO replay intentionally requests detach-only cleanup
and records residual entries and bytes. The code therefore never claims successful
physical deletion. POSIX still cannot prove that no mutation was made and perfectly
restored between two observations.

The beginner repair command is deliberately not promoted to an atomic multi-file
transaction. Each individual output is complete and immutable, but if the ISO or its
output-directory identity changes between files, the report becomes `blocked`, reports no
successful repair and the release pipeline stops before bundle creation. Already linked
complete files may remain non-authoritative and require a fresh output directory for
retry. Its reconstructed provenance remains publication-blocking in every case.

Strict `SHA256SUMS` means a bounded strict-UTF-8 document with LF endings, lower-case
64-hex digests, the canonical two-space separator, unique canonical relative paths and no
control-byte or path aliases. Publish signing is never `ready` from `exists()` checks:
the exact bundle inventory, current ISO, typed release-gate aggregate and items, manifest
snapshot, strict checksum file, pinned keyring and exactly three descriptor-bound
signatures must agree and verify cryptographically. These are source and adversarial
fixture properties only. `capture_origin` remains `unverified-mutable-target-rootfs`,
`filesystem_causality` remains `unverified`, and `release_ready` remains false. The
blocking policy for an unreadable CVE database is the separate M3.2a.3 item; the next
producer-causality milestone is M3.2b.

M3.1 adds the run-bound `PACKAGE-FILESYSTEM-CAUSALITY.json` artifact with schema
`distroforge.package-filesystem-causality.v1`. For a fresh bootstrap, an authoritative
refresh re-hashes and re-extracts the exact `.deb` files selected by the sealed
`PACKAGE-INPUTS.final_inventory` snapshot, reloads `ROOTFS-MANIFEST.json` and recomputes every path as `exact`,
`modified`, `missing`, `unattributed`, `ambiguous`, `structural`, `excluded` or
`unsupported`. The stored verdict cannot authorize itself, and drift in the artifact or
either aggregate/manifest input is a refusal.

The report deliberately describes `sealed-recorded-deb` scope and records that
authenticated package inputs are an external assurance dependency. Only the release
gate's preceding package-input replay supplies signed `InRelease`/`Packages`, freshness
and policy authentication. M3.1 itself opens the run directory once without following
any ancestor symlink, traverses every input with descriptor-relative `openat` semantics,
rechecks every input leaf at run sealing and creates the report once through that same
descriptor. Run, transaction and rootfs paths are bounded before parsing and must already
be canonical. JSON size, package summaries, classifications, selected members, logical
payload and raw tar bytes, physical headers, extension chains, PAX fields and `dpkg-deb`
stdout/stderr are incrementally bounded; each remaining aggregate allowance is applied
before the next extraction or parse. Compressed, over-nested, malformed or drifting
inputs fail closed rather than becoming a partial success.

These are measured fixture guards, not a claim that a full desktop manifest fits them.
The first executing product run must stop on a budget refusal and provide measurements
before any limit or schema is changed. In schema v1, `payload_identity` reports supported
enumeration coverage; the `modified`, `missing` and `ambiguous` counters are a distinct
comparison axis. A later schema may split those axes into separate named fields, but v1
must not reinterpret them retroactively.

ISO-remaster mode is deliberately narrower in M3.1. The report binds the package-input
aggregate and final manifest but, without a semantic manifest for the authenticated source
ISO, does not inspect even newly captured remaster payload blobs: every final path is
`unsupported` and `payload_identity` is `partial`. The preceding package-input validator
still independently re-hashes those `.deb` records, so the gate as a whole refuses blob
drift; the static map itself makes no remaster-payload claim.

This closes only static `payload_identity`. It is `verified` only for a bootstrap map that
accounts for every supported, in-scope direct payload member of that inventory snapshot.
The snapshot precedes arbitrary post-host hooks, and M3.1 does not re-read dpkg state after
them; a later package mutation therefore remains M3.2b debt. ISO-remaster mode, an excluded
path or an unsupported object makes it `partial`. Identical payload
and final objects do not prove which APT/dpkg action, maintainer script, trigger, conffile
decision, diversion, alternative, customizer or other producer created the final state.
Consequently `filesystem_causality` remains `unverified`, `release_ready` remains false
and `package-inputs` remains `blocked`, even when every comparable object is `exact`.
M3.2a validates only the self-consistency of supplied
`DPkg::Pre-Install-Pkgs` protocol-v3 bytes; it does not authenticate their origin.
M3.2b must move capture to the acknowledged host boundary, bind observed before/after
producer deltas and account explicitly for those dynamic transformations and the ISO
baseline.

The package-input, M3.1 payload-identity and M3.2a action-replay paths are implemented and
covered by offline, rootless cryptographic/package fixtures. The M3.2a harness also
executes the generated shell pre/post state machine against synthetic input and controlled
helpers, not a real apt/apt-get transaction or dpkg operation. No new live-archive ISO
build has exercised these paths. A fixture pass is not an archive or ISO proof.

The same distinction applies to the product bytes. The code now captures a semantic
`ROOTFS-MANIFEST.json`, proves no source-tree drift across `mksquashfs`, unpacks the
descriptor-held SquashFS into a fresh tree, and binds those bytes to the SquashFS member
extracted from the final ISO. The authoritative provenance gate repeats that path from the
published ISO itself and compares the replayed semantic tree with the manifest. Round-trip
and forged-evidence tests exercise this path on synthetic trees, but the hardening lot did
not execute a new product rootfs, SquashFS or ISO build.

“Append-only” is an application rule, not a cryptographic filesystem property: the
application refuses a reused run ID, but a local writer can still alter or delete the
directory and recompute unsigned digests. The local checks detect ordinary drift against
the recorded manifest; the bundle becomes tamper-evident and authenticated only after the
manifest is signed and that signature is verified, or after the evidence is anchored in
trusted WORM/content-addressed storage.

`publish-bundle` creates `dist/publish/` for maintainer review. It copies the ISO,
`SHA256SUMS`, `BUILDINFO`, provenance, HTML report, executed boot proof when present, plus
the referenced run evidence (including package-input transactions, the M3.2a receipt and
its collected journal/transcript copies),
`RELEASE-GATE.json` and `README-PUBLISH.txt`. A blocked release gate still produces an
inspection bundle, but the README marks it `BLOCKED` and lists the blocking items; the
top-level CLI exits 2 for that blocked result.

Bundle publication copies each regular file from a stable descriptor and copies each
referenced run as a bounded no-follow tree into a synced staging directory. A single
Linux no-replace rename exposes the complete bundle; a symlink, special file, collision,
copy/fsync failure or unexpected mutation leaves no final partial tree. Its receipt carries
the published directory identity; signing, notes, verification, explanation, pipeline and
drill writers must still see that identity. A post-publication clone receives no output.
Before that publication, `create_publish_bundle` consumes a deliberately ephemeral
`ArtifactVerificationReceipt` returned by the gate and never serialized into
`RELEASE-GATE.json`. It binds every copied regular source to its complete identity and
SHA-256, and each accepted run tree to its anchor plus exact inventory. An omitted source,
unreceipted copy, changed identity or different union of runs is blocked. This gate
receipt is distinct from the post-publication bundle directory identity.

`sign-release` adds maintainer signing evidence only to an existing safe bundle; a missing
or non-directory bundle is refused without creating a partial one. By default it is a
strictly read-only plan: it invokes no GPG process, returns the proposed entry snapshot and
the three planned `.asc` target names, and leaves the authoritative
`RELEASE-MANIFEST.json` and `SIGNING-REPORT.json` names free for a later executing
invocation. Passing `--execute` first requires an exact regular-file
inventory, exactly one
ISO, a strict `ready` or `review` release gate whose aggregate matches its items, no
pre-existing detached signature, a complete 40- or 64-hex OpenPGP signer fingerprint and
an explicit filtered public keyring. It then signs `SHA256SUMS`,
`RELEASE-GATE.json`, and `RELEASE-MANIFEST.json` from held descriptors. The keyring is
imported into an isolated GPG home and re-exported as a minimal public-only
`RELEASE-SIGNING-KEYRING.gpg`; secret packets are a refusal. Its SHA-256 is recorded, and
the complete three-signature set is verified against those same payload/keyring
descriptors before it is reported as signed. Every later inventory and publication stays
bound to the original preflight directory identity. A rollback never unlinks after a
pathname-only check; an inode that cannot be removed safely remains under an internal
quarantine name, is reported as incomplete cleanup and blocks the next preflight.
Reservation or retirement failure of the private signing stage is likewise converted
into a typed blocked report. If publication of the signature set had begun, all three
owned `.asc` files are rolled back as one set and their held descriptors are closed;
already completed manifest or public-keyring evidence may remain, but no partial
signature set is reported as signed.

`release-notes` writes the human review layer: `RELEASE-NOTES.md` and `CHANGELOG.txt`.
The notes summarize status, ISO digest, included artifacts, boot proof, signing evidence,
blocking gate items and verification commands.

`verify-release` computes one descriptor-relative opening inventory and keeps every
manifest, gate, signing report, `SHA256SUMS`, ISO, runtime artifact, keyring, payload and
signature in one verification session. It verifies every manifest size and SHA-256,
requires the checksum file to identify the unique bundled ISO, compares the manifest and
release-gate status, and passes held payload/signature/keyring FDs to GPG. The closing
inventory and session must still equal the opening snapshot before a verdict is accepted.
Missing planned signatures remain review items; malformed UTF-8/JSON, FIFO or symlink
inputs, duplicate checksum entries, same-size replacements and corrupted files block the
bundle. `VERIFY-REPORT.json` itself is published without following a pre-existing symlink,
so verification cannot overwrite an external target. An unsealed descriptor session does
not create that report; an existing report is reused only when the newly derived bytes are
exactly identical and can never authorize a later live verdict by itself. A `blocked`
release gate remains `blocked` under
standalone verification: its aggregate status, `blocked` boolean, manifest status and
individual item verdicts must be mutually consistent.

Once signing execution is claimed, the contract is exact rather than best-effort:
`status` must be `signed`, `execute` must be true, `planned` and `skipped` must be empty,
and both the recorded signed set and the actual `.asc` files must equal these three and
only these three:

- `SHA256SUMS.asc`;
- `RELEASE-GATE.json.asc`;
- `RELEASE-MANIFEST.json.asc`.

A partial set is blocked even when each present signature verifies. Verification also
requires the externally supplied expected full signer fingerprint and the recorded
explicit keyring bytes to match their SHA-256. A blocked verification report is propagated
as CLI exit status 2.

`explain-release` writes `RELEASE-EXPLAIN.md` only after a live descriptor-bound verifier
has reproduced the stored verification report on the same bundle identity. It separates
ready, review and blocked evidence, names the boot proof level (`runtime` or `structural`),
and prints shell-quoted next commands carrying the same ISO/output/bundle triple.
Signature remediation also names the required full fingerprint, filtered public keyring
and terminal verification pin rather than emitting a predictably blocked invocation. A
forged internally consistent JSON quartet cannot explain itself as ready. Terminal
verification may resolve the sole pre-signing `publish-signing` review after the exact
signatures and external fingerprint verify.

`publish-drill` runs the full safe maintainer rehearsal in one command: boot proof with
`auto`, release pipeline, signing plan, verification, explanation, and
`PUBLISH-DRILL.json`. It never signs by default; real signing requires explicit
`--execute-signing`. After explanation is written, a final read-only live verification
must still reproduce the preliminary result before the drill can be published. The
persisted report then passes an exact schema and cross-report validator: pipeline stages,
gate items, manifest, signatures, keyring, verification and bundle identity must agree.
Status is derived from that terminal verifier, not an earlier report; an unpublished,
replaced or semantically inconsistent bundle receives no drill output.

`publish-drill-diff` compares two drill reports and returns `improved`, `unchanged`, or
`regressed`. It flags status or release-gate regressions, boot proof downgrades, new
blockers, manifest removals or SHA changes, signing changes, and next-command changes.
Both bounded strict-JSON inputs are held in one no-follow session, so aliases are parsed
once and a FIFO, link, malformed input or swap is a blocked comparison. Its assurance is
explicitly `structural-only`: it compares the internally coherent stored reports but does
not authenticate either release, re-run GPG or establish who created the files.

`publish-drill-baseline` promotes the current `PUBLISH-DRILL.json` to
`PUBLISH-DRILL.previous.json` for future comparisons. It refuses blocked drills unless
`--allow-blocked` is explicit. The held drill bytes are published durably and the receipt
must reproduce their size and SHA-256 before `PUBLISH-DRILL-BASELINE.json` is written.
For a `ready_to_publish` drill, promotion additionally requires an externally supplied
complete signer fingerprint and identical live descriptor-bound verification before and
after baseline publication. A terminal block or exception leaves no ready promotion
receipt (the immutable baseline bytes may remain as a non-authoritative failed attempt).
Canonical in-bundle comparisons require the exact previous/current names, the real bundle
identity and that local receipt. The receipt proves only current local byte consistency:
it is non-cryptographic, forgeable by a writer that controls the bundle, never a release
attestation and never an input to `release_ready`.

`release-pipeline` runs the maintainer sequence in one command: repair derivable artifacts
when an ISO exists, optionally run boot proof with `--run-boot-proof --boot-backend
auto|qemu|iso-scan`, create the publish bundle, generate signing evidence, write release notes,
refresh the manifest so the notes are covered, verify the bundle, and write
`RELEASE-PIPELINE.json`.

`boot-proof` is the normalized boot evidence command. In dry-run mode it writes
`boot-proof.plan.json` plus a run-scoped file under `dist/evidence/plans/`; it never
replaces the last executed `boot-proof.json`. The default `auto` backend attempts QEMU runtime
proof first, then falls back to `iso-scan` when QEMU is missing or blocked by the host.
The report records `attempted_backends`, `selected_backend`, and `proof_level`. The `qemu`
backend requires QEMU, runs the configured boot smoke, captures `qemu-lab-report.json`,
and marks `boot-proof.json` ready only when the report schema, ISO digest, milestone,
serial marker and artifact digests all verify. The
`iso-scan` backend is a headless fallback: it records ISO size, SHA-256, ISO9660 volume
metadata, El Torito boot catalog evidence and kernel/initrd or live payload markers. A
complete scan can mark `boot-proof.json` structurally ready; partial structural evidence
is `review`. The release gate nevertheless requires runtime evidence and blocks both.

Before either backend consumes bytes, boot proof durably copies the selected regular ISO
into run-owned storage and binds that copy to its invocation session. QEMU and external
ISO scanners receive `/proc/<pid>/fd/<fd>` plus `pass_fds`, and the report records
`consumed_via: held-descriptor`. The QEMU report, serial, firmware, command log, immutable
proof, run manifest and sidecar are measured and parsed from held descriptors; the final
compatibility alias is staged from the verified proof FD only after the session seals.
Leaf or ancestor links, FIFOs and same-size/same-mtime swaps therefore produce a
`blocked` verdict rather than a wait, raw exception or partial alias.

Executing ISO builds use the same separation. The authority is
`dist/evidence/runs/<run_id>/ISO-BUILD.json`; `dist/ISO-BUILD.json` is an atomic alias to
the latest execution, while a dry-run updates only `dist/ISO-BUILD.plan.json`. See
[`iso-build-proof-ledger.md`](iso-build-proof-ledger.md) for the schemas and current
milestone verdicts.

An executed `boot-proof` that came back `blocked` exits **2**; `--dry-run` always exits 0,
including against a project with no ISO, because reporting that is what a plan is for.
`iso-build --execute` follows the same rule. Both used to print a report whose `blocked`
field was `true` and still exit 0 — see the exit-status table in
[packaging-release.md](packaging-release.md), which holds the rule for all three commands.

## Software Bill of Materials

Every executing build writes `distroforge-provenance.json` as an alias to its append-only,
run-scoped provenance. When `--sbom-format` selects a standard
format, the build writes a portable SBOM next to it: `distroforge-sbom.spdx.json` for
SPDX-2.3 or `distroforge-sbom.cdx.json` for CycloneDX 1.5. A published bundle therefore
carries a vendor-neutral component inventory alongside the native provenance document.
Release readiness does have a provenance line, but it probes `PROVENANCE.json` rather than
the name the build writes, so do not read that line as proof that provenance is absent;
check the output directory. The GUI **Quality Lab** exposes the same SBOM format selector
as the CLI `--sbom-format` flag.

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
