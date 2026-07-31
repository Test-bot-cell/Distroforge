# ISO Build Proof Ledger

This ledger records what the DistroForge ISO journey has actually demonstrated. It is
not a roadmap and it does not turn a green command into evidence. A milestone is
**proved** only when the exact inputs, executable toolchain, intermediate artifacts,
final ISO and runtime outputs are joined by verified digests and the closing manifest is
authenticated by a verified signature or anchored in trusted WORM/content-addressed
storage.

The Debian changelog summarizes code changes. It is not the evidence ledger.

## Evidence levels

- **observed**: a real command or runtime event was seen and its raw output still exists;
- **proved**: authenticated, digest-linked evidence binds the observation to exact source,
  inputs and artifact bytes;
- **blocked**: the milestone was attempted and a terminal refusal was captured;
- **planned**: code or workflow exists, but no executing run has proved it.

A structural ISO scan is useful evidence, but it never proves that firmware, a
bootloader, a kernel or a desktop session ran.

## State on 2026-07-31

| Milestone | State | Evidence and limit |
| --- | --- | --- |
| source checkout | observed | `origin/develop` is signed repair commit `a3f14becc0bd2d67d5cadf6c2a10e47b5a0df844`; GitHub reports `verified: true`, reason `valid`, and local GPG verification accepts primary fingerprint `93D942241BECDD422606C36C4C0D75219B5506CF`. The authorized fast-forward advanced only `develop`; `main` and the existing release tag remained unchanged. This is source identity, not build proof. |
| CI action inputs | observed | per-push GitHub Actions run `30518874302` targeted exact signed repair commit `a3f14bec…`, attempt 1, and completed success in all ten jobs. Every Python 3.11--3.14 / PySide6/PyQt6 leg installed mypy 2.3.0, typechecked all 256 source files and reported 1,306 passed / 38 skipped tests; `packaging-static` and `distro-dependencies` also succeeded, the latter with 1,336 passed / eight skipped tests from distribution packages only. This closes the mypy refusal observed in run `30517720041`; it proves a source/test CI verdict, not an executing package, ISO, boot or release chain. |
| Golden builder commit | planned | the workflow pins a public-key file by SHA-256 and primary fingerprint, imports it into an ephemeral `GNUPGHOME`, requires `git verify-commit HEAD`, suppresses Python bytecode and removes editable-install caches before measuring the builder worktree; no post-change run has exercised that refusal rule |
| minbase bootstrap | observed | the local golden-path log contains an executing `mmdebstrap --variant=minbase --include=apt,ca-certificates` with exit 0 |
| source-ISO authentication | planned | executing remasters now require stable regular source/signature inputs, external SHA-256 and one exclusive full `VALIDSIG` signer, then extract through the witnessed source descriptor; the publication item remains `review` because signature/status/keyring evidence cannot yet be replayed offline |
| archive and package bytes | planned | the current code writes `PACKAGE-INPUTS.json` and transaction/CAS evidence, and its test fixture replays a real signed `InRelease` → `Packages` → `.deb` chain; repository policies are per-source and freshness plus the final APT argv ledger are bound, but no fresh ISO build has yet produced this closure from the distribution archive |
| APT/dpkg action transcript | planned | M3.2a code and offline fixtures write and exactly recompute `PACKAGE-APT-ACTIONS.json` (`distroforge.package-apt-actions.v1`) from supplied protocol-v3 bytes, its journal and sealed package records. A non-empty replay is only `apt_actions: self-consistent`: the transcript and CAS remain mutable in the target rootfs until host collection, so `capture_origin` is `unverified-mutable-target-rootfs`. The local harness executes the shell pre/post state machine with synthetic input and controlled helpers; no real APT transaction or APT-produced stream has been observed |
| package payload identity | planned | for a fresh bootstrap, M3.1 code and offline, rootless fixtures write and authoritatively replay `PACKAGE-FILESYSTEM-CAUSALITY.json` (`distroforge.package-filesystem-causality.v1`) from the exact `.deb` payloads named by the sealed pre-post-host `final_inventory` snapshot and `ROOTFS-MANIFEST.json`, classifying `exact`, `modified`, `missing`, `unattributed`, `ambiguous`, `structural`, `excluded` and `unsupported`. `payload_identity` is `verified` only for complete supported snapshot scope; M3.1 does not re-snapshot dpkg after post-host hooks. ISO-remaster mode inspects no payload blob and marks the complete manifest `unsupported`/`partial` until a semantic source baseline exists; no executing product run has emitted this map |
| package-to-rootfs causality | blocked | M3.1 closes static `payload_identity`; M3.2a closes only self-consistent replay of supplied action bytes and explicitly does not authenticate their origin. A host-isolated one-shot witness acknowledged before dpkg, filesystem deltas, maintainer scripts, triggers, conffiles and other transformations remain M3.2b debt; `filesystem_causality` is `unverified` and `release_ready` is false |
| archive trust policy | planned | the reference definition retains only signer `F6ECB3762474EDA9D21B7022871920D1991BC93C`, a SHA-256 pin for the explicit archive keyring and separate release, updates/backports and security namespaces/freshness windows; no fresh archive transaction has yet exercised them |
| APT and live packages | observed | the resulting rootfs contains apt, ca-certificates, casper, kernel, GRUB and shim packages; the staged manifest contains 400 packages |
| executed tool entrypoints | planned | the command runner hashes and opens each recognized host/wrapper/target executable and dispatches through the held `/proc/<pid>/fd/<fd>` descriptor chain; unit tests cover atomic path replacement, but no new real build log has exercised the closure |
| transitive ELF toolchain | planned | descriptor dispatch closes the selected executable file only; it does not by itself bind the ELF interpreter, dynamic libraries, loader configuration, scripts read after process start, kernel or firmware |
| artifact-verdict integrity | planned | M3.2a.2 code and adversarial fixtures remove persistent pathname digest reuse, scope hash/parse/replay reuse to one descriptor-backed verdict, revalidate held inodes, paths and inventories at closure, durably copy binary/run-tree evidence and require strict checksum/signing snapshots. No product build, boot or signed release bundle has exercised this boundary |
| CVE database verdict integrity | planned | M3.2a.3 code and adversarial fixtures make unusable or structurally invalid databases fail closed under blocking policies and explicitly degraded under non-blocking policies. A bounded descriptor-backed session records the exact database SHA-256, schema and declared metadata; bounded control-free text and empty/over-budget/non-canonical package scope cannot become clean. Degraded evidence remains review through the release consumers and cannot authorize signing. This is name-only source/test policy evidence, not database authenticity, freshness, completeness, version applicability or an executing product scan |
| rootfs semantic manifest | planned | code and tests now cover the semantic manifest, host drift guard, descriptor-held SquashFS round-trip, exact embedded-member binding and authoritative replay from the final ISO; no new real build has emitted that evidence |
| squashfs | observed | a real zstd `mksquashfs` completed and the staged and ISO-extracted squashfs digests match |
| ISO assembly | observed | a real `xorriso` completed; `reference-derivative-26.04.iso` is 1,348,337,664 bytes with SHA-256 `2e421cde4d3e62014c1265ce903a821777fe22820ea9677d2ff1c7dbd0e49b2a` |
| reference UEFI boot | blocked | that ISO has no usable GPT ESP; OVMF ended with `No bootable option or device was found` |
| corrected GPT/ESP layout | observed | an audit variant is exposed as GPT and OVMF loads and starts `BOOTX64.EFI` |
| shim to GRUB | blocked | shim ends with `Unexpected return from initial read: Device Error, buffersize 0` while reading `grubx64.efi` |
| GRUB menu | planned | not reached by evidence bound to the current source and ISO |
| kernel and casper | planned | historical logs exist, but their ISO/source chain is incomplete and cannot be promoted retroactively |
| login prompt | planned | no digest-linked v2 runtime report yet binds a login marker to the rebuilt ISO |
| BIOS runtime | planned | boot structure exists, but the exact rebuilt ISO still needs an executing BIOS proof |
| desktop environment | planned | the reference golden-path definition deliberately excludes a desktop |
| release signature contract | planned | code requires an executed bundle to contain exactly the three detached signatures for `SHA256SUMS`, `RELEASE-GATE.json` and `RELEASE-MANIFEST.json`, verified with an externally pinned full fingerprint and sealed keyring; no product/audit artifact bundle has been signed, only a throwaway local GPG fixture |
| reproducibility | planned | deterministic inputs are partly configurable; two independent builds have not produced and compared full artifact sets |

The existing local ISO and historical Secure Boot directory remain useful diagnostic
material. They are not v2 build evidence: neither records the current source worktree,
effective definition, toolchain binaries and full artifact chain. New reports must not
rewrite that history into a stronger claim.

No new real ISO build has been executed for the current hardening lot. Passing unit,
static and fixture tests can prove refusal rules and internal validators; it cannot promote
any row above to an executed archive, squashfs, ISO or boot proof.

## Code-level closures awaiting an executing run

The current audit implements the following fail-closed contracts:

- an executing source-ISO remaster requires stable regular ISO/signature files, an
  external SHA-256 and one exclusively matching full `VALIDSIG` fingerprint. Extraction
  consumes the source through a held descriptor tied to the trusted opening digest. The
  release gate intentionally leaves this item at `review` until the signature,
  verification status and exact keyring bytes are sealed for independent offline replay;
- package transactions seal source/configuration, explicit keyrings, signed Release
  metadata, active `Packages` indices and downloaded `.deb` bytes into the run CAS before
  APT cleanup; the offline validator re-hashes each file, verifies the Release signature
  using captured explicit keyrings in an isolated `gpgv` home, binds each index to a
  signed Release checksum, binds each `.deb` digest, size and internal package identity to
  a `Packages` stanza, and reconciles the final dpkg inventory;
- target-root APT paths are traversed and opened component-by-component relative to
  confined descriptors with `O_NOFOLLOW`; symlink ancestors, special files and
  mount/bind-mount escapes are refused, and enumeration, hashing and copying use the
  already-open descriptor. Only the bootstrap keyring copy already sealed under its
  pinned content digest is allowed outside that target-root boundary;
- a fresh bootstrap has no exempt baseline: it must carry exactly one bootstrap
  transaction, the bootstrap inventory must be non-empty, and every installed bootstrap
  package must have captured archive bytes. An ISO remaster instead binds its only
  baseline exemption to the package inventory captured before mutation;
- signer fingerprints, source mode and bootstrap keyring SHA-256 come from the effective
  definition/options supplied to the verifier. Values copied into
  `PACKAGE-INPUTS.json` cannot authorize themselves. The bootstrap tool consumes a
  content-addressed copy of the keyring after its bytes match the external pin;
- repository authority is partitioned by the external per-source policy's URI,
  suites/codenames, components, architectures, full signer set and keyring digests.
  Release `Date`, optional `Valid-Until`, maximum age and future skew are checked against
  the provenance run instant, and the APT-affecting argv digest is recomputed from the
  complete final command log;
- unsafe APT trust/date overrides, incomplete or duplicate transactions, conflicting
  bytes for one package/version/architecture, and locally built `.deb` files without a
  separate producer attestation block the closure;
- M3.2a writes `PACKAGE-APT-ACTIONS.json`, schema
  `distroforge.package-apt-actions.v1`. The generated fragment requests
  `DPkg::Pre-Install-Pkgs` protocol version 3 on InfoFD 0, while the bounded parser
  accepts the configuration framing and nine-field actions documented by
  [apt.conf(5)](https://manpages.debian.org/testing/apt/apt.conf.5.en.html). APT's
  [`dpkgpm.cc`](https://sources.debian.org/src/apt/3.3.1/apt-pkg/deb/dpkgpm.cc/) and
  [`strutl.cc`](https://sources.debian.org/src/apt/3.3.1/apt-pkg/contrib/strutl.cc/)
  are format references, not evidence that APT produced any fixture transcript;
- the hook refuses a missing `APT_HOOK_INFO_FD` confirmation, an overlapping or
  incomplete interval, unstable inputs and a transcript above its byte bound. The host
  collector later copies the journal, transcript, recorder, configuration and CAS into
  the run, and authoritative replay binds each unpack exactly and exhaustively to one
  sealed `.deb` package/version/architecture identity. Per-stream and aggregate protocol,
  line, configuration, action, transaction, blob, path, journal and report bounds stop
  hostile growth before the next load or allocation;
- that replay is deliberately not an origin attestation. Until host collection, the
  journal, transcript and CAS are mutable target-rootfs state; a matching copied hash
  proves only the supplied set is internally coherent. `apt_actions` is therefore
  `self-consistent` for a non-empty replay or `not-observed` when no post-bootstrap APT
  capture exists. Every valid M3.2a receipt fixes `capture_origin` at
  `unverified-mutable-target-rootfs`, `filesystem_causality` at `unverified` and
  `release_ready` at false. The post marker closes a capture interval, not dpkg success.
  M3.2b must put the first write in a host-isolated one-shot witness and require its
  acknowledgement before dpkg can run;
- M3.1 writes `PACKAGE-FILESYSTEM-CAUSALITY.json`, schema
  `distroforge.package-filesystem-causality.v1`, and its authoritative fresh-bootstrap
  validator re-hashes and re-extracts the exact sealed `.deb` files named by the
  pre-post-host `final_inventory` snapshot before comparing their payload objects with
  `ROOTFS-MANIFEST.json`. Its complete static vocabulary is `exact`,
  `modified`, `missing`, `unattributed`, `ambiguous`, `structural`, `excluded` and
  `unsupported`; any drift in the report or either bound input is refused;
- the map says `sealed-recorded-deb`, not authenticated-by-itself. Its explicit assurance
  dependency is the separate package-input replay that the release gate evaluates first.
  One non-symlinked run-directory descriptor anchors all M3.1 reads and the one-time
  report write; descriptor-relative no-follow traversal and closing leaf checks refuse
  parent or file swaps. Run, transaction and rootfs paths are byte/depth bounded before
  parsing and must already be canonical. JSON, selected packages/members, package
  summaries, classifications, tar bytes, logical payload bytes, physical headers,
  extension/PAX metadata and both `dpkg-deb` streams have explicit incremental bounds.
  Each remaining aggregate allowance is applied before the next extraction or parse.
  Compressed, malformed, recursive or oversized inputs fail closed;
- those aggregate budgets are proved only by hostile fixtures; no real desktop run has
  shown that its manifest fits them. A budget refusal is therefore a measured product
  milestone, not grounds for an unreviewed limit increase. Schema v1
  `payload_identity` records enumeration coverage, while `modified`, `missing` and
  `ambiguous` remain separate comparison counts;
- ISO-remaster mode binds the package aggregate and final manifest but inspects no payload
  blob in M3.1: without a semantic authenticated-source baseline, all final paths are
  `unsupported` and `payload_identity` is `partial`. The separate package-input validator
  still re-hashes captured `.deb` bytes, so the complete gate refuses their drift;
- `payload_identity: verified` records only that a bootstrap map enumerated,
  canonicalized and bound every supported, in-scope direct payload member of that
  inventory snapshot. It does not re-snapshot dpkg after arbitrary post-host hooks; such
  later mutations remain M3.2b debt. ISO-remaster mode, an excluded path or an unsupported
  object records `partial`.
  Static equality cannot identify the action or producer that created the final object,
  so the release gate still requires
  `filesystem_causality: unverified` and `release_ready: false`. M3.2a checks supplied
  protocol-v3 action bytes for self-consistency only. M3.2b must authenticate their
  origin at the pre-dpkg host boundary, bind observed before/after deltas and account for
  maintainer scripts, triggers, conffiles, alternatives, diversions, removals,
  customizers, the ISO baseline and other transformations;
- the final rootfs is captured as a portable semantic manifest plus a host-specific
  packing guard, rescanned around `mksquashfs`, unpacked from the descriptor-held
  SquashFS into a fresh tree, and compared with the manifest. ISO assembly binds that
  witnessed image to the exact final ISO member. The authoritative provenance gate
  independently extracts the member from a descriptor-held published ISO, unpacks it
  through another descriptor and compares the replayed semantic tree field-for-field;
- recognized executable chains are opened, hashed and dispatched through held file
  descriptors. The release gate requires the pre-dispatch, descriptor-binding and
  post-dispatch identities to agree. This closes a path-replacement race for those
  entrypoint files, not the transitive ELF/runtime dependency graph;
- in-process `plugin.py` loading is refused during a sealed ISO build. Project plugins
  that participate in such a build must be executable phase scripts so their executable
  bytes pass through the same command runner and descriptor evidence;
- an executed signing report is accepted only when `status == signed` and the boolean
  `execute == true`, its signed set and actual `.asc` files are exactly the three required
  targets, and `planned` and `skipped` are empty. Partial signing is blocked, even if the
  signatures that do exist are cryptographically valid;
- executing CLI actions propagate a blocked report as exit status 2; plan/dry-run modes
  remain non-mutating reports and do not masquerade as executed success. Standalone
  release verification also keeps a blocked gate blocked and checks its aggregate,
  boolean, manifest and item verdicts for consistency;
- the Golden path verifies the exact checked-out commit against a repository-pinned
  public key (SHA-256
  `a1b6ee870e2708571bc43cf42d12a0c315c58dd1dad7760a27f660db3162e0ab`, primary
  fingerprint `93D942241BECDD422606C36C4C0D75219B5506CF`) in a fresh `GNUPGHOME`.
  Python bytecode is disabled and editable-install caches are removed before the builder
  worktree identity is captured. The key, hash and fingerprint are source-controlled, so
  their external trust still depends on review and branch governance.

These statements describe code and validator contracts. They are candidates for the next
executing proof, not substitutes for it.

## Append-only evidence-run contract

An ISO build now reserves one unique run directory before diagnosis or execution:

```text
dist/
  evidence/
    runs/<run_id>/
      commands.jsonl
      distroforge-provenance.json
      PACKAGE-INPUTS.json
      PACKAGE-APT-ACTIONS.json
      PACKAGE-FILESYSTEM-CAUSALITY.json
      apt/
        transactions.tsv
        transactions/*.json
        protocol/<sha256>.v3
        blobs/<kind>/<sha256>
      ROOTFS-MANIFEST.json
      ROOTFS-PACKING-VERIFICATION.json
      ISO-ASSEMBLY.json
      ISO-BUILD.json
      RUN-MANIFEST.json
      RUN-MANIFEST.json.sha256
      qemu-lab-report.json          # when the integrated lab ran
    plans/<run_id>/
      commands.jsonl
      ISO-BUILD.json
      RUN-MANIFEST.json
      RUN-MANIFEST.json.sha256
  ISO-BUILD.json                    # first no-replace execution compatibility alias
  ISO-BUILD.plan.json               # first no-replace plan compatibility alias
  distroforge-provenance.json       # no-replace executed-build compatibility alias
```

The application creates files inside a run exclusively and refuses a repeated run ID.
Every producer and reader validates that identifier before composing a path: it is one
non-empty canonical strict-UTF-8 component, neither `.` nor `..`, contains no slash,
backslash, NUL, control/DEL or invalid Unicode, and is limited to 255 encoded bytes.
This is an append-only application contract, not a cryptographic or filesystem
immutability property. A local account with write access can still alter or delete the
directory and recompute an unsigned manifest and sidecar. Compatibility aliases are
never the authority and are published once without replacement. A later invocation
leaves an occupied alias untouched, sets `alias_report` to null, records
`alias_problem`, and still returns its fresh invocation-scoped report and manifest. In
particular, a dry-run can create `ISO-BUILD.plan.json` but cannot replace either that
prior plan alias or `ISO-BUILD.json`.

The current schemas are:

- `distroforge.evidence-run.v1`;
- `distroforge.provenance.v2`;
- `distroforge.package-inputs.v1`;
- `distroforge.package-input-transaction.v1`;
- `distroforge.package-apt-actions.v1`;
- `distroforge.package-filesystem-causality.v1`;
- `distroforge.rootfs-manifest.v1`;
- `distroforge.rootfs-packing-verification.v1`;
- `distroforge.iso-assembly.v1`;
- `distroforge.iso-build.v2`;
- `distroforge.build-run-manifest.v1`;
- `distroforge.qemu-lab.v2`;
- `distroforge.boot-proof.v2`.

Build provenance records:

- DistroForge and Python executable versions and executable digests;
- Git root, HEAD, tree, branch, commit-signature state, tracked diff digest,
  untracked-file digest inventory and combined worktree digest;
- raw definition, `project.json` and effective resolved configuration digests;
- installed tool paths, versions, executable digests and recognized wrapper/target
  descriptor-dispatch identities;
- the run-bound package-input aggregate, transactions and static package-filesystem
  identity map when executing a sealed build;
- critical kernel, initrd, manifest, squashfs, EFI/GRUB and final ISO artifacts;
- the commands recorded before the provenance phase.

The executable identity record is deliberately scoped. It proves which already-opened
entrypoint bytes the kernel was asked to execute and detects path/inode drift across the
dispatch. It does not prove that the ELF interpreter or every dynamically loaded library
came from bytes recorded in the run. That transitive loader/library closure remains an
explicit debt.

`RUN-MANIFEST.json` closes the run after the build. It binds the final command log,
provenance, ISO build report and every recorded artifact. Its own SHA-256 is stored in a
sidecar to avoid a self-referential manifest. Re-hashing detects drift against that
recorded state, but an unsigned local manifest and sidecar do not authenticate themselves.
The run becomes tamper-evident against a trusted anchor only when the manifest is signed
and the signature verified, or when the evidence is committed to trusted
WORM/content-addressed storage.

## Runtime proof contract

A QEMU report is accepted only when all of these statements verify:

1. the schema is `distroforge.qemu-lab.v2`, with a unique run ID satisfying the same
   canonical 255-byte component contract as every other evidence producer and reader;
2. the run is `completed` and its verdict is `passed`;
3. the recorded ISO size and SHA-256 equal the ISO presented to the gate;
4. an explicit named milestone was reached; the release minimum is `login_prompt`;
5. the matched marker exists at the recorded byte offset in the manifest-recorded serial
   log, and `login:` is accepted only as a complete getty prompt line, never as a
   substring inside an audit, PAM or ssh diagnostic;
6. no terminal firmware, GRUB, casper or kernel refusal exists anywhere in the final
   serial log, including after the success marker;
7. serial and optional screenshot sizes and SHA-256 digests still match;
8. the QEMU executable identity is recorded; UEFI proofs also record firmware code,
   variables template and stopped-VM variables digests;
9. the VM has stopped before the final serial scan and artifact digests are calculated;
10. the ISO, serial, screenshot and firmware bytes were consumed from the same held
    regular-file descriptors whose identities and paths close the verdict.

The generic marker `Reached target` is rejected because it does not identify a boot
milestone. A structural `iso-scan` may produce a ready structural report, but it does not
satisfy the runtime release gate.

`boot-proof.json` additionally binds the QEMU report digest, proof run ID, build run ID
when available, final ISO digest and reached milestone. A newer blocked executed proof
takes precedence over any older QEMU report.

M3.2a.2 makes that binding causal at the reader boundary. Boot proof copies the selected
ISO durably from a pinned source into run-owned storage; QEMU and external ISO scanners
consume its `/proc/<pid>/fd/<fd>` path through `pass_fds`. The QEMU report, serial,
captures, UEFI firmware, command log, immutable proof, run manifest and sidecar remain
bound to one invocation-scoped verification session through final parsing and closure.
The compatibility alias is copied from the verified proof descriptor after sealing, not
reopened as an independent source.

## Provenance and publication rules

The release gate does not accept file presence as evidence. It validates the provenance
schema, requires `attestation_kind: build`, matches the ISO digest, checks the append-only
application run report and manifest, verifies the manifest sidecar and re-hashes every
listed file. It also locates `PACKAGE-INPUTS.json` through the provenance run ID and
replays its archive/package closure against the effective build definition's external
source mode, per-source policies, signer fingerprints, keyring SHA-256, run instant and
final command ledger. One invocation-scoped artifact session binds those inputs and the
provenance-bound `PACKAGE-APT-ACTIONS.json`; the collected journal, transcripts and
transaction records are read from held descriptors and their self-consistency is
recomputed without independent pathname reopens. This check deliberately requires
`capture_origin: unverified-mutable-target-rootfs`, `filesystem_causality: unverified`
and `release_ready: false`; it cannot convert bytes copied from the mutable target rootfs
into authenticated APT output. The gate next locates
`PACKAGE-FILESYSTEM-CAUSALITY.json`. For a fresh bootstrap it re-extracts the exact
`.deb` payloads named by the bound pre-post-host `final_inventory` snapshot and
recomputes their static comparison with `ROOTFS-MANIFEST.json`; for an ISO remaster it
recomputes the deliberately all-`unsupported` map without inspecting payload blobs. It
does not trust either report's recorded verdict. The authoritative
product path separately extracts the SquashFS from the descriptor-held final ISO, unpacks
it and compares its semantic tree with that same manifest. These checks prove internal
consistency and static `payload_identity` against the recorded local inputs, not which
producer caused the filesystem state. Final authentication still requires a verified
signature or trusted WORM anchor, while `filesystem_causality` remains `unverified`,
`release_ready` remains false and package-to-rootfs causality remains blocking M3.2b debt.

`beginner-iso --repair-release-artifacts` may derive checksums and explanatory files from
an existing ISO. Any provenance it creates is labelled
`attestation_kind: reconstructed`, which is blocked for publication. A matching real
build provenance file is preserved rather than overwritten.

The publish bundle includes `ISO-BUILD.json` and every referenced build, QEMU and
boot-proof run directory. Every path component from the output root through `evidence`,
`runs` and the run itself is checked; a file, directory or ancestor symlink is refused
before copy, and a symlinked bundle destination is refused before its first write.
`create_publish_bundle` additionally requires the gate's ephemeral
`ArtifactVerificationReceipt`, which is deliberately absent from serialized
`RELEASE-GATE.json`: every copied regular source must match its complete received
identity and SHA-256, and each run tree must match its received anchor and exact
inventory. A missing receipt, omitted source or different union of runs blocks.
Regular files are streamed from held descriptors while size and SHA-256 are computed;
run trees are copied descriptor-relatively with explicit file/byte budgets. A fully
synced staging tree is exposed only by a Linux no-replace rename, so a link or special
file appearing during the copy is a refusal rather than content preserved in a partial
bundle. Release signing manifests recurse through accepted directories so the command
logs, runtime output, firmware copies and proof files are covered rather than merely
copied.

Publish-signing readiness likewise no longer follows file presence. The bundle inventory
must be exact, `SHA256SUMS` must be bounded and canonical and name the unique
manifest-bound current ISO, the typed release-gate aggregate must agree with its non-empty
items, the manifest and signing report must describe the same snapshot, and the pinned
keyring plus exactly three detached signatures must verify from held descriptors. A
standalone verification holds the manifest, gate, checksum file, ISO, runtime evidence,
payloads, keyring and signatures in one session and requires its closing inventory to
equal the opening snapshot.

## Next executing milestones

No existing artifact can be retrofitted into v2 proof. M2.2 is closed at its stated
source/test boundary by the receipt below, and M3.1 closes only a static package-payload
identity map in code and fixtures. M3.2a adds only a self-consistency receipt for supplied
APT-format action bytes: their mutable target-rootfs origin remains explicitly unverified.
M3.2a.2 closes stale digest reuse and the descriptor-backed integrity of local artifact
readers, copies and publication snapshots in code and hostile fixtures only. It does not
authenticate an APT producer or any filesystem transformation. M3.2a.3 closes the small
CVE fail-closed policy milestone at the source/test boundary by reusing, not changing, the
descriptor-backed artifact session. It records the database snapshot that supported the
local verdict but does not authenticate that database or turn a name-only match into
product evidence. The next executing product-causality milestone remains M3.2b:

1. implement and test M3.2b producer causality: give a host-isolated one-shot witness the
   first write of each `DPkg::Pre-Install-Pkgs` protocol-v3 stream and require its
   acknowledgement before dpkg can run, bind each executed producer to observed
   before/after filesystem deltas, and account for maintainer scripts, triggers,
   conffiles, alternatives, diversions, removals, customizers and every other
   transformation, including the ISO baseline, before `capture_origin` or
   `filesystem_causality` may be promoted and `release_ready` may become true;
2. seal the source-ISO detached signature, verification status and exact keyring for
   offline release-gate replay, or keep ISO-remaster publication explicitly at `review`;
3. execute a fresh minimal build with the externally pinned archive trust policy, package
   transaction and action receipts, corrected GRUB MBR and appended GPT ESP;
4. replay the semantic rootfs manifest from that exact final ISO and verify every
   append-only run file and intermediate identity;
5. review the executed command identities and explicitly account for the still-open
   transitive ELF loader/library boundary;
6. execute BIOS and UEFI proofs against that exact ISO through `login_prompt`;
7. execute UEFI Secure Boot and prove shim, signed GRUB, kernel and casper milestones;
8. repeat with the selected desktop and require display-manager and graphical-session
   milestones;
9. build independently a second time from pinned inputs and compare the complete
   artifact manifests;
10. sign and verify the closing manifests, or commit them and the corresponding artifacts
   to trusted WORM/content-addressed storage.

Until those rows are proved, `0.3.5-17` stays `UNRELEASED`; no release tag or `main`
fast-forward is justified by this ledger. An explicitly authorized push of the audit code
to `develop` is staging, not publication proof, and must not be reported as a successful
ISO build.

## Staging and CI receipts

### 2026-07-29 — develop audit handoff

- The authorized staging push advanced only `origin/develop`, from
  `66046b75b86f3c0b59303b927b15ce1d6486407b` to signed commit
  `33ddb64c4205428e4208d2ce01a37f6cefb32d8e`. Its signature verifies under primary
  fingerprint `93D942241BECDD422606C36C4C0D75219B5506CF`.
- `origin/main` remained `4b80b8ca5dbb3c08fe5b68c368b0b1420c256d57`. Annotated tag
  `debian/0.3.5-16` remained object `b7e5f3b3504a793a457954f12301c37ab1b17e92`,
  peeled to commit `38217da4ecbd1076514c9c4e949100a18272ee8a`. No tag, pull request
  or `main` fast-forward was created.
- Per-push [CI run 30482945660](https://github.com/Test-bot-cell/Distroforge/actions/runs/30482945660)
  completed with ten failed jobs. Installation, lint and type checks reached success; the
  test and packaging-policy steps all encountered the history-wide subject ratchet because
  `audit:` is not admitted. This is a captured refusal, not a successful CI receipt.
- M2.1 preserves the immutable signed commit and narrows the exception to its exact SHA and
  exact subject. It does not admit `audit:` globally and does not rewrite or force-push
  protected history. No ISO, package, Golden-path build, release tag or publication was
  produced by this handoff.

### 2026-07-29 — M2.1 verdict and local M2.2 repair

- The explicitly authorized push advanced only `origin/develop` from `33ddb64c4205428e4208d2ce01a37f6cefb32d8e`
  to signed commit `ccf1febf361857e47b1447e04f244d79d16ae393`.
  `origin/main` remained `4b80b8ca5dbb3c08fe5b68c368b0b1420c256d57`;
  annotated tag `debian/0.3.5-16` remained object
  `b7e5f3b3504a793a457954f12301c37ab1b17e92`, peeled to
  `38217da4ecbd1076514c9c4e949100a18272ee8a`. No tag, pull request or
  `main` fast-forward was created.
- Per-push [CI run 30485032512](https://github.com/Test-bot-cell/Distroforge/actions/runs/30485032512)
  completed with one success and nine failures for exact HEAD `ccf1febf…`.
  `packaging-static` passed every step, including the complete-history subject policy,
  so M2.1 itself reached its intended remote gate.
- Every Python 3.11–3.14 and Qt matrix leg passed installation, Ruff and mypy, then
  reported the same five tests: four CLI tests were stopped by the real host-tool
  doctor before their subject was reached, and the FIFO fixture requested `0620` but
  observed the correct umask-filtered `0600`. Each leg recorded 1,236 passed, 37
  skipped and five failed tests.
- `distro-dependencies` reported those same five failures plus
  `test_golden_path_verifies_the_builder_with_the_pinned_public_key`: it executed
  `gpg`, but neither the job nor `Build-Depends <!nocheck>` supplied `gnupg`. That
  leg recorded 1,224 passed, 48 skipped and six failed tests.
- The CLI failures reproduce with `PATH=/nonexistent`; the FIFO failure reproduces
  under umask `0022` and passes under the workstation's `0002`. M2.2 pins only the
  required ISO planning tools inside the subject tests, keeps a separate all-tools-
  absent refusal test, applies the requested FIFO mode explicitly after creation,
  and declares plus installs `gnupg` for the suite. The final dependency audit also
  found that executing source-ISO authentication and release signing invoke `gpg`,
  so the binary package now depends on `gnupg` instead of misclassifying it as
  test-only. It also found that the semantic-rootfs fixtures execute `mksquashfs`
  and `unsquashfs` when available; `squashfs-tools` is now a test dependency and
  installed in the distribution job so that proof no longer skips there. Targeted
  CLI tests pass both with the normal PATH and with `PATH=/nonexistent`; the FIFO
  test passes under both umasks.
- The Node 20 deprecation annotation is a separate non-blocking Actions maintenance
  debt: checkout, setup-python and `packaging-static` completed. M2.2 does not mix an
  action-pin migration into this causal repair.
- This local M2.2 work runs no package or ISO build and does not exercise the Golden
  workflow. Its commit and any later push remain separate acts; no push is authorized
  by this receipt.
- The complete local `make check` ran outside the restricted validation wrapper whose
  `no-new-privileges` setting prevents `gpg-agent` startup and changes `sudo -n` from
  an authentication result into a container refusal. In that usable environment Ruff
  passed, mypy checked 255 source files, pytest reported 1,279 passed and one skipped,
  ShellCheck passed and both embedded Python payloads compiled. All eight
  `pre-commit run --all-files` ratchets also passed. These are local source/test
  results. At that point the remote M2.2 verdict did not yet exist; the following
  receipt records the later, separately authorized push and result.

### 2026-07-29 — M2.2 remote verdict

- The explicitly authorized fast-forward advanced only `origin/develop`, from
  `ccf1febf361857e47b1447e04f244d79d16ae393` to signed commit
  `7b87af7e2e2a411fdf626f02ba26928ac1c75dcb`. GitHub reports the commit signature
  `verified: true` with reason `valid`; local verification accepts primary fingerprint
  `93D942241BECDD422606C36C4C0D75219B5506CF`.
- Per-push [CI run 30488026011](https://github.com/Test-bot-cell/Distroforge/actions/runs/30488026011)
  was created for event `push`, branch `develop` and that exact full SHA. It completed
  `success` at `2026-07-29T20:22:47Z`: all eight Python 3.11--3.14 / Qt matrix jobs,
  `packaging-static` and `distro-dependencies` succeeded.
- Each matrix leg passed Ruff, mypy over 255 source files and pytest with 1,243 passed
  and 37 skipped tests. `distro-dependencies` installed only the declared distribution
  packages, satisfied the declared Pydantic version, then ran the suite as the
  unprivileged builder with 1,272 passed and eight skipped tests. `packaging-static`
  passed ShellCheck, embedded-Python compilation, every whole-tree pre-commit ratchet,
  107 packaging/policy tests and the five targeted Lintian-vendor tests.
- No Actions job or step was failed or skipped. The ten annotations, one per job, contain
  no error and report only that the pinned checkout/setup-python actions still target
  deprecated Node 20 and are being forced onto Node 24. That maintenance debt remains
  separate from M2.2.
- `origin/main` remained `4b80b8ca5dbb3c08fe5b68c368b0b1420c256d57`.
  Annotated tag `debian/0.3.5-16` remained object
  `b7e5f3b3504a793a457954f12301c37ab1b17e92`, peeled to
  `38217da4ecbd1076514c9c4e949100a18272ee8a`. No pull request, tag or `main`
  fast-forward was created.
- This receipt closes only the M2.2 source/test-environment milestone. The run did not
  build a Debian package, execute the Golden path, assemble an ISO or boot one, and it
  cannot promote any of those ledger rows.

### 2026-07-29 — M3.1 local static package/rootfs map

- Starting from signed local documentation commit
  `36481c54db3309c2933584b0aa00f6cfe92ef489`, the worktree added the run-bound
  `PACKAGE-FILESYSTEM-CAUSALITY.json` v1 writer, authoritative replay and release-gate
  binding. No existing build artifact was reinterpreted and no product run emitted this
  schema.
- A fresh-bootstrap replay opens each selected recorded `.deb` through a held
  run-directory descriptor, asks bounded `dpkg-deb` commands for identity and the
  documented uncompressed filesystem tar, parses it under per-object and aggregate
  budgets, and compares supported direct payload members with the sealed final rootfs
  manifest. ISO-remaster mode inspects no payload blob until a semantic source baseline
  exists and records the complete final manifest as `unsupported`/`partial`.
- The report says `sealed-recorded-deb`, with the authenticated package-input and external
  source-policy replay as an explicit independent assurance dependency. Static
  `payload_identity` never promotes `filesystem_causality: unverified` or
  `release_ready: false`.
- Negative controls cover path traversal, non-canonical aliases and depth, duplicate
  members, both conflicting-byte and same-byte/multiple-path package identities,
  archive/file drift, run/ancestor/parent/leaf swaps, non-regular objects, exclusions,
  unsupported final objects, conflicting package claims, early rootfs cardinality,
  output and incremental aggregate budgets, bounded stdout/stderr, compressed tar,
  malformed numeric PAX, recursive Solaris PAX, GNU sparse headers and PAX sparse
  metadata, cyclic/absent/deep hardlinks, forged reports and forbidden release
  promotion. The hardlink resolver is iterative and its groups are sorted once.
- The first restricted `make check`, before the final fixes, did useful falsification:
  it exposed one real unpublished-mailbox fixture regression, while `no-new-privileges`
  separately prevented the real `sudo -n` question and seven `gpg-agent` setups. The
  mailbox fixture was corrected; the sandbox refusals were not relabelled as code passes.
- On the final tree, `make check` ran in the usable local environment: Ruff passed, mypy
  checked 256 source files, pytest reported 1,343 passed and one skipped, ShellCheck
  passed, and both embedded maintainer-script Python payloads compiled. All eight
  `pre-commit run --all-files` ratchets passed. The focused M3.1 hostile-input file
  reported 50 passes, the focused rootfs evidence file reported 23 passes, and the
  broader causality/provenance/rootfs/policy selection reported 261 passes.
- These are local source, parser, fixture and policy results only. The aggregate budgets
  have not been sized by a real desktop build. No Debian package, ISO, Golden path, QEMU
  boot, tag, pull request, push or `main` movement occurred. `origin/develop` therefore
  still names signed commit `7b87af7e2e2a411fdf626f02ba26928ac1c75dcb`; any later
  develop-only push remains a separate explicit act.

### 2026-07-30 — M3.1 remote typecheck falsification and local repair

- The explicitly authorized fast-forward advanced only `origin/develop`, from
  `7b87af7e2e2a411fdf626f02ba26928ac1c75dcb` to signed M3.1 commit
  `6017476ee081532507e6029be47ab86bd4f0a2ad`. GitHub reports the signature
  `verified: true`, reason `valid`; local verification accepts primary fingerprint
  `93D942241BECDD422606C36C4C0D75219B5506CF`. `origin/main` remained
  `4b80b8ca5dbb3c08fe5b68c368b0b1420c256d57`; no pull request, tag or `main`
  movement occurred.
- Per-push [CI run 30517720041](https://github.com/Test-bot-cell/Distroforge/actions/runs/30517720041)
  targeted event `push`, branch `develop` and that exact full SHA. It ran from
  `2026-07-30T05:49:33Z` through `2026-07-30T05:51:34Z` and completed `failure`.
  `packaging-static` and `distro-dependencies` succeeded. All eight Python
  3.11--3.14 / PySide6/PyQt6 jobs passed installation and Ruff, then stopped at
  Typecheck before their test step.
- The eight legs share one source failure. Their admitted `mypy>=1.11` dependency
  resolved to mypy 2.3.0. That version inferred `package_binding` as
  `dict[str, int | str]` and rejected its two calls into the invariant
  `dict[str, object]` `_report` contract. The Node 20 action-runtime annotations
  remain non-blocking and did not cause this verdict.
- Local mypy 1.19.1 and the preceding `make check` accepted the tree, so that local
  green result did not cover the newer inference rule. An isolated, non-incremental
  `uvx --from mypy==2.3.0 mypy --no-incremental distroforge/` reproduced exactly
  two errors at the same call sites across 256 source files. Adding the explicit
  `package_binding: dict[str, object]` contract makes the identical mypy 2.3.0
  command pass all 256 files; Ruff, local non-incremental mypy, and the 50 focused
  M3.1 tests also pass.
- On the repaired tree, `make check` passed Ruff, local mypy 1.19.1 over 256
  source files, pytest with 1,343 passed and one skipped test, ShellCheck and both
  embedded maintainer-script Python payloads. All eight
  `pre-commit run --all-files` ratchets passed. The separate mypy 2.3.0 result
  above is the version-specific closure of the remote failure; the general local
  gate does not relabel the failed GitHub run as green.
- This is a local repair receipt only. No follow-up push, package/ISO build,
  Golden-path run, tag, pull request or `main` movement is authorized or performed.

### 2026-07-30 — M3.1 remote CI closure

- A later, separately authorized fast-forward advanced only `origin/develop`, from
  `6017476ee081532507e6029be47ab86bd4f0a2ad` to repair commit
  `a3f14becc0bd2d67d5cadf6c2a10e47b5a0df844`. GitHub verifies that commit's
  signature (`verified: true`, reason `valid`, verified at
  `2026-07-30T06:12:33Z`); local verification accepts primary fingerprint
  `93D942241BECDD422606C36C4C0D75219B5506CF`.
- Per-push [CI run 30518874302](https://github.com/Test-bot-cell/Distroforge/actions/runs/30518874302)
  is bound to event `push`, branch `develop`, attempt 1 and that exact full SHA.
  It ran from `2026-07-30T06:12:35Z` through `2026-07-30T06:15:16Z` and
  completed `success`.
- The terminal jobs API enumerated exactly ten jobs and reported every one
  `completed`/`success`: `packaging-static`, `distro-dependencies`, and the eight
  Python 3.11--3.14 / PySide6/PyQt6 matrix legs. Authenticated `gh run view --log`
  subsequently retrieved the raw job logs after the unauthenticated archive
  endpoint had correctly refused them with HTTP 403. Every matrix installed
  mypy 2.3.0, reported `Success: no issues found in 256 source files`, and then
  completed the test suite as follows:

  | Python / Qt binding | pytest result | elapsed |
  | --- | ---: | ---: |
  | 3.11 / PySide6 | 1,306 passed, 38 skipped | 72.76 s |
  | 3.11 / PyQt6 | 1,306 passed, 38 skipped | 94.47 s |
  | 3.12 / PySide6 | 1,306 passed, 38 skipped | 106.13 s |
  | 3.12 / PyQt6 | 1,306 passed, 38 skipped | 104.31 s |
  | 3.13 / PySide6 | 1,306 passed, 38 skipped | 104.75 s |
  | 3.13 / PyQt6 | 1,306 passed, 38 skipped | 99.95 s |
  | 3.14 / PySide6 | 1,306 passed, 38 skipped | 102.74 s |
  | 3.14 / PyQt6 | 1,306 passed, 38 skipped | 98.29 s |

- `packaging-static` executed ShellCheck, compiled both embedded maintainer-script
  Python payloads, passed all eight pre-commit ratchets, reported 107 packaging
  and policy tests passed, and exercised both Debian and Ubuntu Lintian
  2.129.0ubuntu2.1 profiles with five targeted tests passed and 24 deselected.
  `distro-dependencies` ran under the unprivileged offscreen builder in the
  `ubuntu:26.04` container using only declared distribution dependencies; GnuPG,
  xorriso, SquashFS tools and zstd were present, and pytest reported 1,336 passed
  and eight skipped in 90.36 seconds.
- The quiet pytest output does not name the skipped tests or their reasons, so this
  receipt records counts rather than inventing skip causality. Neither static
  packaging checks nor the distribution-dependency suite built a Debian package,
  rootfs or ISO.
- This remote verdict closes the reproduced mypy refusal for the signed repair
  commit. It does not execute or promote the package, Golden path, ISO, firmware,
  boot, desktop, release-signature or reproducibility milestones. `origin/main`
  remains `4b80b8ca5dbb3c08fe5b68c368b0b1420c256d57`; the existing
  `debian/0.3.5-16` tag remains on `38217da4ecbd1076514c9c4e949100a18272ee8a`.
  No pull request, tag, package/ISO build or `main` movement occurred.

### 2026-07-30 — M3.2a local self-consistent APT-format action receipt

- Starting from signed local documentation commit
  `b0335fcd2a4fdaa4bdf07b17f6cf1864541bc07e`, the worktree added the run-bound
  `PACKAGE-APT-ACTIONS.json` v1 writer, host-side collection replay, provenance and
  release-gate binding. No existing artifact was reinterpreted and no executing product
  run emitted this schema.
- The generated APT fragment requests `DPkg::Pre-Install-Pkgs` protocol version 3 on
  InfoFD 0. The parser's configuration framing, percent encoding and nine-field actions
  were checked against
  [apt.conf(5)](https://manpages.debian.org/testing/apt/apt.conf.5.en.html) and APT's
  [`dpkgpm.cc`](https://sources.debian.org/src/apt/3.3.1/apt-pkg/deb/dpkgpm.cc/) /
  [`strutl.cc`](https://sources.debian.org/src/apt/3.3.1/apt-pkg/contrib/strutl.cc/).
  These are format references only: this milestone observed no stream produced by a real
  APT transaction.
- A local controlled-root harness really executes the generated shell `pre` and `post`
  modes with synthetic protocol bytes and controlled `apt-config`/`apt-get` helpers. It
  confirms the missing-InfoFD, overlapping-interval, protocol, per-blob and aggregate
  oversize refusals and the journal state transition. The shell checks the 32-GiB
  per-input and 64-GiB aggregate blob budgets before hashing, and bounds both hashing and
  copying; the non-authoritative release-gate preview also bounds the action report before
  parsing it. It does not execute apt/apt-get package acquisition or installation, dpkg,
  an archive transaction, a package build, an ISO build or a boot.
- The authoritative replay applies explicit per-input and aggregate bounds, verifies the
  copied journal, raw protocol, recorder/configuration and package-transaction identities,
  and binds every unpack action exactly and exhaustively to one sealed `.deb`
  package/version/architecture record. Malformed or downgraded framing, invalid encoding,
  incomplete intervals, unexpected or duplicate captures, unmatched archives, drift and
  forged status promotion are refusals.
- This establishes internal consistency, not capture provenance. Before host collection,
  the transcript, journal and CAS remain mutable below the target rootfs; copying and
  re-hashing them later cannot prove that APT originated those bytes. A non-empty valid
  receipt therefore records `apt_actions: self-consistent`, while no captured
  post-bootstrap transaction records `apt_actions: not-observed`. Both require
  `capture_origin: unverified-mutable-target-rootfs`,
  `filesystem_causality: unverified` and `release_ready: false`. The post marker closes
  the staged interval and does not prove dpkg success.
- M3.2b must put the first write in a host-isolated one-shot witness and make its
  acknowledgement a prerequisite for dpkg, then bind before/after producer deltas and
  account for maintainer scripts, triggers, conffiles, alternatives, diversions, direct
  dpkg calls, customizers and the bootstrap/ISO baselines.
- The terminal local source/test receipts were:
  - `make check`: Ruff passed; repository mypy passed over 257 source files; complete
    pytest passed `1400` tests with one documented environmental skip; ShellCheck passed
    for `debian/tests/gui-import`, `debian/tests/smoke` and `tools/release-tag.sh`; the
    maintainer-payload gate compiled both embedded Python payloads and reported no
    problem;
  - `uvx --offline --from mypy==2.3.0 mypy --no-incremental distroforge/`: passed over
    257 source files with the CI-pinned mypy release and no network access;
  - focused M3.2a/package/release/policy pytest replay: `171 passed`;
  - the generated capture-hook shell, streamed independently to `shellcheck -s sh -`:
    passed;
  - `pre-commit run --all-files`: all eight offline hooks passed;
  - `git diff --check`: passed.
  These are source, fixture and static-tool receipts only; none is a real APT/dpkg,
  package, ISO, boot or publication receipt.
- This local work performed no push, tag, pull request or `main` movement.
  `origin/develop` remains `a3f14becc0bd2d67d5cadf6c2a10e47b5a0df844`,
  `origin/main` remains `4b80b8ca5dbb3c08fe5b68c368b0b1420c256d57`, and
  `debian/0.3.5-16` remains on `38217da4ecbd1076514c9c4e949100a18272ee8a`.

### 2026-07-30 — M3.2a.1 local durability and harness hardening

- Starting from signed local M3.2a commit
  `8280e770b435167663d58a9b70a88b98b6778b85`, one explicitly approved external
  review suggested durability, path-race and harness-isolation checks. The external
  response was treated as hypotheses, not evidence: local inspection rejected its
  C-specific parser advice because the bounded parser is Python, confirmed the existing
  descriptor-held host collector, and retained the concrete writer, legacy JSON-reader
  and test-environment debts below.
- `write_immutable_text` now UTF-8-encodes before filesystem mutation, creates an
  exclusive temporary below a held same-directory descriptor, writes and file-syncs the
  complete content, publishes through an atomic hard link which refuses replacement,
  syncs the parent, removes the temporary name and syncs the parent again. Existing
  regular files, symlinks and dangling symlinks are refusals. Injected file-sync failure
  publishes no target; injected directory-sync failure leaves at most the already
  complete target. A crash may leave a partial or complete dot-temporary which is never
  treated as the published target. Hard links and directory sync are POSIX/Linux
  assumptions, newly created ancestors are not recursively synced, and publication
  links the random temporary name rather than the held descriptor; a hostile writer
  with same-directory mutation rights remains outside this contract. This is therefore
  a measured append-only durability improvement, not a filesystem or power-loss
  attestation.
- The authoritative package-input validator now opens `PACKAGE-INPUTS.json` and every
  referenced transaction through the confined run reader, applies the existing 128-MiB
  per/aggregate contracts during every digest/read pass, verifies each transaction's
  recorded size and SHA-256, and converts invalid Unicode, malformed/non-object JSON,
  symlinks, oversize, post-`fstat` growth and drift into `ok: false`,
  `release_ready: false`. The release gate opens one bounded provenance snapshot and
  reuses it across package, rootfs, ISO, manifest and provenance checks, then rejects an
  alias that differs at closure. Its direct JSON, command-log and manifest-sidecar
  readers are non-blocking and bounded; the package preview applies explicit bounds to
  `PACKAGE-INPUTS.json`, `PACKAGE-APT-ACTIONS.json` and
  `PACKAGE-FILESYSTEM-CAUSALITY.json` and returns `blocked` for the same malformed-input
  classes. This does not claim that every delegated rootfs, ISO or QEMU validator reader
  has yet been migrated to the same descriptor contract.
- The controlled-root shell harness no longer inherits `os.environ` or falls through to
  the general host `PATH`. Its closed tool directory names the admitted Unix utilities,
  journals the two expected `apt-config` and `apt-get` shims, and supplies failing,
  journaled traps for `apt`, `dpkg`, `dpkg-deb`, `dpkg-query` and `sudo`. The asserted
  call ledger contains exactly the two expected discovery calls. Supplying
  `APT_HOOK_INFO_FD=0` still exercises only the hook guard: neither the variable nor the
  closed harness authenticates the descriptor's producer.
- The local receipts obtained before this hardening was committed were:
  - combined package-input/evidence-run pytest replay: `101 passed`;
  - one sandboxed full replay exposed only its execution boundary: `1412 passed`,
    `1 skipped`, one `sudo` failure under `no_new_privileges` and seven GPG-agent
    startup errors; this non-green run was not accepted as a source verdict;
  - the same gate then ran alone outside that restriction: `make check` passed with
    Ruff, mypy over 257 source files, `1420 passed, 1 skipped`, ShellCheck over the
    discovered Debian/tool scripts, and both embedded Python payloads compiled;
  - `pre-commit run --all-files` passed every configured ratchet;
  - Ruff over all five initially changed Python files and `git diff --check`: passed;
  - direct cached CI-pinned mypy 2.3.0, offline and non-incremental: passed over 257
    source files.
- The resulting commit is
  `ac0bedefd4d0d8b49bdabc1f606fd3471b4ea3ea`. Local `git verify-commit` accepts its
  signature from primary fingerprint
  `93D942241BECDD422606C36C4C0D75219B5506CF`; this post-write metadata is recorded by the
  later documentation lot rather than guessed by the commit about itself.
- No real APT stream or transaction, dpkg operation, package/rootfs/ISO build, boot,
  push, tag, pull request or `main` movement occurred. `capture_origin` remains
  `unverified-mutable-target-rootfs`, `filesystem_causality` remains `unverified`,
  `release_ready` remains false, and the host-isolated one-shot ACK plus producer deltas
  remain M3.2b.

### 2026-07-30 — M3.2a.2 scoped artifact-verdict integrity

- Starting from signed M3.2a.1 commit
  `ac0bedefd4d0d8b49bdabc1f606fd3471b4ea3ea`, signed commit
  `976fa5ae11ee53ef32f46020e06cfa99c15d2a95` removes the persistent path/size/mtime
  SHA-256 cache. Low-level digest calls now recompute from the bytes opened for that
  invocation, so an atomically substituted same-size file with restored mtime cannot
  inherit a prior verdict.
- Signed commit `b7f21fa8fb181c14cb4a09948596dbb36cfb7212` adds the reusable
  `ArtifactVerificationSession` boundary. Both commits pass local `git verify-commit`
  with primary fingerprint `93D942241BECDD422606C36C4C0D75219B5506CF`.
  A session anchors one canonical directory descriptor, opens every path component
  without following links, accepts regular leaves only, uses non-blocking reads, records
  complete host identity, keeps the inode held, and permits digest/bytes/JSON/replay
  reuse only inside one verdict. At sealing it first re-hashes held inodes, repeats
  bounded inventories as the final content observation and only then repins each name
  from the leaf through its ancestors to the anchor before dropping cached content.
  Every producer and reader validates `run_id` before composing a path: it must be one
  canonical strict-UTF-8 component without separators or controls and is limited to 255
  encoded bytes.
- The delegated-reader lot applies that boundary to rootfs manifests and packing,
  ISO assembly and authoritative replay, QEMU report/serial/capture/firmware evidence,
  boot-proof reports/manifests/sidecars, release readiness/gate/signing/verification and
  publish-bundle, drill-baseline and drill-diff inputs. External QEMU, ISO/SquashFS and
  GPG consumers receive held descriptors through `/proc/<pid>/fd` plus `pass_fds`; alias
  comparisons use handles held in the same session instead of reopening names
  independently.
- A non-blocked or ready signed gate must carry one immutable build run B and boot run C,
  with provenance/SBOM paths under B and boot/QEMU paths under C. Terminal verification
  requires the boot proof and boot run manifest to bind exactly `C -> B`; a missing,
  malformed or cross-run path blocks. Pipeline, drill, acceptance, beginner, CLI and GUI
  surfaces retain only IDs selected by that verdict. If B already embeds a valid boot run
  D, boot proof revalidates and reuses D without VM execution or a conflicting C.
  `iso-accept` remediation creates and consumes any new boot run in one
  `release-pipeline` process, so no placeholder ID can enter a path.
- Binary and tree copies now hold and revalidate the source, compute size and SHA-256
  while writing a fully synced same-directory object and publish without replacement.
  Regular text and binary targets use anonymous `O_TMPFILE` inodes, so there is no
  swappable temporary pathname or pathname cleanup; an explicit idempotent collision must
  reproduce the exact size and digest. Tree staging is re-hashed against its per-file
  receipt before rename. Failed owned trees are durably detached into unpredictable
  quarantine names before an independently reported bounded best-effort scrub. The
  quarantine is always physically retained; detach-only replay retirement may report
  residual entries and bytes. Bundle publication first consumes a non-serialized gate
  receipt binding every source identity/digest and run-tree anchor/inventory, then returns
  a distinct stable directory identity which every later writer must reproduce. The gate
  evaluates the explicitly selected bundle descriptor-relatively: absence is review, but
  a symlinked, non-directory or unreadable component is blocked, and another signed bundle
  cannot supply its evidence. The signing gate requires an exact
  bundle snapshot, one current manifest-bound ISO, canonical bounded `SHA256SUMS`, a
  coherent typed release gate, a minimal public-only pinned keyring and exactly three
  cryptographically verified descriptor-bound signatures. Presence alone cannot produce
  `ready`; internal temporary or quarantine entries block the next preflight.
- Standalone verification publishes a report only after its primary session, exact
  opening/closing inventories and original bundle identity seal; an identical existing
  report may be reused but is never replaced. Explanation reproduces that live verifier
  result rather than trusting self-consistent JSON. After explanation, the drill repeats
  the read-only verifier and requires an identical result, then validates the complete
  persisted pipeline/gate/manifest/signing/keyring/verification contract through one
  strict schema. Only that terminal result may resolve the sole pre-signing
  `publish-signing` review. A real local Ed25519 fixture exercises the complete ready
  pipeline while remaining non-product evidence.
- Drill comparison remains explicitly `structural-only`: it validates and compares the
  stored report graph but does not authenticate either release. A canonical promoted
  baseline requires its exact in-bundle names, bundle identity and matching local
  size/SHA receipt; that receipt is forgeable by a bundle writer, is not cryptographic
  provenance and never contributes to `release_ready`. Promoting a `ready_to_publish`
  drill requires an external complete signer fingerprint and identical live verification
  before and after publication; a terminal block or exception creates no ready receipt.
- Local pre-commit receipts gathered during closure:
  - `make check`: Ruff passed; mypy passed over 262 source files; pytest reported
    `2000 passed, 1 skipped`; ShellCheck passed; both embedded maintainer-script Python
    payloads compiled with no problem;
  - the CI-pinned offline `mypy 2.3.0 --no-incremental` replay passed over the same 262
    source files;
  - all eight `pre-commit run --all-files` hooks passed and `git diff --check` reported no
    whitespace error;
  - the non-GPG sandbox matrix reported `1915 passed, 4 skipped`; the two real GPG
    end-to-end scenarios then passed outside the sandbox with generated Ed25519 keys;
  - focused causal matrices reported 56 contract/run-propagation tests, 11 terminal
    verification-session tests, 80 maintainer release tests and 21 off-thread UI tests
    passed.
  No precomputed green flag was substituted for these executions. The delegated-reader
  commit identity and signature are post-write facts: they are intentionally left to the
  completed handoff after that commit exists, rather than predicted in the commit it
  authenticates.
- These checks falsify same-size/same-mtime replacement, swaps after hash or parse,
  symlink leaves and ancestors, FIFO/socket/device/directory inputs, growth/truncation,
  invalid or excessively deep JSON, serial and firmware replacement, copy/fsync/link/
  unlink failures, bundle clones, collisions, descriptor leaks and structural-budget
  exhaustion. They prove the held inode's bytes and equality at observed opening/closure
  boundaries, not the absence of a perfectly restored transient mutation. M3.2a.2 closes
  the earlier regular-writer name window with anonymous-inode re-hashing and one
  no-replace link; it never claims exchange, replacement or safe unlink-by-name.
- Beginner repair remains a convenience producer, not an atomic multi-file attestation.
  An ISO or output-directory swap clears its success list, blocks the pipeline before
  bundle creation and may leave only complete but non-authoritative immutable files; a
  fresh output directory is required for retry. Reconstructed provenance remains blocked.
- This is source and hostile-fixture integrity, not an APT-origin, dpkg-execution,
  package/rootfs/ISO-build, firmware, boot, release-signature or reproducibility receipt.
  No promotion occurs: `capture_origin` remains
  `unverified-mutable-target-rootfs`, `filesystem_causality` remains `unverified`, and
  `release_ready` remains false. The blocking policy for an unreadable CVE database is
  reserved for M3.2a.3. The host-isolated one-shot ACK and producer/filesystem deltas
  remain M3.2b, the next executing causality milestone.
- No push, tag, pull request or `main` movement is part of this local stanza.
  `origin/develop` remains `a3f14becc0bd2d67d5cadf6c2a10e47b5a0df844`,
  `origin/main` remains `4b80b8ca5dbb3c08fe5b68c368b0b1420c256d57`, and
  `debian/0.3.5-16` remains on `38217da4ecbd1076514c9c4e949100a18272ee8a`.

### 2026-07-31 — M3.2a.3 CVE database fail-closed policy

- Starting from signed local M3.2a.2 commit
  `0ba45a1b29a707c4a705e4ff2238fb6f349e5c04`, the preflight traced all four CVE
  consumers before modification. A missing or unreadable database produced only
  `DB-UNAVAILABLE` at warning level, so `enforce()` recorded `vuln-report ok`, the
  build continued and the release gate returned `review`. Worse, a non-object root,
  absent/mistyped `advisories` or silently filtered entries could become an empty clean
  scan and a locally ready CVE item. This policy debt was independent of the package
  claims: `capture_origin`, `filesystem_causality` and `release_ready` were already
  forced to their unverified/unverified/false values.
- The scanner now accepts only a non-empty set of canonical Debian package names and a
  non-empty `distroforge-vulndb/1` database with canonical typed advisory entries. It
  reads at most 16 MiB through one descriptor-backed `ArtifactVerificationSession`,
  refuses links and special files, applies strict UTF-8, unique-key bounded JSON and
  structural node/depth budgets, retains the inode through parse/digest and revalidates
  it at closure. Metadata/advisory text is NFC-normalized, control-free and individually
  byte-bounded; package input is bounded by count and 255-byte canonical names. A
  successful report records the exact SHA-256, schema, declared source/update strings and
  advisory count. Physical, encoding, JSON, bound, path, stability and internal failures
  have stable diagnostic classes; schema and input failures have stable semantic codes.
  Rejected unexpected or duplicate JSON keys are counted/classified without echoing
  attacker-controlled key text into diagnostics.
- `block-high` and `block-critical` turn every unusable database, invalid schema,
  unknown policy, empty, over-budget or non-canonical package scope into an error and
  controlled build refusal. For those failures, `warn` and `off` keep their non-blocking
  build contract but report `degraded`, and the release gate reports `review`, never
  `ready`. That review remains review in readiness and ISO acceptance, cannot mark the
  publish journey ready and cannot authorize executable signing through either the
  release pipeline or direct `sign-release --execute`; only the sole pre-signing
  `publish-signing` review retains its terminal-verification exception. Readiness and
  its embedded dry-run share one `VulnScanReport`, so a second database read cannot
  contradict or promote the same verdict.
  `clean` means only that those exact structurally accepted database bytes contain no
  name match for the exact non-empty planned package set.
- Adversarial fixtures cover absence, injected permission refusal, invalid UTF-8,
  truncated/duplicate/non-finite/deep JSON, non-object roots, wrong/empty schema,
  malformed and duplicate entries, control/format characters, exact text/package/count
  byte boundaries, symlink leaf and ancestor, FIFO, directory, device, same-mtime
  mutation, injected parser/resource/path/iterator failures, empty scope and
  non-canonical package names. Direct consumers prove controlled behavior in build,
  readiness, dry-run, release-gate, journey, ISO-acceptance and signing-authorization
  paths. The exact focused command was:

      PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider \
        tests/test_supply_chain_features.py tests/test_command_virtual.py \
        tests/test_policy_compliance.py tests/test_release_gpg_pinning.py -k vuln

  It reported `72 passed, 148 deselected`. The exact affected-consumer replay was:

      PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider \
        tests/test_iso_acceptance_run_selection.py tests/test_readiness_trust_ai.py \
        tests/test_pillar_contracts.py tests/test_ui_reachability.py \
        tests/test_maintainer_grade_features.py

  It reported `151 passed`.
- An initial confined full-suite replay was deliberately rejected as evidence:
  `2021 passed, 4 skipped, 12 errors`. All twelve errors were `gpg-agent` startup
  failures in the GPG-pinning fixtures, and three of the four skips were Unix-socket
  binds denied by the same sandbox. The identical `make check` outside that confinement
  completed with Ruff clean, mypy clean across 262 source files,
  `2036 passed, 1 skipped`, ShellCheck clean and the maintainer-script payload gate
  reporting no problem. That replay proved the environment and was not retained as the
  final code verdict: the subsequent adversarial review found the control-field,
  stable-error-detail and review-promotion gaps above, which were then corrected and
  retested rather than waived.
- After the first corrections, `make check` completed with Ruff clean, mypy clean over 262
  source files, `2060 passed, 1 skipped`, ShellCheck clean and no maintainer-script
  payload problem. The separately pinned
  `uvx --offline --from mypy==2.3.0 mypy --no-incremental distroforge/` replay also
  passed over the same 262 source files. The counter-review did not waive that green run:
  it then found the independent readiness second-read and direct-signing review bypasses.
  Both were closed and received their own causal falsifications.
- After those final corrections, `make check` completed with Ruff clean, mypy clean over
  262 source files, `2065 passed, 1 skipped`, ShellCheck clean and no maintainer-script
  payload problem. The pinned mypy 2.3.0 command above also passed again over the final
  262-file source state. This is the accepted M3.2a.3 source/test gate receipt; no
  failing, pre-review or sandbox-truncated run is substituted for it.
- The one full-suite environmental skip was identified before implementation as
  `tests/test_chroot.py::test_two_real_phases_leave_the_target_able_to_resolve_names`.
  It requires `unshare` with a user namespace able to mount `tmpfs`. It does not block
  this CVE policy milestone, but remains an explicit M3.2b isolation/transaction proof
  debt until executed on a runner with that capability.
- This milestone does not authenticate the database, parse `meta.updated` as a date,
  establish freshness/completeness, compare installed versions with `fixed_version`,
  cover release/architecture applicability or scan the final transitive rootfs. It is
  source, policy and hostile-fixture evidence only. The live report records package count,
  not a persisted package-set digest, so it is not a replayable product package inventory.
  No package transaction, ISO build, boot or release signing occurred; `capture_origin`
  remains `unverified-mutable-target-rootfs`, `filesystem_causality` remains `unverified`,
  and `release_ready` remains false. M3.2b remains the host-isolated witness, pre-dpkg
  ACK, real transaction and producer-delta milestone.
- The signed commit identity and cryptographic verdict necessarily exist only after this
  stanza is committed. No push, tag, pull request or `main` movement is part of this
  local milestone.
