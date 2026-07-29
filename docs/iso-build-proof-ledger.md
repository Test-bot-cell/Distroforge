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

## State on 2026-07-29

| Milestone | State | Evidence and limit |
| --- | --- | --- |
| source checkout | observed | the audited base of this local M2.2 work is signed commit `ccf1febf361857e47b1447e04f244d79d16ae393`, also `origin/develop`; its signature verifies under primary fingerprint `93D942241BECDD422606C36C4C0D75219B5506CF`. The two authorized staging pushes advanced only `develop`, first to signed audit commit `33ddb64c4205428e4208d2ce01a37f6cefb32d8e`, then to its signed M2.1 repair. `main` and the existing release tag remained unchanged. This is source identity, not build proof. |
| CI action inputs | blocked | GitHub Actions run `30485032512` executed per-push CI for exact commit `ccf1febf…`. `packaging-static` passed the complete-history M2.1 ratchet; the other nine jobs exposed three test-environment debts: CLI planning tests depended on host ISO tools, a FIFO fixture depended on umask, and the distribution-only leg invoked an undeclared `gpg`. This is a captured source/test CI refusal, not a Golden-path or ISO-build result. |
| Golden builder commit | planned | the workflow pins a public-key file by SHA-256 and primary fingerprint, imports it into an ephemeral `GNUPGHOME`, requires `git verify-commit HEAD`, suppresses Python bytecode and removes editable-install caches before measuring the builder worktree; no post-change run has exercised that refusal rule |
| minbase bootstrap | observed | the local golden-path log contains an executing `mmdebstrap --variant=minbase --include=apt,ca-certificates` with exit 0 |
| source-ISO authentication | planned | executing remasters now require stable regular source/signature inputs, external SHA-256 and one exclusive full `VALIDSIG` signer, then extract through the witnessed source descriptor; the publication item remains `review` because signature/status/keyring evidence cannot yet be replayed offline |
| archive and package bytes | planned | the current code writes `PACKAGE-INPUTS.json` and transaction/CAS evidence, and its test fixture replays a real signed `InRelease` → `Packages` → `.deb` chain; repository policies are per-source and freshness plus the final APT argv ledger are bound, but no fresh ISO build has yet produced this closure from the distribution archive |
| package-to-rootfs causality | blocked | the package ledger closes repository metadata and exact `.deb` bytes to installed dpkg identities, not each payload byte to every final rootfs path; `filesystem_causality` is `unverified`, so publication is blocked even when input validation succeeds |
| archive trust policy | planned | the reference definition retains only signer `F6ECB3762474EDA9D21B7022871920D1991BC93C`, a SHA-256 pin for the explicit archive keyring and separate release, updates/backports and security namespaces/freshness windows; no fresh archive transaction has yet exercised them |
| APT and live packages | observed | the resulting rootfs contains apt, ca-certificates, casper, kernel, GRUB and shim packages; the staged manifest contains 400 packages |
| executed tool entrypoints | planned | the command runner hashes and opens each recognized host/wrapper/target executable and dispatches through the held `/proc/<pid>/fd/<fd>` descriptor chain; unit tests cover atomic path replacement, but no new real build log has exercised the closure |
| transitive ELF toolchain | planned | descriptor dispatch closes the selected executable file only; it does not by itself bind the ELF interpreter, dynamic libraries, loader configuration, scripts read after process start, kernel or firmware |
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
| release signature contract | planned | code requires an executed bundle to contain exactly the three detached signatures for `SHA256SUMS`, `RELEASE-GATE.json` and `RELEASE-MANIFEST.json`, verified with an externally pinned full fingerprint and sealed keyring; no bundle from this audit has yet been signed |
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
- the package-input validator still returns `filesystem_causality: unverified`: it has no
  causal ledger from each `.deb` payload object to every final rootfs path. The release
  gate therefore blocks publication rather than promoting a cryptographically valid
  input closure into a complete filesystem claim;
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
- an executed signing report is accepted only when its state is `signed`, its mode is
  `execute`, its signed set and actual `.asc` files are exactly the three required
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
      apt/
        transactions/*.json
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
  ISO-BUILD.json                    # atomic alias to the latest execution
  ISO-BUILD.plan.json               # atomic alias to the latest plan
  distroforge-provenance.json       # atomic alias to executed build provenance
```

The application creates files inside a run exclusively and refuses a repeated run ID.
This is an append-only application contract, not a cryptographic or filesystem immutability
property. A local account with write access can still alter or delete the directory and
recompute an unsigned manifest and sidecar. Aliases are replaceable pointers and are never
the authority. In particular, a dry-run writes `ISO-BUILD.plan.json` and cannot replace
`ISO-BUILD.json`.

The current schemas are:

- `distroforge.evidence-run.v1`;
- `distroforge.provenance.v2`;
- `distroforge.package-inputs.v1`;
- `distroforge.package-input-transaction.v1`;
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
- the run-bound package-input aggregate and transactions when executing a sealed build;
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

1. the schema is `distroforge.qemu-lab.v2`, with a non-empty, unique run ID;
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
9. the VM has stopped before the final serial scan and artifact digests are calculated.

The generic marker `Reached target` is rejected because it does not identify a boot
milestone. A structural `iso-scan` may produce a ready structural report, but it does not
satisfy the runtime release gate.

`boot-proof.json` additionally binds the QEMU report digest, proof run ID, build run ID
when available, final ISO digest and reached milestone. A newer blocked executed proof
takes precedence over any older QEMU report.

## Provenance and publication rules

The release gate does not accept file presence as evidence. It validates the provenance
schema, requires `attestation_kind: build`, matches the ISO digest, checks the append-only
application run report and manifest, verifies the manifest sidecar and re-hashes every
listed file. It also locates `PACKAGE-INPUTS.json` through the provenance run ID and
replays its archive/package closure against the effective build definition's external
source mode, per-source policies, signer fingerprints, keyring SHA-256, run instant and
final command ledger. The authoritative product path separately extracts the SquashFS
from the descriptor-held final ISO, unpacks it and compares its semantic tree with
`ROOTFS-MANIFEST.json`. That proves internal consistency against the recorded local
manifest; final authentication still requires a verified signature or trusted WORM anchor,
and package-to-rootfs filesystem causality remains blocking debt.

`beginner-iso --repair-release-artifacts` may derive checksums and explanatory files from
an existing ISO. Any provenance it creates is labelled
`attestation_kind: reconstructed`, which is blocked for publication. A matching real
build provenance file is preserved rather than overwritten.

The publish bundle includes `ISO-BUILD.json` and every referenced build, QEMU and
boot-proof run directory. Every path component from the output root through `evidence`,
`runs` and the run itself is checked; a file, directory or ancestor symlink is refused
before copy, and a symlinked bundle destination is refused before its first write. The
copier preserves rather than dereferences a link that appears during the copy, then
refuses the result. Release signing manifests recurse through accepted directories so the
command logs, runtime output, firmware copies and proof files are covered rather than
merely copied.

## Next executing milestones

No existing artifact can be retrofitted into v2 proof. The next acceptable journey is:

1. push the signed local M2.2 test-environment repair only after explicit authorization,
   then record its remote CI verdict. M2.1 already preserved the exact
   `(33ddb64c4205428e4208d2ce01a37f6cefb32d8e, audit: harden ISO build evidence
   chain)` pair while keeping every other `audit:` subject rejected; run `30485032512`
   proved that complete-history ratchet green and exposed the next portability debts;
2. implement and test the missing `.deb` payload-to-final-rootfs causal ledger, so the
   package item can become publication-ready for evidence rather than by assertion;
3. seal the source-ISO detached signature, verification status and exact keyring for
   offline release-gate replay, or keep ISO-remaster publication explicitly at `review`;
4. execute a fresh minimal build with the externally pinned archive trust policy, package
   transaction closure, corrected GRUB MBR and appended GPT ESP;
5. replay the semantic rootfs manifest from that exact final ISO and verify every
   append-only run file and intermediate identity;
6. review the executed command identities and explicitly account for the still-open
   transitive ELF loader/library boundary;
7. execute BIOS and UEFI proofs against that exact ISO through `login_prompt`;
8. execute UEFI Secure Boot and prove shim, signed GRUB, kernel and casper milestones;
9. repeat with the selected desktop and require display-manager and graphical-session
   milestones;
10. build independently a second time from pinned inputs and compare the complete
   artifact manifests;
11. sign and verify the closing manifests, or commit them and the corresponding artifacts
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
  results; the remote M2.2 verdict does not exist until an explicitly authorized push.
