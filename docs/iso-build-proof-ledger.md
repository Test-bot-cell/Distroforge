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
| source checkout | observed | local `develop` was based on commit `4b80b8ca5dbb3c08fe5b68c368b0b1420c256d57`; the worktree contains the open `0.3.5-17` audit |
| CI action inputs | planned | GitHub workflows still reference mutable major tags such as `actions/checkout@v4`; a CI-produced proof is not source-closed until every action is pinned to a reviewed commit SHA |
| minbase bootstrap | observed | the local golden-path log contains an executing `mmdebstrap --variant=minbase --include=apt,ca-certificates` with exit 0 |
| archive and package bytes | planned | the release gate deliberately reports `review`: no run-bound chain yet records and verifies the selected InRelease, Packages indices and every downloaded `.deb` byte |
| APT and live packages | observed | the resulting rootfs contains apt, ca-certificates, casper, kernel, GRUB and shim packages; the staged manifest contains 400 packages |
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
| reproducibility | planned | deterministic inputs are partly configurable; two independent builds have not produced and compared full artifact sets |

The existing local ISO and historical Secure Boot directory remain useful diagnostic
material. They are not v2 build evidence: neither records the current source worktree,
effective definition, toolchain binaries and full artifact chain. New reports must not
rewrite that history into a stronger claim.

## Append-only evidence-run contract

An ISO build now reserves one unique run directory before diagnosis or execution:

```text
dist/
  evidence/
    runs/<run_id>/
      commands.jsonl
      distroforge-provenance.json
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
- `distroforge.iso-build.v2`;
- `distroforge.build-run-manifest.v1`;
- `distroforge.qemu-lab.v2`;
- `distroforge.boot-proof.v2`.

Build provenance records:

- DistroForge and Python executable versions and executable digests;
- Git root, HEAD, tree, branch, commit-signature state, tracked diff digest,
  untracked-file digest inventory and combined worktree digest;
- raw definition, `project.json` and effective resolved configuration digests;
- installed tool paths, versions and executable digests;
- critical kernel, initrd, manifest, squashfs, EFI/GRUB and final ISO artifacts;
- the commands recorded before the provenance phase.

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
listed file. That proves internal consistency against the recorded local manifest; final
authentication still requires a verified signature or trusted WORM anchor.

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

1. run the complete static/unit gate on the open source tree;
2. execute a fresh minimal build with the corrected GRUB MBR and appended GPT ESP;
3. verify every append-only run file and compare staged versus ISO-extracted artifacts;
4. execute BIOS and UEFI proofs against that exact ISO through `login_prompt`;
5. execute UEFI Secure Boot and prove shim, signed GRUB, kernel and casper milestones;
6. repeat with the selected desktop and require display-manager and graphical-session
   milestones;
7. build independently a second time from pinned inputs and compare the complete
   artifact manifests;
8. sign and verify the closing manifests, or commit them and the corresponding artifacts
   to trusted WORM/content-addressed storage.

Until those rows are proved, `0.3.5-17` stays `UNRELEASED`; no tag, push or main
fast-forward is justified by this ledger.
