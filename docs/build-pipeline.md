# Build Pipeline

Use `distroforge iso-doctor PROJECT` when the immediate question is why an ISO has not
been produced yet. It checks source selection, host tools, the output ISO target and the
current build posture, then returns one next command.

Use `distroforge iso-build PROJECT --execute --boot-proof auto` for the guarded
one-command ISO path. Without `--execute`, it remains a dry-run and writes
`dist/ISO-BUILD.plan.json`; it never replaces the latest executed
`dist/ISO-BUILD.json`.

Executed ISO builds are marked `built` only when the configured output ISO exists, is
non-empty, and has a recorded SHA-256 digest. A completed build attempt without that
artifact stays `blocked`; dry-runs stay `planned`.

Use `distroforge iso-accept PROJECT --iso dist/NAME-VERSION.iso` after a real build to get the
publication verdict. It accepts only an ISO that matches the digest-linked executed
`ISO-BUILD.json`, has exact-ISO QEMU runtime proof through `login_prompt`, and passes the
release gate; otherwise it writes `ISO-ACCEPTANCE.json` with the next command to run.

Use `distroforge demo-iso PROJECT --execute` to create or reuse a minimal skeleton
project and try the shortest local ISO path on the current host. Without `--execute`, it
writes `DEMO-ISO.json` as a dry-run guide; with `--execute`, it runs doctor, ISO build,
boot proof, and acceptance when host tools allow it.

Use `distroforge iso-toolchain` when `iso-doctor` or `demo-iso` reports missing host
tools. It checks only the ISO build toolchain and prints one apt command; `--install`
runs that installation explicitly.

The build pipeline is ordered to fail early, keep dry-runs useful, and leave auditable
artifacts at the end.

The final ISO is a host artifact. CLI users can pass `--output-iso`; GUI users select the
same path from **Advanced Modules** with **Output ISO**, including a host save-file chooser.
When unset, DistroForge falls back to the project output defaults.

The canonical default ISO name is `dist/{name}-{version}.iso`, where `name` is the project
name and `version` the target release version. It is the only accepted form: the builder
produces it, preflight and the dry-run report expect it, and every downstream review
command resolves it through the single helper `default_output_iso(project)` in
`core/artifact_paths.py`. No unversioned `dist/{name}.iso` fallback exists; a new consumer
must call that helper rather than rebuild the path. Pass `--iso` explicitly only when the
ISO does not sit at that default path.

### The command log

Every command a build runs is recorded, one JSON object per line, and the path is resolved
through a single helper for the same reason the ISO name is: `default_command_log(project,
entry_point)` in `core/artifact_paths.py`. `distroforge build` writes
`logs/build.jsonl`, `distroforge iso-build` writes `logs/iso-build.jsonl`, and the two are
kept apart because appending two different runs into one file interleaves them into
something no one can read. Successive runs of the same entry point do append, which is what
a reader of a scheduled job wants. Override with `--log-file` on either command; in the GUI
the **JSONL log file** field on **Advanced Modules** does the same, and leaving it blank
means the default rather than no log.

Each line carries the command, its argv, its working directory, whether it needed root,
its exit status, and a tail of what it printed on stdout and on stderr — for every command,
not only the ones that failed. That last part was the fix for a specific hole: a build tool
exiting 0 is a claim about the tool, and when the first real golden-path run had a bootstrap
exit 0 after 23 seconds leaving a tree with no `apt-get`, the tool's explanation was
discarded, because a command's own words reached a human only through the exception raised
for a *failing* command. The tail is capped per stream and says how many characters it
dropped, so a short record cannot be mistaken for a quiet tool.

What is never recorded is stdin: the log keeps a boolean saying whether there was any. That
is where a passphrase would be.

### Executable dispatch identity

For a real sealed build, recording the command string is not enough. `CommandRunner`
resolves the outer executable and the recognized `sudo`/`chroot`/`env`/nspawn target
chain, opens each file, records its path, device, inode, size and SHA-256, and keeps those
descriptors open through the child process. The outer process is dispatched with
`Popen(executable=/proc/<parent-pid>/fd/<fd>)`; nested wrapper-selected executables are
rewritten at their argv position to the corresponding descriptor path. The original
`argv[0]` remains in the recorded command.

The evidence contains `dispatch_bound`, `dispatch_argv`, `dispatch_executable` and one
`dispatch_bindings` entry per recognized executable. Dispatch is refused before the child
runs when that complete chain cannot be bound. After the child exits, the runner re-hashes
the held descriptors and re-resolves the paths; the release gate requires the
pre-dispatch, binding and post-dispatch identities to agree. This prevents an atomic path
replacement from selecting different entrypoint bytes after they were measured.

This boundary is precise and intentionally not described as a complete toolchain closure.
An ELF entrypoint can still select an interpreter and dynamically loaded libraries after
dispatch. The current record does not independently bind that loader, every shared
library, loader configuration, kernel or firmware. Closing that transitive runtime graph
remains evidence debt for the toolchain milestone.

Build options are governed by `commands/build_contracts.py`. Each option is assigned to
Beginner, Power user, Maintainer, or Developer level, plus an expected GUI surface. The
contract is tested against the parser and GUI so the build cycle remains explicit instead
of accumulating hidden flags.

Release review is exposed separately from build execution:

```bash
distroforge artifact-paths /path/to/project
distroforge release-readiness --iso /path/to/image.iso --output-dir /path/to/output
distroforge qemu-smoke-plan --iso /path/to/image.iso
```

The GUI **Artifacts** page presents the same host paths, release readiness summary, and
QEMU online/offline install smoke matrix.

1. Resolve the source starter: skeleton, official ISO/netboot, local ISO, or previous project.
2. Validate project, host, and option contracts.
3. Check source trust metadata, consistency, safety policy, and release compatibility.
   An executing ISO remaster requires a regular, non-symlink source ISO, an externally
   supplied full SHA-256, a regular detached signature and one full 40- or 64-hex signer
   fingerprint. GPG's `VALIDSIG` status must name that signer exclusively, and the source,
   signature and ancestor identities must remain stable across verification. Extraction
   then reads the source through a held descriptor whose bytes match the trusted opening
   digest. This is a strict execution boundary, not yet a publication proof: because the
   signature, verification status and exact keyring bytes are not sealed for independent
   offline replay, the release gate reports source-ISO trust as `review`.
   Execution writes `dist/compatibility-report.txt` in the project output directory;
   dry-runs record the same report as a virtual command event.
4. Plan a transaction id, import legacy scripts and preview the requested diff.
5. Prepare workspace and source rootfs by skeleton bootstrap or ISO extraction.
   Locked rootfs boot artifacts are copied into `casper/` through the configured
   privilege helper so root-owned or `0600` kernel files do not break execution.
   Existing bootstrap rootfs directories are reused on retry **only when they were built
   from the base this build wants**; non-empty incomplete rootfs directories stop with a
   cleanup message instead of rerunning debootstrap into stale files. See
   [Reusing a bootstrap rootfs](#reusing-a-bootstrap-rootfs) for what "the same base"
   means and what it deliberately does not cover.
   Cross-architecture bootstrap is supported through `--bootstrap-arch`. When the target
   arch differs from the host, the build requires `qemu-user-static` so foreign binaries
   run during debootstrap; non-BIOS arches such as arm64 skip the El Torito BIOS image.
   The bootstrap tool is passed `--include=apt,ca-certificates`, because mmdebstrap's
   `minbase` does not promise apt and a minimal rootfs has no CA store. Without the latter
   the first
   *in-chroot* `apt-get update` fails TLS verification against every index — while
   `ca-certificates` sits in the very package list that update is fetching for. The
   bootstrap tool itself fetches from the host, with the host's CA store, so it can
   install the store the chroot needs one step later.
   The repack excludes the *contents* of `proc/`, `sys/`, `run/` and `dev/` and refuses
   to run at all while anything is still mounted under the rootfs. Both matter for the
   same reason: `chroot.py` unmounts the runtime binds in a `finally` with
   `check=False`, so a failed unmount says nothing, and on the first real from-scratch
   build `/proc` alone survived while the other four detached. mksquashfs then walked
   into `/proc/kcore` — apparent size 128 TiB — and turned a 2.0 GB rootfs into 5.7 GB
   of squashfs in thirty minutes, still growing. The mount points themselves are kept:
   a live system needs them to mount onto.
   Which compressor the repack uses is a build option, `--squashfs-compression`, empty
   meaning the release default (`xz` for every release shipped here). Only compressors
   a kernel can mount are offered. mksquashfs also writes `lzma`, which its own man page
   marks *deprecated - no kernel support* — the squashfs driver has an XZ decompressor
   and no raw-LZMA one — so an lzma image packs, checksums, passes every artifact gate,
   ships, and then fails to mount on the machine it was built for.
   `validate_squashfs_options` refuses it before the build starts rather than after its
   last heavy phase, and a data test keeps the release table itself inside the mountable
   set.
   Measured on the 2.6 GB `minbase` rootfs of a real from-scratch build — four cores,
   warm page cache, the product's own argv, compressor read back out of the superblock
   rather than trusted from the flags:

   | compressor | wall | CPU | image | against the default |
   | --- | --- | --- | --- | --- |
   | `lz4` | 3.9 s | 7 s | 1657 MiB | 24× faster, 14.8% larger |
   | `gzip` | 28.8 s | 104 s | 1499 MiB | 3.2× faster, 3.8% larger |
   | `zstd` | 37.1 s | 129 s | 1466 MiB | 2.5× faster, 1.5% larger |
   | `xz` (release default) | 93.4 s | 308 s | 1443 MiB | — |

   Wall clock repeats to about ±8% on this host; the image sizes are byte-identical
   between runs. `xz` remains the default because a derivative should stay comparable
   with the upstream image it descends from, but the fast rows are the point: iterating
   on a build does not have to pay ninety seconds a lap.
   Nothing beyond the compressor is passed — no block size, no dictionary size, no BCJ
   filter, no compression level — and that is measured rather than assumed:

   | rejected tuning | wall | image |
   | --- | --- | --- |
   | `xz -b 1M -Xdict-size 100%` | 125 s (+34%) | 1412 MiB (−2.2%) |
   | …and `-Xbcj x86` on top | 244 s (+161%) | 1406 MiB (−2.6%) |
   | `zstd -Xcompression-level 19 -b 1M` | 100 s | 1429 MiB |

   A live rootfs is mostly already-compressed payload — kernel modules and firmware
   ship as `.zst` — so a wider window and an instruction filter have little left to
   find, and tripling the repack for half a percent is what the velocity contract
   exists to prevent. Compression levels are left to the tool for every compressor
   alike; pinning one and not the others would freeze an arbitrary choice against
   future upstream improvement. (`-comp zstd` and `-comp zstd -Xcompression-level 15`
   produce byte-identical images here, so 15 is indeed today's default.)
   One measured result is deliberately **not** acted on: `zstd -b 1M` is a strict
   build-time win, 23–25 s instead of 37 s *and* 10 MiB smaller. Block size is not only
   a build-time knob, though — it also sets how much the live system must decompress to
   serve one small read — and that runtime cost has not been measured here. A 32% faster
   repack is not worth an unmeasured change to every boot of the delivered image.
   `-e` stays last in the argv, always. mksquashfs reads every remaining word after it
   as an exclude pattern, so a flag appended after the list is swallowed in silence: the
   pack falls back to the default compressor, writes a valid image and exits 0. That is
   not hypothetical — it is how the first version of the benchmark above measured plain
   gzip four times over, to the identical byte, while believing it was comparing
   compressors. A test pins the invariant.
   Every in-chroot `apt-get update` goes through one `APT_UPDATE_ARGV` carrying
   `APT::Update::Error-Mode=any`, because **apt returns 0 when every index failed to
   download** — it demotes the failure to "Some index files failed to download. They
   have been ignored". Measured against apt 3.2.0: rc 0 without the option, rc 100 with
   it. Without it the TLS failure above was invisible, and the build died three phases
   later on "Unable to locate package sudo", naming the packages instead of the fetch
   that never happened.
   GUI builds use `sudo` by default. When no terminal is attached, DistroForge uses
   graphical `sudo -A` if an askpass helper such as `ssh-askpass-gnome` is available;
   otherwise preflight stops before the first privileged command with setup guidance.
   `pkexec` remains an advanced opt-in backend because long builds may trigger repeated
   polkit prompts or dismissed authorization requests.
   When `pkexec` is selected, helper commands are resolved to absolute paths such as
   `/usr/bin/install` before polkit authorization.
6. Configure APT, cache, PPAs, release track, and system sync.
   Files written inside the extracted rootfs use the shared `FileSystemOps` layer. This
   includes `etc/apt/sources.list`, deb822 mirror files, PPA source lists, release-track
   pins, apt proxy/cache snippets, and post-install sync helpers. Direct Python writes are
   reserved for host artifacts, not rootfs state.
   Each managed overlay is rewritten as a pure function of the current options: the release
   track, apt cache, apt proxy and PPA services shed their own previously written files before
   (re)writing, so a reused rootfs or unsquashed ISO tree cannot inherit a dropped option's
   config — a removed PPA, a disabled cache, or a stale `APT::Default-Release "devel"` pin can
   no longer resurrect to fail the next build. On bootstrap reuse the rootfs additionally sheds
   every DistroForge apt overlay before the live-base install runs apt.
   The chroot runtime that hosts these phases is hardened on entry: each `/dev`, `/dev/pts`,
   `/proc` and `/sys` bind mount is detached with `mount --make-rslave` so a later
   unmount cannot leak into the host mount namespace, and a `policy-rc.d` that exits 101
   stops package postinst from starting daemons against a chroot with no real init. APT runs
   with `DEBIAN_FRONTEND=noninteractive` so debconf never blocks on a prompt. The block is
   removed and the binds are lazily unmounted on exit, so `policy-rc.d` never ships in the
   image.
   **`/run` is not among those binds, and that is the point.** It used to be, and the host's
   `/run` holds the control sockets of the host's own daemons — `/run/snapd.socket`,
   `/run/systemd/private`, `/run/dbus/system_bus_socket`, `/run/udev/control` — so binding it
   handed every maintainer script in the target root a way to command the *build machine* as
   root. `policy-rc.d` closes only the well-behaved route: measured on an Ubuntu 26.04
   desktop, the postinst or postrm of `udev`, `dbus`, `snapd`, `polkitd`, `accountsservice`
   and `networkd-dispatcher` each call `systemctl --system daemon-reload` or
   `systemctl try-restart` **directly**, outside `invoke-rc.d`. A minbase bootstrap runs few
   such scripts; a desktop seed runs hundreds. The risk was not hypothetical either — snaps
   installed from a chroot phase were found landing in the build host's own
   `/var/lib/snapd`, which is why that phase is refused outright. The target now gets a
   tmpfs of its own on `<root>/run`, private and unmounted with the rest, which is what a
   chroot's `/run` should be. It is mounted `mode=0755,nosuid,nodev,noexec,size=10%` — the
   options this machine's own `/run` carries — because a bare `mount -t tmpfs` comes up 1777
   with suid, dev and exec permitted and no size cap, which would have widened exactly what
   a private `/run` is for.

   **A private `/run` is volatile, and two things in the target depended on it surviving.**
   Both are repaired when the mount goes up, and only ever inside that mount:
   - **The resolver.** `systemd-resolved`'s postinst — which every desktop seed installs —
     moves `/etc/resolv.conf` aside and replaces it with a symlink to
     `../run/systemd/resolve/stub-resolv.conf`, copying the working content there on the way.
     That copy dies with the phase that made it, and the next phase mounts a fresh empty
     tmpfs under a symlink that now dangles: `apt-get update` fails with
     `Temporary failure resolving`. This was measured, not deduced — a from-scratch desktop
     build died exactly there. So each phase reseeds the resolver, but only when
     `/etc/resolv.conf` leads (through however many links, and reading absolute targets as
     `<root>`-relative the way the chroot's own kernel does) into the private `/run`. A
     resolver on the persistent rootfs is left alone: nothing here broke it, and writing to
     `/etc` would ship this machine's DNS in the image. Only `nameserver` lines are copied,
     never the build machine's search domain. When no seed is written the reason is recorded
     as a `resolver-seed-skip` step, so a phase can never start without a resolver *and*
     without a trace of why.
   - **`/run/lock`.** `base-files.postinst` creates it during the bootstrap and Debian Policy
     makes `/var/lock` a symlink to it, so mounting over `/run` left `/var/lock` dangling
     from the second phase onward and any `flock()` under it failing with `ENOENT`. The mount
     restores it, mode 1777.

   The image itself carries neither: the tmpfs is discarded and `run/*` is excluded from the
   squashfs, so nothing seeded for a build phase can reach whoever boots the ISO. What did
   reach it is the copy the postinst leaves behind on the *persistent* rootfs at
   `/etc/.resolv.conf.systemd-resolved.bak` — this machine's nameserver and search domain,
   picked up by the squashfs, read by nothing in the image, and different between two builds
   of one definition on two machines. The sanitize phase deletes it, whatever the sanitize
   options say: keeping the build machine's DNS out of a delivered image is not a preference.

   Executing builds also install a DPkg pre-install hook before post-bootstrap package
   changes. Before APT cleanup can remove the evidence, the hook seals the effective source
   and APT configuration, explicit keyrings, signed Release metadata, the active `Packages`
   indices and every downloaded `.deb` into a run-scoped content-addressed store. A bootstrap
   is captured separately because it runs before an in-root hook can exist. Its externally
   pinned archive keyring is re-hashed, copied into the run CAS and consumed from that sealed
   path by mmdebstrap/debootstrap.

   `PACKAGE-INPUTS.json` references immutable transaction records rather than asserting a
   free-standing green flag. Each configured repository namespace independently pins its
   base URI, suites/codenames, components, architectures, signer fingerprints, keyring
   digests and Release freshness window. The run instant is the provenance verification
   time, and a digest of every APT-affecting argv is recomputed from the complete final
   `commands.jsonl`, so a later unrecorded trust override or package transaction cannot
   hide behind an earlier aggregate. Its offline validator:

   - re-hashes every referenced byte and rejects symlinks, path escapes, duplicate
     transaction identities and CAS collisions;
   - verifies `InRelease` or `Release.gpg` with captured explicit keyrings in an isolated
     `gpgv` home and accepts only full signer fingerprints supplied again by the effective
     build policy;
   - binds each `Packages` index digest and size to the signed Release, then each `.deb`
     digest, size and internal package/version/architecture to its safe `Packages`
     `Filename` stanza;
   - reconciles the final dpkg inventory. A fresh bootstrap has no baseline exemption and
     every bootstrap package needs captured `.deb` bytes; an ISO remaster may exempt only
     the exact inventory captured before mutation;
   - enforces the signed Release `Date`, optional `Valid-Until`, configured maximum age
     and future-skew limits at that bound run instant;
   - refuses insecure APT trust/date overrides, conflicting bytes for one package identity,
     missing final repository state and locally built `.deb` files without a separate
     producer attestation.

   Source mode, allowed signer fingerprints and bootstrap keyring SHA-256 are external
   verifier inputs. Copying different values into the evidence payload cannot redefine
   trust. The release gate replays this chain from the provenance run ID.

   M3.2a then writes `PACKAGE-APT-ACTIONS.json`, schema
   `distroforge.package-apt-actions.v1`, before rootfs evidence and repacking. The
   generated fragment requests `DPkg::Pre-Install-Pkgs` protocol version 3 on InfoFD 0,
   and the shell hook refuses a missing `APT_HOOK_INFO_FD` confirmation. Its parser
   implements the configuration framing and nine-field version-3 action format described
   by [apt.conf(5)](https://manpages.debian.org/testing/apt/apt.conf.5.en.html), with the
   encoding and emission behavior checked against APT's
   [`dpkgpm.cc`](https://sources.debian.org/src/apt/3.3.1/apt-pkg/deb/dpkgpm.cc/) and
   [`strutl.cc`](https://sources.debian.org/src/apt/3.3.1/apt-pkg/contrib/strutl.cc/).
   Those references establish the accepted wire format; no test in this lot observed a
   transcript produced by a real APT transaction.

   The hook stages the supplied raw transcript, journal, recorder, APT configuration and
   input CAS below `/var/lib/distroforge/package-evidence` in the target rootfs. It
   records a pre interval and a post closure marker, but that marker does not prove that
   dpkg succeeded. More importantly, all of those bytes remain mutable target-rootfs state
   until the host collector copies them into the run directory. Re-hashing that copy,
   matching the recorder/configuration bytes and binding every unpack action exactly to
   one sealed `.deb` package/version/architecture record can prove only that the supplied
   evidence is internally self-consistent; it cannot authenticate APT as its producer.

   The resulting receipt therefore uses `apt_actions: self-consistent` for a non-empty
   replay or `apt_actions: not-observed` when there is no post-bootstrap APT capture, and
   always records `capture_origin: unverified-mutable-target-rootfs`,
   `filesystem_causality: unverified` and `release_ready: false`. Per-stream, aggregate,
   line, configuration, action, transaction, blob, path, journal and report limits are
   enforced before the next parse or allocation. A local controlled-root test really
   executes the generated shell pre/post state machine with synthetic protocol input and
   controlled `apt-config`/`apt-get` helpers; it exercises InfoFD, overlap and oversize
   refusals without running an apt/apt-get transaction or dpkg. M3.2b must instead give a
   host-isolated one-shot witness the first write and require its acknowledgement before
   dpkg can run.

   M3.1 writes `PACKAGE-FILESYSTEM-CAUSALITY.json`, schema
   `distroforge.package-filesystem-causality.v1`, before the rootfs is repacked. Its
   authoritative bootstrap validator does not trust the recorded result: it re-hashes and
   re-extracts the exact `.deb` files named by the sealed
   `PACKAGE-INPUTS.final_inventory` snapshot, reloads `ROOTFS-MANIFEST.json` and recomputes
   one static classification map. The closed vocabulary is:

   - `exact`: one package payload object and the final manifest object are identical;
   - `modified`: a package payload path remains, but its final object differs;
   - `missing`: a package payload path is absent from the final manifest;
   - `unattributed`: a final manifest object has no candidate package payload;
   - `ambiguous`: more than one package payload claims the same path;
   - `structural`: a mergeable directory cannot be attributed to one package uniquely;
   - `excluded`: the payload path is outside the manifest scope, including descendants of
     `dev`, `proc`, `run` and `sys`; a captured package absent from the inventory is instead
     recorded once at package level as `excluded-not-final-inventory`, without invented
     path classifications;
   - `unsupported`: an ISO baseline or tar/rootfs object type has no safe M3.1
     representation.

   In ISO-remaster mode M3.1 stops earlier. It binds the package aggregate and final
   manifest but, without a semantic source-ISO baseline, does not inspect the remaster
   payload blobs; every manifest entry is `unsupported` and `payload_identity` is
   `partial`. The package-input validator separately keeps those captured `.deb` bytes
   fail-closed.

   The map is not an authentication oracle. Its recorded scope is
   `sealed-recorded-deb-direct-payload-to-final-rootfs-m3.1`, with an explicit assurance
   dependency on the independently replayed `PACKAGE-INPUTS` signature, freshness and
   source-policy proof. The release gate evaluates that proof first. M3.1 then anchors one
   descriptor to the physical run directory, descends every artifact path component with
   no-follow descriptor-relative opens, rechecks every leaf at the closing boundary and
   creates the report exactly once through the held descriptor. Run, transaction and
   rootfs paths are byte/depth bounded before parsing and must already be canonical. The
   parser enforces incremental JSON, package-summary, classification, member, logical
   payload, raw-tar, physical-header, extension-chain, PAX and command-output limits; the
   remaining aggregate allowance is applied before each next extraction or parse.
   `dpkg-deb --fsys-tarfile` must yield its documented uncompressed tar contract;
   compressed, over-nested, malformed or concurrently replaced inputs are refusals.

   Those aggregate byte/cardinality budgets are fixture-proved but not yet product-sized.
   A real desktop run that reaches one is a measured stop, not permission to raise it
   blindly. Schema v1 uses `payload_identity` for enumeration coverage while comparison
   outcomes remain the separate `modified`, `missing` and `ambiguous` counts; a future
   schema may name both axes independently.

   `payload_identity: verified` means only that a bootstrap map enumerated, canonicalized
   and bound every supported, in-scope direct payload member of that inventory snapshot.
   The snapshot is sealed before arbitrary post-host hooks; M3.1 does not re-snapshot dpkg
   state after them, so later package mutations remain unattributed M3.2b debt.
   ISO-remaster mode, an excluded path or an unsupported object makes it `partial`. Even an
   all-`exact`, `verified` result is only static identity: equality of bytes and metadata
   is not evidence that a recorded APT/dpkg action or package producer caused the final
   object. M3.1 therefore keeps `filesystem_causality: unverified`,
   `release_ready: false` and the package publication item blocked. M3.2a now checks a
   bounded supplied protocol-v3 transcript for self-consistency, but its mutable
   target-rootfs origin is explicitly unverified. M3.2b must add the host-isolated,
   pre-dpkg acknowledgement and before/after filesystem deltas tied to producers, then
   account explicitly for maintainer scripts, triggers, conffiles, alternatives,
   diversions, removals, customizers and other transformations. This is a code/fixture
   closure tested offline and rootless; no real APT transaction, dpkg operation, ISO or
   live-archive build was executed by the hardening lot.
7. Apply packages, snaps, drivers, desktop source builds, size reports, and CVE scanning.
8. Create rollback snapshots around risky phases when enabled. Snapshot archives are
   written to `work/snapshots/*.tar.zst.part` and promoted to `*.tar.zst` only after
   `tar` succeeds; creating and restoring snapshots uses the configured privilege helper
   because the rootfs may contain files that the normal user cannot read or overwrite.
9. Apply customization, branding, users, systemd, network, kiosk, OEM, kernel, and Secure Boot.
   Debranding scans identity text such as `etc/os-release`; protected rootfs files are
   rewritten through the configured privilege helper instead of direct Python writes.
   Branding, wallpaper, locale, hostname, Netplan, kiosk autostart, OEM markers,
   autoinstall, seeds, Casper metadata, and staged chroot hooks follow the same rule.
10. Run hooks/plugins, sanitize target, and produce health status. A sealed ISO build
    refuses every in-process `plugins/*/plugin.py`: importing arbitrary Python would execute
    code outside the command identity/provenance boundary. Executable
    `plugins/*/<phase>.*` scripts remain supported and run through `CommandRunner`, so the
    executable file is descriptor-bound and recorded. Installing Pluggy does not weaken
    this rule.
11. Generate autoinstall, seeds, metadata, squashfs, checksums, and ISO. Before packing,
    `ROOTFS-MANIFEST.json` records the portable semantic tree and a host-specific
    device/inode/time guard. The rootfs is rescanned after `mksquashfs`; that exact
    SquashFS is held open, unpacked into a fresh tree and compared with the manifest.
    `ISO-ASSEMBLY.json` then binds the witnessed staged SquashFS to the exact member
    extracted from the final ISO. An authoritative release-gate refresh independently
    opens the published ISO, extracts that member through its descriptor, opens and
    unpacks the member through another descriptor, and compares the replayed semantic
    tree field-for-field with `ROOTFS-MANIFEST.json`. These paths are implemented and
    covered by round-trip and falsification tests; no new real build has yet emitted and
    replayed this evidence.
12. Produce release artifacts, boot checks, screenshots, provenance, HTML report, and QA matrix.

Dry-run builds should produce command history and findings only. The dry-run report checks
validation, required host tools, source trust, policy, dirty artifact directories, bootstrap
rootfs reuse/incompleteness, locked boot artifacts and privilege-helper intent. If a service
needs to write during dry-run, that write should be represented as a `CommandSpec` such as
`write-file` instead.

Before execution, `distroforge readiness` should be clean enough for the selected mode:
source SHA/GPG state, host tools, policy findings, transaction paths, timeline and diff
preview must all be reviewable without producing package artifacts.

An executing CLI path is fail-closed: a failed build or a blocked executed report exits
with status 2 after writing the available failure evidence. Dry-run and plan modes remain
status 0 because their product is the report, not an ISO. Release commands follow the same
distinction; a blocked `release-gate`, publish bundle, verification or release pipeline is
propagated to the top-level CLI instead of being printed behind a successful process
status, while `sign-release` keeps its non-mutating plan non-failing and fails only a
blocked `--execute` signing attempt.

Source starters are a first-level product entry. Ubuntu 26.04 and Debian 13.5 both expose
minimal skeleton starters for CLI-only seed images, plus official ISO/netboot choices whose
download and checksum locations are visible before injection into a project. Local ISO and
previous-project starters keep the selected path in `project.json` so the source is never
hidden in an advanced build option.

The QEMU lab is the virtualization gate for build confidence. It runs QEMU under QMP
control, writes a serial log, optional screenshot, pid file, QMP socket path, artifact
checksums, and a `qemu-lab-report.json` summary. UEFI uses a writable OVMF variables
copy, TPM mode starts `swtpm`, and success markers are checked from the serial log before
release artifacts are trusted. That check is recorded **once the marker is really there**,
not on the way in: emitted first, it wrote `prebuild-vm-assert-log … rc=0` into the build
journal before the wait had read a byte, so a run that never booted left a log whose last
word was a green assertion — in the one file a maintainer opens to find out which step
failed. A dry run still plans the line, where it is the step rather than its result.

Every QEMU command line — the lab, the boot screenshot, the interactive preview, the
install smoke matrix, the boot-check and the QA matrix — is built from one canonical
`QemuInvocation` in `core/qemu_invocation.py`, so the argv stays auditable and consistent
instead of drifting across call sites.

### Hardware acceleration

Every automated launch ran under TCG, QEMU's interpreter, on hosts with a perfectly
usable `/dev/kvm`: the flag was reachable only from the interactive preview, so the lab,
the boot-check, the QA matrix and the screenshot capture each spent their timeout budget
on emulation without ever asking. They now ask, through one probe — `kvm_is_usable()`
beside `default_ovmf_code` — and it asks the question that matters. `/dev/kvm` on this
build machine is `root:clock` mode 0660 with a POSIX ACL granting the developer rw, so
neither the owning group nor the caller's group list answers it; `access(2)` does, ACLs
included. The check it replaces in the preview, `Path("/dev/kvm").exists() or
has_binary("kvm")`, answered a different question twice: a device node can exist and
still refuse to open, and the `kvm` wrapper is installed by `qemu-system-x86` on hosts
with no virtualisation at all. A host with no usable device simply keeps emulating, which
is also why the interaction lab no longer dies inside QEMU on `Could not access KVM kernel
module` when its default-on option meets such a host.

That sentence used to name every GitHub runner as an example of a host with no device.
The first real run of the weekly golden path measured `crw-rw---- 1 root kvm 10, 232` on
a GitHub runner, so the example was wrong; the rule it illustrated is unchanged, and the
answer there is now whatever `access(2)` says on the day.

Measured 2026-07-27, booting one desktop kernel and its 88 MB initramfs from the same
media under the lab's own defaults: **7.5 s** to the end of the initramfs emulated
against **4.5 s** accelerated, and the Secure Boot firmware emitting the same 217 bytes
either way, so acceleration changes the speed of a run and not its shape. `-cpu host`
was measured too and is deliberately **not** passed: it bought nothing here (5.0 s), and
leaving it out keeps the guest CPU model identical with and without acceleration. This is
a historical performance observation whose source, effective definition, toolchain and
exact ISO chain was not preserved. It is not a current desktop or Secure Boot proof. Nor
does it establish the folklore that a desktop `graphical.target` is unreachable under
emulation — that needs a full ISO and has not been run.

`qemu-lab-report.json` records the answer as `accelerated`. Two runs of the same command
on the same ISO differ by more than half their wall-clock depending on it, and until it
was written down a reader could not tell which of the two they were holding, nor whether
a run that exhausted its timeout had been emulating the whole way. The one launch site
that stays unaccelerated is the install smoke *planner*: it emits command lines into a
report for someone to run later, possibly on another machine, and baking the planning
host's acceleration into a published plan would describe a run nobody performed.
`tests/test_qemu_invocation.py` walks the package for `QemuInvocation(` calls, so a
seventh launch site cannot quietly go back to emulating.

### Which UEFI firmware a run uses

The firmware images are **detected, not hardcoded**. `--prebuild-vm-ovmf-code` and
`--prebuild-vm-ovmf-vars` (and the matching GUI fields, which show the detected path as
placeholder text) default to empty, meaning "use what is installed"; `default_ovmf_code`
and `default_ovmf_vars` in `core/qemu_invocation.py` are the single answer, called by
every option surface the way `package_artifact_dir` is.

This is not a refactor for tidiness. `/usr/share/OVMF/OVMF_CODE.fd` was the default in
nine places and has not been shipped since the firmware was rebuilt at a 4 MB flash size,
so on any current Debian or Ubuntu **every UEFI launch in the product failed on a missing
file** — a path no test covered, because `validate_prebuild_vm_options` had no test at
all. The detection prefers the `_4M` names and keeps the historical ones as fallbacks for
an older host.

Secure Boot is a property of the firmware *pair*, not of the `-global … secure=on` flag:
only the `.secboot` code build enforces it, and only the `.ms` variable store carries the
enrolled Microsoft keys a signed shim chains to. `--prebuild-vm-secure-boot` therefore
resolves that pair, and validation refuses an explicitly named pair that cannot enforce
Secure Boot rather than substituting one silently — a VM reporting Secure Boot while
running with it off is worse than not offering the option.

Secure Boot is also a property of the **machine**, and that half was missing. Both Secure
Boot descriptors in `/usr/share/qemu/firmware` declare `requires-smm` and name `pc-q35-*`
as their only target, while QEMU's default machine is `pc-i440fx-*` without SMM. Measured
on one desktop ISO with ovmf 2026.02 and QEMU 10.2.1: on the default machine the run
emitted **not one serial byte**, while the identical run under `-M q35,smm=on` reached
`getty.target` and a login prompt in about two minutes. Nothing failed in between — the
lab sat in the firmware until its timeout expired and then reported a missing serial
marker, so **the ISO took the blame for a machine that never booted it**, and every
`--prebuild-vm-secure-boot` run since the option shipped was that hang. `QemuInvocation`
now emits `-M q35,smm=on` whenever Secure Boot is on, and only then. Historical,
non-v2 runs reported BIOS, plain-UEFI and Secure-Boot observations on other media, but no
retained evidence binds those results to the current source, effective definition,
toolchain and exact ISO. They are diagnostic observations, not current proofs. The plain
firmware descriptor accepts `pc-i440fx-*`; the machine type is dictated by the firmware,
so no option surface exposes it. `tests/test_qemu_invocation.py` reads the installed
descriptors and checks the constant against them, so an ovmf upload that moves Secure
Boot to another machine turns a test red instead of turning every run back into a silent
half-hour hang.

`distroforge boot-proof` chooses its own firmware: `--firmware bios|uefi` and
`--secure-boot`. Omitting `--firmware` keeps whatever the project or its definition already
says, so the flag is only needed to change that answer — the same precedence as
`--squashfs-compression`. Both land on the project's prebuild-VM options, which is why the
same validation applies: Secure Boot on BIOS, an OVMF image that is not installed, and a
firmware pair that cannot enforce Secure Boot are all **refused before QEMU starts**, and
they report under the `prebuild-vm-*` codes because that is the option group holding the
setting. The report names the firmware that ran (`Firmware: uefi with Secure Boot`, and the
same two fields in `boot-proof.json`) because on a BIOS host a `ready` without that word is
unreadable: a BIOS result establishes BIOS only and says nothing about UEFI. The exact
rebuilt ISO still requires digest-linked v2 proofs for both firmware paths.
`--firmware` with `--backend iso-scan` boots nothing, so the report says the choice did not
apply instead of wearing a firmware it never used.

The **GUI has no second firmware control for boot proof**, deliberately. The Virtualization
Lab combo and Secure Boot checkbox are the one place that answers "which firmware", for the
prebuild VM and for the boot proof alike; the Artifacts button says so in its tooltip and
the run names the firmware in the log line. Two widgets writing one field is how
`OVMF_CODE.fd` came to be hardcoded in nine places.

**Still a gap:** the in-build `--bootcheck` smoke test has no firmware selector of its own —
`BootCheckService` builds its `QemuInvocation` without a firmware, so it is always BIOS.
Such a result covers BIOS only; it cannot establish UEFI, and the exact rebuilt ISO still
needs a digest-linked v2 BIOS proof too. Use `boot-proof --firmware uefi` or
`build --prebuild-vm --prebuild-vm-firmware uefi` for a UEFI runtime proof.

The interactive preview is the drivable, human-facing counterpart to the headless lab.
`distroforge preview PROJECT` plans the session as a dry-run and prints the exact QEMU
command; `--execute` actually launches it. `--display` selects `gtk`, `spice`, or `none`:
`spice` maps to QEMU `-display spice-app`, which starts a SPICE server and opens the
bundled viewer, so the host needs `virt-viewer`; `none` is the headless, QMP-driven mode.
Every session is daemonized with a QMP socket and a pid file so it stays drivable and
stoppable, writes a serial log, and records a JSON `preview-session.json` transcript plus a
`PREVIEW-INTEGRITY` manifest so the run is traceable. The GUI **Virtualization** page
exposes the same surface through the **Preview ISO** action and the **Preview display**
selector, and the in-build `--preview` option reuses the same service once the ISO is
assembled.

Declarative interaction plans turn a QEMU session into scenario-as-data.
`distroforge qemu-interaction PROJECT --plan PLAN` plans a headless, QMP-driven run as a
dry-run and prints the exact command plus every step; `--execute` launches it. A plan is a
typed list of steps — `wait-serial`, `wait`, `screendump`, `sendkey`, `query-status`,
`quit` — carried as JSON so it stays auditable and reproducible. `--plan` resolves a JSON
file, a built-in plan (`boot-capture`, `headless-status`), or a smoke-matrix scenario by
name; `--list` prints every available plan. The same canonical `QmpControl` drives the
headless lab, the boot screenshot, and the interaction service, so there is one QMP engine
instead of divergent copies. This is what makes the QEMU install smoke matrix executable: each smoke scenario
maps to an interaction plan that, when successfully executed, requires a login marker,
captures the screen, and shuts down. Merely defining or source-testing the plan does not
establish that milestone for the current ISO. The run records a deterministic
`qemu-interaction-report.json` and an `INTERACTION-INTEGRITY` manifest. The GUI
**Virtualization** page exposes the same surface through the **Run interaction** action
and the **Interaction plan** selector.

## Phase contracts

`BuildOrchestrator.run` drives the source-to-ISO path as ordered stages over a shared
`BuildServices` boundary: `run_preflight`, `build_services`, `acquire_source`,
`configure_repositories`, `customize_target`, and `assemble_iso`. `build_services` only
constructs the shared services and emits no user-facing phase, so it carries no contract.

Every phase over that boundary has a declarative contract in
`distroforge/core/phase_contracts.py`:

- **title** — the user-facing phase name shared with `plan()` and progress events;
- **stage** — the pipeline stage that owns the phase;
- **inputs** — what the phase consumes;
- **artifacts** — what the phase produces;
- **privileged** — whether the phase mutates protected rootfs/ISO state (the squashfs root
  or ISO tree) or otherwise needs the privilege helper when active;
- **rollback** — the snapshot points the phase creates, when any.

Render the catalog with `distroforge build-phases`; `--stage STAGE` scopes the output to a
single stage (`run_preflight`, `acquire_source`, `configure_repositories`,
`customize_target`, or `assemble_iso`). The GUI **Command Center** surfaces the same text
through **Show build phase contracts**, so the CLI and GUI read from one renderer.

Only two phases declare rollback points, matching step 8 above: `snapshot` creates
`after-apt`, `after-customize`, and `after-sanitize`, and `kernel_module` creates
`before-kernel` and `after-kernel` when a module build is enabled. The catalog is
honesty-tested against a real dry-run: every phase that touches protected rootfs/ISO state
is declared privileged, host-only phases never are, and the observed snapshots match the
declared rollback points exactly.

## Progress model

The build steps come from one canonical sequence. `build_phase_sequence` in
`core/build_sequence.py` produces the ordered `PlannedStep` list for the active
`source_mode` and `run_preview` choice. `BuildOrchestrator.plan()` returns exactly that
sequence, and `run()` emits each step through the same list: `_step` checks the emitted
phase and title against the next expected `PlannedStep` and raises on any drift. The GUI
step list is therefore the run plan — they cannot diverge into different counts, which is
why the GUI denominator no longer inflates itself with a `max()` fallback.

Progress is weighted, not counted. Each `PlannedStep` carries a relative `weight`, and the
overall fraction is completed weight over `total_weight`, not step index over step count.
Heavy phases — source extraction, package application, squashfs pack, and ISO rebuild —
dominate the bar, while light host-only steps advance it only slightly, so the bar tracks
real work instead of jumping a fixed amount per step. The GUI bar runs on a fixed 0–1000
integer scale driven by that fraction; the CLI prints the same percentage next to the
`index/total` counter and a closing `100.0%` line.

Each step opens a weight band `[band_start, band_start + band_width)`. Heavy external
commands stream their output line by line through `CommandRunner.run_streaming`, and the
per-tool parsers in `core/progress_parsers.py` turn a recognized line into a 0–1 fraction
that fills the current band through `_phase_progress`. The squashfs and xorriso shapes were
captured from the real tools (squashfs-tools 4.7.5, xorriso 1.5.6) over a pipe — the
production path — and pinned as fixtures under `tests/fixtures/progress/`. The apt fixture
is deliberately not a capture: running `apt-get install` needs root, a chroot and the
network, none of which the suite uses, so that fixture carries apt's documented
`dlstatus`/`pmstatus` protocol lines instead. Each fixture header records which of the two
it is. The shapes matter because how much a band fills in practice depends entirely on what
each tool actually emits:

- **apt** is the one heavy command that streams a true fraction. With `APT::Status-Fd=1`
  (added only when a progress callback is active in execute mode) it prints an explicit
  per-item percentage that fills the band smoothly.
- **mksquashfs / unsquashfs** print only the final `[===] N/M 100%` bar frame over a pipe
  (the live redraw is tty-gated), then emit closing statistics whose percentages are not
  progress. `squashfs_progress` reads only the bracketed bar — so those statistics cannot
  drive the bar backwards — which means the squashfs bands jump to full at completion
  rather than filling continuously.
- **xorriso** reports file and node counts (`64 files restored`), never `% done`, so the
  ISO extract and rebuild bands carry no sub-progress on this toolchain and simply complete
  at their step boundary.

Sub-progress is an execute-mode behavior: dry-runs and the no-callback path use the plain
`run()` so command history stays identical. Every parser returns `None` for anything it
does not recognize, so a future tool-format change degrades the bar to step-level
granularity rather than raising. The offline fixture tests lock these shapes against the
captured output without executing any tool, so the suite stays deterministic, network-free
and rootless under CI, buildd and autopkgtest. When the toolchain is upgraded, re-capture
the fixtures by hand (each fixture header records the tool, version and capture method) and
re-pin them — the suite never runs a heavy tool itself, by design.

## Boot record reproduction

The ISO rebuild does not guess how to make the image bootable. In execute mode it asks the
source ISO to describe its own boot setup with `xorriso -indev <source> -report_el_torito
as_mkisofs` and replays that description verbatim, overriding only the volume id, output
path and modification date. Because the report is xorriso's own faithful, round-trippable
account of the source's El Torito record, this replays the source's BIOS isolinux/GRUB,
UEFI El Torito or appended EFI System Partition tokens without DistroForge needing to
interpret them. That proves the argument-forwarding contract, not that the rebuilt media
boots. This is the Debian/xorriso-recommended remaster path and it replaces the earlier
brittle file-path guessing that silently dropped UEFI boot records on recent Ubuntu
layouts.

A generic `BootLayout.detect()` scan remains as an explicit fallback for when there is no
source ISO to interrogate (bootstrap mode) or the source reports no boot record. The probe
runs only in execute mode, so dry-run plans build nothing and their rebuild command stays
byte-identical to the detection path.

That fallback path is the one a from-scratch build takes, and it used to be half-built. The
bootstrap staged a BIOS El Torito image and nothing else, so `detect()` found no EFI image
and `xorriso` was handed no EFI tokens: an amd64 ISO booted only in BIOS/CSM mode despite
the target having `grub-efi-<arch>-bin` and `shim-signed` installed, and an arm64 ISO — where
the BIOS image is deliberately skipped as "EFI-only" — carried no boot record whatsoever
while the build exited 0. The bootstrap now stages both.

Staging the images was necessary and not sufficient: the ISO that came out still did not
boot under UEFI, and it took a real VM to find out. `--efi-boot <path>` expands to
`-eltorito-alt-boot -e <path> -no-emul-boot -eltorito-alt-boot`, and that trailing token
closes the entry — so the `-isohybrid-gpt-basdat` emitted after it had no current boot image
left to promote and wrote no GPT at all. `xorriso -report_system_area` printed an MBR and
nothing else; `fdisk` called the label `dos`. Since EDK2 carries no ISO9660 driver, the
firmware was left with an ESP it could not read, sitting as a file inside the ISO9660 tree.

The EFI System Partition is therefore appended as a GPT partition and the El Torito EFI
entry aimed at that partition — `-append_partition 2 0xef <esp> -appended_part_as_gpt` and
`-e --interval:appended_partition_2:all::` — which is the shape `grub-mkrescue` writes and
the Ubuntu images ship, and the shape `boot_args_from_report()` could already *read* long
before anything produced it. The MBR boot code is also now chosen next to the BIOS image it
chains to: `isohdpfx.bin` is ISOLINUX's and `boot_hybrid.img` is GRUB's, and the former was
picked unconditionally, so a from-scratch tree got ISOLINUX boot code spliced in front of
`boot/grub/i386-pc/eltorito.img`.

Measured on ovmf 2026.02 / QEMU 10.2.1, from one 1.35 GB reference-derivative tree:

| ISO shape | what the firmware said |
| --- | --- |
| `--efi-boot` + `-isohybrid-gpt-basdat` (as shipped) | `failed to load Boot0002 … Not Found`, then `No bootable option or device was found.` |
| appended ESP as GPT partition 2 | `BdsDxe: loading Boot0002`, then `BdsDxe: starting Boot0002` |

The second row was confirmed with a positive control on the same ESP rather than on the
firmware's word alone: with `BOOTX64.EFI` replaced by `mmx64.efi`, MokManager drew its full
`Shim UEFI key management` UI and counted down, proving the appended partition really is a
FAT volume the firmware reads and executes from. A deliberately truncated ESP in the same
harness reported `Not Found`, so the negative direction is instrumented too.

Two cautions belong with that table, both learned the hard way. First, the verdicts are slow:
one variant took roughly six minutes to reach its firmware verdict and another said nothing
for eighty seconds and then produced its whole story at once, so any window shorter than
several minutes measures the window and not the ISO. An earlier round of this same
comparison was scored at seventy seconds and at four minutes, and both readings were wrong.
Second, a readable ESP is all this buys. shim starts and then fails to read `grubx64.efi`
off that volume — `Unexpected return from initial read: Device Error, buffersize 0`, which is
shim's own message — so the reference derivative still does not reach a GRUB menu. That is a
separate defect from the partition layout, and no xorriso argument list fixes it.

A tree that ends up with neither amorce is now refused rather than built. `xorriso` accepts
such a tree happily and returns a valid ISO9660 image with a kernel, an initrd, a GRUB
config and no boot record — a data disc — and the only previous hint was the string
`boot assets not detected` inside a command description. The refusal lives at the single
point every path passes through to obtain boot tokens, and it fires in execute mode only:
in dry-run the boot files are planned rather than written, so there is nothing on disk to be
right or wrong about. That is why the dry-run plan is where a from-scratch amorce is
asserted instead (`tests/test_dry_run_host_purity.py`), and why the equivalent check in
`validate.py` never caught this — it is gated on `iso_root.exists()`, and for a from-scratch
build `iso_root` does not exist yet when validation runs.

Verification is honest about its boundary: offline tests pin a real (BIOS-only) `as_mkisofs`
capture and a UEFI-shaped forwarding case, proving the parser drops the options we own and
forwards every boot/partition token — including EFI/appended-partition tokens — verbatim.
Confirming a rebuilt ISO actually boots under UEFI on current releases is a maintainer step
on real hardware or a real target ISO, since the suite builds no artifact by design.

## Supply-Chain and Cross-Architecture Modules

Three optional modules extend the reference path without weakening it. Each can say
"disabled" cleanly in plan, dry-run, GUI, and docs, and each is governed by the build
option contract in `commands/build_contracts.py`.

### CVE scanning

`--vuln-scan` runs the `VULN_SCAN` phase after packages are resolved. `--vuln-policy`
selects the posture:

- `off` records findings only;
- `warn` (default) reports findings without blocking;
- `block-high` promotes high and critical findings to errors;
- `block-critical` blocks only critical findings and leaves high as a warning.

The scanner matches the planned package set by name against a bundled advisory database and
records a `vuln-report` virtual command event carrying the status and finding count, so
dry-runs stay inspectable and real builds never try to exec a `vuln-report` binary. The build fails closed: a blocking finding raises before any ISO is
produced. `--vuln-db PATH` points at a custom advisory JSON; a database that cannot be read
is surfaced as a `DB-UNAVAILABLE` warning, never a silent pass to clean.

### Standard SBOM export

`--sbom-format` selects the Software Bill of Materials emitted in the provenance phase:

- `native` (default) writes only `distroforge-provenance.json`;
- `spdx` also writes `distroforge-sbom.spdx.json` (SPDX-2.3 with package PURLs and
  `DESCRIBES` relationships);
- `cyclonedx` also writes `distroforge-sbom.cdx.json` (CycloneDX 1.5 with an
  operating-system root component and library components).

The standard SBOM is written next to the native provenance document, so a published bundle
can carry a vendor-neutral component inventory.

### Reproducible builds

`--reproducible` used to consist of one file. The `REPRODUCIBLE` phase wrote
`etc/distroforge-reproducible.env` into the target and stopped there, and no reader for
that file has ever existed — not in this project, not in apt, not in any build tool. It
also shipped inside the image. The option was visible in the CLI, in the GUI, in the
phase list and in the build log, and changed nothing about the bytes produced.

The pinning now happens where the bytes are made, on the two tools' own documented
terms rather than on any behaviour invented here:

- `mksquashfs` 4.7.5 documents `SOURCE_DATE_EPOCH` as "used as the filesystem creation
  timestamp", and adds that "any file timestamps which are after SOURCE_DATE_EPOCH will
  be clamped to SOURCE_DATE_EPOCH";
- `xorrisofs` 1.5.6 documents it as supplying the default of `--modification-date=`, of
  `--gpt_disk_guid`, of `--set_all_file_dates`, and of the "now" time for ISO nodes with
  no disk source.

So `--source-date-epoch` needs no flag of its own. It travels as an `env VAR=value`
prefix in the argv, not in `CommandSpec.env`, for two reasons. The privilege wrapper
discards environments it is handed: `sudoers(5)` for the sudo-rs on this platform states
that `env_reset` "cannot be disabled. This causes commands to be executed with a new,
minimal environment", and `pkexec(1)` sets "a minimal known and safe environment" — a
variable passed beside the argv would never reach a privileged `mksquashfs`. And the
printed plan is meant to be re-run: `CommandSpec.display()` and the JSONL build log both
render argv and nothing else, so a pin carried elsewhere would be missing from the very
record that says what the build did. In the `mksquashfs` argv the prefix is at the head,
because everything after `-e` is read as an exclude pattern.

`--apt-snapshot` takes an **identifier**, `YYYYMMDDTHHMMSSZ`, never a URL. It is written
as apt's `snapshot=` source option on the ordinary archive URI (`Snapshot:` in the
deb822 mirror layer), and apt resolves it to whichever snapshot service the repository
belongs to. That indirection is the point: measured, apt routes an Ubuntu source to
`snapshot.ubuntu.com/ubuntu/<id>` and a Debian one to
`snapshot.debian.org/archive/debian/<id>`. Building the URL here would mean hardcoding
two layouts and getting one of them wrong.

Which sources get the pin was settled by listing every place this project writes an apt
source, not by assuming there were two. There are three that can carry it — the one-line
path in `core/apt.py`, the deb822 path in `core/mirrors.py`, and the archive sources
`core/release_track.py` writes for `--release-track` — and all three do. The first two
are *alternatives*, so pinning only one would leave the build unpinned whenever
`--mirrors` happened to be on, which is a flag with nothing to do with reproducibility;
the third is easy to forget precisely because it is a separate file. A source the
operator already pinned by hand keeps its own identifier.

The identifier is validated here because almost nothing downstream validates it.
`sources.list(5)` says outright that APT does not check the form. Measured against the
live service with `APT::Update::Error-Mode=any`:

| identifier | apt | what happens |
| --- | --- | --- |
| malformed (`pouet`) | exits 100 | 404, loud — but an hour into the build |
| before 1 March 2023 | 404 | earlier than the service covers, by its own statement |
| in the future | **exits 0** | HTTP 200 serving the **live archive's** indices |

The third row is why the check exists: a future identifier pins nothing at all while the
build still reports that it is pinned. There is a fourth trap that is deliberately *not*
guarded — an identifier older than the target suite also exits 0, on an archive that is
merely empty, and this project's release table carries no release date to compare
against. Guessing one from the version number would be a convention dressed as a fact,
so it is written down here instead.

Two gaps remain, and both are announced rather than hidden.

`debootstrap` and `mmdebstrap` are given a mirror **URL**, which carries no apt source
option, so a snapshot pins every package installed during the build but not the base
rootfs underneath them. When a snapshot is set and `--bootstrap-mirror` is not, the
dry-run report says so (`reproducible-base-unpinned`) and names the flag that closes it.
Pointing `--bootstrap-mirror` at the snapshot archive also changes the recorded bootstrap
identity, so an existing rootfs from the unpinned mirror is refused rather than reused —
see *Reusing a bootstrap rootfs* below.

A PPA cannot be pinned at all, and the fourth source writer — `core/ppa.py` — therefore
does **not** get the option. Measured: apt derives a snapshot host by prefixing
`snapshot.` to the repository's own host, so a Launchpad source resolves to
`snapshot.ppa.launchpadcontent.net`, which does not exist; every fetch comes back `Ign`,
`apt-get update` exits 0, and the live PPA indices are used. Writing `snapshot=` onto a
PPA source would be a second placebo of exactly the kind this section describes removing.
When a snapshot is set and PPAs are configured, the dry-run report names them
(`reproducible-ppa-unpinned`) instead.

The phase itself now writes nothing and runs no command: it refuses. Enabling
reproducible builds without an epoch, with an epoch outside the unsigned 32-bit range
`mksquashfs` documents, or with an unusable snapshot identifier raises before the first
expensive phase, and the dry-run report carries the same verdicts as
`reproducible-epoch-missing`, `reproducible-epoch-invalid` and
`reproducible-snapshot-invalid`. Because it mutates no rootfs, it is also no longer
declared privileged in `core/phase_contracts.py`, which the privilege gate measures
against the real command history rather than taking on trust.

### Reusing a bootstrap rootfs

A bootstrap target that already exists is reused instead of re-bootstrapped, which is
what makes a retry after a failed later phase cheap. What "already exists" was allowed
to mean was the problem: the check was that `var/lib/dpkg/status` and an `os-release`
both existed. Two paths that exist say the tree is a Debian-family rootfs. They do not
say it is *this* build's rootfs — the target is a fixed `work/filesystem` with no suite
in the path, nothing cleans it between runs, and nothing compared the tree's release to
the project's. Retarget a project at another release, rebuild, and the previous suite's
tree was reused and shipped inside the image, silently.

Those two paths were also not enough to say the tree is *a rootfs*. A tree carrying a dpkg
status file, an `os-release` and no package manager graded **complete** and therefore
reusable — which is exactly the tree the first real golden-path run produced, and a re-run
would have skipped the bootstrap and hit the same missing `apt-get` with no bootstrap left
in the log to blame. Completeness is now `_ROOTFS_REQUIREMENTS`: a dpkg database, an
os-release, `dpkg` and `apt-get`, each with the alternative locations that are legitimate
answers (os-release(5) allows two; `/bin` is a symlink on a merged-usr tree and need not be
on a foreign one). The verdict names the entries that are absent instead of saying only
`incomplete`, and `create_rootfs` checks the same list the moment the bootstrap tool
returns — before the stamp below is written — so the build stops at the phase that produced
the tree rather than five phases later, and a refused tree carries no record claiming a
base. The refusal names the tool, the variant and the suite, because `minbase` does not
mean the same set to debootstrap(8) and mmdebstrap(1).

Reuse is then keyed on the base a tree was built from, and a difference is refused rather
than repaired — deleting a tree the maintainer may have spent an hour on, to recover from
a question they can answer in one command, is not the build's decision:

- A successful bootstrap writes `work/filesystem.bootstrap.json` recording the codename,
  the family, the architecture, the variant and the mirror. It is written **after** the
  bootstrap tool returns, so a bootstrap that died halfway leaves no record claiming a
  base for a tree that does not have one; and it lands **beside** the tree rather than
  inside it, so it neither ships into the image nor outlives what it describes.
- When that record is present it decides, because it carries the architecture, the
  variant and the mirror — differences a finished tree cannot be asked about afterwards.
- When it is absent, which covers both trees bootstrapped before the record existed and
  trees DistroForge never created, the tree is still asked what suite it is: os-release(5)
  has it declare its own codename. That is the difference that actually bit.
- A tree with no record and no codename is reused, and the dry-run report says in a
  warning that its base could not be verified. Refusing there would break every
  hand-assembled tree to guard against a case no evidence points at; passing quietly
  would claim a check that did not happen.

The package set is deliberately **not** part of the key. The bootstrap tool is passed only
`--include=ca-certificates`; the set is applied afterwards by the live-base phase with apt,
against whatever tree exists, so keying on it would force a full re-bootstrap for an edit
the next phase already handles. The honest cost of that choice, named rather than hidden:
**shrinking the package list leaves what it used to name installed in a reused tree**,
because apt is only ever asked to install. A build that must not carry those packages
needs either a clean `work/filesystem` or an explicit removal.

`distroforge build --dry-run` reports the decision by calling the same function the build
calls, so the report and the build cannot disagree about what the build is going to do;
it used to carry its own copy of the reuse test. The finding codes are
`bootstrap-rootfs-new`, `-empty`, `-reuse`, `-unverified`, `-mismatch`, `-incomplete` and
`-unreadable`.

### True cross-architecture bootstrap

`--bootstrap-arch` builds a foreign-architecture image, such as arm64 on an amd64 host.
GRUB packages are architecture-aware: amd64 keeps `grub-pc-bin` plus `grub-efi-amd64-bin`,
while arm64 drops the BIOS package and uses `grub-efi-arm64-bin`. Both add
`grub-efi-<arch>-signed` next to `shim-signed`, which is the pair the UEFI amorce is staged
from. The package name follows GRUB's EFI platform rather than the dpkg architecture, and
for i386 the two differ — `grub-efi-ia32-bin` is the real name, and there has never been a
`grub-efi-i386-bin`, so that build used to fail at `apt-get install`. The kernel
meta-package stays `linux-generic` on Ubuntu. A cross-arch target requires
`qemu-user-static`; native builds add no qemu requirement.

### How the UEFI amorce is staged

The EFI payloads are copied out of the **target rootfs**, never off the build host. The host
is whatever machine the maintainer happens to be on, and a UEFI-only host does not even
carry the BIOS GRUB the El Torito step reads. Nothing extra is installed into the target to
make this work: `shim-signed` already depends on `grub-efi-<arch>-signed`, and
`grub-efi-<arch>-bin` already depends on `grub-efi-<arch>-unsigned`, which is the package
that ships a ready-to-boot monolithic image. `grub-efi-<arch>-bin` itself ships no `.efi`
file at all — only modules — so there is nothing in it to copy.

Shim plus the signed GRUB is the preferred Secure Boot chain; the unsigned monolithic GRUB
is the non-enforcing fallback. Those are intended roles, not proof that the current image
completes either chain. The files are placed in a FAT image at `boot/grub/efi.img`, which is
what `BootLayout.detect()` looks for first and what an El Torito EFI entry is specified to
contain, with plain copies under `EFI/boot/` for whatever reads the tree rather than its
boot record. The FAT container is built on the host with `mtools`, which writes an image as
an ordinary file: no loop mount, no privilege, and `mtools` stays out of the delivered
filesystem. It is therefore a `Depends`, and `doctor`,
`iso-toolchain`, `iso-doctor` and bootstrap validation all report it — validation checks it
up front so a missing tool costs a second rather than an hour of bootstrapping. The volume
serial is pinned so two builds of one tree produce the same image; FAT directory timestamps
still come from the source files and remain a residual reproducibility gap.

One thing here is **not machine-verified**: whether the staged GRUB finds
`boot/grub/grub.cfg` from its own baked-in prefix. A signed GRUB's prefix is fixed at the
vendor's build time and cannot be re-set — that is the point of signing. The
`EFI/BOOT/grub.cfg` trampoline written into the image is the documented mitigation, and
confirming it needs a real ISO booted under UEFI firmware. The weekly golden path is
configured to ask exactly that question with `boot-proof --backend qemu --firmware uefi`
and a runtime milestone, but no completed run has yet proved the trampoline. The current
audit reaches shim and fails before GRUB. The signed GRUB prefix and enforcing Secure Boot
therefore remain unproved as well. See
[`iso-build-proof-ledger.md`](iso-build-proof-ledger.md); structural boot records alone
cannot guarantee that the amorce chain-loads.
