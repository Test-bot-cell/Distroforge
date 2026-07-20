# Capture and Image Workflows

DistroForge treats installed-system capture as a read-only intent extraction workflow.
It does not clone `/`, copy user homes, or package secrets into an ISO.

## Modes

1. **Build from official base**: the existing verified base, chroot, squashfs, ISO pipeline.
2. **Capture installed system**: scan a mounted system and export a sanitized YAML profile.
3. **Rebuild from captured profile**: create a normal DistroForge project from that profile.
4. **GUI review**: inspect captured, ignored, dangerous, and not-reproducible findings before use.
5. **Debian live-build plan**: generate a reviewable `config/` plan for Debian live-build.
6. **Ubuntu livefs ISO plan**: generate a reviewable livefs ISO workspace inspired by Ubuntu's `isobuild` flow.
7. **Upgrade media preflight**: read-only checks for a controlled upgrade workflow.
8. **OEM/systemd image plan**: plan-only support for `systemd-repart`/`sysupdate` style images.

## Capture

```bash
distroforge capture / --output system-profile.yaml --sanitize strict
distroforge capture / --output system-profile.yaml --include-config /etc/netplan --include-config-glob '/etc/distroforge/*.conf'
distroforge capture-diff system-profile.yaml
```

Captured by default:

- manually installed packages when `apt-mark showmanual` is available;
- offline installed package fallback from `var/lib/dpkg/status`;
- active APT sources, marked for review when unsigned or plain HTTP;
- release, codename, architecture, locale, timezone, keyboard, hostname;
- display manager and systemd service state where detectable;
- explicitly whitelisted configuration files, embedded with path, mode, size, SHA-256, and UTF-8 content.

Excluded or flagged by default:

- `/home`, `/root`, shell history, browser caches;
- SSH/GPG keys, machine-id, password hashes, tokens;
- logs, crash dumps, APT caches, temporary files;
- arbitrary `/etc` files that were not whitelisted.

The output profile is a normal build definition plus a `capture` report section.
Whitelisted config capture is intentionally narrow: paths must stay inside the target root,
symlinks are reported but not embedded, files above 64 KiB are skipped, binary files are
not embedded, and names matching secret/cache patterns are blocked even when a glob matches.

`capture-diff` renders the maintainer-facing review summary: captured package count,
embedded config files, ignored findings, dangerous findings, and not-reproducible findings.

## Rebuild

```bash
distroforge rebuild-from-capture system-profile.yaml /tmp/rebuild
distroforge build /tmp/rebuild --definition /tmp/rebuild/captured-profile.yaml
```

The rebuild path uses the standard DistroForge builder. This keeps capture and build
separate: scan first, review next, build only after the profile is understood.

## Debian live-build

```bash
distroforge live-build-plan system-profile.yaml --output-dir /tmp/live-build --write
```

The live-build backend writes a reviewable `config/` tree. Captured package intent becomes
`config/package-lists/distroforge.list.chroot`; embedded whitelisted configuration files
are restored under `config/includes.chroot/`; and a sanitize hook clears machine identity.
Execution remains explicit and external so maintainers can inspect the generated tree first.

## Ubuntu livefs ISO

```bash
distroforge livefs-iso-plan system-profile.yaml --work-dir /tmp/livefs-iso --dest /tmp/distroforge.iso
distroforge livefs-iso-build system-profile.yaml --work-dir /tmp/livefs-iso --dest /tmp/distroforge.iso --write
```

The livefs ISO backend mirrors Ubuntu's newer "make ISO in livefs build" shape as a
review-first workspace. It writes:

- `iso-root/.disk/info` and skeleton ISO directories;
- `package-list.txt` with package pool intent;
- `cdrom.sources`, a deb822 `/cdrom` source with a per-build public-key placeholder;
- `isobuild-commands.txt`, showing the seven planned `isobuild` phases;
- `distroforge-livefs-iso-plan.yaml`, the structured plan.

The planned phases are `init`, `setup-apt`, `generate-pool`, `generate-sources`,
`add-live-filesystem`, `make-bootable`, and `make-iso`. DistroForge does not yet publish
this as a finished official ISO pipeline: pool materialization, per-build GPG key
generation, boot asset staging, and QEMU online/offline install validation remain explicit
review gates before distribution.

## GUI Parity

The **Capture & Images** page exposes the same workflows:

- Scan installed system;
- Export YAML;
- Review capture diff;
- Build from profile;
- Include exact config paths and config globs;
- Plan Debian live-build;
- Plan/write Ubuntu livefs ISO workspace;
- Run upgrade preflight;
- Plan OEM/systemd image.

No operation on that page mutates the captured system.

## Safety Posture

Upgrade media and systemd/OEM image support are intentionally plan/preflight-only in
this phase. They must not grow an "apply now" path until snapshots, storage detection,
rollback reporting, and bootloader safety checks are fully implemented.
