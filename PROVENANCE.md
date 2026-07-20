# Import provenance

This repository was initialized on 2026-07-20 from the local DistroForge
source snapshot after comparison with the package installed on the same
Ubuntu VM.

## Reference package

- Package: `distroforge`
- Debian version: `0.3.5-1`
- Architecture: `all`
- Installed state: `install ok installed`
- Reference archive:
  `/home/ubunturaph/02_Paquets/Distroforge/0.3.4-0.3.5/distroforge_0.3.5-1_all.deb`
- Archive size: `306084` bytes
- Archive SHA-256:
  `4551ddefb8a8ae223ae9a896e096751a0ab9500c7ef12a4fada354b9e824ccba`

The archive payload and the files registered by `dpkg` matched. Because
`dpkg` does not retain the checksum or path of the archive originally passed
to the installer, this proves payload equivalence rather than the identity of
the historical archive file.

## Verification before repository edits

- `dpkg --verify distroforge` reported no modified or missing installed file.
- All 283 installed payload files passed the package MD5 manifest.
- The 248 files below `distroforge/` had the same paths and byte content as
  `/usr/lib/python3/dist-packages/distroforge/`.
- Their sorted path-and-content SHA-256 manifest was identical on both sides:
  `056a91ccbbfc9558e2bc60aa2a7e2e45422b2876d5333b604d9db04c084d5bd6`.
- The 18 documentation files, three manual pages, desktop entry, SVG icon,
  copyright file, maintainer `postinst`, and two packaged examples also
  matched after accounting for Debian's gzip compression.

The binary package does not contain the test suite, CI configuration, or full
Debian source packaging, so those source-only files cannot be authenticated
from the binary payload alone.

## Baseline reconciliation

The snapshot mixed an exact `0.3.5-1` application payload with three partial
`0.3.5-2` source changes. Before the initial commit:

- the unreleased `0.3.5-2` changelog stanza was removed;
- the two `composable-profile` examples introduced for that later package
  were removed from both `examples/` and `debian/examples`;
- the already-applied Ubuntu resolute Standards-Version adjustment was
  flattened into the source, and its stale Quilt metadata was removed.
- a redundant test-only import was removed so the imported baseline passes
  its configured Ruff checks.

The application package under `distroforge/` was not changed during this
reconciliation. Repository-facing files such as `README.md`, `.gitignore`,
`.gitattributes`, `.editorconfig`, and this provenance record were then
created or refreshed for the initial Git import.

## Initial repository checks

The reconciled tree passed the following checks before the first commit:

- Ruff: all checks passed;
- pytest: 576 tests passed;
- DistroForge packaging policy: `blocked: false`, with no malformed or missing
  package data, documentation, or examples;
- Debian changelog version: `0.3.5-1`, byte-identical to the changelog shipped
  in the reference package after decompression;
- application comparison: no difference across the 248 installed source and
  data files.

No Debian package was rebuilt or installed during repository initialization.

## Repeating the application comparison

From the repository root:

```bash
diff -qr \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  distroforge \
  /usr/lib/python3/dist-packages/distroforge

(cd distroforge && \
  find . -type f -not -path '*/__pycache__/*' -not -name '*.pyc' -print0 |
  sort -z | xargs -0 sha256sum) | sha256sum
```
