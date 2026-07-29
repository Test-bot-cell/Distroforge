# Image Definitions

DistroForge accepts JSON or YAML image definitions. YAML is preferred for humans; JSON is
useful for generated presets and exact machine output.

Minimal bootstrap example:

```yaml
source_starter:
  key: ubuntu-26.04-skeleton
  kind: skeleton
  release: "26.04"
  label: Ubuntu 26.04 skeleton
source_mode: bootstrap
bootstrap:
  archive_keyring: /usr/share/keyrings/ubuntu-archive-keyring.gpg
  archive_keyring_sha256: 80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31
  archive_signer_fingerprints:
    - F6ECB3762474EDA9D21B7022871920D1991BC93C
  source_policies:
    - policy_id: ubuntu-release-resolute
      base_uri: https://archive.ubuntu.com/ubuntu
      suites: [resolute]
      codenames: [resolute]
      components: [main, restricted, universe, multiverse]
      architectures: [amd64]
      signer_fingerprints:
        - F6ECB3762474EDA9D21B7022871920D1991BC93C
      keyring_sha256:
        - 80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31
      max_release_age_seconds: 15552000
      max_future_skew_seconds: 300
      require_valid_until: false
packages:
  - git
  - curl
customization:
  desktop: ubuntu_minimal
  locale: en_US.UTF-8
sanitize:
  apt_lists: true
```

Build-option sections can be set in the same definition. Supply-chain and
cross-architecture controls map directly to their CLI flags:

```yaml
bootstrap:
  arch: arm64
  archive_keyring: /usr/share/keyrings/ubuntu-archive-keyring.gpg
  archive_keyring_sha256: 80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31
  archive_signer_fingerprints:
    - F6ECB3762474EDA9D21B7022871920D1991BC93C
  source_policies:
    - policy_id: ubuntu-ports-release-resolute
      base_uri: https://ports.ubuntu.com/ubuntu-ports
      suites: [resolute]
      codenames: [resolute]
      components: [main, restricted, universe, multiverse]
      architectures: [arm64]
      signer_fingerprints:
        - F6ECB3762474EDA9D21B7022871920D1991BC93C
      keyring_sha256:
        - 80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31
      max_release_age_seconds: 15552000
      max_future_skew_seconds: 300
      require_valid_until: false
vuln_scan:
  enabled: true
  policy: block-high
provenance:
  sbom_format: spdx
```

`bootstrap.arch` mirrors `--bootstrap-arch`, `vuln_scan` mirrors
`--vuln-scan`/`--vuln-policy`/`--vuln-db`, and `provenance.sbom_format` mirrors
`--sbom-format`.

An executing bootstrap requires all three archive trust controls: an explicit keyring
path, the reviewed SHA-256 of those keyring bytes, and one or more complete 40- or
64-hex signer fingerprints. DistroForge seals the matching keyring into the run before
dispatching the bootstrap tool and later replays `InRelease` → `Packages` → `.deb`
against the same external values. For that replay, each `source_policies` entry owns only
its configured base URI, suites/codenames, components, architectures, full signers,
keyring digests and freshness window; a valid signature for one namespace cannot
authorize another. `snapshot_at` may pin a historical instant, while
`max_release_age_seconds`, `max_future_skew_seconds` and `require_valid_until` govern
Release freshness at the build instant. The Ubuntu reference retains only
`F6ECB3762474EDA9D21B7022871920D1991BC93C`. An archive key rotation must be reviewed
and changed in the definition rather than inherited silently from the host.

`squashfs.compression` mirrors `--squashfs-compression` and selects the live-filesystem
compressor — `gzip`, `lzo`, `lz4`, `xz` or `zstd`, empty meaning the release default.
Only compressors a kernel can mount are accepted; see `docs/build-pipeline.md` for the
measured cost of each.

Definitions are validated with Pydantic. Unknown top-level keys are preserved for forward
compatibility, while known nested sections reject unsupported fields where strict models exist.
The repository examples under `examples/*.yaml` are part of the Debian package contract:
they must remain schema-valid and be declared in `debian/examples`. Bundled TOML catalogs
under `distroforge/data/*.toml` are package data, must parse with `tomllib`, and must stay
non-executable.

Use `distroforge source-starters` to list the built-in starts. A local ISO starter records
the selected path and trust metadata, while a previous-project starter copies the source
choice from another `project.json`.
