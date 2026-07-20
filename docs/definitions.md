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
vuln_scan:
  enabled: true
  policy: block-high
provenance:
  sbom_format: spdx
```

`bootstrap.arch` mirrors `--bootstrap-arch`, `vuln_scan` mirrors
`--vuln-scan`/`--vuln-policy`/`--vuln-db`, and `provenance.sbom_format` mirrors
`--sbom-format`.

Definitions are validated with Pydantic. Unknown top-level keys are preserved for forward
compatibility, while known nested sections reject unsupported fields where strict models exist.
The repository examples under `examples/*.yaml` are part of the Debian package contract:
they must remain schema-valid and be declared in `debian/examples`. Bundled TOML catalogs
under `distroforge/data/*.toml` are package data, must parse with `tomllib`, and must stay
non-executable.

Use `distroforge source-starters` to list the built-in starts. A local ISO starter records
the selected path and trust metadata, while a previous-project starter copies the source
choice from another `project.json`.
