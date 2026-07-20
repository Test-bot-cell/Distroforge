# Distro Derivative Profiles

DistroForge derivative profiles describe a downstream distribution as reviewable build
intent: base family, base release, repositories, keyrings, identity packages, installer,
live session, hardware channel, branding, and optional build-container hints.

They are not official vendor ISO recipes. They are structured starting points for
maintainers who want a derivative to be explainable and reproducible before any ISO is
published.

## Commands

```bash
distroforge derivative-profiles
distroforge derivative-profile plan mint-ubuntu
distroforge derivative-profile validate mint-ubuntu
distroforge derivative-profile export mint-ubuntu --output mint-derivative.yaml
distroforge derivative-profile create-project mint-ubuntu --root /tmp/mint-project
distroforge derivative-profile export lmde --dockerfile ./lmde7-amd64.Dockerfile --output lmde-derivative.yaml
```

## Built-in Profiles

- `mint-ubuntu`: Ubuntu-based Mint-like profile with Mint repository intent, Cinnamon,
  Mint identity packages, `mint-live-session`, and Ubiquity installer intent.
- `lmde`: Debian-based Mint-like profile with Mint repository intent,
  `debian-system-adjustments`, `mint-live-session`, and `live-installer` intent.
- `mint-edge`: Ubuntu-based Mint-like profile with HWE/edge hardware enablement intent.

## Dockerfile Hints

`--dockerfile` does not execute containers. It reads a Dockerfile and records useful
build-environment clues:

- `FROM` base image;
- APT packages installed in build setup lines, including continued `RUN ... \` lines;
- repository lines that look like Debian/Mint `deb` entries;
- `COPY`/`ADD` lines;
- keyring-like `wget`/`curl` fetches.

This helps compare public build-container intent with the DistroForge derivative profile
without treating the container as a trusted ISO recipe.

## GUI Parity

The **Packages** page exposes the same workflow:

- choose a derivative profile;
- optionally point to a Dockerfile;
- render a derivative plan;
- export the derivative definition.
- create a new project from the derivative profile.

Validation checks that repositories use `signed-by`, keyring packages are declared,
installer choice matches the base family, identity packages are present, edge hardware
channels declare kernel/HWE intent, and Dockerfile base images are compatible when supplied.

Every CLI addition here must stay visible in the GUI and in `docs/gui-parity.md`.

## Safety Posture

Derivative profiles intentionally keep vendor identity explicit. Before distributing an
ISO based on a Mint-like profile, review trademark, artwork, repository trust, installer
behavior, offline install behavior, and package provenance.
