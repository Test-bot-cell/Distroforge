from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from .releases import get_release, load_releases

if TYPE_CHECKING:
    from .project import Project
    from .trust import TrustOptions

StarterKind = Literal["skeleton", "official-iso", "netboot", "local-iso", "previous-project"]


@dataclass(frozen=True)
class SourceStarter:
    key: str
    kind: StarterKind
    release: str
    label: str
    description: str
    source_mode: str
    url: str | None = None
    checksum_url: str | None = None
    checksum_signature_url: str | None = None
    checksum_algorithm: str = "sha256"

    def to_dict(self) -> dict[str, object]:
        return {key: value for key, value in asdict(self).items() if value is not None}


BUILTIN_SOURCE_STARTERS: dict[str, SourceStarter] = {
    "ubuntu-24.04-skeleton": SourceStarter(
        key="ubuntu-24.04-skeleton",
        kind="skeleton",
        release="24.04",
        label="Ubuntu 24.04 skeleton",
        description="Minimal live rootfs seed: no desktop environment and no application layer.",
        source_mode="bootstrap",
    ),
    "ubuntu-25.10-skeleton": SourceStarter(
        key="ubuntu-25.10-skeleton",
        kind="skeleton",
        release="25.10",
        label="Ubuntu 25.10 skeleton",
        description="Minimal live rootfs seed: no desktop environment and no application layer.",
        source_mode="bootstrap",
    ),
    "ubuntu-26.04-skeleton": SourceStarter(
        key="ubuntu-26.04-skeleton",
        kind="skeleton",
        release="26.04",
        label="Ubuntu 26.04 skeleton",
        description="Minimal live rootfs seed: no desktop environment and no application layer.",
        source_mode="bootstrap",
    ),
    "ubuntu-26.04-official-server": SourceStarter(
        key="ubuntu-26.04-official-server",
        kind="official-iso",
        release="26.04",
        label="Ubuntu 26.04 official live server ISO",
        description="Official Ubuntu release ISO; download or inject locally before build.",
        source_mode="iso",
        url="https://releases.ubuntu.com/26.04/ubuntu-26.04-live-server-amd64.iso",
        checksum_url="https://releases.ubuntu.com/26.04/SHA256SUMS",
        checksum_signature_url="https://releases.ubuntu.com/26.04/SHA256SUMS.gpg",
        checksum_algorithm="sha256",
    ),
    "ubuntu-26.04-netboot": SourceStarter(
        key="ubuntu-26.04-netboot",
        kind="netboot",
        release="26.04",
        label="Ubuntu 26.04 netboot tarball",
        description="Official netboot tarball for network installer starts; inject local media before ISO build.",
        source_mode="iso",
        url="https://releases.ubuntu.com/26.04/ubuntu-26.04-netboot-amd64.tar.gz",
        checksum_url="https://releases.ubuntu.com/26.04/SHA256SUMS",
        checksum_signature_url="https://releases.ubuntu.com/26.04/SHA256SUMS.gpg",
        checksum_algorithm="sha256",
    ),
    "debian-13.5-skeleton": SourceStarter(
        key="debian-13.5-skeleton",
        kind="skeleton",
        release="debian-13.5",
        label="Debian 13.5 Trixie skeleton",
        description="Minimal Debian live rootfs seed: no desktop environment and no application layer.",
        source_mode="bootstrap",
    ),
    "debian-13.5-netinst": SourceStarter(
        key="debian-13.5-netinst",
        kind="netboot",
        release="debian-13.5",
        label="Debian 13.5 Trixie netinst ISO",
        description="Official Debian netinst ISO; checksum is published as SHA512SUMS with signature.",
        source_mode="iso",
        url="https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.5.0-amd64-netinst.iso",
        checksum_url="https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA512SUMS",
        checksum_signature_url="https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA512SUMS.sign",
        checksum_algorithm="sha512",
    ),
    "ubuntu-26.10-skeleton": SourceStarter(
        key="ubuntu-26.10-skeleton",
        kind="skeleton",
        release="26.10",
        label="Ubuntu 26.10 skeleton",
        description="Minimal live rootfs seed for the planned Ubuntu development release.",
        source_mode="bootstrap",
    ),
}


def list_source_starters(release: str | None = None) -> list[SourceStarter]:
    releases = load_releases()
    starters = [
        starter
        for starter in BUILTIN_SOURCE_STARTERS.values()
        if release is None or starter.release == release
    ]
    return sorted(starters, key=lambda item: (releases[item.release].family, item.release, item.key))


def get_source_starter(key: str) -> SourceStarter:
    if key in BUILTIN_SOURCE_STARTERS:
        return BUILTIN_SOURCE_STARTERS[key]
    known = ", ".join(sorted(BUILTIN_SOURCE_STARTERS))
    raise ValueError(f"Unknown source starter {key!r}. Known: {known}")


def default_starter_for_release(release: str) -> str:
    release_obj = get_release(release)
    if release_obj.family == "debian":
        return "debian-13.5-skeleton"
    return f"ubuntu-{release}-skeleton"


def local_iso_starter(release: str, source_iso: Path) -> SourceStarter:
    return SourceStarter(
        key="local-iso",
        kind="local-iso",
        release=release,
        label=f"Local ISO for {get_release(release).label}",
        description="Existing local ISO selected by the user and tracked through trust metadata.",
        source_mode="iso",
        url=str(source_iso),
    )


def apply_source_starter(
    project: Project,
    starter_key: str,
    *,
    source_iso: Path | None = None,
    previous_project: Path | None = None,
    trust: TrustOptions | None = None,
) -> None:
    if starter_key == "local-iso":
        if not source_iso:
            raise ValueError("local-iso starter requires --source-iso")
        starter = local_iso_starter(project.release.version, source_iso)
        project.source_mode = "iso"
        project.source_iso = source_iso
    elif starter_key == "previous-project":
        if not previous_project:
            raise ValueError("previous-project starter requires --previous-project")
        previous = project.__class__.load(previous_project)
        starter = SourceStarter(
            key="previous-project",
            kind="previous-project",
            release=previous.release.version,
            label=f"Source from {previous.name}",
            description="Source starter copied from an existing DistroForge project.",
            source_mode=previous.source_mode,
            url=str(previous.source_iso) if previous.source_iso else None,
        )
        project.release = previous.release
        project.source_mode = previous.source_mode
        project.source_iso = previous.source_iso
    else:
        starter = get_source_starter(starter_key)
        project.release = get_release(starter.release)
        project.source_mode = starter.source_mode
        project.source_iso = source_iso

    project.source_starter = starter.to_dict()
    if trust:
        project.source_starter["trust"] = {
            key: str(value)
            for key, value in {
                "source_sha256": trust.source_sha256,
                "source_signature": trust.source_signature,
                "source_gpg_fingerprint": trust.source_gpg_fingerprint,
                "require_source_checksum": trust.require_source_checksum,
                "require_source_signature": trust.require_source_signature,
            }.items()
            if value
        }
    project.save()
