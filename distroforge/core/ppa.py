from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from .command import CommandRunner, CommandSpec, sudo
from .fsops import FileSystemOps
from .releases import UbuntuRelease


@dataclass(frozen=True)
class PpaSpec:
    owner: str
    name: str
    fingerprint: str | None = None

    @classmethod
    def parse(cls, value: str) -> PpaSpec:
        raw = value.removeprefix("ppa:")
        fingerprint = None
        if "@" in raw:
            raw, fingerprint = raw.split("@", 1)
        if "/" not in raw:
            raise ValueError(f"Invalid PPA '{value}', expected ppa:owner/name")
        owner, name = raw.split("/", 1)
        return cls(owner=owner, name=name, fingerprint=fingerprint)

    @property
    def slug(self) -> str:
        return f"{self.owner}-{self.name}".replace("/", "-")


@dataclass
class PpaOptions:
    ppas: list[PpaSpec] = field(default_factory=list)
    require_fingerprint: bool = True
    auto_fetch_fingerprint: bool = True
    keyserver: str = "hkps://keyserver.ubuntu.com"


class PpaService:
    def __init__(
        self,
        runner: CommandRunner,
        root: Path,
        release: UbuntuRelease,
        options: PpaOptions,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.root = root
        self.release = release
        self.options = options
        self.use_sudo = use_sudo
        self.fs = FileSystemOps(runner, use_sudo)

    def configure(self) -> None:
        self._shed_stale({ppa.slug for ppa in self.options.ppas})
        for ppa in self.options.ppas:
            fingerprint = ppa.fingerprint
            if not fingerprint and self.options.auto_fetch_fingerprint:
                fingerprint = self._resolve_fingerprint(ppa)
            if self.options.require_fingerprint and not fingerprint:
                raise ValueError(
                    f"PPA ppa:{ppa.owner}/{ppa.name} requires a verified fingerprint"
                )
            keyring = self.root / "usr" / "share" / "keyrings" / f"distroforge-{ppa.slug}.gpg"
            source = self.root / "etc" / "apt" / "sources.list.d" / f"distroforge-{ppa.slug}.list"
            if fingerprint:
                self.fs.mkdir(keyring.parent, f"Create PPA keyring directory for {ppa.owner}/{ppa.name}")
                self.runner.run(
                    CommandSpec(
                        argv=sudo(
                            (
                                "gpg",
                                "--no-default-keyring",
                                "--keyring",
                                str(keyring),
                                "--keyserver",
                                self.options.keyserver,
                                "--recv-keys",
                                fingerprint,
                            ),
                            self.use_sudo,
                        ),
                        needs_root=self.use_sudo,
                        description=f"Fetch verified PPA key for {ppa.owner}/{ppa.name}",
                    )
                )
            line = (
                f"deb [signed-by=/usr/share/keyrings/distroforge-{ppa.slug}.gpg] "
                f"https://ppa.launchpadcontent.net/{ppa.owner}/{ppa.name}/ubuntu "
                f"{self.release.codename} main\n"
            )
            self.fs.write_text(source, line, f"Write verified PPA source: {line.strip()}")

    def _shed_stale(self, desired_slugs: set[str]) -> None:
        # A reused tree (unsquashfs -f does not prune extra files) still carries every
        # PPA source and keyring a previous run wrote. Drop the ones the current
        # options no longer request so a removed PPA cannot resurrect, exactly as the
        # release track, apt cache and proxy overlays already shed their own stale
        # files. distroforge-track.list belongs to the release track service, never to
        # a PPA (a PPA slug always carries "owner-name", so it can never be the bare
        # "track"), so it is reserved here -- release track sheds/rewrites it itself.
        sources_dir = self.root / "etc" / "apt" / "sources.list.d"
        for path in sorted(sources_dir.glob("distroforge-*.list")):
            if path.name == "distroforge-track.list":
                continue
            slug = path.stem.removeprefix("distroforge-")
            if slug not in desired_slugs:
                self.fs.remove(path, f"Shed stale PPA source {path.relative_to(self.root)}")
        keyrings_dir = self.root / "usr" / "share" / "keyrings"
        for path in sorted(keyrings_dir.glob("distroforge-*.gpg")):
            slug = path.stem.removeprefix("distroforge-")
            if slug not in desired_slugs:
                self.fs.remove(path, f"Shed stale PPA keyring {path.relative_to(self.root)}")

    def _resolve_fingerprint(self, ppa: PpaSpec) -> str | None:
        api_url = f"https://api.launchpad.net/1.0/~{ppa.owner}/+archive/ubuntu/{ppa.name}"
        if self.runner.dry_run:
            self.runner.run(
                CommandSpec(
                    argv=("launchpad-verify-ppa", api_url),
                    description=f"Resolve verified Launchpad signing key for {ppa.owner}/{ppa.name}",
                )
            )
            return "AUTO-LAUNCHPAD-FINGERPRINT"
        try:
            with urlopen(api_url, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, URLError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not verify PPA ppa:{ppa.owner}/{ppa.name}: {exc}") from exc
        fingerprint = payload.get("signing_key_fingerprint")
        if isinstance(fingerprint, str) and fingerprint.strip():
            return fingerprint.strip()
        return None
