from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner
from .fsops import FileSystemOps
from .releases import UbuntuRelease


@dataclass
class ReleaseTrackOptions:
    mode: str = "stable"
    devel_suite: str = "devel"
    enable_backports: bool = False
    enable_proposed: bool = False
    proposed_pin: int = 100
    enable_unattended_upgrades: bool = False
    full_upgrade: bool = False

    @property
    def enabled(self) -> bool:
        return (
            self.mode != "stable"
            or self.enable_backports
            or self.enable_proposed
            or self.enable_unattended_upgrades
            or self.full_upgrade
        )

    def summary(self) -> str:
        if not self.enabled:
            return "stable"
        flags = [self.mode]
        if self.enable_backports:
            flags.append("backports")
        if self.enable_proposed:
            flags.append(f"proposed-pin={self.proposed_pin}")
        if self.enable_unattended_upgrades:
            flags.append("auto-upgrades")
        if self.full_upgrade:
            flags.append("full-upgrade")
        return ", ".join(flags)


class ReleaseTrackService:
    def __init__(
        self,
        runner: CommandRunner,
        root: Path,
        release: UbuntuRelease,
        options: ReleaseTrackOptions,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.root = root
        self.release = release
        self.options = options
        self.use_sudo = use_sudo
        self.fs = FileSystemOps(runner, use_sudo)

    # Every file this service may write, so a reconfigure is a pure function of the
    # current options rather than an additive layer over a previous run's leftovers.
    _MANAGED_FILES = (
        "etc/apt/sources.list.d/distroforge-track.list",
        "etc/apt/preferences.d/distroforge-proposed",
        "etc/apt/apt.conf.d/90distroforge-release-track",
    )

    def configure(self) -> None:
        # Shed any file a previous run left before (re)writing, so disabling the
        # track -- or dropping --proposed -- actually removes its config instead of
        # leaving a stale suite or Default-Release pin behind for the next build to
        # inherit. A reused rootfs would otherwise carry a dead "devel" pin forward.
        for relative in self._MANAGED_FILES:
            self.fs.remove(self.root / relative, f"Remove stale release track config {relative}")
        if not self.options.enabled:
            return
        self._write_text("etc/apt/sources.list.d/distroforge-track.list", self._sources())
        if self.options.enable_proposed:
            self._write_text("etc/apt/preferences.d/distroforge-proposed", self._proposed_pin())
        if self.options.mode in {"devel", "rolling"}:
            self._write_text("etc/apt/apt.conf.d/90distroforge-release-track", self._apt_defaults())

    def apply_after_update(self) -> None:
        if not self.options.enabled:
            return
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        if self.options.enable_unattended_upgrades:
            chroot.run("apt-get", "-y", "install", "unattended-upgrades")
            self._write_text(
                "etc/apt/apt.conf.d/20auto-upgrades",
                'APT::Periodic::Update-Package-Lists "1";\n'
                'APT::Periodic::Unattended-Upgrade "1";\n',
            )
        if self.options.full_upgrade:
            chroot.run("apt-get", "-y", "full-upgrade")

    def _track_suite(self) -> str:
        # Ubuntu and Debian archives expose no symbolic "devel" suite -- it is only a
        # debootstrap script alias, so it 404s on the mirror and is rejected as an
        # APT::Default-Release value. The development series is addressed by its
        # codename, so resolve the "devel" placeholder to this release's codename;
        # an explicit codename override (e.g. --devel-suite) is still honoured.
        if self.options.mode in {"devel", "rolling"}:
            requested = (self.options.devel_suite or "").strip()
            if requested and requested != "devel":
                return requested
            return self.release.codename
        return self.release.codename

    def _sources(self) -> str:
        suite = self._track_suite()
        suites = [suite, f"{suite}-updates", f"{suite}-security"]
        if self.options.enable_backports:
            suites.append(f"{suite}-backports")
        if self.options.enable_proposed:
            suites.append(f"{suite}-proposed")
        lines = []
        for item in suites:
            uri = self.release.security_url if item.endswith("-security") else self.release.archive_url
            lines.append(f"deb {uri} {item} {' '.join(self.release.components)}")
        return "\n".join(lines) + "\n"

    def _proposed_pin(self) -> str:
        suite = self._track_suite()
        return (
            "Package: *\n"
            f"Pin: release a={suite}-proposed\n"
            f"Pin-Priority: {self.options.proposed_pin}\n"
        )

    def _apt_defaults(self) -> str:
        return f'APT::Default-Release "{self._track_suite()}";\n'

    def _write_text(self, relative: str, content: str) -> None:
        path = self.root / relative
        self.fs.write_text(path, content, f"Write release track config {relative}")
