from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .fsops import FileSystemOps
from .project import Project


@dataclass
class MirrorOptions:
    enabled: bool = False
    archive_mirror: str | None = None
    security_mirror: str | None = None
    country: str | None = None
    require_https: bool = True
    keep_canonical_security: bool = True
    deb822: bool = True


@dataclass(frozen=True)
class AptSourceEntry:
    types: tuple[str, ...]
    uris: tuple[str, ...]
    suites: tuple[str, ...]
    components: tuple[str, ...]
    signed_by: str | None = None

    def render_deb822(self) -> str:
        lines = [
            f"Types: {' '.join(self.types)}",
            f"URIs: {' '.join(self.uris)}",
            f"Suites: {' '.join(self.suites)}",
            f"Components: {' '.join(self.components)}",
        ]
        if self.signed_by:
            lines.append(f"Signed-By: {self.signed_by}")
        return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class MirrorDoctorIssue:
    code: str
    severity: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class MirrorDoctorReport:
    base: str
    suite: str
    format: str
    archive_mirror: str
    security_mirror: str
    backup_available: bool
    issues: tuple[MirrorDoctorIssue, ...] = field(default_factory=tuple)

    @property
    def status(self) -> str:
        if any(issue.severity == "error" for issue in self.issues):
            return "blocked"
        if self.issues:
            return "review"
        return "ok"

    def render_text(self) -> str:
        lines = [
            f"Mirror doctor: {self.status}",
            f"Base detected: {self.base}",
            f"Suite: {self.suite}",
            f"APT format: {self.format}",
            f"Archive mirror: {self.archive_mirror}",
            f"Security mirror: {self.security_mirror}",
            f"Backup available: {'yes' if self.backup_available else 'no'}",
        ]
        if not self.issues:
            lines.append("Broken entries: none")
        else:
            for issue in self.issues:
                lines.append(f"- {issue.severity} {issue.code}: {issue.message}")
        return "\n".join(lines) + "\n"

    def render_json(self) -> str:
        return json.dumps(
            {
                "status": self.status,
                "base": self.base,
                "suite": self.suite,
                "format": self.format,
                "archive_mirror": self.archive_mirror,
                "security_mirror": self.security_mirror,
                "backup_available": self.backup_available,
                "issues": [issue.to_dict() for issue in self.issues],
            },
            indent=2,
        )


class MirrorService:
    def __init__(
        self,
        runner: CommandRunner,
        project: Project,
        options: MirrorOptions | None = None,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.project = project
        self.options = options or MirrorOptions()
        self.use_sudo = use_sudo
        self.fs = FileSystemOps(runner, use_sudo)

    def doctor(self) -> MirrorDoctorReport:
        source_format = self._source_format()
        archive_mirror = self.options.archive_mirror or self.project.release.archive_url
        security_mirror = self._security_mirror()
        issues: list[MirrorDoctorIssue] = []
        for label, uri in (("archive", archive_mirror), ("security", security_mirror)):
            if self.options.require_https and uri.startswith("http://"):
                issues.append(
                    MirrorDoctorIssue(
                        "mirror-http",
                        "error",
                        f"{label} mirror must use HTTPS when require_https is enabled: {uri}",
                    )
                )
            if "\n" in uri or "\r" in uri or "\0" in uri:
                issues.append(MirrorDoctorIssue("mirror-uri-invalid", "error", f"{label} mirror contains invalid characters"))
        if self.project.release.family == "ubuntu" and not self.options.keep_canonical_security:
            issues.append(
                MirrorDoctorIssue(
                    "ubuntu-security-override",
                    "warning",
                    "Ubuntu security mirror is overridden; keep Canonical security unless you have a local policy.",
                )
            )
        return MirrorDoctorReport(
            base=self.project.release.family,
            suite=self.project.release.codename,
            format=source_format,
            archive_mirror=archive_mirror,
            security_mirror=security_mirror,
            backup_available=self._backup_dir().exists(),
            issues=tuple(issues),
        )

    def render_sources(self) -> str:
        entries = self._entries()
        return "\n".join(entry.render_deb822() for entry in entries)

    def apply(self, strict: bool = False) -> MirrorDoctorReport:
        report = self.doctor()
        if strict and report.status == "blocked":
            raise ValueError(report.render_text().strip())
        target = self._target_sources()
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("mirror-backup", str(self._apt_dir())), description="Backup APT sources"))
            self.runner.run(CommandSpec(argv=("write-file", str(target)), description="Write deb822 mirror sources"))
            return report
        self.backup()
        self.fs.write_text(target, self.render_sources(), "Write deb822 mirror sources")
        legacy = self._apt_dir() / "sources.list"
        if legacy.exists():
            self.fs.write_text(
                legacy,
                "# Managed by DistroForge mirror layer; see sources.list.d/distroforge.sources\n",
                "Mark legacy sources.list as managed",
            )
        return report

    def backup(self) -> Path:
        backup_dir = self._backup_dir()
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("mirror-backup", str(self._apt_dir())), description="Backup APT sources"))
            return backup_dir
        backup_dir.mkdir(parents=True, exist_ok=True)
        for relative in ("sources.list", "sources.list.d"):
            source = self._apt_dir() / relative
            target = backup_dir / relative
            if source.is_dir():
                if target.exists():
                    shutil.rmtree(target)
                if self.use_sudo:
                    self.fs.copy_tree(source, target, f"Backup protected APT source tree {relative}")
                else:
                    shutil.copytree(source, target)
            elif source.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                if self.use_sudo:
                    self.fs.copy_file(source, target, f"Backup protected APT source {relative}")
                else:
                    shutil.copy2(source, target)
        (backup_dir / "BACKUPINFO").write_text(
            f"Created: {datetime.now(UTC).isoformat()}\nProject: {self.project.name}\n",
            encoding="utf-8",
        )
        return backup_dir

    def restore(self) -> Path:
        backup_dir = self._backup_dir()
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("mirror-restore", str(backup_dir)), description="Restore APT sources backup"))
            return backup_dir
        if not backup_dir.exists():
            raise FileNotFoundError(f"No mirror backup exists at {backup_dir}")
        for relative in ("sources.list", "sources.list.d"):
            source = backup_dir / relative
            target = self._apt_dir() / relative
            if source.is_dir():
                if target.exists():
                    self.fs.remove_tree(target, f"Remove current APT source tree {relative}")
                self.fs.copy_tree(source, target, f"Restore APT source tree {relative}")
            elif source.exists():
                self.fs.copy_file(source, target, f"Restore APT source {relative}")
        return backup_dir

    def _entries(self) -> tuple[AptSourceEntry, ...]:
        archive_mirror = self.options.archive_mirror or self.project.release.archive_url
        security_mirror = self._security_mirror()
        archive_suites = tuple(suite for suite in self.project.release.apt_suites if not suite.endswith("-security"))
        security_suites = tuple(suite for suite in self.project.release.apt_suites if suite.endswith("-security"))
        signed_by = _default_keyring(self.project.release.family)
        entries = [
            AptSourceEntry(
                types=("deb",),
                uris=(archive_mirror,),
                suites=archive_suites,
                components=self.project.release.components,
                signed_by=signed_by,
            )
        ]
        if security_suites:
            entries.append(
                AptSourceEntry(
                    types=("deb",),
                    uris=(security_mirror,),
                    suites=security_suites,
                    components=self.project.release.components,
                    signed_by=signed_by,
                )
            )
        return tuple(entries)

    def _security_mirror(self) -> str:
        if self.project.release.family == "ubuntu" and self.options.keep_canonical_security:
            return self.project.release.security_url
        return self.options.security_mirror or self.project.release.security_url

    def _source_format(self) -> str:
        if (self._apt_dir() / "sources.list.d").exists() and list((self._apt_dir() / "sources.list.d").glob("*.sources")):
            return "deb822"
        if (self._apt_dir() / "sources.list").exists():
            return "one-line"
        return "missing"

    def _apt_dir(self) -> Path:
        return self.project.squashfs_root / "etc" / "apt"

    def _target_sources(self) -> Path:
        return self._apt_dir() / "sources.list.d" / "distroforge.sources"

    def _backup_dir(self) -> Path:
        return self.project.workdir / "apt-sources.backup"


def _default_keyring(family: str) -> str:
    if family == "debian":
        return "/usr/share/keyrings/debian-archive-keyring.gpg"
    return "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
