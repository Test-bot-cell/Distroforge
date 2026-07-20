from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner, CommandSpec, sudo
from .fsops import FileSystemOps
from .progress_parsers import apt_progress
from .releases import UbuntuRelease


@dataclass(frozen=True)
class Repository:
    suite: str
    components: tuple[str, ...]
    uri: str
    signed_by: str | None = None

    def source_line(self) -> str:
        options = f" [signed-by={self.signed_by}]" if self.signed_by else ""
        return f"deb{options} {self.uri} {self.suite} {' '.join(self.components)}"


def parse_repository_line(line: str) -> Repository:
    parts = line.split()
    if not parts or parts[0] != "deb":
        raise ValueError(f"Only deb repository lines are supported for now: {line!r}")
    if len(parts) < 4:
        raise ValueError(f"Incomplete repository line: {line!r}")
    signed_by: str | None = None
    offset = 1
    if parts[offset].startswith("["):
        option_parts: list[str] = []
        while offset < len(parts):
            option_parts.append(parts[offset])
            if parts[offset].endswith("]"):
                offset += 1
                break
            offset += 1
        options = " ".join(option_parts).strip("[]")
        for option in options.split():
            if option.startswith("signed-by="):
                signed_by = option.removeprefix("signed-by=")
    if len(parts) - offset < 3:
        raise ValueError(f"Incomplete repository line: {line!r}")
    return Repository(
        uri=parts[offset],
        suite=parts[offset + 1],
        components=tuple(parts[offset + 2 :]),
        signed_by=signed_by,
    )


def parse_repository_lines(lines: list[str]) -> list[Repository]:
    repositories: list[Repository] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        repositories.append(parse_repository_line(stripped))
    return repositories


@dataclass
class PackagePlan:
    install: list[str] = field(default_factory=list)
    remove: list[str] = field(default_factory=list)
    purge: bool = False

    def normalized(self) -> PackagePlan:
        return PackagePlan(
            install=sorted(set(self.install)),
            remove=sorted(set(self.remove) - set(self.install)),
            purge=self.purge,
        )


@dataclass
class AptService:
    runner: CommandRunner
    root: Path
    release: UbuntuRelease
    use_sudo: bool = True
    arch: str = "amd64"

    def default_repositories(self) -> list[Repository]:
        repos: list[Repository] = []
        for suite in self.release.apt_suites:
            uri = self.release.security_url if suite.endswith("-security") else self.release.archive_url
            repos.append(
                Repository(
                    suite=suite,
                    components=self.release.components,
                    uri=uri,
                )
            )
        return repos

    def render_sources(self, repositories: list[Repository] | None = None) -> str:
        repos = repositories or self.default_repositories()
        return "\n".join(repo.source_line() for repo in repos) + "\n"

    def sources_path(self) -> Path:
        return self.root / "etc" / "apt" / "sources.list"

    def write_sources(self, repositories: list[Repository] | None = None) -> None:
        path = self.sources_path()
        FileSystemOps(self.runner, self.use_sudo).write_text(
            path,
            self.render_sources(repositories),
            "Write apt sources.list",
        )

    def update(self) -> None:
        ChrootService(self.runner, self.root, self.use_sudo).run("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update")

    def apply_plan(
        self,
        plan: PackagePlan,
        *,
        on_progress: Callable[[float], None] | None = None,
    ) -> None:
        plan = plan.normalized()
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        streaming = on_progress is not None and not self.runner.dry_run
        if plan.install:
            install = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y"]
            if streaming:
                install += ["-o", "APT::Status-Fd=1"]
            install += ["install", *plan.install]
            self._run(chroot.command(*install), on_progress if streaming else None)
        if plan.remove:
            action = "purge" if plan.purge else "remove"
            chroot.run("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", action, *plan.remove)
            chroot.run("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "autoremove")

    def _run(self, spec: CommandSpec, on_progress: Callable[[float], None] | None) -> None:
        if on_progress is None:
            self.runner.run(spec)
            return

        def on_line(line: str) -> None:
            fraction = apt_progress(line)
            if fraction is not None:
                on_progress(fraction)

        self.runner.run_streaming(spec, on_line)

    def launch_synaptic(self) -> CommandSpec:
        apt_config = self._apt_config_path()
        FileSystemOps(self.runner, self.use_sudo).write_text(
            apt_config,
            self._synaptic_apt_config(),
            "Write Synaptic target apt configuration",
        )
        spec = CommandSpec(
            argv=sudo(("env", f"APT_CONFIG={apt_config}", "synaptic"), self.use_sudo),
            needs_root=self.use_sudo,
            description="Launch Synaptic against target root",
        )
        self.runner.run(spec)
        return spec

    def _apt_config_path(self) -> Path:
        return self.root / "tmp" / "distroforge-synaptic-apt.conf"

    def _synaptic_apt_config(self) -> str:
        root = str(self.root)
        return "\n".join(
            [
                f'Dir "{root}";',
                'Dir::State "var/lib/apt";',
                'Dir::State::status "var/lib/dpkg/status";',
                'Dir::Cache "var/cache/apt";',
                'Dir::Etc "etc/apt";',
                f'APT::Architecture "{self.arch}";',
                "",
            ]
        )
