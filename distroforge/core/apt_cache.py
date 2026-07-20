from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .fsops import FileSystemOps


@dataclass
class AptCacheOptions:
    enabled: bool = False
    cache_dir: Path | None = None
    proxy_url: str | None = None


class AptCacheService:
    def __init__(self, runner: CommandRunner, root: Path, options: AptCacheOptions, use_sudo: bool = True) -> None:
        self.runner = runner
        self.root = root
        self.options = options
        self.use_sudo = use_sudo
        self.fs = FileSystemOps(runner, use_sudo)

    def configure(self) -> None:
        conf = self.root / "etc" / "apt" / "apt.conf.d" / "02distroforge-cache"
        if not self.options.enabled:
            # Own the file: a reused tree must not inherit a previous run's cache or
            # proxy pin. This runs before system_sync's apt-get update, so a dead
            # cache host left by an earlier build can no longer fail the new one.
            self.fs.remove(conf, "Remove stale apt cache config")
            return
        cache = self.options.cache_dir or Path(".distroforge-apt-cache")
        self.runner.run(CommandSpec(argv=("mkdir", "-p", str(cache)), description="Create apt package cache"))
        detail = f"Configure apt cache at {cache}"
        if self.options.proxy_url:
            detail = f"Configure apt proxy {self.options.proxy_url}"
        content = [f'Dir::Cache::archives "{cache}";\n']
        if self.options.proxy_url:
            content.append(f'Acquire::http::Proxy "{self.options.proxy_url}";\n')
        self.fs.write_text(conf, "".join(content), detail)
