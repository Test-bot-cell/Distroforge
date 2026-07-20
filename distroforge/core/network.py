from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .command import CommandRunner
from .fsops import FileSystemOps


@dataclass
class NetworkOptions:
    netplan_dhcp: bool = False
    dns: list[str] | None = None
    apt_proxy: str | None = None


class NetworkService:
    def __init__(self, runner: CommandRunner, root: Path, options: NetworkOptions, use_sudo: bool = True) -> None:
        self.runner = runner
        self.root = root
        self.options = options
        self.use_sudo = use_sudo
        self.fs = FileSystemOps(runner, use_sudo)

    def apply(self) -> None:
        if self.options.netplan_dhcp:
            self._write("etc/netplan/01-distroforge.yaml", self._netplan())
        proxy_conf = self.root / "etc/apt/apt.conf.d/01distroforge-proxy"
        if self.options.apt_proxy:
            _validate_proxy_url(self.options.apt_proxy)
            self._write(
                "etc/apt/apt.conf.d/01distroforge-proxy",
                f'Acquire::http::Proxy "{self.options.apt_proxy}";\n',
            )
        else:
            # Own the file: a reused tree must not ship (or build against) a previous
            # run's apt proxy once it is no longer requested.
            self.fs.remove(proxy_conf, "Remove stale apt proxy config")

    def _netplan(self) -> str:
        nameservers = ""
        if self.options.dns:
            nameservers = "\n      nameservers:\n        addresses: [" + ", ".join(self.options.dns) + "]"
        return (
            "network:\n"
            "  version: 2\n"
            "  ethernets:\n"
            "    all:\n"
            "      match:\n"
            '        name: "*"\n'
            "      dhcp4: true"
            + nameservers
            + "\n"
        )

    def _write(self, relative: str, content: str) -> None:
        path = self.root / relative
        self.fs.write_text(path, content, f"Write network config {relative}")


def _validate_proxy_url(value: str) -> None:
    if any(ch in value for ch in ("\n", "\r", "\0")):
        raise ValueError("Invalid proxy URL: contains newline or NUL")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Invalid proxy URL scheme: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError("Invalid proxy URL: missing host")
