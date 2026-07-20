from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec, sudo
from .host_artifacts import HostArtifactWriter


@dataclass
class IntegrityOptions:
    strict: bool = False
    require_sha256: bool = False
    require_gpg: bool = False
    keyring: str | None = None
    fingerprint: str | None = None
    use_sudo: bool = False

    def summary(self) -> str:
        flags = []
        if self.strict:
            flags.append("strict")
        if self.require_sha256:
            flags.append("sha256")
        if self.require_gpg:
            flags.append("gpg")
        if self.fingerprint:
            flags.append("fingerprint")
        return ", ".join(flags) if flags else "standard"


class IntegrityService:
    def __init__(self, runner: CommandRunner, options: IntegrityOptions | None = None) -> None:
        self.runner = runner
        self.options = options or IntegrityOptions()

    def verify_sha256(self, path: Path, sha256: str | None, description: str) -> None:
        if sha256:
            self.runner.run(
                CommandSpec(
                    argv=sudo(("sha256sum", "-c", "-"), self.options.use_sudo),
                    stdin=f"{sha256}  {path}\n",
                    needs_root=self.options.use_sudo,
                    description=f"Verify SHA256: {description}",
                )
            )
            return
        if self.options.strict or self.options.require_sha256:
            raise ValueError(f"Missing required SHA256 for {description}")
        self.runner.run(
            CommandSpec(
                argv=sudo(("sha256sum", str(path)), self.options.use_sudo),
                needs_root=self.options.use_sudo,
                description=f"Record SHA256: {description}",
            )
        )

    def verify_gpg(self, signature: Path, payload: Path, description: str) -> None:
        if self.options.require_gpg and not signature:
            raise ValueError(f"Missing required GPG signature for {description}")
        argv = ["gpg", "--verify"]
        if self.options.keyring:
            argv = ["gpg", "--no-default-keyring", "--keyring", self.options.keyring, "--verify"]
        argv.extend([str(signature), str(payload)])
        self.runner.run(
            CommandSpec(
                argv=sudo(argv, self.options.use_sudo),
                needs_root=self.options.use_sudo,
                description=f"Verify GPG: {description}",
            )
        )
        if self.options.fingerprint:
            self.runner.run(
                CommandSpec(
                    argv=("gpg-fingerprint-assert", str(signature), self.options.fingerprint),
                    description=f"Assert GPG fingerprint for {description}",
                )
            )

    def write_manifest(self, target: Path, entries: dict[str, str]) -> None:
        lines = [f"{key}: {value}" for key, value in sorted(entries.items())]
        HostArtifactWriter(self.runner).write_text(
            target, "\n".join(lines) + "\n", "Write integrity manifest"
        )
