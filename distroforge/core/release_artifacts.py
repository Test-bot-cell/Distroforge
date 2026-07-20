from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .command import CommandRunner, CommandSpec
from .host_artifacts import HostArtifactWriter
from .integrity import IntegrityService


@dataclass
class ReleaseArtifactOptions:
    enabled: bool = True
    sign: bool = False
    gpg_key: str | None = None


class ReleaseArtifactService:
    def __init__(
        self,
        runner: CommandRunner,
        output_dir: Path,
        iso_path: Path,
        options: ReleaseArtifactOptions,
    ) -> None:
        self.runner = runner
        self.output_dir = output_dir
        self.iso_path = iso_path
        self.options = options

    def write(self) -> None:
        if not self.options.enabled:
            return
        sums_path = self.output_dir / "SHA256SUMS"
        if self.runner.dry_run:
            self.runner.run(
                CommandSpec(
                    argv=("write-file", str(sums_path)),
                    description="Write SHA256SUMS",
                )
            )
        else:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            result = self.runner.run(
                CommandSpec(
                    argv=("sha256sum", self.iso_path.name),
                    cwd=self.output_dir,
                    description="Compute ISO SHA256",
                )
            )
            sums_path.write_text(result.stdout, encoding="utf-8")
        HostArtifactWriter(self.runner).write_text(
            self.output_dir / "BUILDINFO",
            f"Build-Date: {datetime.now(UTC).isoformat()}\n"
            f"Artifact: {self.iso_path.name}\n"
            "Builder: DistroForge\n",
            "Write BUILDINFO",
        )
        if self.options.sign:
            argv = ["gpg", "--armor", "--detach-sign"]
            if self.options.gpg_key:
                argv.extend(["--local-user", self.options.gpg_key])
            argv.append(str(self.output_dir / "SHA256SUMS"))
            self.runner.run(CommandSpec(argv=tuple(argv), description="Sign SHA256SUMS"))
        IntegrityService(self.runner).write_manifest(
            self.output_dir / "INTEGRITY",
            {
                "artifact": self.iso_path.name,
                "sha256sums": "SHA256SUMS",
                "signature": "SHA256SUMS.asc" if self.options.sign else "unsigned",
            },
        )
