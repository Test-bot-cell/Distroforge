from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner, CommandSpec
from .host_artifacts import HostArtifactWriter


@dataclass
class SizeAnalysisOptions:
    enabled: bool = False
    top: int = 50


class SizeAnalysisService:
    def __init__(
        self,
        runner: CommandRunner,
        root: Path,
        output_dir: Path,
        options: SizeAnalysisOptions,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.root = root
        self.output_dir = output_dir
        self.options = options
        self.use_sudo = use_sudo

    def run(self) -> None:
        if not self.options.enabled:
            return
        target = self.output_dir / "size-report.txt"
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        result = self.runner.run(
            CommandSpec(
                argv=chroot.command("dpkg-query", "-Wf=${Installed-Size}\t${Package}\n").argv,
                needs_root=self.use_sudo,
                description="Collect installed package sizes",
            )
        )
        rows: list[tuple[int, str]] = []
        for line in result.stdout.splitlines():
            parts = line.split("\t", 1)
            if len(parts) != 2:
                continue
            try:
                size = int(parts[0].strip())
            except ValueError:
                continue
            pkg = parts[1].strip()
            if pkg:
                rows.append((size, pkg))
        rows.sort(key=lambda item: item[0], reverse=True)
        top = rows[: max(0, int(self.options.top))]
        lines = [f"{size}\t{pkg}" for size, pkg in top]
        HostArtifactWriter(self.runner).write_text(
            target,
            "\n".join(lines) + ("\n" if lines else ""),
            f"Write top {self.options.top} package size report",
        )
