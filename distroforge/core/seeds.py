from __future__ import annotations

from dataclasses import dataclass, field

from .command import CommandRunner, CommandSpec
from .fsops import FileSystemOps
from .project import Project


@dataclass
class SeedOptions:
    enabled: bool = True
    seed_name: str = "distroforge"
    packages: list[str] = field(default_factory=list)
    snaps: list[str] = field(default_factory=list)


class SeedService:
    def __init__(self, runner: CommandRunner, project: Project, options: SeedOptions, use_sudo: bool = True) -> None:
        self.runner = runner
        self.project = project
        self.options = options
        self.use_sudo = use_sudo
        self.iso = FileSystemOps(runner, use_sudo)

    def write(self) -> None:
        if not self.options.enabled:
            return
        seed_file = self.project.iso_root / "preseed" / f"{self.options.seed_name}.seed"
        manifest_file = self.project.root / "manifests" / f"{self.options.seed_name}.txt"
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("write-file", str(seed_file)), description="Write Ubuntu seed"))
            self.runner.run(
                CommandSpec(
                    argv=("write-file", str(manifest_file)),
                    description="Write requested manifest",
                )
            )
            return
        self.iso.write_text(seed_file, self.render_seed(), "Write Ubuntu seed")
        manifest_file.parent.mkdir(parents=True, exist_ok=True)
        manifest_file.write_text(self.render_manifest(), encoding="utf-8")

    def render_seed(self) -> str:
        packages = sorted(set([*self.project.packages, *self.options.packages]))
        lines = ["Task-Section: distroforge", f"Task-Description: {self.project.name}", ""]
        lines.extend(packages)
        return "\n".join(lines) + "\n"

    def render_manifest(self) -> str:
        packages = sorted(set([*self.project.packages, *self.options.packages]))
        snaps = sorted(set(self.options.snaps))
        lines = ["[packages]", *packages, "", "[snaps]", *snaps, ""]
        return "\n".join(lines)
