from __future__ import annotations

import shutil
from pathlib import Path

from .command import CommandRunner, CommandSpec, sudo


class FileSystemOps:
    """File operations that can cross root-owned extracted filesystem boundaries."""

    def __init__(self, runner: CommandRunner, use_sudo: bool = True) -> None:
        self.runner = runner
        self.use_sudo = use_sudo

    def mkdir(self, path: Path, description: str | None = None) -> None:
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("mkdir", "-p", str(path)), description=description or f"Create {path}"))
            return
        try:
            path.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            self._run_privileged(("install", "-d", str(path)), description or f"Create protected directory {path}")

    def write_text(self, path: Path, content: str, description: str | None = None, mode: str | None = None) -> None:
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("write-file", str(path)), description=description or f"Write {path}"))
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            if mode:
                path.chmod(int(mode, 8))
        except PermissionError:
            if not self.use_sudo:
                raise
            script = 'install -d "$1" && cat > "$2" && { [ -z "$3" ] || chmod "$3" "$2"; }'
            self.runner.run(
                CommandSpec(
                    argv=sudo(("sh", "-c", script, "distroforge-write-text", str(path.parent), str(path), mode or ""), True),
                    stdin=content,
                    needs_root=True,
                    description=description or f"Write protected file {path}",
                )
            )

    def copy_file(
        self,
        source: Path,
        target: Path,
        description: str | None = None,
        mode: str = "0644",
        prefer_sudo: bool = False,
    ) -> None:
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("copy-file", str(source), str(target)), description=description or f"Copy {source}"))
            return
        if prefer_sudo and self.use_sudo:
            self.runner.run(
                CommandSpec(
                    argv=sudo(("install", "-D", "-m", mode, str(source), str(target)), True),
                    needs_root=True,
                    description=description or f"Copy protected file {source} to {target}",
                )
            )
            return
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            if mode:
                target.chmod(int(mode, 8))
        except PermissionError:
            if not self.use_sudo:
                raise
            self.runner.run(
                CommandSpec(
                    argv=sudo(("install", "-D", "-m", mode, str(source), str(target)), True),
                    needs_root=True,
                    description=description or f"Copy protected file {source} to {target}",
                )
            )

    def copy_tree(self, source: Path, target: Path, description: str | None = None) -> None:
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("copy-tree", str(source), str(target)), description=description or f"Copy {source}"))
            return
        try:
            if target.exists():
                shutil.rmtree(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, target)
        except PermissionError:
            if not self.use_sudo:
                raise
            script = 'install -d "$2" && rm -rf "$3" && cp -a "$1" "$3"'
            self.runner.run(
                CommandSpec(
                    argv=sudo(("sh", "-c", script, "distroforge-copy-tree", str(source), str(target.parent), str(target)), True),
                    needs_root=True,
                    description=description or f"Copy protected tree {source} to {target}",
                )
            )

    def rename(self, source: Path, target: Path, description: str | None = None) -> None:
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("mv", "-T", str(source), str(target)), description=description or f"Rename {source}"))
            return
        try:
            source.rename(target)
        except PermissionError:
            self._run_privileged(("mv", "-T", str(source), str(target)), description or f"Rename protected path {source}")

    def remove(self, target: Path, description: str | None = None) -> None:
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("rm", "-f", str(target)), description=description or f"Remove {target}"))
            return
        try:
            target.unlink(missing_ok=True)
        except PermissionError:
            self._run_privileged(("rm", "-f", str(target)), description or f"Remove protected file {target}")

    def remove_tree(self, target: Path, description: str | None = None) -> None:
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("rm-tree", str(target)), description=description or f"Remove {target}"))
            return
        if not target.exists():
            return
        try:
            shutil.rmtree(target)
        except PermissionError:
            self._run_privileged(("rm", "-rf", str(target)), description or f"Remove protected tree {target}")

    def chmod(self, target: Path, mode: str, description: str | None = None) -> None:
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("chmod", mode, str(target)), description=description or f"Chmod {target}"))
            return
        try:
            target.chmod(int(mode, 8))
        except PermissionError:
            self._run_privileged(("chmod", mode, str(target)), description or f"Chmod protected path {target}")

    def _run_privileged(self, argv: tuple[str, ...], description: str) -> None:
        if not self.use_sudo:
            raise PermissionError(description)
        self.runner.run(CommandSpec(argv=sudo(argv, True), needs_root=True, description=description))
