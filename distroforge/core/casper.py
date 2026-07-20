from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner, CommandSpec, sudo
from .fsops import FileSystemOps


@dataclass
class CasperMetadataService:
    runner: CommandRunner
    iso_root: Path
    filesystem_root: Path
    use_sudo: bool = True
    livefs: str = "casper"

    @property
    def casper_dir(self) -> Path:
        return self.iso_root / self.livefs

    @property
    def fs(self) -> FileSystemOps:
        return FileSystemOps(self.runner, self.use_sudo)

    def update_filesystem_size(self) -> None:
        self.fs.mkdir(self.casper_dir, f"Create {self.livefs} metadata directory")
        size_path = self.casper_dir / "filesystem.size"
        result = self.runner.run(
            CommandSpec(
                argv=sudo(("du", "-sx", "--block-size=1", str(self.filesystem_root)), self.use_sudo),
                needs_root=self.use_sudo,
                description=f"Compute {self.livefs} filesystem.size",
            )
        )
        size = result.stdout.split("\t", 1)[0].strip() if result.stdout else ""
        self.fs.write_text(size_path, size + "\n", f"Write {self.livefs} filesystem.size")

    def update_manifest(self) -> None:
        self.fs.mkdir(self.casper_dir, f"Create {self.livefs} metadata directory")
        manifest = self.casper_dir / "filesystem.manifest"
        chroot = ChrootService(self.runner, self.filesystem_root, self.use_sudo)
        result = self.runner.run(
            CommandSpec(
                argv=chroot.command("dpkg-query", "-W", "--showformat=${Package} ${Version}\n").argv,
                needs_root=self.use_sudo,
                description="Generate filesystem.manifest",
            )
        )
        desktop_manifest = self.casper_dir / "filesystem.manifest-desktop"
        self.fs.write_text(manifest, result.stdout, "Write filesystem.manifest")
        self.fs.write_text(desktop_manifest, result.stdout, "Write filesystem.manifest-desktop")

    def update_md5sums(self) -> None:
        md5_path = self.iso_root / "md5sum.txt"
        if self.runner.dry_run:
            self.fs.write_text(md5_path, "", "Write ISO md5sum.txt")
            return
        entries: list[Path] = []
        for path in self.iso_root.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(self.iso_root)
            if rel.as_posix() == "md5sum.txt":
                continue
            if rel.as_posix() == "isolinux/boot.cat":
                continue
            entries.append(path)
        entries.sort(key=lambda p: p.relative_to(self.iso_root).as_posix())
        lines: list[str] = []
        for path in entries:
            rel = path.relative_to(self.iso_root).as_posix()
            digest = hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest()
            lines.append(f"{digest}  ./{rel}")
        self.fs.write_text(md5_path, "\n".join(lines) + ("\n" if lines else ""), "Write ISO md5sum.txt")

    def update_all(self) -> None:
        self.update_manifest()
        self.update_filesystem_size()
        self.update_md5sums()
