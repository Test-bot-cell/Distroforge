from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner, CommandSpec


@dataclass
class SecureBootOptions:
    enabled: bool = False
    mok_key: str | None = None
    mok_cert: str | None = None
    sign_modules: bool = False
    warn_unsigned_modules: bool = True


class SecureBootService:
    def __init__(self, runner: CommandRunner, root: Path, options: SecureBootOptions, use_sudo: bool = True) -> None:
        self.runner = runner
        self.root = root
        self.options = options
        self.use_sudo = use_sudo

    def apply(self) -> None:
        if not self.options.enabled:
            return
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        chroot.run("apt-get", "-y", "install", "sbsigntool", "mokutil")
        if self.options.sign_modules:
            if not self.options.mok_key or not self.options.mok_cert:
                self.runner.run(
                    CommandSpec(
                        argv=("secureboot-warning", "module signing requested without MOK key/cert"),
                        description="Warn about incomplete Secure Boot signing configuration",
                    )
                )
            else:
                kernel = _latest_kernel(self.root)
                key = self._target_path(Path(self.options.mok_key))
                cert = self._target_path(Path(self.options.mok_cert))
                sign_tool = f"/usr/src/linux-headers-{kernel}/scripts/sign-file"
                modules_dir = self.root / "lib" / "modules" / kernel
                modules = sorted(
                    [
                        "/" + str(path.relative_to(self.root)).replace("\\", "/")
                        for path in modules_dir.rglob("*")
                        if path.is_file() and (path.name.endswith(".ko") or path.name.endswith(".ko.xz"))
                    ]
                )
                for module in modules:
                    chroot.run(sign_tool, "sha256", key, cert, module)
        if self.options.warn_unsigned_modules:
            kernel = _latest_kernel(self.root)
            modules_dir = self.root / "lib" / "modules" / kernel
            sample = [
                "/" + str(path.relative_to(self.root)).replace("\\", "/")
                for path in sorted(modules_dir.rglob("*"))
                if path.is_file() and (path.name.endswith(".ko") or path.name.endswith(".ko.xz"))
            ][:20]
            self.runner.run(
                CommandSpec(
                    argv=("secureboot-modules-sample", kernel, *sample),
                    description="Sample kernel modules for Secure Boot review",
                )
            )

    def _target_path(self, path: Path) -> str:
        try:
            relative = path.resolve().relative_to(self.root.resolve())
            return "/" + str(relative).replace("\\", "/")
        except Exception:
            return str(path).replace("\\", "/")


def _latest_kernel(root: Path) -> str:
    modules_root = root / "lib" / "modules"
    if not modules_root.exists():
        raise ValueError("No /lib/modules directory found in target root")
    kernels = [p.name for p in modules_root.iterdir() if p.is_dir()]
    if not kernels:
        raise ValueError("No installed kernels found under /lib/modules")
    kernels.sort()
    return kernels[-1]
