from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .chroot import ChrootService
from .command import CommandRunner, CommandSpec, sudo
from .integrity import IntegrityOptions, IntegrityService
from .releases import UbuntuRelease

KERNEL_RELEASES_JSON = "https://www.kernel.org/releases.json"


@dataclass
class KernelModuleOptions:
    enabled: bool = False
    build_mode: str = "module"
    channel: str = "stable"
    version: str | None = None
    source_url: str | None = None
    pgp_url: str | None = None
    source_sha256: str | None = None
    module_source: str | None = None
    module_subdir: str | None = None
    module_name: str | None = None
    verify_pgp: bool = True
    prune_obsolete_kernels: bool = False
    integrity_check: bool = True
    localversion: str = "-dforge"
    jobs: int = 0
    config_strategy: str = "current"
    install_debs: bool = True
    gpg_keyring: str | None = None
    gpg_fingerprint: str | None = None
    require_sha256: bool = False
    require_gpg: bool = False

    def summary(self) -> str:
        if not self.enabled:
            return "disabled"
        target = self.version or self.channel
        if self.build_mode == "full-deb":
            return f"full kernel .deb from kernel.org {target}"
        module = self.module_name or self.module_subdir or self.module_source or "module"
        return f"{module} from kernel.org {target}"


@dataclass(frozen=True)
class KernelRelease:
    channel: str
    version: str
    source: str
    pgp: str | None


class KernelModuleService:
    def __init__(
        self,
        runner: CommandRunner,
        root: Path,
        workdir: Path,
        options: KernelModuleOptions,
        release: UbuntuRelease | None = None,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.root = root
        self.workdir = workdir
        self.options = options
        self.release = release
        self.use_sudo = use_sudo

    def run(self) -> None:
        if not self.options.enabled:
            self.runner.run(
                CommandSpec(
                    argv=("kernel-module-skip", str(self.root)),
                    description="Kernel module phase disabled",
                )
            )
            return
        release = self.resolve_release()
        source_archive = self.root / "usr" / "src" / "distroforge-kernel" / f"linux-{release.version}.tar.xz"
        source_dir = self.root / "usr" / "src" / "distroforge-kernel" / f"linux-{release.version}"

        self._fetch_sources(release, source_archive)
        self._verify_sources(release, source_archive)
        self._extract_sources(source_archive, source_dir)
        if self.options.build_mode == "full-deb":
            self._prepare_full_kernel_build()
            self._configure_full_kernel(source_dir)
            self._build_kernel_debs(source_dir)
            self._install_kernel_debs(source_dir.parent)
        else:
            module_dir = self._module_dir(source_dir)
            self._prepare_target_headers()
            self._build_module(module_dir)
            self._install_module(module_dir)
        self._refresh_boot()
        self._verify_target()

    def resolve_release(self) -> KernelRelease:
        if self.options.source_url:
            version = self.options.version or self._version_from_url(self.options.source_url)
            return KernelRelease(
                channel=self.options.channel,
                version=version,
                source=self.options.source_url,
                pgp=self.options.pgp_url,
            )
        if self.runner.dry_run:
            version = self.options.version or f"<latest-{self.options.channel}>"
            self.runner.run(
                CommandSpec(
                    argv=("kernel-org-resolve", self.options.channel, KERNEL_RELEASES_JSON),
                    description="Resolve latest kernel.org release",
                )
            )
            return KernelRelease(
                channel=self.options.channel,
                version=version,
                source=f"https://cdn.kernel.org/pub/linux/kernel/<series>/linux-{version}.tar.xz",
                pgp=f"https://cdn.kernel.org/pub/linux/kernel/<series>/linux-{version}.tar.sign",
            )
        with urllib.request.urlopen(KERNEL_RELEASES_JSON, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
        for release in data["releases"]:
            if release["moniker"] == self.options.channel and not release.get("iseol", False):
                if self.options.version and release["version"] != self.options.version:
                    continue
                return KernelRelease(
                    channel=release["moniker"],
                    version=release["version"],
                    source=release["source"],
                    pgp=release.get("pgp"),
                )
        raise ValueError(f"No active kernel.org release found for {self.options.channel}")

    def _fetch_sources(self, release: KernelRelease, archive: Path) -> None:
        if not self.runner.dry_run:
            archive.parent.mkdir(parents=True, exist_ok=True)
        self.runner.run(
            CommandSpec(
                argv=sudo(("curl", "-L", "-o", str(archive), release.source), self.use_sudo),
                needs_root=self.use_sudo,
                description="Fetch kernel.org source tarball",
            )
        )
        if release.pgp:
            self.runner.run(
                CommandSpec(
                    argv=sudo(("curl", "-L", "-o", str(archive) + ".sign", release.pgp), self.use_sudo),
                    needs_root=self.use_sudo,
                    description="Fetch kernel.org source signature",
                )
            )

    def _verify_sources(self, release: KernelRelease, archive: Path) -> None:
        if self.options.integrity_check:
            integrity = IntegrityService(
                self.runner,
                IntegrityOptions(
                    strict=self.options.require_sha256 or self.options.require_gpg,
                    require_sha256=self.options.require_sha256,
                    require_gpg=self.options.require_gpg,
                    keyring=self.options.gpg_keyring,
                    fingerprint=self.options.gpg_fingerprint,
                    use_sudo=self.use_sudo,
                ),
            )
            integrity.verify_sha256(archive, self.options.source_sha256, "kernel source")
        if self.options.verify_pgp and release.pgp:
            IntegrityService(
                self.runner,
                IntegrityOptions(
                    require_gpg=self.options.require_gpg,
                    keyring=self.options.gpg_keyring,
                    fingerprint=self.options.gpg_fingerprint,
                    use_sudo=self.use_sudo,
                ),
            ).verify_gpg(Path(str(archive) + ".sign"), archive, "kernel.org source")
        elif self.options.require_gpg:
            raise ValueError("Kernel source GPG verification is required but no signature URL is available")

    def _extract_sources(self, archive: Path, source_dir: Path) -> None:
        self.runner.run(
            CommandSpec(
                argv=sudo(("tar", "-xf", str(archive), "-C", str(source_dir.parent)), self.use_sudo),
                needs_root=self.use_sudo,
                description="Extract kernel sources",
            )
        )

    def _prepare_target_headers(self) -> None:
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        chroot.run(
            "apt-get",
            "-y",
            "install",
            "build-essential",
            self._headers_package(),
            "kmod",
        )

    def _prepare_full_kernel_build(self) -> None:
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        chroot.run(
            "apt-get",
            "-y",
            "install",
            *self._kernel_build_packages(),
        )

    def _configure_full_kernel(self, source_dir: Path) -> None:
        kernel = self._latest_kernel()
        target_dir = self._target_path(source_dir)
        if self.options.config_strategy == "defconfig":
            command = f"cd {target_dir} && make defconfig"
        else:
            command = (
                f"cd {target_dir} && "
                f"if [ -f /boot/config-{kernel} ]; then "
                f"cp /boot/config-{kernel} .config; "
                "else make defconfig; fi && "
                "make olddefconfig"
            )
        ChrootService(self.runner, self.root, self.use_sudo).run("/bin/bash", "-lc", command)

    def _build_kernel_debs(self, source_dir: Path) -> None:
        target_dir = self._target_path(source_dir)
        jobs = self.options.jobs if self.options.jobs > 0 else "$(nproc)"
        localversion = self._shell_quote(self.options.localversion)
        command = f"cd {target_dir} && make -j{jobs} bindeb-pkg LOCALVERSION={localversion}"
        ChrootService(self.runner, self.root, self.use_sudo).run("/bin/bash", "-lc", command)

    def _install_kernel_debs(self, packages_dir: Path) -> None:
        if not self.options.install_debs:
            self.runner.run(
                CommandSpec(
                    argv=("kernel-deb-install-skip", self._target_path(packages_dir)),
                    description="Kernel .deb installation disabled",
                )
            )
            return
        target_dir = self._target_path(packages_dir)
        command = (
            f"set -e; debs=$(find {target_dir} -maxdepth 1 -name '*.deb' -print | sort); "
            'test -n "$debs"; dpkg -i $debs || apt-get -f -y install'
        )
        ChrootService(self.runner, self.root, self.use_sudo).run("/bin/bash", "-lc", command)

    def _build_module(self, module_dir: Path) -> None:
        kernel = self._latest_kernel()
        ChrootService(self.runner, self.root, self.use_sudo).run(
            "make",
            "-C",
            f"/lib/modules/{kernel}/build",
            f"M={self._target_path(module_dir)}",
            "modules",
        )

    def _install_module(self, module_dir: Path) -> None:
        kernel = self._latest_kernel()
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        chroot.run(
            "make",
            "-C",
            f"/lib/modules/{kernel}/build",
            f"M={self._target_path(module_dir)}",
            "modules_install",
        )
        chroot.run("depmod", "-a", kernel)

    def _refresh_boot(self) -> None:
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        if self.options.prune_obsolete_kernels:
            self._prune_obsolete_kernels(chroot)
        chroot.run("update-initramfs", "-u", "-k", "all")
        chroot.run("update-grub")

    def _prune_obsolete_kernels(self, chroot: ChrootService) -> None:
        keep = self._latest_kernel()
        patterns = (
            "linux-image-[0-9]*",
            "linux-modules-[0-9]*",
            "linux-modules-extra-[0-9]*",
            "linux-headers-[0-9]*",
        )
        result = self.runner.run(
            CommandSpec(
                argv=chroot.command("dpkg-query", "-W", "-f=${Package}\n", *patterns).argv,
                needs_root=self.use_sudo,
                description="List installed kernel packages",
            ),
            check=False,
        )
        candidates = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        old_packages = [pkg for pkg in candidates if keep not in pkg]
        if self.runner.dry_run and not old_packages:
            old_packages = ["<obsolete-kernel-packages>"]
        if old_packages:
            chroot.run("apt-get", "-y", "purge", *old_packages)
            chroot.run("apt-get", "-y", "autoremove", "--purge")
        modules_root = self.root / "lib" / "modules"
        for entry in sorted(modules_root.iterdir()) if modules_root.exists() else []:
            if entry.is_dir() and entry.name != keep:
                chroot.run("rm", "-rf", f"/lib/modules/{entry.name}")
        boot_root = self.root / "boot"
        if boot_root.exists():
            for file in boot_root.iterdir():
                if not file.is_file():
                    continue
                name = file.name
                if not (
                    name.startswith("vmlinuz-")
                    or name.startswith("initrd.img-")
                    or name.startswith("System.map-")
                    or name.startswith("config-")
                ):
                    continue
                if keep in name:
                    continue
                chroot.run("rm", "-f", f"/boot/{name}")

    def _verify_target(self) -> None:
        if not self.options.integrity_check:
            return
        module_name = self.options.module_name
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        chroot.run("update-grub", "--version")
        grub_cfg = self.root / "boot" / "grub" / "grub.cfg"
        if not self.runner.dry_run and grub_cfg.exists() and grub_cfg.stat().st_size == 0:
            raise ValueError("grub.cfg exists but is empty")
        if module_name:
            chroot.run("modinfo", module_name)

    def _latest_kernel(self) -> str:
        modules_root = self.root / "lib" / "modules"
        if self.runner.dry_run and not modules_root.exists():
            return self.options.version or "<target-kernel>"
        if not modules_root.exists():
            raise ValueError("No /lib/modules directory found in target root")
        candidates = [p.name for p in modules_root.iterdir() if p.is_dir()]
        if not candidates:
            raise ValueError("No installed kernels found under /lib/modules")
        candidates.sort(key=_version_key)
        return candidates[-1]

    def _module_dir(self, source_dir: Path) -> Path:
        if self.options.build_mode != "module":
            raise ValueError("Kernel module path is only used in module build mode")
        if self.options.module_source:
            return Path(self.options.module_source)
        if self.options.module_subdir:
            return source_dir / self.options.module_subdir
        raise ValueError("Kernel module phase requires module_source or module_subdir")

    def _target_path(self, path: Path) -> str:
        try:
            relative = path.resolve().relative_to(self.root.resolve())
            return "/" + str(relative).replace("\\", "/")
        except Exception:
            return str(path).replace("\\", "/")

    def _headers_package(self) -> str:
        if self.release and self.release.family == "debian":
            return "linux-headers-amd64"
        return "linux-headers-generic"

    def _kernel_build_packages(self) -> list[str]:
        packages = [
            "build-essential",
            "bc",
            "bison",
            "flex",
            "libssl-dev",
            "libelf-dev",
            "dwarves",
            "fakeroot",
            "rsync",
            "kmod",
            "cpio",
            "xz-utils",
            "dpkg-dev",
        ]
        if self.release and self.release.family == "debian":
            packages.append("linux-headers-amd64")
        else:
            packages.append("linux-headers-generic")
        return packages

    @staticmethod
    def _shell_quote(value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"

    @staticmethod
    def _version_from_url(url: str) -> str:
        filename = url.rsplit("/", 1)[-1]
        return filename.removeprefix("linux-").removesuffix(".tar.xz")


def _version_key(text: str) -> tuple[object, ...]:
    parts: list[object] = []
    buf = ""
    is_digit = False
    for ch in text:
        if ch.isdigit():
            if buf and not is_digit:
                parts.append(buf)
                buf = ""
            is_digit = True
            buf += ch
        else:
            if buf and is_digit:
                parts.append(int(buf))
                buf = ""
            is_digit = False
            buf += ch
    if buf:
        parts.append(int(buf) if is_digit else buf)
    return tuple(parts)
