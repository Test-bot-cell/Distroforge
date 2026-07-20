from __future__ import annotations

import platform
from dataclasses import dataclass
from pathlib import Path

from .apt import PackagePlan
from .chroot import ChrootService
from .command import CommandRunner, CommandSpec, sudo
from .fsops import FileSystemOps
from .releases import UbuntuRelease

# Architectures that boot via legacy BIOS (and therefore need a GRUB El Torito
# image). Everything else (arm64, riscv64, …) is EFI-only on optical/USB media.
_BIOS_ARCHES = {"amd64", "i386"}
_HOST_ARCH_BY_MACHINE = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "armhf",
    "armhf": "armhf",
    "ppc64le": "ppc64el",
    "ppc64el": "ppc64el",
    "riscv64": "riscv64",
    "s390x": "s390x",
}


def host_dpkg_arch() -> str:
    machine = platform.machine().lower()
    return _HOST_ARCH_BY_MACHINE.get(machine, machine)


@dataclass
class BootstrapOptions:
    arch: str = "amd64"
    variant: str = "minbase"
    mirror: str | None = None
    base_packages: list[str] | None = None


class BootstrapService:
    def __init__(
        self,
        runner: CommandRunner,
        release: UbuntuRelease,
        root: Path,
        iso_root: Path,
        options: BootstrapOptions | None = None,
        use_sudo: bool = True,
    ) -> None:
        self.runner = runner
        self.release = release
        self.root = root
        self.iso_root = iso_root
        self.options = options or BootstrapOptions()
        self.use_sudo = use_sudo
        self.fs = FileSystemOps(runner, use_sudo)

    def create_rootfs(self) -> None:
        if self._rootfs_ready():
            self.runner.run(
                CommandSpec(
                    argv=("bootstrap-rootfs-reuse", str(self.root)),
                    description="Reuse existing bootstrap rootfs",
                )
            )
            self._reset_apt_overlays()
            return
        if self.root.exists() and any(self.root.iterdir()):
            raise ValueError(
                f"Bootstrap target {self.root} is non-empty but incomplete. "
                "Clean the work/filesystem directory or choose a new work directory before retrying."
            )
        self.fs.mkdir(self.root, "Create bootstrap rootfs directory")
        if self.options.arch != host_dpkg_arch():
            self.runner.run(
                CommandSpec(
                    argv=("qemu-user-static-required", self.options.arch, host_dpkg_arch()),
                    description=(
                        f"Cross-arch bootstrap {host_dpkg_arch()} -> {self.options.arch} "
                        "needs qemu-user-static and binfmt registered on the host"
                    ),
                )
            )
        mirror = self.options.mirror or self.release.archive_url
        tool = "mmdebstrap" if self.runner.has_binary("mmdebstrap") else "debootstrap"
        if tool == "mmdebstrap":
            argv = (
                "mmdebstrap",
                f"--variant={self.options.variant}",
                f"--architectures={self.options.arch}",
                self.release.codename,
                str(self.root),
                mirror,
            )
        else:
            argv = (
                "debootstrap",
                f"--variant={self.options.variant}",
                "--arch",
                self.options.arch,
                self.release.codename,
                str(self.root),
                mirror,
            )
        self.runner.run(
            CommandSpec(
                argv=sudo(argv, self.use_sudo),
                needs_root=self.use_sudo,
                description=f"Bootstrap minimal {self.release.label} rootfs with {tool}",
            )
        )

    def install_live_base(self) -> None:
        plan = PackagePlan(install=self._base_packages()).normalized()
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        chroot.mount_runtime()
        try:
            chroot.run("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update")
            chroot.run("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "install", *plan.install)
            chroot.run("update-initramfs", "-c", "-k", "all")
        finally:
            chroot.unmount_runtime()

    def create_iso_tree(self) -> None:
        self.fs.mkdir(self.iso_root / self.release.livefs, "Create live filesystem ISO directory")
        self.fs.write_text(
            self.iso_root / ".disk" / "info",
            f"{self.release.label} live media\n",
            "Write live ISO disk info",
        )
        self.fs.write_text(
            self.iso_root / "boot" / "grub" / "grub.cfg",
            (
                "serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1\n"
                "terminal_input console serial\n"
                "terminal_output console serial\n"
                "set timeout=5\n"
                f"menuentry \"Try live system\" {{ linux /{self.release.livefs}/vmlinuz boot=casper console=tty0 console=ttyS0,115200n8; initrd /{self.release.livefs}/initrd }}\n"
            ),
            "Write live ISO GRUB menu",
        )
        self._create_grub_eltorito_image()
        boot_dir = self.root / "boot"
        vmlinuz = sorted(boot_dir.glob("vmlinuz-*"))
        initrd = sorted(boot_dir.glob("initrd.img-*"))
        if self.runner.dry_run:
            vmlinuz_src = boot_dir / "vmlinuz-dry-run"
            initrd_src = boot_dir / "initrd.img-dry-run"
        elif not vmlinuz or not initrd:
            raise ValueError("Bootstrap rootfs is missing vmlinuz-* or initrd.img-* under /boot")
        else:
            vmlinuz_src = vmlinuz[-1]
            initrd_src = initrd[-1]
        live_dir = self.iso_root / self.release.livefs
        vmlinuz_dst = live_dir / "vmlinuz"
        initrd_dst = live_dir / "initrd"
        self._copy_boot_artifact(vmlinuz_src, vmlinuz_dst, "Copy kernel into casper")
        self._copy_boot_artifact(initrd_src, initrd_dst, "Copy initrd into casper")

    def prepare(self) -> None:
        self.create_rootfs()
        self.install_live_base()
        self.create_iso_tree()

    def _copy_boot_artifact(self, source: Path, target: Path, description: str) -> None:
        self.fs.copy_file(source, target, description, prefer_sudo=self.use_sudo)

    def _create_grub_eltorito_image(self) -> None:
        if self.options.arch not in _BIOS_ARCHES:
            self.runner.run(
                CommandSpec(
                    argv=("bootstrap-bios-skip", self.options.arch),
                    description=f"Skip BIOS El Torito image: {self.options.arch} boots EFI-only",
                )
            )
            return
        grub_dir = self.iso_root / "boot" / "grub"
        image_dir = grub_dir / "i386-pc"
        core_img = image_dir / "core.img"
        eltorito = image_dir / "eltorito.img"
        self.fs.mkdir(image_dir, "Create GRUB BIOS boot image directory")
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("write-file", str(eltorito)), description="Plan GRUB El Torito boot image"))
            return
        self.runner.run(CommandSpec(argv=("grub-mkimage", "-O", "i386-pc", "-o", str(core_img), "-p", "/boot/grub", "biosdisk", "iso9660", "normal", "linux", "configfile", "search"), description="Build GRUB BIOS core image"))
        self.runner.run(CommandSpec(argv=("sh", "-c", f"cat /usr/lib/grub/i386-pc/cdboot.img '{core_img}' > '{eltorito}'"), description="Assemble GRUB El Torito boot image"))

    def _rootfs_ready(self) -> bool:
        return (
            self.root.exists()
            and (self.root / "var/lib/dpkg/status").exists()
            and ((self.root / "etc/os-release").exists() or (self.root / "usr/lib/os-release").exists())
        )

    def _reset_apt_overlays(self) -> None:
        # A reused rootfs still carries every APT customization a previous run wrote
        # (release track, proxy, cache, PPAs, the -proposed pin). None of it may
        # leak into the pristine live-base install that runs next: a stale
        # ``APT::Default-Release`` pin in particular makes apt reject the whole run
        # ("E: The value 'devel' is invalid for APT::Default-Release"). Shed every
        # DistroForge-managed overlay so the base install sees the apt state a fresh
        # bootstrap would; configure_repositories re-derives them all afterwards from
        # the current options. The base sources (sources.list and the deb822
        # distroforge.sources a mirror run leaves) are deliberately preserved -- they
        # are the only working repository when a mirror is configured.
        apt = self.root / "etc/apt"
        stale = [
            *sorted((apt / "apt.conf.d").glob("*distroforge*")),
            *sorted((apt / "preferences.d").glob("*distroforge*")),
            *sorted((apt / "sources.list.d").glob("distroforge-*.list")),
        ]
        for path in stale:
            self.fs.remove(path, f"Shed stale APT overlay {path.relative_to(self.root)}")

    def _base_packages(self) -> list[str]:
        if self.options.base_packages is not None:
            return self.options.base_packages
        if self.release.family == "debian":
            common = [
                "debian-standard",
                "live-boot",
                "systemd-sysv",
                "sudo",
                "network-manager",
                "locales",
                "ca-certificates",
            ]
        else:
            common = [
                "ubuntu-minimal",
                "casper",
                "systemd-sysv",
                "sudo",
                "network-manager",
                "locales",
                "ca-certificates",
            ]
        return [*common, *self._kernel_packages(), *self._grub_packages()]

    def _kernel_packages(self) -> list[str]:
        if self.release.family == "debian":
            return [f"linux-image-{self.options.arch}"]
        # Ubuntu's linux-generic meta-package resolves to the correct per-arch kernel.
        return ["linux-generic"]

    def _grub_packages(self) -> list[str]:
        arch = self.options.arch
        packages: list[str] = []
        if arch in _BIOS_ARCHES:
            packages.append("grub-pc-bin")
        packages.append(f"grub-efi-{arch}-bin")
        if self.release.family != "debian" and arch in {"amd64", "arm64"}:
            packages.append("shim-signed")
        return packages
