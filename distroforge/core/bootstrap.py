from __future__ import annotations

import platform
from collections.abc import Iterable
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


@dataclass(frozen=True)
class _EfiArch:
    """Where an arch keeps its EFI payloads, and what they must be called on the ESP.

    None of these names is decoration. Firmware auto-boots removable media only from
    ``EFI/BOOT/BOOT<arch>.EFI``, and shim chain-loads ``grub<arch>.efi`` by that exact
    leafname out of its own directory, so a rename anywhere here silently produces
    media that no machine will start.

    ``bin_suffix`` exists because the package name does not follow the dpkg
    architecture: i386 builds ``grub-efi-ia32-bin``, and there has never been a
    ``grub-efi-i386-bin`` to install.
    """

    boot_leaf: str
    grub_leaf: str
    grub_dir: str
    shim_prefix: str
    mok_leaf: str
    bin_suffix: str


_EFI_ARCHES = {
    "amd64": _EfiArch("BOOTX64.EFI", "grubx64.efi", "x86_64-efi", "shimx64", "mmx64.efi", "amd64"),
    "i386": _EfiArch("BOOTIA32.EFI", "grubia32.efi", "i386-efi", "shimia32", "mmia32.efi", "ia32"),
    "arm64": _EfiArch("BOOTAA64.EFI", "grubaa64.efi", "arm64-efi", "shimaa64", "mmaa64.efi", "arm64"),
}
# An El Torito boot image is addressed in 512-byte blocks by a 16-bit field, so the
# ESP may not exceed 65535 of them. Slack covers the FAT itself plus the directory
# entries; measured at 256 KiB against a real staging run, which left 1.4 MB free on
# a 4 MiB image holding 2.7 MB of payload.
_ESP_MAX_BLOCKS = 65535
_ESP_SLACK_BYTES = 256 * 1024
# mformat stamps a random volume serial unless told otherwise, which would make two
# builds of the same tree differ. Pin it so the ESP is reproducible; the value is
# just "DFOR" in hex.
_ESP_SERIAL = "44464f52"
_ESP_LABEL = "DFORGE_EFI"
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


def _esp_blocks(sources: Iterable[Path]) -> int:
    """512-byte blocks for a FAT ESP holding ``sources``, or raise if it cannot fit.

    Rounded up to a whole track (32 sectors) because that is the geometry mformat is
    given, and floored at 1 MiB so a FAT12 image always has room for its own tables.
    Raising rather than truncating is the point: an oversized image would be silently
    clipped by the 16-bit El Torito block count and the media would not boot.
    """
    total = sum(source.stat().st_size for source in sources) + _ESP_SLACK_BYTES
    blocks = max(2048, -(-total // 512))
    blocks = -(-blocks // 32) * 32
    if blocks > _ESP_MAX_BLOCKS:
        raise ValueError(
            f"UEFI boot payloads need {blocks} blocks of 512 bytes, but an El Torito "
            f"boot image may not exceed {_ESP_MAX_BLOCKS}"
        )
    return blocks


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
        self._create_grub_efi_image()
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

    def _efi_payloads(self, layout: _EfiArch) -> list[tuple[Path, str]]:
        """``(source inside the rootfs, leafname on the ESP)`` for this architecture.

        The payloads come out of the *target* rootfs, never off the build host. That is
        not a preference: the host is whatever machine the maintainer happens to be on,
        and a UEFI-only host does not even carry the BIOS GRUB the sibling method reads.
        ``_grub_packages`` puts everything needed inside the target, and both candidates
        are already there today without adding a single package -- ``shim-signed``
        depends on ``grub-efi-<arch>-signed``, and ``grub-efi-<arch>-bin`` depends on
        ``grub-efi-<arch>-unsigned``, which is the one that ships a ready-to-boot
        monolithic image. ``grub-efi-<arch>-bin`` itself ships no ``.efi`` file at all,
        only modules, so there is nothing in it to copy.

        Shim plus the signed GRUB is preferred because that pair is what boots with
        Secure Boot on; the unsigned monolithic GRUB is the fallback and boots with it
        off. In dry-run the canonical names are returned unconditionally: probing the
        rootfs would make the plan differ between two hosts, and a plan has to be a
        function of the definition alone.
        """
        shim_dir = self.root / "usr/lib/shim"
        grub_root = self.root / "usr/lib/grub"
        signed = grub_root / f"{layout.grub_dir}-signed" / f"{layout.grub_leaf}.signed"
        monolithic = grub_root / layout.grub_dir / "monolithic" / layout.grub_leaf
        mok = shim_dir / layout.mok_leaf
        # Ubuntu ships shimx64.efi.signed.latest, Debian ships shimx64.efi.signed, and an
        # unsigned shimx64.efi exists in both. The family alone does not settle it, so the
        # candidates are tried in order of preference rather than derived.
        shims = [
            shim_dir / f"{layout.shim_prefix}.efi.signed.latest",
            shim_dir / f"{layout.shim_prefix}.efi.signed",
            shim_dir / f"{layout.shim_prefix}.efi",
        ]
        if self.runner.dry_run:
            return [(shims[0], layout.boot_leaf), (signed, layout.grub_leaf), (mok, layout.mok_leaf)]
        grub = next((candidate for candidate in (signed, monolithic) if candidate.exists()), None)
        if grub is None:
            raise ValueError(
                f"No UEFI GRUB image in the target rootfs: looked for {signed} and {monolithic}. "
                f"Expected grub-efi-{layout.bin_suffix}-bin to have pulled in "
                f"grub-efi-{layout.bin_suffix}-unsigned during the live-base install."
            )
        shim = next((candidate for candidate in shims if candidate.exists()), None)
        if shim is None:
            # No shim means no Secure Boot chain, so GRUB becomes the boot file itself.
            return [(grub, layout.boot_leaf)]
        payloads = [(shim, layout.boot_leaf), (grub, layout.grub_leaf)]
        if mok.exists():
            # Without MokManager shim can stop at a MOK prompt it cannot service.
            payloads.append((mok, layout.mok_leaf))
        return payloads

    def _create_grub_efi_image(self) -> None:
        """Stage the UEFI amorce: a FAT image holding the target's own EFI binaries.

        ``BootLayout.detect`` looks for ``boot/grub/efi.img`` before anything else, so
        that is what the El Torito EFI entry ends up pointing at -- a FAT filesystem is
        what such an entry is specified to contain, not a bare PE binary. The plain
        ``EFI/boot/*`` copies staged beside it are what reads the ISO *tree* rather than
        its boot record: a netboot setup, or a user copying the tree onto a FAT stick.

        The container is built on the host with mtools, which writes a FAT image as an
        ordinary file: no loop mount, no privilege, and mtools stays out of the delivered
        filesystem. What is *not* yet machine-verified is whether the staged GRUB finds
        ``boot/grub/grub.cfg`` from its own baked-in prefix -- a signed GRUB's prefix is
        fixed at Canonical's build time and cannot be re-set, which is the point of
        signing. The ``EFI/BOOT/grub.cfg`` trampoline below is the documented mitigation
        for that, and confirming it needs a real ISO booted under OVMF; see
        docs/build-pipeline.md.
        """
        arch = self.options.arch
        layout = _EFI_ARCHES.get(arch)
        if layout is None:
            self.runner.run(
                CommandSpec(
                    argv=("bootstrap-efi-skip", arch),
                    description=f"Skip UEFI boot image: no EFI payload layout known for {arch}",
                )
            )
            return
        payloads = self._efi_payloads(layout)
        tree = self.iso_root / "EFI" / "boot"
        self.fs.mkdir(tree, "Create ISO EFI boot directory")
        for source, leaf in payloads:
            self.fs.copy_file(source, tree / leaf.lower(), f"Stage {leaf} for UEFI boot", prefer_sudo=self.use_sudo)
        esp = self.iso_root / "boot" / "grub" / "efi.img"
        if self.runner.dry_run:
            self.runner.run(CommandSpec(argv=("write-file", str(esp)), description="Plan UEFI El Torito boot image"))
            return
        self.fs.mkdir(esp.parent, "Create GRUB EFI boot image directory")
        blocks = _esp_blocks(source for source, _ in payloads)
        self.runner.run(
            CommandSpec(
                argv=("mformat", "-C", "-i", str(esp), "-v", _ESP_LABEL, "-N", _ESP_SERIAL, "-T", str(blocks), "-h", "64", "-s", "32", "::"),
                description=f"Create {blocks * 512 // 1024} KiB FAT UEFI boot image",
            )
        )
        self.runner.run(CommandSpec(argv=("mmd", "-i", str(esp), "::/EFI", "::/EFI/BOOT"), description="Create EFI/BOOT on the UEFI boot image"))
        for source, leaf in payloads:
            self.runner.run(
                CommandSpec(
                    argv=("mcopy", "-i", str(esp), str(source), f"::/EFI/BOOT/{leaf}"),
                    description=f"Copy {leaf} into the UEFI boot image",
                )
            )
        self.runner.run(
            CommandSpec(
                argv=("mcopy", "-i", str(esp), "-", "::/EFI/BOOT/grub.cfg"),
                stdin=(
                    f"search --set=root --file /{self.release.livefs}/vmlinuz\n"
                    "set prefix=($root)/boot/grub\n"
                    "configfile $prefix/grub.cfg\n"
                ),
                description="Write the GRUB trampoline into the UEFI boot image",
            )
        )
        # Verified through mtools rather than a stat, because this has to prove the
        # payloads are really inside the image: a stat would pass on an empty file, and
        # the run above is a pipeline of four separate commands. It matters because a
        # half-built image still leaves the plain EFI/boot copies staged above, which
        # BootLayout.detect matches as its second candidate -- so the tree would be
        # reported "BIOS+UEFI" on media no firmware can start.
        self.runner.run(
            CommandSpec(
                argv=("mdir", "-/", "-i", str(esp), "::/EFI/BOOT"),
                description="Verify the UEFI boot image contents",
            )
        )

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
        layout = _EFI_ARCHES.get(arch)
        # The package name follows GRUB's EFI platform, not the dpkg architecture, and
        # for i386 the two differ: grub-efi-i386-bin has no candidate in any archive, so
        # every --bootstrap-arch i386 build used to die at apt-get install.
        suffix = layout.bin_suffix if layout else arch
        packages: list[str] = []
        if arch in _BIOS_ARCHES:
            packages.append("grub-pc-bin")
        packages.append(f"grub-efi-{suffix}-bin")
        if self.release.family != "debian" and arch in {"amd64", "arm64"}:
            # Named explicitly even though shim-signed already depends on it: the ESP is
            # staged from these two files, and a dependency we merely inherit could be
            # re-satisfied by the other arch's alternative without anything noticing.
            packages.extend(["shim-signed", f"grub-efi-{suffix}-signed"])
        return packages
