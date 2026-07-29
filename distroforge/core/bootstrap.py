from __future__ import annotations

import json
import platform
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .apt import APT_UPDATE_ARGV, PackagePlan
from .chroot import ChrootService
from .command import CommandRunner, CommandSpec, sudo
from .fsops import FileSystemOps
from .releases import UbuntuRelease, read_os_release

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
# The two boot images a from-scratch bootstrap stages, as paths inside the ISO tree, named
# here so the ISO builder can *plan* them before they exist instead of probing a tree that
# is not there yet. See planned_boot_images below for why that matters.
BOOTSTRAP_BIOS_ELTORITO = "boot/grub/i386-pc/eltorito.img"
BOOTSTRAP_ESP = "boot/grub/efi.img"
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


def planned_boot_images(arch: str) -> tuple[str | None, str | None]:
    """``(BIOS El Torito image, ESP)`` this bootstrap will stage for ``arch``, as tree paths.

    ``BootLayout.detect`` answers the same question by looking at the tree, which is the
    right answer for a tree that exists and the wrong one for a plan. A first-ever
    ``distroforge iso-build`` -- a maintainer asking what the build is going to do, before
    any build has run -- found nothing under ``work/iso`` and planned
    ``xorriso -as mkisofs ... <tree>`` with no boot arguments whatsoever, described as
    "Rebuild bootable ISO tree (boot assets not detected)": a plan for a data disc, printed
    under the word "bootable".

    ``_efi_payloads`` already states the rule this restores -- "a plan has to be a function
    of the definition alone" -- and returns canonical names in dry-run for exactly that
    reason. The arch gates are the same two this module builds against, so an EFI-only arch
    plans no BIOS image and an arch with no known EFI layout plans no ESP, matching what
    ``_create_grub_eltorito_image`` and ``_create_grub_efi_image`` actually skip.
    """
    return (
        BOOTSTRAP_BIOS_ELTORITO if arch in _BIOS_ARCHES else None,
        BOOTSTRAP_ESP if arch in _EFI_ARCHES else None,
    )


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


# Bumped when the recorded fields change meaning. A record from another version is
# treated as no record at all rather than compared field by field, because a
# comparison against a schema this code does not know is not a comparison.
_BOOTSTRAP_STAMP_VERSION = 1
# The inputs that decide what a bootstrapped tree *is*, in the order they are worth
# reporting a difference in.
_IDENTITY_FIELDS = ("codename", "family", "arch", "variant", "mirror")


# What the phase *after* the bootstrap needs to find in the tree, and therefore what
# "a rootfs" means here. install_live_base's first act is `apt-get update` inside the
# chroot, so a tree with no apt is not a base this build can use, however cleanly the
# bootstrap tool exited -- and one did exit 0 without it, in the first real golden-path
# run: 23 seconds, and `env: 'apt-get': No such file or directory` five phases later,
# from a chroot, with the reason for the absence long since discarded.
#
# Each entry is a tuple of alternatives, because more than one path is a correct answer:
# os-release(5) allows either location, and dpkg's own tools live under /usr/bin with
# /bin a compatibility symlink on a merged-usr tree but not necessarily on a foreign one.
_ROOTFS_REQUIREMENTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("a dpkg database", ("var/lib/dpkg/status",)),
    ("an os-release", ("etc/os-release", "usr/lib/os-release")),
    ("dpkg", ("usr/bin/dpkg", "bin/dpkg")),
    ("apt-get", ("usr/bin/apt-get", "bin/apt-get")),
)


def missing_rootfs_requirements(root: Path) -> tuple[str, ...]:
    """What a tree lacks before it can be called a rootfs, named as a reader would.

    Returns descriptions rather than paths so a caller can put them in a sentence, and
    returns them all rather than the first, because "it has no apt-get" and "it has
    nothing at all" deserve different reactions from whoever reads the message.
    """
    return tuple(
        f"{label} ({' or '.join('/' + path for path in paths)})"
        for label, paths in _ROOTFS_REQUIREMENTS
        if not any((root / path).exists() for path in paths)
    )


@dataclass(frozen=True)
class RootfsVerdict:
    """What to do with whatever is already sitting at a bootstrap target.

    ``reason`` is filled for everything except a fully verified reuse -- including a
    reuse that could only be *partly* verified, so a caller can say "reused, and here
    is what could not be checked" without re-deriving anything.
    """

    state: str
    reason: str = ""


def bootstrap_stamp_path(root: Path) -> Path:
    """Where the identity of ``root`` is recorded: beside the tree, never inside it.

    Inside the tree would ship build bookkeeping into the image, which this project
    has already had to undo once for customization hooks. Beside it, the record shares
    the fate of the thing it describes: whatever removes the rootfs removes the claim
    about the rootfs, so a stale record cannot outlive its subject.
    """
    return root.with_name(f"{root.name}.bootstrap.json")


def bootstrap_identity(release: UbuntuRelease, options: BootstrapOptions) -> dict[str, object]:
    """The arguments that produced a tree, and therefore the key to reusing one.

    Exactly what the bootstrap tool is given, and nothing else. The package set is
    deliberately not part of it: the tool is passed only ``--include=ca-certificates``
    here, and ``install_live_base`` applies the set afterwards with apt against
    whatever tree exists, so keying on it would force a full re-bootstrap for an edit
    the next phase already handles. That choice has a cost and it is named rather than
    hidden -- see ``docs/build-pipeline.md``: shrinking the list leaves what it used to
    name installed in a reused tree, because apt is only ever asked to install.
    """
    return {
        "stamp_version": _BOOTSTRAP_STAMP_VERSION,
        "codename": release.codename,
        "family": release.family,
        "arch": options.arch,
        "variant": options.variant,
        "mirror": options.mirror or release.archive_url,
    }


def rootfs_verdict(root: Path, release: UbuntuRelease, options: BootstrapOptions) -> RootfsVerdict:
    """Decide once, here, what an existing bootstrap target is good for.

    This is the only place that answers the question. It used to be answered twice --
    by ``BootstrapService`` and again by the dry-run report -- from the same three-path
    test: a dpkg status file and an os-release. Three paths that exist say the tree is
    a Debian-family rootfs. They do not say it is *this* build's rootfs, and nothing
    checked that: the target path is fixed at ``work/filesystem`` with no suite in it,
    nothing cleans it between runs, and no code compared the tree's release to the
    project's. Point a project at another release and rebuild, and the previous
    suite's tree was silently reused and shipped.

    States: ``absent``, ``empty``, ``unreadable``, ``incomplete``, ``mismatch``,
    ``reusable``. Only ``reusable`` may be reused, and a ``mismatch`` is refused rather
    than repaired -- deleting a tree the user may have spent an hour on, to recover
    from a question they can answer in one command, is not this code's decision.
    """
    if not root.exists():
        return RootfsVerdict("absent")
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        return RootfsVerdict("unreadable", str(exc))
    if not entries:
        return RootfsVerdict("empty")
    missing = missing_rootfs_requirements(root)
    if missing:
        # The reason used to be empty here, and the test used to be two paths: a dpkg
        # status file and an os-release. A tree carrying both and no package manager
        # passed as *complete*, so a re-run would have reused the very tree whose
        # missing apt-get had just stopped the build.
        return RootfsVerdict("incomplete", f"it has no {', no '.join(missing)}")
    return _identity_verdict(root, release, options)


def _identity_verdict(
    root: Path, release: UbuntuRelease, options: BootstrapOptions
) -> RootfsVerdict:
    """Compare a complete tree against the base this build wants, best evidence first.

    The record beside the tree is authoritative when there is one, because it carries
    the arch, the variant and the mirror -- differences a tree cannot be asked about
    afterwards. When there is none, the tree is still not unknowable: os-release(5)
    has it declare its own suite, which is the difference that actually bit. That leg
    matters for two populations at once, trees bootstrapped before this record existed
    and trees DistroForge never created at all.

    The last branch is the only one that lets an unverified tree through, and it says
    so in ``reason`` instead of returning a bare pass. Refusing there would break every
    hand-assembled tree that carries no codename, to guard against a case no evidence
    points at; passing silently would claim a check that did not happen.
    """
    wanted = bootstrap_identity(release, options)
    recorded = _read_stamp(bootstrap_stamp_path(root))
    if recorded is not None:
        for field_name in _IDENTITY_FIELDS:
            if recorded.get(field_name) != wanted[field_name]:
                return RootfsVerdict(
                    "mismatch",
                    f"it was bootstrapped with {field_name}={recorded.get(field_name)!r} "
                    f"and this build wants {wanted[field_name]!r}",
                )
        return RootfsVerdict("reusable")
    declared = read_os_release(root)
    codename = declared.get("VERSION_CODENAME") or declared.get("UBUNTU_CODENAME")
    if codename and codename != release.codename:
        return RootfsVerdict(
            "mismatch",
            f"it declares itself to be {codename!r} and this build wants {release.codename!r}",
        )
    if codename:
        return RootfsVerdict(
            "reusable",
            f"no bootstrap record beside it, so only the {codename!r} it declares was matched",
        )
    return RootfsVerdict(
        "reusable",
        "no bootstrap record beside it and it declares no codename, so its base is unverified",
    )


def _read_stamp(stamp: Path) -> dict[str, object] | None:
    """The recorded identity, or None for anything this code cannot read as one.

    Absent, unreadable, not JSON, not an object, or written by another stamp version:
    all the same answer, because each of them means the record cannot be compared. It
    degrades to the os-release leg rather than to a pass or a refusal.
    """
    try:
        loaded = json.loads(stamp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(loaded, dict) or loaded.get("stamp_version") != _BOOTSTRAP_STAMP_VERSION:
        return None
    return loaded


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
        verdict = rootfs_verdict(self.root, self.release, self.options)
        if verdict.state == "reusable":
            self.runner.run(
                CommandSpec(
                    argv=("bootstrap-rootfs-reuse", str(self.root)),
                    description="Reuse existing bootstrap rootfs",
                )
            )
            self._reset_apt_overlays()
            return
        if verdict.state == "mismatch":
            raise ValueError(
                f"Bootstrap target {self.root} was built from a different base: {verdict.reason}. "
                "Clean the work/filesystem directory or choose a new work directory "
                "before retrying."
            )
        if verdict.state == "unreadable":
            raise ValueError(
                f"Bootstrap target {self.root} cannot be inspected ({verdict.reason}). "
                "Fix ownership/permissions or choose a fresh work directory before retrying."
            )
        if verdict.state == "incomplete":
            raise ValueError(
                f"Bootstrap target {self.root} is non-empty but incomplete: {verdict.reason}. "
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
        # Both of these are asked for by name because --variant=minbase does not promise
        # either one, and the next phase runs apt-get inside this tree.
        #
        # apt: debootstrap(8) defines minbase as "required packages and apt" and adds apt
        # itself; mmdebstrap(1) defines required/minbase as the essential set plus
        # Priority:required, which never mentions apt. The same string therefore means two
        # different package sets depending on which tool has_binary() picked. It looked
        # equivalent only because package sets also pull "the direct and indirect hard
        # dependencies" (mmdebstrap(1), VARIANTS), so apt kept arriving as somebody else's
        # dependency -- until the first real golden-path run, where it did not: mmdebstrap
        # exited 0 in 23 seconds, correctly, having installed exactly what was asked, and
        # five phases later a chroot said `env: 'apt-get': No such file or directory`. In
        # the resolute index on this host apt is Priority:important, not required, so it is
        # outside minbase's set by definition and inside it only by accident.
        #
        # ca-certificates: a minbase rootfs carries no CA store, and every archive URL here
        # is https, so the first apt-get update *inside* the chroot failed TLS verification
        # against every index -- while ca-certificates sat in the very package list that
        # update was fetching for. Bootstrapping it closes the loop: the bootstrap tool
        # fetches from the host, with the host's CA store, so it can install the store the
        # chroot will need one step later.
        #
        # Naming apt is a no-op for debootstrap, which had it in minbase already. That is
        # the point: one include list that does not depend on which tool ran.
        include = "--include=apt,ca-certificates"
        if tool == "mmdebstrap":
            argv = (
                "mmdebstrap",
                f"--variant={self.options.variant}",
                f"--architectures={self.options.arch}",
                include,
                self.release.codename,
                str(self.root),
                mirror,
            )
        else:
            argv = (
                "debootstrap",
                f"--variant={self.options.variant}",
                include,
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
        self._assert_bootstrap_produced_a_rootfs(tool)
        # Written only after the tool ran, so a failed bootstrap leaves no record
        # claiming a base for a tree that does not have one. It goes through the same
        # runner as everything else, which is what makes a dry run describe the write
        # instead of performing it.
        self.fs.write_text(
            bootstrap_stamp_path(self.root),
            json.dumps(bootstrap_identity(self.release, self.options), indent=2, sort_keys=True)
            + "\n",
            "Record the base this rootfs was bootstrapped from",
        )

    def _assert_bootstrap_produced_a_rootfs(self, tool: str) -> None:
        """Check the tool's work before believing its exit status.

        A bootstrap tool exiting 0 is a claim about the tool, not about the tree. The
        first real golden-path run took the claim: mmdebstrap returned 0, the stamp was
        written, and the build ran five more phases before a chroot said ``apt-get`` was
        missing -- at which point the tool's own output, which would have said why, had
        been discarded, because the runner keeps output only for commands that fail.

        That run's cause is now understood and fixed upstream of here: the include list
        asks for apt by name, because ``minbase`` named two different package sets
        depending on which tool has_binary() picked, and apt was only ever arriving as
        another package's indirect dependency. So this check should no longer be the thing
        that catches a missing package manager.

        It stays anyway, and it names the tool. It is the only place that compares what a
        bootstrap tool *claimed* against what it *left*, and the class of bug it caught
        once -- a tool exiting 0 over a tree that cannot host the next phase -- is not
        specific to apt or to that one reason. Whoever reads the message needs to know
        which of the two tools made the claim, since they do not agree about what a
        variant means.
        """
        if self.runner.dry_run:
            return
        missing = missing_rootfs_requirements(self.root)
        if not missing:
            return
        raise ValueError(
            f"{tool} exited successfully but {self.root} has no "
            f"{', no '.join(missing)}. A --variant={self.options.variant} bootstrap of "
            f"{self.release.codename} has to leave a usable package manager behind: the "
            "next phase runs apt-get inside this tree. Re-run with the work directory "
            f"cleaned, and check {tool}'s own output for what it declined to install."
        )

    def install_live_base(self) -> None:
        plan = PackagePlan(install=self._base_packages()).normalized()
        chroot = ChrootService(self.runner, self.root, self.use_sudo)
        chroot.mount_runtime()
        try:
            chroot.run(*APT_UPDATE_ARGV)
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
        eltorito = self.iso_root / BOOTSTRAP_BIOS_ELTORITO
        image_dir = eltorito.parent
        core_img = image_dir / "core.img"
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

    def _grub_trampoline(self) -> str:
        """The config the ESP hands GRUB: find the real medium, then chain to its menu."""
        return (
            f"search --set=root --file /{self.release.livefs}/vmlinuz\n"
            "set prefix=($root)/boot/grub\n"
            "configfile $prefix/grub.cfg\n"
        )

    def _esp_trampoline_targets(self) -> tuple[str, ...]:
        """Where the trampoline has to be, in the order that matters.

        A signed GRUB's prefix is compiled in and cannot be re-set -- that is the whole
        point of signing -- and it reads exactly ``$prefix/grub.cfg`` and nothing else.
        Measured on Ubuntu's own ``grubx64.efi.signed``: the prefix is ``/EFI/ubuntu``,
        and the binary carries no embedded configuration, only the ``%s/grub.cfg``
        format string. Writing the trampoline to ``EFI/BOOT`` alone therefore left a
        real OVMF boot sitting at a rescue ``grub>`` prompt with everything else
        working: shim loaded, GRUB started, no configuration found. ``EFI/BOOT`` is
        kept as the second target because the unsigned monolithic fallback is built
        with that prefix instead.
        """
        return (f"/EFI/{self.release.family}/grub.cfg", "/EFI/BOOT/grub.cfg")

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
        # The same trampoline in the plain tree, for the reader that is not the boot
        # record: a netboot setup, or a user copying the tree onto a FAT stick. Both
        # spellings, because the firmware loads EFI/boot/bootx64.efi while the signed
        # GRUB inside it then looks for its own vendor directory.
        for directory in (self.release.family, "boot"):
            self.fs.write_text(
                self.iso_root / "EFI" / directory / "grub.cfg",
                self._grub_trampoline(),
                f"Write the GRUB trampoline into EFI/{directory}",
            )
        esp = self.iso_root / BOOTSTRAP_ESP
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
        self.runner.run(
            CommandSpec(
                argv=("mmd", "-i", str(esp), "::/EFI", "::/EFI/BOOT", f"::/EFI/{self.release.family}"),
                description="Create the EFI directories on the UEFI boot image",
            )
        )
        for source, leaf in payloads:
            self.runner.run(
                CommandSpec(
                    argv=("mcopy", "-i", str(esp), str(source), f"::/EFI/BOOT/{leaf}"),
                    description=f"Copy {leaf} into the UEFI boot image",
                )
            )
        for target in self._esp_trampoline_targets():
            self.runner.run(
                CommandSpec(
                    argv=("mcopy", "-i", str(esp), "-", f"::{target}"),
                    stdin=self._grub_trampoline(),
                    description=f"Write the GRUB trampoline to {target}",
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
