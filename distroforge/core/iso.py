from __future__ import annotations

import hashlib
import os
import shlex
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .bootstrap import planned_boot_images
from .command import CommandRunner, CommandSpec, sudo
from .fsops import FileSystemOps
from .progress_parsers import xorriso_progress
from .project import Project
from .reproducible import source_date_epoch_argv
from .rootfs_evidence import StableFileWitness

# Options the rebuild command line sets itself; drop them (and the value of the
# value-taking ones) from a replayed report so nothing is specified twice.
_REPORT_DROP_WITH_VALUE = frozenset({"-V", "-o", "-outdev", "--output", "-volid"})
_REPORT_DROP_FLAG = frozenset({"-r", "-J", "-joliet-long", "-l", "-cache-inodes"})
_REPORT_DROP_PREFIX = ("--modification-date", "--set_all_file_dates")
# A replay is trusted only if it actually carries a boot image / partition token.
_REPORT_BOOT_MARKERS = frozenset(
    {"-b", "-e", "-eltorito-boot", "-efi-boot", "-append_partition"}
)


def boot_args_from_report(report_text: str) -> list[str] | None:
    """Turn ``xorriso -report_el_torito as_mkisofs`` output into replayable boot args.

    The report is xorriso's own faithful description of a source ISO's boot record,
    designed to be fed straight back to ``xorriso -as mkisofs``. Every boot/partition
    token is forwarded verbatim -- so a UEFI ``-append_partition`` / ``-e`` layout is
    reproduced exactly without this code needing to understand it -- and only the few
    options the rebuild sets itself (volume id, output, modification date,
    filesystem-tree flags) are dropped. Returns ``None`` when the report carries no
    boot image token, so the caller can fall back to generic detection.
    """
    tokens: list[str] = []
    for raw in report_text.splitlines():
        line = raw.strip()
        if not line or not line.startswith("-"):
            # Skip blanks and diagnostic noise ("Drive current:", "xorriso : UPDATE").
            continue
        try:
            tokens.extend(shlex.split(line))
        except ValueError:
            return None

    args: list[str] = []
    skip_next = False
    saw_boot = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in _REPORT_DROP_WITH_VALUE:
            skip_next = True
            continue
        if token in _REPORT_DROP_FLAG:
            continue
        if token.startswith(_REPORT_DROP_PREFIX):
            continue
        if token in _REPORT_BOOT_MARKERS:
            saw_boot = True
        args.append(token)

    return args if saw_boot else None


@dataclass
class IsoService:
    runner: CommandRunner
    use_sudo: bool = True
    # Pinned only for rebuild(): extract() writes a working tree, not the media.
    source_date_epoch: int | None = None
    # Only read to plan the boot record of a tree that does not exist yet, so the default
    # is the arch BuildOptions itself defaults to rather than a sentinel: an unset arch
    # here would silently plan a BIOS-less ISO on the one arch that needs BIOS most.
    arch: str = "amd64"
    # A sealed derivative must never merge a new source ISO into an old work tree.
    # Kept opt-in for callers that use this low-level service outside a sealed build.
    require_fresh_extract: bool = False

    def extract(
        self,
        iso_path: Path,
        destination: Path,
        *,
        on_progress: Callable[[float], None] | None = None,
    ) -> None:
        if not self.runner.dry_run:
            if self.require_fresh_extract and (
                destination.exists() or destination.is_symlink()
            ):
                raise ValueError(
                    f"ISO extraction destination is not fresh: {destination}"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            if self.require_fresh_extract:
                # Claim the checked path ourselves.  xorriso is then handed a newly
                # created empty directory rather than a path another run populated.
                destination.mkdir()
            else:
                destination.mkdir(parents=True, exist_ok=True)
        spec = CommandSpec(
            argv=sudo(
                (
                    "xorriso",
                    "-osirrox",
                    "on",
                    "-indev",
                    str(iso_path),
                    "-extract",
                    "/",
                    str(destination),
                ),
                self.use_sudo,
            ),
            needs_root=self.use_sudo,
            description="Extract ISO tree",
        )
        self._run(spec, on_progress)

    def extract_witnessed(
        self,
        iso_path: Path,
        destination: Path,
        *,
        expected_sha256: str,
        on_progress: Callable[[float], None] | None = None,
    ) -> dict[str, object]:
        """Extract exact source bytes through an FD and close the source path."""
        expected = expected_sha256.strip().lower()
        if (
            len(expected) != 64
            or any(character not in "0123456789abcdef" for character in expected)
        ):
            raise ValueError("Witnessed source ISO requires a valid expected SHA256")
        witness = StableFileWitness(iso_path)
        if witness.initial_identity["sha256"] != expected:
            witness.close()
            raise ValueError(
                "Witnessed source ISO SHA256 differs from the trusted opening identity"
            )
        with witness:
            self.extract(
                witness.proc_fd_path,
                destination,
                on_progress=on_progress,
            )
        identity = witness.sealed_identity
        if identity["sha256"] != expected:
            raise ValueError(
                "Witnessed source ISO changed during extraction"
            )
        return identity

    def rebuild(
        self,
        project: Project,
        output_iso: Path,
        *,
        staging_output: Path | None = None,
        on_progress: Callable[[float], None] | None = None,
    ) -> dict[str, object] | None:
        staging = staging_output or output_iso.with_name(
            f".{output_iso.name}.distroforge-building"
        )
        if staging == output_iso:
            raise ValueError("ISO staging output must differ from the published output")
        if staging.parent.resolve(strict=False) != output_iso.parent.resolve(strict=False):
            raise ValueError("ISO staging output must share the published output directory")
        if not self.runner.dry_run:
            output_iso.parent.mkdir(parents=True, exist_ok=True)
            if staging.exists() or staging.is_symlink():
                raise ValueError(f"ISO staging output is not fresh: {staging}")
        iso_root = project.iso_root
        boot_args, boot_label = self._boot_args(project, iso_root)
        argv = [
            *source_date_epoch_argv(self.source_date_epoch),
            "xorriso",
            "-as",
            "mkisofs",
            "-r",
            "-V",
            project.name[:32],
            "-o",
            str(staging),
            "-J",
            "-joliet-long",
            "-l",
            "-cache-inodes",
            *boot_args,
            str(iso_root),
        ]
        spec = CommandSpec(
            argv=sudo(tuple(argv), self.use_sudo),
            needs_root=self.use_sudo,
            description=f"Rebuild bootable ISO tree ({boot_label})",
        )
        self._run(spec, on_progress)
        fs = FileSystemOps(self.runner, self.use_sudo)
        if self.runner.dry_run:
            fs.rename(staging, output_iso, "Atomically publish freshly rebuilt ISO")
            return None

        staged_identity = _stable_nonempty_regular_file_identity(staging)
        fs.rename(staging, output_iso, "Atomically publish freshly rebuilt ISO")
        published_identity = _stable_nonempty_regular_file_identity(output_iso)
        if (
            staged_identity["size"] != published_identity["size"]
            or staged_identity["sha256"] != published_identity["sha256"]
        ):
            raise ValueError("Published ISO differs from the validated staging output")
        return published_identity

    def _boot_args(self, project: Project, iso_root: Path) -> tuple[list[str], str]:
        """Prefer the source ISO's own El Torito record; fall back to generic detection.

        Delegating to ``xorriso -report_el_torito as_mkisofs`` reproduces whatever boot
        setup the source actually had (BIOS, UEFI, or both) instead of guessing paths.
        The probe runs only in execute mode, so dry-run plans stay byte-identical.
        """
        if project.source_iso and not self.runner.dry_run:
            replayed = self._replay_source_boot_record(project.source_iso)
            if replayed is not None:
                return replayed, "source El Torito record"
        layout = BootLayout.detect(iso_root)
        if (
            self.runner.dry_run
            and project.source_mode == "bootstrap"
            and not layout.bios_image
            and not layout.efi_image
        ):
            # The tree is not there yet because the bootstrap that writes it has not run.
            # Gated on bootstrap mode: a derivative replays the *source* ISO's boot record,
            # which no plan can know, so claiming the from-scratch pair there would swap one
            # wrong plan for another.
            layout = BootLayout.planned(iso_root, self.arch)
        if not self.runner.dry_run and not layout.bios_image and not layout.efi_image:
            # xorriso would happily accept this and hand back a valid ISO9660 image with
            # a kernel, an initrd, a GRUB config and no boot record whatsoever: a data
            # disc no machine will start. The only prior hint was the string "boot assets
            # not detected" buried in a command description. The existing check in
            # validate.py cannot cover it -- it is gated on iso_root.exists(), and for a
            # from-scratch build iso_root does not exist yet when validation runs.
            raise ValueError(
                f"Refusing to build an ISO with no bootable amorce: {iso_root} contains neither a BIOS "
                "El Torito image (isolinux/isolinux.bin, boot/grub/i386-pc/eltorito.img) nor a UEFI boot "
                "image (boot/grub/efi.img, EFI/boot/bootx64.efi). Check that the bootstrap staged them: "
                "run distroforge iso-toolchain, and see docs/build-pipeline.md."
            )
        return layout.xorriso_args(), layout.description

    def _replay_source_boot_record(self, source_iso: Path) -> list[str] | None:
        probe = CommandSpec(
            argv=("xorriso", "-indev", str(source_iso), "-report_el_torito", "as_mkisofs"),
            description="Report source ISO boot record",
        )
        result = self.runner.run(probe, check=False)
        if result.returncode != 0:
            return None
        return boot_args_from_report(result.stdout)

    def _run(self, spec: CommandSpec, on_progress: Callable[[float], None] | None) -> None:
        if on_progress is None or self.runner.dry_run:
            self.runner.run(spec)
            return

        def on_line(line: str) -> None:
            fraction = xorriso_progress(line)
            if fraction is not None:
                on_progress(fraction)

        self.runner.run_streaming(spec, on_line)


def _stable_nonempty_regular_file_identity(path: Path) -> dict[str, object]:
    """Hash a path through one no-follow descriptor and reject unstable output."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"Fresh ISO output was not produced at {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
            raise ValueError(f"Fresh ISO output is not a non-empty regular file: {path}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if identity != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError(f"Fresh ISO output changed while it was hashed: {path}")
    finally:
        os.close(descriptor)
    try:
        current = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"Fresh ISO output disappeared after hashing: {path}") from exc
    if current.st_dev != before.st_dev or current.st_ino != before.st_ino:
        raise ValueError(f"Fresh ISO output path changed after hashing: {path}")
    return {
        "name": path.name,
        "size": before.st_size,
        "sha256": digest.hexdigest(),
    }


@dataclass(frozen=True)
class BootLayout:
    bios_image: str | None = None
    bios_catalog: str | None = None
    efi_image: str | None = None
    # The same ESP, as a path on the build host: -append_partition takes a file to append,
    # not a path inside the image being written, so the two cannot share one field.
    efi_image_source: Path | None = None
    mbr_image: Path | None = None
    mbr_option: str = ""

    @property
    def description(self) -> str:
        modes = []
        if self.bios_image:
            modes.append("BIOS")
        if self.efi_image:
            modes.append("UEFI")
        return "+".join(modes) if modes else "boot assets not detected"

    @classmethod
    def detect(cls, iso_root: Path) -> BootLayout:
        # The MBR boot code is chosen next to the BIOS image it has to chain to, because
        # the two are halves of one bootloader. isohdpfx.bin is ISOLINUX's and
        # boot_hybrid.img is GRUB's, and this used to pick isohdpfx.bin unconditionally --
        # so a from-scratch tree, which stages GRUB, got an ISOLINUX MBR spliced in front
        # of boot/grub/i386-pc/eltorito.img. grub-mkrescue passes --grub2-mbr for exactly
        # this tree and never -isohybrid-mbr.
        bios_image: str | None = None
        bios_catalog: str | None = None
        mbr_image: Path | None = None
        mbr_option = ""
        if (iso_root / "isolinux" / "isolinux.bin").exists():
            bios_image = "isolinux/isolinux.bin"
            bios_catalog = "isolinux/boot.cat"
            mbr_image = _first_existing(
                Path("/usr/lib/ISOLINUX/isohdpfx.bin"),
                Path("/usr/lib/syslinux/isohdpfx.bin"),
                Path("/usr/lib/syslinux/bios/isohdpfx.bin"),
            )
            mbr_option = "-isohybrid-mbr"
        elif (iso_root / "boot" / "grub" / "i386-pc" / "eltorito.img").exists():
            bios_image = "boot/grub/i386-pc/eltorito.img"
            bios_catalog = "boot.catalog"
            mbr_image = _first_existing(Path("/usr/lib/grub/i386-pc/boot_hybrid.img"))
            mbr_option = "--grub2-mbr"

        # Only a FAT volume can become an ESP. The middle candidate is a PE executable, so
        # it can be named in an El Torito entry but never appended as a 0xef partition, and
        # the flag records which of the two a tree gave us instead of inferring it later.
        efi_image = None
        efi_image_source: Path | None = None
        for candidate, is_filesystem in (
            ("boot/grub/efi.img", True),
            ("EFI/boot/bootx64.efi", False),
            ("efi.img", True),
        ):
            if (iso_root / candidate).exists():
                efi_image = candidate
                if is_filesystem:
                    efi_image_source = iso_root / candidate
                break

        return cls(
            bios_image=bios_image,
            bios_catalog=bios_catalog,
            efi_image=efi_image,
            efi_image_source=efi_image_source,
            mbr_image=mbr_image,
            mbr_option=mbr_option,
        )

    @classmethod
    def planned(cls, iso_root: Path, arch: str) -> BootLayout:
        """What a from-scratch bootstrap is going to stage, for a plan that has no tree yet.

        ``detect`` reads the tree, which is the only honest answer once one exists and the
        wrong question before then. The paths come from ``planned_boot_images`` in the module
        that writes them, so the plan and the staging cannot drift apart without the test
        that pins them together failing.

        The MBR is still resolved against the host, and deliberately so: it is a host file
        the build will splice in, and if it is absent the plan should show the same
        MBR-less command the build would run rather than promise one.
        """
        bios_image, esp = planned_boot_images(arch)
        return cls(
            bios_image=bios_image,
            bios_catalog="boot.catalog" if bios_image else None,
            efi_image=esp,
            efi_image_source=iso_root / esp if esp else None,
            mbr_image=_first_existing(Path("/usr/lib/grub/i386-pc/boot_hybrid.img")) if bios_image else None,
            mbr_option="--grub2-mbr" if bios_image else "",
        )

    def xorriso_args(self) -> list[str]:
        args: list[str] = []
        if self.mbr_image and self.bios_image:
            args.extend([self.mbr_option, str(self.mbr_image)])
        if self.bios_image:
            args.extend(
                [
                    "-b",
                    self.bios_image,
                    "-c",
                    self.bios_catalog or "boot.catalog",
                    "-no-emul-boot",
                    "-boot-load-size",
                    "4",
                    "-boot-info-table",
                ]
            )
        if self.efi_image_source is not None:
            # The ESP is appended as a GPT partition and the El Torito EFI entry is aimed at
            # that partition rather than at a file inside the ISO9660 tree. This is the
            # shape grub-mkrescue writes and the shape the Ubuntu images ship, and
            # boot_args_from_report has been able to *read* it since it was written -- it
            # was only ever the producing side that did something else.
            #
            # What it replaces was `--efi-boot <path>` followed by -isohybrid-gpt-basdat,
            # and the second of those marked nothing: --efi-boot expands to
            # -eltorito-alt-boot -e <path> -no-emul-boot -eltorito-alt-boot, and that
            # trailing token closes the entry, so -isohybrid-gpt-basdat had no current boot
            # image left to promote. No GPT was written -- `xorriso -report_system_area`
            # printed an MBR and nothing else, and fdisk called the label "dos" -- and EDK2
            # carries no ISO9660 driver, so the firmware had no filesystem it could read.
            #
            # Measured on ovmf 2026.02 / QEMU 10.2.1 off one 1.35 GB tree. The shape above
            # got `BdsDxe: failed to load Boot0002 ... Not Found` and then `No bootable
            # option or device was found.` -- the firmware exhausted every option and found
            # no filesystem. This shape gets `BdsDxe: loading Boot0002` and `starting
            # Boot0002`, and an EFI application really does run out of the appended
            # partition: with mmx64.efi put in place of BOOTX64.EFI, MokManager drew its
            # full `Shim UEFI key management` UI and counted down. A deliberately truncated
            # ESP in the same harness reported `Not Found`, so the negative direction is
            # instrumented too.
            #
            # This buys a readable ESP and nothing beyond it. shim then fails to read
            # grubx64.efi off that volume -- `Unexpected return from initial read: Device
            # Error, buffersize 0` -- which is a separate defect, tracked separately, and
            # not something a different xorriso argument list can fix.
            #
            # The image stays a file in the tree as well as an appended partition, which
            # costs its own size twice over -- 4.9 MB on the reference derivative. That is
            # deliberate: detect() keys on that file existing, and a tree whose ESP is only
            # reachable as a partition cannot be re-detected on a later rebuild.
            args.extend(
                [
                    "-append_partition",
                    "2",
                    "0xef",
                    str(self.efi_image_source),
                    "-appended_part_as_gpt",
                ]
            )
            if self.bios_image:
                args.append("-eltorito-alt-boot")
            args.extend(["-e", "--interval:appended_partition_2:all::", "-no-emul-boot"])
        elif self.efi_image:
            # A bare PE, which cannot be a partition. Left as it was rather than guessed at:
            # no tree this product builds reaches here, so nothing has ever measured it.
            if self.bios_image:
                args.extend(["--efi-boot", self.efi_image])
            else:
                # Nothing to alternate away from without -b, and man xorrisofs says
                # -eltorito-alt-boot may be omitted in exactly that case.
                args.extend(["-e", self.efi_image, "-no-emul-boot"])
        if self.bios_image or self.efi_image:
            args.extend(["-partition_offset", "16"])
        return args


def _first_existing(*paths: Path) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None
