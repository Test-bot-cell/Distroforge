from __future__ import annotations

import shlex
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec, sudo
from .progress_parsers import xorriso_progress
from .project import Project

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

    def extract(
        self,
        iso_path: Path,
        destination: Path,
        *,
        on_progress: Callable[[float], None] | None = None,
    ) -> None:
        if not self.runner.dry_run:
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

    def rebuild(
        self,
        project: Project,
        output_iso: Path,
        *,
        on_progress: Callable[[float], None] | None = None,
    ) -> None:
        if not self.runner.dry_run:
            output_iso.parent.mkdir(parents=True, exist_ok=True)
        iso_root = project.iso_root
        boot_args, boot_label = self._boot_args(project, iso_root)
        argv = [
            "xorriso",
            "-as",
            "mkisofs",
            "-r",
            "-V",
            project.name[:32],
            "-o",
            str(output_iso),
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


@dataclass(frozen=True)
class BootLayout:
    bios_image: str | None = None
    bios_catalog: str | None = None
    efi_image: str | None = None
    isohybrid_mbr: Path | None = None

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
        bios_image: str | None = None
        bios_catalog: str | None = None
        if (iso_root / "isolinux" / "isolinux.bin").exists():
            bios_image = "isolinux/isolinux.bin"
            bios_catalog = "isolinux/boot.cat"
        elif (iso_root / "boot" / "grub" / "i386-pc" / "eltorito.img").exists():
            bios_image = "boot/grub/i386-pc/eltorito.img"
            bios_catalog = "boot.catalog"

        efi_image = None
        for candidate in (
            "boot/grub/efi.img",
            "EFI/boot/bootx64.efi",
            "efi.img",
        ):
            if (iso_root / candidate).exists():
                efi_image = candidate
                break

        mbr = _first_existing(
            Path("/usr/lib/ISOLINUX/isohdpfx.bin"),
            Path("/usr/lib/syslinux/isohdpfx.bin"),
            Path("/usr/lib/syslinux/bios/isohdpfx.bin"),
        )
        return cls(
            bios_image=bios_image,
            bios_catalog=bios_catalog,
            efi_image=efi_image,
            isohybrid_mbr=mbr,
        )

    def xorriso_args(self) -> list[str]:
        args: list[str] = []
        if self.isohybrid_mbr and self.bios_image:
            args.extend(["-isohybrid-mbr", str(self.isohybrid_mbr)])
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
        if self.efi_image:
            if self.bios_image:
                args.append("-eltorito-alt-boot")
            args.extend(["-e", self.efi_image, "-no-emul-boot", "-isohybrid-gpt-basdat"])
        if self.bios_image or self.efi_image:
            args.extend(["-partition_offset", "16"])
        return args


def _first_existing(*paths: Path) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None
