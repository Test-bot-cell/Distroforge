from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec, sudo
from .progress_parsers import squashfs_progress
from .reproducible import source_date_epoch_argv

# The compressors an image may use: what mksquashfs can write intersected with what the
# kernel can read. Not the same set as the tool's own list -- mksquashfs also offers
# lzma, which its man page marks "(deprecated - no kernel support)", because the
# squashfs driver ships an XZ decompressor and never a raw-LZMA one. An lzma image
# packs, checksums, passes every artifact gate and ships, and then no kernel will mount
# it. Verified against this kernel's CONFIG_SQUASHFS_{ZLIB,LZO,LZ4,XZ,ZSTD} and against
# the list mksquashfs prints when handed a name it does not know.
SQUASHFS_COMPRESSORS: tuple[str, ...] = ("gzip", "lzo", "lz4", "xz", "zstd")

# Directories that exist in an image only as mount points: the initramfs, udev and
# systemd populate them at boot. Their *contents* are never part of a filesystem
# image, and compressing them is not merely wasteful -- if a runtime bind mount is
# still attached, mksquashfs walks into it and reads /proc/kcore, whose apparent
# size is the whole 128 TiB address space. Measured: a 2.0 GB rootfs with /proc
# still mounted produced 5.7 GB of squashfs in 30 minutes and was still growing.
# The directories themselves are kept -- a live system needs them to mount onto.
_PSEUDO_FS_CONTENTS = ("proc/*", "sys/*", "run/*", "dev/*")


@dataclass
class SquashfsOptions:
    """How to pack the live filesystem.

    ``compression`` empty means "whatever the release says", which is the only default
    that keeps a derivative comparable with the upstream image it descends from.
    """

    compression: str = ""


def resolve_compression(override: str, release_default: str) -> str:
    """The compressor a build will really use -- asked once, answered here.

    The pipeline, the phase description it logs and the validator all need the same
    answer, and each would otherwise re-implement the precedence in its own words.
    """
    return override or release_default


def mounts_under(root: Path) -> list[str]:
    """Mount points at or inside ``root``, read from the kernel.

    /proc/self/mountinfo is parsed here rather than shelling out to ``findmnt``,
    because the test suite must never launch an external tool -- a guard whose test
    depends on a binary being installed is how a green local run turns into a red CI.
    """
    try:
        mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    except OSError:
        # No procfs (a container, a foreign kernel). Nothing can be proven, so nothing
        # is claimed: the excludes above still make the pack itself safe.
        return []
    base = str(root.resolve())
    # rstrip, because "/" would otherwise build the prefix "//" and match nothing.
    prefix = f"{base.rstrip('/')}/"
    found: list[str] = []
    for line in mountinfo.splitlines():
        fields = line.split(" ")
        if len(fields) < 5:
            continue
        # Field 5 is the mount point; the kernel octal-escapes spaces and tabs in it.
        point = fields[4].replace("\\040", " ").replace("\\011", "\t")
        if point == base or point.startswith(prefix):
            found.append(point)
    return found


def _refuse_mounted_source(source: Path) -> None:
    mounted = mounts_under(source)
    if not mounted:
        return
    # chroot.py is the only code in the project that bind-mounts anything, and it always
    # unmounts in a finally with check=False -- so a mount surviving to here is an
    # unmount that failed and said nothing. Observed exactly once, on the first real
    # from-scratch build: /proc alone survived while the other four unmounted, and
    # mksquashfs spent 30 minutes compressing /proc/kcore.
    raise ValueError(
        "Refusing to pack a live filesystem with the chroot still mounted: "
        + ", ".join(sorted(mounted))
        + ". Unmount them before retrying; the runtime bind mounts are unmounted in a "
        "finally block, so one surviving here means that unmount failed silently."
    )


@dataclass
class SquashfsService:
    runner: CommandRunner
    use_sudo: bool = True
    # Pinned only for pack(): unpack() reads an image someone else made and writes a
    # working tree, so clamping its timestamps would change nothing that ships.
    source_date_epoch: int | None = None
    # A sealed derivative must not bless files left in a previous unpack tree.
    require_fresh_unpack: bool = False

    def unpack(
        self,
        squashfs_image: Path,
        destination: Path,
        *,
        on_progress: Callable[[float], None] | None = None,
    ) -> None:
        if not self.runner.dry_run:
            if self.require_fresh_unpack and (
                destination.exists() or destination.is_symlink()
            ):
                raise ValueError(
                    f"SquashFS extraction destination is not fresh: {destination}"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
        spec = CommandSpec(
            argv=sudo(
                (
                    "unsquashfs",
                    "-d",
                    str(destination),
                    str(squashfs_image),
                ),
                self.use_sudo,
            ),
            needs_root=self.use_sudo,
            description="Unpack live filesystem",
        )
        self._run(spec, on_progress)

    def pack(
        self,
        source: Path,
        squashfs_image: Path,
        compression: str = "xz",
        *,
        on_progress: Callable[[float], None] | None = None,
    ) -> None:
        if not self.runner.dry_run:
            squashfs_image.parent.mkdir(parents=True, exist_ok=True)
            _refuse_mounted_source(source)
        spec = CommandSpec(
            argv=sudo(
                (
                    *source_date_epoch_argv(self.source_date_epoch),
                    "mksquashfs",
                    str(source),
                    str(squashfs_image),
                    "-noappend",
                    "-comp",
                    compression,
                    # -e stays last, always. mksquashfs reads every remaining word as an
                    # exclude pattern, so a flag appended after this list is swallowed
                    # silently and the pack falls back to the default compressor with no
                    # warning and a zero exit. Measured while benchmarking compressors:
                    # four "variants" whose flags sat after -e produced byte-identical
                    # gzip images.
                    "-wildcards",
                    "-e",
                    *_PSEUDO_FS_CONTENTS,
                ),
                self.use_sudo,
            ),
            needs_root=self.use_sudo,
            description="Repack live filesystem",
        )
        self._run(spec, on_progress)

    def _run(self, spec: CommandSpec, on_progress: Callable[[float], None] | None) -> None:
        if on_progress is None or self.runner.dry_run:
            self.runner.run(spec)
            return

        def on_line(line: str) -> None:
            fraction = squashfs_progress(line)
            if fraction is not None:
                on_progress(fraction)

        self.runner.run_streaming(spec, on_line)
