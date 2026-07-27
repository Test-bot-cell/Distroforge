from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .command import CommandRunner, CommandSpec, sudo
from .progress_parsers import squashfs_progress

# Directories that exist in an image only as mount points: the initramfs, udev and
# systemd populate them at boot. Their *contents* are never part of a filesystem
# image, and compressing them is not merely wasteful -- if a runtime bind mount is
# still attached, mksquashfs walks into it and reads /proc/kcore, whose apparent
# size is the whole 128 TiB address space. Measured: a 2.0 GB rootfs with /proc
# still mounted produced 5.7 GB of squashfs in 30 minutes and was still growing.
# The directories themselves are kept -- a live system needs them to mount onto.
_PSEUDO_FS_CONTENTS = ("proc/*", "sys/*", "run/*", "dev/*")


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

    def unpack(
        self,
        squashfs_image: Path,
        destination: Path,
        *,
        on_progress: Callable[[float], None] | None = None,
    ) -> None:
        if not self.runner.dry_run:
            destination.parent.mkdir(parents=True, exist_ok=True)
        spec = CommandSpec(
            argv=sudo(
                (
                    "unsquashfs",
                    "-f",
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
                    "mksquashfs",
                    str(source),
                    str(squashfs_image),
                    "-noappend",
                    "-comp",
                    compression,
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
