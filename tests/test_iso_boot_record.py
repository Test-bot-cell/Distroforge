from __future__ import annotations

from pathlib import Path

from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.iso import BootLayout, IsoService, boot_args_from_report
from distroforge.core.project import Project

# These tests pin the El Torito source-record delegation. They run fully offline -- no
# xorriso is executed -- so they stay deterministic and rootless under CI/buildd and
# build no artifact. The BIOS fixture is a real read-only capture (see its header); the
# UEFI shape below is a constructed unit input, explicitly NOT a live capture.

_FIXTURES = Path(__file__).parent / "fixtures" / "eltorito"


def _fixture(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


def _iso_project(tmp_path: Path) -> Project:
    project = Project.create("Remix", tmp_path / "proj", "26.04")
    project.source_mode = "iso"
    source = tmp_path / "source.iso"
    source.write_bytes(b"\x00" * 16)
    project.source_iso = source
    return project


class _FakeRunner:
    """Execute-mode runner that returns canned report stdout and records every call."""

    def __init__(self, report_text: str) -> None:
        self.dry_run = False
        self._report_text = report_text
        self.history: list[CommandSpec] = []

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        stdout = self._report_text if "-report_el_torito" in spec.argv else ""
        return CommandResult(spec=spec, returncode=0, stdout=stdout, stderr="")


def test_bios_report_forwards_boot_tokens_and_drops_owned_options() -> None:
    args = boot_args_from_report(_fixture("distroforge-demo-bios.as_mkisofs.txt"))
    interval = (
        "--interval:local_fs:0s-15s:zero_mbrpt:"
        "/tmp/distroforge-demo/dist/distroforge-demo.iso"
    )
    assert args == [
        "-partition_cyl_align", "off",
        "-partition_offset", "16",
        "-G", interval,
        "-iso_mbr_part_type", "0xcd",
        "-c", "/boot.catalog",
        "-b", "/boot/grub/i386-pc/eltorito.img",
        "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
    ]
    # The volume id and modification date the rebuild sets itself must not be replayed.
    assert "-V" not in args
    assert not any(a.startswith("--modification-date") for a in args)


def test_uefi_shaped_report_forwards_appended_partition_tokens() -> None:
    # Mirrors the shape a stock Ubuntu UEFI ISO emits (NOT a live capture): it proves the
    # parser forwards the EFI / appended-partition tokens it does not itself interpret.
    report = "\n".join(
        [
            "-V 'Ubuntu 26.04 LTS amd64'",
            "--modification-date='2026042100000000'",
            "-partition_offset 16",
            "--grub2-mbr --interval:local_fs:0s-15s:zero_mbrpt:'/src/ubuntu.iso'",
            "-iso_mbr_part_type 0x00",
            "-c '/boot.catalog'",
            "-b '/boot/grub/i386-pc/eltorito.img'",
            "-no-emul-boot -boot-load-size 4 -boot-info-table --grub2-boot-info",
            "-eltorito-alt-boot",
            "-e '--interval:appended_partition_2_start_1234567s_size_8192d:all::'",
            "-no-emul-boot",
            "-boot-load-size 8192",
            "-append_partition 2 0xef --interval:local_fs:1234567d-1242758d::'/src/ubuntu.iso'",
            "-appended_part_as_gpt",
            "-isohybrid-gpt-basdat",
        ]
    )
    args = boot_args_from_report(report)
    assert args is not None
    assert "-V" not in args
    assert not any(a.startswith("--modification-date") for a in args)
    # EFI / appended-partition tokens survive verbatim.
    for token in ("-eltorito-alt-boot", "-e", "-append_partition", "0xef",
                  "-appended_part_as_gpt", "-isohybrid-gpt-basdat", "--grub2-mbr"):
        assert token in args
    # Both boot images (BIOS -b and EFI -e) are kept.
    assert args.count("-no-emul-boot") == 2
    assert "/boot/grub/i386-pc/eltorito.img" in args


def test_report_without_boot_token_returns_none() -> None:
    assert boot_args_from_report("") is None
    assert boot_args_from_report("Drive current: -indev '/x.iso'\nVolume id : 'X'\n") is None
    # Partition tweaks without an actual boot image are not trusted as a boot record.
    assert boot_args_from_report("-V 'X'\n-partition_offset 16\n") is None


def test_rebuild_replays_source_boot_record_in_execute_mode(tmp_path) -> None:
    project = _iso_project(tmp_path)
    runner = _FakeRunner(_fixture("distroforge-demo-bios.as_mkisofs.txt"))
    IsoService(runner, use_sudo=False).rebuild(project, tmp_path / "out.iso")

    # The read-only probe ran, and the rebuild replayed the source boot tokens.
    assert any("-report_el_torito" in spec.argv for spec in runner.history)
    rebuild = next(s for s in runner.history if "mkisofs" in s.argv)
    argv = list(rebuild.argv)
    assert argv[argv.index("-V") + 1] == "Remix"
    assert argv[argv.index("-o") + 1] == str(tmp_path / "out.iso")
    assert "-b" in argv and "/boot/grub/i386-pc/eltorito.img" in argv
    assert "-boot-info-table" in argv
    assert argv[-1] == str(project.iso_root)
    # The source ISO's own volume id must not leak into the rebuilt image.
    assert "distroforge-demo" not in argv


def test_rebuild_is_byte_identical_to_detection_in_dry_run(tmp_path) -> None:
    project = _iso_project(tmp_path)
    runner = CommandRunner(dry_run=True)
    IsoService(runner, use_sudo=False).rebuild(project, tmp_path / "out.iso")

    # No boot-record probe is issued in dry-run, so plans build nothing and stay pure.
    assert not any("-report_el_torito" in spec.argv for spec in runner.history)
    rebuild = next(s for s in runner.history if "mkisofs" in s.argv)
    expected_boot = BootLayout.detect(project.iso_root).xorriso_args()
    prefix = [
        "xorriso", "-as", "mkisofs", "-r",
        "-V", "Remix",
        "-o", str(tmp_path / "out.iso"),
        "-J", "-joliet-long", "-l", "-cache-inodes",
    ]
    # Byte-identical to the pre-delegation behavior: fixed prefix + detector args + root.
    assert list(rebuild.argv) == prefix + expected_boot + [str(project.iso_root)]
