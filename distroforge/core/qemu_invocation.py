from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

QEMU_SYSTEM = "qemu-system-x86_64"

# Debian and Ubuntu shipped OVMF_CODE.fd until the firmware was rebuilt at a 4 MB
# flash size, and since then only the _4M names exist. That literal was the default
# in nine places, so every UEFI launch in the product died on a file no current
# system carries. The historical names stay last so an older host still resolves.
_OVMF_CODE = (
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/ovmf/OVMF.fd",
)
_OVMF_VARS = (
    "/usr/share/OVMF/OVMF_VARS_4M.fd",
    "/usr/share/OVMF/OVMF_VARS.fd",
)
# Secure Boot is a property of the firmware pair, not of the -global flag below.
# Only the .secboot build enforces it, and only the .ms variable store carries the
# enrolled Microsoft keys a signed shim chains to; aim the flag at the plain build
# and the run reports Secure Boot while booting with it off.
_OVMF_SECBOOT_CODE = (
    "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
    "/usr/share/OVMF/OVMF_CODE.secboot.fd",
)
_OVMF_SECBOOT_VARS = (
    "/usr/share/OVMF/OVMF_VARS_4M.ms.fd",
    "/usr/share/OVMF/OVMF_VARS.ms.fd",
)


def default_ovmf_code(override: str = "", *, secure_boot: bool = False) -> str:
    """The OVMF code image to run, or ``override`` when the caller named one.

    One answer to the question, called by every option surface, rather than a
    literal repeated per surface: this is the same shape as
    ``package_artifact_dir(root, override)``. An empty override means auto-detect,
    which is what an empty field in the GUI and an unset flag already meant.
    """
    return _first_installed(override, _OVMF_SECBOOT_CODE if secure_boot else _OVMF_CODE)


def default_ovmf_vars(override: str = "", *, secure_boot: bool = False) -> str:
    """The OVMF variable-store template to copy, or ``override`` if given."""
    return _first_installed(override, _OVMF_SECBOOT_VARS if secure_boot else _OVMF_VARS)


def is_secure_boot_firmware(code: str, vars_: str) -> bool:
    """Whether this pair can actually enforce Secure Boot.

    Decided from the filenames because that is the only thing the packages expose:
    ovmf ships the distinction as ``.secboot`` and ``.ms`` suffixes, with no
    manifest and no way to interrogate a flash image cheaply.
    """
    return ".secboot." in Path(code).name and ".ms." in Path(vars_).name


def _first_installed(override: str, candidates: tuple[str, ...]) -> str:
    if override:
        return override
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    # Nothing installed. Return the modern name so the error a caller reports and
    # the apt line it suggests name the same file.
    return candidates[0]


@dataclass(frozen=True)
class QemuInvocation:
    """Single source of truth for every qemu-system-x86_64 command line.

    Each QEMU launch in DistroForge — the interactive preview, the headless
    screenshot, the QMP lab, the smoke matrix, the boot-check and the QA
    matrix — describes its machine through this one type, so the argv stays
    auditable and consistent instead of drifting across six call sites.
    """

    iso: Path
    memory_mb: int = 4096
    cpus: int | None = None
    boot_order: str = "d"
    disk: Path | None = None
    serial: str | None = None
    display: str | None = None
    qmp_socket: Path | None = None
    pid_file: Path | None = None
    daemonize: bool = False
    firmware: str = "bios"
    ovmf_code: str = field(default_factory=default_ovmf_code)
    ovmf_vars: str | None = None
    legacy_bios: bool = False
    secure_boot: bool = False
    tpm_socket: Path | None = None
    network: str | None = None
    enable_kvm: bool = False
    timeout_seconds: int | None = None

    def argv(self) -> tuple[str, ...]:
        parts: list[str] = []
        if self.timeout_seconds is not None:
            parts.extend(["timeout", str(self.timeout_seconds)])
        parts.append(QEMU_SYSTEM)
        parts.extend(["-m", str(self.memory_mb)])
        if self.cpus is not None:
            parts.extend(["-smp", str(self.cpus)])
        parts.extend(["-cdrom", str(self.iso), "-boot", self.boot_order])
        if self.disk is not None:
            parts.extend(["-drive", f"file={self.disk},format=qcow2,if=virtio"])
        if self.serial is not None:
            parts.extend(["-serial", self.serial])
        if self.qmp_socket is not None:
            parts.extend(["-qmp", f"unix:{self.qmp_socket},server=on,wait=off"])
        if self.pid_file is not None:
            parts.extend(["-pidfile", str(self.pid_file)])
        if self.display is not None:
            parts.extend(["-display", self.display])
        if self.daemonize:
            parts.append("-daemonize")
        parts.extend(self._firmware_args())
        if self.secure_boot:
            parts.extend(["-global", "driver=cfi.pflash01,property=secure,value=on"])
        parts.extend(self._tpm_args())
        parts.extend(self._network_args())
        if self.enable_kvm:
            parts.append("-enable-kvm")
        return tuple(parts)

    def _firmware_args(self) -> list[str]:
        if self.firmware != "uefi":
            return []
        if self.legacy_bios:
            return ["-bios", self.ovmf_code]
        args = ["-drive", f"if=pflash,format=raw,readonly=on,file={self.ovmf_code}"]
        if self.ovmf_vars is not None:
            args.extend(["-drive", f"if=pflash,format=raw,file={self.ovmf_vars}"])
        return args

    def _tpm_args(self) -> list[str]:
        if self.tpm_socket is None:
            return []
        return [
            "-chardev",
            f"socket,id=chrtpm,path={self.tpm_socket}",
            "-tpmdev",
            "emulator,id=tpm0,chardev=chrtpm",
            "-device",
            "tpm-tis,tpmdev=tpm0",
        ]

    def _network_args(self) -> list[str]:
        if self.network is None:
            return []
        if self.network == "user":
            return ["-nic", "user,model=virtio-net-pci"]
        return ["-nic", self.network]
