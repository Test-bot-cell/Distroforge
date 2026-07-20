from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

QEMU_SYSTEM = "qemu-system-x86_64"


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
    ovmf_code: str = "/usr/share/OVMF/OVMF_CODE.fd"
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
