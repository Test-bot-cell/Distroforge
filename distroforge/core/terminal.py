from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .chroot import ChrootBackend, ChrootService, resolve_chroot_backend
from .command import CommandSpec, sudo


@dataclass(frozen=True)
class ChrootTerminalSpec:
    root: Path
    shell: str = "/bin/bash"
    use_sudo: bool = True
    mount_runtime: bool = True
    log_path: Path | None = None
    backend: ChrootBackend = "auto"

    def resolved_backend(self) -> str:
        return resolve_chroot_backend(self.backend)

    def command(self) -> CommandSpec:
        backend = self.resolved_backend()
        prompt = "distroforge-nspawn" if backend == "nspawn" else "distroforge-chroot"
        shell_command = (
            "export TERM=${TERM:-xterm-256color}; "
            "export LANG=${LANG:-C.UTF-8}; "
            "export LC_ALL=${LC_ALL:-C.UTF-8}; "
            f"export PS1='({prompt}) \\u@\\h:\\w# '; "
            f"exec {self.shell}"
        )
        inner_argv = (
            "/usr/bin/env",
            "-i",
            "HOME=/root",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "SHELL=/bin/bash",
            "TERM=xterm-256color",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "/bin/bash",
            "-lc",
            shell_command,
        )
        if backend == "nspawn":
            return CommandSpec(
                argv=sudo(
                    (
                        "systemd-nspawn",
                        "--quiet",
                        "--register=no",
                        "--as-pid2",
                        "--directory",
                        str(self.root),
                        "--setenv=TERM=xterm-256color",
                        "--setenv=LANG=C.UTF-8",
                        "--setenv=LC_ALL=C.UTF-8",
                        *inner_argv,
                    ),
                    self.use_sudo,
                ),
                needs_root=self.use_sudo,
                description="Interactive systemd-nspawn terminal",
            )
        return CommandSpec(
            argv=sudo(
                (
                    "chroot",
                    str(self.root),
                    *inner_argv,
                ),
                self.use_sudo,
            ),
            needs_root=self.use_sudo,
            description="Interactive chroot terminal",
        )


class TerminalBackendUnavailable(RuntimeError):
    pass


class PtySession:
    def __init__(self, spec: ChrootTerminalSpec, runner: object | None = None) -> None:
        self.spec = spec
        self.master_fd: int | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.runner = runner
        self._mounted_runtime = False
        self._log_file = None

    @property
    def pid(self) -> int | None:
        return self.process.pid if self.process else None

    @property
    def returncode(self) -> int | None:
        return self.process.poll() if self.process else None

    def start(self) -> PtySession:
        if platform.system() == "Windows":
            raise TerminalBackendUnavailable("PTY chroot terminal requires Linux")
        try:
            import fcntl
            import pty
        except ImportError as exc:
            raise TerminalBackendUnavailable("PTY support is unavailable") from exc

        master_fd, slave_fd = pty.openpty()
        self.master_fd = master_fd
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        if self.spec.mount_runtime:
            ChrootService(
                self.runner,
                self.spec.root,
                self.spec.use_sudo,
                backend=self.spec.resolved_backend(),
            ).mount_runtime()
            self._mounted_runtime = True
        if self.spec.log_path:
            self.spec.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = self.spec.log_path.open("ab")
            self._write_log(
                f"\n# DistroForge chroot session {datetime.now(UTC).isoformat()} root={self.spec.root}\n".encode()
            )
        self.process = subprocess.Popen(
            self.spec.command().argv,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            close_fds=True,
        )
        os.close(slave_fd)
        return self

    def read(self, size: int = 8192) -> bytes:
        if self.master_fd is None:
            return b""
        try:
            data = os.read(self.master_fd, size)
        except BlockingIOError:
            return b""
        except OSError:
            # The child closed the slave end (it exited): a PTY master raises EIO
            # here rather than returning EOF. Surface it as end-of-stream so the
            # poll loop falls through to its is_alive() cleanup instead of crashing
            # every tick and leaking the runtime bind mounts.
            return b""
        self._write_log(data)
        return data

    def write(self, data: bytes) -> None:
        if self.master_fd is not None:
            self._write_log(b"\n# input> " + data)
            os.write(self.master_fd, data)

    def is_alive(self) -> bool:
        return bool(self.process and self.process.poll() is None)

    def terminate(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        if self.master_fd is not None:
            os.close(self.master_fd)
            self.master_fd = None
        if self._mounted_runtime:
            ChrootService(
                self.runner,
                self.spec.root,
                self.spec.use_sudo,
                backend=self.spec.resolved_backend(),
            ).unmount_runtime()
            self._mounted_runtime = False
        if self._log_file:
            self._write_log(
                f"\n# session ended {datetime.now(UTC).isoformat()}\n".encode()
            )
            self._log_file.close()
            self._log_file = None

    def _write_log(self, data: bytes) -> None:
        if self._log_file:
            self._log_file.write(data)
            self._log_file.flush()


class LocalTerminalBackend:
    """Unix PTY launcher used by the Qt terminal widget."""

    def spawn(self, spec: ChrootTerminalSpec) -> int:
        session = self.open(spec)
        if session.pid is None:
            raise TerminalBackendUnavailable("Terminal process did not start")
        return session.pid

    def open(self, spec: ChrootTerminalSpec) -> PtySession:
        from .command import CommandRunner

        return PtySession(spec, CommandRunner(dry_run=False)).start()
