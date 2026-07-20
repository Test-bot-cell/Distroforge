from __future__ import annotations

import time
from pathlib import Path

from distroforge.core.command import CommandSpec
from distroforge.core.terminal import ChrootTerminalSpec, PtySession


def test_chroot_terminal_command_uses_clean_maintainer_environment(tmp_path) -> None:
    spec = ChrootTerminalSpec(tmp_path / "rootfs", use_sudo=False, backend="chroot")
    argv = spec.command().argv

    assert argv[:4] == ("chroot", str(tmp_path / "rootfs"), "/usr/bin/env", "-i")
    assert "HOME=/root" in argv
    assert "TERM=xterm-256color" in argv
    assert "LC_ALL=C.UTF-8" in argv
    assert "distroforge-chroot" in argv[-1]


def test_nspawn_terminal_command_uses_clean_maintainer_environment(tmp_path) -> None:
    spec = ChrootTerminalSpec(tmp_path / "rootfs", use_sudo=False, backend="nspawn")
    argv = spec.command().argv

    assert argv[:6] == (
        "systemd-nspawn",
        "--quiet",
        "--register=no",
        "--as-pid2",
        "--directory",
        str(tmp_path / "rootfs"),
    )
    assert "--setenv=TERM=xterm-256color" in argv
    env_index = argv.index("/usr/bin/env")
    assert argv[env_index:env_index + 2] == ("/usr/bin/env", "-i")
    assert "HOME=/root" in argv
    assert "LC_ALL=C.UTF-8" in argv
    assert "distroforge-nspawn" in argv[-1]


def test_auto_terminal_prefers_nspawn_when_available(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "distroforge.core.chroot.CommandRunner.has_binary",
        lambda name: name == "systemd-nspawn",
    )

    assert ChrootTerminalSpec(tmp_path / "rootfs").resolved_backend() == "nspawn"


def test_chroot_terminal_supports_session_logs(tmp_path) -> None:
    log_path = tmp_path / "logs" / "chroot-terminal.log"
    spec = ChrootTerminalSpec(tmp_path / "rootfs", log_path=log_path)

    assert spec.log_path == log_path


def test_gui_exposes_maintainer_terminal_controls() -> None:
    shell = Path("distroforge/ui/main_window.py").read_text(encoding="utf-8")
    actions = Path("distroforge/ui/terminal_actions.py").read_text(encoding="utf-8")

    assert "_mount_terminal_runtime" in shell
    assert "_unmount_terminal_runtime" in shell
    assert "terminal_status" in actions
    assert "chroot-terminal.log" in actions
    assert "already running" in actions
    assert "systemd-nspawn isolation" in actions
    assert "Preparing maintainer runtime" in actions
    assert "policy-rc.d guard for nspawn" in actions


class _EchoSpec(ChrootTerminalSpec):
    """A rootless, chroot-free stand-in: emit one line, then exit non-zero."""

    def command(self) -> CommandSpec:
        return CommandSpec(argv=("/bin/sh", "-c", "echo forge-ready; exit 7"))


def test_pty_session_drains_output_and_survives_child_exit(tmp_path) -> None:
    # Once the child closes the slave end, a PTY master raises EIO instead of EOF.
    # The poll loop reads on every tick, so read() must surface that as end-of-stream
    # (never raise) -- otherwise the GUI's is_alive() cleanup never runs and the
    # /dev /proc /sys /run bind mounts leak. This drives a real PTY and keeps reading
    # past the child's exit to lock that contract.
    session = PtySession(
        _EchoSpec(tmp_path / "rootfs", use_sudo=False, mount_runtime=False)
    ).start()
    try:
        output = b""
        deadline = time.time() + 5
        while time.time() < deadline:
            chunk = session.read()  # must never raise, including after EIO
            if chunk:
                output += chunk
            elif not session.is_alive():
                break
            else:
                time.sleep(0.02)
        assert b"forge-ready" in output
        assert session.is_alive() is False
        assert session.returncode == 7
    finally:
        session.terminate()
