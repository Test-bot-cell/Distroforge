"""Unit tests for :mod:`distroforge.core.qmp`.

The QMP driver is the single engine both the interactive driver and the lab use, so
its dry-run contract (an auditable ``qmp-command`` CommandSpec) and its real AF_UNIX
handshake both matter. The handshake is exercised against a throwaway loopback socket
server rather than a real QEMU, so the success, error, and timeout branches are covered
without launching a VM.
"""

from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest

from distroforge.core.command import CommandRunner
from distroforge.core.qmp import QmpControl, stop_by_pidfile


def test_dry_run_command_emits_auditable_spec_without_connecting() -> None:
    runner = CommandRunner(dry_run=True)
    control = QmpControl(runner)

    control.command("system_powerdown", Path("/tmp/does-not-exist.sock"))

    assert len(runner.history) == 1
    spec = runner.history[0]
    assert spec.argv[0] == "qmp-command"
    assert spec.argv[1] == "/tmp/does-not-exist.sock"
    assert json.loads(spec.argv[2]) == {"execute": "system_powerdown", "arguments": {}}
    assert spec.description == "QMP command: system_powerdown"


def test_dry_run_command_preserves_arguments_in_payload() -> None:
    runner = CommandRunner(dry_run=True)
    control = QmpControl(runner)

    control.command("screendump", Path("/tmp/x.sock"), {"filename": "/tmp/shot.ppm"})

    payload = json.loads(runner.history[0].argv[2])
    assert payload == {"execute": "screendump", "arguments": {"filename": "/tmp/shot.ppm"}}


def test_missing_socket_times_out_quickly(tmp_path: Path) -> None:
    runner = CommandRunner(dry_run=False)
    control = QmpControl(runner, timeout_seconds=0)

    with pytest.raises(TimeoutError, match="QMP socket did not appear"):
        control.command("query-status", tmp_path / "absent.sock")


def _serve_once(socket_path: Path, response: str) -> threading.Thread:
    """A minimal QMP-shaped server: greet, ack capabilities, answer one command."""

    def _recv_line(conn: socket.socket, buffer: bytearray) -> None:
        while b"\n" not in buffer:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buffer.extend(chunk)
        del buffer[: buffer.index(b"\n") + 1]

    # bind and listen synchronously before returning: the socket file appears at bind,
    # and the client connects as soon as it sees the file, so listen must already be in
    # effect or the connect races into ECONNREFUSED.
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.listen(1)

    def _run() -> None:
        with server:
            conn, _ = server.accept()
            with conn:
                buffer = bytearray()
                conn.sendall(b'{"QMP": {}}\n')
                _recv_line(conn, buffer)  # qmp_capabilities
                conn.sendall(b'{"return": {}}\n')
                _recv_line(conn, buffer)  # the actual command
                conn.sendall(response.encode("utf-8"))
                # Hold the connection open until the client has read the reply, so the
                # close never races the client's recv into a reset.
                conn.recv(65536)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread


def test_successful_handshake_completes(tmp_path: Path) -> None:
    socket_path = tmp_path / "qmp.sock"
    thread = _serve_once(socket_path, '{"return": {}}\n')
    runner = CommandRunner(dry_run=False)

    QmpControl(runner, timeout_seconds=5).command("stop", socket_path)

    thread.join(timeout=5)
    assert not thread.is_alive()


def test_error_response_is_raised(tmp_path: Path) -> None:
    socket_path = tmp_path / "qmp.sock"
    thread = _serve_once(socket_path, '{"error": {"class": "GenericError", "desc": "no"}}\n')
    runner = CommandRunner(dry_run=False)

    with pytest.raises(ValueError, match="QMP command failed: eject"):
        QmpControl(runner, timeout_seconds=5).command("eject", socket_path)

    thread.join(timeout=5)


def test_stop_by_pidfile_is_a_noop_when_absent(tmp_path: Path) -> None:
    runner = CommandRunner(dry_run=True)

    stop_by_pidfile(runner, tmp_path / "missing.pid")

    assert runner.history == []


def test_stop_by_pidfile_kills_recorded_pid(tmp_path: Path) -> None:
    pid_file = tmp_path / "vm.pid"
    pid_file.write_text("  4321\n", encoding="utf-8")
    runner = CommandRunner(dry_run=True)

    stop_by_pidfile(runner, pid_file, description="Halt the preview VM")

    assert len(runner.history) == 1
    spec = runner.history[0]
    assert spec.argv == ("kill", "4321")
    assert spec.description == "Halt the preview VM"
