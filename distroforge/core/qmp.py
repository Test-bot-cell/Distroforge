from __future__ import annotations

import json
import socket
import time
from pathlib import Path

from .command import CommandRunner, CommandSpec


class QmpControl:
    """Canonical QMP driver shared by every QEMU service.

    The same instance emits an auditable ``qmp-command`` CommandSpec for dry-runs
    and, when executing, performs the real AF_UNIX handshake. Keeping one engine
    means the lab and the interactive driver cannot drift apart.
    """

    def __init__(self, runner: CommandRunner, timeout_seconds: int = 300) -> None:
        self.runner = runner
        self.timeout_seconds = timeout_seconds

    def command(self, command: str, socket_path: Path, arguments: dict[str, object] | None = None) -> None:
        arguments = arguments or {}
        payload = json.dumps({"execute": command, "arguments": arguments})
        self.runner.run(
            CommandSpec(
                argv=("qmp-command", str(socket_path), payload),
                description=f"QMP command: {command}",
            )
        )
        if self.runner.dry_run:
            return
        self._execute(socket_path, command, arguments)

    def _execute(self, socket_path: Path, command: str, arguments: dict[str, object]) -> None:
        deadline = time.monotonic() + self.timeout_seconds
        while not socket_path.exists():
            if time.monotonic() > deadline:
                raise TimeoutError(f"QMP socket did not appear: {socket_path}")
            time.sleep(0.1)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(socket_path))
            client.recv(65536)
            client.sendall(b'{"execute":"qmp_capabilities"}\n')
            client.recv(65536)
            payload: dict[str, object] = {"execute": command}
            if arguments:
                payload["arguments"] = arguments
            client.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            response = client.recv(65536).decode("utf-8", errors="replace")
        if '"error"' in response:
            raise ValueError(f"QMP command failed: {command}: {response}")


def stop_by_pidfile(runner: CommandRunner, pid_file: Path, description: str = "Stop QEMU VM") -> None:
    if not pid_file.exists():
        return
    runner.run(
        CommandSpec(
            argv=("kill", pid_file.read_text(encoding="utf-8").strip()),
            description=description,
        ),
        check=False,
    )
