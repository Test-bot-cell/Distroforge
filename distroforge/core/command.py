from __future__ import annotations

import codecs
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

VIRTUAL_COMMANDS = {
    "autoinstall-skip",
    "bootstrap-bios-skip",
    "bootstrap-efi-skip",
    "bootstrap-rootfs-reuse",
    "compatibility-report",
    "consistency-issue",
    "copy-file",
    "copy-tree",
    "debrand-scan",
    "desktop-source-catalog",
    "desktop-source-install-skip",
    "desktop-source-resolve",
    "desktop-source-skip",
    "gpg-fingerprint-assert",
    "gpg-fingerprint-check",
    "health-score",
    "interaction-await-serial",
    "interaction-wait",
    "kernel-deb-install-skip",
    "kernel-module-skip",
    "kernel-org-resolve",
    "launchpad-verify-ppa",
    "mirror-backup",
    "mirror-restore",
    "packaging-policy-report",
    "plymouth-theme-plan",
    "policy-report",
    "prebuild-vm-assert-log",
    "prebuild-vm-skip",
    "qemu-user-static-required",
    "qmp-command",
    "resolver-seed-skip",
    "sanitize-skip",
    "secureboot-modules-sample",
    "secureboot-warning",
    "stage-chroot-hooks",
    "system-sync-build-skip",
    "system-sync-skip",
    "trust-report",
    "vuln-report",
    "write-file",
}


@dataclass(frozen=True)
class CommandSpec:
    """A command that can be inspected, logged or executed."""

    argv: tuple[str, ...]
    cwd: Path | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    stdin: str | None = None
    needs_root: bool = False
    description: str = ""

    def display(self) -> str:
        return " ".join(_quote(part) for part in self.argv)


@dataclass
class CommandResult:
    spec: CommandSpec
    returncode: int
    stdout: str
    stderr: str


# How much of each stream the command log keeps. The case that decided the number is a
# command that exits 0 and does nothing: in the first real golden-path run mmdebstrap
# returned 0 after 23 seconds and the tree it left had no apt-get, and the reason -- what
# it declined to install, and why -- was in output nobody kept. Only CommandError carries
# a command's words to a human, and this command had not failed.
#
# A tail, not the whole stream, because apt and mksquashfs emit megabytes of progress and
# the sentence that explains a refusal is at the end. Both streams, because tools disagree
# about which one a warning belongs on.
_LOGGED_OUTPUT_TAIL = 4000


def _logged_tail(text: str, limit: int = _LOGGED_OUTPUT_TAIL) -> str | None:
    """The end of ``text``, saying so when it is only the end.

    Returns None for an empty stream so the log carries no key rather than an empty one:
    a dry run genuinely has no output, and that is not the same fact as a command that
    ran and said nothing.
    """
    if not text:
        return None
    if len(text) <= limit:
        return text
    return f"[{len(text) - limit} earlier characters dropped]\n{text[-limit:]}"


class CommandError(RuntimeError):
    def __init__(self, result: CommandResult) -> None:
        message = f"Command failed with exit code {result.returncode}: {result.spec.display()}"
        if result.spec.argv[:1] == ("pkexec",) and result.returncode == 126:
            message += (
                "\nPolkit authorization did not complete. Approve the pkexec prompt, "
                "or switch the build privilege helper to sudo."
            )
        if result.stderr.strip():
            message += f"\n{result.stderr.strip()}"
        super().__init__(message)
        self.result = result


class CommandRunner:
    def __init__(self, dry_run: bool = True, log_path: Path | None = None) -> None:
        self.dry_run = dry_run
        self.log_path = log_path
        self.history: list[CommandSpec] = []
        self.execution_identities: list[dict[str, object]] = []

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        self._write_event("start", spec, None)
        if self.dry_run:
            result = CommandResult(spec=spec, returncode=0, stdout="", stderr="")
            self._write_event("dry-run", spec, result)
            return result
        if spec.argv and spec.argv[0] in VIRTUAL_COMMANDS:
            result = CommandResult(spec=spec, returncode=0, stdout="", stderr="")
            self._write_event("virtual", spec, result)
            return result

        self._capture_execution_identity(spec)
        completed = subprocess.run(
            spec.argv,
            cwd=spec.cwd,
            env=dict(spec.env) if spec.env else None,
            text=True,
            capture_output=True,
            check=False,
            input=spec.stdin,
        )
        result = CommandResult(
            spec=spec,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        self._write_event("finish", spec, result)
        if check and result.returncode != 0:
            raise CommandError(result)
        return result

    def run_streaming(
        self,
        spec: CommandSpec,
        on_line: Callable[[str], None],
        check: bool = True,
    ) -> CommandResult:
        """Execute ``spec`` while forwarding each output line to ``on_line``.

        stderr is merged into stdout and the merged stream is split on both newlines
        and carriage returns, so the in-place progress bars printed by tools such as
        unsquashfs and mksquashfs surface as discrete lines. dry-run and virtual
        commands behave exactly like :meth:`run` and never invoke ``on_line``.

        The pipe is read in binary and decoded incrementally: ``read1`` hands back
        whatever bytes are already available, whereas a text-mode ``read(n)`` blocks
        until n characters or EOF. With the latter, an apt ``pmstatus`` line sat in
        the pipe unseen for the whole silence of a large unpack -- the progress bar
        stalled on information it already had. The Popen context manager then closes
        the pipe deterministically instead of leaving it to the collector.
        """
        self.history.append(spec)
        self._write_event("start", spec, None)
        if self.dry_run:
            result = CommandResult(spec=spec, returncode=0, stdout="", stderr="")
            self._write_event("dry-run", spec, result)
            return result
        if spec.argv and spec.argv[0] in VIRTUAL_COMMANDS:
            result = CommandResult(spec=spec, returncode=0, stdout="", stderr="")
            self._write_event("virtual", spec, result)
            return result

        self._capture_execution_identity(spec)
        captured: list[str] = []
        with subprocess.Popen(
            spec.argv,
            cwd=spec.cwd,
            env=dict(spec.env) if spec.env else None,
            stdin=subprocess.PIPE if spec.stdin is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as process:
            if spec.stdin is not None and process.stdin is not None:
                process.stdin.write(spec.stdin.encode())
                process.stdin.close()
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            buffer = ""
            assert process.stdout is not None
            # Default bufsize gives a BufferedReader, whose read1 issues at most one
            # raw read: it returns the bytes already waiting instead of filling a quota.
            stream = cast(io.BufferedReader, process.stdout)
            while True:
                data = stream.read1(4096)
                if not data:
                    break
                chunk = decoder.decode(data)
                if not chunk:
                    continue
                captured.append(chunk)
                buffer += chunk
                segments = re.split(r"[\r\n]", buffer)
                buffer = segments.pop()
                for segment in segments:
                    if segment:
                        on_line(segment)
            flushed = decoder.decode(b"", True)
            if flushed:
                captured.append(flushed)
            if buffer + flushed:
                on_line(buffer + flushed)
        result = CommandResult(
            spec=spec,
            returncode=process.returncode,
            stdout="".join(captured),
            stderr="",
        )
        self._write_event("finish", spec, result)
        if check and result.returncode != 0:
            raise CommandError(result)
        return result

    @staticmethod
    def has_binary(name: str) -> bool:
        return shutil.which(name) is not None

    def _write_event(
        self, event: str, spec: CommandSpec, result: CommandResult | None
    ) -> None:
        if not self.log_path:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "time": datetime.now(UTC).isoformat(),
            "event": event,
            "command": spec.display(),
            "argv": list(spec.argv),
            "cwd": str(spec.cwd) if spec.cwd else None,
            "needs_root": spec.needs_root,
            "description": spec.description,
            "has_stdin": spec.stdin is not None,
            "env_keys": sorted(spec.env),
            "env_sha256": _environment_sha256(spec.env),
            "returncode": result.returncode if result else None,
            # The command's own words, for every command rather than only the ones that
            # fail. stdin stays a bare boolean above on purpose -- it is where a
            # passphrase would be -- but stdout and stderr are what the tool chose to
            # say about its own work, and a build whose log records only exit statuses
            # cannot answer why a successful command left nothing behind.
            "stdout": _logged_tail(result.stdout) if result else None,
            "stderr": _logged_tail(result.stderr) if result else None,
        }
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _capture_execution_identity(self, spec: CommandSpec) -> None:
        """Snapshot wrapper and target-root executables just before dispatch.

        The first item is the host process Python dispatches. Recognised sudo,
        chroot, nspawn and env layers are also resolved and hashed, including the
        final executable inside the target root. This closes the common gap where a
        host ``apt-get`` digest was reported for ``chroot /target apt-get``.
        """
        chain = _execution_chain(spec.argv)
        entrypoint = chain[0]
        identity: dict[str, object] = {
            "history_index": len(self.history) - 1,
            "captured_at": datetime.now(UTC).isoformat(),
            "scope": "host-entrypoint-pre-dispatch",
            "argv": list(spec.argv),
            "argv0": spec.argv[0],
            "available": entrypoint["available"],
            "path": entrypoint["path"],
            "size": entrypoint["size"],
            "sha256": entrypoint["sha256"],
            "stable_while_hashed": entrypoint["stable_while_hashed"],
            "execution_chain": chain,
        }
        self.execution_identities.append(identity)
        if not self.log_path:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"event": "execution-identity", **identity}
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _execution_chain(argv: Sequence[str]) -> list[dict[str, object]]:
    nested = tuple(argv)
    target_root: Path | None = None
    chain: list[dict[str, object]] = []
    while nested:
        command = nested[0]
        chain.append(_snapshot_executable(command, target_root))
        leaf = Path(command).name
        if leaf == "sudo":
            index = 1
            while index < len(nested) and nested[index] in {"-A", "-n"}:
                index += 1
            nested = nested[index:]
            continue
        if leaf == "pkexec":
            nested = nested[1:]
            continue
        if leaf == "chroot":
            if len(nested) < 3:
                break
            target_root = Path(nested[1]).resolve()
            nested = nested[2:]
            continue
        if leaf == "systemd-nspawn":
            index = 1
            selected_root: Path | None = None
            options_with_value = {
                "--directory",
                "-D",
                "--machine",
                "-M",
                "--image",
                "-i",
                "--setenv",
                "-E",
            }
            while index < len(nested) and nested[index].startswith("-"):
                token = nested[index]
                if token in {"--directory", "-D"} and index + 1 < len(nested):
                    selected_root = Path(nested[index + 1]).resolve()
                index += 2 if token in options_with_value else 1
            target_root = selected_root
            nested = nested[index:]
            continue
        if leaf == "env":
            index = 1
            while index < len(nested):
                token = nested[index]
                if token == "--":
                    index += 1
                    break
                if token.startswith("-") or "=" in token:
                    index += 1
                    continue
                break
            nested = nested[index:]
            continue
        break
    return chain


def _snapshot_executable(
    command: str,
    target_root: Path | None,
) -> dict[str, object]:
    if target_root is None:
        resolved = shutil.which(command)
        path = Path(resolved).resolve() if resolved else Path(command)
        scope = "host-pre-dispatch"
    else:
        path = _target_executable(target_root, command)
        scope = "target-root-pre-dispatch"
    identity: dict[str, object] = {
        "command": command,
        "scope": scope,
        "root": str(target_root) if target_root else None,
        "available": path.is_file(),
        "path": str(path),
        "size": 0,
        "sha256": "",
        "stable_while_hashed": False,
    }
    if not path.is_file():
        return identity
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        stat_before = os.fstat(handle.fileno())
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
        stat_after = os.fstat(handle.fileno())
    identity.update(
        {
            "size": stat_after.st_size,
            "sha256": digest.hexdigest(),
            "stable_while_hashed": (
                stat_before.st_dev,
                stat_before.st_ino,
                stat_before.st_size,
                stat_before.st_mtime_ns,
            )
            == (
                stat_after.st_dev,
                stat_after.st_ino,
                stat_after.st_size,
                stat_after.st_mtime_ns,
            ),
        }
    )
    return identity


def _target_executable(root: Path, command: str) -> Path:
    candidates = (
        (root / command.lstrip("/"),)
        if command.startswith("/")
        else tuple(
            root / relative / command
            for relative in ("usr/sbin", "usr/bin", "sbin", "bin")
        )
    )
    for candidate in candidates:
        resolved = _resolve_target_link(root, candidate)
        if resolved.is_file():
            return resolved
    return candidates[0]


def _resolve_target_link(root: Path, candidate: Path) -> Path:
    current = candidate
    for _ in range(16):
        normalised = Path(os.path.abspath(current))
        try:
            normalised.relative_to(root)
        except ValueError:
            return root / ".distroforge-escaped-executable"
        current = normalised
        if not current.is_symlink():
            return current
        target = Path(os.readlink(current))
        current = (
            root / str(target).lstrip("/")
            if target.is_absolute()
            else current.parent / target
        )
    return current


def sudo(argv: Sequence[str], use_sudo: bool = True) -> tuple[str, ...]:
    if use_sudo:
        backend = privilege_backend()
        if backend == "pkexec":
            return ("pkexec", _absolute_program(argv[0]), *argv[1:])
        if backend == "none":
            return tuple(argv)
        if not sys.stdin.isatty():
            askpass = ensure_sudo_askpass()
            if askpass:
                return ("sudo", "-A", *argv)
        return ("sudo", *argv)
    return tuple(argv)


def privilege_backend() -> str:
    return os.environ.get("DISTROFORGE_PRIVILEGE", "sudo").strip().lower() or "sudo"


def ensure_sudo_askpass() -> str | None:
    askpass = os.environ.get("SUDO_ASKPASS")
    if askpass:
        return askpass
    detected = sudo_askpass_program()
    if detected:
        os.environ["SUDO_ASKPASS"] = detected
    return detected


def sudo_askpass_program() -> str | None:
    for candidate in ("ssh-askpass", "ssh-askpass-gnome", "ksshaskpass", "lxqt-openssh-askpass"):
        found = shutil.which(candidate)
        if found:
            return found
    for path in (
        "/usr/lib/ssh/ssh-askpass",
        "/usr/lib/openssh/gnome-ssh-askpass",
        "/usr/libexec/openssh/ssh-askpass",
        "/usr/bin/ssh-askpass",
        "/usr/bin/ssh-askpass-gnome",
        "/usr/bin/ksshaskpass",
        "/usr/bin/lxqt-openssh-askpass",
    ):
        if Path(path).exists():
            return path
    return None


def _absolute_program(program: str) -> str:
    if program.startswith("/"):
        return program
    return shutil.which(program) or program


def _quote(value: str) -> str:
    # CommandSpec.display() feeds the printed plan, which operators read and
    # re-run, so every part is quoted by shlex rather than only the ones with a
    # space in them: $(...), *, ~root and backticks carry no whitespace and used
    # to be printed raw. The same defect was live in the GUI's CLI-equivalent
    # panel and in the desktop-source chroot command.
    return shlex.quote(value)


def _environment_sha256(environment: Mapping[str, str]) -> str:
    body = json.dumps(
        dict(sorted(environment.items())),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()
