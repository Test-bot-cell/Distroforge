from __future__ import annotations

import codecs
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast

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
    "python-plugin-refused",
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
    pass_fds: tuple[int, ...] = ()
    pass_directory_fds: tuple[int, ...] = ()

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
_BINARY_STDERR_LIMIT = 1024 * 1024


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


class ExecutionIdentityError(CommandError):
    """A command returned after an executable in its dispatch chain changed.

    Exit 125 is the runner's refusal, not the child process' exit status. Keeping
    this a ``CommandError`` makes the integrity failure flow through the same
    machine-readable build-failure path as an apt, chroot or ISO-tool failure.
    """

    def __init__(
        self,
        result: CommandResult,
        divergences: Sequence[str],
    ) -> None:
        detail = "; ".join(divergences)
        stderr = result.stderr
        if stderr and not stderr.endswith("\n"):
            stderr += "\n"
        stderr += (
            "DistroForge execution-identity refusal: "
            f"child exit {result.returncode}; {detail}\n"
        )
        refused = CommandResult(
            spec=result.spec,
            returncode=125,
            stdout=result.stdout,
            stderr=stderr,
        )
        super().__init__(refused)
        self.process_result = result
        self.divergences = tuple(divergences)


@dataclass
class _ExecutableWitness:
    """An executable identity whose exact open file survives the dispatch."""

    command: str
    target_root: Path | None
    argv_index: int
    path: Path
    handle: BinaryIO | None
    pre: dict[str, object]


@dataclass
class _ExecutionCapture:
    identity: dict[str, object]
    witnesses: list[_ExecutableWitness]
    dispatch_argv: tuple[str, ...] = ()
    dispatch_executable: str | None = None
    finalized: bool = False
    divergences: tuple[str, ...] = ()


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

        self._validate_pass_fds(spec)
        capture = self._capture_execution_identity(spec)
        self._bind_execution_dispatch(capture, spec)
        try:
            completed = subprocess.run(
                capture.dispatch_argv,
                cwd=spec.cwd,
                env=dict(spec.env) if spec.env else None,
                text=True,
                capture_output=True,
                check=False,
                input=spec.stdin,
                executable=capture.dispatch_executable,
                pass_fds=spec.pass_fds,
            )
        except BaseException:
            self._finalize_execution_identity(capture, process_returncode=None)
            raise
        result = CommandResult(
            spec=spec,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        divergences = self._finalize_execution_identity(
            capture,
            process_returncode=result.returncode,
        )
        self._write_event("finish", spec, result)
        if divergences:
            raise ExecutionIdentityError(result, divergences)
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

        self._validate_pass_fds(spec)
        capture = self._capture_execution_identity(spec)
        self._bind_execution_dispatch(capture, spec)
        captured: list[str] = []
        process: subprocess.Popen[bytes] | None = None
        try:
            with subprocess.Popen(
                capture.dispatch_argv,
                cwd=spec.cwd,
                env=dict(spec.env) if spec.env else None,
                stdin=subprocess.PIPE if spec.stdin is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                executable=capture.dispatch_executable,
                pass_fds=spec.pass_fds,
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
        except BaseException:
            self._finalize_execution_identity(
                capture,
                process_returncode=process.returncode if process is not None else None,
            )
            raise
        assert process is not None
        result = CommandResult(
            spec=spec,
            returncode=process.returncode,
            stdout="".join(captured),
            stderr="",
        )
        divergences = self._finalize_execution_identity(
            capture,
            process_returncode=result.returncode,
        )
        self._write_event("finish", spec, result)
        if divergences:
            raise ExecutionIdentityError(result, divergences)
        if check and result.returncode != 0:
            raise CommandError(result)
        return result

    def run_binary_to_file(
        self,
        spec: CommandSpec,
        output: BinaryIO,
        *,
        max_output_bytes: int,
        check: bool = True,
    ) -> CommandResult:
        """Capture binary stdout without leaving the sealed dispatch boundary.

        ``run`` necessarily decodes stdout as text, while package tools such as
        ``dpkg-deb --fsys-tarfile`` emit an arbitrary tar stream.  Shell pipelines
        would make the downstream command and the transferred bytes an unaudited
        side channel, so this method keeps the normal pre/post executable witness
        and writes the child's stdout directly to a caller-owned binary file.

        The bound is mandatory.  A signed but maliciously compressed package must
        not be able to expand until the evidence filesystem is exhausted. Stderr
        is drained concurrently without a spool file, retains only the logged tail
        and triggers a separate fixed-size refusal.
        """

        if max_output_bytes <= 0:
            raise ValueError("binary command output limit must be positive")
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

        self._validate_pass_fds(spec)
        capture = self._capture_execution_identity(spec)
        self._bind_execution_dispatch(capture, spec)
        process: subprocess.Popen[bytes] | None = None
        written = 0
        stdout_exceeded = False
        stderr_exceeded = False
        stderr_size = 0
        stderr_tail = bytearray()
        stderr_failure: BaseException | None = None
        stderr_thread: threading.Thread | None = None
        stderr_text = ""
        try:
            with subprocess.Popen(
                capture.dispatch_argv,
                cwd=spec.cwd,
                env=dict(spec.env) if spec.env else None,
                stdin=subprocess.PIPE if spec.stdin is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                executable=capture.dispatch_executable,
                pass_fds=spec.pass_fds,
            ) as process:
                assert process.stderr is not None
                stderr_stream = cast(io.BufferedReader, process.stderr)
                active_process = process

                def drain_stderr() -> None:
                    nonlocal stderr_exceeded, stderr_failure, stderr_size
                    try:
                        while True:
                            chunk = stderr_stream.read1(64 * 1024)
                            if not chunk:
                                break
                            stderr_size += len(chunk)
                            stderr_tail.extend(chunk)
                            if len(stderr_tail) > _LOGGED_OUTPUT_TAIL:
                                del stderr_tail[:-_LOGGED_OUTPUT_TAIL]
                            if (
                                stderr_size > _BINARY_STDERR_LIMIT
                                and not stderr_exceeded
                            ):
                                stderr_exceeded = True
                                if active_process.poll() is None:
                                    active_process.kill()
                    except BaseException as exc:
                        stderr_failure = exc
                        if active_process.poll() is None:
                            active_process.kill()

                stderr_thread = threading.Thread(
                    target=drain_stderr,
                    name="distroforge-binary-stderr",
                    daemon=True,
                )
                stderr_thread.start()
                if spec.stdin is not None and process.stdin is not None:
                    process.stdin.write(spec.stdin.encode())
                    process.stdin.close()
                assert process.stdout is not None
                stream = cast(io.BufferedReader, process.stdout)
                while True:
                    chunk = stream.read1(1024 * 1024)
                    if not chunk:
                        break
                    remaining = max_output_bytes - written
                    if len(chunk) > remaining:
                        if remaining:
                            output.write(chunk[:remaining])
                            written += remaining
                        stdout_exceeded = True
                        if process.poll() is None:
                            process.kill()
                        break
                    output.write(chunk)
                    written += len(chunk)
                process.wait()
                stderr_thread.join()
                output.flush()
            if stderr_failure is not None:
                raise stderr_failure
            stderr_text = bytes(stderr_tail).decode("utf-8", errors="replace")
            if stderr_size > len(stderr_tail):
                stderr_text = (
                    f"[{stderr_size - len(stderr_tail)} earlier bytes dropped]\n"
                    + stderr_text
                )
        except BaseException:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            if stderr_thread is not None and stderr_thread.is_alive():
                stderr_thread.join()
            self._finalize_execution_identity(
                capture,
                process_returncode=(
                    process.returncode if process is not None else None
                ),
            )
            raise
        assert process is not None
        if stdout_exceeded:
            if stderr_text and not stderr_text.endswith("\n"):
                stderr_text += "\n"
            stderr_text += (
                "binary stdout exceeded the "
                f"{max_output_bytes}-byte capture limit\n"
            )
        if stderr_exceeded:
            if stderr_text and not stderr_text.endswith("\n"):
                stderr_text += "\n"
            stderr_text += (
                "binary stderr exceeded the "
                f"{_BINARY_STDERR_LIMIT}-byte capture limit\n"
            )
        exceeded = stdout_exceeded or stderr_exceeded
        result = CommandResult(
            spec=spec,
            returncode=125 if exceeded else process.returncode,
            stdout=f"<{written} binary bytes captured>\n",
            stderr=stderr_text,
        )
        divergences = self._finalize_execution_identity(
            capture,
            process_returncode=process.returncode,
        )
        self._write_event("finish", spec, result)
        if divergences:
            raise ExecutionIdentityError(result, divergences)
        if check and result.returncode != 0:
            raise CommandError(result)
        return result

    @staticmethod
    def has_binary(name: str) -> bool:
        return shutil.which(name) is not None

    @staticmethod
    def _validate_pass_fds(spec: CommandSpec) -> None:
        """Refuse malformed, closed or incorrectly typed inherited descriptors.

        Regular artifacts remain the default.  A directory descriptor is inherited
        only when the command explicitly lists it in ``pass_directory_fds``; pipes,
        sockets and devices are never admitted through either contract.
        """

        seen: set[int] = set()
        declared_directories = spec.pass_directory_fds
        if len(set(declared_directories)) != len(declared_directories):
            raise ValueError("command pass_directory_fds must not contain duplicates")
        if any(
            isinstance(descriptor, bool)
            or not isinstance(descriptor, int)
            or descriptor < 0
            for descriptor in declared_directories
        ):
            raise ValueError(
                "command pass_directory_fds must contain non-negative integers"
            )
        directory_set = set(declared_directories)
        if not directory_set.issubset(spec.pass_fds):
            raise ValueError(
                "command pass_directory_fds must be a subset of pass_fds"
            )
        for descriptor in spec.pass_fds:
            if (
                isinstance(descriptor, bool)
                or not isinstance(descriptor, int)
                or descriptor < 0
            ):
                raise ValueError(
                    "command pass_fds must contain non-negative integers"
                )
            if descriptor in seen:
                raise ValueError("command pass_fds must not contain duplicates")
            seen.add(descriptor)
            try:
                identity = os.fstat(descriptor)
            except OSError as exc:
                raise ValueError(
                    f"command pass_fds contains a closed descriptor: {descriptor}"
                ) from exc
            if descriptor in directory_set:
                if not stat.S_ISDIR(identity.st_mode):
                    raise ValueError(
                        "command pass_directory_fds may inherit only held "
                        f"directories: {descriptor}"
                    )
            elif not stat.S_ISREG(identity.st_mode):
                raise ValueError(
                    "command pass_fds may inherit only held regular artifacts: "
                    f"{descriptor}"
                )

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
            "passed_fd_count": len(spec.pass_fds),
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

    def _capture_execution_identity(self, spec: CommandSpec) -> _ExecutionCapture:
        """Snapshot wrapper and target-root executables just before dispatch.

        The first item is the host process Python dispatches. Recognised sudo,
        chroot, nspawn and env layers are also resolved and hashed, including the
        final executable inside the target root. Every executable stays open until
        the child returns: the post-dispatch verifier can therefore rehash the same
        inode as well as the path that would resolve for the next invocation.
        """
        witnesses = _execution_witnesses(spec.argv)
        chain = [witness.pre for witness in witnesses]
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
        try:
            self._write_execution_identity_event("execution-identity", identity)
        except BaseException:
            for witness in witnesses:
                if witness.handle is not None:
                    witness.handle.close()
                    witness.handle = None
            self.execution_identities.pop()
            raise
        return _ExecutionCapture(identity=identity, witnesses=witnesses)

    def _bind_execution_dispatch(
        self,
        capture: _ExecutionCapture,
        spec: CommandSpec,
    ) -> None:
        """Make the kernel consume the already hashed open executable files.

        The outer executable is selected with Popen's ``executable`` parameter so
        argv[0] keeps its normal value.  Wrapper-selected executables are replaced in
        argv with paths to the descriptors held by this still-running Python process.
        Atomic path replacement can therefore trigger a refusal, but cannot select
        different bytes for the child that is actually dispatched.
        """
        dispatch = list(spec.argv)
        binding_by_witness: dict[int, dict[str, object]] = {}
        process_id = os.getpid()

        def descriptor_for(witness: _ExecutableWitness) -> str | None:
            handle = witness.handle
            if (
                handle is None
                or witness.pre.get("available") is not True
                or witness.pre.get("stable_while_hashed") is not True
            ):
                return None
            return f"/proc/{process_id}/fd/{handle.fileno()}"

        def bind(
            witness: _ExecutableWitness,
            descriptor_path: str,
            mode: str,
        ) -> None:
            binding_by_witness[id(witness)] = {
                "command": witness.command,
                "argv_index": witness.argv_index,
                "execution_role": witness.pre.get("execution_role"),
                "descriptor_path": descriptor_path,
                "mode": mode,
                "device": witness.pre.get("device"),
                "inode": witness.pre.get("inode"),
                "size": witness.pre.get("size"),
                "sha256": witness.pre.get("sha256"),
            }

        groups: dict[int, list[_ExecutableWitness]] = {}
        for witness in capture.witnesses:
            groups.setdefault(witness.argv_index, []).append(witness)

        dispatch_executable: str | None = None
        # Replacing a nested script expands one argv token into interpreter,
        # shebang arguments and the script descriptor. Work right-to-left so the
        # original argv indices remain valid.
        for argv_index in sorted(groups, reverse=True):
            group = groups[argv_index]
            entrypoints = [
                witness
                for witness in group
                if witness.pre.get("execution_role")
                != "shebang-interpreter"
            ]
            if len(entrypoints) != 1:
                continue
            entrypoint = entrypoints[0]
            entry_descriptor = descriptor_for(entrypoint)
            role = entrypoint.pre.get("execution_role")
            if role != "script-body":
                if entry_descriptor is None:
                    continue
                mode = (
                    "outer-executable"
                    if argv_index == 0
                    else "nested-argv-rewrite"
                )
                if argv_index == 0:
                    dispatch_executable = entry_descriptor
                else:
                    dispatch[argv_index] = entry_descriptor
                bind(entrypoint, entry_descriptor, mode)
                continue

            interpreters = [
                witness
                for witness in group
                if witness.pre.get("execution_role")
                == "shebang-interpreter"
            ]
            if (
                entrypoint.pre.get("shebang_valid") is not True
                or entry_descriptor is None
                or len(interpreters) != 1
            ):
                continue
            interpreter = interpreters[0]
            interpreter_descriptor = descriptor_for(interpreter)
            arguments = entrypoint.pre.get("shebang_arguments")
            if (
                interpreter_descriptor is None
                or not isinstance(arguments, list)
                or not all(isinstance(value, str) for value in arguments)
            ):
                continue
            replacement = [
                interpreter_descriptor,
                *arguments,
                entry_descriptor,
            ]
            dispatch[argv_index : argv_index + 1] = replacement
            if argv_index == 0:
                dispatch_executable = interpreter_descriptor
                interpreter_mode = "outer-shebang-interpreter"
            else:
                interpreter_mode = "nested-shebang-interpreter"
            bind(entrypoint, entry_descriptor, "script-argument")
            bind(interpreter, interpreter_descriptor, interpreter_mode)

        bindings = [
            binding_by_witness[id(witness)]
            for witness in capture.witnesses
            if id(witness) in binding_by_witness
        ]
        capture.dispatch_argv = tuple(dispatch)
        capture.dispatch_executable = dispatch_executable
        fully_bound = (
            len(bindings) == len(capture.witnesses)
            and capture.dispatch_executable is not None
        )
        capture.identity.update(
            {
                "dispatch_bound": fully_bound,
                "dispatch_argv": list(capture.dispatch_argv),
                "dispatch_executable": capture.dispatch_executable,
                "dispatch_bindings": bindings,
            }
        )
        if not fully_bound:
            unavailable = [
                witness.command
                for witness in capture.witnesses
                if id(witness) not in binding_by_witness
            ]
            result = CommandResult(
                spec=spec,
                returncode=125,
                stdout="",
                stderr=(
                    "DistroForge cannot bind dispatch to the pre-hashed executable "
                    "descriptor chain: "
                    + ", ".join(unavailable)
                ),
            )
            self._finalize_execution_identity(
                capture,
                process_returncode=None,
            )
            raise ExecutionIdentityError(
                result,
                ("unbound executable dispatch",),
            )

    def _finalize_execution_identity(
        self,
        capture: _ExecutionCapture,
        *,
        process_returncode: int | None,
    ) -> list[str]:
        """Close the pre/post executable identity interval.

        Verification has two independent legs for every wrapper and target-root
        executable:

        * rehash the still-open pre-dispatch inode and compare its metadata;
        * resolve the command again and hash the file now present at that path.

        The first detects in-place mutation, including a later content restore whose
        ctime changed. The second detects atomic replacement, symlink retargeting and
        removal. Both must agree before the command result is accepted.
        """
        if capture.finalized:
            return list(capture.divergences)
        capture.finalized = True
        post_chain: list[dict[str, object]] = []
        divergences: list[str] = []
        try:
            for witness in capture.witnesses:
                post = _post_dispatch_identity(witness)
                post_chain.append(post)
                if post["stable_across_dispatch"] is not True:
                    reasons = post.get("divergences")
                    detail = (
                        ", ".join(str(reason) for reason in reasons)
                        if isinstance(reasons, list)
                        else "identity mismatch"
                    )
                    divergences.append(
                        f"{witness.command} ({witness.path}): {detail}"
                    )
        finally:
            for witness in capture.witnesses:
                if witness.handle is not None:
                    witness.handle.close()
                    witness.handle = None
        capture.divergences = tuple(divergences)
        identity = capture.identity
        identity.update(
            {
                "post_dispatch_captured_at": datetime.now(UTC).isoformat(),
                "post_dispatch_process_returncode": process_returncode,
                "post_dispatch_verified": not divergences,
                "stable_across_dispatch": not divergences,
                "post_execution_chain": post_chain,
                "post_execution_chain_sha256": _canonical_json_sha256(post_chain),
                "post_dispatch_divergences": divergences,
            }
        )
        self._write_execution_identity_event(
            "execution-identity-post-dispatch",
            identity,
        )
        return divergences

    def _write_execution_identity_event(
        self,
        event: str,
        identity: Mapping[str, object],
    ) -> None:
        if not self.log_path:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"event": event, **identity}
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _execution_chain(argv: Sequence[str]) -> list[dict[str, object]]:
    witnesses = _execution_witnesses(argv)
    try:
        return [dict(witness.pre) for witness in witnesses]
    finally:
        for witness in witnesses:
            if witness.handle is not None:
                witness.handle.close()


def _execution_witnesses(argv: Sequence[str]) -> list[_ExecutableWitness]:
    witnesses: list[_ExecutableWitness] = []
    for command, target_root, argv_index in _execution_targets(argv):
        entrypoint = _open_executable_witness(
            command,
            target_root,
            argv_index,
        )
        entrypoint.pre["execution_role"] = "argv-executable"
        witnesses.append(entrypoint)
        try:
            shebang = _shebang_dispatch_spec(entrypoint)
        except ValueError as exc:
            entrypoint.pre.update(
                {
                    "execution_role": "script-body",
                    "shebang_valid": False,
                    "shebang_error": str(exc),
                }
            )
            continue
        if shebang is None:
            continue
        interpreter_command, interpreter_arguments, resolver = shebang
        entrypoint.pre.update(
            {
                "execution_role": "script-body",
                "shebang_valid": True,
                "shebang_resolver": resolver,
                "shebang_interpreter_command": interpreter_command,
                "shebang_arguments": list(interpreter_arguments),
            }
        )
        interpreter = _open_executable_witness(
            interpreter_command,
            target_root,
            argv_index,
        )
        interpreter.pre.update(
            {
                "execution_role": "shebang-interpreter",
                "shebang_for": command,
                "shebang_arguments": list(interpreter_arguments),
            }
        )
        try:
            nested_shebang = _shebang_dispatch_spec(interpreter)
        except ValueError as exc:
            nested_shebang = None
            interpreter.pre["shebang_error"] = str(exc)
        if nested_shebang is not None:
            entrypoint.pre.update(
                {
                    "shebang_valid": False,
                    "shebang_error": (
                        "a shebang interpreter that is itself a script is not "
                        "dispatch-bindable"
                    ),
                }
            )
        witnesses.append(interpreter)
    return witnesses


def _shebang_dispatch_spec(
    witness: _ExecutableWitness,
) -> tuple[str, tuple[str, ...], str] | None:
    """Resolve the interpreter that will consume an executable script.

    DistroForge dispatches the resolved interpreter and script through their
    already-hashed descriptors.  ``env`` shebangs are therefore resolved here
    instead of executing a mutable PATH lookup in the child.  Only the portable
    ``env PROGRAM`` and ``env -S PROGRAM ARGS...`` forms are accepted.
    """

    handle = witness.handle
    if handle is None:
        return None
    handle.seek(0)
    first_line = handle.readline(4096)
    if not first_line.startswith(b"#!"):
        return None
    if len(first_line) >= 4096 and not first_line.endswith(b"\n"):
        raise ValueError("shebang line exceeds the auditable 4095-byte limit")
    try:
        declaration = first_line[2:].decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("shebang is not valid UTF-8") from exc
    if not declaration:
        raise ValueError("shebang has no interpreter")
    interpreter, separator, optional = declaration.partition(" ")
    optional = optional.strip() if separator else ""
    if Path(interpreter).name != "env":
        if not interpreter.startswith("/"):
            raise ValueError("direct shebang interpreter is not absolute")
        arguments = (optional,) if optional else ()
        return interpreter, arguments, interpreter

    if not optional:
        raise ValueError("env shebang has no program")
    if optional.startswith("-S "):
        split_value = optional[3:]
    elif optional.startswith("--split-string="):
        split_value = optional.removeprefix("--split-string=")
    elif optional.startswith("-"):
        raise ValueError("unsupported env shebang option")
    else:
        if any(character.isspace() for character in optional):
            raise ValueError(
                "env shebang arguments require the explicit -S form"
            )
        split_value = optional
    try:
        tokens = tuple(shlex.split(split_value))
    except ValueError as exc:
        raise ValueError("env shebang arguments are malformed") from exc
    if not tokens or tokens[0].startswith("-") or "=" in tokens[0]:
        raise ValueError("env shebang program is ambiguous")
    return tokens[0], tokens[1:], interpreter


def _execution_targets(
    argv: Sequence[str],
) -> list[tuple[str, Path | None, int]]:
    nested = tuple(argv)
    target_root: Path | None = None
    targets: list[tuple[str, Path | None, int]] = []
    offset = 0
    while nested:
        command = nested[0]
        targets.append((command, target_root, offset))
        leaf = Path(command).name
        if leaf == "sudo":
            index = 1
            while index < len(nested) and nested[index] in {"-A", "-n"}:
                index += 1
            nested = nested[index:]
            offset += index
            continue
        if leaf == "pkexec":
            nested = nested[1:]
            offset += 1
            continue
        if leaf == "chroot":
            if len(nested) < 3:
                break
            target_root = Path(nested[1]).resolve()
            nested = nested[2:]
            offset += 2
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
            offset += index
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
            offset += index
            continue
        break
    return targets


def _snapshot_executable(
    command: str,
    target_root: Path | None,
    argv_index: int,
) -> dict[str, object]:
    witness = _open_executable_witness(command, target_root, argv_index)
    try:
        return dict(witness.pre)
    finally:
        if witness.handle is not None:
            witness.handle.close()


def _open_executable_witness(
    command: str,
    target_root: Path | None,
    argv_index: int,
) -> _ExecutableWitness:
    if target_root is None:
        resolved = shutil.which(command)
        path = Path(resolved).resolve() if resolved else Path(command)
        scope = "host-pre-dispatch"
    else:
        path = _target_executable(target_root, command)
        scope = "target-root-pre-dispatch"
    identity: dict[str, object] = {
        "command": command,
        "argv_index": argv_index,
        "scope": scope,
        "root": str(target_root) if target_root else None,
        "available": path.is_file(),
        "path": str(path),
        "size": 0,
        "sha256": "",
        "stable_while_hashed": False,
        "path_matches_open_file": False,
        "device": None,
        "inode": None,
        "mode": None,
        "mtime_ns": None,
        "ctime_ns": None,
    }
    try:
        handle = path.open("rb")
    except OSError:
        return _ExecutableWitness(
            command, target_root, argv_index, path, None, identity
        )
    stat_before = os.fstat(handle.fileno())
    if not stat.S_ISREG(stat_before.st_mode):
        handle.close()
        return _ExecutableWitness(
            command, target_root, argv_index, path, None, identity
        )
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    stat_after = os.fstat(handle.fileno())
    path_stat = _stat_path(path)
    path_matches_open_file = (
        path_stat is not None
        and (path_stat.st_dev, path_stat.st_ino)
        == (stat_after.st_dev, stat_after.st_ino)
    )
    stable_while_hashed = (
        _stat_signature(stat_before) == _stat_signature(stat_after)
        and path_matches_open_file
    )
    identity.update(
        {
            "available": True,
            "size": stat_after.st_size,
            "sha256": digest.hexdigest(),
            "stable_while_hashed": stable_while_hashed,
            "path_matches_open_file": path_matches_open_file,
            **_stat_payload(stat_after),
        }
    )
    return _ExecutableWitness(
        command, target_root, argv_index, path, handle, identity
    )


def _post_dispatch_identity(witness: _ExecutableWitness) -> dict[str, object]:
    pre = witness.pre
    handle = witness.handle
    divergences: list[str] = []
    held_sha256 = ""
    held_stat: os.stat_result | None = None
    held_stable_while_rehashed = False
    held_metadata_unchanged = False
    held_sha256_unchanged = False
    if pre.get("available") is not True or handle is None:
        divergences.append("unavailable before dispatch")
    else:
        try:
            held_before = os.fstat(handle.fileno())
            handle.seek(0)
            digest = hashlib.sha256()
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
            held_stat = os.fstat(handle.fileno())
            held_sha256 = digest.hexdigest()
            held_stable_while_rehashed = (
                _stat_signature(held_before) == _stat_signature(held_stat)
            )
            held_metadata_unchanged = _mapping_stat_signature(pre) == _stat_signature(
                held_stat
            )
            held_sha256_unchanged = held_sha256 == pre.get("sha256")
        except OSError:
            divergences.append("open pre-dispatch file could not be rehashed")
    if pre.get("stable_while_hashed") is not True:
        divergences.append("pre-dispatch hash was unstable")
    if handle is not None and not held_stable_while_rehashed:
        divergences.append("open file changed while post-dispatch hash was computed")
    if handle is not None and not held_metadata_unchanged:
        divergences.append("open file metadata changed across dispatch")
    if handle is not None and not held_sha256_unchanged:
        divergences.append("open file bytes changed across dispatch")

    current_witness = _open_executable_witness(
        witness.command,
        witness.target_root,
        witness.argv_index,
    )
    try:
        current = dict(current_witness.pre)
    finally:
        if current_witness.handle is not None:
            current_witness.handle.close()
    current["scope"] = str(current["scope"]).replace(
        "-pre-dispatch",
        "-post-dispatch",
    )
    current_available = current.get("available") is True
    if not current_available:
        divergences.append("path is unavailable after dispatch")
    elif current.get("stable_while_hashed") is not True:
        divergences.append("post-dispatch path hash was unstable")

    resolved_path_unchanged = current.get("path") == pre.get("path")
    resolved_path_matches_held = (
        held_stat is not None
        and current.get("device") == held_stat.st_dev
        and current.get("inode") == held_stat.st_ino
    )
    resolved_sha256_unchanged = current.get("sha256") == pre.get("sha256")
    if current_available and not resolved_path_unchanged:
        divergences.append("resolved path changed across dispatch")
    if current_available and not resolved_path_matches_held:
        divergences.append("resolved path no longer names the open file")
    if current_available and not resolved_sha256_unchanged:
        divergences.append("resolved path bytes changed across dispatch")

    post: dict[str, object] = {
        **current,
        "held_fd_available": handle is not None,
        "held_fd_sha256": held_sha256,
        "held_fd_stable_while_rehashed": held_stable_while_rehashed,
        "held_fd_metadata_unchanged": held_metadata_unchanged,
        "held_fd_sha256_unchanged": held_sha256_unchanged,
        "resolved_path_unchanged": resolved_path_unchanged,
        "resolved_path_matches_held_fd": resolved_path_matches_held,
        "resolved_sha256_unchanged": resolved_sha256_unchanged,
        "stable_across_dispatch": not divergences,
        "divergences": divergences,
    }
    if held_stat is not None:
        post["held_fd"] = {
            "size": held_stat.st_size,
            "sha256": held_sha256,
            **_stat_payload(held_stat),
        }
    else:
        post["held_fd"] = None
    return post


def _stat_path(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except OSError:
        return None


def _stat_payload(value: os.stat_result) -> dict[str, int]:
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "mode": value.st_mode,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _stat_signature(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _mapping_stat_signature(
    value: Mapping[str, object],
) -> tuple[object, object, object, object, object, object]:
    return (
        value.get("device"),
        value.get("inode"),
        value.get("mode"),
        value.get("size"),
        value.get("mtime_ns"),
        value.get("ctime_ns"),
    )


def _canonical_json_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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


def sudo(
    argv: Sequence[str],
    use_sudo: bool = True,
    *,
    preserve_fds: Sequence[int] = (),
) -> tuple[str, ...]:
    """Wrap a privileged command without silently dropping held artifacts.

    ``sudo`` normally closes every descriptor above stderr.  ``-C max_fd+1``
    preserves exactly the descriptors Python admits through ``pass_fds`` (regular
    artifacts plus explicitly declared held directories; all other descriptors
    are already closed by ``subprocess``).  Hosts whose sudo
    policy forbids ``closefrom_override`` fail closed.  ``pkexec`` exposes no
    equivalent contract, so a descriptor-bound command must use sudo or execute
    directly as an already privileged process.
    """

    inherited = tuple(preserve_fds)
    if any(
        isinstance(descriptor, bool)
        or not isinstance(descriptor, int)
        or descriptor < 0
        for descriptor in inherited
    ):
        raise ValueError("preserved descriptors must be non-negative integers")
    if len(set(inherited)) != len(inherited):
        raise ValueError("preserved descriptors must not contain duplicates")
    if use_sudo:
        backend = privilege_backend()
        if backend == "pkexec":
            if inherited:
                raise ValueError(
                    "pkexec cannot preserve descriptor-bound artifact inputs; "
                    "use sudo or an already privileged process"
                )
            return ("pkexec", _absolute_program(argv[0]), *argv[1:])
        if backend == "none":
            return tuple(argv)
        prefix = ["sudo"]
        if not sys.stdin.isatty():
            askpass = ensure_sudo_askpass()
            if askpass:
                prefix.append("-A")
        if inherited:
            prefix.extend(("-C", str(max(inherited) + 1)))
        return (*prefix, *argv)
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
