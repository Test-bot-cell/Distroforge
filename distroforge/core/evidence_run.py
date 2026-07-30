from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import uuid
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from distroforge import __version__

from .command import VIRTUAL_COMMANDS, CommandSpec
from .hashing import sha256_file

if TYPE_CHECKING:
    from .project import Project


EVIDENCE_SCHEMA = "distroforge.evidence-run.v1"
IDENTITY_CLOSURE_SCHEMA = "distroforge.run-identity-closure.v1"
TOOLCHAIN_BINARIES: tuple[str, ...] = (
    "python3",
    "git",
    "mmdebstrap",
    "debootstrap",
    "apt-get",
    "dpkg",
    "dpkg-deb",
    "mksquashfs",
    "unsquashfs",
    "lz4",
    "zstd",
    "xorriso",
    "grub-mkimage",
    "gpgv",
    "mformat",
    "mmd",
    "mcopy",
    "mdir",
    "qemu-system-x86_64",
    "sha256sum",
    "chroot",
    "sudo",
)


def new_run_id(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"{stamp}-{uuid.uuid4().hex[:12]}"


def evidence_run_path(
    output_dir: Path,
    run_id: str,
    filename: str,
    *,
    executed: bool,
) -> Path:
    if not run_id or Path(run_id).name != run_id:
        raise ValueError(f"invalid evidence run_id: {run_id!r}")
    relative = Path(filename)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"evidence filename must stay inside its run directory: {filename}")
    kind = "runs" if executed else "plans"
    return output_dir / "evidence" / kind / run_id / relative


def reserve_evidence_run(output_dir: Path, run_id: str, *, executed: bool) -> Path:
    directory = evidence_run_path(
        output_dir,
        run_id,
        ".reserved",
        executed=executed,
    ).parent
    directory.mkdir(parents=True, exist_ok=False)
    return directory


def first_symlink_in_confined_tree(anchor: Path, root: Path) -> Path | None:
    """Find a symlink from ``anchor`` through ``root`` and below it.

    Looking only below ``root`` misses a symlinked ``evidence`` or ``runs`` parent:
    ``root.is_symlink()`` is false for a child reached through that link.  Component
    checks therefore happen before recursion.
    """
    confined_anchor = anchor.absolute()
    confined_root = root.absolute()
    try:
        relative = confined_root.relative_to(confined_anchor)
    except ValueError:
        return confined_root
    current = confined_anchor
    if current.is_symlink():
        return current
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            return current
    if not confined_root.is_dir():
        return None
    return next(
        (path for path in confined_root.rglob("*") if path.is_symlink()),
        None,
    )


def write_immutable_text(path: Path, content: str) -> None:
    """Durably create an evidence file once and refuse replacement.

    ``os.replace`` is deliberately unsuitable here: immutable evidence must never
    displace an existing path.  A same-directory hard link publishes the fully
    synced temporary inode atomically and fails with ``FileExistsError`` for every
    pre-existing destination, including a dangling symlink.
    """
    encoded = content.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    directory_flags = os.O_RDONLY
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(path.parent, directory_flags)
    temporary_name = f".{path.name}.tmp-{uuid.uuid4().hex}"
    temporary_created = False
    try:
        temporary_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        temporary_flags |= getattr(os, "O_CLOEXEC", 0)
        temporary_flags |= getattr(os, "O_NOFOLLOW", 0)
        temporary_fd = os.open(
            temporary_name,
            temporary_flags,
            0o666,
            dir_fd=directory_fd,
        )
        temporary_created = True
        with os.fdopen(temporary_fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.fsync(directory_fd)
        os.unlink(temporary_name, dir_fd=directory_fd)
        temporary_created = False
        os.fsync(directory_fd)
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def copy_immutable_file(source: Path, target: Path) -> None:
    """Copy evidence once, refusing a pre-existing destination."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as source_handle, target.open("xb") as target_handle:
        shutil.copyfileobj(source_handle, target_handle)
        target_handle.flush()
        os.fsync(target_handle.fileno())


def write_json_alias(path: Path, payload: dict[str, object]) -> None:
    """Write a compatibility pointer; the immutable copy is the evidence."""
    write_text_alias(path, json.dumps(payload, indent=2) + "\n")


def write_text_alias(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def canonical_sha256(value: object) -> str:
    body = json.dumps(_normalise(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def make_run_context(
    project: Project,
    options: object,
    *,
    definition: Path | None = None,
    run_id: str | None = None,
    mode: str = "execute",
) -> dict[str, object]:
    # Measure Git before asking it to describe the builder.  The closing toolchain
    # identity then catches an in-place rewrite or pathname swap around those probes.
    toolchain = toolchain_identity(include_versions=mode == "execute")
    builder_identity = builder_source_identity(use_git=mode == "execute")
    definition_identity = _definition_identity(project, options, definition)
    source_iso_identity = _source_iso_identity(project)
    opening_identity = {
        "builder_source": builder_identity,
        "definition": definition_identity,
        "source_iso": source_iso_identity,
        "toolchain": toolchain,
    }
    return {
        "schema": EVIDENCE_SCHEMA,
        "run_id": run_id or new_run_id(),
        "created_at": datetime.now(UTC).isoformat(),
        "mode": mode,
        "distroforge": {
            "version": __version__,
            "python": _file_identity(Path(sys.executable).resolve()),
        },
        "builder_source": builder_identity,
        "definition": definition_identity,
        "source_iso": source_iso_identity,
        "opening_identity_sha256": canonical_sha256(opening_identity),
        "toolchain": toolchain,
    }


def close_run_identity(
    project: Project,
    options: object,
    evidence_context: dict[str, object] | None,
) -> dict[str, object]:
    """Re-measure every mutable build identity and refuse a non-identical close.

    SHA equality alone cannot prove that a file stayed put: an input can be changed,
    consumed, and restored before the final hash.  The file identities below therefore
    bind the descriptor's device/inode and its ctime/mtime as well as its bytes.  The
    builder worktree applies the same rule to every tracked and non-ignored untracked
    entry.  A same-byte atomic replacement changes the inode; an A→B→A rewrite changes
    ctime even when the attacker restores mtime.
    """
    if not isinstance(evidence_context, dict):
        raise RuntimeError("Run identity closure requires an injected evidence context.")

    initial_builder = evidence_context.get("builder_source")
    initial_definition = evidence_context.get("definition")
    initial_source_iso = evidence_context.get("source_iso")
    initial_toolchain = evidence_context.get("toolchain")
    opening_identity = {
        "builder_source": initial_builder,
        "definition": initial_definition,
        "source_iso": initial_source_iso,
        "toolchain": initial_toolchain,
    }
    opening_digest = canonical_sha256(opening_identity)
    recorded_opening_digest = evidence_context.get("opening_identity_sha256")
    opening_issues: list[str] = []
    if recorded_opening_digest != opening_digest:
        opening_issues.append(
            "the opening identity record changed after make_run_context"
        )

    definition_path = _identity_path(initial_definition)
    source_trusted_path = _source_trusted_path(initial_source_iso)
    use_git = not (
        isinstance(initial_builder, dict)
        and initial_builder.get("kind") == "source-tree-plan"
    )
    final_components: dict[str, object] = {
        "builder_source": builder_source_identity(use_git=use_git),
        "definition": _definition_identity(
            project,
            options,
            definition_path,
        ),
        "source_iso": _source_iso_identity(
            project,
            trusted_path=source_trusted_path,
        ),
        "toolchain": toolchain_identity(
            include_versions=evidence_context.get("mode") == "execute"
        ),
    }
    initial_components = {
        "builder_source": initial_builder,
        "definition": initial_definition,
        "source_iso": initial_source_iso,
        "toolchain": initial_toolchain,
    }

    checks: list[dict[str, object]] = []
    failure_messages = list(opening_issues)
    for name in ("builder_source", "definition", "source_iso", "toolchain"):
        initial = initial_components[name]
        final = final_components[name]
        initial_sha256 = canonical_sha256(initial)
        final_sha256 = canonical_sha256(final)
        issues = [
            *_measurement_issues(name, initial, moment="opening"),
            *_measurement_issues(name, final, moment="closing"),
        ]
        if initial_sha256 != final_sha256:
            issues.append("opening and closing identities differ")
        status = "closed" if not issues else "blocked"
        checks.append(
            {
                "name": name,
                "status": status,
                "initial_sha256": initial_sha256,
                "final_sha256": final_sha256,
                "final": final,
                "issues": issues,
            }
        )
        failure_messages.extend(f"{name}: {issue}" for issue in issues)

    closure: dict[str, object] = {
        "schema": IDENTITY_CLOSURE_SCHEMA,
        "status": "closed" if not failure_messages else "blocked",
        "checked_at": datetime.now(UTC).isoformat(),
        "opening_identity_sha256": recorded_opening_digest,
        "checks": checks,
        "checks_sha256": canonical_sha256(checks),
        "issues": failure_messages,
    }
    # Record the failed close before raising, so ISO-BUILD.json can say exactly which
    # input moved even though no provenance is allowed to be sealed.
    evidence_context["identity_closure"] = closure
    if failure_messages:
        raise RuntimeError(
            "Run identity closure refused: " + "; ".join(failure_messages)
        )
    return closure


def builder_source_identity(*, use_git: bool = True) -> dict[str, object]:
    """Describe the source bytes at the instant a run starts.

    This must not be cached: one long-lived CLI or GUI process can launch several
    builds while the worktree changes between them. Reusing the first identity would
    bind a later ISO to source bytes that were no longer present.
    """
    source_root = Path(__file__).resolve().parents[2]
    if not use_git:
        first_guard = _builder_filesystem_guard(
            source_root,
            _source_tree_paths(source_root),
        )
        second_guard = _builder_filesystem_guard(
            source_root,
            _source_tree_paths(source_root),
        )
        return {
            "kind": "source-tree-plan",
            "root": str(source_root),
            "source_tree_sha256": second_guard["content_sha256"],
            "filesystem_guard": second_guard,
            "stable_while_measured": first_guard == second_guard,
        }
    git_root_text = _git_text(source_root, "rev-parse", "--show-toplevel")
    if git_root_text is None:
        first_guard = _builder_filesystem_guard(
            source_root,
            _source_tree_paths(source_root),
        )
        second_guard = _builder_filesystem_guard(
            source_root,
            _source_tree_paths(source_root),
        )
        return {
            "kind": "source-tree",
            "root": str(source_root),
            "source_tree_sha256": second_guard["content_sha256"],
            "filesystem_guard": second_guard,
            "stable_while_measured": first_guard == second_guard,
        }
    git_root = Path(git_root_text)
    raw_head = _git_text(git_root, "rev-parse", "HEAD")
    raw_tree = _git_text(git_root, "rev-parse", "HEAD^{tree}")
    raw_branch = _git_text(git_root, "branch", "--show-current")
    raw_diff = _git_bytes(git_root, "diff", "--binary", "HEAD", "--")
    head = raw_head or ""
    tree = raw_tree or ""
    branch = raw_branch or ""
    diff = raw_diff or b""
    diff_sha256 = hashlib.sha256(diff).hexdigest()
    untracked: list[dict[str, str]] = []
    raw_untracked = _git_bytes(
        git_root,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
    )
    if raw_untracked:
        for raw_name in raw_untracked.split(b"\0"):
            if not raw_name:
                continue
            name = os.fsdecode(raw_name)
            path = git_root / name
            identity = _stable_regular_file_identity(path, required=True)
            digest = identity.get("sha256")
            untracked.append(
                {
                    "path": name,
                    "sha256": digest if isinstance(digest, str) else "",
                }
            )
    raw_tracked_result = _git_bytes(
        git_root,
        "ls-files",
        "--cached",
        "-z",
    )
    raw_tracked = raw_tracked_result or b""
    tracked_paths = {
        os.fsdecode(raw_name)
        for raw_name in raw_tracked.split(b"\0")
        if raw_name
    }
    untracked_paths = {
        os.fsdecode(raw_name)
        for raw_name in (raw_untracked or b"").split(b"\0")
        if raw_name
    }
    runtime_paths = set(_source_tree_paths(git_root))
    guarded_paths = sorted(tracked_paths | untracked_paths | runtime_paths)
    ignored_runtime_paths = sorted(
        relative
        for relative in runtime_paths - tracked_paths - untracked_paths
        if (git_root / relative).is_file() or (git_root / relative).is_symlink()
    )
    first_guard = _builder_filesystem_guard(git_root, guarded_paths)
    second_guard = _builder_filesystem_guard(git_root, guarded_paths)
    raw_signature = _git_text(git_root, "log", "-1", "--format=%G? %GF")
    signature = raw_signature or ""
    git_measurements_complete = all(
        item is not None
        for item in (
            raw_head,
            raw_tree,
            raw_branch,
            raw_diff,
            raw_untracked,
            raw_tracked_result,
            raw_signature,
        )
    )
    worktree_sha256 = canonical_sha256(
        {
            "head": head,
            "tracked_diff_sha256": diff_sha256,
            "untracked": untracked,
        }
    )
    return {
        "kind": "git",
        "root": str(git_root),
        "head": head,
        "tree": tree,
        "branch": branch,
        "commit_signature": signature.strip(),
        "git_measurements_complete": git_measurements_complete,
        "dirty": bool(diff or untracked),
        "tracked_diff_sha256": diff_sha256,
        "untracked": untracked,
        "ignored_runtime_paths": ignored_runtime_paths,
        "worktree_sha256": worktree_sha256,
        "filesystem_guard": second_guard,
        "stable_while_measured": first_guard == second_guard,
    }


def toolchain_identity(
    names: tuple[str, ...] = TOOLCHAIN_BINARIES,
    *,
    include_versions: bool = True,
) -> dict[str, object]:
    tools: dict[str, object] = {}
    for name in names:
        resolved = shutil.which(name)
        if resolved is None:
            tools[name] = {"available": False}
            continue
        path = Path(resolved).resolve()
        file_identity = _stable_regular_file_identity(path, required=True)
        tools[name] = {
            "available": True,
            "path": str(path),
            "sha256": file_identity.get("sha256"),
            "stable_while_hashed": file_identity.get("stable_while_hashed"),
            "file_identity": file_identity,
            "version": _tool_version(path) if include_versions else "not-probed-in-plan",
        }
    return tools


def observed_toolchain_identity(history: Iterable[CommandSpec]) -> dict[str, object]:
    """Bind the executable entry points actually present in the command history.

    Privilege and chroot wrappers are expanded far enough to identify both the host
    wrapper and the command it launched. A command executed inside the target root may
    not resolve on the host; recording it as unavailable is still preferable to
    silently pretending it was never invoked.
    """
    specs = tuple(history)
    observed = observed_executable_counts(spec.argv for spec in specs)
    real_names = tuple(sorted(name for name in observed if name not in VIRTUAL_COMMANDS))
    resolved = toolchain_identity(real_names)
    tools: dict[str, object] = {}
    for name in sorted(observed):
        raw_identity = resolved.get(name)
        identity = {"available": True, "kind": "virtual"}
        if name not in VIRTUAL_COMMANDS:
            identity = (
                dict(raw_identity)
                if isinstance(raw_identity, dict)
                else {"available": False}
            )
        identity["observed_count"] = observed[name]
        tools[name] = identity
    return {
        "command_count": len(specs),
        "resolution_scope": "post-run-path-snapshot",
        "tools": tools,
    }


def observed_executable_counts(
    commands: Iterable[Sequence[str]],
) -> dict[str, int]:
    observed: dict[str, int] = {}
    for argv in commands:
        for name in _executable_candidates(argv):
            observed[name] = observed.get(name, 0) + 1
    return observed


def critical_artifact_identity(project: Project, output_iso: Path | None) -> list[dict[str, object]]:
    paths: set[Path] = set()
    if output_iso and output_iso.is_file():
        paths.add(output_iso)
    if project.iso_root.is_dir():
        for pattern in (
            "**/filesystem.squashfs",
            "**/filesystem.manifest",
            "**/vmlinuz*",
            "**/initrd*",
            "**/BOOTX64.EFI",
            "**/bootx64.efi",
            "**/grubx64.efi",
            "**/efi.img",
            "**/eltorito.img",
            "**/filesystem.manifest-desktop",
            "**/md5sum.txt",
            "**/grub.cfg",
        ):
            paths.update(path for path in project.iso_root.glob(pattern) if path.is_file())
    return [
        {
            "path": str(path),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(paths)
    ]


def artifact_identity(path: Path, *, role: str = "") -> dict[str, object]:
    identity = _file_identity(path)
    if role:
        identity["role"] = role
    return identity


def _executable_candidates(argv: Sequence[str]) -> tuple[str, ...]:
    if not argv:
        return ()
    candidates: list[str] = []
    nested = tuple(argv)
    while nested:
        command = nested[0]
        if command not in candidates:
            candidates.append(command)
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
            nested = nested[2:] if len(nested) >= 3 else ()
            continue
        if leaf == "systemd-nspawn":
            index = 1
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
                index += 2 if token in options_with_value else 1
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
    return tuple(candidates)


def _definition_identity(
    project: Project,
    options: object,
    definition: Path | None,
) -> dict[str, object]:
    definition_file = _stable_regular_file_identity(
        definition,
        required=definition is not None,
    )
    project_file_path = project.root / "project.json"
    project_file = _stable_regular_file_identity(project_file_path, required=True)
    identity: dict[str, object] = {
        # Keep the original convenience fields for existing evidence readers while
        # carrying the full stable identities needed by the closing comparison.
        "path": str(definition) if definition else None,
        "sha256": definition_file.get("sha256"),
        "file": definition_file,
        "effective_sha256": canonical_sha256(
            {
                "project": project.to_dict(),
                "options": _normalise_effective(options),
            }
        ),
        "project_file": str(project_file_path),
        "project_file_sha256": project_file.get("sha256"),
        "project_file_identity": project_file,
    }
    return identity


def _source_iso_identity(
    project: Project,
    *,
    trusted_path: Path | None = None,
) -> dict[str, object]:
    configured_path = project.source_iso
    opening_path = trusted_path if trusted_path is not None else configured_path
    required = project.source_mode == "iso"
    file_identity = _stable_regular_file_identity(
        opening_path,
        required=required,
    )
    return {
        "source_mode": project.source_mode,
        "path": str(configured_path) if configured_path else None,
        "trusted_path": str(opening_path) if opening_path else None,
        "sha256": file_identity.get("sha256"),
        "file": file_identity,
    }


def _identity_path(identity: object) -> Path | None:
    if not isinstance(identity, dict):
        return None
    path = identity.get("path")
    return Path(path) if isinstance(path, str) and path else None


def _source_trusted_path(identity: object) -> Path | None:
    if not isinstance(identity, dict):
        return None
    path = identity.get("trusted_path")
    return Path(path) if isinstance(path, str) and path else None


def _measurement_issues(
    name: str,
    identity: object,
    *,
    moment: str,
) -> list[str]:
    if not isinstance(identity, dict):
        return [f"{moment} identity is absent or malformed"]
    issues: list[str] = []
    if name == "builder_source":
        if identity.get("stable_while_measured") is not True:
            issues.append(f"{moment} builder worktree moved while it was measured")
        guard = identity.get("filesystem_guard")
        if not isinstance(guard, dict):
            issues.append(f"{moment} builder filesystem guard is absent")
        elif guard.get("stable") is not True:
            issues.append(f"{moment} builder filesystem guard is incomplete")
        return issues
    if name == "toolchain":
        for tool_name, tool_identity in identity.items():
            if not isinstance(tool_identity, dict):
                issues.append(f"{moment} toolchain entry {tool_name} is malformed")
                continue
            if tool_identity.get("available") is not True:
                continue
            if tool_identity.get("stable_while_hashed") is not True:
                issues.append(
                    f"{moment} toolchain binary {tool_name} moved while hashed"
                )
            if not isinstance(tool_identity.get("path"), str) or not isinstance(
                tool_identity.get("sha256"),
                str,
            ):
                issues.append(
                    f"{moment} toolchain binary {tool_name} lacks path/SHA256"
                )
        return issues

    file_keys = (
        ("definition file", "file"),
        ("project definition", "project_file_identity"),
    ) if name == "definition" else (("source ISO", "file"),)
    for label, key in file_keys:
        file_identity = identity.get(key)
        if not isinstance(file_identity, dict):
            issues.append(f"{moment} {label} identity is absent")
            continue
        required = file_identity.get("required") is True
        if required and file_identity.get("exists") is not True:
            issues.append(f"{moment} {label} is missing")
        if file_identity.get("stable_while_hashed") is not True:
            issues.append(f"{moment} {label} moved while it was hashed")
        error = file_identity.get("error")
        if isinstance(error, str) and error:
            issues.append(f"{moment} {label}: {error}")
    return issues


def _stable_regular_file_identity(
    path: Path | None,
    *,
    required: bool,
) -> dict[str, object]:
    """Hash one path through a stable descriptor and bind it back to the pathname."""
    if path is None:
        return {
            "path": None,
            "required": required,
            "exists": False,
            "kind": "not-configured",
            "size": 0,
            "sha256": None,
            "stable_while_hashed": not required,
        }
    measured_path = path.absolute()
    identity: dict[str, object] = {
        "path": str(measured_path),
        "required": required,
        "exists": False,
        "kind": "missing",
        "size": 0,
        "sha256": None,
        "stable_while_hashed": False,
    }
    try:
        parent_before = measured_path.parent.lstat()
        path_before = measured_path.lstat()
    except OSError as exc:
        identity["error"] = f"cannot lstat: {exc}"
        return identity
    identity["exists"] = True
    identity["path_stat"] = _stat_identity(path_before)
    if stat.S_ISLNK(path_before.st_mode):
        identity["kind"] = "symlink"
        identity["error"] = "trusted inputs must not be symlinks"
        return identity
    if not stat.S_ISREG(path_before.st_mode):
        identity["kind"] = _mode_kind(path_before.st_mode)
        identity["error"] = "trusted input is not a regular file"
        return identity

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(measured_path, flags)
        descriptor_before = os.fstat(descriptor)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        descriptor_after = os.fstat(descriptor)
        path_after = measured_path.lstat()
        parent_after = measured_path.parent.lstat()
    except OSError as exc:
        identity["error"] = f"cannot hash through stable descriptor: {exc}"
        return identity
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    stable = (
        _stable_stat_equal(path_before, descriptor_before)
        and _stable_stat_equal(descriptor_before, descriptor_after)
        and _stable_stat_equal(descriptor_after, path_after)
        and _stable_stat_equal(parent_before, parent_after)
    )
    identity.update(
        {
            "kind": "regular",
            "size": descriptor_after.st_size,
            "sha256": digest.hexdigest(),
            "descriptor_stat": _stat_identity(descriptor_after),
            "parent_stat": _stat_identity(parent_after),
            "stable_while_hashed": stable,
        }
    )
    if not stable:
        identity["error"] = "pathname/descriptor identity changed during hashing"
    return identity


def _builder_filesystem_guard(
    root: Path,
    relative_paths: Iterable[str],
) -> dict[str, object]:
    safe_relative_paths: list[Path] = []
    entries: list[dict[str, object]] = []
    content_entries: list[dict[str, object]] = []
    metadata_entries: list[dict[str, object]] = []
    problems: list[str] = []
    for relative in sorted(set(relative_paths)):
        relative_path = Path(relative)
        if (
            relative_path.is_absolute()
            or ".." in relative_path.parts
            or not relative_path.parts
        ):
            problems.append(f"unsafe worktree path {relative!r}")
            continue
        safe_relative_paths.append(relative_path)
        guarded = _guard_path_identity(root / relative_path)
        entry = {"path": relative_path.as_posix(), **guarded}
        entries.append(entry)
        content_entries.append(
            {
                key: value
                for key, value in entry.items()
                if key
                in {
                    "path",
                    "exists",
                    "kind",
                    "size",
                    "sha256",
                    "link_target",
                }
            }
        )
        metadata_entries.append(
            {
                "path": entry["path"],
                "stat": entry.get("stat"),
                "stable_while_hashed": entry.get("stable_while_hashed"),
            }
        )
        error = guarded.get("error")
        if isinstance(error, str) and error:
            problems.append(f"{relative}: {error}")
    directory_paths = {Path(".")}
    for relative_path in safe_relative_paths:
        absolute_path = root / relative_path
        if absolute_path.is_dir() and not absolute_path.is_symlink():
            directory_paths.add(relative_path)
        directory_paths.update(
            parent
            for parent in relative_path.parents
            if parent != Path(".") and parent.parts
        )
    directories: list[dict[str, object]] = []
    for relative_directory in sorted(
        directory_paths,
        key=lambda item: item.as_posix(),
    ):
        guarded = _guard_directory_identity(root / relative_directory)
        label = relative_directory.as_posix()
        entry = {"path": label, **guarded}
        directories.append(entry)
        error = guarded.get("error")
        if isinstance(error, str) and error:
            problems.append(f"directory {label}: {error}")
    metadata_record = {
        "files": metadata_entries,
        "directories": directories,
    }
    return {
        "entry_count": len(entries),
        "directory_count": len(directories),
        "entries_sha256": canonical_sha256(
            {"files": entries, "directories": directories}
        ),
        "content_sha256": canonical_sha256(content_entries),
        "metadata_sha256": canonical_sha256(metadata_record),
        "directory_metadata_sha256": canonical_sha256(directories),
        "stable": not problems,
        "problems": problems,
    }


def _guard_path_identity(path: Path) -> dict[str, object]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        # A tracked deletion is a legitimate, measurable dirty-worktree state.  The
        # parent-directory guard detects a create/delete transition, and the second
        # whole-tree pass proves that "missing" itself stayed stable while captured.
        return {
            "exists": False,
            "kind": "missing",
            "stable_while_hashed": True,
        }
    except OSError as exc:
        return {
            "exists": False,
            "kind": "missing",
            "stable_while_hashed": False,
            "error": f"cannot lstat: {exc}",
        }
    if stat.S_ISREG(before.st_mode):
        identity = _stable_regular_file_identity(path, required=True)
        return {
            key: value
            for key, value in identity.items()
            if key not in {"path", "required", "path_stat", "descriptor_stat"}
        } | {"stat": identity.get("descriptor_stat", identity.get("path_stat"))}
    if stat.S_ISLNK(before.st_mode):
        try:
            first_target = os.readlink(path)
            after = path.lstat()
            second_target = os.readlink(path)
        except OSError as exc:
            return {
                "exists": True,
                "kind": "symlink",
                "stat": _stat_identity(before),
                "stable_while_hashed": False,
                "error": f"cannot measure symlink: {exc}",
            }
        stable = _stable_stat_equal(before, after) and first_target == second_target
        return {
            "exists": True,
            "kind": "symlink",
            "size": len(os.fsencode(second_target)),
            "link_target": second_target,
            "sha256": hashlib.sha256(os.fsencode(second_target)).hexdigest(),
            "stat": _stat_identity(after),
            "stable_while_hashed": stable,
            **({} if stable else {"error": "symlink changed while measured"}),
        }
    return {
        "exists": True,
        "kind": _mode_kind(before.st_mode),
        "size": before.st_size,
        "stat": _stat_identity(before),
        "stable_while_hashed": True,
    }


def _guard_directory_identity(path: Path) -> dict[str, object]:
    try:
        before = path.lstat()
        after = path.lstat()
    except OSError as exc:
        return {
            "exists": False,
            "kind": "missing",
            "stable_while_measured": False,
            "error": f"cannot lstat: {exc}",
        }
    is_directory = stat.S_ISDIR(before.st_mode)
    stable = is_directory and _stable_stat_equal(before, after)
    return {
        "exists": True,
        "kind": _mode_kind(after.st_mode),
        "stat": _stat_identity(after),
        "stable_while_measured": stable,
        **(
            {}
            if stable
            else {"error": "directory is not stable while measured"}
        ),
    }


def _source_tree_paths(root: Path) -> list[str]:
    return [
        path.relative_to(root).as_posix()
        for path in sorted((root / "distroforge").rglob("*"))
        if path.is_file() or path.is_dir() or path.is_symlink()
    ]


def _stat_identity(value: os.stat_result) -> dict[str, int]:
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "mode": value.st_mode,
        "links": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }


def _stable_stat_equal(first: os.stat_result, second: os.stat_result) -> bool:
    return _stat_identity(first) == _stat_identity(second)


def _mode_kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "other"


def _normalise_effective(value: Any) -> Any:
    """Normalise user-visible options without mutable internal run bookkeeping."""
    if isinstance(value, Path):
        return str(value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _normalise_effective(getattr(value, field.name))
            for field in dataclasses.fields(value)
            if not field.name.startswith("_")
        }
    if isinstance(value, dict):
        return {
            str(key): _normalise_effective(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if not str(key).startswith("_")
        }
    if isinstance(value, (list, tuple)):
        return [_normalise_effective(item) for item in value]
    if isinstance(value, set):
        return sorted(_normalise_effective(item) for item in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _normalise(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _normalise(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): _normalise(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    if isinstance(value, set):
        return sorted(_normalise(item) for item in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _git_bytes(cwd: Path, *args: str) -> bytes | None:
    try:
        completed = subprocess.run(
            ("git", *args),
            cwd=cwd,
            capture_output=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout if completed.returncode == 0 else None


def _git_text(cwd: Path, *args: str) -> str | None:
    output = _git_bytes(cwd, *args)
    if output is None:
        return None
    return output.decode("utf-8", errors="replace").strip()


def _source_tree_sha256(root: Path) -> str:
    entries = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
        }
        for path in sorted((root / "distroforge").rglob("*.py"))
        if path.is_file()
    ]
    return canonical_sha256(entries)


def _tool_version(path: Path) -> str:
    for flag in ("--version", "-V"):
        try:
            completed = subprocess.run(
                (str(path), flag),
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unavailable"
        output = (completed.stdout or completed.stderr).strip()
        if output:
            return output.splitlines()[0][:500]
    return "unavailable"


def _file_identity(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {"path": str(path), "size": 0, "sha256": ""}
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }
