from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
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
TOOLCHAIN_BINARIES: tuple[str, ...] = (
    "python3",
    "mmdebstrap",
    "debootstrap",
    "apt-get",
    "dpkg",
    "mksquashfs",
    "xorriso",
    "grub-mkimage",
    "mformat",
    "mmd",
    "mcopy",
    "mdir",
    "qemu-system-x86_64",
    "sha256sum",
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
    """Create an evidence file once and refuse accidental replacement."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(content)


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
    effective = {
        "project": project.to_dict(),
        "options": options,
    }
    definition_identity: dict[str, object] = {
        "path": str(definition) if definition else None,
        "sha256": sha256_file(definition) if definition and definition.is_file() else None,
        "effective_sha256": canonical_sha256(effective),
    }
    project_file = project.root / "project.json"
    if project_file.is_file():
        definition_identity["project_file"] = str(project_file)
        definition_identity["project_file_sha256"] = sha256_file(project_file)
    return {
        "schema": EVIDENCE_SCHEMA,
        "run_id": run_id or new_run_id(),
        "created_at": datetime.now(UTC).isoformat(),
        "mode": mode,
        "distroforge": {
            "version": __version__,
            "python": _file_identity(Path(sys.executable).resolve()),
        },
        "builder_source": builder_source_identity(use_git=mode == "execute"),
        "definition": definition_identity,
        "toolchain": toolchain_identity(include_versions=mode == "execute"),
    }


def builder_source_identity(*, use_git: bool = True) -> dict[str, object]:
    """Describe the source bytes at the instant a run starts.

    This must not be cached: one long-lived CLI or GUI process can launch several
    builds while the worktree changes between them. Reusing the first identity would
    bind a later ISO to source bytes that were no longer present.
    """
    source_root = Path(__file__).resolve().parents[2]
    if not use_git:
        return {
            "kind": "source-tree-plan",
            "root": str(source_root),
            "source_tree_sha256": _source_tree_sha256(source_root),
        }
    git_root_text = _git_text(source_root, "rev-parse", "--show-toplevel")
    if git_root_text is None:
        return {
            "kind": "source-tree",
            "root": str(source_root),
            "source_tree_sha256": _source_tree_sha256(source_root),
        }
    git_root = Path(git_root_text)
    head = _git_text(git_root, "rev-parse", "HEAD") or ""
    tree = _git_text(git_root, "rev-parse", "HEAD^{tree}") or ""
    branch = _git_text(git_root, "branch", "--show-current") or ""
    diff = _git_bytes(git_root, "diff", "--binary", "HEAD", "--") or b""
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
            if path.is_file():
                untracked.append({"path": name, "sha256": sha256_file(path)})
    signature = _git_text(git_root, "log", "-1", "--format=%G? %GF") or ""
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
        "dirty": bool(diff or untracked),
        "tracked_diff_sha256": diff_sha256,
        "untracked": untracked,
        "worktree_sha256": worktree_sha256,
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
        tools[name] = {
            "available": True,
            "path": str(path),
            "sha256": sha256_file(path) if path.is_file() else None,
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
