"""Session-wide test environment.

The Qt platform plugin is set here rather than in individual modules. It used to
depend on whichever Qt-touching module happened to import first calling
`os.environ.setdefault`, so the suite passed for a reason that had nothing to do
with intent: run a single Qt test on its own, or reorder the files, and it would
try to reach a real display.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from distroforge.core import qemu_invocation
from distroforge.core.bootstrap import _ROOTFS_REQUIREMENTS
from distroforge.core.evidence_run import canonical_sha256
from distroforge.core.project import Project

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# Qt reads XDG_RUNTIME_DIR at startup and warns when it is unset or wrong-moded;
# offscreen does not need it, and the warning is noise in every CI log.
os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")


def _artifact(path: Path) -> dict[str, object]:
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def write_valid_qemu_report(
    output_dir: Path,
    iso: Path,
    *,
    run_id: str = "proof-run",
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = output_dir / "evidence" / "runs" / run_id
    qemu_dir = run_dir / "qemu"
    qemu_dir.mkdir(parents=True, exist_ok=True)
    serial = qemu_dir / "serial.log"
    serial.write_text("host login: ", encoding="utf-8")
    marker = b"login:"
    serial_artifact = _artifact(serial)
    serial_artifact["path"] = "qemu/serial.log"
    qemu_argv = ["qemu-system-x86_64", "-cdrom", str(iso)]
    payload = {
        "schema": "distroforge.qemu-lab.v2",
        "run_id": run_id,
        "status": "completed",
        "verdict": "passed",
        "started_at": "2026-07-29T00:00:00+00:00",
        "finished_at": "2026-07-29T00:01:00+00:00",
        "iso": _artifact(iso),
        "accelerated": False,
        "boot": {
            "profile": "live",
            "firmware": "bios",
            "secure_boot": False,
            "required_milestone": "login_prompt",
            "reached_milestone": "login_prompt",
            "matched_marker": {
                "pattern": "login:",
                "line": "host login:",
                "byte_offset": serial.read_bytes().find(marker),
            },
            "terminal_refusal": None,
            "sealed_after_vm_stop": True,
        },
        "artifacts": {
            "serial_log": serial_artifact,
            "screenshot": None,
        },
        "execution": {
            "accelerated": False,
            "memory_mb": 4096,
            "cpus": 2,
            "disk_size": "24G",
            "network": False,
            "tpm": False,
            "timeout_seconds": 300,
            "qmp_socket": "test",
            "pid_file": "test",
            "toolchain": {
                "qemu-system-x86_64": {
                    "available": True,
                    "path": "/usr/bin/qemu-system-x86_64",
                    "sha256": "a" * 64,
                    "version": "QEMU test fixture",
                }
            },
            "argv": qemu_argv,
            "entrypoint": {
                "history_index": 0,
                "captured_at": "2026-07-29T00:00:00+00:00",
                "scope": "host-entrypoint-pre-dispatch",
                "argv": qemu_argv,
                "argv0": "qemu-system-x86_64",
                "available": True,
                "path": "/usr/bin/qemu-system-x86_64",
                "size": 1,
                "sha256": "a" * 64,
                "stable_while_hashed": True,
            },
            "firmware": {},
        },
        "error": None,
    }
    report = output_dir / "qemu-lab-report.json"
    report_text = json.dumps(payload, indent=2) + "\n"
    (run_dir / report.name).write_text(report_text, encoding="utf-8")
    report.write_text(report_text, encoding="utf-8")
    return report


def write_valid_boot_proof(
    project: Project,
    iso: Path,
    *,
    run_id: str = "proof-run",
) -> Path:
    qemu_report = write_valid_qemu_report(project.output_dir, iso, run_id=run_id)
    run_dir = project.output_dir / "evidence" / "runs" / run_id
    command_log = run_dir / "commands.jsonl"
    command_log.write_text(
        '{"event":"finish","argv":["qemu-system-x86_64"],"returncode":0}\n',
        encoding="utf-8",
    )
    payload = {
        "schema": "distroforge.boot-proof.v2",
        "run_id": run_id,
        "created_at": "2026-07-29T00:01:00+00:00",
        "project": str(project.root),
        "iso": str(iso),
        "iso_sha256": hashlib.sha256(iso.read_bytes()).hexdigest(),
        "backend": "qemu",
        "status": "ready",
        "blocked": False,
        "proof": "boot-proof.json",
        "qemu_report": qemu_report.name,
        "notes": ["fixture runtime proof"],
        "evidence": {},
        "attempted_backends": ["qemu"],
        "selected_backend": "qemu",
        "proof_level": "runtime",
        "firmware": "bios",
        "secure_boot": False,
        "immutable_proof": "boot-proof.json",
        "qemu_report_sha256": hashlib.sha256(qemu_report.read_bytes()).hexdigest(),
        "reached_milestone": "login_prompt",
        "build_run_id": "",
        "command_log": command_log.name,
        "run_manifest": "RUN-MANIFEST.json",
    }
    proof = project.output_dir / "boot-proof.json"
    proof_text = json.dumps(payload, indent=2) + "\n"
    immutable_proof = run_dir / "boot-proof.json"
    immutable_proof.write_text(proof_text, encoding="utf-8")
    proof.write_text(proof_text, encoding="utf-8")
    manifest = {
        "schema": "distroforge.boot-proof-run-manifest.v1",
        "run_id": run_id,
        "mode": "execute",
        "status": "ready",
        "files": [
            *[
                _artifact(path)
                for path in sorted(run_dir.rglob("*"))
                if path.is_file()
                and path.name
                not in {"RUN-MANIFEST.json", "RUN-MANIFEST.json.sha256"}
            ],
            _artifact(iso),
        ],
    }
    manifest_path = run_dir / "RUN-MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (run_dir / "RUN-MANIFEST.json.sha256").write_text(
        f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  "
        "RUN-MANIFEST.json\n",
        encoding="utf-8",
    )
    return proof


def write_valid_build_evidence(
    project: Project,
    iso: Path,
    *,
    run_id: str = "build-run",
) -> Path:
    output_dir = iso.parent
    run_dir = output_dir / "evidence" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    iso_sha = hashlib.sha256(iso.read_bytes()).hexdigest()
    tool_commands = (
        ("mmdebstrap", "Bootstrap fixture rootfs"),
        ("mksquashfs", "Pack fixture rootfs"),
        ("grub-mkimage", "Build fixture GRUB image"),
        ("mformat", "Format fixture ESP"),
        ("mcopy", "Copy fixture EFI payload"),
        ("xorriso", "Build fixture ISO"),
    )
    command_records = [
        {
            "argv": [tool],
            "cwd": str(project.root),
            "needs_root": False,
            "description": description,
            "has_stdin": False,
            "env_keys": [],
            "env_sha256": canonical_sha256({}),
        }
        for tool, description in tool_commands
    ]
    executed_entrypoints = [
        {
            "history_index": index,
            "captured_at": "2026-07-29T00:00:01+00:00",
            "scope": "host-entrypoint-pre-dispatch",
            "argv": [tool],
            "argv0": tool,
            "available": True,
            "path": f"/usr/bin/{tool}",
            "size": 1,
            "sha256": "d" * 64,
            "stable_while_hashed": True,
            "execution_chain": [
                {
                    "command": tool,
                    "scope": "host-pre-dispatch",
                    "root": None,
                    "available": True,
                    "path": f"/usr/bin/{tool}",
                    "size": 1,
                    "sha256": "d" * 64,
                    "stable_while_hashed": True,
                }
            ],
        }
        for index, (tool, _description) in enumerate(tool_commands)
    ]
    provenance = {
        "schema": "distroforge.provenance.v2",
        "attestation_kind": "build",
        "generated_at": "2026-07-29T00:00:00+00:00",
        "project": project.to_dict(),
        "output_iso": str(iso),
        "output_iso_sha256": iso_sha,
        "artifacts": [_artifact(iso)],
        "sbom_format": "native",
        "run_id": run_id,
        "run": {
            "schema": "distroforge.evidence-run.v1",
            "run_id": run_id,
            "mode": "execute",
            "builder_source": {"kind": "git", "worktree_sha256": "b" * 64},
            "definition": {"effective_sha256": "c" * 64},
            "toolchain": {
                tool: {"available": True, "sha256": "d" * 64}
                for tool, _description in tool_commands
            },
        },
        "command_records": command_records,
        "commands_sha256": canonical_sha256(command_records),
        "observed_toolchain": {
            "command_count": len(command_records),
            "resolution_scope": "post-run-path-snapshot",
            "tools": {
                tool: {
                    "available": True,
                    "sha256": "d" * 64,
                    "observed_count": 1,
                }
                for tool, _description in tool_commands
            },
        },
        "executed_host_entrypoints": executed_entrypoints,
        "executed_host_entrypoints_sha256": canonical_sha256(
            executed_entrypoints
        ),
    }
    provenance_text = json.dumps(provenance, indent=2) + "\n"
    immutable_provenance = run_dir / "distroforge-provenance.json"
    immutable_provenance.write_text(provenance_text, encoding="utf-8")
    (output_dir / "distroforge-provenance.json").write_text(
        provenance_text,
        encoding="utf-8",
    )
    build = {
        "schema": "distroforge.iso-build.v2",
        "run_id": run_id,
        "project": str(project.root),
        "status": "built",
        "execute": True,
        "output_iso": str(iso),
        "output_exists": True,
        "output_size": iso.stat().st_size,
        "output_sha256": iso_sha,
    }
    iso_report = run_dir / "ISO-BUILD.json"
    build_text = json.dumps(build, indent=2) + "\n"
    iso_report.write_text(build_text, encoding="utf-8")
    (output_dir / "ISO-BUILD.json").write_text(build_text, encoding="utf-8")
    command_log = run_dir / "commands.jsonl"
    command_log.write_text(
        "".join(
            json.dumps(
                {
                    "event": "start",
                    "argv": record["argv"],
                    "cwd": record["cwd"],
                    "needs_root": record["needs_root"],
                    "description": record["description"],
                    "has_stdin": record["has_stdin"],
                    "env_keys": record["env_keys"],
                    "env_sha256": record["env_sha256"],
                }
            )
            + "\n"
            for record in command_records
        ),
        encoding="utf-8",
    )
    sums = output_dir / "SHA256SUMS"
    sums.write_text(f"{iso_sha}  {iso.name}\n", encoding="utf-8")
    buildinfo = output_dir / "BUILDINFO"
    buildinfo.write_text("Build-Date: fixture\n", encoding="utf-8")
    html_report = output_dir / "report.html"
    html_report.write_text("<html></html>\n", encoding="utf-8")
    manifest = {
        "schema": "distroforge.build-run-manifest.v1",
        "run_id": run_id,
        "mode": "execute",
        "status": "built",
        "files": [
            _artifact(immutable_provenance),
            _artifact(iso_report),
            _artifact(iso),
            _artifact(command_log),
            _artifact(output_dir / "distroforge-provenance.json"),
            _artifact(sums),
            _artifact(buildinfo),
            _artifact(html_report),
        ],
    }
    manifest_path = run_dir / "RUN-MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    (run_dir / "RUN-MANIFEST.json.sha256").write_text(
        f"{manifest_sha}  RUN-MANIFEST.json\n",
        encoding="utf-8",
    )
    return immutable_provenance


def make_rootfs(root: Path, codename: str | None = None) -> Path:
    """Materialise the smallest tree ``rootfs_verdict`` will accept as a rootfs.

    Built *from* ``_ROOTFS_REQUIREMENTS`` rather than from a hand-copied list of paths,
    because the hand-copied version already cost four test files. When a package manager
    joined the requirements, every test that had spelled out "dpkg status plus an
    os-release" started failing on the new entry before reaching what it was written to
    check -- none of them was about completeness, they all just needed a plausible tree.
    Deriving it means adding a fifth requirement updates them all, and
    ``test_the_shared_rootfs_helper_satisfies_the_real_requirements`` fails loudly here
    if this ever drifts from the production definition instead of quietly in four places.

    The first alternative of each requirement is the one created: os-release(5) allows
    two locations and a real Ubuntu tree uses ``/etc``.
    """
    for _label, paths in _ROOTFS_REQUIREMENTS:
        target = root / paths[0]
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_text("", encoding="utf-8")
    body = "ID=ubuntu\n" + (f"VERSION_CODENAME={codename}\n" if codename else "")
    (root / "etc/os-release").write_text(body, encoding="utf-8")
    return root


@pytest.fixture(scope="session", autouse=True)
def _isolated_config_home(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Give the whole session a throwaway XDG_CONFIG_HOME.

    The suite must never read or write the user's live
    ``~/.config/distroforge/ui.json``; `distroforge.ui.preferences` resolves that
    path from this variable. Six modules used to arrange it for themselves, at
    import time, with

        os.environ.setdefault("XDG_CONFIG_HOME", tempfile.mkdtemp())

    which leaked a directory per module per run. `setdefault` evaluates its second
    argument before it decides whether to use it, so all six calls to `mkdtemp`
    ran and five of the six directories were created, never used, and never
    removed -- and the sixth, the one that won, was not removed either. Measured
    2026-07-27: 1425 had piled up under /tmp, 241 of them holding a `ui.json`.

    `tmp_path_factory` puts this under pytest's own base directory, which pytest
    rotates (it keeps the last three runs), so nothing accumulates.

    Two details are deliberate:

    - `setenv`, not `setdefault`. The old form skipped the redirection entirely
      for anyone who exports XDG_CONFIG_HOME -- a legitimate thing to do -- and
      pointed the suite straight at their real configuration. The isolation this
      fixture exists for cannot be conditional on the developer's environment.
    - Session scope with autouse, rather than the import-time statement it
      replaces. `preferences.config_dir()` reads the variable on every call and
      no module reads it while importing, so setting it at fixture time is early
      enough; pytest orders session-scoped autouse fixtures ahead of the
      module-scoped `qt_app` fixtures, so QApplication is still built under it.

    Tests that want their own config home keep overriding it with
    `monkeypatch.setenv`, which nests inside this one and restores to it.
    """
    config_home = tmp_path_factory.mktemp("xdg-config")
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("XDG_CONFIG_HOME", str(config_home))
        yield


@pytest.fixture(scope="session", autouse=True)
def _unaccelerated_qemu() -> Iterator[None]:
    """Decide QEMU acceleration for the suite instead of letting the host decide it.

    Every service that launches QEMU asks `qemu_invocation.kvm_is_usable()`, which
    reads a real device node. Left alone, the argv a test asserts against would carry
    `-enable-kvm` on a developer's machine and not on a CI runner -- the same test,
    two outcomes, neither of them about the code. Pointing the probe at a path that
    cannot exist makes emulation the answer everywhere.

    The probe itself is tested in `test_qemu_invocation.py` against files it creates,
    and the two tests that assert the accelerated argv point this at one of those.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(qemu_invocation, "KVM_DEVICE", Path("/nonexistent/dev/kvm"))
        yield


def pytest_collection_modifyitems(items) -> None:
    """Skip the mode-locked-path tests when the suite runs as root.

    Those tests lock a directory to 0500 and assert that DistroForge falls back to a
    privileged command. Root -- and the owner of the directory -- can write it anyway,
    so the PermissionError never arrives and the assertion fails for a reason that has
    nothing to do with the code. Rootless is the supported configuration: debian/control
    declares Rules-Requires-Root: no and ci.yml's distro-dependencies job runs the suite as
    an unprivileged user for exactly this reason. It is the only job that does: the golden
    path builds the package as the container's root, because autopkgtest's null backend has
    to install what it built, so these tests skip there and that job is not where they are
    covered.
    """
    if os.geteuid() != 0:
        return
    skip = pytest.mark.skip(reason="running as root: a mode-locked path is still writable")
    for item in items:
        if "unprivileged" in item.keywords:
            item.add_marker(skip)
