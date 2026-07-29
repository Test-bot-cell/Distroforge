"""Session-wide test environment.

The Qt platform plugin is set here rather than in individual modules. It used to
depend on whichever Qt-touching module happened to import first calling
`os.environ.setdefault`, so the suite passed for a reason that had nothing to do
with intent: run a single Qt test on its own, or reorder the files, and it would
try to reach a real display.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from distroforge.core import qemu_invocation
from distroforge.core.bootstrap import _ROOTFS_REQUIREMENTS
from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandRunner
from distroforge.core.evidence_run import canonical_sha256
from distroforge.core.iso_evidence import (
    ISO_ASSEMBLY_FILENAME,
    ISO_ASSEMBLY_SCHEMA,
    validate_iso_assembly_evidence,
)
from distroforge.core.package_causality import write_package_filesystem_causality
from distroforge.core.package_evidence import (
    PACKAGE_INPUTS_SCHEMA,
    PACKAGE_TRANSACTION_SCHEMA,
    package_apt_command_argv_sha256,
    package_source_policy_sha256,
    validate_package_evidence_payload,
)
from distroforge.core.project import Project
from distroforge.core.rootfs_evidence import (
    RootfsEvidenceService,
    validate_rootfs_evidence,
)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# Qt reads XDG_RUNTIME_DIR at startup and warns when it is unset or wrong-moded;
# offscreen does not need it, and the warning is noise in every CI log.
os.environ.setdefault("QT_LOGGING_RULES", "qt.qpa.*=false")

_PACKAGE_FIXTURE_BUILD_TIME = "2026-07-29T19:00:00+00:00"
_PACKAGE_FIXTURE_FINGERPRINT = "944A5B2E697AE75752752332F7B76532EE05A7FE"
_PACKAGE_FIXTURE_DEB = (
    "ITxhcmNoPgpkZWJpYW4tYmluYXJ5ICAgMTc4NTM0MDQ2OCAgMCAgICAgMCAgICAgMTAwNjQ0ICA0"
    "ICAgICAgICAgYAoyLjAKY29udHJvbC50YXIuenN0IDE3ODUzNDA0NjggIDAgICAgIDAgICAgIDEw"
    "MDY0NCAgMjIyICAgICAgIGAKKLUv/WQAJ4UGANLLJRlgeQMzyyomMYkkMnVVSBJQ9/EKv1mUGIAM"
    "EQCvJdviru7XMnscvkHm7tuuH4CprlY/fIXWuK2C3YSVU44X2dc75J+7+0jlO+NbI0DT6nvZdr6Y"
    "fQeYQSFQYUoF++2+J4ALLPfnpNJXzWyVCBmNWcyZUGoYiOafsdtBiNn9o5Rfc+fFQ0ZiJtFAiEkN"
    "WtBjRiIeR0LEQQgVIOBogjHXZYMZL8+CtbOxtQAfOEEFjjgssConD1wGDzDdsxSGATj7A6ZGDJ6H"
    "QAKYAjCfgBvMsSRkZGF0YS50YXIuenN0ICAgIDE3ODUzNDA0NjggIDAgICAgIDAgICAgIDEwMDY0"
    "NCAgMTU4ICAgICAgIGAKKLUv/WQAJ4UEAFJHFhGgb6DlN1t6+n/nyFONBhCOKQ1su3kF1mJU10ro"
    "oU1K6A1CTM2YFS3mDDdnpcWLGa2qZ4l/GdXiIfpRVfGVeOEOoaprcZ/QnsoTb4OcvPnyh7SfRE5K"
    "3kMEFSCQF5cb2Xu/wKqGXHtw1I4DagOqI5Aqbyo5UCXNVdIYkKqkUTA4EB2CJKAVINkJXJ/EEPM/"
    "J/s="
)
_PACKAGE_FIXTURE_PUBLIC_KEY = (
    "mQENBGpqSNsBCADVlHSgZDkHG+uJ7+GcQoQIr/y/QXqNbxZ9+QSe22DIkXXAeXctfvfgVEPSQXWh"
    "i5yN2KVHXPSSAOTAxRAPDbg+jtvJVPPfpc4nYMDfXRiEGbvQKhTl/rA2smQuQIf4g7B6c34afFTG"
    "8sCEOhyhzj1LBJgwjfw3ASHB173vdnnLQXeuXvv0bH/vPlTqGrJl8HmWq02rKJKdCeBgLzb5d3bx"
    "bgFZ4wo/Xh0L/D9alIGx/rUVzb7fTPXo+kQORPt0JfFotHFL/HyLCRUcGpgFaPmj0n9GCTaY6vZL"
    "UorKRCX5wvYdTsXELR3a/2W5MHYkCquyB9Rbwnq6wykjDuE6N/NPABEBAAG0OURpc3Ryb0Zvcmdl"
    "IEZpeHR1cmUgQXJjaGl2ZSA8Zml4dHVyZUBkaXN0cm9mb3JnZS5pbnZhbGlkPokBTgQTAQoAOBYh"
    "BJRKWy5peudXUnUjMve3ZTLuBaf+BQJqakjbAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJ"
    "EPe3ZTLuBaf+wmEH/1HrvxdMQdmVhvZDc0tz1WLjScGhSophrTugoeX364mR9oaQSb3zYa8tOgGr"
    "rUo3vuRA7j/O5442G/sRiJJi1vQAyZiivlXZuRgTTRhHG+fcnEyxEjOBRcTLKn4ZS1pPAwrvqKkF"
    "IiD03zdhTq9WCss+++EXRRIgk960VIMj1uZl1aGtmeUvxYYwUEHfgMZ+RA5UTejC+9fRZ3cx0sQG"
    "La7m0vPLBydORllSqIGq8fIqHOoIjnOYGOtAj8zLbhgAEEIq1U/+rXU/bzQjTZebYhWJsRHkPD5G"
    "343/IvUh6+JW5fQgjAY230k4MQc55KFH0j6FXINfS+VfDXr/uj+JLfA="
)
_PACKAGE_FIXTURE_INRELEASE = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Origin: Fixture
Suite: proof
Codename: proof
Date: Wed, 29 Jul 2026 10:00:00 +0000
Valid-Until: Thu, 30 Jul 2026 10:00:00 +0000
Architectures: all
Components: main
SHA256:
 aa17eee632a9081bf90bc32a29ace199b14ac888c3a0a85c015a8750c578748d 207 main/binary-all/Packages
-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEElEpbLml651dSdSMy97dlMu4Fp/4FAmpqSOsACgkQ97dlMu4F
p/56xwf+K/Pszib7FfRk9vqoU6UrhatZ0GnjW4gbg1qJwbCQt+0zARWSahwy6DUd
XYW+XDd7ICQaJQHxsUnVg1bMc8eVWzZe7Ila3KJjS/gH5vpej3T87ECiXvNXtNRl
J4wD7Fj5fGbRfzpEpjKYc06mDUKEbhNDiP8/oyZmd3J5sQavtAnGk6Hsl9nodnip
rUgwVyyeFau6YFQ4QtGYOBVFfqrdqaoUQf3L6v8m9av7Wati047iQ6reKW/Y+278
IDJu9p7Lg+h7KXFLtDIRd59XAhHpAJo+m8t4/mhhSdN2+1yxdxBiJCIDHWjBlApb
RGQQq9aJzapdvT3gbv/QHaxiN5/XTQ==
=qasA
-----END PGP SIGNATURE-----
"""

_PRODUCT_FIXTURE_TOOLS = ("dpkg-deb", "mksquashfs", "unsquashfs", "xorriso")


def _require_product_fixture_tools() -> None:
    missing = [tool for tool in _PRODUCT_FIXTURE_TOOLS if shutil.which(tool) is None]
    if missing:
        pytest.skip(
            "authoritative build-evidence fixture requires: " + ", ".join(missing)
        )


def _package_fixture_keyring_bytes() -> bytes:
    return base64.b64decode(_PACKAGE_FIXTURE_PUBLIC_KEY, validate=True)


def _package_fixture_source_policy() -> dict[str, object]:
    return {
        "policy_id": "fixture-archive",
        "base_uri": "https://repo.invalid",
        "suites": ["proof"],
        "codenames": ["proof"],
        "components": ["main"],
        "architectures": ["all"],
        "signer_fingerprints": [_PACKAGE_FIXTURE_FINGERPRINT],
        "keyring_sha256": [
            hashlib.sha256(_package_fixture_keyring_bytes()).hexdigest()
        ],
        "snapshot_at": None,
        "max_release_age_seconds": 24 * 60 * 60,
        "max_future_skew_seconds": 5 * 60,
        "require_valid_until": True,
    }


def package_fixture_options(
    options: BuildOptions | None = None,
) -> BuildOptions:
    """Return build policy that independently pins the package-proof fixture."""

    options = options or BuildOptions()
    options.use_sudo = False
    options.bootstrap.archive_signer_fingerprints = [_PACKAGE_FIXTURE_FINGERPRINT]
    options.bootstrap.archive_keyring_sha256 = hashlib.sha256(
        _package_fixture_keyring_bytes()
    ).hexdigest()
    options.bootstrap.source_policies = [_package_fixture_source_policy()]
    return options


def _artifact(path: Path) -> dict[str, object]:
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _run_artifact(
    path: Path,
    run_dir: Path,
    **metadata: object,
) -> dict[str, object]:
    identity = _artifact(path)
    identity["path"] = str(path.relative_to(run_dir))
    identity.update(metadata)
    return identity


def _write_valid_package_input_evidence(
    run_dir: Path,
    run_id: str,
    command_argv: tuple[tuple[str, ...], ...],
) -> Path:
    """Create a self-contained, offline-verifiable APT transaction fixture.

    These are real bytes, not a validator stub: the embedded archive key signs
    InRelease, InRelease binds Packages, Packages binds a valid .deb, and the
    .deb's internal dpkg identity closes the final installed-package inventory.
    """

    blobs = run_dir / "apt" / "blobs"
    for kind in ("source", "keyring", "release", "index", "deb"):
        (blobs / kind).mkdir(parents=True, exist_ok=True)

    def write_blob(kind: str, data: bytes, suffix: str = "") -> Path:
        digest = hashlib.sha256(data).hexdigest()
        path = blobs / kind / f"{digest}{suffix}"
        path.write_bytes(data)
        return path

    deb_bytes = base64.b64decode(_PACKAGE_FIXTURE_DEB, validate=True)
    deb = write_blob("deb", deb_bytes, ".deb")
    packages_text = "\n".join(
        [
            "Package: proof-package",
            "Version: 1.2.3-1",
            "Architecture: all",
            f"Size: {len(deb_bytes)}",
            f"SHA256: {hashlib.sha256(deb_bytes).hexdigest()}",
            "Filename: pool/main/p/proof-package/proof-package_1.2.3-1_all.deb",
            "",
        ]
    )
    packages = write_blob("index", packages_text.encode())
    keyring = write_blob(
        "keyring",
        _package_fixture_keyring_bytes(),
        ".gpg",
    )
    inrelease = write_blob(
        "release",
        _PACKAGE_FIXTURE_INRELEASE.encode(),
    )
    source = write_blob(
        "source",
        (
            b"deb [signed-by=/usr/share/keyrings/distroforge-fixture.gpg] "
            b"https://repo.invalid proof main\n"
        ),
    )

    records = [
        _run_artifact(
            source,
            run_dir,
            kind="source",
            source_path="/etc/apt/sources.list.d/distroforge-fixture.list",
            extra="",
        ),
        _run_artifact(
            keyring,
            run_dir,
            kind="keyring",
            source_path="/usr/share/keyrings/distroforge-fixture.gpg",
            extra="host-bootstrap",
        ),
        _run_artifact(
            inrelease,
            run_dir,
            kind="release",
            source_path="/var/lib/apt/lists/repo.invalid_proof_InRelease",
            extra="",
        ),
        _run_artifact(
            packages,
            run_dir,
            kind="index",
            source_path=("/var/lib/apt/lists/repo.invalid_proof_main_binary-all_Packages"),
            extra="https://repo.invalid/dists/proof/main/binary-all/Packages",
        ),
        _run_artifact(
            deb,
            run_dir,
            kind="deb",
            source_path=("/var/cache/apt/archives/proof-package_1.2.3-1_all.deb"),
            extra="",
        ),
    ]
    transaction = {
        "schema": PACKAGE_TRANSACTION_SCHEMA,
        "run_id": run_id,
        "id": "bootstrap",
        "kind": "bootstrap",
        "fresh_rootfs": True,
        "records": records,
        "inventory": [
            {
                "package": "proof-package",
                "version": "1.2.3-1",
                "architecture": "all",
            }
        ],
        "complete": True,
        "issues": [],
    }
    transaction_path = run_dir / "apt" / "transactions" / "bootstrap.json"
    transaction_path.parent.mkdir(parents=True, exist_ok=True)
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    final_state = {
        "schema": PACKAGE_TRANSACTION_SCHEMA,
        "run_id": run_id,
        "id": "final-apt-state",
        "kind": "apt-state",
        "fresh_rootfs": True,
        "records": [record for record in records if record["kind"] != "deb"],
        "inventory": [],
        "complete": True,
        "issues": [],
    }
    final_state_path = run_dir / "apt" / "transactions" / "final-apt-state.json"
    final_state_path.write_text(
        json.dumps(final_state, indent=2) + "\n",
        encoding="utf-8",
    )
    payload: dict[str, object] = {
        "schema": PACKAGE_INPUTS_SCHEMA,
        "run_id": run_id,
        "scope": "target-root",
        "source_mode": "bootstrap",
        "capture_mode": "dpkg-pre-install-sealed-copy",
        "fresh_rootfs": True,
        "archive_keyring": {
            "source": "/usr/share/keyrings/distroforge-fixture.gpg",
            "expected_sha256": hashlib.sha256(keyring.read_bytes()).hexdigest(),
        },
        "allowed_signer_fingerprints": [_PACKAGE_FIXTURE_FINGERPRINT],
        "source_policy_sha256": package_source_policy_sha256(
            [_package_fixture_source_policy()]
        ),
        "verification_time": _PACKAGE_FIXTURE_BUILD_TIME,
        "apt_command_argv_sha256": package_apt_command_argv_sha256(command_argv),
        "transactions": [
            _run_artifact(transaction_path, run_dir),
            _run_artifact(final_state_path, run_dir),
        ],
        "baseline_inventory": [],
        "final_inventory": [
            {
                "package": "proof-package",
                "version": "1.2.3-1",
                "architecture": "all",
            }
        ],
    }
    validation = validate_package_evidence_payload(
        payload,
        run_dir,
        run_gpg=True,
        expected_source_mode="bootstrap",
        expected_signer_fingerprints=[_PACKAGE_FIXTURE_FINGERPRINT],
        expected_keyring_sha256=hashlib.sha256(keyring.read_bytes()).hexdigest(),
        expected_source_policies=[_package_fixture_source_policy()],
        expected_verification_time=_PACKAGE_FIXTURE_BUILD_TIME,
        apt_command_argv=command_argv,
    )
    if not validation.ok:
        raise AssertionError(f"invalid package-input fixture: {validation.detail}")
    payload["validation"] = {
        "ok": validation.ok,
        "detail": validation.detail,
        "filesystem_causality": validation.filesystem_causality,
        "release_ready": validation.release_ready,
    }
    target = run_dir / "PACKAGE-INPUTS.json"
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


def _closed_execution_entrypoint(index: int, tool: str) -> dict[str, object]:
    stat_identity: dict[str, object] = {
        "device": 1,
        "inode": index + 1,
        "mode": 0o100755,
        "mtime_ns": 1,
        "ctime_ns": 1,
    }
    pre: dict[str, object] = {
        "command": tool,
        "argv_index": 0,
        "scope": "host-pre-dispatch",
        "root": None,
        "available": True,
        "path": f"/usr/bin/{tool}",
        "size": 1,
        "sha256": "d" * 64,
        "stable_while_hashed": True,
        "path_matches_open_file": True,
        **stat_identity,
    }
    post: dict[str, object] = {
        **pre,
        "scope": "host-post-dispatch",
        "held_fd_available": True,
        "held_fd_sha256": "d" * 64,
        "held_fd_stable_while_rehashed": True,
        "held_fd_metadata_unchanged": True,
        "held_fd_sha256_unchanged": True,
        "resolved_path_unchanged": True,
        "resolved_path_matches_held_fd": True,
        "resolved_sha256_unchanged": True,
        "stable_across_dispatch": True,
        "divergences": [],
        "held_fd": {
            "size": 1,
            "sha256": "d" * 64,
            **stat_identity,
        },
    }
    post_chain = [post]
    descriptor = f"/proc/1234/fd/{index + 10}"
    dispatch_binding = {
        "command": tool,
        "argv_index": 0,
        "descriptor_path": descriptor,
        "mode": "outer-executable",
        "device": stat_identity["device"],
        "inode": stat_identity["inode"],
        "size": 1,
        "sha256": "d" * 64,
    }
    return {
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
        "execution_chain": [pre],
        "dispatch_bound": True,
        "dispatch_argv": [tool],
        "dispatch_executable": descriptor,
        "dispatch_bindings": [dispatch_binding],
        "post_dispatch_captured_at": "2026-07-29T00:00:02+00:00",
        "post_dispatch_process_returncode": 0,
        "post_dispatch_verified": True,
        "stable_across_dispatch": True,
        "post_execution_chain": post_chain,
        "post_execution_chain_sha256": canonical_sha256(post_chain),
        "post_dispatch_divergences": [],
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
                and path.name not in {"RUN-MANIFEST.json", "RUN-MANIFEST.json.sha256"}
            ],
            _artifact(iso),
        ],
    }
    manifest_path = run_dir / "RUN-MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (run_dir / "RUN-MANIFEST.json.sha256").write_text(
        f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  RUN-MANIFEST.json\n",
        encoding="utf-8",
    )
    return proof


def _write_valid_rootfs_manifest(
    run_dir: Path,
    run_id: str,
    rootfs: Path,
) -> Path:
    (rootfs / "etc").mkdir(parents=True, exist_ok=False)
    (rootfs / "etc" / "os-release").write_bytes(b"NAME=DistroForge fixture\n")
    service = RootfsEvidenceService(rootfs, run_id=run_id)
    manifest = run_dir / "ROOTFS-MANIFEST.json"
    service.capture_before_packing(manifest)
    return manifest


def _write_valid_rootfs_packing_evidence(
    run_dir: Path,
    run_id: str,
    rootfs: Path,
    staged_squashfs: Path,
    manifest: Path,
) -> Path:
    service = RootfsEvidenceService(rootfs, run_id=run_id)
    staged_squashfs.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        (
            "mksquashfs",
            str(rootfs),
            str(staged_squashfs),
            "-noappend",
            "-comp",
            "gzip",
            "-processors",
            "1",
            "-no-progress",
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    image_identity = {
        "name": staged_squashfs.name,
        "size": staged_squashfs.stat().st_size,
        "sha256": hashlib.sha256(staged_squashfs.read_bytes()).hexdigest(),
    }

    unpacked = rootfs.with_name(f"{rootfs.name}-packing-replay")
    subprocess.run(
        (
            "unsquashfs",
            "-no-progress",
            "-d",
            str(unpacked),
            str(staged_squashfs),
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    verification = run_dir / "ROOTFS-PACKING-VERIFICATION.json"
    service.verify_after_packing(
        manifest,
        staged_squashfs,
        unpacked,
        image_identity,
        verification,
    )
    validation = validate_rootfs_evidence(
        run_dir,
        expected_run_id=run_id,
    )
    if not validation.ok:
        raise AssertionError(validation.detail)
    return verification


def _write_fixture_iso(project: Project, iso: Path, run_id: str) -> None:
    _require_product_fixture_tools()
    staging_iso = iso.with_name(f".{iso.name}.{run_id}.fixture")
    if staging_iso.exists() or staging_iso.is_symlink():
        raise AssertionError(f"stale fixture ISO staging path: {staging_iso}")
    subprocess.run(
        (
            "xorriso",
            "-as",
            "mkisofs",
            "-quiet",
            "-o",
            str(staging_iso),
            str(project.iso_root),
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    staging_iso.replace(iso)


def _write_valid_iso_assembly_evidence(
    run_dir: Path,
    run_id: str,
    iso: Path,
) -> tuple[Path, dict[str, object]]:
    verification = json.loads(
        (run_dir / "ROOTFS-PACKING-VERIFICATION.json").read_text(encoding="utf-8")
    )
    staged = verification["packed_image"]["witness"]
    output_identity = {
        "name": iso.name,
        "size": iso.stat().st_size,
        "sha256": hashlib.sha256(iso.read_bytes()).hexdigest(),
    }
    payload = {
        "schema": ISO_ASSEMBLY_SCHEMA,
        "run_id": run_id,
        "status": "verified",
        "iso_member": "/casper/filesystem.squashfs",
        "output_iso": output_identity,
        "staged_squashfs": staged,
        "embedded_squashfs": staged,
        "matches_staged": True,
    }
    evidence = run_dir / ISO_ASSEMBLY_FILENAME
    evidence.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    validation = validate_iso_assembly_evidence(
        run_dir,
        expected_run_id=run_id,
        output_iso_path=iso,
        replay_use_sudo=False,
    )
    if not validation.ok:
        raise AssertionError(validation.detail)
    return evidence, payload


def write_valid_build_evidence(
    project: Project,
    iso: Path,
    *,
    run_id: str = "build-run",
) -> Path:
    output_dir = iso.parent
    run_dir = output_dir / "evidence" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    tool_commands = (
        ("mmdebstrap", "Bootstrap fixture rootfs"),
        ("dpkg-deb", "Inspect fixture package payload"),
        ("mksquashfs", "Pack fixture rootfs"),
        ("unsquashfs", "Extract witnessed fixture rootfs"),
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
        _closed_execution_entrypoint(index, tool)
        for index, (tool, _description) in enumerate(tool_commands)
    ]
    _require_product_fixture_tools()
    command_argv = tuple((tool,) for tool, _description in tool_commands)
    package_inputs = _write_valid_package_input_evidence(
        run_dir,
        run_id,
        command_argv,
    )
    package_inputs_identity = _artifact(package_inputs)
    package_inputs_identity["role"] = "package-input-closure"
    staged_squashfs = (
        project.iso_root
        / project.release.livefs
        / "filesystem.squashfs"
    )
    fixture_rootfs = project.workdir / f"fixture-rootfs-{run_id}"
    rootfs_manifest = _write_valid_rootfs_manifest(
        run_dir,
        run_id,
        fixture_rootfs,
    )
    rootfs_manifest_identity = _artifact(rootfs_manifest)
    rootfs_manifest_identity["role"] = "rootfs-manifest"
    package_filesystem_causality = write_package_filesystem_causality(
        run_dir,
        expected_run_id=run_id,
        runner=CommandRunner(dry_run=False),
    )
    package_filesystem_causality_identity = _artifact(
        package_filesystem_causality
    )
    package_filesystem_causality_identity["role"] = "package-filesystem-causality"
    rootfs_verification = _write_valid_rootfs_packing_evidence(
        run_dir,
        run_id,
        fixture_rootfs,
        staged_squashfs,
        rootfs_manifest,
    )
    rootfs_verification_identity = _artifact(rootfs_verification)
    rootfs_verification_identity["role"] = "rootfs-packing-verification"
    _write_fixture_iso(project, iso, run_id)
    iso_sha = hashlib.sha256(iso.read_bytes()).hexdigest()
    iso_assembly, iso_assembly_payload = _write_valid_iso_assembly_evidence(
        run_dir,
        run_id,
        iso,
    )
    iso_assembly_identity = _artifact(iso_assembly)
    iso_assembly_identity["role"] = "iso-assembly"
    builder_source = {
        "kind": "git",
        "head": "a" * 40,
        "tree": "9" * 40,
        "branch": "develop",
        "commit_signature": "G " + "8" * 40,
        "git_measurements_complete": True,
        "dirty": False,
        "tracked_diff_sha256": (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        ),
        "untracked": [],
        "ignored_runtime_paths": [],
        "worktree_sha256": "b" * 64,
        "filesystem_guard": {
            "entry_count": 1,
            "directory_count": 1,
            "entries_sha256": "1" * 64,
            "content_sha256": "2" * 64,
            "metadata_sha256": "3" * 64,
            "directory_metadata_sha256": "5" * 64,
            "stable": True,
            "problems": [],
        },
        "stable_while_measured": True,
    }
    absent_file = {
        "path": None,
        "required": False,
        "exists": False,
        "kind": "not-configured",
        "size": 0,
        "sha256": None,
        "stable_while_hashed": True,
    }
    definition = {
        "path": None,
        "sha256": None,
        "file": absent_file,
        "effective_sha256": "c" * 64,
        "project_file": str(project.root / "project.json"),
        "project_file_sha256": "4" * 64,
        "project_file_identity": {
            "path": str((project.root / "project.json").absolute()),
            "required": True,
            "exists": True,
            "kind": "regular",
            "size": (project.root / "project.json").stat().st_size,
            "sha256": "4" * 64,
            "stable_while_hashed": True,
        },
    }
    source_iso = {
        "source_mode": project.source_mode,
        "path": str(project.source_iso) if project.source_iso else None,
        "trusted_path": str(project.source_iso) if project.source_iso else None,
        "sha256": None,
        "file": absent_file,
    }
    toolchain = {
        tool: {
            "available": True,
            "path": f"/usr/bin/{tool}",
            "sha256": "d" * 64,
            "stable_while_hashed": True,
            "version": f"{tool} fixture",
        }
        for tool, _description in tool_commands
    }
    opening_identity = {
        "builder_source": builder_source,
        "definition": definition,
        "source_iso": source_iso,
        "toolchain": toolchain,
    }
    opening_identity_sha256 = canonical_sha256(opening_identity)
    identity_checks = [
        {
            "name": name,
            "status": "closed",
            "initial_sha256": canonical_sha256(identity),
            "final_sha256": canonical_sha256(identity),
            "final": identity,
            "issues": [],
        }
        for name, identity in opening_identity.items()
    ]
    identity_closure = {
        "schema": "distroforge.run-identity-closure.v1",
        "status": "closed",
        "checked_at": "2026-07-29T00:00:00+00:00",
        "opening_identity_sha256": opening_identity_sha256,
        "checks": identity_checks,
        "checks_sha256": canonical_sha256(identity_checks),
        "issues": [],
    }
    provenance = {
        "schema": "distroforge.provenance.v2",
        "attestation_kind": "build",
        "generated_at": _PACKAGE_FIXTURE_BUILD_TIME,
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
            "created_at": _PACKAGE_FIXTURE_BUILD_TIME,
            **opening_identity,
            "opening_identity_sha256": opening_identity_sha256,
            "identity_closure": identity_closure,
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
        "executed_host_entrypoints_sha256": canonical_sha256(executed_entrypoints),
        "package_inputs": package_inputs_identity,
        "package_filesystem_causality": package_filesystem_causality_identity,
        "rootfs_manifest": rootfs_manifest_identity,
        "rootfs_packing_verification": rootfs_verification_identity,
        "iso_assembly": iso_assembly_identity,
        "assembled_output_iso": iso_assembly_payload["output_iso"],
        "staged_filesystem_squashfs": iso_assembly_payload["staged_squashfs"],
        "embedded_filesystem_squashfs": iso_assembly_payload["embedded_squashfs"],
        "staged_filesystem_squashfs_artifact": {
            **_artifact(staged_squashfs),
            "role": "staged-filesystem-squashfs",
        },
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
    command_events: list[dict[str, object]] = []
    for record, identity in zip(
        command_records,
        executed_entrypoints,
        strict=True,
    ):
        command_events.extend(
            [
                {
                    "event": "start",
                    "argv": record["argv"],
                    "cwd": record["cwd"],
                    "needs_root": record["needs_root"],
                    "description": record["description"],
                    "has_stdin": record["has_stdin"],
                    "env_keys": record["env_keys"],
                    "env_sha256": record["env_sha256"],
                },
                {
                    "event": "execution-identity-post-dispatch",
                    **identity,
                },
            ]
        )
    command_log.write_text(
        "".join(json.dumps(event) + "\n" for event in command_events),
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
            *[
                _artifact(path)
                for path in sorted(run_dir.rglob("*"))
                if path.is_file()
                and path.name not in {"RUN-MANIFEST.json", "RUN-MANIFEST.json.sha256"}
            ],
            _artifact(iso),
            _artifact(staged_squashfs),
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
