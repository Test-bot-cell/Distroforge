from __future__ import annotations

import json
import stat
from pathlib import Path

_SIGN_TARGETS = ("SHA256SUMS", "RELEASE-GATE.json", "RELEASE-MANIFEST.json")
_SIGNATURES = [f"{name}.asc" for name in _SIGN_TARGETS]
_FINGERPRINT = "A" * 40
_KEYRING = "RELEASE-SIGNING-KEYRING.gpg"
_KEYRING_SHA256 = "d" * 64
_BUILD_RUN_ID = "build-run"
_BOOT_RUN_ID = "boot-run"
_GATE_CODES = (
    "source-trust",
    "package-inputs",
    "rootfs-identity",
    "iso-assembly",
    "vuln-scan",
    "buildinfo",
    "provenance",
    "sbom",
    "html-report",
    "boot-proof",
    "release-readiness",
    "packaging-policy",
    "publish-signing",
    "provenance-snapshot",
    "artifact-session",
)


def stable_directory_identity(path: Path) -> list[int]:
    identity = path.stat()
    return [
        identity.st_dev,
        identity.st_ino,
        stat.S_IFMT(identity.st_mode),
        identity.st_uid,
        identity.st_gid,
        identity.st_nlink,
        identity.st_rdev,
    ]


def publish_drill_payload(
    *,
    status: str = "ready_to_publish",
    gate: str = "ready",
    boot: str = "runtime",
    blockers: tuple[str, ...] = (),
    sha256: str = "a" * 64,
    project: Path = Path("/workspace/DistroForge"),
    project_name: str = "DistroForge",
    bundle_dir: Path = Path("/workspace/DistroForge/dist/publish"),
    bundle_identity: list[int] | None = None,
) -> dict[str, object]:
    iso = bundle_dir.parent / "DistroForge.iso"
    build_run_dir = iso.parent / "evidence" / "runs" / _BUILD_RUN_ID
    boot_run_dir = iso.parent / "evidence" / "runs" / _BOOT_RUN_ID
    digest = sha256 if len(sha256) == 64 else (sha256 * 64)[:64]
    identity = bundle_identity or [1, 2, stat.S_IFDIR, 1000, 1000, 2, 0]
    gate_items: list[dict[str, object]] = [
        {"code": "iso", "status": "ready", "detail": "3 bytes"},
        {"code": "sha256", "status": "ready", "detail": digest},
        *[
            {
                "code": code,
                "status": "ready",
                "detail": f"{code} fixture evidence",
            }
            for code in _GATE_CODES
        ],
    ]
    if gate == "review":
        publish_signing = next(item for item in gate_items if item["code"] == "publish-signing")
        publish_signing.update(
            status="review",
            detail="awaiting the exact detached signature set",
        )
    elif gate == "blocked":
        packaging = next(item for item in gate_items if item["code"] == "packaging-policy")
        packaging.update(
            status="blocked",
            detail="release policy is not closed",
        )

    terminal_ready = status in {"ready_to_publish", "ready"}
    signing_status = "signed" if terminal_ready else "planned"
    signing_execute = terminal_ready
    manifest_files: list[dict[str, object]] = [
        {"name": iso.name, "size": 3, "sha256": digest},
        {"name": "RELEASE-GATE.json", "size": 1024, "sha256": "b" * 64},
        {"name": "SHA256SUMS", "size": 96, "sha256": "c" * 64},
    ]
    if signing_status == "signed":
        manifest_files.append(
            {
                "name": _KEYRING,
                "size": 128,
                "sha256": _KEYRING_SHA256,
            }
        )

    if status == "blocked":
        verify_status = "blocked"
        explanation_status = "blocked"
        pipeline_status = "blocked"
    elif status == "review_required":
        verify_status = "review"
        explanation_status = "review"
        pipeline_status = "review"
    else:
        verify_status = "ready"
        explanation_status = "ready"
        pipeline_status = "ready"

    if gate == "blocked":
        gate_verify_status = "blocked"
        gate_verify_detail = "Release gate is blocked."
    elif gate == "review" and terminal_ready:
        gate_verify_status = "ready"
        gate_verify_detail = (
            "The sole pre-signing publish review is resolved by the exact "
            "descriptor-bound signature set verified in this verdict."
        )
    elif gate == "review":
        gate_verify_status = "review"
        gate_verify_detail = "Release gate is review."
    else:
        gate_verify_status = "ready"
        gate_verify_detail = "Release gate is ready."
    verify_items: list[dict[str, object]] = [
        {
            "code": "manifest",
            "status": "ready",
            "detail": str(bundle_dir / "RELEASE-MANIFEST.json"),
        },
        {
            "code": "release-gate",
            "status": "ready",
            "detail": str(bundle_dir / "RELEASE-GATE.json"),
        },
        {
            "code": "signing-report",
            "status": "ready",
            "detail": str(bundle_dir / "SIGNING-REPORT.json"),
        },
        {
            "code": "sha256sums",
            "status": "ready",
            "detail": f"{iso.name} matches SHA256SUMS.",
        },
        {
            "code": "runtime-evidence",
            "status": "ready",
            "detail": "Runtime QEMU evidence binds the bundled ISO.",
        },
        {
            "code": "gate-status",
            "status": gate_verify_status,
            "detail": gate_verify_detail,
        },
    ]
    if signing_status == "signed":
        verify_items.extend(
            [
                {
                    "code": "signature-fingerprint",
                    "status": "ready",
                    "detail": (f"Externally pinned complete signer fingerprint: {_FINGERPRINT}."),
                },
                {
                    "code": "signature-keyring",
                    "status": "ready",
                    "detail": f"{_KEYRING} matches SHA256 {_KEYRING_SHA256}.",
                },
                *[
                    {
                        "code": "signature",
                        "status": "ready",
                        "detail": f"{name} has VALIDSIG from {_FINGERPRINT}.",
                    }
                    for name in _SIGNATURES
                ],
            ]
        )
    else:
        verify_items.append(
            {
                "code": "signature-contract",
                "status": "review",
                "detail": "Detached signatures are planned but not executed.",
            }
        )
    verify_items.extend(
        {
            "code": "manifest-file",
            "status": "ready",
            "detail": f"{entry['name']} verified.",
        }
        for entry in manifest_files
    )
    verify_items.append(
        {
            "code": "artifact-session",
            "status": "ready",
            "detail": "Descriptor session sealed exact terminal evidence.",
        }
    )
    if verify_status == "blocked" and not any(item["status"] == "blocked" for item in verify_items):
        verify_items.append(
            {
                "code": "terminal-verification",
                "status": "blocked",
                "detail": "Terminal evidence is blocked.",
            }
        )

    explanation_blocked = list(blockers)
    if explanation_status == "blocked" and not explanation_blocked:
        explanation_blocked.append("release-policy: terminal evidence is blocked")
    explanation_review = (
        ["publish-signing: detached signatures require review"]
        if explanation_status == "review"
        else []
    )
    explanation_ready = ["iso: manifest-bound ISO verified"]
    if gate == "review" and terminal_ready:
        explanation_ready.append(
            "publish-signing: resolved by terminal descriptor-bound signature verification"
        )
    publish_stage = gate
    if terminal_ready and gate == "review":
        publish_stage = "ready"
    sign_stage = signing_status
    stage_statuses = [
        ("boot-proof", "ready"),
        ("repair-artifacts", "ready"),
        ("publish-bundle", publish_stage),
        ("manifest-plan", "ready"),
        ("release-notes", "ready"),
        ("sign-release-final", sign_stage),
        ("verify-release", verify_status),
    ]

    return {
        "project": str(project),
        "project_name": project_name,
        "iso": str(iso),
        "bundle_dir": str(bundle_dir),
        "status": status,
        "blocked": status == "blocked",
        "drill": str(bundle_dir / "PUBLISH-DRILL.json"),
        "execute_signing": signing_execute,
        "pipeline": {
            "project": str(project),
            "bundle_dir": str(bundle_dir),
            "status": pipeline_status,
            "stages": [
                {
                    "name": name,
                    "status": stage_status,
                    "detail": f"{name} fixture evidence",
                }
                for name, stage_status in stage_statuses
            ],
            "bundle_identity": identity,
            "build_run_id": _BUILD_RUN_ID,
            "boot_run_id": _BOOT_RUN_ID,
        },
        "explanation": {
            "project": str(project),
            "iso": str(iso),
            "bundle_dir": str(bundle_dir),
            "status": explanation_status,
            "blocked": explanation_status == "blocked",
            "markdown": str(bundle_dir / "RELEASE-EXPLAIN.md"),
            "ready": explanation_ready,
            "review": explanation_review,
            "blocked_items": explanation_blocked,
            "boot_proof": {
                "status": "ready",
                "selected_backend": "qemu",
                "proof_level": boot,
                "attempted_backends": "qemu",
            },
            "next_commands": [f"distroforge verify-release {project} --bundle-dir {bundle_dir}"],
        },
        "evidence": {
            "release_gate": {
                "project": str(project),
                "iso": str(iso),
                "output_dir": str(iso.parent),
                "build_run_id": _BUILD_RUN_ID,
                "boot_run_id": _BOOT_RUN_ID,
                "immutable_iso_build": str(build_run_dir / "ISO-BUILD.json"),
                "immutable_provenance": str(
                    build_run_dir / "distroforge-provenance.json"
                ),
                "immutable_boot_proof": str(boot_run_dir / "boot-proof.json"),
                "immutable_qemu_report": str(
                    boot_run_dir / "qemu-lab-report.json"
                ),
                "immutable_sbom": str(
                    build_run_dir / "distroforge-sbom.spdx.json"
                ),
                "status": gate,
                "blocked": gate == "blocked",
                "items": gate_items,
            },
            "manifest": {
                "generated_at": "2026-07-30T12:00:00+00:00",
                "project": project_name,
                "bundle_dir": str(bundle_dir),
                "gate_status": gate,
                "files": manifest_files,
            },
            "signing": {
                "project": str(project),
                "bundle_dir": str(bundle_dir),
                "manifest": str(bundle_dir / "RELEASE-MANIFEST.json"),
                "status": signing_status,
                "execute": signing_execute,
                "signer_fingerprint": _FINGERPRINT if signing_execute else None,
                "verification_keyring": _KEYRING if signing_execute else None,
                "verification_keyring_sha256": (_KEYRING_SHA256 if signing_execute else None),
                "signed": _SIGNATURES if signing_execute else [],
                "planned": [] if signing_execute else _SIGNATURES,
                "skipped": [],
                "manifest_entries": [dict(entry) for entry in manifest_files],
            },
            "verify": {
                "project": str(project),
                "bundle_dir": str(bundle_dir),
                "status": verify_status,
                "blocked": verify_status == "blocked",
                "items": verify_items,
                "bundle_identity": list(identity),
            },
        },
    }


def publish_drill_text(**kwargs: object) -> str:
    return (
        json.dumps(
            publish_drill_payload(**kwargs),
            sort_keys=True,
        )
        + "\n"
    )
