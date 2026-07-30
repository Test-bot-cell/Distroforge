from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from distroforge.core.build import BuildOptions
from distroforge.core.command import (
    CommandError,
    CommandResult,
    CommandRunner,
    CommandSpec,
)
from distroforge.core.project import Project
from distroforge.core.release_contract import REQUIRED_RELEASE_GATE_CODES
from distroforge.core.release_gate import (
    ReleaseGateReport,
    _check_publish_signing,
)
from distroforge.core.release_signing import SIGN_TARGETS, SIGNING_KEYRING
from distroforge.core.release_verification import (
    ReleaseVerifyItem,
    _resolve_pre_signing_gate_review,
)

FINGERPRINT = "4248DCA20A9407BBFA31818518BC560A874C3C7F"


def _complete_gate_items(
    iso: Path,
) -> list[dict[str, object]]:
    items = [
        {
            "code": code,
            "status": "ready",
            "detail": f"{code} fixture evidence",
        }
        for code in sorted(REQUIRED_RELEASE_GATE_CODES - {"iso", "sha256"})
    ]
    items.extend(
        (
            {
                "code": "iso",
                "status": "ready",
                "detail": f"{iso.stat().st_size} bytes",
            },
            {
                "code": "sha256",
                "status": "ready",
                "detail": _sha256(iso),
            },
        )
    )
    return items


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _unselected_run_fields() -> dict[str, object]:
    return {
        "build_run_id": None,
        "boot_run_id": None,
        "immutable_iso_build": None,
        "immutable_provenance": None,
        "immutable_boot_proof": None,
        "immutable_qemu_report": None,
        "immutable_sbom": None,
    }


def _selected_run_fields(output_dir: Path) -> dict[str, object]:
    build_run_id = "build-run"
    boot_run_id = "boot-run"
    build_run_dir = output_dir / "evidence" / "runs" / build_run_id
    boot_run_dir = output_dir / "evidence" / "runs" / boot_run_id
    return {
        "build_run_id": build_run_id,
        "boot_run_id": boot_run_id,
        "immutable_iso_build": str(build_run_dir / "ISO-BUILD.json"),
        "immutable_provenance": str(
            build_run_dir / "distroforge-provenance.json"
        ),
        "immutable_boot_proof": str(boot_run_dir / "boot-proof.json"),
        "immutable_qemu_report": str(boot_run_dir / "qemu-lab-report.json"),
        "immutable_sbom": str(build_run_dir / "distroforge-sbom.spdx.json"),
    }


def _signed_snapshot(tmp_path: Path) -> tuple[Project, BuildOptions, ReleaseGateReport]:
    project = Project.create("SignedGate", tmp_path / "signed-gate", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    iso = bundle / "SignedGate-26.04.iso"
    iso.write_bytes(b"iso bytes")
    (bundle / "SHA256SUMS").write_text(
        f"{_sha256(iso)}  {iso.name}\n",
        encoding="utf-8",
    )
    (bundle / "RELEASE-GATE.json").write_text(
        json.dumps(
            {
                "project": str(project.root),
                "iso": str(iso),
                "output_dir": str(iso.parent),
                **_selected_run_fields(iso.parent),
                "status": "ready",
                "blocked": False,
                "items": _complete_gate_items(iso),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (bundle / SIGNING_KEYRING).write_bytes(b"pinned keyring")
    snapshot_names = (iso.name, "SHA256SUMS", "RELEASE-GATE.json", SIGNING_KEYRING)
    entries = [
        {
            "name": name,
            "size": (bundle / name).stat().st_size,
            "sha256": _sha256(bundle / name),
        }
        for name in snapshot_names
    ]
    (bundle / "RELEASE-MANIFEST.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-07-30T12:00:00+00:00",
                "project": project.name,
                "bundle_dir": str(bundle),
                "gate_status": "ready",
                "files": entries,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    for name in SIGN_TARGETS:
        (bundle / f"{name}.asc").write_bytes(f"signature:{name}".encode())
    (bundle / "SIGNING-REPORT.json").write_text(
        json.dumps(
            {
                "project": str(project.root),
                "bundle_dir": str(bundle),
                "manifest": str(bundle / "RELEASE-MANIFEST.json"),
                "status": "signed",
                "execute": True,
                "signer_fingerprint": FINGERPRINT,
                "verification_keyring": SIGNING_KEYRING,
                "verification_keyring_sha256": _sha256(bundle / SIGNING_KEYRING),
                "signed": [f"{name}.asc" for name in SIGN_TARGETS],
                "planned": [],
                "skipped": [],
                "manifest_entries": entries,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    options = BuildOptions()
    options.release_artifacts.sign = True
    options.release_artifacts.gpg_key = FINGERPRINT
    return (
        project,
        options,
        ReleaseGateReport(
            project.root,
            iso,
            project.output_dir,
        ),
    )


def _rewrite_gate_snapshot(
    bundle: Path,
    gate: dict[str, object],
    *,
    manifest_gate_status: str | None = None,
) -> None:
    gate_path = bundle / "RELEASE-GATE.json"
    gate_path.write_text(json.dumps(gate) + "\n", encoding="utf-8")
    manifest_path = bundle / "RELEASE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest_gate_status is not None:
        manifest["gate_status"] = manifest_gate_status
    entries = manifest["files"]
    gate_entry = next(entry for entry in entries if entry["name"] == "RELEASE-GATE.json")
    gate_entry["size"] = gate_path.stat().st_size
    gate_entry["sha256"] = _sha256(gate_path)
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    signing_path = bundle / "SIGNING-REPORT.json"
    signing = json.loads(signing_path.read_text(encoding="utf-8"))
    signing["manifest_entries"] = entries
    signing_path.write_text(json.dumps(signing) + "\n", encoding="utf-8")


def test_publish_signing_ready_requires_descriptor_bound_crypto_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, options, report = _signed_snapshot(tmp_path)
    verified: list[tuple[int, int, int]] = []

    monkeypatch.setattr(CommandRunner, "has_binary", staticmethod(lambda _name: True))

    def verify(*_args, **kwargs):
        descriptors = (
            kwargs["signature_fd"],
            kwargs["payload_fd"],
            kwargs["keyring_fd"],
        )
        assert all(os.path.isfile(f"/proc/self/fd/{fd}") for fd in descriptors)
        verified.append(descriptors)
        return (FINGERPRINT,)

    monkeypatch.setattr(
        "distroforge.core.release_gate.verify_detached_signature",
        verify,
    )

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
    )

    assert len(verified) == len(SIGN_TARGETS)
    assert report.items[-1].status == "ready"


def test_publish_signing_never_accepts_empty_exists_only_evidence(
    tmp_path: Path,
) -> None:
    project = Project.create("EmptySigning", tmp_path / "empty-signing", "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    for name in (
        "RELEASE-MANIFEST.json",
        "SIGNING-REPORT.json",
        "SHA256SUMS",
        "RELEASE-GATE.json",
        SIGNING_KEYRING,
        *(f"{target}.asc" for target in SIGN_TARGETS),
    ):
        (bundle / name).touch()
    options = BuildOptions()
    options.release_artifacts.sign = True
    options.release_artifacts.gpg_key = FINGERPRINT
    report = ReleaseGateReport(project.root, bundle / "empty.iso", bundle)

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
    )

    assert report.items[-1].status == "blocked"


@pytest.mark.parametrize(
    "unsafe_shape",
    ("bundle-symlink", "ancestor-symlink", "bundle-file"),
)
def test_publish_signing_blocks_unsafe_bundle_path_before_missing_evidence_review(
    tmp_path: Path,
    unsafe_shape: str,
) -> None:
    project = Project.create(
        "UnsafeSigningPath",
        tmp_path / f"unsafe-signing-{unsafe_shape}",
        "26.04",
    )
    external = tmp_path / f"external-{unsafe_shape}"
    external.mkdir()
    (external / "RELEASE-MANIFEST.json").write_text("{}\n", encoding="utf-8")
    if unsafe_shape == "bundle-symlink":
        bundle = project.output_dir / "publish"
        bundle.symlink_to(external, target_is_directory=True)
    elif unsafe_shape == "ancestor-symlink":
        ancestor = tmp_path / "selected-bundle-parent"
        ancestor.symlink_to(external, target_is_directory=True)
        bundle = ancestor / "publish"
    else:
        bundle = project.output_dir / "publish"
        bundle.write_bytes(b"not a directory")
    options = BuildOptions()
    options.release_artifacts.sign = True
    report = ReleaseGateReport(
        project.root,
        project.output_dir / "missing.iso",
        project.output_dir,
    )

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
        bundle_dir=bundle,
    )

    assert report.items[-1].status == "blocked"
    assert "Cannot anchor publish signing bundle safely" in report.items[-1].detail
    assert "Missing publish signing evidence" not in report.items[-1].detail


def test_publish_signing_blocks_required_leaf_symlink_before_missing_review(
    tmp_path: Path,
) -> None:
    project, options, report = _signed_snapshot(tmp_path)
    bundle = project.output_dir / "publish"
    keyring = bundle / SIGNING_KEYRING
    outside = tmp_path / "outside-keyring.gpg"
    outside.write_bytes(keyring.read_bytes())
    keyring.unlink()
    keyring.symlink_to(outside)

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
    )

    assert report.items[-1].status == "blocked"
    assert SIGNING_KEYRING in report.items[-1].detail
    assert "Missing publish signing evidence" not in report.items[-1].detail


def test_publish_signing_does_not_credit_default_bundle_when_custom_is_selected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, options, report = _signed_snapshot(tmp_path)
    custom_bundle = tmp_path / "custom-release" / "publish"
    monkeypatch.setattr(CommandRunner, "has_binary", staticmethod(lambda _name: True))
    monkeypatch.setattr(
        "distroforge.core.release_gate.verify_detached_signature",
        lambda *_args, **_kwargs: (FINGERPRINT,),
    )

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
        bundle_dir=custom_bundle,
    )

    assert report.items[-1].status == "review"
    assert "Missing publish signing evidence" in report.items[-1].detail


def test_publish_signing_blocks_noncanonical_sha256sums(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, options, report = _signed_snapshot(tmp_path)
    bundle = project.output_dir / "publish"
    sums = bundle / "SHA256SUMS"
    sums.write_bytes(sums.read_bytes().replace(b"  ", b" *", 1))
    monkeypatch.setattr(CommandRunner, "has_binary", staticmethod(lambda _name: True))

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
    )

    assert report.items[-1].status == "blocked"


def test_publish_signing_blocks_stale_or_blocked_gate_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, options, report = _signed_snapshot(tmp_path)
    bundle = project.output_dir / "publish"
    gate_items = _complete_gate_items(report.iso)
    next(item for item in gate_items if item["code"] == "source-trust").update(
        status="blocked",
        detail="source trust is intentionally blocked",
    )
    _rewrite_gate_snapshot(
        bundle,
        {
            "project": str(project.root),
            "iso": str(report.iso),
            "output_dir": str(report.iso.parent),
            **_selected_run_fields(report.iso.parent),
            "status": "blocked",
            "blocked": True,
            "items": gate_items,
        },
        manifest_gate_status="blocked",
    )
    monkeypatch.setattr(CommandRunner, "has_binary", staticmethod(lambda _name: True))

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
    )

    assert report.items[-1].status == "blocked"
    assert "status is blocked" in report.items[-1].detail


def test_publish_signing_blocks_bundle_for_a_different_current_iso(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, options, report = _signed_snapshot(tmp_path)
    current_iso = project.output_dir / "CURRENT.iso"
    current_iso.write_bytes(b"different current ISO")
    report.iso = current_iso
    monkeypatch.setattr(CommandRunner, "has_binary", staticmethod(lambda _name: True))

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
    )

    assert report.items[-1].status == "blocked"
    assert "expected product" in report.items[-1].detail


def test_publish_signing_rejects_false_like_blocked_and_empty_gate_items(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, options, report = _signed_snapshot(tmp_path)
    bundle = project.output_dir / "publish"
    _rewrite_gate_snapshot(
        bundle,
        {
            "project": str(project.root),
            "iso": str(report.iso),
            "output_dir": str(report.iso.parent),
            **_unselected_run_fields(),
            "status": "ready",
            "blocked": 0,
            "items": [],
        },
    )
    monkeypatch.setattr(CommandRunner, "has_binary", staticmethod(lambda _name: True))

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
    )

    assert report.items[-1].status == "blocked"
    assert "blocked flag contradicts" in report.items[-1].detail


def test_publish_signing_rejects_duplicate_gate_item_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, options, report = _signed_snapshot(tmp_path)
    bundle = project.output_dir / "publish"
    _rewrite_gate_snapshot(
        bundle,
        {
            "project": str(project.root),
            "iso": str(report.iso),
            "output_dir": str(report.iso.parent),
            **_unselected_run_fields(),
            "status": "ready",
            "blocked": False,
            "items": [
                {
                    "code": "iso",
                    "status": "ready",
                    "detail": f"{report.iso.stat().st_size} bytes",
                },
                {
                    "code": "iso",
                    "status": "ready",
                    "detail": _sha256(report.iso),
                },
            ],
        },
    )
    monkeypatch.setattr(CommandRunner, "has_binary", staticmethod(lambda _name: True))

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
    )

    assert report.items[-1].status == "blocked"
    assert "unique non-empty codes" in report.items[-1].detail


def test_publish_signing_blocks_unmanifested_bundle_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, options, report = _signed_snapshot(tmp_path)
    bundle = project.output_dir / "publish"
    (bundle / "unmanifested.bin").write_bytes(b"not signed")
    monkeypatch.setattr(CommandRunner, "has_binary", staticmethod(lambda _name: True))

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
    )

    assert report.items[-1].status == "blocked"
    assert "inventory is not exact" in report.items[-1].detail
    assert "unmanifested.bin" in report.items[-1].detail


def test_publish_signing_converts_gpg_command_error_to_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, options, report = _signed_snapshot(tmp_path)
    monkeypatch.setattr(CommandRunner, "has_binary", staticmethod(lambda _name: True))

    def fail_verification(*_args, **_kwargs) -> None:
        raise CommandError(
            CommandResult(
                CommandSpec(("gpg", "--verify")),
                2,
                "",
                "bad signature",
            )
        )

    monkeypatch.setattr(
        "distroforge.core.release_gate.verify_detached_signature",
        fail_verification,
    )

    _check_publish_signing(
        report,
        project.root,
        options,
        project_name=project.name,
    )

    assert report.items[-1].status == "blocked"
    assert "bad signature" in report.items[-1].detail


def test_verified_signature_set_resolves_only_publish_signing_review() -> None:
    gate = {
        "status": "review",
        "blocked": False,
        "items": [
            {"code": "iso", "status": "ready", "detail": "3 bytes"},
            {"code": "sha256", "status": "ready", "detail": "a" * 64},
            {
                "code": "publish-signing",
                "status": "review",
                "detail": "pre-signing evidence is not present yet",
            },
        ],
    }
    signing = {
        "status": "signed",
        "execute": True,
        "signed": [f"{name}.asc" for name in SIGN_TARGETS],
        "planned": [],
        "skipped": [],
    }
    items = [
        ReleaseVerifyItem("gate-status", "review", "Release gate is review."),
        ReleaseVerifyItem("signature-fingerprint", "ready", "pinned"),
        ReleaseVerifyItem("signature-keyring", "ready", "pinned"),
        *[ReleaseVerifyItem("signature", "ready", name) for name in SIGN_TARGETS],
    ]

    _resolve_pre_signing_gate_review(gate, signing, items)

    resolved = next(item for item in items if item.code == "gate-status")
    assert resolved.status == "ready"
    assert "sole pre-signing publish review" in resolved.detail


def test_verified_signature_set_never_resolves_an_unrelated_review() -> None:
    gate = {
        "status": "review",
        "blocked": False,
        "items": [
            {"code": "iso", "status": "ready", "detail": "3 bytes"},
            {"code": "sha256", "status": "ready", "detail": "a" * 64},
            {
                "code": "packaging-policy",
                "status": "review",
                "detail": "maintainer review required",
            },
        ],
    }
    signing = {
        "status": "signed",
        "execute": True,
        "signed": [f"{name}.asc" for name in SIGN_TARGETS],
        "planned": [],
        "skipped": [],
    }
    items = [
        ReleaseVerifyItem("gate-status", "review", "Release gate is review."),
        ReleaseVerifyItem("signature-fingerprint", "ready", "pinned"),
        ReleaseVerifyItem("signature-keyring", "ready", "pinned"),
        *[ReleaseVerifyItem("signature", "ready", name) for name in SIGN_TARGETS],
    ]

    _resolve_pre_signing_gate_review(gate, signing, items)

    unresolved = next(item for item in items if item.code == "gate-status")
    assert unresolved.status == "review"
