from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from conftest import (
    package_fixture_options,
    write_valid_boot_proof,
    write_valid_build_evidence,
)

import distroforge.core.evidence_run as evidence_run_module
import distroforge.core.release_signing as release_signing_module
from distroforge.cli import build_parser, main
from distroforge.core.artifact_paths import default_output_iso
from distroforge.core.command import CommandError, CommandResult, CommandSpec
from distroforge.core.hashing import sha256_file
from distroforge.core.project import Project
from distroforge.core.publish_drill import _drill_status, _read_drill_evidence
from distroforge.core.release_contract import REQUIRED_RELEASE_GATE_CODES
from distroforge.core.release_explain import explain_release
from distroforge.core.release_gate import (
    ReleaseGateItem,
    ReleaseGateReport,
    ReleaseGateService,
)
from distroforge.core.release_pipeline import run_release_pipeline
from distroforge.core.release_signing import (
    OPERATIONAL_BUNDLE_FILES,
    SIGN_TARGETS,
    SIGNING_KEYRING,
    full_fingerprint,
    sign_release_bundle,
    validsig_fingerprints,
    verify_detached_signature,
)
from distroforge.core.release_verification import (
    _verify_gate,
    _verify_signatures,
    verify_release_bundle,
)

FINGERPRINT = "4248DCA20A9407BBFA31818518BC560A874C3C7F"
OTHER_FINGERPRINT = "0000000000000000000000000000000000000000"
_GATE_PROJECT = Path("/workspace/Demo")


def _complete_gate_items(
    *,
    iso_size: int,
    iso_sha256: str,
    publish_signing: str | None = None,
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
            {"code": "iso", "status": "ready", "detail": f"{iso_size} bytes"},
            {"code": "sha256", "status": "ready", "detail": iso_sha256},
        )
    )
    if publish_signing is not None:
        items.append(
            {
                "code": "publish-signing",
                "status": publish_signing,
                "detail": (
                    "awaiting the exact detached signature set"
                    if publish_signing == "review"
                    else "publish-signing fixture evidence"
                ),
            }
        )
    return items


class _DescriptorSigningRunner:
    history: list[CommandSpec] = []
    mutate_target: Path | None = None
    raise_signing = False

    def __init__(self, *, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    @staticmethod
    def has_binary(name: str) -> bool:
        return name == "gpg"

    def run(
        self,
        spec: CommandSpec,
        *,
        check: bool = True,
    ) -> CommandResult:
        type(self).history.append(spec)
        if "--list-secret-keys" in spec.argv:
            return CommandResult(
                spec,
                0,
                f"sec:::::::::\nfpr:::::::::{FINGERPRINT}:\n",
                "",
            )
        if "--list-keys" in spec.argv:
            return CommandResult(
                spec,
                0,
                f"pub:::::::::\nfpr:::::::::{FINGERPRINT}:\n",
                "",
            )
        if "--import-options" in spec.argv and "show-only" in spec.argv:
            assert len(spec.pass_fds) == 1
            return CommandResult(
                spec,
                0,
                f"pub:::::::::\nfpr:::::::::{FINGERPRINT}:\n",
                "",
            )
        if "--import" in spec.argv:
            assert len(spec.pass_fds) == 1
            return CommandResult(spec, 0, "[GNUPG:] IMPORT_OK\n", "")
        if "--export" in spec.argv:
            output = Path(spec.argv[spec.argv.index("--output") + 1])
            output.write_bytes(b"minimal public verification keyring")
            return CommandResult(spec, 0, "", "")
        if "--detach-sign" in spec.argv:
            if type(self).raise_signing:
                raise CommandError(CommandResult(spec, 1, "", "simulated signing command failure"))
            assert len(spec.pass_fds) == 1
            payload_fd = spec.pass_fds[0]
            payload = os.pread(payload_fd, os.fstat(payload_fd).st_size, 0)
            output = Path(spec.argv[spec.argv.index("--output") + 1])
            output.write_bytes(b"descriptor-signature:" + payload)
            target = type(self).mutate_target
            if target is not None:
                opening = target.stat()
                original = target.read_bytes()
                target.write_bytes(b"X" * len(original))
                os.utime(
                    target,
                    ns=(opening.st_atime_ns, opening.st_mtime_ns),
                )
                type(self).mutate_target = None
            return CommandResult(spec, 0, "[GNUPG:] SIG_CREATED\n", "")
        if "--verify" in spec.argv:
            return CommandResult(
                spec,
                0,
                f"[GNUPG:] VALIDSIG {FINGERPRINT}\n",
                "",
            )
        return CommandResult(spec, 0, "", "")


def _use_descriptor_signing_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    _DescriptorSigningRunner.history = []
    _DescriptorSigningRunner.mutate_target = None
    _DescriptorSigningRunner.raise_signing = False
    monkeypatch.setattr(
        release_signing_module,
        "CommandRunner",
        _DescriptorSigningRunner,
    )


def test_release_verification_propagates_a_blocked_gate() -> None:
    gate, manifest = _strict_ready_gate()
    gate["status"] = "blocked"
    gate["blocked"] = True
    manifest["gate_status"] = "blocked"
    package_item = next(item for item in gate["items"] if item["code"] == "package-inputs")
    package_item.update(
        status="blocked",
        detail="filesystem causality is unverified",
    )
    items = []

    _verify_gate(
        gate,
        manifest,
        items,
        project_root=_GATE_PROJECT,
    )

    assert len(items) == 1
    assert items[0].code == "gate-status"
    assert items[0].status == "blocked"


def test_release_verification_rejects_a_false_ready_gate_aggregate() -> None:
    gate, manifest = _strict_ready_gate()
    package_item = next(item for item in gate["items"] if item["code"] == "package-inputs")
    package_item.update(status="blocked", detail="not closed")
    items = []

    _verify_gate(
        gate,
        manifest,
        items,
        project_root=_GATE_PROJECT,
    )

    assert len(items) == 1
    assert items[0].status == "blocked"
    assert "contradicts" in items[0].detail


def _strict_ready_gate() -> tuple[dict[str, object], dict[str, object]]:
    digest = "a" * 64
    output_dir = _GATE_PROJECT / "dist"
    build_run_id = "build-run"
    boot_run_id = "boot-run"
    build_run_dir = output_dir / "evidence" / "runs" / build_run_id
    boot_run_dir = output_dir / "evidence" / "runs" / boot_run_id
    gate = {
        "project": str(_GATE_PROJECT),
        "iso": str(output_dir / "Demo.iso"),
        "output_dir": str(output_dir),
        "build_run_id": build_run_id,
        "boot_run_id": boot_run_id,
        "immutable_iso_build": str(build_run_dir / "ISO-BUILD.json"),
        "immutable_provenance": str(
            build_run_dir / "distroforge-provenance.json"
        ),
        "immutable_boot_proof": str(boot_run_dir / "boot-proof.json"),
        "immutable_qemu_report": str(boot_run_dir / "qemu-lab-report.json"),
        "immutable_sbom": str(build_run_dir / "distroforge-sbom.spdx.json"),
        "status": "ready",
        "blocked": False,
        "items": _complete_gate_items(iso_size=3, iso_sha256=digest),
    }
    manifest = {
        "gate_status": "ready",
        "files": [
            {
                "name": "Demo.iso",
                "size": 3,
                "sha256": digest,
            }
        ],
    }
    return gate, manifest


def test_release_verification_accepts_a_strict_manifest_bound_ready_gate() -> None:
    gate, manifest = _strict_ready_gate()
    items = []

    _verify_gate(
        gate,
        manifest,
        items,
        project_root=_GATE_PROJECT,
    )

    assert items[0].status == "ready"


def test_release_verification_rejects_an_iso_sha_only_gate() -> None:
    gate, manifest = _strict_ready_gate()
    gate["items"] = [
        {"code": "iso", "status": "ready", "detail": "3 bytes"},
        {"code": "sha256", "status": "ready", "detail": "a" * 64},
    ]
    items = []

    _verify_gate(
        gate,
        manifest,
        items,
        project_root=_GATE_PROJECT,
    )

    assert items[0].status == "blocked"
    assert "proof set is not exact" in items[0].detail


@pytest.mark.parametrize(
    "tampering",
    ("extra-key", "foreign-project", "foreign-output"),
)
def test_release_verification_rejects_non_exact_gate_metadata(
    tampering: str,
) -> None:
    gate, manifest = _strict_ready_gate()
    if tampering == "extra-key":
        gate["untrusted"] = True
    elif tampering == "foreign-project":
        gate["project"] = "/workspace/AnotherProject"
    else:
        gate["output_dir"] = "/workspace/another-output"
    items = []

    _verify_gate(
        gate,
        manifest,
        items,
        project_root=_GATE_PROJECT,
    )

    assert items[0].status == "blocked"
    assert "not authoritative" in items[0].detail


@pytest.mark.parametrize(
    ("blocked", "problem"),
    (
        (None, "top-level keys differ from the exact release gate schema"),
        (0, "blocked flag contradicts the aggregate status"),
    ),
)
def test_release_verification_rejects_non_boolean_or_missing_blocked_flag(
    blocked: object,
    problem: str,
) -> None:
    gate, manifest = _strict_ready_gate()
    if blocked is None:
        gate.pop("blocked")
    else:
        gate["blocked"] = blocked
    items = []

    _verify_gate(
        gate,
        manifest,
        items,
        project_root=_GATE_PROJECT,
    )

    assert items[0].status == "blocked"
    assert problem in items[0].detail


def test_release_verification_rejects_an_empty_ready_gate() -> None:
    gate, manifest = _strict_ready_gate()
    gate["items"] = []
    items = []

    _verify_gate(
        gate,
        manifest,
        items,
        project_root=_GATE_PROJECT,
    )

    assert items[0].status == "blocked"
    assert "non-empty" in items[0].detail


def test_release_verification_rejects_duplicate_gate_codes() -> None:
    gate, manifest = _strict_ready_gate()
    raw_items = gate["items"]
    assert isinstance(raw_items, list)
    raw_items.append({"code": "iso", "status": "ready", "detail": "3 bytes"})
    items = []

    _verify_gate(
        gate,
        manifest,
        items,
        project_root=_GATE_PROJECT,
    )

    assert items[0].status == "blocked"
    assert "unique" in items[0].detail


def test_release_verification_rejects_gate_iso_details_not_bound_to_manifest() -> None:
    gate, manifest = _strict_ready_gate()
    raw_items = gate["items"]
    assert isinstance(raw_items, list)
    sha_item = next(
        item for item in raw_items if isinstance(item, dict) and item.get("code") == "sha256"
    )
    assert isinstance(sha_item, dict)
    sha_item["detail"] = "b" * 64
    items = []

    _verify_gate(
        gate,
        manifest,
        items,
        project_root=_GATE_PROJECT,
    )

    assert items[0].status == "blocked"
    assert "manifest-bound ISO" in items[0].detail


def _ready_bundle(tmp_path: Path, name: str = "Pinned") -> tuple[Project, Path]:
    project = Project.create(name, tmp_path / name.lower(), "26.04")
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    source_iso = project.output_dir / f"{name}-26.04.iso"
    build_run_id = "build-run"
    boot_run_id = "boot-run"
    build_run_dir = (
        source_iso.parent / "evidence" / "runs" / build_run_id
    )
    boot_run_dir = (
        source_iso.parent / "evidence" / "runs" / boot_run_id
    )
    source_iso.write_bytes(b"iso")
    iso = bundle / source_iso.name
    iso.write_bytes(b"iso")
    (bundle / "SHA256SUMS").write_text(
        f"{sha256_file(iso)}  {iso.name}\n",
        encoding="utf-8",
    )
    (bundle / "RELEASE-GATE.json").write_text(
        json.dumps(
            {
                "project": str(project.root),
                "iso": str(source_iso),
                "output_dir": str(source_iso.parent),
                "build_run_id": build_run_id,
                "boot_run_id": boot_run_id,
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
                "status": "ready",
                "blocked": False,
                "items": _complete_gate_items(
                    iso_size=iso.stat().st_size,
                    iso_sha256=sha256_file(iso),
                ),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return project, bundle


def _enable_fixture_spdx_sbom(
    project: Project,
    *,
    build_run_id: str = "build-run",
) -> Path:
    run_dir = project.output_dir / "evidence" / "runs" / build_run_id
    sbom = run_dir / "distroforge-sbom.spdx.json"
    sbom.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": project.name,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    immutable_provenance = run_dir / "distroforge-provenance.json"
    provenance = json.loads(
        immutable_provenance.read_text(encoding="utf-8")
    )
    provenance["sbom_format"] = "spdx"
    provenance_text = json.dumps(provenance, indent=2) + "\n"
    immutable_provenance.write_text(provenance_text, encoding="utf-8")
    (project.output_dir / "distroforge-provenance.json").write_text(
        provenance_text,
        encoding="utf-8",
    )
    manifest_path = run_dir / "RUN-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest["files"]
    assert isinstance(files, list)
    for path in (
        immutable_provenance,
        project.output_dir / "distroforge-provenance.json",
        sbom,
    ):
        identity = {
            "path": str(path),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for index, item in enumerate(files):
            if isinstance(item, dict) and item.get("path") == str(path):
                files[index] = identity
                break
        else:
            files.append(identity)
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    (run_dir / "RUN-MANIFEST.json.sha256").write_text(
        f"{sha256_file(manifest_path)}  RUN-MANIFEST.json\n",
        encoding="utf-8",
    )
    return sbom


def test_signing_plan_refuses_an_exists_only_ready_gate(tmp_path: Path) -> None:
    project, bundle = _ready_bundle(tmp_path, "ExistsOnlyGate")
    (bundle / "RELEASE-GATE.json").write_text(
        '{"status":"ready","blocked":false,"items":[]}\n',
        encoding="utf-8",
    )

    report = sign_release_bundle(project, bundle_dir=bundle)

    assert report.status == "blocked"
    assert report.planned == ()
    assert any("exact release gate schema" in item for item in report.skipped)
    assert not (bundle / "RELEASE-MANIFEST.json").exists()
    assert not (bundle / "SIGNING-REPORT.json").exists()
    assert not list(bundle.glob("*.asc"))


def test_signing_plan_refuses_an_iso_sha_only_gate(tmp_path: Path) -> None:
    project, bundle = _ready_bundle(tmp_path, "IncompleteGate")
    gate_path = bundle / "RELEASE-GATE.json"
    gate = json.loads(gate_path.read_text(encoding="utf-8"))
    gate["items"] = [item for item in gate["items"] if item["code"] in {"iso", "sha256"}]
    gate_path.write_text(json.dumps(gate) + "\n", encoding="utf-8")

    report = sign_release_bundle(project, bundle_dir=bundle)

    assert report.status == "blocked"
    assert any("proof set is not exact" in item for item in report.skipped)
    assert not (bundle / "RELEASE-MANIFEST.json").exists()
    assert not (bundle / "SIGNING-REPORT.json").exists()


def test_signing_preflight_refuses_a_retained_internal_quarantine(
    tmp_path: Path,
) -> None:
    project, bundle = _ready_bundle(tmp_path, "RetainedQuarantine")
    quarantine = bundle / ".RELEASE-MANIFEST.json.asc.cleanup-deadbeef"
    quarantine.write_bytes(b"owned signature awaiting maintainer cleanup")

    report = sign_release_bundle(project, bundle_dir=bundle)

    assert report.status == "blocked"
    assert any("internal temporary or quarantine" in item for item in report.skipped)
    assert quarantine.is_file()
    assert not (bundle / "RELEASE-MANIFEST.json").exists()
    assert not (bundle / "SIGNING-REPORT.json").exists()


@pytest.mark.parametrize(
    "invalid_input",
    ("missing-gate", "missing-iso", "malformed-sums"),
)
def test_signing_plan_requires_a_strict_iso_and_sha_bound_gate_without_partial_manifest(
    tmp_path: Path,
    invalid_input: str,
) -> None:
    project, bundle = _ready_bundle(tmp_path, f"InvalidPlan{invalid_input}")
    if invalid_input == "missing-gate":
        (bundle / "RELEASE-GATE.json").unlink()
    elif invalid_input == "missing-iso":
        next(bundle.glob("*.iso")).unlink()
    else:
        (bundle / "SHA256SUMS").write_text(
            "not-a-strict-checksum\n",
            encoding="utf-8",
        )

    report = sign_release_bundle(project, bundle_dir=bundle)

    assert report.status == "blocked"
    assert report.planned == ()
    assert not (bundle / "RELEASE-MANIFEST.json").exists()
    assert not (bundle / "SIGNING-REPORT.json").exists()
    assert not list(bundle.glob("*.asc"))


def test_strict_blocked_gate_can_be_planned_but_never_executed(
    tmp_path: Path,
) -> None:
    project, bundle = _ready_bundle(tmp_path, "StrictBlockedPlan")
    gate_path = bundle / "RELEASE-GATE.json"
    gate = json.loads(gate_path.read_text(encoding="utf-8"))
    gate["status"] = "blocked"
    gate["blocked"] = True
    boot_item = next(item for item in gate["items"] if item["code"] == "boot-proof")
    boot_item.update(
        status="blocked",
        detail="causal boot evidence is incomplete",
    )
    gate_path.write_text(json.dumps(gate) + "\n", encoding="utf-8")

    planned = sign_release_bundle(project, bundle_dir=bundle)
    executed = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=tmp_path / "unused.gpg",
    )

    assert planned.status == "planned"
    assert len(planned.planned) == 3
    assert executed.status == "blocked"
    assert any("BLOCKED" in item for item in executed.skipped)
    assert not list(bundle.glob("*.asc"))


def test_vuln_review_gate_can_be_planned_but_never_executed(
    tmp_path: Path,
) -> None:
    project, bundle = _ready_bundle(tmp_path, "VulnReviewPlan")
    gate_path = bundle / "RELEASE-GATE.json"
    gate = json.loads(gate_path.read_text(encoding="utf-8"))
    gate["status"] = "review"
    vuln_item = next(
        item for item in gate["items"] if item["code"] == "vuln-scan"
    )
    vuln_item.update(
        status="review",
        detail="CVE database evidence is degraded",
    )
    gate_path.write_text(json.dumps(gate) + "\n", encoding="utf-8")

    planned = sign_release_bundle(project, bundle_dir=bundle)
    executed = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=tmp_path / "unused.gpg",
    )

    assert planned.status == "planned"
    assert len(planned.planned) == len(SIGN_TARGETS)
    assert executed.status == "blocked"
    assert any(
        "sole pre-signing publish-signing review" in item
        for item in executed.skipped
    )
    assert not list(bundle.glob("*.asc"))


@pytest.mark.parametrize("rogue_kind", ("file", "empty-directory"))
def test_plan_blocks_inventory_injected_after_manifest_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    rogue_kind: str,
) -> None:
    project, bundle = _ready_bundle(tmp_path, f"ManifestInjection{rogue_kind}")
    real_publish = release_signing_module.publish_regular_text
    injected = False

    def inject_after_manifest(
        path: Path,
        content: str,
        **kwargs: object,
    ) -> evidence_run_module.ImmutableCopyReceipt:
        nonlocal injected
        receipt = real_publish(path, content, **kwargs)
        if path.name != "RELEASE-MANIFEST.json" or injected:
            return receipt
        injected = True
        rogue = bundle / ("rogue-payload.bin" if rogue_kind == "file" else "rogue-empty")
        if rogue_kind == "file":
            rogue.write_bytes(b"not bound by the manifest")
        else:
            rogue.mkdir()
        return receipt

    monkeypatch.setattr(
        release_signing_module,
        "publish_regular_text",
        inject_after_manifest,
    )

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        publish_artifacts=True,
    )

    assert report.status == "blocked"
    assert report.planned == ()
    assert not list(bundle.glob("*.asc"))
    assert any(
        "inventory is not exact" in item or "preflight anchor" in item for item in report.skipped
    )


def test_executed_signing_without_a_complete_fingerprint_is_blocked(tmp_path: Path) -> None:
    project, bundle = _ready_bundle(tmp_path)

    report = sign_release_bundle(project, bundle_dir=bundle, execute=True)

    assert report.status == "blocked"
    assert any("complete OpenPGP signer fingerprint" in item for item in report.skipped)
    assert not list(bundle.glob("*.asc"))


def test_signing_never_creates_a_missing_partial_bundle(tmp_path: Path) -> None:
    project = Project.create("MissingPublish", tmp_path / "missing-publish", "26.04")
    bundle = project.output_dir / "publish"

    report = sign_release_bundle(project, bundle_dir=bundle)

    assert report.status == "blocked"
    assert not bundle.exists()
    assert any("Publish bundle is missing" in item for item in report.skipped)


def test_signing_refuses_a_bundle_anchor_different_from_the_publish_receipt(
    tmp_path: Path,
) -> None:
    project, bundle = _ready_bundle(tmp_path, "BundleReceipt")
    unrelated = tmp_path / "unrelated-bundle"
    unrelated.mkdir()
    expected = evidence_run_module.stable_parent_identity(unrelated)

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        expected_bundle_identity=expected,
    )

    assert report.status == "blocked"
    assert any("published bundle identity" in item for item in report.skipped)
    assert not (bundle / "RELEASE-MANIFEST.json").exists()
    assert not (bundle / "SIGNING-REPORT.json").exists()


def test_signing_accepts_the_publish_receipt_stable_parent_identity(
    tmp_path: Path,
) -> None:
    project, bundle = _ready_bundle(tmp_path, "StableBundleReceipt")
    expected = evidence_run_module.stable_parent_identity(bundle)

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        expected_bundle_identity=expected,
    )

    assert report.status == "planned"
    assert report.manifest_entries
    assert not (bundle / "RELEASE-MANIFEST.json").exists()
    assert not (bundle / "SIGNING-REPORT.json").exists()


@pytest.mark.parametrize(
    "tampering",
    ("extra-key", "duplicate-target", "wrong-project", "manifest-mismatch"),
)
def test_release_verification_rejects_non_exact_signing_reports(
    tmp_path: Path,
    tampering: str,
) -> None:
    project, bundle = _ready_bundle(
        tmp_path,
        f"SigningContract{tampering}",
    )
    planned = sign_release_bundle(
        project,
        bundle_dir=bundle,
        publish_artifacts=True,
    )
    assert planned.status == "planned"
    report_path = bundle / "SIGNING-REPORT.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if tampering == "extra-key":
        report["untrusted"] = True
    elif tampering == "duplicate-target":
        report["planned"].append(report["planned"][0])
    elif tampering == "wrong-project":
        report["project"] = str(tmp_path / "another-project")
    else:
        report["manifest_entries"] = []
    report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")

    verified = verify_release_bundle(project, bundle_dir=bundle)

    assert verified.blocked
    contract = next(item for item in verified.items if item.code == "signature-contract")
    assert contract.status == "blocked"
    assert "not authoritative" in contract.detail


@pytest.mark.parametrize(
    "tampering",
    ("extra-key", "wrong-project", "wrong-bundle", "naive-time"),
)
def test_release_verification_rejects_non_exact_release_manifests(
    tmp_path: Path,
    tampering: str,
) -> None:
    project, bundle = _ready_bundle(
        tmp_path,
        f"ManifestContract{tampering}",
    )
    planned = sign_release_bundle(
        project,
        bundle_dir=bundle,
        publish_artifacts=True,
    )
    assert planned.status == "planned"
    manifest_path = bundle / "RELEASE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if tampering == "extra-key":
        manifest["untrusted"] = True
    elif tampering == "wrong-project":
        manifest["project"] = "AnotherProject"
    elif tampering == "wrong-bundle":
        manifest["bundle_dir"] = str(tmp_path / "another-bundle")
    else:
        manifest["generated_at"] = "2026-07-30T12:00:00"
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    verified = verify_release_bundle(project, bundle_dir=bundle)

    assert verified.blocked
    contract = next(item for item in verified.items if item.code == "manifest-contract")
    assert contract.status == "blocked"
    assert "not authoritative" in contract.detail


@pytest.mark.parametrize("execute", (False, True), ids=("plan", "execute"))
def test_signing_refuses_a_bundle_clone_substituted_after_preflight(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    execute: bool,
) -> None:
    project, bundle = _ready_bundle(
        tmp_path,
        f"PostPreflightClone{'Execute' if execute else 'Plan'}",
    )
    expected = evidence_run_module.stable_parent_identity(bundle)
    substitute = tmp_path / f"{bundle.name}-substitute"
    held_original = tmp_path / f"{bundle.name}-held-original"
    shutil.copytree(bundle, substitute)
    real_preflight = release_signing_module._signing_preflight
    swapped = False

    def swap_after_preflight(*args: object, **kwargs: object):
        nonlocal swapped
        result = real_preflight(*args, **kwargs)
        assert not swapped
        os.rename(bundle, held_original)
        os.rename(substitute, bundle)
        swapped = True
        return result

    monkeypatch.setattr(
        release_signing_module,
        "_signing_preflight",
        swap_after_preflight,
    )
    keyring: Path | None = None
    if execute:
        _use_descriptor_signing_runner(monkeypatch)
        keyring = tmp_path / "post-preflight-clone.gpg"
        keyring.write_bytes(b"filtered public keyring")

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=execute,
        gpg_key=FINGERPRINT if execute else None,
        gpg_keyring=keyring,
        expected_bundle_identity=expected,
    )

    assert swapped
    assert report.status == "blocked"
    assert any("anchor" in item or "publication receipt" in item for item in report.skipped)
    forbidden = {
        SIGNING_KEYRING,
        "RELEASE-MANIFEST.json",
        "SIGNING-REPORT.json",
        *[f"{name}.asc" for name in release_signing_module.SIGN_TARGETS],
    }
    for directory in (bundle, held_original):
        assert forbidden.isdisjoint(path.name for path in directory.iterdir())


def test_executed_signing_without_an_explicit_public_keyring_is_blocked(
    tmp_path: Path,
) -> None:
    project, bundle = _ready_bundle(tmp_path)

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
    )

    assert report.status == "blocked"
    assert any("explicit filtered public GPG keyring" in item for item in report.skipped)
    assert not list(bundle.glob("*.asc"))


def test_signing_stage_reservation_failure_is_a_blocked_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "SigningStageReservation")
    keyring = tmp_path / "signing-stage-reservation.gpg"
    keyring.write_bytes(b"filtered public keyring")

    def refuse_signing_stage(*, prefix: str) -> Iterator[Path]:
        assert prefix == "distroforge-signing-stage-"
        raise OSError("simulated signing stage reservation refusal")

    monkeypatch.setattr(
        release_signing_module,
        "owned_temporary_directory",
        refuse_signing_stage,
    )

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert report.status == "blocked"
    assert report.signed == ()
    assert report.planned == ()
    assert any(
        "staging lifecycle failed closed" in item and "reservation refusal" in item
        for item in report.skipped
    )
    assert not list(bundle.glob("*.asc"))
    assert not (bundle / SIGNING_KEYRING).exists()
    assert not (bundle / "RELEASE-MANIFEST.json").exists()
    written = json.loads((bundle / "SIGNING-REPORT.json").read_text(encoding="utf-8"))
    assert written["status"] == "blocked"


def test_signing_stage_cleanup_failure_rolls_back_signatures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "SigningStageCleanup")
    keyring = tmp_path / "signing-stage-cleanup.gpg"
    keyring.write_bytes(b"filtered public keyring")
    real_owned_temporary_directory = release_signing_module.owned_temporary_directory

    @contextmanager
    def fail_after_signing_stage(*, prefix: str) -> Iterator[Path]:
        with real_owned_temporary_directory(prefix=prefix) as staging:
            yield staging
        if prefix == "distroforge-signing-stage-":
            raise OSError("simulated signing stage cleanup refusal")

    monkeypatch.setattr(
        release_signing_module,
        "owned_temporary_directory",
        fail_after_signing_stage,
    )

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert report.status == "blocked"
    assert report.signed == ()
    assert report.planned == ()
    assert any(
        "staging lifecycle failed closed" in item and "cleanup refusal" in item
        for item in report.skipped
    )
    assert not list(bundle.glob("*.asc"))
    written = json.loads((bundle / "SIGNING-REPORT.json").read_text(encoding="utf-8"))
    assert written["status"] == "blocked"
    assert verify_release_bundle(project, bundle_dir=bundle).blocked


def test_signing_plan_does_not_probe_or_copy_key_material(tmp_path: Path) -> None:
    project, bundle = _ready_bundle(tmp_path)
    missing_keyring = tmp_path / "not-present.gpg"

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=False,
        gpg_key=FINGERPRINT,
        gpg_keyring=missing_keyring,
    )

    assert report.status == "planned"
    assert report.signer_fingerprint == FINGERPRINT
    assert report.verification_keyring is None
    assert not (bundle / SIGNING_KEYRING).exists()


def test_executed_signing_uses_held_payload_fds_and_no_replace_outputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "HeldSigning")
    keyring = tmp_path / "held-signing.gpg"
    keyring.write_bytes(b"filtered public keyring")

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert report.status == "signed"
    signing_specs = [
        spec for spec in _DescriptorSigningRunner.history if "--detach-sign" in spec.argv
    ]
    assert len(signing_specs) == 3
    assert all("--yes" not in spec.argv for spec in signing_specs)
    assert all(spec.pass_fds for spec in signing_specs)
    assert all(spec.argv[-1].startswith("/proc/self/fd/") for spec in signing_specs)


def test_manifest_swap_between_publication_validation_and_signing_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "ManifestReceiptSwap")
    keyring = tmp_path / "manifest-receipt-swap.gpg"
    keyring.write_bytes(b"filtered public keyring")
    real_stage = release_signing_module._stage_descriptor_bound_signatures
    swapped = False

    def swap_before_staging(*args: object, **kwargs: object):
        nonlocal swapped
        manifest_path = bundle / "RELEASE-MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        project_name = manifest["project"]
        assert isinstance(project_name, str)
        manifest["project"] = "X" * len(project_name)
        replacement = bundle / ".manifest-replacement.json"
        replacement.write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(replacement, manifest_path)
        swapped = True
        return real_stage(*args, **kwargs)

    monkeypatch.setattr(
        release_signing_module,
        "_stage_descriptor_bound_signatures",
        swap_before_staging,
    )

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert swapped
    assert report.status == "blocked"
    assert not list(bundle.glob("*.asc"))
    assert any("durable publication receipt" in reason for reason in report.skipped)


def test_existing_signature_is_never_replaced(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "ExistingSignature")
    keyring = tmp_path / "existing-signature.gpg"
    keyring.write_bytes(b"filtered public keyring")
    existing = bundle / "SHA256SUMS.asc"
    existing.write_bytes(b"pre-existing signature")

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert report.status == "blocked"
    assert existing.read_bytes() == b"pre-existing signature"
    assert list(bundle.glob("*.asc")) == [existing]
    assert not any("--detach-sign" in spec.argv for spec in _DescriptorSigningRunner.history)


def test_same_size_same_mtime_swap_during_gpg_blocks_before_signature_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "SigningSwap")
    keyring = tmp_path / "signing-swap.gpg"
    keyring.write_bytes(b"filtered public keyring")
    _DescriptorSigningRunner.mutate_target = bundle / "SHA256SUMS"

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert report.status == "blocked"
    assert not list(bundle.glob("*.asc"))
    assert any("Descriptor-bound release signing failed" in item for item in report.skipped)


def test_command_error_is_blocked_without_raw_exception_or_signature(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "SigningCommandError")
    keyring = tmp_path / "command-error.gpg"
    keyring.write_bytes(b"filtered public keyring")
    _DescriptorSigningRunner.raise_signing = True

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert report.status == "blocked"
    assert not list(bundle.glob("*.asc"))
    assert any("signing command failure" in item for item in report.skipped)


def test_retry_after_gpg_failure_requires_a_fresh_immutable_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "SigningRetry")
    keyring = tmp_path / "retry.gpg"
    keyring.write_bytes(b"filtered public keyring")
    _DescriptorSigningRunner.raise_signing = True

    failed = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )
    sealed_keyring = (bundle / SIGNING_KEYRING).read_bytes()
    _DescriptorSigningRunner.raise_signing = False

    retried = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert failed.status == "blocked"
    assert retried.status == "blocked"
    assert (bundle / SIGNING_KEYRING).read_bytes() == sealed_keyring
    assert not list(bundle.glob("*.asc"))
    assert any("already exists with different bytes" in item for item in retried.skipped)


def test_retry_refuses_a_different_existing_keyring_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "SigningRetryMismatch")
    keyring = tmp_path / "retry-source.gpg"
    keyring.write_bytes(b"expected filtered public keyring")
    existing = bundle / SIGNING_KEYRING
    existing.write_bytes(b"different sealed keyring")

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert report.status == "blocked"
    assert existing.read_bytes() == b"different sealed keyring"
    assert not list(bundle.glob("*.asc"))
    assert any("different identity" in item for item in report.skipped)


def test_staged_keyring_path_swap_cannot_publish_unvalidated_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "SigningKeyringSwap")
    keyring = tmp_path / "keyring-swap.gpg"
    validated_keyring = b"validated source key material"
    substituted_keyring = b"unvalidated replacement keyring bytes"
    keyring.write_bytes(validated_keyring)
    real_fingerprints = release_signing_module._isolated_keyring_fingerprints

    def swap_after_validation(
        runner,
        keyring_path: Path,
        *,
        keyring_fd: int | None = None,
    ) -> tuple[str, ...]:
        fingerprints = real_fingerprints(
            runner,
            keyring_path,
            keyring_fd=keyring_fd,
        )
        replacement = keyring_path.with_name(f".{keyring_path.name}.replacement")
        replacement.write_bytes(substituted_keyring)
        os.replace(replacement, keyring_path)
        return fingerprints

    monkeypatch.setattr(
        release_signing_module,
        "_isolated_keyring_fingerprints",
        swap_after_validation,
    )

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert report.status == "blocked"
    assert (bundle / SIGNING_KEYRING).read_bytes() == (b"minimal public verification keyring")
    assert substituted_keyring not in (bundle / SIGNING_KEYRING).read_bytes()
    assert not list(bundle.glob("*.asc"))
    assert any("staged release verification keyring" in item for item in report.skipped)


def test_large_signing_inventory_blocks_while_scanning_before_materialization(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _project, bundle = _ready_bundle(tmp_path, "SigningInventoryBudget")
    for index in range(64):
        (bundle / f"extra-{index:03d}.txt").write_text("bounded\n", encoding="utf-8")
    observed_names: list[str] = []
    real_strict_name = release_signing_module._strict_filesystem_name

    def observe_name(value: str | bytes) -> str:
        observed_names.append(os.fsdecode(value))
        return real_strict_name(value)

    monkeypatch.setattr(
        release_signing_module,
        "_SIGNING_INVENTORY_MAX_ENTRIES",
        8,
    )
    monkeypatch.setattr(
        release_signing_module,
        "_strict_filesystem_name",
        observe_name,
    )

    with pytest.raises(
        release_signing_module.ArtifactVerificationError,
        match="inventory entry limit",
    ):
        release_signing_module._descriptor_tree_inventory(bundle)

    assert len(observed_names) == 8


def test_signing_inventory_limit_cannot_exceed_session_descriptor_budget(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _project, bundle = _ready_bundle(tmp_path, "SigningInventoryAlignment")
    monkeypatch.setattr(
        release_signing_module,
        "_SIGNING_INVENTORY_MAX_ENTRIES",
        release_signing_module._SIGNING_LIMITS.max_open_files + 1,
    )

    with pytest.raises(
        release_signing_module.ArtifactVerificationError,
        match="open-file budget",
    ):
        release_signing_module._descriptor_tree_inventory(bundle)


def test_signature_set_rolls_back_every_file_after_mid_publication_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "SigningRollback")
    keyring = tmp_path / "rollback.gpg"
    keyring.write_bytes(b"filtered public keyring")
    real_copy = release_signing_module.copy_immutable_file_descriptor

    def fail_after_complete_second_signature(
        source_fd: int,
        target: Path,
        **kwargs: object,
    ):
        receipt = real_copy(source_fd, target, **kwargs)
        if target.name == "RELEASE-GATE.json.asc":
            raise OSError("simulated post-publication fsync failure")
        return receipt

    monkeypatch.setattr(
        release_signing_module,
        "copy_immutable_file_descriptor",
        fail_after_complete_second_signature,
    )

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert report.status == "blocked"
    assert not list(bundle.glob("*.asc"))
    assert any("post-publication fsync failure" in item for item in report.skipped)


def test_rogue_file_injected_between_signature_publications_blocks_and_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "SigningRoguePublication")
    keyring = tmp_path / "rogue-publication.gpg"
    keyring.write_bytes(b"source key material")
    real_copy = release_signing_module.copy_immutable_file_descriptor
    injected = False

    def inject_after_first_signature(
        source_fd: int,
        target: Path,
        **kwargs: object,
    ):
        nonlocal injected
        receipt = real_copy(source_fd, target, **kwargs)
        if target.name == "SHA256SUMS.asc" and not injected:
            injected = True
            (bundle / "rogue-after-manifest.bin").write_bytes(b"rogue")
        return receipt

    monkeypatch.setattr(
        release_signing_module,
        "copy_immutable_file_descriptor",
        inject_after_first_signature,
    )

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert report.status == "blocked"
    assert not list(bundle.glob("*.asc"))
    assert (bundle / "rogue-after-manifest.bin").read_bytes() == b"rogue"
    assert any("inventory is not exact" in item for item in report.skipped)


def test_signature_rollback_never_deletes_a_name_swapped_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "SigningRollbackSwap")
    keyring = tmp_path / "rollback-swap.gpg"
    keyring.write_bytes(b"source key material")
    victim = bundle / "victim-proof.txt"
    victim_bytes = b"replacement victim must survive"
    victim.write_bytes(victim_bytes)
    hidden_owned = bundle / ".held-owned-signature"
    real_rename = evidence_run_module._rename_directory_noreplace
    swapped = False

    def swap_before_quarantine(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        nonlocal swapped
        if source_name == "RELEASE-MANIFEST.json.asc" and not swapped:
            swapped = True
            os.rename(
                source_name,
                hidden_owned.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.rename(
                victim.name,
                source_name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        real_rename(parent_fd, source_name, target_name)

    monkeypatch.setattr(
        release_signing_module,
        "_rename_directory_noreplace",
        swap_before_quarantine,
    )
    monkeypatch.setattr(
        release_signing_module,
        "_verify_published_signature_snapshot",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("simulated final signature verification failure")
        ),
    )

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    replacement = bundle / "RELEASE-MANIFEST.json.asc"
    assert report.status == "blocked"
    assert replacement.read_bytes() == victim_bytes
    assert hidden_owned.is_file()
    assert any("rollback was incomplete" in item for item in report.skipped)


def test_signature_cleanup_never_unlinks_a_late_swapped_quarantine_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "cleanup-bundle"
    bundle.mkdir()
    signature = bundle / "Demo.iso.asc"
    signature_bytes = b"owned detached signature"
    signature.write_bytes(signature_bytes)
    victim = bundle / "late-cleanup-victim.txt"
    victim_bytes = b"late cleanup victim must survive"
    victim.write_bytes(victim_bytes)
    signature_fd = os.open(
        signature,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    directory_fd = os.open(
        bundle,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    identity = release_signing_module.ArtifactIdentity.from_stat(os.fstat(signature_fd))
    owned = release_signing_module._OwnedRegularFile(
        signature.name,
        signature_fd,
        identity,
        release_signing_module._descriptor_sha256(signature_fd, identity),
    )
    real_unlink = os.unlink
    unlink_attempted = False

    def swap_at_late_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal unlink_attempted
        name = os.fsdecode(path)
        if name.startswith(f".{signature.name}.cleanup-"):
            assert dir_fd is not None
            unlink_attempted = True
            os.rename(
                name,
                ".held-owned-signature",
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
            )
            os.rename(
                victim.name,
                name,
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
            )
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(release_signing_module.os, "unlink", swap_at_late_unlink)
    try:
        with pytest.raises(
            release_signing_module.ArtifactVerificationError,
            match="retained safely",
        ):
            release_signing_module._remove_owned_regular_name(
                directory_fd,
                owned,
                label="detached signature",
            )
    finally:
        os.close(directory_fd)
        os.close(signature_fd)

    assert unlink_attempted is False
    assert victim.read_bytes() == victim_bytes
    assert not signature.exists()
    quarantined = list(bundle.glob(f".{signature.name}.cleanup-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == signature_bytes


def test_manifest_publication_exposes_no_swappable_temporary_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project, bundle = _ready_bundle(tmp_path, "SigningTemporarySwap")
    victim = bundle / "temporary-cleanup-victim.txt"
    victim_bytes = b"temporary cleanup victim must survive"
    victim.write_bytes(victim_bytes)
    hidden_owned = bundle / ".held-manifest-temporary"
    real_rename = release_signing_module._rename_directory_noreplace
    swapped = False

    def swap_temporary_before_quarantine(
        parent_fd: int,
        source_name: str,
        target_name: str,
    ) -> None:
        nonlocal swapped
        if source_name.startswith(".RELEASE-MANIFEST.json.tmp-") and not swapped:
            swapped = True
            os.rename(
                source_name,
                hidden_owned.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.rename(
                victim.name,
                source_name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        real_rename(parent_fd, source_name, target_name)

    monkeypatch.setattr(
        evidence_run_module,
        "_rename_directory_noreplace",
        swap_temporary_before_quarantine,
    )

    report = sign_release_bundle(project, bundle_dir=bundle)

    assert report.status == "planned"
    assert swapped is False
    assert victim.read_bytes() == victim_bytes
    assert not hidden_owned.exists()
    assert not list(bundle.glob(".RELEASE-MANIFEST.json.tmp-*"))


def test_signature_set_rolls_back_if_signed_report_cannot_be_published(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_descriptor_signing_runner(monkeypatch)
    project, bundle = _ready_bundle(tmp_path, "SigningReportRollback")
    keyring = tmp_path / "report-rollback.gpg"
    keyring.write_bytes(b"filtered public keyring")
    real_publish = release_signing_module.publish_regular_text

    def fail_signed_report(
        path: Path,
        content: str,
        **kwargs: object,
    ) -> evidence_run_module.ImmutableCopyReceipt:
        if path.name == "SIGNING-REPORT.json" and '"status": "signed"' in content:
            raise OSError("simulated signing report fsync failure")
        return real_publish(path, content, **kwargs)

    monkeypatch.setattr(
        release_signing_module,
        "publish_regular_text",
        fail_signed_report,
    )

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=FINGERPRINT,
        gpg_keyring=keyring,
    )

    assert report.status == "blocked"
    assert any("signing report fsync failure" in item for item in report.skipped)
    assert not list(bundle.glob("*.asc"))


def test_short_key_ids_are_not_release_fingerprints() -> None:
    assert full_fingerprint(FINGERPRINT) == FINGERPRINT
    assert full_fingerprint(f"0x{FINGERPRINT.lower()}") == FINGERPRINT
    assert full_fingerprint(FINGERPRINT[-16:]) is None


def test_release_cli_exposes_external_fingerprint_and_keyring_inputs(
    tmp_path: Path,
) -> None:
    parser = build_parser()
    keyring = tmp_path / "filtered.gpg"
    sign = parser.parse_args(
        [
            "sign-release",
            str(tmp_path),
            "--gpg-key",
            FINGERPRINT,
            "--gpg-keyring",
            str(keyring),
            "--execute",
        ]
    )
    verify = parser.parse_args(
        [
            "verify-release",
            str(tmp_path),
            "--gpg-fingerprint",
            FINGERPRINT,
        ]
    )

    assert sign.gpg_key == FINGERPRINT
    assert sign.gpg_keyring == keyring
    assert verify.gpg_fingerprint == FINGERPRINT


def test_executed_release_cli_propagates_blocked_sign_and_verify_status(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = Project.create("BlockedCli", tmp_path / "blocked-cli", "26.04")

    with pytest.raises(SystemExit) as sign_exit:
        main(
            [
                "sign-release",
                str(project.root),
                "--execute",
                "--json",
            ]
        )
    assert sign_exit.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"

    with pytest.raises(SystemExit) as verify_exit:
        main(["verify-release", str(project.root), "--json"])
    assert verify_exit.value.code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"


def test_validsig_parser_records_signing_and_primary_fingerprints() -> None:
    signing_subkey = "1111111111111111111111111111111111111111"
    status = (
        f"[GNUPG:] VALIDSIG {signing_subkey} 2026-07-29 1785300000 0 4 0 22 10 00 {FINGERPRINT}\n"
    )

    assert validsig_fingerprints(status) == (signing_subkey, FINGERPRINT)


class _StatusRunner:
    def __init__(self, stdout: str, returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.history: list[CommandSpec] = []

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        return CommandResult(spec, self.returncode, self.stdout, "")


def test_rc_zero_without_validsig_is_never_accepted(tmp_path: Path) -> None:
    keyring = tmp_path / "trusted.gpg"
    keyring.write_bytes(b"not inspected by the fake runner")
    signature = tmp_path / "payload.asc"
    signature.write_text("signature\n", encoding="utf-8")
    payload = tmp_path / "payload"
    payload.write_text("payload\n", encoding="utf-8")
    runner = _StatusRunner("[GNUPG:] GOODSIG 1234 signer\n")

    with pytest.raises(ValueError, match="no VALIDSIG"):
        verify_detached_signature(  # type: ignore[arg-type]
            runner,
            signature,
            payload,
            keyring,
            FINGERPRINT,
        )

    argv = runner.history[0].argv
    assert "--no-options" in argv
    assert "--no-default-keyring" in argv
    assert "--no-auto-key-retrieve" in argv
    assert "--status-fd" in argv


def test_signature_verification_can_bind_held_artifact_descriptors(
    tmp_path: Path,
) -> None:
    keyring = tmp_path / "trusted.gpg"
    keyring.write_bytes(b"held keyring bytes")
    signature = tmp_path / "payload.asc"
    signature.write_bytes(b"held signature bytes")
    payload = tmp_path / "payload"
    payload.write_bytes(b"held payload bytes")
    runner = _StatusRunner(f"[GNUPG:] VALIDSIG {FINGERPRINT}\n")
    descriptors = tuple(os.open(path, os.O_RDONLY) for path in (signature, payload, keyring))
    try:
        for descriptor in descriptors:
            os.lseek(descriptor, 2, os.SEEK_SET)
        seen = verify_detached_signature(  # type: ignore[arg-type]
            runner,
            signature,
            payload,
            keyring,
            FINGERPRINT,
            signature_fd=descriptors[0],
            payload_fd=descriptors[1],
            keyring_fd=descriptors[2],
        )
        offsets = tuple(os.lseek(descriptor, 0, os.SEEK_CUR) for descriptor in descriptors)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)

    assert seen == (FINGERPRINT,)
    spec = runner.history[0]
    assert f"/proc/self/fd/{descriptors[0]}" in spec.argv
    assert f"/proc/self/fd/{descriptors[1]}" in spec.argv
    assert spec.pass_fds == descriptors[:2]
    assert offsets == (2, 2, 2)


def test_release_verification_rejects_a_symlinked_signature(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    outside = tmp_path / "outside.asc"
    outside.write_text("not bundle evidence\n", encoding="utf-8")
    (bundle / "SHA256SUMS.asc").symlink_to(outside)
    items = []

    _verify_signatures(
        bundle,
        {"planned": ["SHA256SUMS.asc"]},
        items,
        FINGERPRINT,
    )

    assert any(item.code == "signature-path" and item.status == "blocked" for item in items)


def test_release_verification_rejects_a_forged_partial_signed_report(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "partial"
    bundle.mkdir()
    (bundle / "SHA256SUMS").write_text("payload\n", encoding="utf-8")
    (bundle / "SHA256SUMS.asc").write_text("signature\n", encoding="utf-8")
    items = []

    _verify_signatures(
        bundle,
        {
            "status": "signed",
            "execute": True,
            "signed": ["SHA256SUMS.asc"],
            "planned": [],
            "skipped": [],
        },
        items,
        FINGERPRINT,
    )

    assert any(item.code == "signature-contract" and item.status == "blocked" for item in items)


gpg_binary = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is not installed")


@pytest.fixture
def release_signers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[str, str, Path, Path]:
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("GNUPGHOME", str(home))
    base = ("gpg", "--batch", "--quiet", "--passphrase", "")
    identities = (
        "DistroForge Probe A <probe@distroforge.invalid>",
        "DistroForge Probe B <probe@distroforge.invalid>",
    )
    fingerprints: list[str] = []
    keyrings: list[Path] = []
    for identity in identities:
        subprocess.run(
            (
                *base,
                "--quick-generate-key",
                identity,
                "ed25519",
                "sign",
                "never",
            ),
            check=True,
            capture_output=True,
        )
        listing = subprocess.run(
            ("gpg", "--batch", "--with-colons", "--fingerprint", "--list-keys", identity),
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        fingerprints.append(
            next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        )
        keyring = tmp_path / f"signer-{len(keyrings) + 1}.gpg"
        subprocess.run(
            (
                "gpg",
                "--batch",
                "--output",
                str(keyring),
                "--export-options",
                "export-minimal",
                "--export",
                fingerprints[-1],
            ),
            check=True,
            capture_output=True,
        )
        keyrings.append(keyring)
    return fingerprints[0], fingerprints[1], keyrings[0], keyrings[1]


@gpg_binary
def test_real_signing_plan_is_nonmutating_before_execute_on_the_same_bundle(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, _, signer_keyring, _ = release_signers
    project, bundle = _ready_bundle(tmp_path, "RealPlanThenExecute")
    bundled_iso = next(bundle.glob("*.iso"))
    source_iso = project.output_dir / bundled_iso.name
    write_valid_build_evidence(project, source_iso, run_id="build-run")
    write_valid_boot_proof(
        project,
        source_iso,
        run_id="boot-run",
        build_run_id="build-run",
    )
    sbom = _enable_fixture_spdx_sbom(project)
    bundled_iso.write_bytes(source_iso.read_bytes())
    (bundle / "SHA256SUMS").write_text(
        f"{sha256_file(bundled_iso)}  {bundled_iso.name}\n",
        encoding="utf-8",
    )
    gate_path = bundle / "RELEASE-GATE.json"
    gate = json.loads(gate_path.read_text(encoding="utf-8"))
    gate["items"] = _complete_gate_items(
        iso_size=bundled_iso.stat().st_size,
        iso_sha256=sha256_file(bundled_iso),
    )
    gate_path.write_text(json.dumps(gate) + "\n", encoding="utf-8")
    for name in ("boot-proof.json", "qemu-lab-report.json"):
        shutil.copyfile(project.output_dir / name, bundle / name)
    shutil.copyfile(sbom, bundle / sbom.name)
    shutil.copytree(project.output_dir / "evidence", bundle / "evidence")
    opening_entries = tuple(
        sorted(path.relative_to(bundle).as_posix() for path in bundle.rglob("*"))
    )
    opening_files = {
        path.relative_to(bundle).as_posix(): path.read_bytes()
        for path in bundle.rglob("*")
        if path.is_file()
    }

    planned = sign_release_bundle(
        project,
        bundle_dir=bundle,
        gpg_key=signer,
        gpg_keyring=signer_keyring,
    )

    assert planned.status == "planned"
    assert planned.execute is False
    assert len(planned.planned) == len(release_signing_module.SIGN_TARGETS)
    assert opening_entries == tuple(
        sorted(path.relative_to(bundle).as_posix() for path in bundle.rglob("*"))
    )
    assert opening_files == {
        path.relative_to(bundle).as_posix(): path.read_bytes()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    assert not (bundle / SIGNING_KEYRING).exists()
    assert not (bundle / "RELEASE-MANIFEST.json").exists()
    assert not (bundle / "SIGNING-REPORT.json").exists()
    assert not list(bundle.glob("*.asc"))

    signed = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=signer_keyring,
    )
    verified = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_signer_fingerprint=signer,
    )

    assert signed.status == "signed"
    assert verified.status == "ready", verified.render_text()
    assert sum(
        item.code == "signature" and item.status == "ready" for item in verified.items
    ) == len(release_signing_module.SIGN_TARGETS)


@gpg_binary
def test_real_signed_pipeline_resolves_the_sole_publish_signing_review_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, _, signer_keyring, _ = release_signers
    project = Project.create(
        "RealSignedPipeline",
        tmp_path / "real-signed-pipeline",
        "26.04",
    )
    project.source_mode = "bootstrap"
    iso = default_output_iso(project)
    iso.write_bytes(b"real signed pipeline ISO fixture")
    options = package_fixture_options()
    write_valid_build_evidence(project, iso)
    write_valid_boot_proof(project, iso)
    _enable_fixture_spdx_sbom(project)
    sealed_names = (
        "SHA256SUMS",
        "BUILDINFO",
        "distroforge-provenance.json",
        "report.html",
    )
    sealed_source = {name: (project.output_dir / name).read_bytes() for name in sealed_names}
    measured_gate = ReleaseGateService().check(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        capture_artifact_receipt=True,
    )
    assert measured_gate.artifact_receipt is not None
    gate = ReleaseGateReport(
        project.root,
        iso,
        project.output_dir,
        [
            ReleaseGateItem(
                str(item["code"]),
                str(item["status"]),
                str(item["detail"]),
            )
            for item in _complete_gate_items(
                iso_size=iso.stat().st_size,
                iso_sha256=sha256_file(iso),
                publish_signing="review",
            )
        ],
        artifact_receipt=measured_gate.artifact_receipt,
        build_run_id=measured_gate.build_run_id,
        boot_run_id=measured_gate.boot_run_id,
        immutable_iso_build=measured_gate.immutable_iso_build,
        immutable_provenance=measured_gate.immutable_provenance,
        immutable_boot_proof=measured_gate.immutable_boot_proof,
        immutable_qemu_report=measured_gate.immutable_qemu_report,
        immutable_sbom=measured_gate.immutable_sbom,
    )
    monkeypatch.setattr(
        ReleaseGateService,
        "check",
        lambda *_args, **_kwargs: gate,
    )
    bundle = project.output_dir / "publish"

    pipeline = run_release_pipeline(
        project,
        options,
        iso=iso,
        output_dir=project.output_dir,
        bundle_dir=bundle,
        execute_signing=True,
        gpg_key=signer,
        gpg_keyring=signer_keyring,
    )

    stages = {stage.name: stage.status for stage in pipeline.stages}
    assert pipeline.status == "ready", pipeline.render_text()
    assert stages == {
        "boot-proof": "ready",
        "repair-artifacts": "ready",
        "publish-bundle": "ready",
        "manifest-plan": "ready",
        "release-notes": "ready",
        "sign-release-final": "signed",
        "verify-release": "ready",
    }
    repair_detail = next(
        stage.detail
        for stage in pipeline.stages
        if stage.name == "repair-artifacts"
    )
    assert "immutable build run build-run is the authority" in repair_detail
    assert "compatibility aliases were not read or rewritten" in repair_detail
    assert sealed_source == {
        name: (project.output_dir / name).read_bytes() for name in sealed_names
    }
    assert pipeline.bundle_identity is not None

    terminal = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_signer_fingerprint=signer,
        expected_bundle_identity=pipeline.bundle_identity,
    )

    assert terminal.status == "ready"
    assert terminal.bundle_identity == pipeline.bundle_identity
    assert sum(
        item.code == "signature" and item.status == "ready" for item in terminal.items
    ) == len(release_signing_module.SIGN_TARGETS)
    gate_status = next(item for item in terminal.items if item.code == "gate-status")
    assert gate_status.status == "ready"
    assert "sole pre-signing publish review is resolved" in gate_status.detail

    explanation = explain_release(
        project,
        iso=iso,
        bundle_dir=bundle,
        write=True,
        expected_bundle_identity=pipeline.bundle_identity,
        verification=terminal,
    )
    evidence, evidence_problem = _read_drill_evidence(
        bundle,
        expected_bundle_identity=pipeline.bundle_identity,
    )

    assert explanation.status == "ready"
    assert explanation.review == ()
    assert any(item.startswith("publish-signing: resolved") for item in explanation.ready)
    assert evidence_problem is None
    assert evidence["release_gate"]["status"] == "review"
    assert evidence["verify"]["status"] == "ready"
    assert (
        _drill_status(
            pipeline.status,
            explanation.status,
            terminal.status,
            evidence_problem,
        )
        == "ready_to_publish"
    )


@gpg_binary
def test_release_verification_accepts_only_the_externally_pinned_signer(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, other_valid_signer, signer_keyring, _ = release_signers
    project, bundle = _ready_bundle(tmp_path, "RealPinned")
    signing = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=signer_keyring,
    )

    assert signing.status == "signed"
    assert signing.signer_fingerprint == signer
    assert signing.verification_keyring == SIGNING_KEYRING
    assert signing.verification_keyring_sha256 == sha256_file(bundle / SIGNING_KEYRING)
    manifest = json.loads((bundle / "RELEASE-MANIFEST.json").read_text(encoding="utf-8"))
    keyring_entry = next(entry for entry in manifest["files"] if entry["name"] == SIGNING_KEYRING)
    assert keyring_entry["sha256"] == signing.verification_keyring_sha256
    accepted = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_signer_fingerprint=signer,
    )
    assert all(
        item.status == "ready"
        for item in accepted.items
        if item.code in {"signature", "signature-fingerprint", "signature-keyring"}
    )
    assert any(item.code == "signature" and "VALIDSIG" in item.detail for item in accepted.items)

    # Simulate an attacker replacing the unsigned operational report so that it names
    # another perfectly valid key. The externally supplied pin still controls trust,
    # and the cryptographic VALIDSIG from the real signature does not match it.
    report_path = bundle / "SIGNING-REPORT.json"
    tampered = json.loads(report_path.read_text(encoding="utf-8"))
    tampered["signer_fingerprint"] = other_valid_signer
    report_path.write_text(json.dumps(tampered), encoding="utf-8")
    rejected = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_signer_fingerprint=other_valid_signer,
    )
    assert any(
        item.code == "signature" and item.status == "blocked" and "not" in item.detail
        for item in rejected.items
    )


@gpg_binary
def test_secret_keyring_input_is_reexported_as_minimal_public_material(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, _, _, _ = release_signers
    secret_source = tmp_path / "source-secret-keyring.gpg"
    subprocess.run(
        (
            "gpg",
            "--batch",
            "--yes",
            "--output",
            str(secret_source),
            "--export-secret-keys",
            signer,
        ),
        check=True,
        capture_output=True,
    )
    project, bundle = _ready_bundle(tmp_path, "SecretKeyringSanitization")

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=secret_source,
    )

    assert report.status == "signed"
    published = bundle / SIGNING_KEYRING
    assert published.read_bytes() != secret_source.read_bytes()
    inspection_home = tmp_path / "inspect-published-keyring"
    inspection_home.mkdir(mode=0o700)
    subprocess.run(
        (
            "gpg",
            "--batch",
            "--homedir",
            str(inspection_home),
            "--import",
            str(published),
        ),
        check=True,
        capture_output=True,
    )
    public_listing = subprocess.run(
        (
            "gpg",
            "--batch",
            "--homedir",
            str(inspection_home),
            "--with-colons",
            "--fingerprint",
            "--list-keys",
        ),
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    secret_listing = subprocess.run(
        (
            "gpg",
            "--batch",
            "--homedir",
            str(inspection_home),
            "--with-colons",
            "--list-secret-keys",
        ),
        check=False,
        capture_output=True,
        text=True,
    ).stdout

    assert release_signing_module._primary_fingerprints(
        public_listing,
        "pub",
    ) == (signer,)
    assert not any(line.startswith(("sec:", "ssb:")) for line in secret_listing.splitlines())


@gpg_binary
def test_release_verification_allows_named_post_pipeline_operational_files(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, _, signer_keyring, _ = release_signers
    project, bundle = _ready_bundle(tmp_path, "OperationalFiles")
    signing = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=signer_keyring,
    )
    assert signing.status == "signed"
    baseline = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_signer_fingerprint=signer,
    )
    post_pipeline_reports = {
        "PUBLISH-DRILL-BASELINE.json",
        "PUBLISH-DRILL.json",
        "PUBLISH-DRILL.previous.json",
        "RELEASE-EXPLAIN.md",
        "RELEASE-PIPELINE.json",
    }
    assert post_pipeline_reports < OPERATIONAL_BUNDLE_FILES
    for name in post_pipeline_reports:
        content = (
            f"operational report: {name}\n"
            if name.endswith(".md")
            else json.dumps({"operational_report": name}) + "\n"
        )
        (bundle / name).write_text(content, encoding="utf-8")

    report = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_signer_fingerprint=signer,
    )

    assert report.status == baseline.status
    assert not any(item.code == "manifest-extra" for item in report.items)


@gpg_binary
def test_release_verification_blocks_an_unmanifested_empty_directory(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, _, signer_keyring, _ = release_signers
    project, bundle = _ready_bundle(tmp_path, "RogueDirectory")
    signing = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=signer_keyring,
    )
    assert signing.status == "signed"
    (bundle / "rogue-empty").mkdir()

    report = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_signer_fingerprint=signer,
    )

    assert report.blocked
    assert any(
        item.code == "manifest-extra" and item.status == "blocked" and "rogue-empty" in item.detail
        for item in report.items
    )


@gpg_binary
def test_release_verification_blocks_when_external_fingerprint_is_absent(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, _, signer_keyring, _ = release_signers
    project, bundle = _ready_bundle(tmp_path, "MissingPin")
    signing = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=signer_keyring,
    )
    assert signing.status == "signed"

    report = verify_release_bundle(project, bundle_dir=bundle)

    assert any(
        item.code == "signature-fingerprint" and item.status == "blocked" for item in report.items
    )


@gpg_binary
def test_signing_rejects_a_public_keyring_for_another_valid_key(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, _, _, other_keyring = release_signers
    project, bundle = _ready_bundle(tmp_path, "WrongKeyring")

    report = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=other_keyring,
    )

    assert report.status == "blocked"
    assert any("must contain only the pinned primary key" in item for item in report.skipped)
    assert not list(bundle.glob("*.asc"))


@gpg_binary
def test_verification_rejects_a_keyring_whose_digest_changed(
    tmp_path: Path,
    release_signers: tuple[str, str, Path, Path],
) -> None:
    signer, _, signer_keyring, _ = release_signers
    project, bundle = _ready_bundle(tmp_path, "ChangedKeyring")
    signing = sign_release_bundle(
        project,
        bundle_dir=bundle,
        execute=True,
        gpg_key=signer,
        gpg_keyring=signer_keyring,
    )
    assert signing.status == "signed"
    with (bundle / SIGNING_KEYRING).open("ab") as handle:
        handle.write(b"tampered")

    report = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_signer_fingerprint=signer,
    )

    assert any(
        item.code == "signature-keyring" and item.status == "blocked" for item in report.items
    )
