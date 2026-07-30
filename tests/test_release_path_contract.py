from __future__ import annotations

import hashlib
import json
import shlex
from pathlib import Path
from types import SimpleNamespace

import distroforge.commands.artifacts as artifact_commands
import distroforge.core.publish_bundle as publish_bundle_module
import distroforge.core.release_explain as release_explain_module
from distroforge.cli import build_parser
from distroforge.core.build import BuildOptions
from distroforge.core.project import Project
from distroforge.core.release_contract import REQUIRED_RELEASE_GATE_CODES
from distroforge.core.release_explain import _next_commands, explain_release
from distroforge.core.release_signing import sign_release_bundle
from distroforge.core.release_verification import (
    ReleaseVerifyReport,
    verify_release_bundle,
)
from distroforge.ui.artifact_release_paths import (
    resolve_artifact_release_paths,
)

_FINGERPRINT = "A" * 40


class _Edit:
    def __init__(self, value: str = "") -> None:
        self.value = value

    def text(self) -> str:
        return self.value


def _window(
    project: Project,
    *,
    iso: Path,
    reports: Path | None,
    build_run_id: str = "",
    boot_run_id: str = "",
) -> SimpleNamespace:
    return SimpleNamespace(
        project=project,
        artifacts_output_iso_edit=_Edit(str(iso)),
        output_iso_edit=_Edit(),
        artifacts_reports_dir_edit=_Edit("" if reports is None else str(reports)),
        artifacts_build_run_id_edit=_Edit(build_run_id),
        artifacts_boot_run_id_edit=_Edit(boot_run_id),
    )


def test_ui_release_path_resolver_separates_product_from_reports(
    tmp_path: Path,
) -> None:
    project = Project.create("PathContract", tmp_path / "project", "26.04")
    iso = tmp_path / "custom-product" / "Custom.iso"
    reports = tmp_path / "release-records" / "reports"

    paths = resolve_artifact_release_paths(_window(project, iso=iso, reports=reports))

    assert paths.iso == iso
    assert paths.product_output_dir == iso.parent
    assert paths.bundle_dir == reports.parent / "publish"


def test_ui_release_path_resolver_freezes_build_and_boot_run_ids(
    tmp_path: Path,
) -> None:
    project = Project.create("RunPathContract", tmp_path / "project", "26.04")
    iso = tmp_path / "custom-product" / "Custom.iso"

    paths = resolve_artifact_release_paths(
        _window(
            project,
            iso=iso,
            reports=None,
            build_run_id=" build-selected ",
            boot_run_id=" boot-selected ",
        )
    )

    assert paths.build_run_id == "build-selected"
    assert paths.boot_run_id == "boot-selected"


def test_ui_release_path_resolver_handles_explicit_and_default_bundle(
    tmp_path: Path,
) -> None:
    project = Project.create("BundleContract", tmp_path / "project", "26.04")
    iso = tmp_path / "custom-product" / "Custom.iso"
    explicit_bundle = tmp_path / "release-records" / "publish"

    explicit = resolve_artifact_release_paths(_window(project, iso=iso, reports=explicit_bundle))
    default = resolve_artifact_release_paths(_window(project, iso=iso, reports=None))
    product_parent = resolve_artifact_release_paths(_window(project, iso=iso, reports=iso.parent))

    assert explicit.bundle_dir == explicit_bundle
    assert default.bundle_dir == project.output_dir / "publish"
    assert product_parent.bundle_dir == iso.parent / "publish"


def test_custom_iso_implies_its_parent_for_signing_and_verification(
    tmp_path: Path,
) -> None:
    project, source_iso, bundle = _custom_product_bundle(tmp_path)

    signing = sign_release_bundle(
        project,
        bundle_dir=bundle,
        expected_product_iso=source_iso,
        publish_artifacts=True,
    )

    assert signing.status == "planned"
    verification = verify_release_bundle(
        project,
        bundle_dir=bundle,
        expected_product_iso=source_iso,
        publish_report=False,
    )
    gate = next(item for item in verification.items if item.code == "gate-status")
    assert gate.status == "ready"


def test_sign_and_verify_cli_forward_an_iso_only_product_selection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("IsoOnlyCli", tmp_path / "project", "26.04")
    iso = tmp_path / "custom-product" / "Custom.iso"
    bundle = tmp_path / "release-records" / "publish"
    calls: list[tuple[str, dict[str, object]]] = []

    class _SigningReport:
        status = "planned"

        def render_text(self) -> str:
            return "planned"

        def render_json(self) -> str:
            return "{}"

    class _VerifyReport:
        blocked = False

        def render_text(self) -> str:
            return "review"

        def render_json(self) -> str:
            return "{}"

    def fake_sign(*_args, **kwargs) -> _SigningReport:
        calls.append(("sign", kwargs))
        return _SigningReport()

    def fake_verify(*_args, **kwargs) -> _VerifyReport:
        calls.append(("verify", kwargs))
        return _VerifyReport()

    monkeypatch.setattr(artifact_commands, "sign_release_bundle", fake_sign)
    monkeypatch.setattr(artifact_commands, "verify_release_bundle", fake_verify)

    for command in ("sign-release", "verify-release"):
        parsed = build_parser().parse_args(
            [
                command,
                str(project.root),
                "--iso",
                str(iso),
                "--bundle-dir",
                str(bundle),
            ]
        )
        artifact_commands.render_artifacts_command(parsed)

    assert calls[0][0] == "sign"
    assert calls[1][0] == "verify"
    for _, kwargs in calls:
        assert kwargs["expected_product_iso"] == iso
        assert kwargs["expected_product_output_dir"] is None


def test_release_gate_cli_forwards_the_selected_bundle(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("GateBundleCli", tmp_path / "project", "26.04")
    iso = tmp_path / "custom-product" / "Custom.iso"
    bundle = tmp_path / "release-records" / "publish"
    parsed = build_parser().parse_args(
        [
            "release-gate",
            str(project.root),
            "--iso",
            str(iso),
            "--bundle-dir",
            str(bundle),
        ]
    )
    captured: dict[str, object] = {}

    class _GateReport:
        blocked = False

        def render_text(self) -> str:
            return "review"

        def render_json(self) -> str:
            return "{}"

    def fake_check(_self, _project, _options, **kwargs) -> _GateReport:
        captured.update(kwargs)
        return _GateReport()

    monkeypatch.setattr(
        artifact_commands.ReleaseGateService,
        "check",
        fake_check,
    )

    artifact_commands.render_artifacts_command(parsed)

    assert captured["iso"] == iso
    assert captured["output_dir"] is None
    assert captured["bundle_dir"] == bundle


def test_publish_bundle_forwards_its_selected_bundle_to_the_gate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("GateBundlePublish", tmp_path / "project", "26.04")
    bundle = tmp_path / "release-records" / "publish"
    captured: dict[str, object] = {}
    gate = object()

    def fake_check(_self, _project, _options, **kwargs):
        captured.update(kwargs)
        return gate

    monkeypatch.setattr(
        publish_bundle_module.ReleaseGateService,
        "check",
        fake_check,
    )

    def stop_after_gate(_path: Path) -> None:
        raise ValueError("stop after gate")

    monkeypatch.setattr(
        publish_bundle_module,
        "ensure_directory_nofollow",
        stop_after_gate,
    )

    report = publish_bundle_module.create_publish_bundle(
        project,
        BuildOptions(),
        bundle_dir=bundle,
    )

    assert captured["bundle_dir"] == bundle
    assert captured["capture_artifact_receipt"] is True
    assert report.gate is gate


def test_explain_release_forwards_the_expected_signer_fingerprint(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("ExplainPin", tmp_path / "project", "26.04")
    iso = tmp_path / "custom-product" / "Custom.iso"
    bundle = tmp_path / "release-records" / "publish"
    captured: dict[str, object] = {}

    def fake_verify(*args, **kwargs) -> ReleaseVerifyReport:
        captured.update(kwargs)
        return ReleaseVerifyReport(project.root, bundle, "blocked", ())

    monkeypatch.setattr(
        release_explain_module,
        "verify_release_bundle",
        fake_verify,
    )

    explain_release(
        project,
        iso=iso,
        bundle_dir=bundle,
        write=False,
        expected_signer_fingerprint=_FINGERPRINT,
    )

    assert captured["expected_signer_fingerprint"] == _FINGERPRINT
    assert captured["expected_product_iso"] == iso
    assert captured["expected_product_output_dir"] == iso.parent


def test_explain_release_cli_parses_and_propagates_fingerprint(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("ExplainCliPin", tmp_path / "project", "26.04")
    iso = tmp_path / "custom-product" / "Custom.iso"
    bundle = tmp_path / "release-records" / "publish"
    parsed = build_parser().parse_args(
        [
            "explain-release",
            str(project.root),
            "--iso",
            str(iso),
            "--bundle-dir",
            str(bundle),
            "--gpg-fingerprint",
            _FINGERPRINT,
        ]
    )
    captured: dict[str, object] = {}

    class _Report:
        def render_text(self) -> str:
            return "explanation"

        def render_json(self) -> str:
            return "{}"

    def fake_explain(*args, **kwargs) -> _Report:
        captured.update(kwargs)
        return _Report()

    monkeypatch.setattr(artifact_commands, "explain_release", fake_explain)

    rendered = artifact_commands.render_explain_release(
        parsed.root,
        parsed.iso,
        parsed.bundle_dir,
        expected_signer_fingerprint=parsed.gpg_fingerprint,
    )

    assert rendered == "explanation"
    assert captured == {
        "iso": iso,
        "bundle_dir": bundle,
        "expected_signer_fingerprint": _FINGERPRINT,
    }


def test_release_remediation_commands_are_quoted_and_propagate_product_and_pin(
    tmp_path: Path,
) -> None:
    project = Project.create(
        "QuotedRemediation",
        tmp_path / "project ; $(touch should-not-run)",
        "26.04",
    )
    iso = tmp_path / "product dir" / "Release ; $(false).iso"
    bundle = tmp_path / "bundle dir ; $(false)"

    commands = _next_commands(
        project,
        iso,
        bundle,
        "review",
        {"proof_level": "runtime"},
        ["sha256: product checksum must be rebuilt"],
        ["signature: awaiting maintainer action"],
        expected_signer_fingerprint=_FINGERPRINT.lower(),
    )
    parsed = {shlex.split(command)[1]: shlex.split(command) for command in commands}

    assert all(shlex.join(shlex.split(command)) == command for command in commands)
    assert parsed["release-gate"] == [
        "distroforge",
        "release-gate",
        str(project.root),
        "--iso",
        str(iso),
        "--output-dir",
        str(iso.parent),
        "--bundle-dir",
        str(bundle),
    ]
    assert parsed["release-pipeline"] == [
        "distroforge",
        "release-pipeline",
        str(project.root),
        "--iso",
        str(iso),
        "--output-dir",
        str(iso.parent),
        "--bundle-dir",
        str(bundle),
        "--run-boot-proof",
        "--boot-backend",
        "auto",
    ]
    assert parsed["sign-release"] == [
        "distroforge",
        "sign-release",
        str(project.root),
        "--bundle-dir",
        str(bundle),
        "--iso",
        str(iso),
        "--output-dir",
        str(iso.parent),
        "--gpg-key",
        _FINGERPRINT,
        "--gpg-keyring",
        "/path/to/public-keyring.gpg",
        "--execute",
    ]
    assert parsed["verify-release"] == [
        "distroforge",
        "verify-release",
        str(project.root),
        "--bundle-dir",
        str(bundle),
        "--iso",
        str(iso),
        "--output-dir",
        str(iso.parent),
        "--gpg-fingerprint",
        _FINGERPRINT,
    ]
    sign_args = build_parser().parse_args(parsed["sign-release"][1:])
    verify_args = build_parser().parse_args(parsed["verify-release"][1:])
    assert sign_args.gpg_key == _FINGERPRINT
    assert sign_args.gpg_keyring == Path("/path/to/public-keyring.gpg")
    assert verify_args.gpg_fingerprint == _FINGERPRINT


def test_release_remediation_commands_use_explicit_fingerprint_placeholder(
    tmp_path: Path,
) -> None:
    project = Project.create("Placeholder", tmp_path / "project", "26.04")
    iso = tmp_path / "product" / "Release.iso"
    bundle = tmp_path / "bundle"

    commands = _next_commands(
        project,
        iso,
        bundle,
        "review",
        {"proof_level": "runtime"},
        [],
        ["signature: awaiting maintainer action"],
    )
    parsed = [shlex.split(command) for command in commands]
    sign = next(argv for argv in parsed if argv[1] == "sign-release")
    verify = next(argv for argv in parsed if argv[1] == "verify-release")

    assert sign[sign.index("--gpg-key") + 1] == "FULL_FINGERPRINT"
    assert sign[sign.index("--gpg-keyring") + 1] == ("/path/to/public-keyring.gpg")
    assert verify[verify.index("--gpg-fingerprint") + 1] == ("FULL_FINGERPRINT")


def test_release_remediation_preserves_selected_build_and_boot_runs(
    tmp_path: Path,
) -> None:
    project = Project.create("RunBoundRepair", tmp_path / "project", "26.04")
    iso = tmp_path / "product" / "Release.iso"
    bundle = tmp_path / "bundle"

    commands = _next_commands(
        project,
        iso,
        bundle,
        "blocked",
        {"proof_level": "none"},
        ["sha256: product checksum must be rebuilt"],
        [],
        build_run_id="build-selected",
        boot_run_id="boot-selected",
    )
    parsed = {shlex.split(command)[1]: shlex.split(command) for command in commands}

    assert parsed["boot-proof"][-2:] == [
        "--build-run-id",
        "build-selected",
    ]
    assert "--run-boot-proof" not in parsed["release-pipeline"]
    assert parsed["release-pipeline"][-4:] == [
        "--build-run-id",
        "build-selected",
        "--boot-run-id",
        "boot-selected",
    ]
    assert parsed["release-gate"][-4:] == [
        "--build-run-id",
        "build-selected",
        "--boot-run-id",
        "boot-selected",
    ]


def test_publish_drill_baseline_cli_uses_canonical_fingerprint_with_alias(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = Project.create("BaselineCliPin", tmp_path / "project", "26.04")
    captured: list[str | None] = []

    class _Report:
        blocked = False

        def render_text(self) -> str:
            return "baseline"

        def render_json(self) -> str:
            return "{}"

    def fake_promote(*_args, **kwargs) -> _Report:
        captured.append(kwargs["expected_signer_fingerprint"])
        return _Report()

    monkeypatch.setattr(
        artifact_commands,
        "promote_publish_drill_baseline",
        fake_promote,
    )
    for option in ("--gpg-fingerprint", "--gpg-key"):
        parsed = build_parser().parse_args(
            [
                "publish-drill-baseline",
                str(project.root),
                option,
                _FINGERPRINT,
            ]
        )
        assert parsed.gpg_fingerprint == _FINGERPRINT
        rendered = artifact_commands.render_artifacts_command(parsed)
        assert rendered == ("baseline", False)

    assert captured == [_FINGERPRINT, _FINGERPRINT]


def _custom_product_bundle(
    tmp_path: Path,
) -> tuple[Project, Path, Path]:
    project = Project.create("CustomProduct", tmp_path / "project", "26.04")
    source_iso = tmp_path / "custom-product" / "CustomProduct.iso"
    source_iso.parent.mkdir(parents=True)
    source_iso.write_bytes(b"custom iso")
    digest = hashlib.sha256(source_iso.read_bytes()).hexdigest()
    bundle = project.output_dir / "publish"
    bundle.mkdir(parents=True)
    (bundle / source_iso.name).write_bytes(source_iso.read_bytes())
    (bundle / "SHA256SUMS").write_text(
        f"{digest}  {source_iso.name}\n",
        encoding="utf-8",
    )
    items = [
        {
            "code": code,
            "status": "ready",
            "detail": (
                f"{source_iso.stat().st_size} bytes"
                if code == "iso"
                else digest
                if code == "sha256"
                else f"{code} fixture evidence"
            ),
        }
        for code in sorted(REQUIRED_RELEASE_GATE_CODES)
    ]
    (bundle / "RELEASE-GATE.json").write_text(
        json.dumps(
            {
                "project": str(project.root),
                "iso": str(source_iso),
                "output_dir": str(source_iso.parent),
                "build_run_id": "build-run",
                "boot_run_id": "boot-run",
                "immutable_iso_build": str(
                    source_iso.parent
                    / "evidence"
                    / "runs"
                    / "build-run"
                    / "ISO-BUILD.json"
                ),
                "immutable_provenance": str(
                    source_iso.parent
                    / "evidence"
                    / "runs"
                    / "build-run"
                    / "distroforge-provenance.json"
                ),
                "immutable_boot_proof": str(
                    source_iso.parent
                    / "evidence"
                    / "runs"
                    / "boot-run"
                    / "boot-proof.json"
                ),
                "immutable_qemu_report": str(
                    source_iso.parent
                    / "evidence"
                    / "runs"
                    / "boot-run"
                    / "qemu-lab-report.json"
                ),
                "immutable_sbom": str(
                    source_iso.parent
                    / "evidence"
                    / "runs"
                    / "build-run"
                    / "distroforge-sbom.spdx.json"
                ),
                "status": "ready",
                "blocked": False,
                "items": items,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return project, source_iso, bundle
