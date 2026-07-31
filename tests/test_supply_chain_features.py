from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path

import pytest

import distroforge.core.artifact_verification as artifact_verification_module
import distroforge.core.bootstrap as bootstrap_module
import distroforge.core.build_journey as build_journey_module
import distroforge.core.iso_acceptance as iso_acceptance_module
import distroforge.core.readiness as readiness_module
import distroforge.core.release_gate as release_gate_module
import distroforge.core.release_pipeline as release_pipeline_module
import distroforge.core.vulnscan as vulnscan_module
from distroforge.core.apt import PackagePlan
from distroforge.core.bootstrap import BootstrapOptions, BootstrapService, host_dpkg_arch
from distroforge.core.build import BuildOptions, BuildOrchestrator, BuildPhase
from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.dry_run_report import generate_dry_run_report
from distroforge.core.project import Project
from distroforge.core.provenance import (
    CYCLONEDX_FILENAME,
    SPDX_FILENAME,
    ProvenanceOptions,
    ProvenanceService,
)
from distroforge.core.readiness import ReadinessService
from distroforge.core.releases import get_release
from distroforge.core.squashfs import SquashfsOptions
from distroforge.core.vulnscan import VulnScanOptions, VulnScanService


class _RecordingExecuteRunner(CommandRunner):
    """Not dry-run, but launches nothing -- the same shape as in test_core_smoke.

    Needed because the suite is L0/L1 by contract: it must never invoke an external
    tool. A plain CommandRunner(dry_run=False) does, and the difference is invisible on
    a developer machine that happens to have the tool installed -- which is how a test
    added here passed locally and failed on CI for want of grub-mkimage.
    """

    def __init__(self) -> None:
        super().__init__(dry_run=False)

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        return CommandResult(spec=spec, returncode=0, stdout="", stderr="")


def _bootstrap_project(tmp_path, name: str) -> Project:
    project = Project.create(name, tmp_path / name.lower(), "26.04")
    project.source_mode = "bootstrap"
    return project


# --------------------------------------------------------------------------- #
# #1 CVE / vulnerability scanning
# --------------------------------------------------------------------------- #


def _vuln_advisory(**overrides: object) -> dict[str, object]:
    advisory: dict[str, object] = {
        "id": "CVE-TEST-0001",
        "package": "fixture-package",
        "severity": "high",
        "fixed_version": "2",
        "summary": "Fixture advisory.",
    }
    advisory.update(overrides)
    return advisory


def _vuln_database(
    *,
    advisories: list[object] | None = None,
    schema: str = vulnscan_module.VULN_DB_SCHEMA,
) -> dict[str, object]:
    return {
        "meta": {
            "schema": schema,
            "source": "test-fixture",
            "updated": "2026-07-31",
        },
        "advisories": (
            advisories
            if advisories is not None
            else [_vuln_advisory()]
        ),
    }


def _write_vuln_database(
    path: Path,
    *,
    payload: object | None = None,
) -> Path:
    path.write_text(
        json.dumps(_vuln_database() if payload is None else payload),
        encoding="utf-8",
    )
    return path


def _custom_vuln_scan(
    path: Path,
    *,
    policy: str = "block-high",
) -> VulnScanService:
    return VulnScanService(VulnScanOptions(enabled=True, policy=policy, db_path=path))


def test_vuln_scan_matches_bundled_advisory_by_name() -> None:
    report = VulnScanService(VulnScanOptions(enabled=True, policy="warn")).scan(["curl", "vim"])

    assert report.scanned == 2
    assert report.database_status == "valid"
    assert report.database_error == ""
    assert report.advisory_count > 0
    assert len(report.database_sha256) == 64
    assert report.database_schema == vulnscan_module.VULN_DB_SCHEMA
    assert report.database_source == "seed-snapshot"
    assert report.database_updated == "2026-05-01"
    assert report.verdict == "findings"
    assert [finding.cve for finding in report.findings] == ["CVE-2023-38545"]
    finding = report.findings[0]
    assert finding.package == "curl" and finding.severity == "high"
    assert finding.level == "warning" and report.ok is True


def test_vuln_policy_block_high_promotes_high_to_error() -> None:
    report = VulnScanService(VulnScanOptions(enabled=True, policy="block-high")).scan(["curl"])

    assert report.findings[0].level == "error"
    assert report.ok is False


def test_vuln_policy_block_critical_ignores_high_but_blocks_critical() -> None:
    service = VulnScanService(VulnScanOptions(enabled=True, policy="block-critical"))

    high_only = service.scan(["curl"])
    assert high_only.findings[0].level == "warning"
    assert high_only.ok is True

    with_critical = service.scan(["curl", "libwebp"])
    levels = {finding.package: finding.level for finding in with_critical.findings}
    assert levels["curl"] == "warning"
    assert levels["libwebp"] == "error"
    assert with_critical.ok is False
    # Findings are ordered by descending severity, so critical comes first.
    assert with_critical.findings[0].package == "libwebp"


def test_vuln_scan_disabled_returns_empty_report() -> None:
    report = VulnScanService(VulnScanOptions(enabled=False)).scan(["curl", "sudo"])

    assert report.findings == []
    assert report.ok is True
    assert report.database_status == "disabled"
    assert report.verdict == "disabled"
    assert "disabled" in report.render_text()


def test_vuln_scan_missing_custom_db_blocks_a_blocking_policy(tmp_path) -> None:
    options = VulnScanOptions(enabled=True, policy="block-critical", db_path=tmp_path / "nope.json")

    report = VulnScanService(options).scan(["curl"])

    assert [finding.cve for finding in report.findings] == ["DB-UNAVAILABLE"]
    assert report.findings[0].level == "error"
    assert report.database_status == "invalid"
    assert report.database_error == "missing"
    assert report.verdict == "blocked"
    assert report.ok is False


@pytest.mark.parametrize("policy", ["warn", "off"])
def test_vuln_scan_missing_custom_db_degrades_a_nonblocking_policy(
    tmp_path,
    policy,
) -> None:
    service = _custom_vuln_scan(tmp_path / "nope.json", policy=policy)

    report = service.scan(["curl"])

    assert report.database_status == "invalid"
    assert report.findings[0].level == "warning"
    assert report.verdict == "degraded"
    assert report.ok is True
    assert report.to_dict()["verdict"] == "degraded"


def test_vuln_scan_disabled_does_not_consume_package_input() -> None:
    def broken_packages():
        raise AssertionError("disabled CVE scan consumed its package input")
        yield "unreachable"

    report = VulnScanService(VulnScanOptions(enabled=False)).scan(broken_packages())

    assert report.verdict == "disabled"
    assert report.scanned == 0


def test_vuln_scan_invalid_policy_blocks_instead_of_falling_back_to_warn() -> None:
    report = VulnScanService(VulnScanOptions(enabled=True, policy="blok-critical")).scan(["curl"])

    assert report.policy == "blok-critical"
    assert report.database_status == "not-checked"
    assert report.database_error == "invalid-policy"
    assert [finding.cve for finding in report.findings] == ["POLICY-INVALID"]
    assert report.verdict == "blocked"
    assert report.ok is False


def test_vuln_scan_empty_package_input_never_becomes_clean() -> None:
    blocking = VulnScanService(
        VulnScanOptions(enabled=True, policy="block-high")
    ).scan([])
    warning = VulnScanService(VulnScanOptions(enabled=True, policy="warn")).scan([])

    assert blocking.database_status == "not-checked"
    assert blocking.database_error == "empty-package-set"
    assert [finding.cve for finding in blocking.findings] == ["SCAN-EMPTY"]
    assert blocking.verdict == "blocked"
    assert blocking.ok is False
    assert warning.verdict == "degraded"
    assert warning.ok is True


@pytest.mark.parametrize(
    "package",
    ["CURL", "curl ", "curl:amd64", "cúrl", "curl/name", "curl\n", 123],
)
def test_vuln_scan_noncanonical_package_input_never_becomes_clean(package) -> None:
    report = VulnScanService(
        VulnScanOptions(enabled=True, policy="block-high")
    ).scan([package])

    assert report.database_status == "not-checked"
    assert report.database_error == "invalid-package-input"
    assert [finding.cve for finding in report.findings] == ["INPUT-INVALID"]
    assert report.verdict == "blocked"


def test_vuln_scan_package_name_byte_limit_is_exact(tmp_path, monkeypatch) -> None:
    path = _write_vuln_database(
        tmp_path / "valid.json",
        payload=_vuln_database(advisories=[_vuln_advisory(package="zz")]),
    )
    monkeypatch.setattr(vulnscan_module, "MAX_VULN_PACKAGE_NAME_BYTES", 4)
    service = _custom_vuln_scan(path)

    below = service.scan(["abc"])
    exact = service.scan(["abcd"])
    above = service.scan(["abcde"])

    assert below.verdict == "clean"
    assert exact.verdict == "clean"
    assert above.database_error == "package-input-bounds"
    assert [finding.cve for finding in above.findings] == ["INPUT-BOUNDS"]
    assert above.verdict == "blocked"


def test_vuln_scan_package_count_limit_is_exact(tmp_path, monkeypatch) -> None:
    path = _write_vuln_database(tmp_path / "valid.json")
    monkeypatch.setattr(vulnscan_module, "MAX_VULN_SCAN_PACKAGE_INPUTS", 2)
    service = _custom_vuln_scan(path)

    below = service.scan(["aa"])
    exact = service.scan(["aa", "bb"])
    above = service.scan(["aa", "bb", "cc"])

    assert below.verdict == "clean"
    assert exact.verdict == "clean"
    assert above.database_error == "package-input-bounds"
    assert [finding.cve for finding in above.findings] == ["INPUT-BOUNDS"]
    assert above.verdict == "blocked"


def test_vuln_scan_package_iterator_failure_is_controlled() -> None:
    def broken_packages():
        yield "curl"
        raise RuntimeError("injected package iterator failure")

    report = VulnScanService(
        VulnScanOptions(enabled=True, policy="block-high")
    ).scan(broken_packages())

    assert report.database_error == "package-input-error"
    assert [finding.cve for finding in report.findings] == ["INPUT-INVALID"]
    assert report.verdict == "blocked"


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        ({}, "missing-meta"),
        (_vuln_database(schema=""), "schema-mismatch"),
        (_vuln_database(schema="distroforge-vulndb/0"), "schema-mismatch"),
        ({"meta": _vuln_database()["meta"]}, "invalid-advisories"),
        (
            {"meta": _vuln_database()["meta"], "advisories": {}},
            "invalid-advisories",
        ),
        (_vuln_database(advisories=[]), "empty-advisories"),
        (_vuln_database(advisories=["not-an-object"]), "invalid-advisory"),
        (
            _vuln_database(
                advisories=[
                    _vuln_advisory(),
                    _vuln_advisory(),
                ]
            ),
            "duplicate-advisory",
        ),
        (
            _vuln_database(
                advisories=[
                    {
                        "id": "CVE-TEST-0001",
                        "severity": "high",
                        "summary": "Missing package.",
                    }
                ]
            ),
            "invalid-advisory-package",
        ),
        (
            _vuln_database(
                advisories=[
                    {
                        "id": "CVE-TEST-0001",
                        "package": "CURL",
                        "severity": "high",
                        "summary": "Non-canonical package.",
                    }
                ]
            ),
            "invalid-advisory-package",
        ),
    ],
)
def test_vuln_scan_structurally_invalid_database_blocks(
    tmp_path,
    payload,
    expected_error,
) -> None:
    path = _write_vuln_database(tmp_path / "invalid.json", payload=payload)

    report = _custom_vuln_scan(path).scan(["fixture-package"])

    assert [finding.cve for finding in report.findings] == ["DB-INVALID"]
    assert report.database_status == "invalid"
    assert report.database_error == expected_error
    assert report.verdict == "blocked"
    assert report.ok is False


@pytest.mark.parametrize(
    ("scope", "expected_error"),
    [
        ("root", "unexpected-root-fields"),
        ("meta", "unexpected-meta-fields"),
        ("advisory", "unexpected-advisory-fields"),
    ],
)
def test_vuln_scan_unexpected_keys_cannot_forge_diagnostics(
    tmp_path,
    scope,
    expected_error,
) -> None:
    payload = _vuln_database()
    if scope == "root":
        target = payload
    elif scope == "meta":
        target = payload["meta"]
    else:
        advisories = payload["advisories"]
        assert isinstance(advisories, list)
        target = advisories[0]
    assert isinstance(target, dict)
    target["forged\n[ready]\u202e"] = "ignored"
    path = _write_vuln_database(tmp_path / "unexpected-key.json", payload=payload)

    report = _custom_vuln_scan(path).scan(["fixture-package"])

    assert report.database_error == expected_error
    assert report.verdict == "blocked"
    assert "\n" not in report.findings[0].message
    assert "[ready]" not in report.findings[0].message
    assert "\u202e" not in report.findings[0].message


def test_vuln_scan_duplicate_key_cannot_forge_diagnostics(tmp_path) -> None:
    path = tmp_path / "duplicate-key.json"
    path.write_text(
        '{"forged\\n[ready]":1,"forged\\n[ready]":2}',
        encoding="utf-8",
    )

    report = _custom_vuln_scan(path).scan(["fixture-package"])

    assert report.database_error == "json"
    assert report.verdict == "blocked"
    assert "duplicate JSON key" in report.findings[0].message
    assert "\n" not in report.findings[0].message
    assert "[ready]" not in report.findings[0].message


@pytest.mark.parametrize(
    ("raw", "expected_error"),
    [
        (b"\xff", "encoding"),
        (b'{"meta":', "json"),
        (
            b'{"meta":{"schema":"distroforge-vulndb/1","source":"x","updated":"x"},'
            b'"advisories":[],"advisories":[]}',
            "json",
        ),
        (
            b'{"meta":{"schema":"distroforge-vulndb/1","source":"x","updated":"x"},'
            b'"advisories":[NaN]}',
            "json",
        ),
        (b"[]", "json"),
    ],
)
def test_vuln_scan_invalid_json_never_becomes_clean(
    tmp_path,
    raw,
    expected_error,
) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(raw)

    report = _custom_vuln_scan(path).scan(["fixture-package"])

    assert [finding.cve for finding in report.findings] == ["DB-UNAVAILABLE"]
    assert report.database_status == "invalid"
    assert report.database_error == expected_error
    assert report.verdict == "blocked"
    assert report.ok is False


@pytest.mark.parametrize(
    ("scope", "field", "value", "expected_error"),
    [
        ("meta", "source", "trusted\n[ready] forged", "invalid-meta-source"),
        ("meta", "source", "trusted\r[ready] forged", "invalid-meta-source"),
        ("meta", "updated", "2026\t07", "invalid-meta-updated"),
        ("meta", "description", "safe\u202eevil", "invalid-meta-description"),
        ("meta", "source", "e\u0301", "invalid-meta-source"),
        ("advisory", "id", "CVE-TEST-0001\x00forged", "invalid-advisory-id"),
        ("advisory", "summary", "safe\u2028forged", "invalid-advisory-summary"),
        ("advisory", "fixed_version", " 2", "invalid-advisory-fixed-version"),
        ("advisory", "severity", "HIGH", "invalid-advisory-severity"),
    ],
)
def test_vuln_scan_rejects_noncanonical_database_text(
    tmp_path,
    scope,
    field,
    value,
    expected_error,
) -> None:
    payload = _vuln_database()
    if scope == "meta":
        target = payload["meta"]
    else:
        advisories = payload["advisories"]
        assert isinstance(advisories, list)
        target = advisories[0]
    assert isinstance(target, dict)
    target[field] = value
    path = _write_vuln_database(tmp_path / "invalid-text.json", payload=payload)

    report = _custom_vuln_scan(path).scan(["fixture-package"])

    assert report.database_error == expected_error
    assert [finding.cve for finding in report.findings] == ["DB-INVALID"]
    assert report.verdict == "blocked"


def test_vuln_scan_database_text_byte_limit_is_exact(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(vulnscan_module, "MAX_VULN_ADVISORY_SUMMARY_BYTES", 8)
    service = _custom_vuln_scan(tmp_path / "database.json")

    for size in (7, 8):
        _write_vuln_database(
            tmp_path / "database.json",
            payload=_vuln_database(
                advisories=[_vuln_advisory(summary="s" * size)]
            ),
        )
        assert service.scan(["different-package"]).verdict == "clean"

    _write_vuln_database(
        tmp_path / "database.json",
        payload=_vuln_database(advisories=[_vuln_advisory(summary="s" * 9)]),
    )
    above = service.scan(["different-package"])
    assert above.database_error == "invalid-advisory-summary"
    assert above.verdict == "blocked"


def test_vuln_scan_valid_database_without_a_package_match_is_clean(tmp_path) -> None:
    path = _write_vuln_database(tmp_path / "valid.json")

    report = _custom_vuln_scan(path).scan(["different-package"])

    assert report.database_status == "valid"
    assert report.advisory_count == 1
    assert report.database_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert report.database_schema == vulnscan_module.VULN_DB_SCHEMA
    assert report.database_source == "test-fixture"
    assert report.database_updated == "2026-07-31"
    assert report.findings == []
    assert report.verdict == "clean"
    assert report.ok is True


def test_vuln_scan_oversized_database_blocks_before_buffering(
    tmp_path,
    monkeypatch,
) -> None:
    path = _write_vuln_database(tmp_path / "large.json")
    monkeypatch.setattr(vulnscan_module, "MAX_VULN_DB_BYTES", 64)

    report = _custom_vuln_scan(path).scan(["fixture-package"])

    assert report.database_error == "bounds"
    assert report.verdict == "blocked"


def test_vuln_scan_excessive_json_depth_is_bounded(tmp_path) -> None:
    nested: object = "bottom"
    for _ in range(80):
        nested = [nested]
    payload = _vuln_database()
    assert isinstance(payload["meta"], dict)
    payload["meta"]["description"] = nested
    path = _write_vuln_database(tmp_path / "deep.json", payload=payload)

    report = _custom_vuln_scan(path).scan(["fixture-package"])

    assert report.database_error == "json"
    assert report.verdict == "blocked"


def test_vuln_scan_symlink_and_fifo_inputs_block_without_following_or_waiting(tmp_path) -> None:
    target = _write_vuln_database(tmp_path / "target.json")
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(target)
    fifo = tmp_path / "database.fifo"
    os.mkfifo(fifo)

    symlink_report = _custom_vuln_scan(symlink).scan(["fixture-package"])
    fifo_report = _custom_vuln_scan(fifo).scan(["fixture-package"])

    assert symlink_report.verdict == "blocked"
    assert symlink_report.database_error == "unsafe-path"
    assert fifo_report.verdict == "blocked"
    assert fifo_report.database_error == "non-regular"


def test_vuln_scan_symlinked_ancestor_is_an_unsafe_path(tmp_path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    _write_vuln_database(real / "database.json")
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    report = _custom_vuln_scan(linked / "database.json").scan(["fixture-package"])

    assert report.database_error == "unsafe-path"
    assert report.verdict == "blocked"


def test_vuln_scan_directory_and_device_inputs_are_not_databases(tmp_path) -> None:
    directory_report = _custom_vuln_scan(tmp_path).scan(["fixture-package"])
    device_report = _custom_vuln_scan(Path("/dev/null")).scan(["fixture-package"])

    assert directory_report.verdict == "blocked"
    assert directory_report.database_error == "non-regular"
    assert device_report.verdict == "blocked"
    assert device_report.database_error == "non-regular"


def test_vuln_scan_permission_error_is_a_controlled_block(
    tmp_path,
    monkeypatch,
) -> None:
    path = _write_vuln_database(tmp_path / "denied.json")

    def denied_open(*args, **kwargs):
        raise PermissionError(errno.EACCES, "permission denied", path.name)

    monkeypatch.setattr(
        vulnscan_module.ArtifactVerificationSession,
        "_open_relative",
        denied_open,
    )

    report = _custom_vuln_scan(path).scan(["fixture-package"])

    assert report.verdict == "blocked"
    assert report.database_error == "permission"
    assert "Traceback" not in report.findings[0].message


def test_vuln_scan_mutation_during_session_closure_blocks(
    tmp_path,
    monkeypatch,
) -> None:
    path = _write_vuln_database(tmp_path / "mutable.json")
    original_seal = vulnscan_module.ArtifactVerificationSession.seal
    changed = False

    def mutate_then_seal(session):
        nonlocal changed
        if not changed:
            before = path.stat()
            body = path.read_bytes()
            path.write_bytes(body.replace(b"fixture-package", b"mutated-package"))
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            changed = True
        return original_seal(session)

    monkeypatch.setattr(
        vulnscan_module.ArtifactVerificationSession,
        "seal",
        mutate_then_seal,
    )

    report = _custom_vuln_scan(path).scan(["fixture-package"])

    assert changed
    assert report.verdict == "blocked"
    assert report.database_error == "unstable"


def test_vuln_scan_internal_parser_error_is_a_controlled_block(
    tmp_path,
    monkeypatch,
) -> None:
    path = _write_vuln_database(tmp_path / "parser.json")

    def broken_loads(*args, **kwargs):
        raise RuntimeError("injected parser failure")

    monkeypatch.setattr(artifact_verification_module.json, "loads", broken_loads)

    report = _custom_vuln_scan(path).scan(["fixture-package"])

    assert report.verdict == "blocked"
    assert report.database_error == "internal"
    assert "RuntimeError" in report.findings[0].message


def test_vuln_scan_resource_lookup_error_is_a_controlled_block(monkeypatch) -> None:
    def broken_files(*args, **kwargs):
        raise RuntimeError("injected resource failure")

    monkeypatch.setattr(vulnscan_module, "files", broken_files)

    report = VulnScanService(
        VulnScanOptions(enabled=True, policy="block-high")
    ).scan(["fixture-package"])

    assert report.verdict == "blocked"
    assert report.database_error == "internal"
    assert [finding.cve for finding in report.findings] == ["DB-UNAVAILABLE"]


def test_vuln_scan_path_resolution_error_is_a_controlled_block(monkeypatch) -> None:
    original_absolute = Path.absolute

    def broken_absolute(path):
        if path.name == "relative-vulndb.json":
            raise OSError("injected path resolution failure")
        return original_absolute(path)

    monkeypatch.setattr(Path, "absolute", broken_absolute)

    report = _custom_vuln_scan(Path("relative-vulndb.json")).scan(
        ["fixture-package"]
    )

    assert report.verdict == "blocked"
    assert report.database_error == "io"
    assert [finding.cve for finding in report.findings] == ["DB-UNAVAILABLE"]


def test_vuln_enforce_blocks_an_unusable_database_and_records_it(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)
    service = _custom_vuln_scan(tmp_path / "missing.json")

    with pytest.raises(ValueError, match="DB-UNAVAILABLE"):
        service.enforce(["fixture-package"], runner)

    assert ("vuln-report", "blocked", "1") in [spec.argv for spec in runner.history]
    assert "database_error=missing" in runner.history[-1].description


def test_vuln_enforce_records_degraded_for_nonblocking_database_error(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)
    service = _custom_vuln_scan(tmp_path / "missing.json", policy="warn")

    report = service.enforce(["fixture-package"], runner)

    assert report.verdict == "degraded"
    assert ("vuln-report", "degraded", "1") in [spec.argv for spec in runner.history]
    assert "database_error=missing" in runner.history[-1].description


def test_build_readiness_and_dry_run_block_an_unusable_database(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "CveConsumers")
    options = BuildOptions(
        use_sudo=False,
        package_plan=PackagePlan(install=["fixture-package"]),
        vuln_scan=VulnScanOptions(
            enabled=True,
            policy="block-high",
            db_path=tmp_path / "missing.json",
        ),
    )
    runner = CommandRunner(dry_run=True)

    with pytest.raises(ValueError, match="DB-UNAVAILABLE"):
        BuildOrchestrator(project, runner, options).run()
    readiness = ReadinessService().check(project, options, include_dry_run=False)
    dry_run = generate_dry_run_report(project, options, run_orchestrator=False)

    assert ("vuln-report", "blocked", "1") in [spec.argv for spec in runner.history]
    assert any(
        check.level == "error" and check.code == "vuln-db-unavailable"
        for check in readiness.checks
    )
    assert any(
        finding.level == "error" and finding.code == "vuln-db-unavailable"
        for finding in dry_run.findings
    )


def test_vuln_degraded_forces_readiness_review_even_with_a_high_score(
    tmp_path,
    monkeypatch,
) -> None:
    project = _bootstrap_project(tmp_path, "CveReadinessReview")
    options = BuildOptions(
        use_sudo=False,
        package_plan=PackagePlan(install=["fixture-package"]),
        vuln_scan=VulnScanOptions(
            enabled=True,
            policy="warn",
            db_path=tmp_path / "missing.json",
        ),
    )
    real_scan = vulnscan_module.VulnScanService.scan
    scan_calls = 0

    def counted_scan(service, packages):
        nonlocal scan_calls
        scan_calls += 1
        return real_scan(service, packages)

    monkeypatch.setattr(readiness_module, "_score", lambda *args: 100)
    monkeypatch.setattr(readiness_module, "_has_blockers", lambda *args: False)
    monkeypatch.setattr(
        vulnscan_module.VulnScanService,
        "scan",
        counted_scan,
    )

    report = ReadinessService().check(project, options)

    assert any(check.code == "vuln-db-unavailable" for check in report.checks)
    assert report.dry_run is not None
    assert any(
        finding.code == "vuln-db-unavailable"
        for finding in report.dry_run.findings
    )
    assert scan_calls == 1
    assert report.score == 100
    assert report.status == "review"


def test_release_gate_item_blocks_database_failure_under_blocking_policy(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "CveReleaseGate")
    options = BuildOptions(
        use_sudo=False,
        package_plan=PackagePlan(install=["fixture-package"]),
        vuln_scan=VulnScanOptions(
            enabled=True,
            policy="block-high",
            db_path=tmp_path / "missing.json",
        ),
    )
    report = release_gate_module.ReleaseGateReport(
        project.root,
        tmp_path / "product.iso",
        tmp_path,
    )

    release_gate_module._check_vuln_policy(report, project, options)

    assert report.items[-1].code == "vuln-scan"
    assert report.items[-1].status == "blocked"
    assert "database_status=invalid" in report.items[-1].detail
    assert "database_error=missing" in report.items[-1].detail

    options.vuln_scan.policy = "warn"
    warning_report = release_gate_module.ReleaseGateReport(
        project.root,
        tmp_path / "product.iso",
        tmp_path,
    )
    release_gate_module._check_vuln_policy(warning_report, project, options)

    assert warning_report.items[-1].status == "review"
    assert "CVE scan degraded" in warning_report.items[-1].detail
    assert "database_error=missing" in warning_report.items[-1].detail
    assert warning_report.status == "review"


def test_release_gate_valid_cve_item_binds_database_snapshot(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "CveReleaseGateDigest")
    database = _write_vuln_database(tmp_path / "database.json")
    digest = hashlib.sha256(database.read_bytes()).hexdigest()
    options = BuildOptions(
        use_sudo=False,
        package_plan=PackagePlan(install=["different-package"]),
        vuln_scan=VulnScanOptions(
            enabled=True,
            policy="block-high",
            db_path=database,
        ),
    )
    report = release_gate_module.ReleaseGateReport(
        project.root,
        tmp_path / "product.iso",
        tmp_path,
    )

    release_gate_module._check_vuln_policy(report, project, options)

    item = report.items[-1]
    assert item.status == "ready"
    assert "database_status=valid" in item.detail
    assert "database_error=none" in item.detail
    assert f"db_sha256={digest}" in item.detail
    assert f"schema={vulnscan_module.VULN_DB_SCHEMA}" in item.detail
    assert "source=test-fixture" in item.detail
    assert "updated=2026-07-31" in item.detail
    assert "advisories=1" in item.detail
    assert "scanned=1" in item.detail


def test_vuln_degraded_gate_cannot_mark_publish_journey_ready(
    tmp_path,
    monkeypatch,
) -> None:
    project = _bootstrap_project(tmp_path, "CveJourneyReview")
    options = BuildOptions(
        use_sudo=False,
        package_plan=PackagePlan(install=["fixture-package"]),
        vuln_scan=VulnScanOptions(
            enabled=True,
            policy="warn",
            db_path=tmp_path / "missing.json",
        ),
    )
    gate = release_gate_module.ReleaseGateReport(
        project.root,
        tmp_path / "product.iso",
        tmp_path,
    )
    release_gate_module._check_vuln_policy(gate, project, options)

    def reviewed_gate(*args, **kwargs):
        return gate

    monkeypatch.setattr(
        release_gate_module.ReleaseGateService,
        "check",
        reviewed_gate,
    )

    assert gate.status == "review"
    assert build_journey_module._publish_gate_ready(project, options) is False
    assert (
        release_pipeline_module._release_signing_authorized(
            gate,
            bundle_status="review",
        )
        is False
    )
    assert (
        release_pipeline_module._release_signing_authorized(
            gate,
            bundle_status="ready",
        )
        is False
    )


def test_vuln_release_signing_authorization_allows_only_its_sole_bootstrap_review(
    tmp_path,
) -> None:
    gate = release_gate_module.ReleaseGateReport(
        tmp_path,
        tmp_path / "product.iso",
        tmp_path,
        items=[
            release_gate_module.ReleaseGateItem(
                "publish-signing",
                "review",
                "Signatures are created by the next stage.",
            )
        ],
    )

    assert release_pipeline_module._release_signing_authorized(
        gate,
        bundle_status="review",
    )


def test_vuln_degraded_gate_keeps_iso_acceptance_in_review(
    tmp_path,
    monkeypatch,
) -> None:
    project = _bootstrap_project(tmp_path, "CveIsoReview")
    iso = tmp_path / "product.iso"
    options = BuildOptions(
        use_sudo=False,
        package_plan=PackagePlan(install=["fixture-package"]),
        vuln_scan=VulnScanOptions(
            enabled=True,
            policy="warn",
            db_path=tmp_path / "missing.json",
        ),
    )
    gate = release_gate_module.ReleaseGateReport(project.root, iso, tmp_path)
    release_gate_module._check_vuln_policy(gate, project, options)

    class SelectedRun:
        run_id = "20260731T120000Z-cve-review"
        iso_build_path = tmp_path / "ISO-BUILD.json"

    def reviewed_gate(*args, **kwargs):
        return gate

    def ready_iso_contract(items, *args):
        items.append(
            iso_acceptance_module.IsoAcceptanceItem(
                "iso",
                "ready",
                "fixture ISO contract",
            )
        )

    monkeypatch.setattr(
        iso_acceptance_module,
        "select_executed_release_run",
        lambda *args, **kwargs: SelectedRun(),
    )
    monkeypatch.setattr(
        iso_acceptance_module,
        "_check_iso_contract",
        ready_iso_contract,
    )
    monkeypatch.setattr(
        iso_acceptance_module.ReleaseGateService,
        "check",
        reviewed_gate,
    )

    acceptance = iso_acceptance_module.accept_iso(
        project,
        options,
        iso=iso,
        output_dir=tmp_path,
    )

    assert acceptance.status == "review"
    assert any(
        item.code == "gate-vuln-scan" and item.status == "review"
        for item in acceptance.items
    )
    assert acceptance.next_command.startswith("distroforge release-gate ")


def test_vuln_enforce_records_command_and_raises_on_error() -> None:
    runner = CommandRunner(dry_run=True)
    service = VulnScanService(VulnScanOptions(enabled=True, policy="block-critical"))

    with pytest.raises(ValueError, match="CVE policy"):
        service.enforce(["xz-utils"], runner)

    assert ("vuln-report", "blocked", "1") in [spec.argv for spec in runner.history]


def test_vuln_enforce_passes_clean_package_set() -> None:
    runner = CommandRunner(dry_run=True)
    service = VulnScanService(VulnScanOptions(enabled=True, policy="block-high"))

    report = service.enforce(["vim", "htop"], runner)

    assert report.ok is True
    assert ("vuln-report", "ok", "0") in [spec.argv for spec in runner.history]


def test_build_blocks_on_cve_policy_in_dry_run(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "CveGate")
    options = BuildOptions(
        use_sudo=False,
        package_plan=PackagePlan(install=["curl"]),
        vuln_scan=VulnScanOptions(enabled=True, policy="block-high"),
    )
    runner = CommandRunner(dry_run=True)

    with pytest.raises(ValueError, match="CVE policy"):
        BuildOrchestrator(project, runner, options).run()

    assert ("vuln-report", "blocked", "1") in [spec.argv for spec in runner.history]


def test_build_warn_policy_records_report_without_blocking(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "CveWarn")
    options = BuildOptions(
        use_sudo=False,
        package_plan=PackagePlan(install=["curl"]),
        vuln_scan=VulnScanOptions(enabled=True, policy="warn"),
    )
    runner = CommandRunner(dry_run=True)

    report = BuildOrchestrator(project, runner, options).run()

    assert ("vuln-report", "ok", "1") in [spec.argv for spec in runner.history]
    assert BuildPhase.VULN_SCAN in {step.phase for step in report.steps}


# --------------------------------------------------------------------------- #
# #2 Standard SBOM export (SPDX / CycloneDX)
# --------------------------------------------------------------------------- #


def test_spdx_document_lists_packages_with_purls(tmp_path) -> None:
    project = Project.create("SpdxDoc", tmp_path / "spdx-doc", "26.04")
    service = ProvenanceService(CommandRunner(dry_run=True), project, ProvenanceOptions())

    doc = service.spdx_document(["curl", "vim"])

    assert doc["spdxVersion"] == "SPDX-2.3"
    names = {pkg["name"] for pkg in doc["packages"]}
    assert names == {"curl", "vim"}
    curl = next(pkg for pkg in doc["packages"] if pkg["name"] == "curl")
    assert curl["versionInfo"] == "NOASSERTION"
    assert curl["externalRefs"][0]["referenceLocator"].endswith("/curl")
    assert all(rel["relationshipType"] == "DESCRIBES" for rel in doc["relationships"])


def test_cyclonedx_document_has_os_root_and_library_components(tmp_path) -> None:
    project = Project.create("CdxDoc", tmp_path / "cdx-doc", "26.04")
    service = ProvenanceService(CommandRunner(dry_run=True), project, ProvenanceOptions())

    doc = service.cyclonedx_document(["curl"])

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["metadata"]["component"]["type"] == "operating-system"
    assert doc["components"][0]["purl"].endswith("/curl")


def test_provenance_dry_run_plans_spdx_target(tmp_path) -> None:
    project = Project.create("SpdxPlan", tmp_path / "spdx-plan", "26.04")
    runner = CommandRunner(dry_run=True)
    options = ProvenanceOptions(enabled=True, sbom_format="spdx")

    ProvenanceService(runner, project, options).write(project.output_dir / "x.iso", ["curl"])

    written = [spec.argv[1] for spec in runner.history if spec.argv[0] == "write-file"]
    assert str(project.output_dir / SPDX_FILENAME) in written
    assert str(project.output_dir / "distroforge-provenance.json") in written


def test_provenance_dry_run_plans_cyclonedx_target(tmp_path) -> None:
    project = Project.create("CdxPlan", tmp_path / "cdx-plan", "26.04")
    runner = CommandRunner(dry_run=True)
    options = ProvenanceOptions(enabled=True, sbom_format="cyclonedx")

    ProvenanceService(runner, project, options).write(project.output_dir / "x.iso", ["curl"])

    written = [spec.argv[1] for spec in runner.history if spec.argv[0] == "write-file"]
    assert str(project.output_dir / CYCLONEDX_FILENAME) in written


def test_provenance_native_format_writes_only_provenance(tmp_path) -> None:
    project = Project.create("NativePlan", tmp_path / "native-plan", "26.04")
    runner = CommandRunner(dry_run=True)
    options = ProvenanceOptions(enabled=True, sbom_format="native")

    ProvenanceService(runner, project, options).write(project.output_dir / "x.iso", ["curl"])

    written = [spec.argv[1] for spec in runner.history if spec.argv[0] == "write-file"]
    assert written == [str(project.output_dir / "distroforge-provenance.json")]


def test_provenance_writes_valid_spdx_to_disk(tmp_path) -> None:
    project = Project.create("SpdxDisk", tmp_path / "spdx-disk", "26.04")
    options = ProvenanceOptions(enabled=True, sbom_format="spdx")

    ProvenanceService(CommandRunner(dry_run=False), project, options).write(
        project.output_dir / "x.iso", ["curl", "vim"]
    )

    doc = json.loads((project.output_dir / SPDX_FILENAME).read_text(encoding="utf-8"))
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert {pkg["name"] for pkg in doc["packages"]} == {"curl", "vim"}


# --------------------------------------------------------------------------- #
# #3 True cross-arch bootstrap (arm64 on amd64)
# --------------------------------------------------------------------------- #


def test_host_dpkg_arch_maps_machine_names(monkeypatch) -> None:
    monkeypatch.setattr(bootstrap_module.platform, "machine", lambda: "x86_64")
    assert host_dpkg_arch() == "amd64"
    monkeypatch.setattr(bootstrap_module.platform, "machine", lambda: "aarch64")
    assert host_dpkg_arch() == "arm64"


def _bootstrap_service(tmp_path, arch: str) -> BootstrapService:
    return BootstrapService(
        CommandRunner(dry_run=True),
        get_release("26.04"),
        tmp_path / "root",
        tmp_path / "iso",
        BootstrapOptions(arch=arch),
        use_sudo=False,
    )


def test_bootstrap_grub_packages_are_arch_aware(tmp_path) -> None:
    amd64 = _bootstrap_service(tmp_path, "amd64")._base_packages()
    arm64 = _bootstrap_service(tmp_path, "arm64")._base_packages()

    assert "grub-pc-bin" in amd64
    assert "grub-efi-amd64-bin" in amd64
    assert "grub-pc-bin" not in arm64
    assert "grub-efi-arm64-bin" in arm64
    # The signed pair the ESP is staged from. Named explicitly rather than inherited
    # through shim-signed's "grub-efi-amd64-signed | grub-efi-arm64-signed" alternation,
    # which apt could satisfy with the wrong arch's package on a cross build.
    assert "grub-efi-amd64-signed" in amd64
    assert "grub-efi-arm64-signed" in arm64
    # The EFI package name follows GRUB's platform, not the dpkg architecture: there has
    # never been a grub-efi-i386-bin, so this build used to die at apt-get install.
    i386 = _bootstrap_service(tmp_path, "i386")._base_packages()
    assert "grub-efi-ia32-bin" in i386
    assert not any(name.startswith("grub-efi-i386") for name in i386)


def test_bootstrap_kernel_meta_package_is_arch_independent_on_ubuntu(tmp_path) -> None:
    arm64 = _bootstrap_service(tmp_path, "arm64")._base_packages()
    assert "linux-generic" in arm64


def test_cross_arch_build_requires_qemu_and_skips_bios(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(bootstrap_module, "host_dpkg_arch", lambda: "amd64")
    project = _bootstrap_project(tmp_path, "ArmRemix")
    options = BuildOptions(use_sudo=False, bootstrap=BootstrapOptions(arch="arm64"))
    runner = CommandRunner(dry_run=True)

    BuildOrchestrator(project, runner, options).run()

    commands = [spec.argv for spec in runner.history]
    assert ("qemu-user-static-required", "arm64", "amd64") in commands
    assert ("bootstrap-bios-skip", "arm64") in commands
    # Skipping BIOS is correct on arm64; producing nothing in its place was not. The
    # bios-skip marker's own description says the arch "boots EFI-only", and for as long
    # as this assertion was missing that claim was false: the build shipped an ISO with
    # no boot record at all, and exited 0.
    assert ("write-file", str(project.iso_root / "boot" / "grub" / "efi.img")) in commands
    assert not any(argv[0] == "bootstrap-efi-skip" for argv in commands)


def test_esp_sizing_rounds_to_a_track_and_refuses_what_el_torito_cannot_address(tmp_path) -> None:
    small = tmp_path / "shim.efi"
    small.write_bytes(b"\x00" * 4096)

    blocks = bootstrap_module._esp_blocks([small])

    # A whole number of 32-sector tracks, because that is the geometry mformat is given.
    assert blocks % 32 == 0
    assert blocks * 512 >= 4096
    huge = tmp_path / "huge.efi"
    huge.write_bytes(b"\x00" * (33 * 1024 * 1024))
    # An El Torito boot image is addressed in 512-byte blocks by a 16-bit field. Raising
    # is the point: an oversized image would be silently clipped and would not boot.
    with pytest.raises(ValueError, match="may not exceed 65535"):
        bootstrap_module._esp_blocks([huge])


def test_bootstrap_refuses_a_rootfs_with_no_uefi_grub(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "NoGrub")
    boot = project.squashfs_root / "boot"
    boot.mkdir(parents=True)
    (boot / "vmlinuz-6.17.0-1-generic").write_bytes(b"\x00")
    (boot / "initrd.img-6.17.0-1-generic").write_bytes(b"\x00")
    service = BootstrapService(
        _RecordingExecuteRunner(),
        get_release("26.04"),
        project.squashfs_root,
        project.iso_root,
        BootstrapOptions(arch="amd64"),
        use_sudo=False,
    )

    # Silently skipping the amorce is what shipped an unbootable ISO, so an absent
    # payload has to stop the build rather than be worked around.
    with pytest.raises(ValueError, match="No UEFI GRUB image in the target rootfs"):
        service.create_iso_tree()


def test_native_amd64_build_does_not_require_qemu(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(bootstrap_module, "host_dpkg_arch", lambda: "amd64")
    project = _bootstrap_project(tmp_path, "Amd64Remix")
    options = BuildOptions(use_sudo=False, bootstrap=BootstrapOptions(arch="amd64"))
    runner = CommandRunner(dry_run=True)

    BuildOrchestrator(project, runner, options).run()

    commands = [spec.argv for spec in runner.history]
    assert not any(argv[0] == "qemu-user-static-required" for argv in commands)
    assert not any(argv == ("bootstrap-bios-skip", "amd64") for argv in commands)
    # amd64 is a BIOS arch, so the El Torito image is planned rather than skipped.
    assert any(
        argv[0] == "write-file" and argv[1].endswith("i386-pc/eltorito.img") for argv in commands
    )


# The two defects below were found by actually running the chain, not by reading it.
# A real from-scratch build reached apt inside the chroot and could not fetch a single
# index, then reported "Unable to locate package sudo" three phases later.


def test_bootstrap_installs_a_ca_store_so_the_chroot_can_speak_https(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "CaStore")
    runner = CommandRunner(dry_run=True)
    options = BuildOptions(use_sudo=False, bootstrap=BootstrapOptions(arch="amd64"))

    BuildOrchestrator(project, runner, options).run()

    bootstrap = next(
        spec.argv for spec in runner.history if spec.argv and spec.argv[0] in {"mmdebstrap", "debootstrap"}
    )
    # Measured failure without it: every index Err'd with "SSL routines::certificate
    # verify failed", because a minbase rootfs has no CA store and every archive URL
    # here is https -- while ca-certificates sat in the package list that update was
    # fetching for.
    #
    # Asserted as a member of the include list rather than as the whole option, because
    # this test owns the CA store and not the list: apt joined it later, for its own
    # reason, and spelling the option out here made an unrelated fix look like a
    # regression in TLS. tests/test_bootstrap_requires_a_package_manager.py owns the rest.
    includes = [arg for arg in bootstrap if arg.startswith("--include=")]
    assert len(includes) == 1, includes
    assert "ca-certificates" in includes[0].removeprefix("--include=").split(",")
    assert bootstrap[-1].startswith("https://")


def test_no_apt_update_in_the_chroot_can_fail_silently(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "LoudUpdate")
    runner = CommandRunner(dry_run=True)
    options = BuildOptions(
        use_sudo=False,
        bootstrap=BootstrapOptions(arch="amd64"),
        package_plan=PackagePlan(install=["cowsay"]),
    )

    BuildOrchestrator(project, runner, options).run()

    updates = [
        spec.argv
        for spec in runner.history
        if "apt-get" in spec.argv and spec.argv[-1] == "update"
    ]
    assert updates, "the plan runs no apt-get update at all, so this guard proves nothing"
    for argv in updates:
        # apt-get update returns 0 having downloaded nothing: it demotes every failed
        # index to a warning. Verified against apt 3.2.0 -- rc 0 without this option,
        # rc 100 with it -- so a build that cannot reach its archive must stop here
        # rather than at a misleading "Unable to locate package" minutes later.
        assert "APT::Update::Error-Mode=any" in argv, argv


def test_the_chosen_compressor_reaches_the_pack_and_not_only_the_progress_line(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "Compressor")
    runner = CommandRunner(dry_run=True)
    options = BuildOptions(
        use_sudo=False,
        bootstrap=BootstrapOptions(arch="amd64"),
        squashfs=SquashfsOptions(compression="zstd"),
    )

    BuildOrchestrator(project, runner, options).run()

    packs = [spec.argv for spec in runner.history if spec.argv[0] == "mksquashfs"]
    assert len(packs) == 1, packs
    # The release default is xz. An override that reached the phase description but not
    # the command would look right in the log and ship the wrong image.
    assert packs[0][packs[0].index("-comp") + 1] == "zstd"


def test_the_grub_trampoline_lands_on_the_signed_prefix(tmp_path) -> None:
    project = _bootstrap_project(tmp_path, "Prefix")
    runner = CommandRunner(dry_run=True)
    options = BuildOptions(use_sudo=False, bootstrap=BootstrapOptions(arch="amd64"))

    BuildOrchestrator(project, runner, options).run()

    written = [spec.argv[1] for spec in runner.history if spec.argv[0] == "write-file"]
    # A signed GRUB's prefix is compiled in and cannot be re-set; Ubuntu's is
    # /EFI/ubuntu, and the binary carries no embedded config, only "%s/grub.cfg".
    # Measured on a real OVMF boot: with the trampoline in EFI/boot alone, shim
    # loaded and GRUB started, then sat at a rescue "grub>" prompt.
    assert str(project.iso_root / "EFI/ubuntu/grub.cfg") in written
    assert str(project.iso_root / "EFI/boot/grub.cfg") in written


def test_the_esp_carries_the_trampoline_at_both_prefixes(tmp_path) -> None:
    boot = tmp_path / "root" / "boot"
    boot.mkdir(parents=True)
    (boot / "vmlinuz-7.0.0-14-generic").write_bytes(b"\x00")
    (boot / "initrd.img-7.0.0-14-generic").write_bytes(b"\x00")
    shim = tmp_path / "root/usr/lib/shim"
    shim.mkdir(parents=True)
    (shim / "shimx64.efi.signed.latest").write_bytes(b"\x00")
    grub = tmp_path / "root/usr/lib/grub/x86_64-efi-signed"
    grub.mkdir(parents=True)
    (grub / "grubx64.efi.signed").write_bytes(b"\x00")
    runner = _RecordingExecuteRunner()
    service = BootstrapService(
        runner,
        get_release("26.04"),
        tmp_path / "root",
        tmp_path / "iso",
        BootstrapOptions(arch="amd64"),
        use_sudo=False,
    )

    service.create_iso_tree()

    trampolines = [
        spec.argv[-1] for spec in runner.history if spec.argv[0] == "mcopy" and spec.argv[-2] == "-"
    ]
    assert trampolines == ["::/EFI/ubuntu/grub.cfg", "::/EFI/BOOT/grub.cfg"]
    # The vendor directory has to be created, or every mcopy above fails.
    assert any(
        spec.argv[0] == "mmd" and "::/EFI/ubuntu" in spec.argv for spec in runner.history
    )
