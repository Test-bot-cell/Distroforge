from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandRunner
from distroforge.core.preflight import validate_build_options
from distroforge.core.project import Project

FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"


def _policy(keyring_sha256: str) -> dict[str, object]:
    return {
        "policy_id": "fixture-release",
        "base_uri": "https://repo.invalid/archive",
        "suites": ["proof"],
        "codenames": ["proof"],
        "components": ["main"],
        "architectures": ["amd64"],
        "signer_fingerprints": [FINGERPRINT],
        "keyring_sha256": [keyring_sha256],
        "max_release_age_seconds": 86400,
        "max_future_skew_seconds": 300,
        "require_valid_until": True,
    }


def _bootstrap_options(keyring: Path) -> BuildOptions:
    options = BuildOptions(use_sudo=False)
    digest = hashlib.sha256(keyring.read_bytes()).hexdigest()
    options.bootstrap.archive_keyring = keyring
    options.bootstrap.archive_keyring_sha256 = digest
    options.bootstrap.archive_signer_fingerprints = [FINGERPRINT]
    options.bootstrap.source_policies = [_policy(digest)]
    return options


def test_executing_sealed_build_requires_external_per_source_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("PolicyMissing", tmp_path / "project", "26.04")
    project.source_mode = "bootstrap"
    keyring = tmp_path / "archive.gpg"
    keyring.write_bytes(b"fixture archive keyring")
    options = _bootstrap_options(keyring)
    options.bootstrap.source_policies = []
    runner = CommandRunner(dry_run=True)
    monkeypatch.setattr(runner, "has_binary", lambda _name: True)

    issues = validate_build_options(project, options, runner, execute=True)

    assert "package-source-policy" in {issue.code for issue in issues}


def test_complete_per_source_policy_closes_preflight_trust_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("PolicyReady", tmp_path / "project", "26.04")
    project.source_mode = "bootstrap"
    keyring = tmp_path / "archive.gpg"
    keyring.write_bytes(b"fixture archive keyring")
    options = _bootstrap_options(keyring)
    runner = CommandRunner(dry_run=True)
    monkeypatch.setattr(runner, "has_binary", lambda _name: True)

    issues = validate_build_options(project, options, runner, execute=True)
    codes = {issue.code for issue in issues}

    assert not {
        "archive-signer-pin",
        "archive-keyring-pin",
        "archive-keyring-file",
        "package-source-policy",
        "package-source-policy-signers",
        "package-source-policy-keyring",
        "package-index-lz4",
    } & codes


def test_per_source_signer_ownership_must_equal_global_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project.create("PolicySigner", tmp_path / "project", "26.04")
    project.source_mode = "bootstrap"
    keyring = tmp_path / "archive.gpg"
    keyring.write_bytes(b"fixture archive keyring")
    options = _bootstrap_options(keyring)
    options.bootstrap.source_policies[0]["signer_fingerprints"] = [
        "0123456789ABCDEF0123456789ABCDEF01234567"
    ]
    runner = CommandRunner(dry_run=True)
    monkeypatch.setattr(runner, "has_binary", lambda _name: True)

    issues = validate_build_options(project, options, runner, execute=True)

    assert "package-source-policy-signers" in {issue.code for issue in issues}
