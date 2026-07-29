from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from distroforge.core.build import BuildOptions
from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.preflight import validate_build_options
from distroforge.core.project import Project
from distroforge.core.release_gate import (
    ReleaseGateItem,
    ReleaseGateReport,
    _check_source_trust,
)
from distroforge.core.trust import TrustOptions, TrustService

FINGERPRINT = "4248DCA20A9407BBFA31818518BC560A874C3C7F"
OTHER_FINGERPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"


def _validsig(fingerprint: str) -> str:
    return (
        "[GNUPG:] VALIDSIG "
        f"{fingerprint} 2026-07-29 1785283200 0 4 0 22 10 00 {fingerprint}\n"
    )


class _StatusRunner:
    dry_run = False

    def __init__(
        self,
        status: str,
        *,
        mutate_during_verify: Path | None = None,
    ) -> None:
        self.status = status
        self.mutate_during_verify = mutate_during_verify
        self.history: list[CommandSpec] = []

    def run(self, spec: CommandSpec, check: bool = True) -> CommandResult:
        self.history.append(spec)
        stdout = ""
        if spec.argv[:1] == ("gpg",):
            if self.mutate_during_verify is not None:
                self.mutate_during_verify.write_bytes(b"changed during verification")
            stdout = self.status
        return CommandResult(spec=spec, returncode=0, stdout=stdout, stderr="")


def _trusted_inputs(tmp_path: Path) -> tuple[Path, Path, TrustOptions]:
    source = tmp_path / "source.iso"
    signature = tmp_path / "source.iso.sig"
    source.write_bytes(b"source ISO bytes")
    signature.write_bytes(b"detached signature bytes")
    options = TrustOptions(
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        source_signature=signature,
        source_gpg_fingerprint=FINGERPRINT,
    )
    return source, signature, options


@pytest.mark.parametrize(
    ("kind", "expected_code"),
    (
        ("source", "source-iso-symlink"),
        ("signature", "source-signature-symlink"),
    ),
)
def test_strict_source_trust_rejects_symlinked_inputs(
    tmp_path: Path,
    kind: str,
    expected_code: str,
) -> None:
    source, signature, options = _trusted_inputs(tmp_path)
    if kind == "source":
        target = source
        source = tmp_path / "source-link.iso"
        source.symlink_to(target)
    else:
        target = signature
        signature = tmp_path / "signature-link.sig"
        signature.symlink_to(target)
        options.source_signature = signature

    report = TrustService().check_source_iso(source, options, strict=True)

    assert not report.ok
    assert any(check.code == expected_code for check in report.checks)


def test_strict_source_trust_rejects_nonregular_input_without_opening_it(
    tmp_path: Path,
) -> None:
    source, signature, options = _trusted_inputs(tmp_path)
    signature.unlink()
    os.mkfifo(signature)

    report = TrustService().check_source_iso(source, options, strict=True)

    assert not report.ok
    assert any(
        check.code == "source-signature-not-regular" for check in report.checks
    )


def test_strict_source_trust_rejects_symlinked_parent_component(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    source, _signature, options = _trusted_inputs(real)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)

    report = TrustService().check_source_iso(
        alias / source.name,
        options,
        strict=True,
    )

    assert not report.ok
    assert any(check.code == "source-iso-symlink" for check in report.checks)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    (
        ("sha", "source-sha256-required"),
        ("signature", "source-signature-required"),
        ("fingerprint", "source-gpg-fingerprint-invalid"),
    ),
)
def test_executing_remaster_requires_all_external_trust_inputs(
    tmp_path: Path,
    mutation: str,
    expected_code: str,
) -> None:
    source, _signature, options = _trusted_inputs(tmp_path)
    if mutation == "sha":
        options.source_sha256 = None
    elif mutation == "signature":
        options.source_signature = None
    else:
        options.source_gpg_fingerprint = FINGERPRINT[-16:]
    runner = _StatusRunner(_validsig(FINGERPRINT))

    with pytest.raises(ValueError, match=expected_code):
        TrustService().enforce_source_iso(source, options, runner)  # type: ignore[arg-type]


def test_executing_remaster_requires_one_exclusive_full_signer(
    tmp_path: Path,
) -> None:
    source, _signature, options = _trusted_inputs(tmp_path)
    runner = _StatusRunner(
        _validsig(FINGERPRINT) + _validsig(OTHER_FINGERPRINT)
    )

    with pytest.raises(ValueError, match="not exclusively"):
        TrustService().enforce_source_iso(source, options, runner)  # type: ignore[arg-type]


@pytest.mark.parametrize("input_name", ("source", "signature"))
def test_executing_remaster_closes_trust_input_paths_across_gpg(
    tmp_path: Path,
    input_name: str,
) -> None:
    source, signature, options = _trusted_inputs(tmp_path)
    runner = _StatusRunner(
        _validsig(FINGERPRINT),
        mutate_during_verify=source if input_name == "source" else signature,
    )

    with pytest.raises(ValueError, match="changed during GPG verification"):
        TrustService().enforce_source_iso(source, options, runner)  # type: ignore[arg-type]


def test_executing_remaster_accepts_closed_sha_signature_and_signer(
    tmp_path: Path,
) -> None:
    source, signature, options = _trusted_inputs(tmp_path)
    runner = _StatusRunner(_validsig(FINGERPRINT))

    report = TrustService().enforce_source_iso(
        source,
        options,
        runner,  # type: ignore[arg-type]
    )

    assert report.ok
    assert (
        "gpg",
        "--status-fd",
        "1",
        "--verify",
        str(signature),
        str(source),
    ) in [spec.argv for spec in runner.history]


def test_preflight_blocks_symlinked_signature_and_short_fingerprint(
    tmp_path: Path,
) -> None:
    source, signature, trust = _trusted_inputs(tmp_path)
    signature_link = tmp_path / "source.sig"
    signature_link.symlink_to(signature)
    trust.source_signature = signature_link
    trust.source_gpg_fingerprint = FINGERPRINT[-16:]
    project = Project.create("SourcePreflight", tmp_path / "project", "26.04")
    project.source_mode = "iso"
    project.source_iso = source
    options = BuildOptions(trust=trust, use_sudo=False)

    issues = validate_build_options(
        project,
        options,
        CommandRunner(dry_run=True),
        execute=True,
    )
    codes = {issue.code for issue in issues}

    assert "source-trust-signature" in codes
    assert "source-trust-fingerprint" in codes


def test_preflight_accepts_complete_regular_source_trust_configuration(
    tmp_path: Path,
) -> None:
    source, _signature, trust = _trusted_inputs(tmp_path)
    project = Project.create("SourcePreflightReady", tmp_path / "project", "26.04")
    project.source_mode = "iso"
    project.source_iso = source
    options = BuildOptions(trust=trust, use_sudo=False)

    issues = validate_build_options(
        project,
        options,
        CommandRunner(dry_run=True),
        execute=True,
    )

    assert not any(issue.code.startswith("source-trust-") for issue in issues)


def _source_gate(
    project: Project,
    options: BuildOptions,
) -> ReleaseGateItem:
    report = ReleaseGateReport(
        project=project.root,
        iso=project.output_dir / "output.iso",
        output_dir=project.output_dir,
    )
    _check_source_trust(
        report,
        project,
        options,
        ReleaseGateItem("package-inputs", "blocked", "not applicable"),
    )
    return report.items[0]


def test_publication_source_trust_is_review_until_offline_inputs_are_sealed(
    tmp_path: Path,
) -> None:
    source, _signature, trust = _trusted_inputs(tmp_path)
    project = Project.create("SourceGate", tmp_path / "project", "26.04")
    project.source_mode = "iso"
    project.source_iso = source

    item = _source_gate(project, BuildOptions(trust=trust))

    assert item.status == "review"
    assert "keyring bytes" in item.detail


@pytest.mark.parametrize("mutation", ("missing-sha", "symlink-signature", "short-pin"))
def test_publication_source_trust_blocks_incomplete_or_unsafe_inputs(
    tmp_path: Path,
    mutation: str,
) -> None:
    source, signature, trust = _trusted_inputs(tmp_path)
    if mutation == "missing-sha":
        trust.source_sha256 = None
    elif mutation == "symlink-signature":
        link = tmp_path / "source-link.sig"
        link.symlink_to(signature)
        trust.source_signature = link
    else:
        trust.source_gpg_fingerprint = FINGERPRINT[-16:]
    project = Project.create("SourceGateBlocked", tmp_path / "project", "26.04")
    project.source_mode = "iso"
    project.source_iso = source

    item = _source_gate(project, BuildOptions(trust=trust))

    assert item.status == "blocked"
