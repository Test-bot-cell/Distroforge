"""Guards for the small utilities consolidated out of duplicated call sites."""

from __future__ import annotations

from pathlib import Path

from distroforge.ai.forgeadvisor import AdvisorFinding
from distroforge.ai.verdict import verdict_for_findings
from distroforge.core.command import CommandRunner
from distroforge.core.qemu_invocation import prepare_ovmf_vars_store
from distroforge.ui.field_parsing import int_or_default, optional_int


def _finding(level: str) -> AdvisorFinding:
    return AdvisorFinding(level=level, code="c", title="t", detail="d")


def test_verdict_is_blocked_when_any_finding_is_an_error() -> None:
    findings = [_finding("info"), _finding("warning"), _finding("error")]
    assert verdict_for_findings(findings) == "blocked"


def test_verdict_is_review_when_the_worst_finding_is_a_warning() -> None:
    assert verdict_for_findings([_finding("info"), _finding("warning")]) == "review"


def test_verdict_is_informational_with_no_error_or_warning() -> None:
    assert verdict_for_findings([]) == "informational"
    assert verdict_for_findings([_finding("info")]) == "informational"


def test_int_or_default_falls_back_on_blank_or_malformed_text() -> None:
    assert int_or_default("12", 7) == 12
    assert int_or_default("", 7) == 7
    assert int_or_default("nope", 7) == 7


def test_optional_int_is_none_only_for_an_empty_field() -> None:
    assert optional_int("  ") is None
    assert optional_int("") is None
    assert optional_int("5") == 5
    assert optional_int("bad") == 0


def test_prepare_ovmf_vars_store_is_a_noop_for_non_uefi_firmware() -> None:
    runner = CommandRunner(dry_run=True)
    prepare_ovmf_vars_store(
        runner,
        firmware="bios",
        ovmf_vars_override="",
        secure_boot=False,
        dest=Path("/tmp/vars.fd"),
    )
    assert runner.history == []


def test_prepare_ovmf_vars_store_records_the_copy_for_uefi() -> None:
    runner = CommandRunner(dry_run=True)
    dest = Path("/tmp/vars.fd")
    prepare_ovmf_vars_store(
        runner,
        firmware="uefi",
        ovmf_vars_override="/img/OVMF_VARS.fd",
        secure_boot=False,
        dest=dest,
    )
    assert len(runner.history) == 1
    spec = runner.history[0]
    assert spec.argv == ("copy-file", "/img/OVMF_VARS.fd", str(dest))
