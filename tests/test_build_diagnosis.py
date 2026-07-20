from __future__ import annotations

from pathlib import Path

import distroforge.core.beginner_iso as beginner_iso_module
from distroforge.ai.forgeadvisor import ForgeAdvisor
from distroforge.core.beginner_iso import explain_beginner_iso_failure
from distroforge.core.build_diagnosis import (
    BUILD_DIAGNOSIS_RULES,
    classify_log,
    iter_log_matches,
)
from distroforge.core.project import Project


def test_taxonomy_is_the_single_source_no_parallel_rule_tables() -> None:
    # The unification is structural: neither consumer may keep its own rule table,
    # or the taxonomy could silently re-diverge.
    assert not hasattr(ForgeAdvisor, "PATTERNS")
    assert not hasattr(beginner_iso_module, "FAILURE_RULES")
    # Externally locked ids must each exist exactly once in the canonical taxonomy.
    codes = [rule.code for rule in BUILD_DIAGNOSIS_RULES]
    assert codes.count("squashfs") == 1
    assert codes.count("pkexec-authorization") == 1


def test_classify_log_is_first_match_and_falls_back_to_unknown() -> None:
    assert classify_log("mksquashfs root filesystem.squashfs").code == "squashfs"
    assert "squashfs-tools" in classify_log("mksquashfs failed").remediation
    assert classify_log("nothing notable here").code == "unknown"


def test_iter_log_matches_dedups_by_code_and_cites_first_line() -> None:
    matches = iter_log_matches(["mksquashfs a", "mksquashfs b", "xorriso c"])
    assert [match.rule.code for match in matches] == ["squashfs", "iso-assembly"]
    assert matches[0].line == 1  # first squashfs line wins the citation
    assert matches[1].line == 3


def test_both_consumers_agree_on_the_same_log(tmp_path: Path) -> None:
    # A squashfs failure is labelled "squashfs" whether the beginner explainer or
    # the advisor reads it -- that agreement is the whole point of unifying.
    log = tmp_path / "beginner-iso-build-commands.jsonl"
    log.write_text(
        '{"event":"finish","command":"mksquashfs root filesystem.squashfs","returncode":1}\n',
        encoding="utf-8",
    )
    project = Project.create("Diag", tmp_path / "diag", "26.04")

    beginner = explain_beginner_iso_failure(project, log)
    assert beginner.category == "squashfs"
    assert "squashfs-tools" in beginner.next_action

    advisor_codes = {finding.code for finding in ForgeAdvisor().explain_log(log).findings}
    assert "squashfs" in advisor_codes
    assert beginner.category in advisor_codes


def test_advisor_log_findings_carry_canonical_level_and_citation(tmp_path: Path) -> None:
    log = tmp_path / "build.log"
    log.write_text(
        "Command failed with exit code 126: pkexec /usr/bin/install file target\n"
        "mksquashfs failed near filesystem.squashfs\n",
        encoding="utf-8",
    )

    by_code = {finding.code: finding for finding in ForgeAdvisor().explain_log(log).findings}

    assert {"pkexec-authorization", "squashfs"} <= set(by_code)
    assert by_code["pkexec-authorization"].level == "error"
    assert by_code["pkexec-authorization"].citations
    assert by_code["pkexec-authorization"].citations[0].line == 1
