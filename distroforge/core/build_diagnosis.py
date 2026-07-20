"""Canonical build-failure diagnosis: one taxonomy, one set of patterns.

Two classifiers used to diverge. ``core.beginner_iso`` triaged the beginner ISO
command log with one set of rules, and ``ai.forgeadvisor`` triaged arbitrary
build logs with another. They disagreed on codes and even on which failure
classes existed, so the same log could be labelled two different ways. The
advisory-agent contract (``docs/advisory-agent.md``) requires *reproducible,
testable failure diagnoses* and a build-memory corpus that counts them
("3 of your last 5 builds failed at squashfs"). A count is only auditable if a
category means exactly one thing, so the taxonomy needs a single source of truth.

This module is that source. ``beginner-iso --explain-last-failure`` and the
ForgeAdvisor log reader both delegate here, and the build-memory corpus records
the canonical :attr:`DiagnosisRule.code`. The rules below are the union of what
both classifiers previously recognised, so neither caller loses coverage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DiagnosisRule:
    """One canonical failure category: its id, severity, and how to recognise it."""

    code: str
    level: str  # "error" | "warning"
    title: str
    detail: str
    remediation: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class DiagnosisMatch:
    """A rule that fired, cited to the line that triggered it."""

    rule: DiagnosisRule
    line: int  # 1-based line number within the scanned text
    evidence: str  # the matched line, stripped and length-capped


# Canonical, ordered taxonomy. Order is the first-match priority used by
# single-verdict callers: errors before warnings, and the specific privilege
# signals before the generic ones. The relative order of the shared classes
# (privilege < apt < bootstrap < squashfs < iso < boot) matches the historical
# beginner-iso order, so single-verdict selection on a multi-match log is stable.
BUILD_DIAGNOSIS_RULES: tuple[DiagnosisRule, ...] = (
    DiagnosisRule(
        "permission-denied",
        "error",
        "Permission denied",
        "A build step could not read or write a required path.",
        "Check ownership and enable the configured privilege helper (sudo) for rootfs operations.",
        re.compile(r"\bpermission denied\b|\bpermission non accord", re.I),
    ),
    DiagnosisRule(
        "pkexec-authorization",
        "error",
        "Polkit authorization failed",
        "A privileged command was cancelled, refused, or could not start through pkexec.",
        "Approve the pkexec prompt or switch DistroForge to sudo for this build.",
        re.compile(r"\bpkexec\b.*\b(126|cancel|not authorized|authorization)\b|\b126\b.*\bpkexec\b", re.I),
    ),
    DiagnosisRule(
        "apt-resolution",
        "warning",
        "APT resolution issue",
        "APT could not resolve packages, repositories, or dependencies cleanly.",
        "Review the suite, mirrors, PPAs, pins, and requested package names.",
        re.compile(r"\bapt-get\b|unable to locate package|held broken|unmet dependencies", re.I),
    ),
    DiagnosisRule(
        "bootstrap-rootfs",
        "warning",
        "Bootstrap/rootfs retry risk",
        "The log points at bootstrap or an already-populated rootfs.",
        "Reuse a valid rootfs or clean the work/filesystem directory before retrying.",
        re.compile(r"\bdebootstrap\b|\bbootstrap\b|Cannot open: File exists|target directory .*not empty", re.I),
    ),
    DiagnosisRule(
        "squashfs",
        "warning",
        "Squashfs packaging issue",
        "The failure is near live-filesystem repacking.",
        "Check squashfs-tools, available disk space, and rootfs permissions.",
        re.compile(r"\bmksquashfs\b|squashfs", re.I),
    ),
    DiagnosisRule(
        "iso-assembly",
        "warning",
        "ISO assembly issue",
        "The failure is near ISO image assembly or boot-metadata generation.",
        "Check xorriso, work/iso contents, bootloader files, volume labels, and output permissions.",
        re.compile(r"\bxorriso\b|mkisofs|El Torito|ISO image", re.I),
    ),
    DiagnosisRule(
        "boot-stack",
        "warning",
        "Boot stack issue",
        "The log mentions GRUB, shim, or Casper boot assets.",
        "Verify kernel/initrd artifacts, bootloader packages, and ISO casper paths.",
        re.compile(r"\bgrub\b|\bshim\b|\bcasper\b", re.I),
    ),
    DiagnosisRule(
        "boot-proof",
        "warning",
        "Boot proof failed",
        "The QEMU/bootcheck boot-proof step did not pass.",
        "Review QEMU availability, VM resources, and boot logs.",
        re.compile(r"\bqemu\b|\bbootcheck\b", re.I),
    ),
)

# Returned when no rule matches, so single-verdict callers always have a code.
# The pattern never matches, so this rule is reachable only via classify_log's
# fallthrough -- it is never produced by iter_log_matches.
UNKNOWN_DIAGNOSIS = DiagnosisRule(
    "unknown",
    "warning",
    "No known failure pattern matched",
    "The log did not match any known DistroForge failure signature.",
    "Open the command log and dry-run report, then rerun with the failing phase visible.",
    re.compile(r"(?!)"),
)


def classify_log(text: str) -> DiagnosisRule:
    """First-match verdict over a whole log blob (single-category callers).

    Returns :data:`UNKNOWN_DIAGNOSIS` when nothing matches so callers always
    have a stable code, title, and remediation to render.
    """
    for rule in BUILD_DIAGNOSIS_RULES:
        if rule.pattern.search(text):
            return rule
    return UNKNOWN_DIAGNOSIS


def iter_log_matches(lines: list[str]) -> list[DiagnosisMatch]:
    """Every distinct category present, each cited to its first matching line.

    Scanning is line-major then rule-order within a line, so the first match of
    a code wins its citation and the result order is deterministic.
    """
    matches: list[DiagnosisMatch] = []
    seen: set[str] = set()
    for index, line in enumerate(lines, start=1):
        for rule in BUILD_DIAGNOSIS_RULES:
            if rule.code in seen or not rule.pattern.search(line):
                continue
            seen.add(rule.code)
            matches.append(DiagnosisMatch(rule, index, line.strip()[:180]))
    return matches
