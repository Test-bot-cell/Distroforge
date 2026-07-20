from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from distroforge.ai.backend import (
    AdvisorBackend,
    AdvisorContext,
    OfflineBackend,
    available_backends,
)
from distroforge.ai.proposals import ProposalReport, build_proposal
from distroforge.ai.registers import AdvisorRegister, select_register
from distroforge.core.build import BuildOptions
from distroforge.core.build_diagnosis import iter_log_matches
from distroforge.core.definition import load_definition
from distroforge.core.dry_run_report import DryRunReport, generate_dry_run_report
from distroforge.core.education import GLOSSARY
from distroforge.core.evidence import EvidenceItem, EvidenceStatusReport, EvidenceStatusService
from distroforge.core.project import Project
from distroforge.core.readiness import ReadinessReport, ReadinessService
from distroforge.core.schema import validate_definition_data

if TYPE_CHECKING:
    from distroforge.core.build_memory import BuildMemory

_MAX_GLOSSARY_NOTES = 6
_SEARCH_ROOTS = ("docs", "debian", "tests", "distroforge")
_SEARCH_SUFFIXES = {".md", ".txt", ".py", ".yaml", ".yml", ".json", ".toml", ".desktop", ".control"}
_MAX_SEARCH_BYTES = 512_000


@dataclass(frozen=True)
class AdvisorCitation:
    source: str
    line: int
    text: str

    def to_dict(self) -> dict[str, object]:
        return self.__dict__


@dataclass(frozen=True)
class AdvisorFinding:
    level: str
    code: str
    title: str
    detail: str
    remediation: str = ""
    citations: tuple[AdvisorCitation, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "level": self.level,
            "code": self.code,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "citations": [citation.to_dict() for citation in self.citations],
        }


@dataclass
class AdvisorReport:
    title: str
    backend: str = "offline"
    register: str = "Beginner"
    findings: list[AdvisorFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if any(finding.level == "error" for finding in self.findings):
            return "blocked"
        if any(finding.level == "warning" for finding in self.findings):
            return "review"
        return "informational"

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "backend": self.backend,
            "register": self.register,
            "verdict": self.verdict,
            "findings": [finding.to_dict() for finding in self.findings],
            "notes": self.notes,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            f"ForgeAdvisor: {self.title}",
            f"Backend: {self.backend}",
            f"Register: {self.register}",
            f"Verdict: {self.verdict}",
        ]
        if self.notes:
            lines.extend(["", "Notes:"])
            lines.extend(f"- {note}" for note in self.notes)
        lines.extend(["", "Findings:"])
        if not self.findings:
            lines.append("- no findings")
        for finding in self.findings:
            lines.append(f"- {finding.level.upper():7} {finding.code:28} {finding.title}")
            lines.append(f"          {finding.detail}")
            if finding.remediation:
                lines.append(f"          fix: {finding.remediation}")
            for citation in finding.citations[:3]:
                lines.append(f"          cite: {citation.source}:{citation.line}: {citation.text}")
        return "\n".join(lines)


class ForgeAdvisor:
    """Local-first advisory layer.

    Findings and citations are always computed deterministically: log triage
    delegates to the single canonical taxonomy in ``core.build_diagnosis`` (so the
    advisor, the beginner-iso explainer, and the build-memory corpus agree on every
    category), and grounding is read from the injected build-memory corpus, never
    invented. A pluggable :class:`~distroforge.ai.backend.AdvisorBackend` only
    *rephrases* that context into a short narrative; any optional model backend
    that cannot help degrades to the always-available offline backend. The advisor
    stays advisory: it produces text only and never mutates the build or host.
    """

    def __init__(
        self,
        backend: AdvisorBackend | None = None,
        memory: BuildMemory | None = None,
        level: str | None = None,
    ) -> None:
        self.backend: AdvisorBackend = backend or OfflineBackend()
        self.memory = memory
        # Ring 0: pick the advisory voice for the active level, silently and
        # overridably. A missing/unknown level degrades to the beginner voice.
        self.register: AdvisorRegister = select_register(level)

    def _new_report(self, title: str) -> AdvisorReport:
        return AdvisorReport(title, register=self.register.voice)

    def _corpus_citation(self) -> str:
        if self.memory is None:
            return ""
        return self.memory.summarize().citation

    def _apply_register_voice(self, report: AdvisorReport) -> None:
        """Ring 1: speak in the selected register without changing the facts.

        The findings are already deterministic; this only frames them through
        the register's lens and, for the beginner voice, expands the jargon that
        actually appears in the findings using the ``core.education`` glossary.
        """
        if self.register.lens_note:
            report.notes.append(self.register.lens_note)
        if not self.register.expand_jargon:
            return
        for term in _glossary_terms_in(report.findings):
            report.notes.append(f"Plain language - {term}: {GLOSSARY[term]}")

    def _narrate(self, report: AdvisorReport) -> None:
        """Attach corpus grounding and a backend narrative to ``report``.

        The corpus citation is the deterministic, never-hallucinated grounding;
        the narrative is advisory prose. If the selected backend cannot narrate,
        we fall back to the offline backend and say so.
        """
        citation = self._corpus_citation()
        if citation:
            report.notes.append(f"Build memory: {citation}")
        self._apply_register_voice(report)
        context = AdvisorContext(
            title=report.title,
            verdict=report.verdict,
            findings=tuple(f"{finding.code}: {finding.title}" for finding in report.findings),
            corpus_citation=citation,
            register=self.register.audience,
        )
        narration = self.backend.narrate(context)
        effective = self.backend.name
        if narration is None and self.backend.name != "offline":
            narration = OfflineBackend().narrate(context)
            effective = "offline"
            report.notes.append(
                f"Backend {self.backend.name} was unavailable; narration fell back to offline."
            )
        report.backend = effective
        if narration:
            report.notes.append(f"Narrative ({effective}): {narration}")

    def doctor(self) -> AdvisorReport:
        report = self._new_report("local advisory backend")
        report.notes.append(f"Active backend: {self.backend.name}.")
        report.notes.append(f"Active register: {self.register.voice}.")
        for status in (backend.status() for backend in available_backends()):
            level = "info" if status.available else "warning"
            remediation = (
                ""
                if status.available
                else "Install only if you want that optional backend; the offline backend always works."
            )
            report.findings.append(
                AdvisorFinding(level, f"backend-{status.name}", status.name, status.detail, remediation)
            )
        self._narrate(report)
        return report

    def explain_log(self, path: Path) -> AdvisorReport:
        report = self._new_report(f"log explanation for {path}")
        if not path.exists():
            report.findings.append(
                AdvisorFinding(
                    "error",
                    "log-missing",
                    "Log file is missing",
                    f"Cannot read {path}.",
                    "Pass an existing log file.",
                )
            )
            return report
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            report.findings.append(
                AdvisorFinding("error", "log-unreadable", "Log file is unreadable", str(exc))
            )
            return report
        report.findings.extend(_findings_from_lines(str(path), lines))
        if not report.findings:
            report.notes.append("No known build failure pattern matched this log.")
        self._narrate(report)
        return report

    def triage_log(self, path: Path) -> AdvisorReport:
        report = self.explain_log(path)
        report.title = f"build log triage for {path}"
        if report.findings:
            report.notes.insert(0, "Triage: matched log patterns are ordered by first appearance.")
        else:
            report.notes.insert(0, "Triage: no known failure taxonomy matched this log.")
        return report

    def explain_evidence(
        self,
        root: Path,
        *,
        options: BuildOptions | None = None,
        iso: Path | None = None,
        output_dir: Path | None = None,
        profile: str = "publish",
    ) -> AdvisorReport:
        evidence = _evidence_report(root, options=options, iso=iso, output_dir=output_dir, profile=profile)
        report = self._new_report(f"evidence explanation for {evidence.project}")
        report.findings.extend(_findings_from_evidence(evidence))
        counts = evidence.counts()
        report.notes.append(f"evidence status: {evidence.status}")
        report.notes.append(
            f"profile {evidence.profile}: ready={counts['ready']} review={counts['review']} blocked={counts['blocked']} invalid={counts['invalid']}"
        )
        if doctor_item := _evidence_item(evidence, "debian-dev-doctor"):
            report.notes.append(f"maintainer toolchain: {doctor_item.detail}")
        for action in evidence.next_actions():
            report.notes.append(f"next action: {action}")
        if not report.findings:
            report.notes.append("Evidence is ready for the selected profile.")
        self._narrate(report)
        return report

    def narrate_fix_plan(
        self,
        root: Path,
        *,
        options: BuildOptions | None = None,
        iso: Path | None = None,
        output_dir: Path | None = None,
        profile: str = "publish",
    ) -> AdvisorReport:
        evidence = _evidence_report(root, options=options, iso=iso, output_dir=output_dir, profile=profile)
        report = self._new_report(f"evidence fix plan for {evidence.project}")
        report.findings.extend(_findings_from_evidence(evidence))
        commands = evidence.fix_plan()
        if commands:
            for command in commands:
                report.notes.append(f"fix command: {command}")
        else:
            report.notes.append("No fix commands are suggested for the selected profile.")
        report.notes.append("Preview only: no command has been executed or applied.")
        self._narrate(report)
        return report

    def review_definition(self, path: Path) -> AdvisorReport:
        report = self._new_report(f"definition review for {path}")
        try:
            data = load_definition(path)
            validate_definition_data(data)
        except Exception as exc:
            report.findings.append(
                AdvisorFinding(
                    "error",
                    "definition-invalid",
                    "Definition does not pass schema validation",
                    str(exc),
                    "Fix the definition, then rerun forgeadvisor review-definition.",
                    (AdvisorCitation(str(path), 1, _first_line(path)),),
                )
            )
            self._narrate(report)
            return report
        report.findings.extend(_definition_findings(path, data))
        report.notes.append(f"recommended evidence profile: {_recommended_profile(data)}")
        if not report.findings:
            report.notes.append("Definition passed schema validation and no advisory risks were detected.")
        self._narrate(report)
        return report

    def search_local(self, root: Path, query: str, limit: int = 8) -> AdvisorReport:
        report = self._new_report(f"local knowledge search for {query}")
        matches = _search_local(root, query, limit=max(1, limit))
        for source, line, text in matches:
            report.findings.append(
                AdvisorFinding(
                    "info",
                    "local-citation",
                    source,
                    text,
                    citations=(AdvisorCitation(source, line, text),),
                )
            )
        if not matches:
            report.notes.append("No local docs, reports, tests, or source snippets matched the query.")
        else:
            report.notes.append(f"{len(matches)} local citation(s) found under {root}.")
        self._narrate(report)
        return report

    def maintainer_copilot(
        self,
        root: Path,
        *,
        options: BuildOptions | None = None,
        iso: Path | None = None,
        output_dir: Path | None = None,
        profile: str = "publish",
        query: str = "evidence release readiness",
        limit: int = 5,
    ) -> AdvisorReport:
        evidence = _evidence_report(root, options=options, iso=iso, output_dir=output_dir, profile=profile)
        report = self._new_report(f"maintainer copilot for {evidence.project}")
        report.findings.extend(_findings_from_evidence(evidence))
        counts = evidence.counts()
        report.notes.append("Workflow: explain-evidence -> fix-plan -> search-local.")
        report.notes.append(
            f"Evidence [{evidence.profile}]: {evidence.status} "
            f"(ready={counts['ready']} review={counts['review']} blocked={counts['blocked']} invalid={counts['invalid']})."
        )
        if doctor_item := _evidence_item(evidence, "debian-dev-doctor"):
            report.notes.append(f"Maintainer toolchain: {doctor_item.detail}.")
        for action in evidence.next_actions():
            report.notes.append(f"Next action: {action}")
        commands = evidence.fix_plan()
        if commands:
            for command in commands:
                report.notes.append(f"Fix command: {command}")
        else:
            report.notes.append("Fix command: no command suggested for the selected profile.")
        matches = _search_local(evidence.project, query, limit=max(1, limit))
        for source, line, text in matches:
            report.findings.append(
                AdvisorFinding(
                    "info",
                    "copilot-local-citation",
                    source,
                    text,
                    citations=(AdvisorCitation(source, line, text),),
                )
            )
        report.notes.append(f"Local search query: {query}")
        report.notes.append(f"Preview only: {len(commands)} command(s) suggested, none executed.")
        self._narrate(report)
        return report

    def _collect_review_findings(
        self, project: Project, options: BuildOptions
    ) -> tuple[list[AdvisorFinding], ReadinessReport, DryRunReport]:
        """Single source for the findings a build review yields.

        Both ``review_build`` (Ring 1) and ``propose_fixes`` (Ring 2) read from
        here, so an explanation and a proposal can never disagree on what the
        build raised.
        """
        readiness = ReadinessService().check(project, options)
        dry_run = generate_dry_run_report(project, options, run_orchestrator=False)
        findings = [*_findings_from_readiness(readiness), *_findings_from_dry_run(dry_run)]
        return findings, readiness, dry_run

    def review_build(self, project: Project, options: BuildOptions) -> AdvisorReport:
        findings, readiness, dry_run = self._collect_review_findings(project, options)
        report = self._new_report(f"build review for {project.name}")
        report.findings.extend(findings)
        report.notes.append(f"readiness status: {readiness.status}")
        report.notes.append(f"dry-run findings: {len(dry_run.findings)}")
        if not report.findings:
            report.notes.append("No readiness or dry-run findings need advisory escalation.")
        self._narrate(report)
        return report

    def propose_fixes(self, project: Project, options: BuildOptions) -> ProposalReport:
        """Ring 2: draft a previewable remediation plan; never apply anything.

        The plan's steps and any option diff are grounded in the same findings
        ``review_build`` explains; ``options`` is read to ground the diff and is
        never mutated. Applying a proposal stays the user's explicit action.
        """
        findings, _readiness, _dry_run = self._collect_review_findings(project, options)
        proposal = build_proposal(
            f"fix proposals for {project.name}", findings, options, self.register.voice
        )
        self._narrate(proposal)
        return proposal


def _glossary_terms_in(findings: list[AdvisorFinding]) -> list[str]:
    """Glossary terms that literally appear in the findings, in glossary order.

    Matches whole tokens only (hyphens count as part of a term), so "iso" does
    not fire inside "isolated"; capped so the beginner voice stays a short aside
    rather than dumping the whole glossary.
    """
    haystack = " ".join(
        f"{finding.code} {finding.title} {finding.detail} {finding.remediation}"
        for finding in findings
    ).lower()
    found = [
        term
        for term in GLOSSARY
        if re.search(rf"(?<![\w-]){re.escape(term)}(?![\w-])", haystack)
    ]
    return found[:_MAX_GLOSSARY_NOTES]


def _findings_from_lines(source: str, lines: list[str]) -> list[AdvisorFinding]:
    findings: list[AdvisorFinding] = []
    for match in iter_log_matches(lines):
        rule = match.rule
        findings.append(
            AdvisorFinding(
                rule.level,
                rule.code,
                rule.title,
                rule.detail,
                rule.remediation,
                (AdvisorCitation(source, match.line, match.evidence),),
            )
        )
    return findings


def _findings_from_readiness(readiness: ReadinessReport) -> list[AdvisorFinding]:
    findings: list[AdvisorFinding] = []
    for check in readiness.checks:
        if check.level not in {"error", "warning"}:
            continue
        findings.append(
            AdvisorFinding(
                check.level,
                f"readiness-{check.code}",
                check.code,
                check.message,
                check.remediation,
            )
        )
    return findings


def _findings_from_dry_run(dry_run: DryRunReport) -> list[AdvisorFinding]:
    findings: list[AdvisorFinding] = []
    for finding in dry_run.findings:
        if finding.level not in {"error", "warning"}:
            continue
        findings.append(
            AdvisorFinding(
                finding.level,
                f"dry-run-{finding.code}",
                finding.code,
                finding.message,
                finding.remediation,
            )
        )
    return findings


def _evidence_report(
    root: Path,
    *,
    options: BuildOptions | None,
    iso: Path | None,
    output_dir: Path | None,
    profile: str,
) -> EvidenceStatusReport:
    try:
        project = Project.load(root)
    except FileNotFoundError:
        return EvidenceStatusService().check_source_tree(root, iso=iso, output_dir=output_dir, profile=profile)
    return EvidenceStatusService().check(project, options or BuildOptions(), iso=iso, output_dir=output_dir, profile=profile)


def _findings_from_evidence(evidence: EvidenceStatusReport) -> list[AdvisorFinding]:
    levels = {"invalid": "error", "blocked": "error", "review": "warning"}
    findings: list[AdvisorFinding] = []
    for item in evidence.items:
        level = levels.get(item.status)
        if level is None:
            continue
        findings.append(
            AdvisorFinding(
                level,
                f"evidence-{item.code}",
                item.code,
                item.detail,
                _evidence_remediation(item.code),
                (AdvisorCitation(str(item.path), 1, item.detail),) if item.path else (),
            )
        )
    return findings


def _evidence_item(evidence: EvidenceStatusReport, code: str) -> EvidenceItem | None:
    return next((item for item in evidence.items if item.code == code), None)


def _evidence_remediation(code: str) -> str:
    if code == "debian-dev-doctor":
        return "Run distroforge doctor --debian-dev and install missing safe tooling."
    if code == "buildinfo-taint":
        return "Rebuild in sbuild, pbuilder or mmdebstrap before publication."
    if code == "autopkgtest-run":
        return "Run autopkgtest-doctor; use schroot/qemu when the local testbed is broken."
    if "iso" in code:
        return "Build an ISO or pass --iso with an existing image."
    if "bundle" in code or code.startswith("package:"):
        return "Create or verify a hermetic release bundle."
    if "qemu" in code:
        return "Review or execute the boot proof matrix when release evidence is needed."
    if "publish" in code:
        return "Prepare publish evidence and rerun verify-release."
    return "Review the evidence item and rerun evidence-status."


def _definition_findings(path: Path, data: dict[str, object]) -> list[AdvisorFinding]:
    findings: list[AdvisorFinding] = []
    if not data.get("schema"):
        findings.append(
            AdvisorFinding(
                "warning",
                "definition-schema-missing",
                "Definition schema is missing",
                "The definition validates, but it does not declare an explicit schema.",
                "Export or add the current DistroForge preset schema for maintainer review.",
                (AdvisorCitation(str(path), 1, _first_line(path)),),
            )
        )
    if data.get("source_iso") and not _truthy_nested(data, ("trust", "source_iso_sha256")) and not data.get("source_iso_sha256"):
        findings.append(
            AdvisorFinding(
                "warning",
                "definition-source-checksum-missing",
                "Source ISO checksum is missing",
                "A definition that pins source_iso should also carry checksum evidence before release review.",
                "Add source_iso_sha256 or require source checksum in the trust options.",
            )
        )
    release_artifacts = data.get("release_artifacts")
    if isinstance(release_artifacts, dict) and release_artifacts.get("enabled") is False:
        findings.append(
            AdvisorFinding(
                "warning",
                "definition-release-evidence-disabled",
                "Release evidence is disabled",
                "This is acceptable for dev iteration, but publish/package review needs release artifacts enabled.",
                "Use profile dev while iterating; enable release artifacts before package, ISO, or publish review.",
            )
        )
    if data.get("release_track") == "devel" or _truthy_nested(data, ("release_track", "enable_proposed")):
        findings.append(
            AdvisorFinding(
                "warning",
                "definition-devel-track",
                "Definition uses devel/proposed packages",
                "Development tracks are useful for testing but need explicit maintainer sign-off.",
                "Keep APT pinning low and document why the devel/proposed path is needed.",
            )
        )
    return findings


def _recommended_profile(data: dict[str, object]) -> str:
    if data.get("publish") or data.get("sign_artifacts"):
        return "publish"
    if data.get("output_iso") or data.get("boot_proof") or data.get("qemu_screenshot"):
        return "iso"
    if data.get("release_artifacts") or data.get("debian"):
        return "package"
    return "dev"


def _truthy_nested(data: dict[str, object], path: tuple[str, ...]) -> bool:
    value: object = data
    for key in path:
        if not isinstance(value, dict):
            return False
        value = value.get(key)
    return bool(value)


def _first_line(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except (IndexError, OSError):
        return ""


def _search_local(root: Path, query: str, *, limit: int) -> list[tuple[str, int, str]]:
    terms = [term.lower() for term in re.findall(r"[\w.-]+", query) if len(term) > 1]
    if not terms:
        return []
    candidates: list[tuple[int, str, int, str]] = []
    for base_name in _SEARCH_ROOTS:
        base = root / base_name
        if not base.exists():
            continue
        files = [base] if base.is_file() else list(base.rglob("*"))
        for path in files:
            if not path.is_file() or path.suffix.lower() not in _SEARCH_SUFFIXES:
                continue
            if any(part.startswith(".") or part == "__pycache__" for part in path.parts):
                continue
            try:
                if path.stat().st_size > _MAX_SEARCH_BYTES:
                    continue
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for index, line in enumerate(lines, start=1):
                haystack = line.lower()
                score = sum(1 for term in terms if term in haystack)
                if score:
                    candidates.append((score, str(path), index, line.strip()[:240]))
    candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
    return [(source, line, text) for _score, source, line, text in candidates[:limit]]
