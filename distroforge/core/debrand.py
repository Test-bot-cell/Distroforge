from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .branding import BrandingOptions
from .branding_compliance import CANONICAL_MARKS
from .command import CommandRunner, CommandSpec
from .fsops import FileSystemOps
from .project import Project

TEXT_TARGETS = (
    "boot/grub",
    "isolinux",
    "EFI",
    ".disk",
    "README.diskdefines",
    "etc/os-release",
    "etc/lsb-release",
    "etc/issue",
    "etc/issue.net",
    "etc/motd",
    "usr/share/plymouth",
    "usr/share/backgrounds",
    "usr/share/icons",
    "usr/share/ubiquity-slideshow",
)
PATH_RENAME_TARGETS = (
    "boot/grub",
    "isolinux",
    "EFI",
    ".disk",
    "README.diskdefines",
    "usr/share/plymouth",
    "usr/share/backgrounds",
    "usr/share/icons",
    "usr/share/ubiquity-slideshow",
)
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".conf",
    ".txt",
    ".theme",
    ".plymouth",
    ".script",
    ".desktop",
    ".list",
    ".md",
    ".html",
    ".css",
    ".json",
}
MARK_RE = re.compile(
    r"\b("
    + "|".join(re.escape(mark).replace(r"\ ", r"\s+") for mark in sorted(CANONICAL_MARKS, key=len, reverse=True))
    + r")\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DebrandFinding:
    root: str
    path: str
    mark: str
    line: int
    replacement: str
    action: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DebrandReport:
    project: str
    status: str
    findings: list[DebrandFinding]

    def to_dict(self) -> dict[str, object]:
        return {
            "project": self.project,
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [f"Debrand scan: {self.status}"]
        if not self.findings:
            lines.append("No Canonical/Ubuntu text matches found in scanned source targets.")
            return "\n".join(lines)
        for finding in self.findings:
            lines.append(
                f"- {finding.action} {finding.root}:{finding.path}:{finding.line} "
                f"{finding.mark} -> {finding.replacement}"
            )
        return "\n".join(lines)


class DebrandService:
    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner or CommandRunner(dry_run=True)

    def scan(self, project: Project, options: BrandingOptions) -> DebrandReport:
        findings: list[DebrandFinding] = []
        replacement = _replacement_name(project, options)
        for root_name, root in (("iso", project.iso_root), ("filesystem", project.squashfs_root)):
            if not root.exists():
                continue
            findings.extend(_scan_paths(root_name, root, replacement))
            for path in _candidate_files(root):
                findings.extend(_scan_file(root_name, root, path, replacement))
        status = "clear" if not findings else "needs-debranding"
        return DebrandReport(project.name, status, findings)

    def apply(
        self,
        project: Project,
        options: BrandingOptions,
        strict: bool = False,
        output: Path | None = None,
        use_sudo: bool = True,
    ) -> DebrandReport:
        if self.runner.dry_run:
            self.runner.run(
                CommandSpec(
                    argv=("debrand-scan", str(project.iso_root), str(project.squashfs_root)),
                    description="Scan extracted ISO and live filesystem for Canonical/Ubuntu identity traces",
                )
            )
            report = DebrandReport(project.name, "planned", [])
            self._write_report(project, report, output)
            return report

        report = self.scan(project, options)
        replacement = _replacement_name(project, options)
        for root in (project.iso_root, project.squashfs_root):
            if not root.exists():
                continue
            for path in _candidate_files(root):
                text = _read_text(path)
                if text is None or not MARK_RE.search(text):
                    continue
                FileSystemOps(self.runner, use_sudo).write_text(
                    path,
                    MARK_RE.sub(replacement, text),
                    f"Write debranded text file {path}",
                )
            for path in sorted(_candidate_path_renames(root), key=lambda item: len(item.parts), reverse=True):
                target = path.with_name(MARK_RE.sub(_path_replacement(replacement), path.name))
                if target != path and not target.exists():
                    FileSystemOps(self.runner, use_sudo).rename(path, target, f"Rename branding path {path}")
        after = self.scan(project, options)
        final_report = DebrandReport(project.name, "clear" if not after.findings else "blocked", after.findings)
        self._write_report(project, report, output)
        if strict and final_report.findings:
            raise ValueError("Debranding left Canonical/Ubuntu identity traces; see DEBRAND-REPORT.json")
        return DebrandReport(project.name, "applied", report.findings)

    def _write_report(self, project: Project, report: DebrandReport, output: Path | None) -> None:
        target = output or project.output_dir / "DEBRAND-REPORT.json"
        if self.runner.dry_run:
            self.runner.run(
                CommandSpec(
                    argv=("write-file", str(target)),
                    description="Write debranding report",
                )
            )
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(report.render_json() + "\n", encoding="utf-8")


def _candidate_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for target in TEXT_TARGETS:
        path = root / target
        if path.is_file() and _is_text_target(path):
            files.append(path)
        elif path.is_dir():
            files.extend(item for item in path.rglob("*") if item.is_file() and _is_text_target(item))
    return files


def _candidate_path_renames(root: Path) -> list[Path]:
    paths: list[Path] = []
    for target in PATH_RENAME_TARGETS:
        path = root / target
        if not path.exists():
            continue
        if MARK_RE.search(path.name):
            paths.append(path)
        if path.is_dir():
            paths.extend(item for item in path.rglob("*") if MARK_RE.search(item.name))
    return paths


def _scan_paths(root_name: str, root: Path, replacement: str) -> list[DebrandFinding]:
    findings: list[DebrandFinding] = []
    for path in _candidate_path_renames(root):
        for match in MARK_RE.finditer(path.name):
            findings.append(
                DebrandFinding(
                    root=root_name,
                    path=str(path.relative_to(root)),
                    mark=match.group(0),
                    line=0,
                    replacement=_path_replacement(replacement),
                    action="rename",
                )
            )
    return findings


def _is_text_target(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES or path.name in {"info", "release_notes_url"}


def _scan_file(root_name: str, root: Path, path: Path, replacement: str) -> list[DebrandFinding]:
    text = _read_text(path)
    if text is None:
        return []
    findings: list[DebrandFinding] = []
    for index, line in enumerate(text.splitlines(), start=1):
        for match in MARK_RE.finditer(line):
            findings.append(
                DebrandFinding(
                    root=root_name,
                    path=str(path.relative_to(root)),
                    mark=match.group(0),
                    line=index,
                    replacement=replacement,
                    action="replace",
                )
            )
    return findings


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def _replacement_name(project: Project, options: BrandingOptions) -> str:
    return options.product_name or options.pretty_name or options.name or project.name


def _path_replacement(value: str) -> str:
    return "-".join(part for part in value.lower().split() if part) or "distro"
