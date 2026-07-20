from __future__ import annotations

from dataclasses import dataclass
from html import escape
from pathlib import Path

from .build_types import BuildReportLike
from .command import CommandRunner
from .host_artifacts import HostArtifactWriter
from .project import Project


@dataclass
class HtmlReportOptions:
    enabled: bool = True
    filename: str = "report.html"


class HtmlReportService:
    def __init__(
        self,
        runner: CommandRunner,
        project: Project,
        options: HtmlReportOptions,
    ) -> None:
        self.runner = runner
        self.project = project
        self.options = options

    def write(self, report: BuildReportLike, output_iso: Path) -> None:
        if not self.options.enabled:
            return
        target = self.project.output_dir / self.options.filename
        HostArtifactWriter(self.runner).write_text(
            target, self.render(report, output_iso), "Write HTML build report"
        )

    def render(self, report: BuildReportLike, output_iso: Path) -> str:
        checksum = _sha256_text(output_iso)
        rows = "\n".join(
            "<tr>"
            f"<td>{escape(step.phase.value)}</td>"
            f"<td>{escape(step.title)}</td>"
            f"<td>{escape(step.detail)}</td>"
            "</tr>"
            for step in report.steps
        )
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>DistroForge Build Report</title>"
            "<style>body{font-family:sans-serif;margin:2rem;max-width:1100px;color:#202124}"
            ".summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem;margin:1rem 0}"
            ".box{border:1px solid #ccc;padding:1rem;background:#fafafa}"
            "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.45rem}"
            "th{background:#f4f4f4;text-align:left}</style></head><body>"
            f"<h1>{escape(self.project.name)}</h1>"
            "<div class='summary'>"
            f"<div class='box'><strong>Release</strong><br>{escape(self.project.release.label)}</div>"
            f"<div class='box'><strong>ISO</strong><br>{escape(str(output_iso))}</div>"
            f"<div class='box'><strong>SHA256</strong><br>{escape(checksum)}</div>"
            f"<div class='box'><strong>Phases</strong><br>{len(report.steps)}</div>"
            "</div>"
            "<table><thead><tr><th>Phase</th><th>Action</th><th>Detail</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></body></html>"
        )


def _sha256_text(path: Path) -> str:
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if sidecar.exists():
        return sidecar.read_text(encoding="utf-8").strip()
    sums = path.parent / "SHA256SUMS"
    if sums.exists():
        for line in sums.read_text(encoding="utf-8").splitlines():
            if path.name in line:
                return line.strip()
    return "not generated yet"
