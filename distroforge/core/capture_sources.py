from __future__ import annotations

from pathlib import Path

from .capture_report import CaptureFinding


def capture_apt_sources(root: Path) -> tuple[list[str], list[CaptureFinding]]:
    findings: list[CaptureFinding] = []
    repositories: list[str] = []
    apt_dir = root / "etc/apt"
    candidates = [apt_dir / "sources.list"]
    sources_d = apt_dir / "sources.list.d"
    if sources_d.exists():
        candidates.extend(sorted(sources_d.glob("*.list")))
        candidates.extend(sorted(sources_d.glob("*.sources")))

    for path in candidates:
        display = "/" + str(path.relative_to(root)) if path.exists() else str(path)
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        active_lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if not active_lines:
            findings.append(CaptureFinding("apt-source", display, "ignored", "No active entries"))
            continue
        status = "captured"
        message = "Official-looking APT source"
        if any("signed-by=" not in line and line.startswith(("deb ", "Types:")) for line in active_lines):
            status = "needs review"
            message = "APT source lacks explicit signed-by metadata"
        if any("http://" in line for line in active_lines):
            status = "needs review"
            message = "APT source uses plain HTTP"
        repositories.extend(active_lines)
        findings.append(CaptureFinding("apt-source", display, status, message))
    return repositories, findings
