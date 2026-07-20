from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .definition import load_definition, write_definition


@dataclass
class LiveBuildPlan:
    profile: Path
    output_dir: Path
    package_lists: list[str] = field(default_factory=list)
    hooks: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    config_files: list[dict[str, object]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "backend": "debian-live-build",
            "profile": str(self.profile),
            "output_dir": str(self.output_dir),
            "package_lists": self.package_lists,
            "hooks": self.hooks,
            "includes": self.includes,
            "config_files": self.config_files,
            "warnings": self.warnings,
        }

    def render_text(self) -> str:
        lines = [
            "Debian live-build plan",
            f"Profile: {self.profile}",
            f"Output: {self.output_dir}",
            "",
            "Package list entries:",
        ]
        lines.extend(f"- {item}" for item in self.package_lists) or lines.append("-")
        lines.extend(["", "Hooks:"])
        lines.extend(f"- {item}" for item in self.hooks) or lines.append("-")
        lines.extend(["", "Includes:"])
        lines.extend(f"- {item}" for item in self.includes) or lines.append("-")
        lines.extend(["", "Captured config files:"])
        lines.extend(f"- {item.get('path', '-')}" for item in self.config_files) or lines.append("-")
        if self.warnings:
            lines.extend(["", "Warnings:"])
            lines.extend(f"- {item}" for item in self.warnings)
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class LiveBuildPlanner:
    def plan(self, profile: Path, output_dir: Path) -> LiveBuildPlan:
        data = load_definition(profile)
        packages = [str(value) for value in data.get("packages", [])]
        extra = [str(value) for value in data.get("extra_install", [])]
        package_lists = sorted(set(packages + extra))
        capture = data.get("capture", {})
        included_configs = []
        if isinstance(capture, dict):
            included_configs = [str(value) for value in capture.get("included_configs", [])]
        config_files = [
            value for value in data.get("capture_config_files", []) if isinstance(value, dict)
        ]
        warnings = [
            "This is a plan only; live-build execution is intentionally not automatic.",
            "Review APT sources and included configs before running lb build.",
        ]
        return LiveBuildPlan(
            profile=profile,
            output_dir=output_dir,
            package_lists=package_lists,
            hooks=["config/hooks/live/9990-distroforge-sanitize.hook.chroot"],
            includes=included_configs,
            config_files=config_files,
            warnings=warnings,
        )

    def write_plan(self, plan: LiveBuildPlan) -> None:
        config_dir = plan.output_dir / "config"
        package_dir = config_dir / "package-lists"
        hook_dir = config_dir / "hooks/live"
        include_dir = config_dir / "includes.chroot"
        package_dir.mkdir(parents=True, exist_ok=True)
        hook_dir.mkdir(parents=True, exist_ok=True)
        include_dir.mkdir(parents=True, exist_ok=True)
        (package_dir / "distroforge.list.chroot").write_text(
            "\n".join(plan.package_lists) + "\n", encoding="utf-8"
        )
        (hook_dir / "9990-distroforge-sanitize.hook.chroot").write_text(
            "#!/bin/sh\nset -eu\nrm -f /etc/machine-id /var/lib/dbus/machine-id\n: > /etc/machine-id\n",
            encoding="utf-8",
        )
        for item in plan.config_files:
            path = str(item.get("path", "")).lstrip("/")
            content = item.get("content")
            if not path or not isinstance(content, str):
                continue
            target = include_dir / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            mode = item.get("mode")
            if isinstance(mode, str):
                target.chmod(int(mode, 8))
        write_definition(plan.to_dict(), plan.output_dir / "distroforge-live-build-plan.yaml")
