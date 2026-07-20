from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .definition import load_definition, write_definition


@dataclass
class LivefsIsoPlan:
    profile: Path
    work_dir: Path
    dest: Path
    series: str
    arch: str
    mirror: str
    components: list[str]
    disk_id: str
    project: str
    volume_id: str
    package_list: list[str] = field(default_factory=list)
    steps: list[dict[str, object]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "backend": "ubuntu-livefs-isobuild",
            "status": "plan-only",
            "profile": str(self.profile),
            "work_dir": str(self.work_dir),
            "dest": str(self.dest),
            "series": self.series,
            "arch": self.arch,
            "mirror": self.mirror,
            "components": self.components,
            "disk_id": self.disk_id,
            "project": self.project,
            "volume_id": self.volume_id,
            "package_list": self.package_list,
            "steps": self.steps,
            "warnings": self.warnings,
        }

    def render_text(self) -> str:
        lines = [
            "Ubuntu livefs ISO plan",
            f"Profile: {self.profile}",
            f"Work dir: {self.work_dir}",
            f"Destination ISO: {self.dest}",
            f"Series/arch: {self.series}/{self.arch}",
            f"Mirror: {self.mirror}",
            f"Components: {', '.join(self.components)}",
            f"Disk ID: {self.disk_id}",
            f"Volume ID: {self.volume_id}",
            "",
            "Steps:",
        ]
        lines.extend(f"- {step['name']}: {step['description']}" for step in self.steps)
        lines.extend(["", "Package pool intent:"])
        lines.extend(f"- {package}" for package in self.package_list) or lines.append("-")
        if self.warnings:
            lines.extend(["", "Warnings:"])
            lines.extend(f"- {warning}" for warning in self.warnings)
        return "\n".join(lines)

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class LivefsIsoPlanner:
    def plan(
        self,
        profile: Path,
        work_dir: Path,
        dest: Path,
        *,
        series: str | None = None,
        arch: str = "amd64",
        mirror: str = "http://archive.ubuntu.com/ubuntu",
        components: list[str] | None = None,
        disk_id: str | None = None,
        project: str | None = None,
        volume_id: str | None = None,
    ) -> LivefsIsoPlan:
        data = load_definition(profile)
        metadata = data.get("metadata", {})
        metadata = metadata if isinstance(metadata, dict) else {}
        resolved_series = series or str(metadata.get("codename") or metadata.get("release") or "resolute")
        resolved_project = project or _project_name(metadata)
        resolved_disk_id = disk_id or f"{resolved_project} {resolved_series} {arch}"
        resolved_volume_id = (volume_id or _volume_id(resolved_project, resolved_series, arch))[:32]
        package_list = sorted({str(value) for value in data.get("packages", [])})
        resolved_components = components or ["main", "restricted", "universe", "multiverse"]
        steps = [
            _step("init", "Create ISO skeleton, .disk metadata, and per-build signing key placeholder"),
            _step("setup-apt", "Prepare isolated apt state for the selected mirror and components"),
            _step("generate-pool", "Resolve package pool intent from captured/manual package list"),
            _step("generate-sources", "Write deb822 /cdrom source with embedded public signing key"),
            _step("add-live-filesystem", "Copy squashfs, kernel, initrd, and Casper metadata into /casper"),
            _step("make-bootable", "Stage GRUB/shim boot assets for BIOS and UEFI boot"),
            _step("make-iso", "Generate checksums and run xorriso with the planned volume ID"),
        ]
        warnings = [
            "This backend follows Ubuntu livefs ISO structure but does not run Launchpad/livecd-rootfs.",
            "Pool signing key generation and apt pool materialization require an explicit implementation step before publication.",
            "Validate online and offline installs in QEMU before distributing generated ISOs.",
        ]
        return LivefsIsoPlan(
            profile=profile,
            work_dir=work_dir,
            dest=dest,
            series=resolved_series,
            arch=arch,
            mirror=mirror,
            components=resolved_components,
            disk_id=resolved_disk_id,
            project=resolved_project,
            volume_id=resolved_volume_id,
            package_list=package_list,
            steps=steps,
            warnings=warnings,
        )

    def write_plan(self, plan: LivefsIsoPlan) -> None:
        iso_root = plan.work_dir / "iso-root"
        apt_dir = plan.work_dir / "apt"
        pool_dir = iso_root / "pool"
        dists_dir = iso_root / "dists" / plan.series
        casper_dir = iso_root / "casper"
        for path in (iso_root / ".disk", apt_dir, pool_dir, dists_dir, casper_dir, iso_root / "boot/grub"):
            path.mkdir(parents=True, exist_ok=True)
        (iso_root / ".disk/info").write_text(plan.disk_id + "\n", encoding="utf-8")
        (iso_root / ".disk/release_notes_url").write_text("https://example.invalid/release-notes\n", encoding="utf-8")
        (iso_root / "README.diskdefines").write_text(_render_diskdefines(plan), encoding="utf-8")
        (iso_root / ".disk/casper-uuid-generic").write_text("planned-livefs-uuid\n", encoding="utf-8")
        (dists_dir / "Release").write_text(_render_release_stub(plan), encoding="utf-8")
        (pool_dir / "README.distroforge").write_text("Package pool materialization remains manual.\n", encoding="utf-8")
        (iso_root / "boot/grub/grub.cfg").write_text(_render_grub_stub(plan), encoding="utf-8")
        (plan.work_dir / "package-list.txt").write_text(
            "\n".join(plan.package_list) + ("\n" if plan.package_list else ""),
            encoding="utf-8",
        )
        (plan.work_dir / "cdrom.sources").write_text(_render_cdrom_sources(plan), encoding="utf-8")
        (plan.work_dir / "isobuild-commands.txt").write_text(_render_commands(plan), encoding="utf-8")
        (casper_dir / "README.distroforge").write_text(
            "Place live filesystem artifacts here before make-iso.\n",
            encoding="utf-8",
        )
        (plan.work_dir / "manual-gates.txt").write_text(_render_manual_gates(plan), encoding="utf-8")
        write_definition(plan.to_dict(), plan.work_dir / "distroforge-livefs-iso-plan.yaml")


def _step(name: str, description: str) -> dict[str, object]:
    return {"name": name, "description": description}


def _project_name(metadata: dict[object, object]) -> str:
    name = str(metadata.get("name") or "DistroForge").replace("Captured ", "")
    return "".join(char for char in name if char.isalnum() or char in ("-", "_", " ")).strip() or "DistroForge"


def _volume_id(project: str, series: str, arch: str) -> str:
    value = f"{project} {series} {arch}".upper()
    return "".join(char if char.isalnum() else "_" for char in value)


def _render_cdrom_sources(plan: LivefsIsoPlan) -> str:
    return (
        "Types: deb\n"
        "URIs: file:/cdrom\n"
        f"Suites: {plan.series}\n"
        f"Components: {' '.join(plan.components)}\n"
        "Signed-By:\n"
        " -----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        " Planned per-build public key placeholder\n"
        " -----END PGP PUBLIC KEY BLOCK-----\n"
    )


def _render_commands(plan: LivefsIsoPlan) -> str:
    commands = [
        f'isobuild --work-dir "{plan.work_dir}" init --disk-id "{plan.disk_id}" --series "{plan.series}" --arch "{plan.arch}"',
        f'isobuild --work-dir "{plan.work_dir}" setup-apt --mirror "{plan.mirror}" --components "{" ".join(plan.components)}"',
        f'isobuild --work-dir "{plan.work_dir}" generate-pool --package-list-file "{plan.work_dir / "package-list.txt"}"',
        f'isobuild --work-dir "{plan.work_dir}" generate-sources --mountpoint "/cdrom"',
        f'isobuild --work-dir "{plan.work_dir}" add-live-filesystem --artifact-prefix "{plan.work_dir / "livefs"}"',
        f'isobuild --work-dir "{plan.work_dir}" make-bootable --project "{plan.project}" --capitalized-project "{plan.project.title()}" --subarch "{plan.arch}"',
        f'isobuild --work-dir "{plan.work_dir}" make-iso --vol-id "{plan.volume_id}" --dest "{plan.dest}"',
    ]
    return "\n".join(commands) + "\n"


def _render_diskdefines(plan: LivefsIsoPlan) -> str:
    return (
        "#define DISKNAME  " + plan.disk_id + "\n"
        "#define TYPE  binary\n"
        f"#define TYPEbinary  1\n#define ARCH  {plan.arch}\n#define ARCH" + plan.arch + "  1\n"
        "#define DISKNUM  1\n#define DISKCOUNT  1\n#define TOTALNUM  0\n#define TOTALCOUNT  1\n"
    )


def _render_release_stub(plan: LivefsIsoPlan) -> str:
    return (
        f"Origin: {plan.project}\n"
        f"Label: {plan.project}\n"
        f"Suite: {plan.series}\n"
        f"Codename: {plan.series}\n"
        f"Architectures: {plan.arch}\n"
        f"Components: {' '.join(plan.components)}\n"
        "Description: DistroForge planned livefs ISO repository\n"
    )


def _render_grub_stub(plan: LivefsIsoPlan) -> str:
    return (
        "set timeout=5\n"
        f'menuentry "{plan.project} live" {{\n'
        "  linux /casper/vmlinuz boot=casper quiet splash ---\n"
        "  initrd /casper/initrd\n"
        "}\n"
    )


def _render_manual_gates(plan: LivefsIsoPlan) -> str:
    return "\n".join(
        [
            "Manual gates before publication:",
            "- Generate per-build signing key and replace cdrom.sources placeholder.",
            "- Materialize pool/ with apt-ftparchive or equivalent.",
            "- Copy vmlinuz, initrd and squashfs into iso-root/casper.",
            "- Validate boot/grub assets for BIOS and UEFI.",
            "- Run QEMU live boot, offline install and online install scenarios.",
            f"- Build final ISO at {plan.dest}.",
            "",
        ]
    )
