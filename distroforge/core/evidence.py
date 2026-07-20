from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .artifact_paths import default_artifact_paths
from .build import BuildOptions
from .chroot import detect_chroot_backends
from .command import CommandRunner
from .doctor import (
    install_packages_for_debian_dev,
    manual_install_packages_for_debian_dev,
    run_debian_dev_doctor,
)
from .host import detect_host_capabilities
from .packaging import diagnose_autopkgtest, packaging_policy_report
from .project import Project
from .qemu_smoke import QemuSmokePlanner
from .release_gate import ReleaseGateService
from .release_readiness import ReleaseReadinessService

EVIDENCE_PROFILES = ("dev", "package", "iso", "publish")
CONTRACT_SCHEMA = "distroforge.hermetic-release-bundle.contract.v1"
_STATUS_ORDER = ("ready", "review", "blocked", "invalid")


@dataclass(frozen=True)
class EvidenceItem:
    code: str
    status: str
    detail: str
    path: Path | None = None

    @property
    def blocked(self) -> bool:
        return self.status in {"blocked", "invalid"}

    @property
    def needs_review(self) -> bool:
        return self.status == "review"

    @property
    def invalid(self) -> bool:
        return self.status == "invalid"

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "code": self.code,
            "status": self.status,
            "detail": self.detail,
        }
        if self.path is not None:
            payload["path"] = str(self.path)
        return payload


@dataclass
class EvidenceStatusReport:
    project: Path
    iso: Path
    output_dir: Path
    profile: str = "publish"
    items: list[EvidenceItem] = field(default_factory=list)

    @property
    def status(self) -> str:
        if any(item.invalid for item in self.items):
            return "invalid"
        if any(item.blocked for item in self.items):
            return "blocked"
        if any(item.needs_review for item in self.items):
            return "review"
        return "ready"

    @property
    def blocked(self) -> bool:
        return self.status in {"blocked", "invalid"}

    def counts(self) -> dict[str, int]:
        return {
            status: sum(1 for item in self.items if item.status == status)
            for status in _STATUS_ORDER
        }

    def next_actions(self, limit: int = 5) -> list[str]:
        actions: list[str] = []
        seen: set[str] = set()
        for status in ("invalid", "blocked", "review"):
            for item in self.items:
                if item.status != status:
                    continue
                action = _next_action(item)
                key = " ".join(action.lower().split())
                if key in seen:
                    continue
                seen.add(key)
                actions.append(action)
        return actions[:limit]

    def fix_plan(self) -> list[str]:
        commands: list[str] = []
        seen: set[str] = set()
        for status in ("invalid", "blocked", "review"):
            for item in self.items:
                if item.status != status:
                    continue
                command = _fix_plan_command(item, self)
                if not command or command in seen:
                    continue
                seen.add(command)
                commands.append(command)
        return commands

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "distroforge.evidence-status.v1",
            "project": str(self.project),
            "iso": str(self.iso),
            "output_dir": str(self.output_dir),
            "profile": self.profile,
            "status": self.status,
            "blocked": self.blocked,
            "counts": self.counts(),
            "next_actions": self.next_actions(),
            "fix_plan": self.fix_plan(),
            "items": [item.to_dict() for item in self.items],
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self, *, verbose: bool = False) -> str:
        counts = self.counts()
        lines = [
            "Evidence status",
            f"Project: {self.project}",
            f"Profile: {self.profile}",
            f"ISO: {self.iso}",
            f"Output: {self.output_dir}",
            f"Status: {self.status.upper()}",
            f"Summary: ready={counts['ready']} review={counts['review']} blocked={counts['blocked']} invalid={counts['invalid']}",
            "",
            "Next actions:",
        ]
        lines.extend(f"- {action}" for action in self.next_actions())
        if not self.next_actions():
            lines.append("- Evidence is ready.")
        lines.append("")
        visible = self.items if verbose else [item for item in self.items if item.status != "ready"]
        if verbose:
            lines.append("Items:")
        else:
            lines.append("Review and blocked items:")
        if visible:
            lines.extend(_format_item(item) for item in visible)
        else:
            lines.append("- none")
        if not verbose and counts["ready"]:
            lines.extend(["", f"{counts['ready']} ready items hidden; pass --verbose to show all evidence."])
        return "\n".join(lines)

    def render_fix_plan_text(self) -> str:
        lines = [
            "Evidence fix plan",
            f"Project: {self.project}",
            f"Profile: {self.profile}",
            "",
        ]
        commands = self.fix_plan()
        if commands:
            lines.extend(f"- {command}" for command in commands)
        else:
            lines.append("- No fix commands suggested; evidence is ready.")
        return "\n".join(lines)


class EvidenceStatusService:
    def check(
        self,
        project: Project,
        options: BuildOptions | None = None,
        *,
        iso: Path | None = None,
        output_dir: Path | None = None,
        profile: str = "publish",
    ) -> EvidenceStatusReport:
        profile = _normalize_profile(profile)
        options = options or BuildOptions()
        paths = default_artifact_paths(project)
        iso = iso or options.output_iso or paths.output_iso
        output_dir = output_dir or paths.reports_dir
        report = EvidenceStatusReport(project.root, iso, output_dir, profile)
        report.items.append(EvidenceItem("project", "ready", "DistroForge project metadata loaded.", project.root))
        if profile in {"package", "iso", "publish"}:
            report.items.extend(_host_items())
            report.items.extend(_backend_items())
        if profile in {"package", "publish"}:
            report.items.extend(_debian_dev_items(project.root))
        report.items.extend(_packaging_items(project.root))
        if profile in {"package", "publish"}:
            report.items.extend(_package_artifact_items(output_dir, project.root))
            report.items.extend(_autopkgtest_run_items(project.root, output_dir))
        if profile in {"iso", "publish"}:
            report.items.extend(_artifact_items(output_dir))
            report.items.extend(_qemu_items(iso))
            report.items.extend(_readiness_items(iso, output_dir))
            report.items.extend(_release_gate_items(project, options, iso, output_dir))
        if profile == "publish":
            report.items.extend(_publish_artifact_items(output_dir))
        report.items = _dedupe_items(report.items)
        return report

    def check_source_tree(
        self,
        root: Path,
        *,
        iso: Path | None = None,
        output_dir: Path | None = None,
        profile: str = "publish",
    ) -> EvidenceStatusReport:
        profile = _normalize_profile(profile)
        root = root.resolve()
        explicit_iso = iso is not None
        output_dir = (output_dir or root / "dist").resolve()
        iso = (iso or output_dir / f"{root.name}.iso").resolve()
        report = EvidenceStatusReport(root, iso, output_dir, profile)
        report.items.append(_source_tree_item(root))
        if profile in {"package", "iso", "publish"}:
            report.items.extend(_host_items())
            report.items.extend(_backend_items())
        if profile in {"package", "publish"}:
            report.items.extend(_debian_dev_items(root))
        report.items.extend(_packaging_items(root))
        if profile in {"package", "publish"}:
            report.items.extend(_package_artifact_items(output_dir, root))
            report.items.extend(_autopkgtest_run_items(root, output_dir))
        if profile in {"iso", "publish"}:
            report.items.extend(_artifact_items(output_dir))
            report.items.extend(_qemu_items(iso))
            report.items.extend(_readiness_items(iso, output_dir, block_missing_iso=explicit_iso or profile in {"iso", "publish"}))
        if profile == "publish":
            report.items.extend(_publish_artifact_items(output_dir))
        report.items = _dedupe_items(report.items)
        return report


@dataclass(frozen=True)
class EvidenceContractValidation:
    contract: Path
    base_dir: Path
    schema: str
    required_artifacts: tuple[str, ...]
    required_evidence: tuple[str, ...]
    missing_artifacts: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    errors: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        if self.errors:
            return "invalid"
        return "blocked" if self.missing_artifacts or self.missing_evidence else "ready"

    @property
    def blocked(self) -> bool:
        return self.status in {"blocked", "invalid"}

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": "distroforge.evidence-contract-validation.v1",
            "contract": str(self.contract),
            "base_dir": str(self.base_dir),
            "contract_schema": self.schema,
            "status": self.status,
            "blocked": self.blocked,
            "required_artifacts": list(self.required_artifacts),
            "required_evidence": list(self.required_evidence),
            "missing_artifacts": list(self.missing_artifacts),
            "missing_evidence": list(self.missing_evidence),
            "errors": list(self.errors),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Evidence contract validation",
            f"Contract: {self.contract}",
            f"Base: {self.base_dir}",
            f"Schema: {self.schema}",
            f"Status: {self.status.upper()}",
            "",
            "Contract errors:",
            *([f"- {error}" for error in self.errors] or ["- none"]),
            "",
            "Missing artifacts:",
            *([f"- {name}" for name in self.missing_artifacts] or ["- none"]),
            "",
            "Missing evidence:",
            *([f"- {name}" for name in self.missing_evidence] or ["- none"]),
        ]
        return "\n".join(lines)


def validate_evidence_contract(path: Path) -> EvidenceContractValidation:
    contract = _resolve_contract_path(path)
    base_dir = contract.parent
    try:
        data = json.loads(contract.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{contract} is not valid JSON: {exc.msg} at line {exc.lineno}, column {exc.colno}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{contract} must contain a JSON object")
    errors: list[str] = []
    schema = str(data.get("schema", "unknown"))
    if schema != CONTRACT_SCHEMA:
        errors.append(f"schema must be {CONTRACT_SCHEMA}")
    required_artifacts = _string_list(data, "required_artifacts", errors)
    required_evidence = _string_list(data, "required_evidence", errors)
    missing_artifacts = tuple(name for name in required_artifacts if not (base_dir / name).exists())
    missing_evidence = tuple(name for name in required_evidence if not (base_dir / name).exists())
    return EvidenceContractValidation(
        contract=contract,
        base_dir=base_dir,
        schema=schema,
        required_artifacts=required_artifacts,
        required_evidence=required_evidence,
        missing_artifacts=missing_artifacts,
        missing_evidence=missing_evidence,
        errors=tuple(errors),
    )


def _resolve_contract_path(path: Path) -> Path:
    if path.is_dir():
        candidate = path / "BUNDLE-CONTRACT.json"
        if candidate.exists():
            return candidate
        raise FileNotFoundError(f"No BUNDLE-CONTRACT.json found in {path}")
    return path


def _normalize_profile(profile: str) -> str:
    if profile not in EVIDENCE_PROFILES:
        raise ValueError(f"evidence profile must be one of: {', '.join(EVIDENCE_PROFILES)}")
    return profile


def _string_list(data: dict[str, object], key: str, errors: list[str]) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list):
        errors.append(f"{key} must be a list of relative file names")
        return ()
    names: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{key}[{index}] must be a non-empty string")
            continue
        candidate = Path(item)
        if candidate.is_absolute() or ".." in candidate.parts:
            errors.append(f"{key}[{index}] must be relative to the bundle directory")
            continue
        names.append(item)
    return tuple(names)


def _host_items() -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for capability in detect_host_capabilities(CommandRunner(dry_run=True)):
        status = "ready" if capability.available else "review"
        items.append(EvidenceItem(f"host:{capability.name}", status, capability.detail))
    return items


def _source_tree_item(root: Path) -> EvidenceItem:
    markers = ("pyproject.toml", "distroforge", "debian/control")
    missing = [marker for marker in markers if not (root / marker).exists()]
    if missing:
        return EvidenceItem("source-tree", "blocked", f"Missing source markers: {', '.join(missing)}", root)
    return EvidenceItem("source-tree", "ready", "DistroForge source tree markers found.", root)


def _backend_items() -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for backend in detect_chroot_backends():
        if backend.name == "auto":
            status = "ready"
        elif backend.active:
            status = "ready" if backend.available else "blocked"
        else:
            status = "ready" if backend.available else "review"
        selected = "selected" if backend.selected else "active" if backend.active else "available" if backend.available else "missing"
        items.append(EvidenceItem(f"chroot:{backend.name}", status, f"{selected}; {backend.detail}"))
    return items


def _debian_dev_items(root: Path) -> list[EvidenceItem]:
    report = run_debian_dev_doctor(CommandRunner(dry_run=True))
    missing_packages = install_packages_for_debian_dev(report)
    manual_packages = manual_install_packages_for_debian_dev(report)
    if not missing_packages and not manual_packages:
        return [
            EvidenceItem(
                "debian-dev-doctor",
                "ready",
                f"{len(report)} Debian/Ubuntu maintainer tools available",
                root,
            )
        ]
    details: list[str] = []
    if missing_packages:
        details.append(f"missing apt packages: {', '.join(missing_packages)}")
    if manual_packages:
        details.append(f"manual review packages: {', '.join(manual_packages)}")
    return [EvidenceItem("debian-dev-doctor", "review", "; ".join(details), root)]


def _artifact_items(output_dir: Path) -> list[EvidenceItem]:
    expected = (
        "SHA256SUMS",
        "BUILDINFO",
        "distroforge-provenance.json",
        "qemu-lab-report.json",
        "RELEASE-GATE.json",
        "BUNDLE-CONTRACT.json",
    )
    items: list[EvidenceItem] = []
    for name in expected:
        path = output_dir / name
        status = "ready" if path.exists() else "review"
        detail = f"{path.stat().st_size} bytes" if path.exists() else f"missing {name}"
        items.append(EvidenceItem(f"artifact:{name}", status, detail, path))
    return items


def _package_artifact_items(output_dir: Path, root: Path | None = None) -> list[EvidenceItem]:
    search_dirs = (output_dir,) if root is None else (output_dir, root.resolve().parent)
    checks = (
        ("package:deb", "Debian package", _any_exists_anywhere(search_dirs, "*.deb")),
        ("package:buildinfo", "Debian buildinfo", _any_exists_anywhere(search_dirs, "*.buildinfo") or (output_dir / "BUILDINFO-REPORT.txt").exists()),
        ("package:lintian", "Lintian report", (output_dir / "LINTIAN.txt").exists()),
        ("bundle-contract", "Evidence bundle contract", (output_dir / "BUNDLE-CONTRACT.json").exists()),
    )
    items: list[EvidenceItem] = []
    for code, label, available in checks:
        status = "ready" if available else "review"
        items.append(EvidenceItem(code, status, f"{label} {'found' if available else 'missing'}", output_dir))
    contract = output_dir / "BUNDLE-CONTRACT.json"
    if contract.exists():
        try:
            validation = validate_evidence_contract(contract)
        except ValueError as exc:
            items.append(EvidenceItem("bundle-contract-validation", "invalid", str(exc), contract))
        else:
            detail = "contract ready" if validation.status == "ready" else "; ".join((*validation.errors, *validation.missing_artifacts, *validation.missing_evidence))
            items.append(EvidenceItem("bundle-contract-validation", validation.status, detail or "contract needs review", contract))
    return items


def _autopkgtest_run_items(root: Path, output_dir: Path) -> list[EvidenceItem]:
    saved = output_dir / "AUTOPKGTEST-DOCTOR.json"
    if saved.exists():
        try:
            data = json.loads(saved.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return [EvidenceItem("autopkgtest-run", "invalid", f"Invalid AUTOPKGTEST-DOCTOR.json: {exc.msg}", saved)]
        status = str(data.get("status", "unknown"))
        classification = str(data.get("classification", "unknown"))
        detail = str(data.get("detail", ""))
        evidence_status = "ready" if status == "passed" else "blocked" if status == "test-failed" else "review"
        return [
            EvidenceItem(
                "autopkgtest-run",
                evidence_status,
                f"{status}: {classification}" + (f" - {detail}" if detail else ""),
                saved,
            )
        ]
    report = diagnose_autopkgtest(root, execute=False)
    if report.status == "missing-deb":
        return [EvidenceItem("autopkgtest-run", "review", "No package artifact available for autopkgtest run.", root)]
    if report.status == "missing-tool":
        return [EvidenceItem("autopkgtest-run", "review", report.detail, root)]
    return [
        EvidenceItem(
            "autopkgtest-run",
            "review",
            "Autopkgtest execution evidence missing; run autopkgtest-doctor --execute to classify the testbed.",
            output_dir,
        )
    ]


def _publish_artifact_items(output_dir: Path) -> list[EvidenceItem]:
    expected = (
        "MANIFEST.json",
        "SHA256SUMS",
        "RELEASE-NOTES.md",
        "VERIFY-REPORT.txt",
        "PUBLISH-DRILL.json",
    )
    return [
        EvidenceItem(
            f"publish:{name}",
            "ready" if (output_dir / name).exists() else "review",
            f"{name} {'found' if (output_dir / name).exists() else 'missing'}",
            output_dir / name,
        )
        for name in expected
    ]


def _any_exists(root: Path, pattern: str) -> bool:
    return any(root.glob(pattern))


def _any_exists_anywhere(roots: tuple[Path, ...], pattern: str) -> bool:
    return any(_any_exists(root, pattern) for root in roots if root.exists())


def _packaging_items(root: Path) -> list[EvidenceItem]:
    if not (root / "debian/control").exists():
        return [EvidenceItem("packaging", "review", "No Debian packaging metadata in project root.")]
    buildinfo = _latest_package_artifact(root, "distroforge_*_*.buildinfo")
    changes = _latest_package_artifact(root, "distroforge_*_*.changes")
    policy = packaging_policy_report(root, buildinfo, changes)
    items = [
        EvidenceItem(
            "packaging-policy",
            "blocked" if policy.blocked else "ready",
            "blocked" if policy.blocked else "policy checks pass",
            )
        ]
    if policy.autopkgtest_policy:
        autopkgtest_status = policy.autopkgtest_policy.status
        status = "ready" if autopkgtest_status == "declared and meaningful" else "review"
        if autopkgtest_status in {"undeclared", "declared but weak"}:
            status = "blocked"
        items.append(EvidenceItem("autopkgtest", status, autopkgtest_status))
    if policy.buildinfo and policy.buildinfo.tainted:
        items.append(
            EvidenceItem(
                "buildinfo-taint",
                "review",
                ", ".join(policy.buildinfo.tainted_by),
                policy.buildinfo.path,
            )
        )
    return items


def _latest_package_artifact(root: Path, pattern: str) -> Path | None:
    values = list(root.resolve().parent.glob(pattern))
    if not values:
        return None
    return max(values, key=lambda path: (path.stat().st_mtime_ns, path.name))


def _qemu_items(iso: Path) -> list[EvidenceItem]:
    plan = QemuSmokePlanner().plan(iso)
    return [
        EvidenceItem("qemu-smoke-plan", "review", f"{len(plan.scenarios)} planned scenarios"),
        *[
            EvidenceItem(
                f"qemu:{scenario.name}",
                "review",
                f"{scenario.firmware} {'online' if scenario.network else 'offline'} {scenario.install_mode}",
            )
            for scenario in plan.scenarios
        ],
    ]


def _readiness_items(iso: Path, output_dir: Path, *, block_missing_iso: bool = True) -> list[EvidenceItem]:
    readiness = ReleaseReadinessService().check(iso, output_dir)
    items: list[EvidenceItem] = []
    for item in readiness.items:
        status = "blocked" if item.status == "blocked" else "review"
        if not block_missing_iso and item.name in {"iso", "sha256"} and status == "blocked":
            status = "review"
        items.append(EvidenceItem(f"readiness:{item.name}", status, item.detail))
    return items


def _release_gate_items(project: Project, options: BuildOptions, iso: Path, output_dir: Path) -> list[EvidenceItem]:
    gate = ReleaseGateService().check(project, options, iso=iso, output_dir=output_dir)
    return [
        EvidenceItem(f"release-gate:{item.code}", item.status, item.detail)
        for item in gate.items
    ]


def _format_item(item: EvidenceItem) -> str:
    path = f" ({item.path})" if item.path is not None else ""
    return f"[{item.status}] {item.code}: {item.detail}{path}"


def _dedupe_items(items: list[EvidenceItem]) -> list[EvidenceItem]:
    artifact_codes = {item.code for item in items if item.code.startswith("artifact:")}
    readiness_codes = {item.code for item in items if item.code.startswith("readiness:")}
    result: list[EvidenceItem] = []
    seen_codes: set[str] = set()
    for item in items:
        if item.code in seen_codes:
            continue
        if item.code == "artifact:SHA256SUMS" and {"readiness:sha256", "readiness:sha256sums"} & readiness_codes and item.status != "ready":
            continue
        if item.code in {"readiness:sha256", "readiness:sha256sums"} and "artifact:SHA256SUMS" in artifact_codes and item.status != "blocked":
            continue
        if item.code in {"readiness:buildinfo", "readiness:qemu-lab-report.json", "readiness:provenance.json"} and item.status != "blocked":
            continue
        if item.code == "readiness:qemu-smoke" and "qemu-smoke-plan" in {existing.code for existing in items}:
            continue
        seen_codes.add(item.code)
        result.append(item)
    return result


def _next_action(item: EvidenceItem) -> str:
    if item.status == "invalid":
        return f"Fix invalid evidence contract data for {item.code}: {item.detail}"
    if item.code == "source-tree":
        return item.detail
    if item.code == "debian-dev-doctor":
        return "Review Debian/Ubuntu maintainer tooling before release rehearsal."
    if item.code == "buildinfo-taint":
        return "Rebuild in a hermetic sbuild/pbuilder/mmdebstrap environment before publication."
    if item.code == "autopkgtest-run":
        if "test-failed" in item.detail:
            return "Fix debian/tests/* or package dependencies, then rerun autopkgtest-doctor."
        return "Run autopkgtest-doctor with a writable schroot/qemu backend and store the report."
    if item.code.startswith("package:") or item.code.startswith("bundle-contract"):
        return "Create or verify a hermetic release bundle before package review."
    if item.code.startswith("publish:"):
        return "Prepare publish evidence, then run verify-release before publication."
    if item.code.startswith("artifact:"):
        name = item.code.split(":", 1)[1]
        return f"Capture or generate {name} when preparing release evidence."
    if item.code.startswith("readiness:iso") or item.code.startswith("release-gate:iso"):
        return "Select an existing ISO with --iso or produce one through the guarded ISO workflow."
    if item.code.startswith("readiness:sha256") or item.code.startswith("release-gate:sha256"):
        return "Generate SHA256SUMS for the selected ISO before publication review."
    if item.code == "packaging-policy":
        return "Run packaging-policy and fix blocked Debian source checks."
    if item.code == "autopkgtest":
        return "Strengthen debian/tests/smoke until autopkgtest is declared and meaningful."
    if item.code.startswith("qemu:") or item.code == "qemu-smoke-plan":
        return "Review the planned QEMU smoke matrix; execute boot proof only when release evidence is needed."
    if item.code.startswith("release-gate:boot-proof"):
        return "Plan or run boot-proof in dry-run/source mode before treating artifacts as publishable."
    if item.code.startswith("host:") or item.code.startswith("chroot:"):
        return f"Review host capability: {item.detail}"
    return f"Review {item.code}: {item.detail}"


def _fix_plan_command(item: EvidenceItem, report: EvidenceStatusReport) -> str | None:
    root = report.project
    iso = report.iso
    output = report.output_dir
    if item.status == "invalid":
        return f"distroforge evidence-verify {output}"
    if item.code.startswith("readiness:iso") or item.code.startswith("release-gate:iso"):
        return f"distroforge iso-build {root} --boot-proof none"
    if item.code in {"packaging-policy", "autopkgtest"}:
        return f"distroforge packaging-policy {root}"
    if item.code == "debian-dev-doctor":
        return "distroforge doctor --debian-dev --install"
    if item.code == "buildinfo-taint":
        return f"distroforge hermetic-build-plan {root} --backend sbuild --suite unstable"
    if item.code == "autopkgtest-run":
        return f"distroforge autopkgtest-doctor {root} --backend schroot --execute --output {output / 'AUTOPKGTEST-DOCTOR.json'}"
    if item.code.startswith("package:") or item.code.startswith("bundle-contract"):
        return f"distroforge hermetic-release-bundle {root} --output {output}"
    if item.code.startswith("artifact:") or item.code.startswith("readiness:"):
        return f"distroforge release-readiness --iso {iso} --output-dir {output}"
    if item.code.startswith("qemu:") or item.code == "qemu-smoke-plan":
        return f"distroforge qemu-smoke-plan --iso {iso}"
    if item.code.startswith("release-gate:"):
        return f"distroforge release-gate {root} --iso {iso} --output-dir {output}"
    if item.code.startswith("publish:"):
        return f"distroforge verify-release {root} --bundle-dir {output}"
    if item.code.startswith(("host:", "chroot:")):
        return "distroforge host && distroforge chroot-backends"
    return None
