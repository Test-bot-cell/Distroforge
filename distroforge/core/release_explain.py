from __future__ import annotations

import json
import os
import shlex
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .artifact_paths import default_output_iso
from .artifact_verification import (
    ArtifactIdentity,
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .evidence_run import (
    StableParentIdentity,
    is_safe_run_id,
    publish_regular_text,
)
from .project import Project
from .release_signing import full_fingerprint
from .release_verification import ReleaseVerifyReport, verify_release_bundle

_EXPLAIN_JSON_MAX_BYTES = 16 * 1024 * 1024
_EXPLAIN_LIMITS = ArtifactLimits(
    max_open_files=16,
    max_file_bytes=_EXPLAIN_JSON_MAX_BYTES,
    max_buffered_bytes=4 * _EXPLAIN_JSON_MAX_BYTES,
    max_hashed_bytes=8 * _EXPLAIN_JSON_MAX_BYTES,
    max_json_depth=256,
    max_json_nodes=1_000_000,
    max_closing_fds=64,
)


@dataclass(frozen=True)
class ReleaseExplainReport:
    project: Path
    iso: Path
    bundle_dir: Path
    status: str
    markdown: Path
    ready: tuple[str, ...]
    review: tuple[str, ...]
    blocked: tuple[str, ...]
    boot_proof: dict[str, str]
    next_commands: tuple[str, ...]

    @property
    def blocked_release(self) -> bool:
        return self.status == "blocked"

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "iso": str(self.iso),
            "bundle_dir": str(self.bundle_dir),
            "status": self.status,
            "blocked": self.blocked_release,
            "markdown": str(self.markdown),
            "ready": list(self.ready),
            "review": list(self.review),
            "blocked_items": list(self.blocked),
            "boot_proof": self.boot_proof,
            "next_commands": list(self.next_commands),
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Release evidence explanation",
            f"Project: {self.project}",
            f"ISO: {self.iso}",
            f"Bundle: {self.bundle_dir}",
            f"Status: {self.status.upper()}",
            f"Markdown: {self.markdown}",
            "",
            "Boot proof:",
            f"- status: {self.boot_proof.get('status', 'missing')}",
            f"- selected backend: {self.boot_proof.get('selected_backend', 'unknown')}",
            f"- proof level: {self.boot_proof.get('proof_level', 'none')}",
            "",
            "Ready:",
            *([f"- {item}" for item in self.ready] or ["- none"]),
            "",
            "Review:",
            *([f"- {item}" for item in self.review] or ["- none"]),
            "",
            "Blocked:",
            *([f"- {item}" for item in self.blocked] or ["- none"]),
            "",
            "Next commands:",
            *[f"- {item}" for item in self.next_commands],
        ]
        return "\n".join(lines)


def explain_release(
    project: Project,
    *,
    iso: Path | None = None,
    bundle_dir: Path | None = None,
    write: bool = True,
    expected_bundle_identity: StableParentIdentity | None = None,
    expected_signer_fingerprint: str | None = None,
    verification: ReleaseVerifyReport | None = None,
) -> ReleaseExplainReport:
    iso = Path(os.path.abspath(iso or default_output_iso(project)))
    bundle_dir = Path(
        os.path.abspath(bundle_dir or project.output_dir / "publish")
    )
    authoritative = verification or verify_release_bundle(
        project,
        bundle_dir=bundle_dir,
        expected_signer_fingerprint=expected_signer_fingerprint,
        expected_bundle_identity=expected_bundle_identity,
        expected_product_iso=iso,
        expected_product_output_dir=iso.parent,
    )
    authority_problems: list[str] = []
    if Path(os.path.abspath(authoritative.bundle_dir)) != Path(
        os.path.abspath(bundle_dir)
    ):
        authority_problems.append(
            "verify: live verification belongs to a different bundle"
        )
    if authoritative.bundle_identity is None:
        authority_problems.append(
            "verify: live descriptor verification did not seal a bundle identity"
        )
    elif (
        expected_bundle_identity is not None
        and authoritative.bundle_identity != expected_bundle_identity
    ):
        authority_problems.append(
            "verify: live verification differs from the published bundle receipt"
        )
    reports, read_problems = _read_bundle_reports(
        bundle_dir,
        expected_bundle_identity=(
            authoritative.bundle_identity or expected_bundle_identity
        ),
    )
    gate = reports.get("release-gate", {})
    boot = reports.get("boot-proof", {})
    manifest = reports.get("manifest", {})
    verify = reports.get("verify", {})
    ready: list[str] = []
    review: list[str] = []
    blocked = [*authority_problems, *read_problems]
    inputs_valid = not blocked
    build_run_id = _selected_run_id(gate.get("build_run_id"))
    boot_run_id = _selected_run_id(gate.get("boot_run_id"))
    if gate.get("build_run_id") is not None and build_run_id is None:
        blocked.append("release-gate: selected build run id is unsafe")
        inputs_valid = False
    if gate.get("boot_run_id") is not None and boot_run_id is None:
        blocked.append("release-gate: selected boot run id is unsafe")
        inputs_valid = False
    gate_problem = _verdict_contract_problem(
        "release-gate",
        gate,
        unique_codes=True,
    )
    verify_problem = _verdict_contract_problem(
        "verify",
        verify,
        unique_codes=False,
    )
    manifest_problem = _manifest_contract_problem(manifest, gate)
    if verify != authoritative.to_dict():
        authority_problem = (
            "verify: VERIFY-REPORT.json does not reproduce the live "
            "descriptor-bound verification"
        )
        blocked.append(authority_problem)
        inputs_valid = False
    for problem in (gate_problem, verify_problem, manifest_problem):
        if problem is not None:
            blocked.append(problem)
            inputs_valid = False
    if gate_problem is None and verify_problem is None:
        resolved_publish_signing = (
            authoritative.status == "ready"
            and any(
                item.code == "gate-status"
                and item.status == "ready"
                and "pre-signing" in item.detail
                for item in authoritative.items
            )
        )
        ready, review, report_blocked = _collect_items(
            gate,
            verify,
            resolved_publish_signing=resolved_publish_signing,
        )
        blocked.extend(report_blocked)
    boot_summary = _boot_summary(boot)
    if boot_summary["status"] == "missing":
        blocked.append("boot-proof: boot-proof.json is missing")
    elif (
        boot_summary["status"] != "ready"
        or boot_summary["proof_level"] != "runtime"
    ):
        blocked.append(
            "boot-proof: "
            f"{boot_summary['status']}/{boot_summary['proof_level']} via "
            f"{boot_summary['selected_backend']}"
        )
    else:
        ready.append(f"boot-proof: {boot_summary['proof_level']} proof via {boot_summary['selected_backend']}")
    status = "blocked" if blocked else "review" if review else "ready"
    commands = _next_commands(
        project,
        iso,
        bundle_dir,
        status,
        boot_summary,
        blocked,
        review,
        build_run_id=build_run_id,
        boot_run_id=boot_run_id,
        expected_signer_fingerprint=expected_signer_fingerprint,
    )
    markdown = bundle_dir / "RELEASE-EXPLAIN.md"
    report = ReleaseExplainReport(project.root, iso, bundle_dir, status, markdown, tuple(ready), tuple(review), tuple(blocked), boot_summary, tuple(commands))
    if write and inputs_valid:
        try:
            publish_regular_text(
                markdown,
                _markdown(report),
                expected_parent_identity=authoritative.bundle_identity,
            )
        except (OSError, ValueError) as exc:
            blocked.append(
                f"explanation-output: RELEASE-EXPLAIN.md was not published: {exc}"
            )
            status = "blocked"
            commands = _next_commands(
                project,
                iso,
                bundle_dir,
                status,
                boot_summary,
                blocked,
                review,
                build_run_id=build_run_id,
                boot_run_id=boot_run_id,
                expected_signer_fingerprint=expected_signer_fingerprint,
            )
            report = ReleaseExplainReport(
                project.root,
                iso,
                bundle_dir,
                status,
                markdown,
                tuple(ready),
                tuple(review),
                tuple(blocked),
                boot_summary,
                tuple(commands),
            )
    return report


def _read_bundle_reports(
    bundle_dir: Path,
    *,
    expected_bundle_identity: StableParentIdentity | None = None,
) -> tuple[dict[str, dict[str, object]], tuple[str, ...]]:
    absolute_bundle = Path(os.path.abspath(bundle_dir))
    reports: dict[str, dict[str, object]] = {}
    problems: list[str] = []
    session: ArtifactVerificationSession | None = None
    try:
        session = ArtifactVerificationSession(
            absolute_bundle,
            label="release explanation inputs",
            limits=_EXPLAIN_LIMITS,
        )
        if (
            expected_bundle_identity is not None
            and _stable_directory_identity(session.anchor_identity)
            != expected_bundle_identity
        ):
            raise ArtifactVerificationError(
                "release explanation bundle differs from the published receipt"
            )
        for code, name in (
            ("release-gate", "RELEASE-GATE.json"),
            ("boot-proof", "boot-proof.json"),
            ("manifest", "RELEASE-MANIFEST.json"),
            ("verify", "VERIFY-REPORT.json"),
        ):
            try:
                reports[code] = session.file(
                    Path(name),
                    label=f"release explanation {name}",
                    max_bytes=_EXPLAIN_JSON_MAX_BYTES,
                ).json_object()
            except (ArtifactVerificationError, OSError, ValueError) as exc:
                reports[code] = {}
                problems.append(
                    f"{code}: {name} is missing, unsafe, or invalid: {exc}"
                )
        session.seal()
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        problems.append(f"artifact-session: release bundle did not seal: {exc}")
    finally:
        if session is not None:
            session.close()
    return reports, tuple(problems)


def _stable_directory_identity(
    identity: ArtifactIdentity,
) -> StableParentIdentity:
    return (
        identity.dev,
        identity.ino,
        stat.S_IFMT(identity.mode),
        identity.uid,
        identity.gid,
        identity.nlink,
        identity.rdev,
    )


def _verdict_contract_problem(
    label: str,
    report: dict[str, object],
    *,
    unique_codes: bool,
) -> str | None:
    if not report:
        return f"{label}: required verdict report is missing or invalid"
    status = report.get("status")
    blocked = report.get("blocked")
    if (
        status not in {"ready", "review", "blocked"}
        or not isinstance(blocked, bool)
        or blocked is not (status == "blocked")
    ):
        return f"{label}: aggregate status and blocked flag are not strict"
    raw_items = report.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        return f"{label}: verdict items are missing or empty"
    item_statuses: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        if not isinstance(item, dict):
            return f"{label}: verdict contains a non-object item"
        code = item.get("code")
        item_status = item.get("status")
        detail = item.get("detail")
        if (
            not isinstance(code, str)
            or not code
            or (unique_codes and code in seen)
            or item_status not in {"ready", "review", "blocked"}
            or not isinstance(detail, str)
            or not detail
        ):
            return f"{label}: verdict item fields are malformed or contradictory"
        seen.add(code)
        item_statuses.append(item_status)
    derived = (
        "blocked"
        if "blocked" in item_statuses
        else "review"
        if "review" in item_statuses
        else "ready"
    )
    if derived != status:
        return f"{label}: aggregate status contradicts its item verdicts"
    return None


def _manifest_contract_problem(
    manifest: dict[str, object],
    gate: dict[str, object],
) -> str | None:
    if not manifest:
        return "manifest: required release manifest is missing or invalid"
    gate_status = gate.get("status")
    if (
        gate_status not in {"ready", "review", "blocked"}
        or manifest.get("gate_status") != gate_status
    ):
        return "manifest: gate status does not match RELEASE-GATE.json"
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        return "manifest: file snapshot is missing or empty"
    seen: set[str] = set()
    for entry in raw_files:
        if not isinstance(entry, dict):
            return "manifest: file snapshot contains a non-object entry"
        name = entry.get("name")
        size = entry.get("size")
        digest = entry.get("sha256")
        if (
            not isinstance(name, str)
            or not name
            or name in seen
            or "\\" in name
            or "\x00" in name
            or Path(name).is_absolute()
            or Path(name).as_posix() != name
            or any(part in {"", ".", ".."} for part in Path(name).parts)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(digest, str)
            or len(digest) != 64
            or digest != digest.lower()
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            return "manifest: file snapshot contains an unsafe or malformed entry"
        seen.add(name)
    return None


def _collect_items(
    *reports: dict[str, object],
    resolved_publish_signing: bool = False,
) -> tuple[list[str], list[str], list[str]]:
    ready: list[str] = []
    review: list[str] = []
    blocked: list[str] = []
    for report_index, report in enumerate(reports):
        for item in report.get("items", []) if isinstance(report, dict) else []:
            if not isinstance(item, dict):
                continue
            if (
                resolved_publish_signing
                and report_index == 0
                and item.get("code") == "publish-signing"
                and item.get("status") == "review"
            ):
                ready.append(
                    "publish-signing: resolved by terminal descriptor-bound "
                    "signature verification"
                )
                continue
            entry = f"{item.get('code', 'item')}: {item.get('detail', '')}".strip()
            status = str(item.get("status", "review"))
            if status == "ready":
                ready.append(entry)
            elif status == "blocked":
                blocked.append(entry)
            else:
                review.append(entry)
    return ready, review, blocked


def _boot_summary(data: dict[str, object]) -> dict[str, str]:
    if not data:
        return {"status": "missing", "selected_backend": "unknown", "proof_level": "none", "attempted_backends": ""}
    attempted = data.get("attempted_backends", [])
    return {
        "status": str(data.get("status", "unknown")),
        "selected_backend": str(data.get("selected_backend", data.get("backend", "unknown"))),
        "proof_level": str(data.get("proof_level", "none")),
        "attempted_backends": ", ".join(str(item) for item in attempted) if isinstance(attempted, list) else str(attempted),
    }


def _selected_run_id(value: object) -> str | None:
    if value is None:
        return None
    if not is_safe_run_id(value):
        return None
    assert isinstance(value, str)
    return value


def _next_commands(
    project: Project,
    iso: Path,
    bundle_dir: Path,
    status: str,
    boot: dict[str, str],
    blocked: list[str],
    review: list[str],
    *,
    build_run_id: str | None = None,
    boot_run_id: str | None = None,
    expected_signer_fingerprint: str | None = None,
) -> list[str]:
    root = str(project.root)
    product_iso = str(iso)
    product_output_dir = str(iso.parent)
    signer_fingerprint = (
        full_fingerprint(expected_signer_fingerprint) or "FULL_FINGERPRINT"
    )
    commands: list[str] = []
    if boot.get("proof_level") != "runtime":
        command = [
            "distroforge",
            "boot-proof",
            root,
            "--iso",
            product_iso,
            "--backend",
            "qemu",
        ]
        if build_run_id is not None:
            command.extend(["--build-run-id", build_run_id])
        commands.append(shlex.join(command))
    if any(
        "sha256" in item.lower() or "release file" in item.lower()
        for item in blocked
    ):
        command = [
            "distroforge",
            "release-pipeline",
            root,
            "--iso",
            product_iso,
            "--output-dir",
            product_output_dir,
            "--bundle-dir",
            str(bundle_dir),
        ]
        if build_run_id is not None:
            command.extend(["--build-run-id", build_run_id])
        if boot_run_id is not None:
            command.extend(["--boot-run-id", boot_run_id])
        else:
            command.extend(["--run-boot-proof", "--boot-backend", "auto"])
        commands.append(shlex.join(command))
    if status != "ready":
        command = [
            "distroforge",
            "release-gate",
            root,
            "--iso",
            product_iso,
            "--output-dir",
            product_output_dir,
            "--bundle-dir",
            str(bundle_dir),
        ]
        if build_run_id is not None:
            command.extend(["--build-run-id", build_run_id])
        if boot_run_id is not None:
            command.extend(["--boot-run-id", boot_run_id])
        commands.append(shlex.join(command))
    if review or any("signature" in item.lower() for item in blocked):
        commands.append(
            shlex.join(
                (
                    "distroforge",
                    "sign-release",
                    root,
                    "--bundle-dir",
                    str(bundle_dir),
                    "--iso",
                    product_iso,
                    "--output-dir",
                    product_output_dir,
                    "--gpg-key",
                    signer_fingerprint,
                    "--gpg-keyring",
                    "/path/to/public-keyring.gpg",
                    "--execute",
                )
            )
        )
    commands.append(
        shlex.join(
            (
                "distroforge",
                "verify-release",
                root,
                "--bundle-dir",
                str(bundle_dir),
                "--iso",
                product_iso,
                "--output-dir",
                product_output_dir,
                "--gpg-fingerprint",
                signer_fingerprint,
            )
        )
    )
    return commands


def _markdown(report: ReleaseExplainReport) -> str:
    lines = [
        f"# {report.project.name} Release Evidence",
        "",
        f"- Status: **{report.status.upper()}**",
        f"- ISO: `{report.iso}`",
        f"- Bundle: `{report.bundle_dir}`",
        f"- Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## Boot Proof",
        f"- Status: {report.boot_proof.get('status', 'missing')}",
        f"- Selected backend: {report.boot_proof.get('selected_backend', 'unknown')}",
        f"- Proof level: {report.boot_proof.get('proof_level', 'none')}",
        f"- Attempted backends: {report.boot_proof.get('attempted_backends', '') or 'none'}",
        "",
        "## Ready",
        *([f"- {item}" for item in report.ready] or ["- none"]),
        "",
        "## Review",
        *([f"- {item}" for item in report.review] or ["- none"]),
        "",
        "## Blocked",
        *([f"- {item}" for item in report.blocked] or ["- none"]),
        "",
        "## Next Commands",
        "```bash",
        *report.next_commands,
        "```",
        "",
    ]
    return "\n".join(lines)
