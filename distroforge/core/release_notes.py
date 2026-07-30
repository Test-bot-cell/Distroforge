from __future__ import annotations

import json
import os
import shlex
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .artifact_verification import (
    ArtifactIdentity,
    ArtifactLimits,
    ArtifactVerificationError,
    ArtifactVerificationSession,
)
from .evidence_run import StableParentIdentity, publish_regular_text
from .project import Project
from .release_explain import (
    _manifest_contract_problem,
    _verdict_contract_problem,
)
from .release_signing import SIGN_TARGETS

_NOTES_JSON_MAX_BYTES = 16 * 1024 * 1024
_NOTES_TEXT_MAX_BYTES = 16 * 1024 * 1024
_NOTES_LIMITS = ArtifactLimits(
    max_open_files=16,
    max_file_bytes=max(_NOTES_JSON_MAX_BYTES, _NOTES_TEXT_MAX_BYTES),
    max_buffered_bytes=5 * _NOTES_JSON_MAX_BYTES,
    max_hashed_bytes=10 * _NOTES_JSON_MAX_BYTES,
    max_json_depth=256,
    max_json_nodes=1_000_000,
    max_closing_fds=64,
)


@dataclass(frozen=True)
class ReleaseNotesReport:
    project: Path
    bundle_dir: Path
    notes: Path
    changelog: Path
    status: str
    blockers: tuple[str, ...]
    written: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "project": str(self.project),
            "bundle_dir": str(self.bundle_dir),
            "notes": str(self.notes),
            "changelog": str(self.changelog),
            "status": self.status,
            "blockers": list(self.blockers),
            "written": self.written,
        }

    def render_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def render_text(self) -> str:
        lines = [
            "Maintainer release notes",
            f"Project: {self.project}",
            f"Bundle: {self.bundle_dir}",
            f"Status: {self.status.upper()}",
            f"Notes: {self.notes}",
            f"Changelog: {self.changelog}",
            "",
            "Blockers:",
            *([f"- {item}" for item in self.blockers] or ["- none"]),
        ]
        return "\n".join(lines)


def write_release_notes(
    project: Project,
    *,
    bundle_dir: Path | None = None,
    expected_bundle_identity: StableParentIdentity | None = None,
    manifest_override: dict[str, object] | None = None,
    signing_override: dict[str, object] | None = None,
) -> ReleaseNotesReport:
    bundle_dir = bundle_dir or project.output_dir / "publish"
    notes_path = bundle_dir / "RELEASE-NOTES.md"
    changelog_path = bundle_dir / "CHANGELOG.txt"
    try:
        bundle_identity = bundle_dir.lstat()
    except FileNotFoundError:
        return ReleaseNotesReport(
            project.root,
            bundle_dir,
            notes_path,
            changelog_path,
            "blocked",
            ("publish-bundle: complete bundle directory is missing",),
            False,
        )
    if not stat.S_ISDIR(bundle_identity.st_mode):
        return ReleaseNotesReport(
            project.root,
            bundle_dir,
            notes_path,
            changelog_path,
            "blocked",
            ("publish-bundle: bundle path is not a safe directory",),
            False,
        )
    inputs, input_problems, input_bundle_identity = _read_notes_inputs(
        bundle_dir,
        expected_bundle_identity=expected_bundle_identity,
        read_manifest=manifest_override is None,
        read_signing=signing_override is None,
    )
    if manifest_override is not None:
        inputs["manifest"] = manifest_override
    if signing_override is not None:
        inputs["signing"] = signing_override
    manifest_value = inputs.get("manifest")
    gate_value = inputs.get("gate")
    signing_value = inputs.get("signing")
    manifest = manifest_value if isinstance(manifest_value, dict) else {}
    gate = gate_value if isinstance(gate_value, dict) else {}
    signing = signing_value if isinstance(signing_value, dict) else {}
    buildinfo_value = inputs.get("buildinfo", "")
    buildinfo = buildinfo_value if isinstance(buildinfo_value, str) else ""
    provenance = inputs.get("provenance", {})
    if not isinstance(provenance, dict):
        provenance = {}
    problems = list(input_problems)
    gate_problem = _verdict_contract_problem(
        "release-gate",
        gate,
        unique_codes=True,
    )
    manifest_problem = _manifest_contract_problem(manifest, gate)
    signing_problem = _signing_contract_problem(signing)
    problems.extend(
        problem
        for problem in (gate_problem, manifest_problem, signing_problem)
        if problem is not None
    )
    if input_bundle_identity is None:
        problems.append(
            "artifact-session: release notes have no sealed bundle identity"
        )
    if problems:
        return ReleaseNotesReport(
            project.root,
            bundle_dir,
            notes_path,
            changelog_path,
            "blocked",
            tuple(problems),
            False,
        )
    status = str(gate.get("status") or manifest.get("gate_status") or "unknown")
    blockers = tuple(
        f"{item.get('code', 'unknown')}: {item.get('detail', '')}"
        for item in gate.get("items", [])
        if isinstance(item, dict) and item.get("status") == "blocked"
    )
    try:
        publish_regular_text(
            notes_path,
            _notes(
                project,
                bundle_dir,
                manifest,
                gate,
                signing,
                buildinfo,
                provenance,
                status,
                blockers,
            ),
            expected_parent_identity=input_bundle_identity,
        )
        publish_regular_text(
            changelog_path,
            _changelog(project, manifest, gate, signing, status, blockers),
            expected_parent_identity=input_bundle_identity,
        )
    except (OSError, ValueError) as exc:
        return ReleaseNotesReport(
            project.root,
            bundle_dir,
            notes_path,
            changelog_path,
            "blocked",
            (*blockers, f"release-notes-output: publication failed: {exc}"),
            False,
        )
    return ReleaseNotesReport(
        project.root,
        bundle_dir,
        notes_path,
        changelog_path,
        status,
        blockers,
        True,
    )


def _read_notes_inputs(
    bundle_dir: Path,
    *,
    expected_bundle_identity: StableParentIdentity | None = None,
    read_manifest: bool = True,
    read_signing: bool = True,
) -> tuple[
    dict[str, object],
    tuple[str, ...],
    StableParentIdentity | None,
]:
    inputs: dict[str, object] = {}
    problems: list[str] = []
    sealed_identity: StableParentIdentity | None = None
    session: ArtifactVerificationSession | None = None
    try:
        session = ArtifactVerificationSession(
            Path(os.path.abspath(bundle_dir)),
            label="release notes inputs",
            limits=_NOTES_LIMITS,
        )
        if (
            expected_bundle_identity is not None
            and _stable_directory_identity(session.anchor_identity)
            != expected_bundle_identity
        ):
            raise ArtifactVerificationError(
                "release notes bundle differs from the published receipt"
            )
        json_inputs = [
            ("gate", "RELEASE-GATE.json"),
            ("provenance", "distroforge-provenance.json"),
        ]
        if read_manifest:
            json_inputs.insert(0, ("manifest", "RELEASE-MANIFEST.json"))
        if read_signing:
            json_inputs.append(("signing", "SIGNING-REPORT.json"))
        for key, name in json_inputs:
            try:
                inputs[key] = session.file(
                    Path(name),
                    label=f"release notes {name}",
                    max_bytes=_NOTES_JSON_MAX_BYTES,
                ).json_object()
            except (ArtifactVerificationError, OSError, ValueError) as exc:
                problems.append(
                    f"{key}: {name} is missing, unsafe, or invalid: {exc}"
                )
        try:
            inputs["buildinfo"] = session.file(
                Path("BUILDINFO"),
                label="release notes BUILDINFO",
                max_bytes=_NOTES_TEXT_MAX_BYTES,
            ).read_text()
        except (ArtifactVerificationError, OSError, ValueError) as exc:
            problems.append(
                f"buildinfo: BUILDINFO is missing, unsafe, or invalid: {exc}"
            )
        session.seal()
        sealed_identity = _stable_directory_identity(session.anchor_identity)
    except (ArtifactVerificationError, OSError, ValueError) as exc:
        problems.append(f"artifact-session: release notes inputs did not seal: {exc}")
    finally:
        if session is not None:
            session.close()
    return inputs, tuple(problems), sealed_identity


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


def _signing_contract_problem(signing: dict[str, object]) -> str | None:
    if not signing:
        return "signing: required signing report is missing or invalid"
    status = signing.get("status")
    execute = signing.get("execute")
    signed = signing.get("signed")
    planned = signing.get("planned")
    skipped = signing.get("skipped")
    if (
        status not in {"signed", "planned", "blocked"}
        or not isinstance(execute, bool)
        or not isinstance(signed, list)
        or not isinstance(planned, list)
        or not isinstance(skipped, list)
        or not all(
            isinstance(name, str)
            for values in (signed, planned, skipped)
            for name in values
        )
    ):
        return "signing: status, execute flag, or result lists are malformed"
    required = {f"{name}.asc" for name in SIGN_TARGETS}
    if status == "signed" and (
        execute is not True
        or set(signed) != required
        or planned
        or skipped
    ):
        return "signing: signed report does not contain the exact signature set"
    if status == "planned" and (
        execute is not False
        or signed
        or set(planned) != required
        or skipped
    ):
        return "signing: planned report does not contain the exact signature plan"
    if status == "blocked" and not skipped:
        return "signing: blocked report has no typed refusal detail"
    return None


def _notes(
    project: Project,
    bundle_dir: Path,
    manifest: dict[str, object],
    gate: dict[str, object],
    signing: dict[str, object],
    buildinfo: str,
    provenance: dict[str, object],
    status: str,
    blockers: tuple[str, ...],
) -> str:
    files = [item for item in manifest.get("files", []) if isinstance(item, dict)]
    iso = next((item for item in files if str(item.get("name", "")).endswith(".iso")), None)
    boot = [item for item in files if item.get("name") in {"qemu-lab-report.json", "boot-proof.json"}]
    signed = signing.get("signed", [])
    planned = signing.get("planned", [])
    lines = [
        f"# {project.name} Release Notes",
        "",
        f"- Status: **{status.upper()}**",
        f"- Bundle: `{bundle_dir}`",
        f"- Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## ISO",
        f"- Image: {iso.get('name') if iso else 'missing'}",
        f"- SHA256: {iso.get('sha256') if iso else 'missing'}",
        "",
        "## Included Artifacts",
        *[f"- `{item.get('name')}` ({item.get('size')} bytes)" for item in files],
        "",
        "## Boot Proof",
        *([f"- `{item.get('name')}` present" for item in boot] or ["- missing"]),
        "",
        "## Signing Snapshot",
        "- This section records the state before the final manifest signature.",
        *([f"- signed at snapshot: `{item}`" for item in signed] or []),
        *([f"- planned at snapshot: `{item}`" for item in planned] or []),
        *([] if signed or planned else ["- no signing evidence"]),
        "- The terminal result is authoritative only after `verify-release`.",
        "",
        "## Release Gate",
        *[f"- [{item.get('status')}] {item.get('code')}: {item.get('detail')}" for item in gate.get("items", []) if isinstance(item, dict)],
        "",
        "## Blockers",
        *([f"- {item}" for item in blockers] or ["- none"]),
        "",
        "## Verification Commands",
        "```bash",
        "sha256sum -c SHA256SUMS",
        (
            "distroforge verify-release "
            f"{shlex.quote(str(project.root))} "
            f"--bundle-dir {shlex.quote(str(bundle_dir))} "
            "--gpg-fingerprint EXPECTED_FULL_FINGERPRINT"
        ),
        "```",
        "",
        "## Build Info",
        "```text",
        buildinfo.strip() or "missing",
        "```",
        "",
        "## Provenance",
        "```json",
        json.dumps(provenance, indent=2) if provenance else "{}",
        "```",
    ]
    return "\n".join(lines) + "\n"


def _changelog(project: Project, manifest: dict[str, object], gate: dict[str, object], signing: dict[str, object], status: str, blockers: tuple[str, ...]) -> str:
    files = [item.get("name") for item in manifest.get("files", []) if isinstance(item, dict)]
    lines = [
        f"{project.name} release bundle",
        f"Status: {status.upper()}",
        f"Generated: {datetime.now(UTC).isoformat()}",
        "",
        "Included files:",
        *[f"- {name}" for name in files],
        "",
        f"Release gate items: {len(gate.get('items', []))}",
        (
            "Signing status at note snapshot: "
            f"{signing.get('status', 'unknown')}"
        ),
        "Terminal signing status: verify SIGNING-REPORT.json and signatures",
        "",
        "Blockers:",
        *([f"- {item}" for item in blockers] or ["- none"]),
    ]
    return "\n".join(lines) + "\n"
