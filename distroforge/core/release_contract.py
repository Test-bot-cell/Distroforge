from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path

SIGN_TARGETS = (
    "SHA256SUMS",
    "RELEASE-GATE.json",
    "RELEASE-MANIFEST.json",
)
SIGNATURE_NAMES = tuple(f"{name}.asc" for name in SIGN_TARGETS)
SIGNING_KEYRING = "RELEASE-SIGNING-KEYRING.gpg"
_FULL_FINGERPRINT = re.compile(r"(?:[0-9A-F]{40}|[0-9A-F]{64})")

REQUIRED_RELEASE_GATE_CODES = frozenset(
    {
        "source-trust",
        "package-inputs",
        "rootfs-identity",
        "iso-assembly",
        "vuln-scan",
        "iso",
        "sha256",
        "buildinfo",
        "provenance",
        "sbom",
        "html-report",
        "boot-proof",
        "release-readiness",
        "packaging-policy",
        "provenance-snapshot",
        "artifact-session",
    }
)
OPTIONAL_RELEASE_GATE_CODES = frozenset({"publish-signing"})
ALLOWED_RELEASE_GATE_CODES = REQUIRED_RELEASE_GATE_CODES | OPTIONAL_RELEASE_GATE_CODES


def release_gate_code_problem(codes: set[str] | frozenset[str]) -> str | None:
    """Return why a gate does not carry the exact release proof contract."""

    actual = frozenset(codes)
    if actual in {
        REQUIRED_RELEASE_GATE_CODES,
        ALLOWED_RELEASE_GATE_CODES,
    }:
        return None
    missing = sorted(REQUIRED_RELEASE_GATE_CODES - actual)
    unexpected = sorted(actual - ALLOWED_RELEASE_GATE_CODES)
    details: list[str] = []
    if missing:
        details.append("missing: " + ", ".join(missing))
    if unexpected:
        details.append("unexpected: " + ", ".join(unexpected))
    if not details:
        details.append("optional publish-signing is the only permitted extension")
    return "release gate proof set is not exact (" + "; ".join(details) + ")"


def release_gate_report_problem(
    value: object,
    *,
    expected_project: Path,
    expected_iso: Path | None = None,
    expected_iso_name: str | None = None,
    expected_output_dir: Path | None = None,
) -> str | None:
    """Validate the exact metadata and typed verdict set of RELEASE-GATE.json."""

    if not isinstance(value, dict):
        return "release gate is not an object"
    gate = value
    if set(gate) != {
        "project",
        "iso",
        "output_dir",
        "build_run_id",
        "boot_run_id",
        "immutable_iso_build",
        "immutable_provenance",
        "immutable_boot_proof",
        "immutable_qemu_report",
        "immutable_sbom",
        "status",
        "blocked",
        "items",
    }:
        return "top-level keys differ from the exact release gate schema"
    project = _exact_absolute_path(gate.get("project"))
    iso = _exact_absolute_path(gate.get("iso"))
    output_dir = _exact_absolute_path(gate.get("output_dir"))
    if project != Path(os.path.abspath(expected_project)):
        return "project is not bound to the expected project"
    if iso is None or output_dir is None or iso.parent != output_dir:
        return "ISO and output_dir are not one canonical absolute product path"
    if expected_iso is not None and iso != Path(os.path.abspath(expected_iso)):
        return "ISO is not bound to the expected product"
    if expected_iso_name is not None and iso.name != expected_iso_name:
        return "ISO name is not bound to the unique bundled product"
    if expected_output_dir is not None and output_dir != Path(os.path.abspath(expected_output_dir)):
        return "output_dir is not bound to the expected product directory"
    if expected_output_dir is None:
        try:
            output_dir.relative_to(Path(os.path.abspath(expected_project)))
        except ValueError:
            return "output_dir is outside the expected project"

    build_run_id = gate.get("build_run_id")
    boot_run_id = gate.get("boot_run_id")
    immutable_iso_build = _exact_absolute_path(gate.get("immutable_iso_build"))
    immutable_provenance = _exact_absolute_path(gate.get("immutable_provenance"))
    immutable_boot_proof = _exact_absolute_path(gate.get("immutable_boot_proof"))
    immutable_qemu_report = _exact_absolute_path(gate.get("immutable_qemu_report"))
    immutable_sbom = _exact_absolute_path(gate.get("immutable_sbom"))
    for key, parsed in (
        ("immutable_iso_build", immutable_iso_build),
        ("immutable_provenance", immutable_provenance),
        ("immutable_boot_proof", immutable_boot_proof),
        ("immutable_qemu_report", immutable_qemu_report),
        ("immutable_sbom", immutable_sbom),
    ):
        if gate.get(key) is not None and parsed is None:
            return f"{key} is not null or one canonical absolute path"
    if build_run_id is None:
        if (
            immutable_iso_build is not None
            or immutable_provenance is not None
            or immutable_sbom is not None
        ):
            return "unselected build run exposes immutable build paths"
    elif (
        not _is_safe_run_id(build_run_id)
        or immutable_iso_build != output_dir / "evidence" / "runs" / build_run_id / "ISO-BUILD.json"
        or immutable_provenance
        != output_dir / "evidence" / "runs" / build_run_id / "distroforge-provenance.json"
        or (
            immutable_sbom is not None
            and immutable_sbom.parent
            != output_dir / "evidence" / "runs" / build_run_id
        )
    ):
        return "immutable build paths do not bind the selected build_run_id"
    if boot_run_id is None:
        if immutable_boot_proof is not None or immutable_qemu_report is not None:
            return "unselected boot run exposes immutable boot paths"
    elif (
        not _is_safe_run_id(boot_run_id)
        or immutable_boot_proof
        != output_dir / "evidence" / "runs" / boot_run_id / "boot-proof.json"
        or (
            immutable_qemu_report is not None
            and immutable_qemu_report.parent != output_dir / "evidence" / "runs" / boot_run_id
        )
    ):
        return "immutable boot paths do not bind the selected boot_run_id"

    status = gate.get("status")
    if status not in {"blocked", "review", "ready"}:
        return "aggregate status is invalid"
    blocked = gate.get("blocked")
    if not isinstance(blocked, bool) or blocked is not (status == "blocked"):
        return "blocked flag contradicts the aggregate status"
    raw_items = gate.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        return "items are not a non-empty typed verdict list"
    codes: set[str] = set()
    statuses: list[str] = []
    item_statuses: dict[str, str] = {}
    for item in raw_items:
        if not isinstance(item, dict) or set(item) != {"code", "status", "detail"}:
            return "an item differs from the exact typed verdict schema"
        code = item.get("code")
        item_status = item.get("status")
        detail = item.get("detail")
        if (
            not isinstance(code, str)
            or not code
            or code in codes
            or not isinstance(item_status, str)
            or item_status not in {"blocked", "review", "ready"}
            or not isinstance(detail, str)
            or not detail
        ):
            return "items require unique non-empty codes and strict status/detail strings"
        codes.add(code)
        statuses.append(item_status)
        item_statuses[code] = item_status
    derived = "blocked" if "blocked" in statuses else "review" if "review" in statuses else "ready"
    if derived != status:
        return "aggregate status contradicts its item verdicts"
    build_selected = (
        isinstance(build_run_id, str)
        and immutable_iso_build is not None
        and immutable_provenance is not None
    )
    boot_selected = (
        isinstance(boot_run_id, str)
        and immutable_boot_proof is not None
        and immutable_qemu_report is not None
    )
    if status != "blocked" and not build_selected:
        return "non-blocked gate has no immutable selected build run"
    if status != "blocked" and not boot_selected:
        return "non-blocked gate has no immutable selected boot run"
    if item_statuses.get("provenance") == "ready" and not build_selected:
        return "ready provenance item has no immutable selected build run"
    if item_statuses.get("boot-proof") == "ready" and (
        not build_selected or not boot_selected
    ):
        return "ready boot-proof item has no immutable build/boot selection"
    if item_statuses.get("sbom") == "ready" and immutable_sbom is None:
        return "ready SBOM item has no immutable selected SBOM"
    return release_gate_code_problem(codes)


def _is_safe_run_id(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    return (
        len(encoded) <= 255
        and value not in {".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        and Path(value).name == value
    )


def release_manifest_problem(
    value: object,
    *,
    expected_project_name: str,
    expected_bundle_dir: Path,
) -> str | None:
    """Validate the exact metadata and file identities of RELEASE-MANIFEST.json."""

    if not isinstance(value, dict):
        return "release manifest is not an object"
    manifest = value
    if set(manifest) != {
        "generated_at",
        "project",
        "bundle_dir",
        "gate_status",
        "files",
    }:
        return "top-level keys differ from the exact release manifest schema"
    generated_at = manifest.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at:
        return "generated_at is not a non-empty timestamp"
    try:
        parsed_time = datetime.fromisoformat(generated_at)
    except ValueError:
        return "generated_at is not strict ISO-8601"
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        return "generated_at has no timezone"
    if manifest.get("project") != expected_project_name:
        return "project is not bound to the expected project name"
    if _exact_absolute_path(manifest.get("bundle_dir")) != Path(
        os.path.abspath(expected_bundle_dir)
    ):
        return "bundle_dir is not bound to the verified bundle"
    if manifest.get("gate_status") not in {"blocked", "review", "ready"}:
        return "gate_status is invalid"
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        return "files are not a non-empty identity list"
    names: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"name", "size", "sha256"}:
            return "a file entry differs from the exact manifest schema"
        name = entry.get("name")
        size = entry.get("size")
        digest = entry.get("sha256")
        if (
            not isinstance(name, str)
            or not _is_canonical_relative_path(name)
            or name in names
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not _is_sha256(digest)
        ):
            return "file entries contain an unsafe or duplicate identity"
        names.add(name)
    return None


def release_signing_report_problem(
    value: object,
    manifest: object,
    *,
    expected_project: Path,
    expected_bundle_dir: Path,
) -> str | None:
    """Return why a persisted signing report is not an exact release contract."""

    if not isinstance(value, dict):
        return "signing report is not an object"
    signing = value
    expected_keys = {
        "project",
        "bundle_dir",
        "manifest",
        "status",
        "execute",
        "signer_fingerprint",
        "verification_keyring",
        "verification_keyring_sha256",
        "signed",
        "planned",
        "skipped",
        "manifest_entries",
    }
    if set(signing) != expected_keys:
        return "top-level keys differ from the exact signing report schema"
    absolute_project = Path(os.path.abspath(expected_project))
    absolute_bundle = Path(os.path.abspath(expected_bundle_dir))
    for key, expected in (
        ("project", absolute_project),
        ("bundle_dir", absolute_bundle),
        ("manifest", absolute_bundle / "RELEASE-MANIFEST.json"),
    ):
        path = _exact_absolute_path(signing.get(key))
        if path != expected:
            return f"{key} is not bound to the verified project and bundle"

    status = signing.get("status")
    if status not in {"blocked", "planned", "signed"}:
        return "status is not blocked, planned, or signed"
    execute = signing.get("execute")
    if not isinstance(execute, bool):
        return "execute is not a boolean"

    fingerprint = signing.get("signer_fingerprint")
    if fingerprint is not None and (
        not isinstance(fingerprint, str) or _FULL_FINGERPRINT.fullmatch(fingerprint) is None
    ):
        return "signer_fingerprint is not a canonical complete fingerprint"

    keyring = signing.get("verification_keyring")
    keyring_sha = signing.get("verification_keyring_sha256")
    if keyring is None:
        if keyring_sha is not None:
            return "verification keyring SHA exists without a keyring"
    elif keyring != SIGNING_KEYRING or not _is_sha256(keyring_sha):
        return "verification keyring identity is malformed"

    signed = _unique_string_list(signing.get("signed"))
    planned = _unique_string_list(signing.get("planned"))
    skipped = _unique_string_list(signing.get("skipped"))
    if signed is None or planned is None or skipped is None:
        return "signed, planned, and skipped must be unique non-empty string lists"
    if set(signed) & set(planned):
        return "signed and planned target lists overlap"

    authoritative_entries = manifest.get("files") if isinstance(manifest, dict) else None
    manifest_entries = signing.get("manifest_entries")
    if not isinstance(manifest_entries, list) or manifest_entries != authoritative_entries:
        return "manifest_entries do not exactly reproduce RELEASE-MANIFEST.json"
    names: set[str] = set()
    entries_by_name: dict[str, dict[object, object]] = {}
    for entry in manifest_entries:
        if not isinstance(entry, dict) or set(entry) != {"name", "size", "sha256"}:
            return "manifest_entries contain a malformed entry"
        name = entry.get("name")
        size = entry.get("size")
        digest = entry.get("sha256")
        if (
            not isinstance(name, str)
            or not _is_canonical_relative_path(name)
            or name in names
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not _is_sha256(digest)
        ):
            return "manifest_entries contain an unsafe or duplicate identity"
        names.add(name)
        entries_by_name[name] = entry
    if keyring is not None:
        keyring_entry = entries_by_name.get(keyring)
        if keyring_entry is None or keyring_entry.get("sha256") != keyring_sha:
            return "verification keyring is not bound by manifest_entries"

    if status == "signed":
        if (
            execute is not True
            or fingerprint is None
            or keyring != SIGNING_KEYRING
            or signed != SIGNATURE_NAMES
            or planned
            or skipped
        ):
            return "signed report does not contain the exact executed signature set"
    elif status == "planned":
        if (
            execute is not False
            or signed
            or planned != SIGNATURE_NAMES
            or skipped
            or keyring is not None
            or keyring_sha is not None
        ):
            return "planned signing report contradicts its exact dry-run target set"
    elif signed or planned or not skipped:
        return "blocked signing report contradicts its target or reason lists"
    return None


def _exact_absolute_path(value: object) -> Path | None:
    if not isinstance(value, str) or not value or _has_control(value):
        return None
    path = Path(value)
    if (
        not path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
        or path != Path(os.path.abspath(path))
        or str(path) != value
    ):
        return None
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        return None
    return path


def _unique_string_list(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or _has_control(item):
            return None
        try:
            item.encode("utf-8", errors="strict")
        except UnicodeError:
            return None
        result.append(item)
    if len(set(result)) != len(result):
        return None
    return tuple(result)


def _is_canonical_relative_path(value: str) -> bool:
    if not value or _has_control(value) or "\\" in value:
        return False
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    relative = Path(value)
    return (
        not relative.is_absolute()
        and relative != Path(".")
        and not any(part in {"", ".", ".."} for part in relative.parts)
        and relative.as_posix() == value
    )


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _has_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)
