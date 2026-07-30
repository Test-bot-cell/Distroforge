"""Bounded APT ``DPkg::Pre-Install-Pkgs`` protocol-v3 evidence.

M3.2a records and replays the action-plan format APT sends immediately before
it invokes dpkg.  This is deliberately narrower than origin or execution
causality: a valid stream binds every claimed ``.deb`` path to the corresponding
sealed PACKAGE-INPUTS record.  Until capture is acknowledged outside the
mutable target rootfs, it does not prove that APT originated the stream, that
dpkg completed an action, or which process produced a final rootfs byte.

The module is intentionally pure.  Callers provide already-read bytes and
decoded PACKAGE-INPUTS transactions; filesystem confinement and immutable
writes remain the responsibility of the evidence service.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import cast

PACKAGE_APT_ACTIONS_SCHEMA = "distroforge.package-apt-actions.v1"
PACKAGE_APT_ACTIONS_FILENAME = "PACKAGE-APT-ACTIONS.json"

# Public bounds are part of the report contract.  They cap both individual
# hostile inputs and aggregate growth before JSON materialisation.
MAX_APT_PROTOCOL_BYTES = 16 * 1024 * 1024
MAX_TOTAL_APT_PROTOCOL_BYTES = 128 * 1024 * 1024
MAX_APT_PROTOCOL_LINE_BYTES = 64 * 1024
MAX_APT_PROTOCOL_LINES = 200_000
MAX_APT_CONFIG_DIRECTIVES = 50_000
MAX_APT_ACTIONS_PER_CAPTURE = 100_000
MAX_APT_ACTION_CAPTURES = 10_000
MAX_TOTAL_APT_ACTIONS = 100_000
MAX_TOTAL_APT_CONFIG_DIRECTIVES = 100_000
MAX_PACKAGE_TRANSACTIONS = 10_000
MAX_PACKAGE_RECORDS_PER_TRANSACTION = 20_000
MAX_TOTAL_PACKAGE_RECORDS = 100_000
MAX_PACKAGE_INPUTS_BYTES = 128 * 1024 * 1024
MAX_PACKAGE_TRANSACTION_BYTES = 128 * 1024 * 1024
MAX_PACKAGE_INPUT_BLOB_BYTES = 32 * 1024 * 1024 * 1024
MAX_TOTAL_PACKAGE_INPUT_BLOB_BYTES = 64 * 1024 * 1024 * 1024
MAX_CAPTURE_JOURNAL_BYTES = 32 * 1024 * 1024
MAX_REPORT_JSON_BYTES = 96 * 1024 * 1024
MAX_REPORT_DYNAMIC_JSON_BYTES = 48 * 1024 * 1024
MAX_RUN_RELATIVE_PATH_BYTES = 4 * 1024
MAX_RUN_RELATIVE_PATH_COMPONENTS = 256
MAX_TRANSACTION_ID_BYTES = 255
MAX_PACKAGE_NAME_BYTES = 255
MAX_VERSION_BYTES = 4 * 1024
MAX_ARCHITECTURE_BYTES = 255
MAX_CONFIG_KEY_BYTES = 16 * 1024
MAX_CONFIG_VALUE_BYTES = 64 * 1024

_PACKAGE_INPUTS_SCHEMA = "distroforge.package-inputs.v1"
_PACKAGE_TRANSACTION_SCHEMA = "distroforge.package-input-transaction.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
_VERSION = re.compile(r"^[A-Za-z0-9.+:~\-]+$")
_ARCHITECTURE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_MULTIARCH = frozenset({"same", "foreign", "allowed", "none", "no"})
_DIRECTIONS = frozenset({"<", "=", ">"})
_ACTION_MARKERS = frozenset({"**CONFIGURE**", "**REMOVE**"})
_COUNTS = (
    "install",
    "upgrade",
    "downgrade",
    "reinstall",
    "configure",
    "remove",
    "unpack",
    "total",
)
_LIMITS = (
    (
        "the report proves an exact self-consistent replay of the supplied "
        "protocol-v3 transcript, not that APT originated those bytes or that "
        "dpkg started or completed any announced action"
    ),
    (
        "the transcript, journal and CAS are staged in the mutable target "
        "rootfs until host collection; origin authentication requires a "
        "host-isolated one-shot witness acknowledged before dpkg can run"
    ),
    (
        "maintainer scripts, dpkg triggers, conffile policy, diversions and "
        "alternatives are outside this action-plan milestone"
    ),
    (
        "direct dpkg invocations and other filesystem writers which bypass "
        "DPkg::Pre-Install-Pkgs remain outside this capture"
    ),
    (
        "bootstrap packages installed before the hook and source-ISO baseline "
        "bytes remain outside this capture"
    ),
    (
        "all valid M3.2a reports keep filesystem_causality unverified and "
        "release_ready false"
    ),
)


class PackageAptActionsError(ValueError):
    """APT action evidence cannot be parsed or recomputed without ambiguity."""


@dataclass(frozen=True)
class AptPackageAction:
    """One exact nine-field package action from protocol version 3."""

    package: str
    old_version: str
    old_architecture: str
    old_multiarch: str
    direction: str
    new_version: str
    new_architecture: str
    new_multiarch: str
    action: str
    operation: str

    def document(self, *, index: int) -> dict[str, object]:
        return {
            "index": index,
            "package": self.package,
            "old": {
                "version": self.old_version,
                "architecture": self.old_architecture,
                "multiarch": self.old_multiarch,
            },
            "direction": self.direction,
            "new": {
                "version": self.new_version,
                "architecture": self.new_architecture,
                "multiarch": self.new_multiarch,
            },
            "action": self.action,
            "operation": self.operation,
        }


@dataclass(frozen=True)
class AptProtocolV3:
    """Decoded, bounded representation of one supplied raw stream."""

    configuration: tuple[tuple[str, str], ...]
    actions: tuple[AptPackageAction, ...]
    size: int
    sha256: str
    version: int = 3


@dataclass(frozen=True)
class AptProtocolCapture:
    """Identity and bytes of one sealed pre-install protocol stream."""

    transaction_id: str
    path: str
    size: int
    sha256: str
    data: bytes
    complete: bool


@dataclass(frozen=True)
class PackageAptActionsValidation:
    """Fail-closed validation result for a recomputed M3.2a report."""

    ok: bool
    detail: str
    apt_actions: str = "unverified"
    capture_origin: str = "unverified"
    filesystem_causality: str = "unverified"
    release_ready: bool = False


def parse_apt_pre_install_v3(data: bytes) -> AptProtocolV3:
    """Parse one complete, canonical APT protocol-v3 stream.

    The accepted framing is exactly ``VERSION 3``, zero or more percent-encoded
    ``key=value`` configuration lines, a required empty delimiter, and one or
    more nine-field action lines.  The final LF is part of completeness.
    """

    if not isinstance(data, bytes):
        raise PackageAptActionsError("APT protocol capture is not bytes")
    if not data:
        raise PackageAptActionsError("APT protocol capture is empty")
    if len(data) > MAX_APT_PROTOCOL_BYTES:
        raise PackageAptActionsError("APT protocol capture exceeds the byte bound")
    if not data.endswith(b"\n"):
        raise PackageAptActionsError("APT protocol capture has no final newline")
    if b"\x00" in data:
        raise PackageAptActionsError("APT protocol capture contains NUL")
    if b"\r" in data:
        raise PackageAptActionsError("APT protocol capture contains a carriage return")
    if data.count(b"\n") > MAX_APT_PROTOCOL_LINES:
        raise PackageAptActionsError("APT protocol capture exceeds the line bound")
    raw_lines = data[:-1].split(b"\n")
    if any(len(line) > MAX_APT_PROTOCOL_LINE_BYTES for line in raw_lines):
        raise PackageAptActionsError("APT protocol capture exceeds the per-line bound")
    try:
        lines = [line.decode("utf-8", errors="strict") for line in raw_lines]
    except UnicodeDecodeError as exc:
        raise PackageAptActionsError("APT protocol capture is not UTF-8") from exc
    if not lines or lines[0] != "VERSION 3":
        raise PackageAptActionsError("APT protocol capture is not exact version 3")
    try:
        delimiter = lines.index("", 1)
    except ValueError as exc:
        raise PackageAptActionsError(
            "APT protocol configuration has no empty terminator"
        ) from exc

    raw_configuration = lines[1:delimiter]
    if len(raw_configuration) > MAX_APT_CONFIG_DIRECTIVES:
        raise PackageAptActionsError(
            "APT protocol configuration exceeds the directive bound"
        )
    configuration = tuple(
        _parse_configuration_line(line) for line in raw_configuration
    )

    raw_actions = lines[delimiter + 1 :]
    if not raw_actions:
        raise PackageAptActionsError("APT protocol capture has no package actions")
    if len(raw_actions) > MAX_APT_ACTIONS_PER_CAPTURE:
        raise PackageAptActionsError("APT protocol capture exceeds the action bound")
    if any(not line for line in raw_actions):
        raise PackageAptActionsError(
            "APT protocol capture contains an empty package-action line"
        )
    actions = tuple(_parse_action_line(line) for line in raw_actions)
    return AptProtocolV3(
        configuration=configuration,
        actions=actions,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def build_package_apt_actions_report(
    *,
    run_id: str,
    package_inputs: Mapping[str, object],
    package_inputs_identity: Mapping[str, object],
    journal_identity: Mapping[str, object],
    transactions: Sequence[Mapping[str, object]],
    captures: Sequence[AptProtocolCapture],
) -> dict[str, object]:
    """Build the canonical report from supplied raw and PACKAGE-INPUTS data."""

    return recompute_package_apt_actions_report(
        run_id=run_id,
        package_inputs=package_inputs,
        package_inputs_identity=package_inputs_identity,
        journal_identity=journal_identity,
        transactions=transactions,
        captures=captures,
    )


def recompute_package_apt_actions_report(
    *,
    run_id: str,
    package_inputs: Mapping[str, object],
    package_inputs_identity: Mapping[str, object],
    journal_identity: Mapping[str, object],
    transactions: Sequence[Mapping[str, object]],
    captures: Sequence[AptProtocolCapture],
) -> dict[str, object]:
    """Recompute the complete M3.2a document without trusting a prior report."""

    _safe_component(run_id, "run_id", MAX_TRANSACTION_ID_BYTES)
    if not isinstance(package_inputs, Mapping):
        raise PackageAptActionsError("PACKAGE-INPUTS payload is not an object")
    if package_inputs.get("schema") != _PACKAGE_INPUTS_SCHEMA:
        raise PackageAptActionsError("PACKAGE-INPUTS schema is unsupported")
    if package_inputs.get("run_id") != run_id:
        raise PackageAptActionsError("PACKAGE-INPUTS belongs to another run")
    source_mode = package_inputs.get("source_mode")
    if source_mode not in {"bootstrap", "iso"}:
        raise PackageAptActionsError("PACKAGE-INPUTS source mode is unsupported")
    input_identity = _identity(
        package_inputs_identity,
        "PACKAGE-INPUTS",
        max_size=MAX_PACKAGE_INPUTS_BYTES,
        required_path="PACKAGE-INPUTS.json",
    )
    capture_journal = _identity(
        journal_identity,
        "APT capture journal",
        max_size=MAX_CAPTURE_JOURNAL_BYTES,
        required_path="apt/transactions.tsv",
    )
    transaction_contexts, transaction_refs = _transaction_contexts(
        package_inputs,
        transactions,
        run_id,
    )
    capture_map = _captures(captures)
    apt_transactions: list[dict[str, object]] = []
    for context in transaction_contexts:
        payload = cast(Mapping[str, object], context["payload"])
        if payload.get("kind") == "apt-pre-install":
            apt_transactions.append(context)
    expected_ids = {cast(str, context["id"]) for context in apt_transactions}
    if set(capture_map) != expected_ids:
        missing = sorted(expected_ids - set(capture_map))
        unexpected = sorted(set(capture_map) - expected_ids)
        if missing:
            raise PackageAptActionsError(
                f"APT action capture is missing transaction {missing[0]}"
            )
        raise PackageAptActionsError(
            f"APT action capture references a non-APT transaction {unexpected[0]}"
        )

    total_protocol_bytes = sum(capture.size for capture in capture_map.values())
    if total_protocol_bytes > MAX_TOTAL_APT_PROTOCOL_BYTES:
        raise PackageAptActionsError(
            "APT protocol captures exceed the aggregate byte bound"
        )

    report_transactions: list[dict[str, object]] = []
    counts = {name: 0 for name in _COUNTS}
    total_action_count = 0
    total_config_count = 0
    dynamic_json_bytes = 0
    for context in apt_transactions:
        transaction_id = cast(str, context["id"])
        transaction = cast(Mapping[str, object], context["payload"])
        contract_records = _transaction_contract_records(transaction)
        capture = capture_map[transaction_id]
        parsed = parse_apt_pre_install_v3(capture.data)
        total_action_count += len(parsed.actions)
        total_config_count += len(parsed.configuration)
        if total_action_count > MAX_TOTAL_APT_ACTIONS:
            raise PackageAptActionsError(
                "APT protocol captures exceed the aggregate action bound"
            )
        if total_config_count > MAX_TOTAL_APT_CONFIG_DIRECTIVES:
            raise PackageAptActionsError(
                "APT protocol captures exceed the aggregate configuration bound"
            )
        if parsed.size != capture.size or parsed.sha256 != capture.sha256:
            raise PackageAptActionsError(
                f"APT action capture identity differs for {transaction_id}"
            )
        debs = _transaction_deb_records(transaction)
        action_documents: list[dict[str, object]] = []
        referenced_debs: set[str] = set()
        seen_actions: set[tuple[str, str, str, str]] = set()
        for index, action in enumerate(parsed.actions):
            action_key = (
                action.package,
                action.new_version,
                action.new_architecture,
                action.action,
            )
            if action_key in seen_actions:
                raise PackageAptActionsError(
                    f"APT protocol duplicates a package action in {transaction_id}"
                )
            seen_actions.add(action_key)
            document = action.document(index=index)
            if action.operation in {"install", "upgrade", "downgrade", "reinstall"}:
                matches = debs.get(action.action, ())
                if len(matches) != 1:
                    raise PackageAptActionsError(
                        "APT unpack action does not bind exactly one sealed .deb: "
                        f"{action.action}"
                    )
                if action.action in referenced_debs:
                    raise PackageAptActionsError(
                        f"APT protocol reuses one sealed .deb: {action.action}"
                    )
                referenced_debs.add(action.action)
                binding = matches[0]
                if (
                    action.package != binding["package"]
                    or action.new_version != binding["version"]
                    or action.new_architecture != binding["architecture"]
                ):
                    raise PackageAptActionsError(
                        "APT unpack action identity differs from its sealed .deb "
                        f"record: {action.action}"
                    )
                document["deb"] = binding
                counts["unpack"] += 1
            dynamic_json_bytes += _compact_json_size(document) + 1
            if dynamic_json_bytes > MAX_REPORT_DYNAMIC_JSON_BYTES:
                raise PackageAptActionsError(
                    "APT action report exceeds its dynamic JSON budget"
                )
            counts[action.operation] += 1
            counts["total"] += 1
            action_documents.append(document)
        if referenced_debs != set(debs):
            unreferenced = sorted(set(debs) - referenced_debs)
            raise PackageAptActionsError(
                f"sealed .deb has no APT unpack action: {unreferenced[0]}"
            )
        configuration: list[dict[str, str]] = []
        for key, value in parsed.configuration:
            directive = {"key": key, "value": value}
            dynamic_json_bytes += _compact_json_size(directive) + 1
            if dynamic_json_bytes > MAX_REPORT_DYNAMIC_JSON_BYTES:
                raise PackageAptActionsError(
                    "APT action report exceeds its dynamic JSON budget"
                )
            configuration.append(directive)
        report_transactions.append(
            {
                "id": transaction_id,
                "package_input_transaction": context["identity"],
                "recorder": contract_records["recorder"],
                "configuration": contract_records["configuration"],
                "capture": {
                    "path": capture.path,
                    "size": capture.size,
                    "sha256": capture.sha256,
                    "complete": True,
                },
                "protocol": {
                    "version": parsed.version,
                    "configuration": configuration,
                    "configuration_sha256": _canonical_sha256(configuration),
                    "action_count": len(action_documents),
                    "actions_sha256": _canonical_sha256(action_documents),
                },
                "actions": action_documents,
            }
        )

    apt_status = "self-consistent" if report_transactions else "not-observed"
    package_binding: dict[str, object] = {
        **input_identity,
        "schema": _PACKAGE_INPUTS_SCHEMA,
        "source_mode": source_mode,
        "transaction_count": len(transaction_refs),
        "transactions_sha256": _canonical_sha256(transaction_refs),
    }
    report: dict[str, object] = {
        "schema": PACKAGE_APT_ACTIONS_SCHEMA,
        "run_id": run_id,
        "scope": "apt-dpkg-pre-install-pkgs-v3-planned-actions-m3.2a",
        "assurance_dependency": (
            "PACKAGE-INPUTS authentication, repository policy and transaction "
            "identities must be validated independently"
        ),
        "capture_assurance_dependency": (
            "a host-isolated one-shot witness must acknowledge the transcript "
            "before dpkg runs to authenticate APT origin"
        ),
        "digest": "sha256",
        "package_inputs": package_binding,
        "capture_journal": capture_journal,
        "bounds": {
            "max_apt_protocol_bytes": MAX_APT_PROTOCOL_BYTES,
            "max_total_apt_protocol_bytes": MAX_TOTAL_APT_PROTOCOL_BYTES,
            "max_apt_protocol_line_bytes": MAX_APT_PROTOCOL_LINE_BYTES,
            "max_apt_protocol_lines": MAX_APT_PROTOCOL_LINES,
            "max_apt_config_directives": MAX_APT_CONFIG_DIRECTIVES,
            "max_apt_actions_per_capture": MAX_APT_ACTIONS_PER_CAPTURE,
            "max_apt_action_captures": MAX_APT_ACTION_CAPTURES,
            "max_total_apt_actions": MAX_TOTAL_APT_ACTIONS,
            "max_total_apt_config_directives": (
                MAX_TOTAL_APT_CONFIG_DIRECTIVES
            ),
            "max_package_transactions": MAX_PACKAGE_TRANSACTIONS,
            "max_package_records_per_transaction": (
                MAX_PACKAGE_RECORDS_PER_TRANSACTION
            ),
            "max_total_package_records": MAX_TOTAL_PACKAGE_RECORDS,
            "max_package_inputs_bytes": MAX_PACKAGE_INPUTS_BYTES,
            "max_package_transaction_bytes": MAX_PACKAGE_TRANSACTION_BYTES,
            "max_package_input_blob_bytes": MAX_PACKAGE_INPUT_BLOB_BYTES,
            "max_total_package_input_blob_bytes": (
                MAX_TOTAL_PACKAGE_INPUT_BLOB_BYTES
            ),
            "max_capture_journal_bytes": MAX_CAPTURE_JOURNAL_BYTES,
            "max_report_json_bytes": MAX_REPORT_JSON_BYTES,
            "max_report_dynamic_json_bytes": MAX_REPORT_DYNAMIC_JSON_BYTES,
            "max_run_relative_path_bytes": MAX_RUN_RELATIVE_PATH_BYTES,
            "max_run_relative_path_components": MAX_RUN_RELATIVE_PATH_COMPONENTS,
            "max_transaction_id_bytes": MAX_TRANSACTION_ID_BYTES,
            "max_package_name_bytes": MAX_PACKAGE_NAME_BYTES,
            "max_version_bytes": MAX_VERSION_BYTES,
            "max_architecture_bytes": MAX_ARCHITECTURE_BYTES,
            "max_config_key_bytes": MAX_CONFIG_KEY_BYTES,
            "max_config_value_bytes": MAX_CONFIG_VALUE_BYTES,
        },
        "limits": list(_LIMITS),
        "transactions": report_transactions,
        "counts": counts,
        "apt_actions": apt_status,
        "capture_origin": "unverified-mutable-target-rootfs",
        "filesystem_causality": "unverified",
        "release_ready": False,
        "detail": (
            f"{len(report_transactions)} self-consistent protocol-v3 capture(s) bind "
            f"{counts['total']} planned action(s), including {counts['unpack']} "
            "sealed .deb unpack action(s); APT origin, dpkg execution and final "
            "filesystem causality remain unverified"
        ),
    }
    if _compact_json_size(report) > MAX_REPORT_JSON_BYTES:
        raise PackageAptActionsError("APT action report exceeds the JSON byte bound")
    return report


def validate_package_apt_actions_report(
    recorded: Mapping[str, object],
    *,
    run_id: str,
    package_inputs: Mapping[str, object],
    package_inputs_identity: Mapping[str, object],
    journal_identity: Mapping[str, object],
    transactions: Sequence[Mapping[str, object]],
    captures: Sequence[AptProtocolCapture],
) -> PackageAptActionsValidation:
    """Recompute all semantics and refuse any release or causality promotion."""

    try:
        if not isinstance(recorded, Mapping):
            raise PackageAptActionsError("APT action report is not an object")
        if recorded.get("schema") != PACKAGE_APT_ACTIONS_SCHEMA:
            raise PackageAptActionsError("APT action report schema is unsupported")
        if recorded.get("run_id") != run_id:
            raise PackageAptActionsError("APT action report belongs to another run")
        if (
            recorded.get("capture_origin")
            != "unverified-mutable-target-rootfs"
            or recorded.get("filesystem_causality") != "unverified"
            or recorded.get("release_ready") is not False
        ):
            raise PackageAptActionsError(
                "APT action report contains a forbidden release promotion"
            )
        if recorded.get("apt_actions") not in {
            "self-consistent",
            "not-observed",
        }:
            raise PackageAptActionsError("APT action status is malformed")
        recomputed = recompute_package_apt_actions_report(
            run_id=run_id,
            package_inputs=package_inputs,
            package_inputs_identity=package_inputs_identity,
            journal_identity=journal_identity,
            transactions=transactions,
            captures=captures,
        )
        if dict(recorded) != recomputed:
            raise PackageAptActionsError(
                "APT action report differs from exact recomputation"
            )
        status = cast(str, recomputed["apt_actions"])
        return PackageAptActionsValidation(
            True,
            (
                "APT protocol-v3 action report recomputes exactly; "
                f"apt_actions={status}, while capture origin, dpkg execution "
                "and filesystem causality remain unverified"
            ),
            apt_actions=status,
            capture_origin="unverified-mutable-target-rootfs",
        )
    except (
        PackageAptActionsError,
        UnicodeError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        return PackageAptActionsValidation(
            False,
            f"APT action validation failed: {exc}",
        )


def _parse_configuration_line(line: str) -> tuple[str, str]:
    if "=" not in line:
        raise PackageAptActionsError(
            "APT protocol configuration directive has no equals sign"
        )
    raw_key, raw_value = line.split("=", 1)
    if not raw_key:
        raise PackageAptActionsError("APT protocol configuration key is empty")
    # SendPkgsInfo omits configuration nodes whose value is empty, so accepting
    # ``key=`` would widen the language beyond the stream APT actually emits.
    if not raw_value:
        raise PackageAptActionsError("APT protocol configuration value is empty")
    if '"' in raw_key:
        raise PackageAptActionsError(
            "APT protocol configuration key has an unescaped quotation mark"
        )
    key = _percent_decode(raw_key, "configuration key", key=True)
    value = _percent_decode(raw_value, "configuration value", key=False)
    if len(key.encode("utf-8")) > MAX_CONFIG_KEY_BYTES:
        raise PackageAptActionsError("APT protocol configuration key exceeds its bound")
    if len(value.encode("utf-8")) > MAX_CONFIG_VALUE_BYTES:
        raise PackageAptActionsError("APT protocol configuration value exceeds its bound")
    return key, value


def _percent_decode(value: str, label: str, *, key: bool) -> str:
    encoded = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char == "%":
            if index + 2 >= len(value):
                raise PackageAptActionsError(
                    f"APT protocol {label} has a truncated percent escape"
                )
            digits = value[index + 1 : index + 3]
            if not re.fullmatch(r"[0-9a-f]{2}", digits):
                raise PackageAptActionsError(
                    f"APT protocol {label} has a non-canonical percent escape"
                )
            byte = int(digits, 16)
            needs_escape = (
                byte <= 0x20
                or byte >= 0x7F
                or byte == ord("%")
                or (key and byte in {ord("="), ord('"')})
            )
            if not needs_escape:
                raise PackageAptActionsError(
                    f"APT protocol {label} percent-encodes a safe byte"
                )
            encoded.append(byte)
            index += 3
            continue
        if ord(char) <= 0x20 or ord(char) >= 0x7F:
            raise PackageAptActionsError(
                f"APT protocol {label} has an unescaped unsafe character"
            )
        encoded.extend(char.encode("utf-8"))
        index += 1
    try:
        return bytes(encoded).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PackageAptActionsError(
            f"APT protocol {label} percent escapes are not UTF-8"
        ) from exc


def _parse_action_line(line: str) -> AptPackageAction:
    if "\t" in line:
        raise PackageAptActionsError("APT package action contains a tab")
    fields = line.split(" ")
    if len(fields) != 9 or any(not field for field in fields):
        raise PackageAptActionsError(
            "APT package action does not contain exactly nine fields"
        )
    (
        package,
        old_version,
        old_architecture,
        old_multiarch,
        direction,
        new_version,
        new_architecture,
        new_multiarch,
        action,
    ) = fields
    _package_name(package)
    _version_triplet(
        old_version,
        old_architecture,
        old_multiarch,
        "old",
    )
    _version_triplet(
        new_version,
        new_architecture,
        new_multiarch,
        "new",
    )
    if old_version == "-" and new_version == "-":
        raise PackageAptActionsError("APT package action has no old or new version")
    if direction not in _DIRECTIONS:
        raise PackageAptActionsError("APT package action direction is unsupported")
    if old_version == "-" and direction != "<":
        raise PackageAptActionsError(
            "APT first-install action does not use the upgrade direction"
        )
    if new_version == "-" and direction != ">":
        raise PackageAptActionsError(
            "APT removal action does not use the downgrade direction"
        )
    if direction == "=" and old_version != new_version:
        raise PackageAptActionsError(
            "APT no-change direction carries different versions"
        )
    if (
        old_version != "-"
        and new_version != "-"
        and old_version == new_version
        and direction != "="
    ):
        raise PackageAptActionsError(
            "APT equal versions carry a change direction"
        )

    if action == "**REMOVE**":
        if new_version != "-":
            raise PackageAptActionsError(
                "APT remove marker still carries a new package version"
            )
        operation = "remove"
    elif action == "**CONFIGURE**":
        if new_version == "-":
            raise PackageAptActionsError(
                "APT configure marker has no new package version"
            )
        operation = "configure"
    else:
        if action.startswith("**") or action.endswith("**"):
            raise PackageAptActionsError("APT package action marker is unsupported")
        _absolute_deb_path(action)
        if new_version == "-":
            raise PackageAptActionsError(
                "APT unpack action has no new package version"
            )
        if old_version == "-":
            operation = "install"
        elif direction == "<":
            operation = "upgrade"
        elif direction == ">":
            operation = "downgrade"
        else:
            operation = "reinstall"
    return AptPackageAction(
        package=package,
        old_version=old_version,
        old_architecture=old_architecture,
        old_multiarch=old_multiarch,
        direction=direction,
        new_version=new_version,
        new_architecture=new_architecture,
        new_multiarch=new_multiarch,
        action=action,
        operation=operation,
    )


def _package_name(value: str) -> None:
    if (
        len(value.encode("utf-8")) > MAX_PACKAGE_NAME_BYTES
        or not _PACKAGE_NAME.fullmatch(value)
    ):
        raise PackageAptActionsError("APT package action has an unsafe package name")


def _version_triplet(
    version: str,
    architecture: str,
    multiarch: str,
    label: str,
) -> None:
    if version == "-":
        if architecture != "-" or multiarch != "none":
            raise PackageAptActionsError(
                f"APT absent {label} version has inconsistent architecture or MultiArch"
            )
        return
    if (
        len(version.encode("utf-8")) > MAX_VERSION_BYTES
        or not _VERSION.fullmatch(version)
    ):
        raise PackageAptActionsError(f"APT {label} version is unsafe")
    if (
        len(architecture.encode("utf-8")) > MAX_ARCHITECTURE_BYTES
        or not _ARCHITECTURE.fullmatch(architecture)
    ):
        raise PackageAptActionsError(f"APT {label} architecture is unsafe")
    if multiarch not in _MULTIARCH:
        raise PackageAptActionsError(f"APT {label} MultiArch value is unsupported")


def _absolute_deb_path(value: str) -> None:
    if len(value.encode("utf-8")) > MAX_RUN_RELATIVE_PATH_BYTES:
        raise PackageAptActionsError("APT .deb action path exceeds its bound")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or value != path.as_posix()
        or not path.name.endswith(".deb")
        or any(part in {"", ".", ".."} for part in path.parts[1:])
        or len(path.parts) > MAX_RUN_RELATIVE_PATH_COMPONENTS
    ):
        raise PackageAptActionsError("APT unpack action has an unsafe .deb path")


def _transaction_contexts(
    package_inputs: Mapping[str, object],
    transactions: Sequence[Mapping[str, object]],
    run_id: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    refs_raw = package_inputs.get("transactions")
    if not isinstance(refs_raw, list) or not refs_raw:
        raise PackageAptActionsError("PACKAGE-INPUTS has no transaction references")
    if len(refs_raw) > MAX_PACKAGE_TRANSACTIONS:
        raise PackageAptActionsError(
            "PACKAGE-INPUTS exceeds the transaction-reference bound"
        )
    if (
        isinstance(transactions, (str, bytes))
        or not isinstance(transactions, Sequence)
        or len(transactions) != len(refs_raw)
    ):
        raise PackageAptActionsError(
            "decoded package transactions do not cover PACKAGE-INPUTS exactly"
        )

    refs_by_stem: dict[str, dict[str, object]] = {}
    normalised_refs: list[dict[str, object]] = []
    total_transaction_bytes = 0
    for raw_ref in refs_raw:
        ref = _identity(
            raw_ref,
            "package transaction",
            max_size=MAX_PACKAGE_TRANSACTION_BYTES,
        )
        path = cast(str, ref["path"])
        stem = PurePosixPath(path).stem
        if (
            not stem
            or path != f"apt/transactions/{stem}.json"
            or stem in refs_by_stem
        ):
            raise PackageAptActionsError(
                "PACKAGE-INPUTS transaction paths are ambiguous"
            )
        total_transaction_bytes += cast(int, ref["size"])
        if total_transaction_bytes > MAX_PACKAGE_TRANSACTION_BYTES:
            raise PackageAptActionsError(
                "PACKAGE-INPUTS transactions exceed the aggregate byte bound"
            )
        refs_by_stem[stem] = ref
        normalised_refs.append(ref)

    supplied: dict[str, Mapping[str, object]] = {}
    total_records = 0
    for raw_transaction in transactions:
        if not isinstance(raw_transaction, Mapping):
            raise PackageAptActionsError("package transaction is not an object")
        if (
            raw_transaction.get("schema") != _PACKAGE_TRANSACTION_SCHEMA
            or raw_transaction.get("run_id") != run_id
        ):
            raise PackageAptActionsError("package transaction identity is inconsistent")
        transaction_id = raw_transaction.get("id")
        if not isinstance(transaction_id, str):
            raise PackageAptActionsError("package transaction id is malformed")
        _safe_component(
            transaction_id,
            "package transaction id",
            MAX_TRANSACTION_ID_BYTES,
        )
        if transaction_id in supplied:
            raise PackageAptActionsError("package transaction id is duplicated")
        records = raw_transaction.get("records")
        if not isinstance(records, list):
            raise PackageAptActionsError("package transaction records are malformed")
        if len(records) > MAX_PACKAGE_RECORDS_PER_TRANSACTION:
            raise PackageAptActionsError(
                "package transaction exceeds the record bound"
            )
        total_records += len(records)
        if total_records > MAX_TOTAL_PACKAGE_RECORDS:
            raise PackageAptActionsError(
                "package transactions exceed the aggregate record bound"
            )
        if (
            raw_transaction.get("complete") is not True
            or raw_transaction.get("issues") != []
        ):
            raise PackageAptActionsError(
                f"package transaction {transaction_id} is not closed"
            )
        supplied[transaction_id] = raw_transaction
    if set(supplied) != set(refs_by_stem):
        raise PackageAptActionsError(
            "decoded package transaction ids differ from PACKAGE-INPUTS references"
        )

    contexts: list[dict[str, object]] = []
    for ref in normalised_refs:
        transaction_id = PurePosixPath(cast(str, ref["path"])).stem
        transaction = supplied[transaction_id]
        contexts.append(
            {
                "id": transaction_id,
                "identity": ref,
                "payload": transaction,
            }
        )
    return contexts, normalised_refs


def _captures(
    captures: Sequence[AptProtocolCapture],
) -> dict[str, AptProtocolCapture]:
    if (
        isinstance(captures, (str, bytes))
        or not isinstance(captures, Sequence)
        or len(captures) > MAX_APT_ACTION_CAPTURES
    ):
        raise PackageAptActionsError("APT action captures exceed their bound")
    result: dict[str, AptProtocolCapture] = {}
    paths: set[str] = set()
    for capture in captures:
        if not isinstance(capture, AptProtocolCapture):
            raise PackageAptActionsError("APT action capture is malformed")
        _safe_component(
            capture.transaction_id,
            "APT action transaction id",
            MAX_TRANSACTION_ID_BYTES,
        )
        path = _canonical_relative_path(capture.path, "APT action capture")
        expected_path = f"apt/protocol/{capture.sha256}.v3"
        if path != expected_path:
            raise PackageAptActionsError(
                "APT action capture path differs from its content identity"
            )
        if capture.transaction_id in result or path in paths:
            raise PackageAptActionsError("APT action capture is duplicated")
        if capture.complete is not True:
            raise PackageAptActionsError(
                f"APT action capture is incomplete: {capture.transaction_id}"
            )
        if (
            isinstance(capture.size, bool)
            or not isinstance(capture.size, int)
            or capture.size <= 0
            or capture.size > MAX_APT_PROTOCOL_BYTES
            or capture.size != len(capture.data)
        ):
            raise PackageAptActionsError(
                f"APT action capture size is invalid: {capture.transaction_id}"
            )
        if (
            not isinstance(capture.sha256, str)
            or not _SHA256.fullmatch(capture.sha256)
            or hashlib.sha256(capture.data).hexdigest() != capture.sha256
        ):
            raise PackageAptActionsError(
                f"APT action capture SHA256 is invalid: {capture.transaction_id}"
            )
        result[capture.transaction_id] = AptProtocolCapture(
            transaction_id=capture.transaction_id,
            path=path,
            size=capture.size,
            sha256=capture.sha256,
            data=capture.data,
            complete=True,
        )
        paths.add(path)
    return result


def _transaction_contract_records(
    transaction: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    raw_records = transaction.get("records")
    if not isinstance(raw_records, list):
        raise PackageAptActionsError("package transaction records are malformed")
    requirements = {
        "recorder": "/usr/lib/distroforge/capture-package-inputs",
        "config": "/etc/apt/apt.conf.d/99distroforge-evidence",
    }
    selected: dict[str, dict[str, object]] = {}
    for kind, source_path in requirements.items():
        matches = [
            record
            for record in raw_records
            if isinstance(record, Mapping)
            and record.get("kind") == kind
            and record.get("source_path") == source_path
        ]
        if len(matches) != 1:
            raise PackageAptActionsError(
                f"APT transaction does not seal exactly one {kind} contract record"
            )
        identity = _identity(
            matches[0],
            f"APT {kind} contract record",
            max_size=MAX_PACKAGE_INPUT_BLOB_BYTES,
        )
        selected[kind] = {
            "source_path": source_path,
            **identity,
        }
    recorder = selected["recorder"]
    configuration = selected["config"]
    if (
        recorder["path"] == configuration["path"]
        or (
            recorder["size"],
            recorder["sha256"],
        )
        == (
            configuration["size"],
            configuration["sha256"],
        )
    ):
        raise PackageAptActionsError(
            "APT recorder and configuration identities are duplicated"
        )
    return {
        "recorder": recorder,
        "configuration": configuration,
    }


def _transaction_deb_records(
    transaction: Mapping[str, object],
) -> dict[str, tuple[dict[str, object], ...]]:
    raw_records = transaction.get("records")
    if not isinstance(raw_records, list):
        raise PackageAptActionsError("package transaction records are malformed")
    grouped: dict[str, list[dict[str, object]]] = {}
    for raw_record in raw_records:
        if not isinstance(raw_record, Mapping) or raw_record.get("kind") != "deb":
            continue
        source = raw_record.get("source_path")
        if not isinstance(source, str):
            raise PackageAptActionsError("sealed .deb record has no source path")
        _absolute_deb_path(source)
        package = raw_record.get("package")
        version = raw_record.get("version")
        architecture = raw_record.get("architecture")
        if not isinstance(package, str):
            raise PackageAptActionsError(
                "sealed .deb record has no authoritative package name"
            )
        if not isinstance(version, str):
            raise PackageAptActionsError(
                "sealed .deb record has no authoritative package version"
            )
        if not isinstance(architecture, str):
            raise PackageAptActionsError(
                "sealed .deb record has no authoritative package architecture"
            )
        _package_name(package)
        _version_triplet(
            version,
            architecture,
            "none",
            "sealed .deb",
        )
        identity = _identity(
            raw_record,
            "sealed .deb record",
            max_size=MAX_PACKAGE_INPUT_BLOB_BYTES,
        )
        grouped.setdefault(source, []).append(
            {
                "source_path": source,
                "path": identity["path"],
                "size": identity["size"],
                "sha256": identity["sha256"],
                "package": package,
                "version": version,
                "architecture": architecture,
            }
        )
    return {source: tuple(records) for source, records in grouped.items()}


def _identity(
    value: object,
    label: str,
    *,
    max_size: int,
    required_path: str | None = None,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise PackageAptActionsError(f"{label} identity is not an object")
    path_raw = value.get("path")
    size = value.get("size")
    sha256 = value.get("sha256")
    if not isinstance(path_raw, str):
        raise PackageAptActionsError(f"{label} identity has no path")
    path = _canonical_relative_path(path_raw, label)
    if required_path is not None and path != required_path:
        raise PackageAptActionsError(f"{label} identity path is not canonical")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size <= 0
        or size > max_size
    ):
        raise PackageAptActionsError(f"{label} identity has an invalid size")
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        raise PackageAptActionsError(f"{label} identity has an invalid SHA256")
    return {"path": path, "size": size, "sha256": sha256}


def _canonical_relative_path(value: str, label: str) -> str:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PackageAptActionsError(f"{label} path is not UTF-8") from exc
    path = PurePosixPath(value)
    if (
        not value
        or len(encoded) > MAX_RUN_RELATIVE_PATH_BYTES
        or value.count("/") >= MAX_RUN_RELATIVE_PATH_COMPONENTS
        or path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PackageAptActionsError(f"{label} path is unsafe or non-canonical")
    return path.as_posix()


def _safe_component(value: str, label: str, max_bytes: int) -> None:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PackageAptActionsError(f"{label} is not UTF-8") from exc
    if (
        not value
        or len(encoded) > max_bytes
        or PurePosixPath(value).name != value
        or value in {".", ".."}
    ):
        raise PackageAptActionsError(f"{label} is unsafe")


def _canonical_sha256(value: object) -> str:
    try:
        body = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise PackageAptActionsError(
            f"APT action metadata is not serializable: {exc}"
        ) from exc
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _compact_json_size(value: object) -> int:
    try:
        return len(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise PackageAptActionsError(
            f"APT action report is not serializable: {exc}"
        ) from exc


__all__ = [
    "MAX_APT_ACTIONS_PER_CAPTURE",
    "MAX_APT_ACTION_CAPTURES",
    "MAX_APT_CONFIG_DIRECTIVES",
    "MAX_APT_PROTOCOL_BYTES",
    "MAX_APT_PROTOCOL_LINES",
    "MAX_APT_PROTOCOL_LINE_BYTES",
    "MAX_ARCHITECTURE_BYTES",
    "MAX_CONFIG_KEY_BYTES",
    "MAX_CONFIG_VALUE_BYTES",
    "MAX_CAPTURE_JOURNAL_BYTES",
    "MAX_PACKAGE_INPUTS_BYTES",
    "MAX_PACKAGE_INPUT_BLOB_BYTES",
    "MAX_TOTAL_PACKAGE_INPUT_BLOB_BYTES",
    "MAX_PACKAGE_NAME_BYTES",
    "MAX_PACKAGE_RECORDS_PER_TRANSACTION",
    "MAX_PACKAGE_TRANSACTIONS",
    "MAX_REPORT_JSON_BYTES",
    "MAX_REPORT_DYNAMIC_JSON_BYTES",
    "MAX_RUN_RELATIVE_PATH_BYTES",
    "MAX_RUN_RELATIVE_PATH_COMPONENTS",
    "MAX_TOTAL_APT_PROTOCOL_BYTES",
    "MAX_TOTAL_APT_ACTIONS",
    "MAX_TOTAL_APT_CONFIG_DIRECTIVES",
    "MAX_TOTAL_PACKAGE_RECORDS",
    "MAX_TRANSACTION_ID_BYTES",
    "MAX_VERSION_BYTES",
    "PACKAGE_APT_ACTIONS_FILENAME",
    "PACKAGE_APT_ACTIONS_SCHEMA",
    "AptPackageAction",
    "AptProtocolCapture",
    "AptProtocolV3",
    "PackageAptActionsError",
    "PackageAptActionsValidation",
    "build_package_apt_actions_report",
    "parse_apt_pre_install_v3",
    "recompute_package_apt_actions_report",
    "validate_package_apt_actions_report",
]
