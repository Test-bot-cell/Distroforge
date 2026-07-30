from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping, Sequence

import pytest

import distroforge.core.package_apt_actions as package_apt_actions_module
from distroforge.core.package_apt_actions import (
    MAX_APT_PROTOCOL_LINE_BYTES,
    PACKAGE_APT_ACTIONS_SCHEMA,
    AptProtocolCapture,
    PackageAptActionsError,
    build_package_apt_actions_report,
    parse_apt_pre_install_v3,
    validate_package_apt_actions_report,
)

_RUN_ID = "m32a-actions-fixture"
_HEX_A = "a" * 64
_HEX_B = "b" * 64
_HEX_C = "c" * 64

_INSTALL_PATH = "/var/cache/apt/archives/alpha_1.0-1_amd64.deb"
_UPGRADE_PATH = "/var/cache/apt/archives/bravo_2.0-1_amd64.deb"
_DOWNGRADE_PATH = "/var/cache/apt/archives/charlie_1.0-1_amd64.deb"

_PROTOCOL = (
    "VERSION 3\n"
    "APT::Architecture=amd64\n"
    "List::=first%25value\n"
    "Quoted%22Key=line%0abreak\n"
    "\n"
    f"alpha - - none < 1.0-1 amd64 no {_INSTALL_PATH}\n"
    f"bravo 1.0-1 amd64 none < 2.0-1 amd64 allowed {_UPGRADE_PATH}\n"
    f"charlie 2.0-1 amd64 no > 1.0-1 amd64 foreign {_DOWNGRADE_PATH}\n"
    "delta - - none < 3.0-1 arm64 same **CONFIGURE**\n"
    "echo 4.0-1 all foreign > - - none **REMOVE**\n"
).encode()


def _identity(
    path: str,
    sha256: str = _HEX_A,
    *,
    size: int = 123,
) -> dict[str, object]:
    return {"path": path, "size": size, "sha256": sha256}


def _deb_record(
    source_path: str,
    sha256: str,
    *,
    package: str | None = None,
    version: str | None = None,
    architecture: str | None = None,
) -> dict[str, object]:
    known_identities = {
        _INSTALL_PATH: ("alpha", "1.0-1", "amd64"),
        _UPGRADE_PATH: ("bravo", "2.0-1", "amd64"),
        _DOWNGRADE_PATH: ("charlie", "1.0-1", "amd64"),
    }
    inferred = known_identities.get(source_path, ("unused", "1", "all"))
    return {
        "kind": "deb",
        "source_path": source_path,
        "path": f"apt/blobs/deb/{sha256}.deb",
        "size": 100,
        "sha256": sha256,
        "package": package or inferred[0],
        "version": version or inferred[1],
        "architecture": architecture or inferred[2],
        "extra": "",
    }


def _contract_records() -> list[dict[str, object]]:
    return [
        {
            "kind": "recorder",
            "source_path": "/usr/lib/distroforge/capture-package-inputs",
            "path": "apt/blobs/recorder/" + "d" * 64,
            "size": 8192,
            "sha256": "d" * 64,
            "extra": "",
        },
        {
            "kind": "config",
            "source_path": "/etc/apt/apt.conf.d/99distroforge-evidence",
            "path": "apt/blobs/config/" + "e" * 64,
            "size": 1024,
            "sha256": "e" * 64,
            "extra": "",
        },
    ]


def _transaction(
    *,
    transaction_id: str = "apt-0001",
    kind: str = "apt-pre-install",
    records: Sequence[Mapping[str, object]] | None = None,
    contract_records: Sequence[Mapping[str, object]] | None = None,
) -> dict[str, object]:
    selected_records = (
        [
            _deb_record(_INSTALL_PATH, _HEX_A),
            _deb_record(_UPGRADE_PATH, _HEX_B),
            _deb_record(_DOWNGRADE_PATH, _HEX_C),
        ]
        if records is None
        else [dict(record) for record in records]
    )
    if kind == "apt-pre-install":
        selected_records.extend(
            dict(record)
            for record in (
                _contract_records()
                if contract_records is None
                else contract_records
            )
        )
    return {
        "schema": "distroforge.package-input-transaction.v1",
        "run_id": _RUN_ID,
        "id": transaction_id,
        "kind": kind,
        "fresh_rootfs": True,
        "records": selected_records,
        "inventory": [],
        "complete": True,
        "issues": [],
    }


def _package_inputs(
    transactions: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "schema": "distroforge.package-inputs.v1",
        "run_id": _RUN_ID,
        "scope": "target-root",
        "source_mode": "bootstrap",
        "capture_mode": "dpkg-pre-install-sealed-copy",
        "transactions": [
            _identity(
                f"apt/transactions/{transaction['id']}.json",
                hashlib.sha256(str(index).encode()).hexdigest(),
            )
            for index, transaction in enumerate(transactions)
        ],
        "baseline_inventory": [],
        "final_inventory": [],
    }


def _capture(
    data: bytes = _PROTOCOL,
    *,
    transaction_id: str = "apt-0001",
    complete: bool = True,
) -> AptProtocolCapture:
    digest = hashlib.sha256(data).hexdigest()
    return AptProtocolCapture(
        transaction_id=transaction_id,
        path=f"apt/protocol/{digest}.v3",
        size=len(data),
        sha256=digest,
        data=data,
        complete=complete,
    )


def _inputs_identity() -> dict[str, object]:
    return _identity("PACKAGE-INPUTS.json", _HEX_C, size=4096)


def _journal_identity() -> dict[str, object]:
    return _identity("apt/transactions.tsv", _HEX_B, size=2048)


def _report_fixture() -> tuple[
    dict[str, object],
    dict[str, object],
    list[dict[str, object]],
    list[AptProtocolCapture],
]:
    transactions = [_transaction()]
    package_inputs = _package_inputs(transactions)
    captures = [_capture()]
    report = build_package_apt_actions_report(
        run_id=_RUN_ID,
        package_inputs=package_inputs,
        package_inputs_identity=_inputs_identity(),
        journal_identity=_journal_identity(),
        transactions=transactions,
        captures=captures,
    )
    return report, package_inputs, transactions, captures


def test_protocol_v3_parser_preserves_configuration_and_all_action_types() -> None:
    parsed = parse_apt_pre_install_v3(_PROTOCOL)

    assert parsed.version == 3
    assert parsed.size == len(_PROTOCOL)
    assert parsed.sha256 == hashlib.sha256(_PROTOCOL).hexdigest()
    assert parsed.configuration == (
        ("APT::Architecture", "amd64"),
        ("List::", "first%value"),
        ('Quoted"Key', "line\nbreak"),
    )
    assert [action.operation for action in parsed.actions] == [
        "install",
        "upgrade",
        "downgrade",
        "configure",
        "remove",
    ]
    assert parsed.actions[0].old_architecture == "-"
    assert parsed.actions[1].new_multiarch == "allowed"
    assert parsed.actions[2].new_multiarch == "foreign"
    assert parsed.actions[3].new_multiarch == "same"
    assert parsed.actions[4].old_multiarch == "foreign"


def test_protocol_configuration_decodes_canonical_spaces_and_safe_punctuation() -> None:
    protocol = (
        b"VERSION 3\n"
        b"CommandLine::AsString=apt-get%20install%20proof\n"
        b'Quoted=two%20words%20"and"=equals\n'
        b"\n"
        b"proof - - none < 1 all no /tmp/proof.deb\n"
    )

    parsed = parse_apt_pre_install_v3(protocol)

    assert parsed.configuration == (
        ("CommandLine::AsString", "apt-get install proof"),
        ("Quoted", 'two words "and"=equals'),
    )


def test_report_binds_every_unpack_to_one_sealed_package_input_record() -> None:
    report, package_inputs, transactions, captures = _report_fixture()

    assert report["schema"] == PACKAGE_APT_ACTIONS_SCHEMA
    assert report["scope"] == "apt-dpkg-pre-install-pkgs-v3-planned-actions-m3.2a"
    package_binding = report["package_inputs"]
    assert isinstance(package_binding, dict)
    assert package_binding == {
        **_inputs_identity(),
        "schema": "distroforge.package-inputs.v1",
        "source_mode": "bootstrap",
        "transaction_count": 1,
        "transactions_sha256": package_binding["transactions_sha256"],
    }
    assert report["apt_actions"] == "self-consistent"
    assert report["capture_origin"] == "unverified-mutable-target-rootfs"
    assert report["filesystem_causality"] == "unverified"
    assert report["release_ready"] is False
    assert report["capture_journal"] == _journal_identity()
    assert report["counts"] == {
        "install": 1,
        "upgrade": 1,
        "downgrade": 1,
        "reinstall": 0,
        "configure": 1,
        "remove": 1,
        "unpack": 3,
        "total": 5,
    }
    report_transactions = report["transactions"]
    assert isinstance(report_transactions, list)
    apt_transaction = report_transactions[0]
    assert apt_transaction["recorder"] == {
        "source_path": "/usr/lib/distroforge/capture-package-inputs",
        "path": "apt/blobs/recorder/" + "d" * 64,
        "size": 8192,
        "sha256": "d" * 64,
    }
    assert apt_transaction["configuration"] == {
        "source_path": "/etc/apt/apt.conf.d/99distroforge-evidence",
        "path": "apt/blobs/config/" + "e" * 64,
        "size": 1024,
        "sha256": "e" * 64,
    }
    actions = apt_transaction["actions"]
    assert [action["deb"]["sha256"] for action in actions[:3]] == [
        _HEX_A,
        _HEX_B,
        _HEX_C,
    ]
    assert all("deb" not in action for action in actions[3:])
    assert apt_transaction["capture"] == {
        "path": f"apt/protocol/{hashlib.sha256(_PROTOCOL).hexdigest()}.v3",
        "size": len(_PROTOCOL),
        "sha256": hashlib.sha256(_PROTOCOL).hexdigest(),
        "complete": True,
    }

    validation = validate_package_apt_actions_report(
        report,
        run_id=_RUN_ID,
        package_inputs=package_inputs,
        package_inputs_identity=_inputs_identity(),
        journal_identity=_journal_identity(),
        transactions=transactions,
        captures=captures,
    )
    assert validation.ok
    assert validation.apt_actions == "self-consistent"
    assert validation.capture_origin == "unverified-mutable-target-rootfs"
    assert validation.filesystem_causality == "unverified"
    assert validation.release_ready is False


def test_no_apt_transaction_is_explicitly_not_observed_and_never_promoted() -> None:
    transactions = [_transaction(transaction_id="final-apt-state", kind="apt-state", records=[])]
    package_inputs = _package_inputs(transactions)
    header_only_journal = _journal_identity()

    report = build_package_apt_actions_report(
        run_id=_RUN_ID,
        package_inputs=package_inputs,
        package_inputs_identity=_inputs_identity(),
        journal_identity=header_only_journal,
        transactions=transactions,
        captures=[],
    )

    assert report["apt_actions"] == "not-observed"
    assert report["transactions"] == []
    counts = report["counts"]
    assert isinstance(counts, dict)
    assert counts["total"] == 0
    assert report["filesystem_causality"] == "unverified"
    assert report["release_ready"] is False
    validation = validate_package_apt_actions_report(
        report,
        run_id=_RUN_ID,
        package_inputs=package_inputs,
        package_inputs_identity=_inputs_identity(),
        journal_identity=header_only_journal,
        transactions=transactions,
        captures=[],
    )
    assert validation.ok
    assert validation.apt_actions == "not-observed"


def test_not_observed_still_requires_a_nonempty_capture_journal() -> None:
    transactions = [
        _transaction(
            transaction_id="final-apt-state",
            kind="apt-state",
            records=[],
        )
    ]
    package_inputs = _package_inputs(transactions)

    with pytest.raises(PackageAptActionsError, match="invalid size"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=package_inputs,
            package_inputs_identity=_inputs_identity(),
            journal_identity=_identity(
                "apt/transactions.tsv",
                hashlib.sha256(b"").hexdigest(),
                size=0,
            ),
            transactions=transactions,
            captures=[],
        )


@pytest.mark.parametrize(
    ("data", "detail"),
    [
        (b"VERSION 2\n\npkg - - none < 1 all no /tmp/pkg.deb\n", "version 3"),
        (b"VERSION 3\nAPT::Architecture=amd64\n", "empty terminator"),
        (b"VERSION 3\n\n", "no package actions"),
        (
            b"VERSION 3\nBroken=%2F\n\npkg - - none < 1 all no /tmp/pkg.deb\n",
            "percent escape",
        ),
        (
            b"VERSION 3\nEmpty=\n\npkg - - none < 1 all no /tmp/pkg.deb\n",
            "value is empty",
        ),
        (
            b"VERSION 3\nBroken=two\twords\n\npkg - - none < 1 all no /tmp/pkg.deb\n",
            "unescaped unsafe character",
        ),
        (
            b'VERSION 3\nRaw"Quote=value\n\npkg - - none < 1 all no /tmp/pkg.deb\n',
            "quotation mark",
        ),
        (
            b"VERSION 3\n\npkg - - none < 1 all no /tmp/pkg.deb",
            "final newline",
        ),
        (
            b"VERSION 3\r\n\r\npkg - - none < 1 all no /tmp/pkg.deb\r\n",
            "carriage return",
        ),
        (
            b"VERSION 3\n\npkg - - none < 1 all no\n",
            "exactly nine fields",
        ),
        (
            b"VERSION 3\n\npkg\t-\t-\tnone\t<\t1\tall\tno\t/tmp/pkg.deb\n",
            "tab",
        ),
        (
            b"VERSION 3\n\npkg - - none < 1 all no **ERROR**\n",
            "marker",
        ),
        (
            b"VERSION 3\n\npkg - - none < 1 all no relative.deb\n",
            "unsafe .deb path",
        ),
        (
            b"VERSION 3\n\npkg - all none < 1 all no /tmp/pkg.deb\n",
            "inconsistent architecture",
        ),
        (
            b"VERSION 3\n\npkg 1 all unknown < 2 all no /tmp/pkg.deb\n",
            "MultiArch",
        ),
        (
            b"VERSION 3\n\npkg 1 all no = 2 all no /tmp/pkg.deb\n",
            "different versions",
        ),
        (
            b"VERSION 3\n\npkg 1 all no < 1 all no /tmp/pkg.deb\n",
            "equal versions",
        ),
        (
            b"VERSION 3\n\npkg 1 all no < 2 all no /tmp/pkg.deb\n\n",
            "empty package-action",
        ),
        (
            b"VERSION 3\nBad=\xff\n\npkg - - none < 1 all no /tmp/pkg.deb\n",
            "not UTF-8",
        ),
    ],
)
def test_protocol_parser_fails_closed_on_malformed_or_downgraded_streams(
    data: bytes,
    detail: str,
) -> None:
    with pytest.raises(PackageAptActionsError, match=detail):
        parse_apt_pre_install_v3(data)


def test_protocol_parser_enforces_the_per_line_bound_before_growth() -> None:
    data = b"VERSION 3\nKey=" + b"x" * MAX_APT_PROTOCOL_LINE_BYTES + b"\n\n"
    data += b"pkg - - none < 1 all no /tmp/pkg.deb\n"

    with pytest.raises(PackageAptActionsError, match="per-line bound"):
        parse_apt_pre_install_v3(data)


@pytest.mark.parametrize(
    "mutation",
    [
        "capture_origin",
        "filesystem_causality",
        "release_ready",
        "actions",
        "capture",
    ],
)
def test_validation_recomputes_and_refuses_forged_reports(mutation: str) -> None:
    report, package_inputs, transactions, captures = _report_fixture()
    forged = copy.deepcopy(report)
    if mutation == "capture_origin":
        forged["capture_origin"] = "verified"
    elif mutation == "filesystem_causality":
        forged["filesystem_causality"] = "verified"
    elif mutation == "release_ready":
        forged["release_ready"] = True
    else:
        forged_transactions = forged["transactions"]
        assert isinstance(forged_transactions, list)
        forged_transaction = forged_transactions[0]
        assert isinstance(forged_transaction, dict)
        if mutation == "actions":
            forged_actions = forged_transaction["actions"]
            assert isinstance(forged_actions, list)
            forged_action = forged_actions[0]
            assert isinstance(forged_action, dict)
            forged_action["package"] = "forged"
        else:
            forged_capture = forged_transaction["capture"]
            assert isinstance(forged_capture, dict)
            forged_capture["complete"] = False

    validation = validate_package_apt_actions_report(
        forged,
        run_id=_RUN_ID,
        package_inputs=package_inputs,
        package_inputs_identity=_inputs_identity(),
        journal_identity=_journal_identity(),
        transactions=transactions,
        captures=captures,
    )

    assert not validation.ok
    assert validation.apt_actions == "unverified"
    assert validation.filesystem_causality == "unverified"
    assert validation.release_ready is False


def test_capture_bytes_must_match_their_size_sha_and_completion_marker() -> None:
    transactions = [_transaction()]
    package_inputs = _package_inputs(transactions)
    good = _capture()
    captures = [
        AptProtocolCapture(
            transaction_id=good.transaction_id,
            path=good.path,
            size=good.size,
            sha256=good.sha256,
            data=good.data + b"forged",
            complete=True,
        )
    ]

    with pytest.raises(PackageAptActionsError, match="size is invalid"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=package_inputs,
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=captures,
        )
    with pytest.raises(PackageAptActionsError, match="incomplete"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=package_inputs,
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=[_capture(complete=False)],
        )


def test_every_apt_transaction_requires_exactly_one_matching_capture() -> None:
    transactions = [_transaction()]
    package_inputs = _package_inputs(transactions)

    with pytest.raises(PackageAptActionsError, match="missing transaction"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=package_inputs,
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=[],
        )

    final_transactions = [
        _transaction(transaction_id="final-apt-state", kind="apt-state", records=[])
    ]
    with pytest.raises(PackageAptActionsError, match="non-APT transaction"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=_package_inputs(final_transactions),
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=final_transactions,
            captures=[_capture(transaction_id="final-apt-state")],
        )


def test_unpack_actions_require_an_exact_and_exhaustive_deb_binding() -> None:
    records = [
        _deb_record(_INSTALL_PATH, _HEX_A),
        _deb_record(_UPGRADE_PATH, _HEX_B),
    ]
    transactions = [_transaction(records=records)]
    with pytest.raises(PackageAptActionsError, match="does not bind exactly one"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=_package_inputs(transactions),
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=[_capture()],
        )

    duplicate_records = [
        _deb_record(_INSTALL_PATH, _HEX_A),
        _deb_record(_INSTALL_PATH, _HEX_B),
        _deb_record(_UPGRADE_PATH, _HEX_B),
        _deb_record(_DOWNGRADE_PATH, _HEX_C),
    ]
    duplicate_transactions = [_transaction(records=duplicate_records)]
    with pytest.raises(PackageAptActionsError, match="does not bind exactly one"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=_package_inputs(duplicate_transactions),
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=duplicate_transactions,
            captures=[_capture()],
        )

    extra_path = "/var/cache/apt/archives/unused_1_all.deb"
    extra_records = [
        _deb_record(_INSTALL_PATH, _HEX_A),
        _deb_record(_UPGRADE_PATH, _HEX_B),
        _deb_record(_DOWNGRADE_PATH, _HEX_C),
        _deb_record(extra_path, "d" * 64),
    ]
    extra_transactions = [_transaction(records=extra_records)]
    with pytest.raises(PackageAptActionsError, match="no APT unpack action"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=_package_inputs(extra_transactions),
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=extra_transactions,
            captures=[_capture()],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("package", "not-alpha"),
        ("version", "9.9-1"),
        ("architecture", "arm64"),
    ],
)
def test_unpack_action_must_match_the_authoritative_deb_identity_fields(
    field: str,
    value: str,
) -> None:
    first = _deb_record(_INSTALL_PATH, _HEX_A)
    first[field] = value
    records = [
        first,
        _deb_record(_UPGRADE_PATH, _HEX_B),
        _deb_record(_DOWNGRADE_PATH, _HEX_C),
    ]
    transactions = [_transaction(records=records)]

    with pytest.raises(PackageAptActionsError, match="identity differs"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=_package_inputs(transactions),
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=[_capture()],
        )


@pytest.mark.parametrize("missing_kind", ["recorder", "config"])
def test_apt_transaction_requires_one_sealed_recorder_and_configuration(
    missing_kind: str,
) -> None:
    contract = [
        record for record in _contract_records() if record["kind"] != missing_kind
    ]
    transactions = [_transaction(contract_records=contract)]

    with pytest.raises(PackageAptActionsError, match="contract record"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=_package_inputs(transactions),
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=[_capture()],
        )


def test_recorder_and_configuration_identities_cannot_be_duplicated() -> None:
    contract = _contract_records()
    contract[1]["path"] = contract[0]["path"]
    contract[1]["size"] = contract[0]["size"]
    contract[1]["sha256"] = contract[0]["sha256"]
    transactions = [_transaction(contract_records=contract)]

    with pytest.raises(PackageAptActionsError, match="identities are duplicated"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=_package_inputs(transactions),
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=[_capture()],
        )


def test_package_inputs_and_transaction_identity_are_external_recompute_inputs() -> None:
    report, package_inputs, transactions, captures = _report_fixture()
    changed_identity = _inputs_identity()
    changed_identity["sha256"] = _HEX_A

    validation = validate_package_apt_actions_report(
        report,
        run_id=_RUN_ID,
        package_inputs=package_inputs,
        package_inputs_identity=changed_identity,
        journal_identity=_journal_identity(),
        transactions=transactions,
        captures=captures,
    )
    assert not validation.ok
    assert "recomputation" in validation.detail

    changed_journal = _journal_identity()
    changed_journal["sha256"] = _HEX_A
    journal_validation = validate_package_apt_actions_report(
        report,
        run_id=_RUN_ID,
        package_inputs=package_inputs,
        package_inputs_identity=_inputs_identity(),
        journal_identity=changed_journal,
        transactions=transactions,
        captures=captures,
    )
    assert not journal_validation.ok
    assert "recomputation" in journal_validation.detail

    malformed_inputs = dict(package_inputs)
    malformed_inputs["run_id"] = "another-run"
    with pytest.raises(PackageAptActionsError, match="another run"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=malformed_inputs,
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=captures,
        )


def test_transaction_and_protocol_paths_are_content_bound() -> None:
    transactions = [_transaction()]
    package_inputs = _package_inputs(transactions)
    wrong_refs = [dict(package_inputs["transactions"][0])]
    wrong_refs[0]["path"] = "renamed/apt-0001.json"
    wrong_inputs = {**package_inputs, "transactions": wrong_refs}

    with pytest.raises(PackageAptActionsError, match="paths are ambiguous"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=wrong_inputs,
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=[_capture()],
        )

    capture = _capture()
    renamed_capture = AptProtocolCapture(
        transaction_id=capture.transaction_id,
        path="apt/protocol/renamed.v3",
        size=capture.size,
        sha256=capture.sha256,
        data=capture.data,
        complete=True,
    )
    with pytest.raises(PackageAptActionsError, match="content identity"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=package_inputs,
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=[renamed_capture],
        )


def test_large_sealed_deb_identity_is_not_confused_with_json_bounds() -> None:
    records = [
        _deb_record(_INSTALL_PATH, _HEX_A),
        _deb_record(_UPGRADE_PATH, _HEX_B),
        _deb_record(_DOWNGRADE_PATH, _HEX_C),
    ]
    records[0]["size"] = 512 * 1024 * 1024
    transactions = [_transaction(records=records)]

    report = build_package_apt_actions_report(
        run_id=_RUN_ID,
        package_inputs=_package_inputs(transactions),
        package_inputs_identity=_inputs_identity(),
        journal_identity=_journal_identity(),
        transactions=transactions,
        captures=[_capture()],
    )

    assert report["apt_actions"] == "self-consistent"


def test_aggregate_action_and_dynamic_report_budgets_fail_before_growth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = (
        b"VERSION 3\n\n"
        b"alpha 1 amd64 none = 1 amd64 none **CONFIGURE**\n"
        b"bravo 1 amd64 none = 1 amd64 none **CONFIGURE**\n"
    )
    transactions = [_transaction(records=[])]
    package_inputs = _package_inputs(transactions)
    capture = _capture(protocol)
    monkeypatch.setattr(
        package_apt_actions_module,
        "MAX_TOTAL_APT_ACTIONS",
        1,
    )

    with pytest.raises(PackageAptActionsError, match="aggregate action bound"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=package_inputs,
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=[capture],
        )

    monkeypatch.setattr(
        package_apt_actions_module,
        "MAX_TOTAL_APT_ACTIONS",
        100_000,
    )
    monkeypatch.setattr(
        package_apt_actions_module,
        "MAX_REPORT_DYNAMIC_JSON_BYTES",
        1,
    )
    with pytest.raises(PackageAptActionsError, match="dynamic JSON budget"):
        build_package_apt_actions_report(
            run_id=_RUN_ID,
            package_inputs=package_inputs,
            package_inputs_identity=_inputs_identity(),
            journal_identity=_journal_identity(),
            transactions=transactions,
            captures=[capture],
        )
