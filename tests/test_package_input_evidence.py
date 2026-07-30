from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path

import pytest

import distroforge.core.package_evidence as package_evidence_module
from distroforge.core.bootstrap import BootstrapOptions, BootstrapService
from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.package_apt_actions import (
    MAX_APT_PROTOCOL_BYTES,
    MAX_PACKAGE_INPUT_BLOB_BYTES,
    MAX_TOTAL_PACKAGE_INPUT_BLOB_BYTES,
    PACKAGE_APT_ACTIONS_FILENAME,
    AptProtocolCapture,
    build_package_apt_actions_report,
)
from distroforge.core.package_evidence import (
    PACKAGE_INPUTS_SCHEMA,
    PACKAGE_TRANSACTION_SCHEMA,
    PackageEvidenceService,
    PackageEvidenceValidation,
    PackageSourcePolicy,
    _capture_hook_config,
    _capture_hook_script,
    _inside_root,
    _packages_records,
    _parse_sealed_capture_journal,
    _stable_digest,
    package_apt_command_argv_sha256,
    package_source_policy_sha256,
    validate_package_apt_actions_evidence,
    validate_package_evidence_payload,
)
from distroforge.core.project import Project
from distroforge.core.release_gate import _command_argv_ledger

FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
BUILD_TIME = "2026-07-29T12:00:00+00:00"
SAFE_APT_COMMANDS = (("apt-get", "update"),)


def test_release_gate_apt_ledger_uses_the_complete_final_command_log(
    tmp_path: Path,
) -> None:
    command_log = tmp_path / "commands.jsonl"
    events = (
        {"event": "start", "argv": ["mmdebstrap", "proof"]},
        {"event": "finish", "argv": ["mmdebstrap", "proof"], "returncode": 0},
        {"event": "start", "argv": ["xorriso", "-as", "mkisofs"]},
        {"event": "start", "argv": ["apt-get", "install", "late-package"]},
    )
    command_log.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    assert _command_argv_ledger(command_log) == (
        ("mmdebstrap", "proof"),
        ("xorriso", "-as", "mkisofs"),
        ("apt-get", "install", "late-package"),
    )


def test_release_gate_apt_ledger_rejects_malformed_or_symlinked_logs(
    tmp_path: Path,
) -> None:
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_text('{"event":"start","argv":[]}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="malformed argv"):
        _command_argv_ledger(malformed)

    target = tmp_path / "target.jsonl"
    target.write_text('{"event":"start","argv":["apt-get","update"]}\n', encoding="utf-8")
    linked = tmp_path / "linked.jsonl"
    linked.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        _command_argv_ledger(linked)


def _identity(path: Path, run_dir: Path, **extra: object) -> dict[str, object]:
    digest, size = _stable_digest(path)
    return {
        "path": str(path.relative_to(run_dir)),
        "size": size,
        "sha256": digest,
        **extra,
    }


def _capture_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    index_targets: str = "",
    archive_keyring: Path | None = None,
    archive_keyring_sha256: str | None = None,
) -> tuple[PackageEvidenceService, Project]:
    project = Project.create("Confinement", tmp_path / "project", "26.04")
    project.squashfs_root.mkdir(parents=True)
    runner = CommandRunner(dry_run=False)

    def fake_run(spec: CommandSpec, check: bool = True) -> CommandResult:
        del check
        argv = spec.argv
        if "apt-config" in argv:
            stdout = (
                "lists='/var/lib/apt/lists'\n"
                "archives='/var/cache/apt/archives'\n"
            )
        elif "indextargets" in argv:
            stdout = index_targets
        else:
            stdout = ""
        return CommandResult(
            spec=spec,
            returncode=0,
            stdout=stdout,
            stderr="",
        )

    monkeypatch.setattr(runner, "run", fake_run)
    service = PackageEvidenceService(
        runner,
        project,
        project.squashfs_root,
        {
            "run_id": "confinement-run",
            "mode": "execute",
            "created_at": BUILD_TIME,
        },
        use_sudo=False,
        archive_keyring=archive_keyring,
        archive_keyring_sha256=archive_keyring_sha256,
    )
    return service, project


def _assert_bytes_absent(root: Path, forbidden: bytes) -> None:
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            assert forbidden not in path.read_bytes()


def _minimal_deb(tmp_path: Path) -> tuple[Path, str, int]:
    tree = tmp_path / "deb-tree"
    (tree / "DEBIAN").mkdir(parents=True)
    (tree / "DEBIAN/control").write_text(
        "\n".join(
            [
                "Package: proof-package",
                "Version: 1.2.3-1",
                "Architecture: all",
                "Maintainer: DistroForge <github@distroforge.anonaddy.com>",
                "Description: package-input evidence fixture",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tree / "usr/share/proof").mkdir(parents=True)
    (tree / "usr/share/proof/payload").write_bytes(b"installed bytes\n")
    deb = tmp_path / "proof-package_1.2.3-1_all.deb"
    subprocess.run(
        ("dpkg-deb", "--build", str(tree), str(deb)),
        check=True,
        capture_output=True,
        text=True,
    )
    digest, size = _stable_digest(deb)
    return deb, digest, size


def _valid_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, object], Path, Path, str]:
    run_dir = tmp_path / "run"
    blobs = run_dir / "apt/blobs"
    for kind in ("source", "keyring", "release", "index", "deb"):
        (blobs / kind).mkdir(parents=True, exist_ok=True)

    built_deb, deb_sha, deb_size = _minimal_deb(tmp_path)
    sealed_deb = blobs / "deb" / f"{deb_sha}.deb"
    sealed_deb.write_bytes(built_deb.read_bytes())
    packages_text = "\n".join(
        [
            "Package: proof-package",
            "Version: 1.2.3-1",
            "Architecture: all",
            f"Size: {deb_size}",
            f"SHA256: {deb_sha}",
            "Filename: pool/main/p/proof-package/proof-package_1.2.3-1_all.deb",
            "",
        ]
    )
    packages = blobs / "index" / "packages"
    packages.write_text(packages_text, encoding="utf-8")
    packages_sha, packages_size = _stable_digest(packages)
    release_payload = "\n".join(
        [
            "Origin: Fixture",
            "Suite: proof",
            "Codename: proof",
            "Date: Wed, 29 Jul 2026 10:00:00 +0000",
            "Valid-Until: Thu, 30 Jul 2026 10:00:00 +0000",
            "Architectures: all",
            "Components: main",
            "SHA256:",
            f" {packages_sha} {packages_size} main/binary-all/Packages",
            "",
        ]
    )
    inrelease = blobs / "release" / "inrelease"
    inrelease.write_text("signed fixture bytes\n", encoding="utf-8")
    keyring = blobs / "keyring" / "archive.gpg"
    keyring.write_bytes(b"fixture trust anchor\n")
    source = blobs / "source" / "sources.list"
    source.write_text(
        "deb [signed-by=/usr/share/keyrings/archive.gpg] https://repo.invalid proof main\n",
        encoding="utf-8",
    )
    keyring_sha256 = _stable_digest(keyring)[0]
    source_policy = PackageSourcePolicy(
        policy_id="fixture-archive",
        base_uri="https://repo.invalid",
        suites=("proof",),
        codenames=("proof",),
        components=("main",),
        architectures=("all",),
        signer_fingerprints=(FINGERPRINT,),
        keyring_sha256=(keyring_sha256,),
        max_release_age_seconds=24 * 60 * 60,
        require_valid_until=True,
    )

    records = [
        _identity(
            source,
            run_dir,
            kind="source",
            source_path="/etc/apt/sources.list",
            extra="",
        ),
        _identity(
            keyring,
            run_dir,
            kind="keyring",
            source_path="/usr/share/keyrings/archive.gpg",
            extra="host-bootstrap",
        ),
        _identity(
            inrelease,
            run_dir,
            kind="release",
            source_path="/var/lib/apt/lists/repo_proof_InRelease",
            extra="",
        ),
        _identity(
            packages,
            run_dir,
            kind="index",
            source_path="/var/lib/apt/lists/repo_proof_main_binary-all_Packages",
            extra="https://repo.invalid/dists/proof/main/binary-all/Packages",
        ),
        _identity(
            sealed_deb,
            run_dir,
            kind="deb",
            source_path="/var/cache/apt/archives/proof-package_1.2.3-1_all.deb",
            extra="",
        ),
    ]
    transaction = {
        "schema": PACKAGE_TRANSACTION_SCHEMA,
        "run_id": "proof-run",
        "id": "bootstrap",
        "kind": "bootstrap",
        "fresh_rootfs": True,
        "records": records,
        "inventory": [
            {
                "package": "proof-package",
                "version": "1.2.3-1",
                "architecture": "all",
            }
        ],
        "complete": True,
        "issues": [],
    }
    transaction_path = run_dir / "apt/transactions/bootstrap.json"
    transaction_path.parent.mkdir(parents=True)
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    final_state = {
        "schema": PACKAGE_TRANSACTION_SCHEMA,
        "run_id": "proof-run",
        "id": "final-apt-state",
        "kind": "apt-state",
        "fresh_rootfs": True,
        "records": [record for record in records if record["kind"] != "deb"],
        "inventory": [],
        "complete": True,
        "issues": [],
    }
    final_state_path = run_dir / "apt/transactions/final-apt-state.json"
    final_state_path.write_text(
        json.dumps(final_state, indent=2) + "\n",
        encoding="utf-8",
    )
    payload = {
        "schema": PACKAGE_INPUTS_SCHEMA,
        "run_id": "proof-run",
        "scope": "target-root",
        "source_mode": "bootstrap",
        "capture_mode": "dpkg-pre-install-sealed-copy",
        "fresh_rootfs": True,
        "archive_keyring": {
            "source": "/usr/share/keyrings/archive.gpg",
            "expected_sha256": keyring_sha256,
        },
        "allowed_signer_fingerprints": [FINGERPRINT],
        "source_policy_sha256": package_source_policy_sha256([source_policy]),
        "verification_time": BUILD_TIME,
        "apt_command_argv_sha256": package_apt_command_argv_sha256(
            SAFE_APT_COMMANDS
        ),
        "transactions": [
            _identity(transaction_path, run_dir),
            _identity(final_state_path, run_dir),
        ],
        "baseline_inventory": [],
        "final_inventory": [
            {
                "package": "proof-package",
                "version": "1.2.3-1",
                "architecture": "all",
            }
        ],
    }
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            release_payload,
            f"[GNUPG:] VALIDSIG {FINGERPRINT} 0 0 0 4 0 1 10 01 {FINGERPRINT}\n",
        ),
    )
    return payload, run_dir, sealed_deb, release_payload


def _validate(
    payload: dict[str, object],
    run_dir: Path,
    *,
    apt_command_argv: tuple[tuple[str, ...], ...] = SAFE_APT_COMMANDS,
    signer_fingerprints: tuple[str, ...] = (FINGERPRINT,),
) -> PackageEvidenceValidation:
    keyring = payload["archive_keyring"]
    assert isinstance(keyring, dict)
    expected_keyring_sha256 = keyring["expected_sha256"]
    assert isinstance(expected_keyring_sha256, str)
    source_policy = PackageSourcePolicy(
        policy_id="fixture-archive",
        base_uri="https://repo.invalid",
        suites=("proof",),
        codenames=("proof",),
        components=("main",),
        architectures=("all",),
        signer_fingerprints=signer_fingerprints,
        keyring_sha256=(expected_keyring_sha256,),
        max_release_age_seconds=24 * 60 * 60,
        require_valid_until=True,
    )
    return validate_package_evidence_payload(
        payload,
        run_dir,
        run_gpg=True,
        expected_source_mode="bootstrap",
        expected_signer_fingerprints=signer_fingerprints,
        expected_keyring_sha256=expected_keyring_sha256,
        expected_source_policies=[source_policy],
        expected_verification_time=BUILD_TIME,
        apt_command_argv=apt_command_argv,
    )


def test_bootstrap_tools_retain_inputs_and_pin_an_explicit_keyring(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project = Project.create("Proof", tmp_path / "project", "26.04")
    keyring = tmp_path / "archive.gpg"
    options = BootstrapOptions(archive_keyring=keyring)

    mm_runner = CommandRunner(dry_run=True)
    monkeypatch.setattr(mm_runner, "has_binary", lambda name: name == "mmdebstrap")
    BootstrapService(
        mm_runner,
        project.release,
        project.squashfs_root,
        project.iso_root,
        options,
        use_sudo=False,
    ).create_rootfs()
    mm_argv = next(
        spec.argv for spec in mm_runner.history if spec.argv[:1] == ("mmdebstrap",)
    )
    assert f"--keyring={keyring}" in mm_argv
    assert "--skip=essential/unlink" in mm_argv
    assert "--skip=cleanup/apt/lists" in mm_argv
    assert "--skip=cleanup/apt/cache" in mm_argv

    debootstrap_runner = CommandRunner(dry_run=True)
    monkeypatch.setattr(debootstrap_runner, "has_binary", lambda _name: False)
    BootstrapService(
        debootstrap_runner,
        project.release,
        project.squashfs_root,
        project.iso_root,
        options,
        use_sudo=False,
    ).create_rootfs()
    debootstrap_argv = next(
        spec.argv
        for spec in debootstrap_runner.history
        if spec.argv[:1] == ("debootstrap",)
    )
    assert "--force-check-sig" in debootstrap_argv
    assert f"--keyring={keyring}" in debootstrap_argv


def test_preinstall_hook_captures_apt_v3_and_all_chain_bytes_before_dpkg(
    tmp_path: Path,
) -> None:
    script = _capture_hook_script()
    config = _capture_hook_config()

    assert (
        'DPkg::Pre-Install-Pkgs {'
        '"/usr/lib/distroforge/capture-package-inputs pre";'
        "};"
    ) in config
    assert (
        "DPkg::Tools::options::"
        '/usr/lib/distroforge/capture-package-inputs::Version "3";'
    ) in config
    assert (
        "DPkg::Tools::options::"
        '/usr/lib/distroforge/capture-package-inputs::InfoFD "0";'
    ) in config
    assert (
        'DPkg::Post-Invoke {'
        '"/usr/lib/distroforge/capture-package-inputs post";'
        "};"
    ) in config
    assert 'APT::Keep-Downloaded-Packages "true"' in config
    for kind in (
        "recorder",
        "source",
        "config",
        "keyring",
        "release",
        "index",
        "deb",
    ):
        assert f"seal_file {kind}" in script
    assert '"${APT_HOOK_INFO_FD-}" = 0' in script
    assert f"protocol_limit={MAX_APT_PROTOCOL_BYTES}" in script
    assert f"blob_limit={MAX_PACKAGE_INPUT_BLOB_BYTES}" in script
    assert (
        f"blob_total_limit={MAX_TOTAL_PACKAGE_INPUT_BLOB_BYTES}"
        in script
    )
    assert "apt-pre-install-v3" in script
    assert "complete" in script
    assert "apt-get indextargets" in script
    assert "sha256sum --" in script
    assert "bytes changed during capture" in script
    assert 'head -c $((blob_limit + 1)) -- "$source"' in script
    assert script.index('size=$(wc -c < "$source")') < script.index(
        'before=$(head -c $((blob_limit + 1)) -- "$source" | sha256sum)'
    )
    assert script.index(
        'existing_size=$(wc -c < "$protocol_target")'
    ) < script.index("existing_sha=$(")

    config_path = tmp_path / "99distroforge-evidence"
    config_path.write_text(config, encoding="utf-8")
    dumped = subprocess.run(
        ("apt-config", "-c", str(config_path), "dump"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert (
        'DPkg::Tools::options::'
        '/usr/lib/distroforge/capture-package-inputs::Version "3";'
    ) in dumped
    assert (
        "DPkg::Tools::options::"
        '/usr/lib/distroforge/capture-package-inputs::InfoFD "0";'
    ) in dumped
    subprocess.run(
        ("sh", "-n"),
        input=script,
        check=True,
        capture_output=True,
        text=True,
    )


def test_hook_pre_post_state_machine_executes_in_a_controlled_root(
    tmp_path: Path,
) -> None:
    controlled_root = tmp_path / "root"
    base = controlled_root / "var/lib/distroforge/package-evidence"
    recorder = (
        controlled_root
        / "usr/lib/distroforge/capture-package-inputs"
    )
    config_dir = controlled_root / "etc/apt/apt.conf.d"
    keyring_dir = controlled_root / "usr/share/keyrings"
    fake_bin = controlled_root / "fake-bin"
    for directory in (
        recorder.parent,
        config_dir,
        keyring_dir,
        fake_bin,
    ):
        directory.mkdir(parents=True)
    (config_dir / "99distroforge-evidence").write_text(
        _capture_hook_config(),
        encoding="utf-8",
    )
    for helper in ("apt-config", "apt-get"):
        target = fake_bin / helper
        target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        target.chmod(0o755)

    script = _capture_hook_script()
    replacements = (
        (
            "base=/var/lib/distroforge/package-evidence",
            f"base={shlex.quote(str(base))}",
        ),
        (
            "/usr/lib/distroforge/capture-package-inputs",
            str(recorder),
        ),
        ("/etc/apt", str(controlled_root / "etc/apt")),
        ("/usr/share/keyrings", str(keyring_dir)),
    )
    for source, replacement in replacements:
        script = script.replace(source, replacement)
    recorder.write_text(script, encoding="utf-8")
    recorder.chmod(0o755)

    protocol = (
        b"VERSION 3\n"
        b"APT::Architecture=amd64\n\n"
        b"proof 1 amd64 none = 1 amd64 none **CONFIGURE**\n"
    )
    base_env = {
        **os.environ,
        "PATH": f"{fake_bin}:/usr/bin:/bin",
    }
    missing_fd = subprocess.run(
        ("sh", str(recorder), "pre"),
        input=protocol,
        capture_output=True,
        env=base_env,
        check=False,
    )
    assert missing_fd.returncode == 125
    assert b"APT_HOOK_INFO_FD" in missing_fd.stderr

    hook_env = {**base_env, "APT_HOOK_INFO_FD": "0"}
    pre = subprocess.run(
        ("sh", str(recorder), "pre"),
        input=protocol,
        capture_output=True,
        env=hook_env,
        check=False,
    )
    assert pre.returncode == 0, pre.stderr.decode(errors="replace")
    assert (base / "active").is_file()

    concurrent = subprocess.run(
        ("sh", str(recorder), "pre"),
        input=protocol,
        capture_output=True,
        env=hook_env,
        check=False,
    )
    assert concurrent.returncode == 125
    assert b"earlier APT transaction was not closed" in concurrent.stderr

    post = subprocess.run(
        ("sh", str(recorder), "post"),
        capture_output=True,
        env=base_env,
        check=False,
    )
    assert post.returncode == 0, post.stderr.decode(errors="replace")
    assert not (base / "active").exists()
    journal = (base / "transactions.tsv").read_bytes()
    parsed = _parse_sealed_capture_journal(journal)
    assert len(parsed) == 1
    assert parsed[0]["size"] == len(protocol)
    assert any(
        record["kind"] == "recorder"
        for record in parsed[0]["records"]
    )
    assert b"\nE\t1\tcomplete\tstable\n" in journal

    oversized_base = controlled_root / "oversized"
    oversized_script = script.replace(
        f"base={shlex.quote(str(base))}",
        f"base={shlex.quote(str(oversized_base))}",
    ).replace(
        f"protocol_limit={MAX_APT_PROTOCOL_BYTES}",
        "protocol_limit=64",
    )
    oversized_recorder = controlled_root / "oversized-recorder"
    oversized_recorder.write_text(oversized_script, encoding="utf-8")
    oversized_recorder.chmod(0o755)
    oversized = subprocess.run(
        ("sh", str(oversized_recorder), "pre"),
        input=b"x" * 65,
        capture_output=True,
        env=hook_env,
        check=False,
    )
    assert oversized.returncode == 125
    assert b"exceeds the byte limit" in oversized.stderr

    blob_limited_base = controlled_root / "blob-limited"
    blob_limited_script = script.replace(
        f"base={shlex.quote(str(base))}",
        f"base={shlex.quote(str(blob_limited_base))}",
    ).replace(
        f"blob_limit={MAX_PACKAGE_INPUT_BLOB_BYTES}",
        "blob_limit=1",
    )
    blob_limited_recorder = controlled_root / "blob-limited-recorder"
    blob_limited_recorder.write_text(
        blob_limited_script,
        encoding="utf-8",
    )
    blob_limited_recorder.chmod(0o755)
    blob_limited = subprocess.run(
        ("sh", str(blob_limited_recorder), "pre"),
        input=protocol,
        capture_output=True,
        env=hook_env,
        check=False,
    )
    assert blob_limited.returncode == 125
    assert b"exceeds the blob byte limit" in blob_limited.stderr

    aggregate_limited_base = controlled_root / "aggregate-limited"
    aggregate_limited_script = script.replace(
        f"base={shlex.quote(str(base))}",
        f"base={shlex.quote(str(aggregate_limited_base))}",
    ).replace(
        f"blob_total_limit={MAX_TOTAL_PACKAGE_INPUT_BLOB_BYTES}",
        "blob_total_limit=1",
    )
    aggregate_limited_recorder = controlled_root / "aggregate-limited-recorder"
    aggregate_limited_recorder.write_text(
        aggregate_limited_script,
        encoding="utf-8",
    )
    aggregate_limited_recorder.chmod(0o755)
    aggregate_limited = subprocess.run(
        ("sh", str(aggregate_limited_recorder), "pre"),
        input=protocol,
        capture_output=True,
        env=hook_env,
        check=False,
    )
    assert aggregate_limited.returncode == 125
    assert b"aggregate byte limit" in aggregate_limited.stderr


@pytest.mark.parametrize(
    ("action", "requires_deb"),
    (
        (
            "proof 1 amd64 none = 1 amd64 none **CONFIGURE**",
            False,
        ),
        (
            "proof - - none < 1 amd64 none "
            "/var/cache/apt/archives/proof_1_amd64.deb",
            True,
        ),
    ),
)
def test_hook_journal_closes_and_replays_protocol_v3_before_transaction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    action: str,
    requires_deb: bool,
) -> None:
    service, project = _capture_service(tmp_path, monkeypatch)
    root = project.squashfs_root
    staging = root / "var/lib/distroforge/package-evidence"
    recorder = root / "usr/lib/distroforge/capture-package-inputs"
    recorder.parent.mkdir(parents=True)
    recorder.write_bytes(b"recorder bytes\n")
    recorder_sha = hashlib.sha256(recorder.read_bytes()).hexdigest()
    recorder_store = staging / "store" / "recorder" / recorder_sha
    recorder_store.parent.mkdir(parents=True)
    recorder_store.write_bytes(recorder.read_bytes())

    protocol = (
        "VERSION 3\n"
        "APT::Architecture=amd64\n"
        "\n"
        f"{action}\n"
    ).encode()
    protocol_sha = hashlib.sha256(protocol).hexdigest()
    protocol_store = staging / "store" / "protocol" / protocol_sha
    protocol_store.parent.mkdir(parents=True)
    protocol_store.write_bytes(protocol)
    journal = staging / "transactions.tsv"
    journal.write_text(
        (
            "J\t1\tapt-pre-install-v3\tstable\n"
            f"P\t1\t{protocol_sha}\t{len(protocol)}\t"
            "apt-pre-install-v3\tstable\n"
            f"F\t1\trecorder\t{recorder_sha}\t"
            f"{recorder.stat().st_size}\t"
            "/usr/lib/distroforge/capture-package-inputs\t\tstable\n"
            "E\t1\tcomplete\tstable\n"
        ),
        encoding="utf-8",
    )

    closed: list[tuple[str, str, bool]] = []
    written: list[str] = []

    def close_transaction(
        transaction_id: str,
        kind: str,
        records: list[dict[str, object]],
        *,
        inventory: list[dict[str, str]],
        require_debs: bool,
    ) -> dict[str, object]:
        del records, inventory
        closed.append((transaction_id, kind, require_debs))
        return {
            "schema": PACKAGE_TRANSACTION_SCHEMA,
            "run_id": service._run_id,
            "id": transaction_id,
            "kind": kind,
            "complete": True,
            "issues": [],
        }

    monkeypatch.setattr(service, "_close_transaction", close_transaction)
    monkeypatch.setattr(
        service,
        "_write_transaction",
        lambda name, _transaction: written.append(name),
    )

    captures = service._collect_hook_transactions()

    assert closed == [("apt-0001", "apt-pre-install", requires_deb)]
    assert written == ["apt-0001"]
    assert len(captures) == 1
    assert captures[0]["transaction_id"] == "apt-0001"
    assert captures[0]["data"] == protocol
    assert captures[0]["complete"] is True
    assert (
        service._run_dir / f"apt/protocol/{protocol_sha}.v3"
    ).read_bytes() == protocol


def test_hook_journal_refuses_an_unclosed_protocol_transaction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, project = _capture_service(tmp_path, monkeypatch)
    staging = (
        project.squashfs_root
        / "var/lib/distroforge/package-evidence"
    )
    protocol = (
        b"VERSION 3\n\n"
        b"proof 1 amd64 none = 1 amd64 none **CONFIGURE**\n"
    )
    digest = hashlib.sha256(protocol).hexdigest()
    source = staging / "store" / "protocol" / digest
    source.parent.mkdir(parents=True)
    source.write_bytes(protocol)
    journal = staging / "transactions.tsv"
    journal.write_text(
        (
            "J\t1\tapt-pre-install-v3\tstable\n"
            f"P\t1\t{digest}\t{len(protocol)}\t"
            "apt-pre-install-v3\tstable\n"
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="incomplete transaction"):
        service._collect_hook_transactions()


def test_hook_journal_enforces_its_byte_bound_before_reading(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, project = _capture_service(tmp_path, monkeypatch)
    journal = (
        project.squashfs_root
        / "var/lib/distroforge/package-evidence/transactions.tsv"
    )
    journal.parent.mkdir(parents=True)
    journal.write_text(
        "J\t1\tapt-pre-install-v3\tstable\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        package_evidence_module,
        "MAX_CAPTURE_JOURNAL_BYTES",
        journal.stat().st_size - 1,
    )

    with pytest.raises(ValueError, match="journal exceeds its byte bound"):
        service._collect_hook_transactions()


def test_offline_journal_rejects_protocol_aggregate_before_loading_cas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        package_evidence_module,
        "MAX_TOTAL_APT_PROTOCOL_BYTES",
        10,
    )
    digest = "a" * 64
    journal = (
        "J\t1\tapt-pre-install-v3\tstable\n"
        f"P\t1\t{digest}\t6\tapt-pre-install-v3\tstable\n"
        f"F\t1\trecorder\t{digest}\t1\t/usr/lib/recorder\t\tstable\n"
        "E\t1\tcomplete\tstable\n"
        f"P\t2\t{digest}\t6\tapt-pre-install-v3\tstable\n"
        f"F\t2\trecorder\t{digest}\t1\t/usr/lib/recorder\t\tstable\n"
        "E\t2\tcomplete\tstable\n"
    ).encode()

    with pytest.raises(ValueError, match="aggregate byte bound"):
        _parse_sealed_capture_journal(journal)


def test_offline_journal_requires_canonical_transaction_numbers() -> None:
    digest = "a" * 64
    journal = (
        "J\t1\tapt-pre-install-v3\tstable\n"
        f"P\t01\t{digest}\t1\tapt-pre-install-v3\tstable\n"
    ).encode()

    with pytest.raises(ValueError, match="protocol record is malformed"):
        _parse_sealed_capture_journal(journal)


def test_hook_collector_refuses_an_oversized_blob_before_hashing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, project = _capture_service(tmp_path, monkeypatch)
    staging = (
        project.squashfs_root
        / "var/lib/distroforge/package-evidence"
    )
    protocol = (
        b"VERSION 3\n\n"
        b"proof 1 amd64 none = 1 amd64 none **CONFIGURE**\n"
    )
    protocol_digest = hashlib.sha256(protocol).hexdigest()
    protocol_store = staging / "store/protocol" / protocol_digest
    protocol_store.parent.mkdir(parents=True)
    protocol_store.write_bytes(protocol)
    recorder = (
        project.squashfs_root
        / "usr/lib/distroforge/capture-package-inputs"
    )
    recorder.parent.mkdir(parents=True)
    recorder.write_bytes(b"xx")
    recorder_digest = hashlib.sha256(recorder.read_bytes()).hexdigest()
    recorder_store = staging / "store/recorder" / recorder_digest
    recorder_store.parent.mkdir(parents=True)
    recorder_store.write_bytes(recorder.read_bytes())
    (staging / "transactions.tsv").write_text(
        (
            "J\t1\tapt-pre-install-v3\tstable\n"
            f"P\t1\t{protocol_digest}\t{len(protocol)}\t"
            "apt-pre-install-v3\tstable\n"
            f"F\t1\trecorder\t{recorder_digest}\t2\t"
            "/usr/lib/distroforge/capture-package-inputs\t\tstable\n"
            "E\t1\tcomplete\tstable\n"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        package_evidence_module,
        "MAX_PACKAGE_INPUT_BLOB_BYTES",
        1,
    )

    with pytest.raises(ValueError, match="blob bound"):
        service._collect_hook_transactions()


@pytest.mark.parametrize("authentic_recorder", (True, False))
def test_offline_apt_action_validator_replays_journal_and_contract_bytes(
    tmp_path: Path,
    authentic_recorder: bool,
) -> None:
    run_id = "apt-action-offline-run"
    run_dir = tmp_path / "run"
    transaction_dir = run_dir / "apt" / "transactions"
    transaction_dir.mkdir(parents=True)

    def contract_record(
        kind: str,
        source_path: str,
        content: bytes,
    ) -> dict[str, object]:
        digest = hashlib.sha256(content).hexdigest()
        target = run_dir / "apt" / "blobs" / kind / digest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return _identity(
            target,
            run_dir,
            kind=kind,
            source_path=source_path,
            extra="",
        )

    recorder_bytes = (
        _capture_hook_script().encode()
        if authentic_recorder
        else b"#!/bin/sh\nexit 0\n"
    )
    records = [
        contract_record(
            "recorder",
            "/usr/lib/distroforge/capture-package-inputs",
            recorder_bytes,
        ),
        contract_record(
            "config",
            "/etc/apt/apt.conf.d/99distroforge-evidence",
            _capture_hook_config().encode(),
        ),
    ]
    transaction = {
        "schema": PACKAGE_TRANSACTION_SCHEMA,
        "run_id": run_id,
        "id": "apt-0001",
        "kind": "apt-pre-install",
        "fresh_rootfs": True,
        "records": records,
        "inventory": [],
        "complete": True,
        "issues": [],
    }
    transaction_path = transaction_dir / "apt-0001.json"
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    package_inputs = {
        "schema": PACKAGE_INPUTS_SCHEMA,
        "run_id": run_id,
        "scope": "target-root",
        "source_mode": "bootstrap",
        "capture_mode": "dpkg-pre-install-sealed-copy",
        "transactions": [_identity(transaction_path, run_dir)],
        "baseline_inventory": [],
        "final_inventory": [],
    }
    package_inputs_path = run_dir / "PACKAGE-INPUTS.json"
    package_inputs_path.write_text(
        json.dumps(package_inputs, indent=2) + "\n",
        encoding="utf-8",
    )

    protocol = (
        b"VERSION 3\nAPT::Architecture=amd64\n\n"
        b"proof 1 amd64 none = 1 amd64 none **CONFIGURE**\n"
    )
    protocol_sha = hashlib.sha256(protocol).hexdigest()
    protocol_path = run_dir / "apt" / "protocol" / f"{protocol_sha}.v3"
    protocol_path.parent.mkdir(parents=True)
    protocol_path.write_bytes(protocol)
    journal_path = run_dir / "apt" / "transactions.tsv"
    journal_lines = [
        "J\t1\tapt-pre-install-v3\tstable",
        (
            f"P\t1\t{protocol_sha}\t{len(protocol)}\t"
            "apt-pre-install-v3\tstable"
        ),
    ]
    for record in records:
        journal_lines.append(
            "\t".join(
                (
                    "F",
                    "1",
                    str(record["kind"]),
                    str(record["sha256"]),
                    str(record["size"]),
                    str(record["source_path"]),
                    "",
                    "stable",
                )
            )
        )
    journal_lines.append("E\t1\tcomplete\tstable")
    journal_path.write_text(
        "\n".join(journal_lines) + "\n",
        encoding="utf-8",
    )

    capture = AptProtocolCapture(
        transaction_id="apt-0001",
        path=f"apt/protocol/{protocol_sha}.v3",
        size=len(protocol),
        sha256=protocol_sha,
        data=protocol,
        complete=True,
    )
    report = build_package_apt_actions_report(
        run_id=run_id,
        package_inputs=package_inputs,
        package_inputs_identity=_identity(
            package_inputs_path,
            run_dir,
        ),
        journal_identity=_identity(journal_path, run_dir),
        transactions=[transaction],
        captures=[capture],
    )
    (run_dir / PACKAGE_APT_ACTIONS_FILENAME).write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    validation = validate_package_apt_actions_evidence(
        run_dir,
        expected_run_id=run_id,
    )

    assert validation.ok is authentic_recorder
    assert validation.filesystem_causality == "unverified"
    assert validation.release_ready is False
    if authentic_recorder:
        assert validation.apt_actions == "self-consistent"
        assert (
            validation.capture_origin
            == "unverified-mutable-target-rootfs"
        )
    else:
        assert "unexpected recorder contract bytes" in validation.detail


def test_offline_validator_recomputes_release_packages_and_deb_chain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)

    validation = _validate(payload, run_dir)

    assert validation.ok is True
    assert "1 archive .deb inputs" in validation.detail
    assert validation.filesystem_causality == "unverified"
    assert validation.release_ready is False


def test_package_input_validator_authenticates_apt_deb_identity_fields(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    refs = payload["transactions"]
    assert isinstance(refs, list)
    bootstrap_ref = refs[0]
    assert isinstance(bootstrap_ref, dict)
    bootstrap = json.loads(
        (run_dir / str(bootstrap_ref["path"])).read_text(encoding="utf-8")
    )
    records = bootstrap["records"]
    assert isinstance(records, list)
    for record in records:
        if isinstance(record, dict) and record.get("kind") == "deb":
            record.update(
                {
                    "package": "proof-package",
                    "version": "1.2.3-1",
                    "architecture": "all",
                }
            )
    transaction = {
        "schema": PACKAGE_TRANSACTION_SCHEMA,
        "run_id": "proof-run",
        "id": "apt-0001",
        "kind": "apt-pre-install",
        "fresh_rootfs": True,
        "records": records,
        "inventory": [],
        "complete": True,
        "issues": [],
    }
    transaction_path = run_dir / "apt/transactions/apt-0001.json"
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    refs.insert(1, _identity(transaction_path, run_dir))

    assert _validate(payload, run_dir).ok is True

    for record in records:
        if isinstance(record, dict) and record.get("kind") == "deb":
            record["version"] = "forged-version"
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    refs[1] = _identity(transaction_path, run_dir)

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "APT .deb action identity differs" in validation.detail


def test_offline_validator_rejects_a_tampered_deb(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, deb, _release = _valid_payload(tmp_path, monkeypatch)
    deb.write_bytes(deb.read_bytes() + b"tamper")

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "changed" in validation.detail


def test_offline_validator_rejects_a_different_valid_signer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    other = "1" * 40
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            release_payload,
            f"[GNUPG:] VALIDSIG {other} 0 0 0 4 0 1 10 01 {other}\n",
        ),
    )

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "policy-bound" in validation.detail


def test_offline_validator_rejects_an_insecure_source_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    transactions = payload["transactions"]
    assert isinstance(transactions, list)
    transaction_ref = transactions[0]
    assert isinstance(transaction_ref, dict)
    transaction_path = run_dir / str(transaction_ref["path"])
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    source_record = next(
        record for record in transaction["records"] if record["kind"] == "source"
    )
    source = run_dir / source_record["path"]
    source.write_text(
        "deb [trusted=yes] https://repo.invalid proof main\n",
        encoding="utf-8",
    )
    source_record.update(_identity(source, run_dir))
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    transaction_ref.update(_identity(transaction_path, run_dir))

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "insecure APT override" in validation.detail


def test_bootstrap_cannot_exempt_an_injected_baseline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    payload["baseline_inventory"] = [
        {
            "package": "unsigned-injection",
            "version": "9",
            "architecture": "all",
        }
    ]
    baseline_inventory = payload["baseline_inventory"]
    assert isinstance(baseline_inventory, list)
    payload["final_inventory"] = list(baseline_inventory)

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "cannot exempt" in validation.detail


def test_bootstrap_transaction_must_capture_its_own_inventory_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    transactions = payload["transactions"]
    assert isinstance(transactions, list)
    transaction_ref = transactions[0]
    assert isinstance(transaction_ref, dict)
    transaction_path = run_dir / str(transaction_ref["path"])
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    transaction["inventory"].append(
        {
            "package": "missing-bootstrap-byte",
            "version": "1",
            "architecture": "all",
        }
    )
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    transaction_ref.update(_identity(transaction_path, run_dir))

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "bootstrap package has no captured input bytes" in validation.detail


def test_payload_cannot_replace_the_external_signer_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    payload["allowed_signer_fingerprints"] = ["1" * 40]

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "per-source policy" in validation.detail


def test_policy_accepts_explicit_primary_fingerprint_for_a_signing_subkey(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    signing_subkey = "A" * 40
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            release_payload,
            (
                f"[GNUPG:] VALIDSIG {signing_subkey} "
                f"0 0 0 4 0 1 10 01 {FINGERPRINT}\n"
            ),
        ),
    )

    validation = _validate(payload, run_dir)

    assert validation.ok is True


def test_policy_rejects_a_signed_release_with_the_wrong_suite(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            release_payload.replace("Suite: proof", "Suite: other"),
            f"[GNUPG:] VALIDSIG {FINGERPRINT} 0 0 0 4 0 1 10 01 {FINGERPRINT}\n",
        ),
    )

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "Release Suite" in validation.detail


def test_policy_rejects_an_expired_signed_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    expired = release_payload.replace(
        "Valid-Until: Thu, 30 Jul 2026 10:00:00 +0000",
        "Valid-Until: Wed, 29 Jul 2026 11:00:00 +0000",
    )
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            expired,
            f"[GNUPG:] VALIDSIG {FINGERPRINT} 0 0 0 4 0 1 10 01 {FINGERPRINT}\n",
        ),
    )

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "expired" in validation.detail


def test_policy_rejects_a_future_dated_signed_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    future = release_payload.replace(
        "Date: Wed, 29 Jul 2026 10:00:00 +0000",
        "Date: Thu, 30 Jul 2026 10:00:00 +0000",
    ).replace(
        "Valid-Until: Thu, 30 Jul 2026 10:00:00 +0000",
        "Valid-Until: Fri, 31 Jul 2026 10:00:00 +0000",
    )
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            future,
            f"[GNUPG:] VALIDSIG {FINGERPRINT} 0 0 0 4 0 1 10 01 {FINGERPRINT}\n",
        ),
    )

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "in the future" in validation.detail


def test_explicit_snapshot_checks_release_freshness_at_snapshot_time(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, release_payload = _valid_payload(
        tmp_path,
        monkeypatch,
    )
    keyring = payload["archive_keyring"]
    assert isinstance(keyring, dict)
    keyring_sha256 = str(keyring["expected_sha256"])
    policy = PackageSourcePolicy(
        policy_id="fixture-archive",
        base_uri="https://repo.invalid",
        suites=("proof",),
        codenames=("proof",),
        components=("main",),
        architectures=("all",),
        signer_fingerprints=(FINGERPRINT,),
        keyring_sha256=(keyring_sha256,),
        snapshot_at="2026-07-01T12:00:00+00:00",
        max_release_age_seconds=24 * 60 * 60,
        require_valid_until=True,
    )
    payload["source_policy_sha256"] = package_source_policy_sha256([policy])
    snapshot_release = release_payload.replace(
        "Date: Wed, 29 Jul 2026 10:00:00 +0000",
        "Date: Wed, 01 Jul 2026 10:00:00 +0000",
    ).replace(
        "Valid-Until: Thu, 30 Jul 2026 10:00:00 +0000",
        "Valid-Until: Thu, 02 Jul 2026 10:00:00 +0000",
    )
    monkeypatch.setattr(
        "distroforge.core.package_evidence._gpgv_inrelease",
        lambda *_args, **_kwargs: (
            0,
            snapshot_release,
            f"[GNUPG:] VALIDSIG {FINGERPRINT} 0 0 0 4 0 1 10 01 {FINGERPRINT}\n",
        ),
    )

    validation = validate_package_evidence_payload(
        payload,
        run_dir,
        run_gpg=True,
        expected_source_mode="bootstrap",
        expected_signer_fingerprints=[FINGERPRINT],
        expected_keyring_sha256=keyring_sha256,
        expected_source_policies=[policy],
        expected_verification_time=BUILD_TIME,
        apt_command_argv=SAFE_APT_COMMANDS,
    )

    assert validation.ok is True


@pytest.mark.parametrize(
    "apt_command_argv",
    [
        (
            (
                "apt-get",
                "update",
                "-o",
                "Acquire::Check-Valid-Until=false",
            ),
        ),
        (("sh", "-c", "apt-get update --allow-insecure-repositories"),),
        (
            (
                "mmdebstrap",
                "--aptopt=APT::Get::AllowUnauthenticated=true",
                "proof",
            ),
        ),
        (("debootstrap", "--no-check-gpg", "proof", "/target"),),
    ],
)
def test_policy_rejects_command_line_authentication_overrides(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    apt_command_argv: tuple[tuple[str, ...], ...],
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)

    validation = _validate(
        payload,
        run_dir,
        apt_command_argv=apt_command_argv,
    )

    assert validation.ok is False
    assert "insecure APT command-line" in validation.detail


def test_index_uri_must_belong_to_its_external_repository_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    transactions = payload["transactions"]
    assert isinstance(transactions, list)
    transaction_ref = transactions[0]
    assert isinstance(transaction_ref, dict)
    transaction_path = run_dir / str(transaction_ref["path"])
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    index_record = next(
        record for record in transaction["records"] if record["kind"] == "index"
    )
    index_record["extra"] = (
        "https://other.invalid/dists/proof/main/binary-all/Packages"
    )
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    transaction_ref.update(_identity(transaction_path, run_dir))

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "external policy" in validation.detail


def test_index_is_joined_to_the_release_in_its_apt_cache_namespace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, run_dir, _deb, _release = _valid_payload(tmp_path, monkeypatch)
    transactions = payload["transactions"]
    assert isinstance(transactions, list)
    transaction_ref = transactions[0]
    assert isinstance(transaction_ref, dict)
    transaction_path = run_dir / str(transaction_ref["path"])
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    release_record = next(
        record for record in transaction["records"] if record["kind"] == "release"
    )
    release_record["source_path"] = (
        "/var/lib/apt/lists/unrelated_proof_InRelease"
    )
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    transaction_ref.update(_identity(transaction_path, run_dir))

    validation = _validate(payload, run_dir)

    assert validation.ok is False
    assert "unique policy-bound signed Release" in validation.detail


@pytest.mark.parametrize(
    ("tool", "magic"),
    [
        ("lz4", b"\x04\x22\x4d\x18"),
        ("zstd", b"\x28\xb5\x2f\xfd"),
    ],
)
def test_lz4_and_zstd_packages_use_command_runner_bound_decompressors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    tool: str,
    magic: bytes,
) -> None:
    packages_text = "\n".join(
        [
            "Package: compressed-proof",
            "Version: 1",
            "Architecture: all",
            "Size: 1",
            f"SHA256: {'0' * 64}",
            "Filename: pool/main/c/compressed-proof.deb",
            "",
        ]
    ).encode()
    compressed = tmp_path / f"Packages.{tool}"
    compressed.write_bytes(magic + packages_text)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / tool
    executable.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                "set -eu",
                'if [ "$#" -eq 4 ]; then',
                "    input=$3",
                "    output=$4",
                "else",
                "    output=$5",
                "    input=$6",
                "fi",
                'tail -c +5 -- "$input" > "$output"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv(
        "PATH",
        f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
    )
    runner = CommandRunner(dry_run=False)

    records = _packages_records(compressed, runner=runner)

    assert records[0]["Package"] == "compressed-proof"
    assert runner.history[0].argv[0] == tool
    assert runner.execution_identities[0]["available"] is True


def test_lz4_packages_fail_closed_without_the_external_tool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    compressed = tmp_path / "Packages.lz4"
    compressed.write_bytes(b"\x04\x22\x4d\x18not-a-real-frame")
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))

    with pytest.raises(ValueError, match="lz4 decompressor is unavailable"):
        _packages_records(compressed, runner=CommandRunner(dry_run=False))


def test_real_zstd_packages_round_trip_through_the_bound_cli(
    tmp_path: Path,
) -> None:
    if not CommandRunner.has_binary("zstd"):
        pytest.skip("zstd is not installed in this test environment")
    plain = tmp_path / "Packages"
    plain.write_text(
        "\n".join(
            [
                "Package: zstd-proof",
                "Version: 1",
                "Architecture: all",
                "Size: 1",
                f"SHA256: {'0' * 64}",
                "Filename: pool/main/z/zstd-proof.deb",
                "",
            ]
        ),
        encoding="utf-8",
    )
    compressed = tmp_path / "Packages.zst"
    subprocess.run(
        ("zstd", "--quiet", "--force", "-o", str(compressed), str(plain)),
        check=True,
    )
    runner = CommandRunner(dry_run=False)

    records = _packages_records(compressed, runner=runner)

    assert records[0]["Package"] == "zstd-proof"
    assert runner.history[0].argv[:4] == (
        "zstd",
        "--decompress",
        "--force",
        "--quiet",
    )
    assert runner.execution_identities[0]["available"] is True


@pytest.mark.parametrize("escaped_directory", ["lists", "archives"])
def test_apt_cache_ancestor_symlink_cannot_copy_outside_rootfs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    escaped_directory: str,
) -> None:
    service, project = _capture_service(tmp_path, monkeypatch)
    root = project.squashfs_root
    outside = tmp_path / "outside"
    outside.mkdir()
    forbidden = b"OUTSIDE-APT-BYTES-MUST-NEVER-BE-SEALED"
    if escaped_directory == "lists":
        (outside / "lists").mkdir()
        (outside / "lists/repo_InRelease").write_bytes(forbidden)
        (root / "var/lib").mkdir(parents=True)
        (root / "var/lib/apt").symlink_to(
            outside,
            target_is_directory=True,
        )
        (root / "var/cache/apt/archives").mkdir(parents=True)
    else:
        (root / "var/lib/apt/lists").mkdir(parents=True)
        (outside / "archives").mkdir()
        (outside / "archives/outside.deb").write_bytes(forbidden)
        (root / "var/cache").mkdir(parents=True)
        (root / "var/cache/apt").symlink_to(
            outside,
            target_is_directory=True,
        )

    with pytest.raises(ValueError, match="symlink"):
        service._current_apt_records(include_host_keyring=False)

    _assert_bytes_absent(project.output_dir, forbidden)


def test_physically_confined_apt_inputs_are_copied_from_open_descriptors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    index_targets = (
        "Packages\t/var/lib/apt/lists/repo_Packages\t"
        "https://repo.invalid/dists/proof/main/binary-amd64/Packages\n"
    )
    service, project = _capture_service(
        tmp_path,
        monkeypatch,
        index_targets=index_targets,
    )
    root = project.squashfs_root
    lists = root / "var/lib/apt/lists"
    archives = root / "var/cache/apt/archives"
    lists.mkdir(parents=True)
    archives.mkdir(parents=True)
    (lists / "repo_Packages").write_bytes(b"Package: confined\n")
    (lists / "repo_InRelease").write_bytes(b"signed release bytes\n")
    (archives / "confined.deb").write_bytes(b"deb bytes\n")
    source = root / "etc/apt/sources.list"
    source.parent.mkdir(parents=True)
    source.write_text(
        "deb https://repo.invalid proof main\n",
        encoding="utf-8",
    )
    keyring = root / "usr/share/keyrings/archive.gpg"
    keyring.parent.mkdir(parents=True)
    keyring.write_bytes(b"keyring bytes\n")

    records = service._current_apt_records(include_host_keyring=False)

    assert {"source", "keyring", "release", "index", "deb"} <= {
        str(record["kind"]) for record in records
    }
    for record in records:
        sealed = service._run_dir / str(record["path"])
        assert sealed.is_file()
        record_size = record["size"]
        assert isinstance(record_size, int)
        assert _stable_digest(sealed) == (
            str(record["sha256"]),
            record_size,
        )


def test_apt_index_ancestor_symlink_cannot_copy_outside_rootfs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    index_targets = (
        "Packages\t/var/lib/apt/lists/escape/Packages\t"
        "https://repo.invalid/dists/proof/main/binary-amd64/Packages\n"
    )
    service, project = _capture_service(
        tmp_path,
        monkeypatch,
        index_targets=index_targets,
    )
    root = project.squashfs_root
    (root / "var/lib/apt/lists").mkdir(parents=True)
    (root / "var/cache/apt/archives").mkdir(parents=True)
    outside = tmp_path / "outside-index"
    outside.mkdir()
    forbidden = b"OUTSIDE-PACKAGES-INDEX"
    (outside / "Packages").write_bytes(forbidden)
    (root / "var/lib/apt/lists/escape").symlink_to(
        outside,
        target_is_directory=True,
    )

    with pytest.raises(ValueError, match="symlink"):
        service._current_apt_records(include_host_keyring=False)

    _assert_bytes_absent(project.output_dir, forbidden)


@pytest.mark.parametrize(
    "relative",
    [
        "etc/apt/sources.list",
        "etc/apt/apt.conf",
        "etc/apt/trusted.gpg",
    ],
)
def test_apt_configuration_final_symlink_is_a_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    relative: str,
) -> None:
    service, project = _capture_service(tmp_path, monkeypatch)
    root = project.squashfs_root
    (root / "var/lib/apt/lists").mkdir(parents=True)
    (root / "var/cache/apt/archives").mkdir(parents=True)
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / f"outside-{target.name}"
    forbidden = f"OUTSIDE-{relative}".encode()
    outside.write_bytes(forbidden)
    target.symlink_to(outside)

    with pytest.raises(ValueError, match="symlink"):
        service._current_apt_records(include_host_keyring=False)

    _assert_bytes_absent(project.output_dir, forbidden)


def test_inside_root_rejects_a_descendant_mountpoint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    target = root / "var/lib/apt/lists"
    target.mkdir(parents=True)
    monkeypatch.setattr(
        "distroforge.core.package_evidence._linux_mountpoints",
        lambda: {target},
    )

    with pytest.raises(ValueError, match="mount boundary"):
        _inside_root(root, "/var/lib/apt/lists", expected="directory")


def test_inside_root_rejects_a_symlinked_rootfs_itself(
    tmp_path: Path,
) -> None:
    physical = tmp_path / "physical-root"
    (physical / "var/lib/apt/lists").mkdir(parents=True)
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(physical, target_is_directory=True)

    with pytest.raises(ValueError, match="rootfs.*symlink"):
        _inside_root(
            linked_root,
            "/var/lib/apt/lists",
            expected="directory",
        )


def test_inside_root_rejects_a_non_regular_index(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    index = root / "var/lib/apt/lists/Packages"
    index.parent.mkdir(parents=True)
    os.mkfifo(index)

    with pytest.raises(ValueError, match="not a regular file"):
        _inside_root(
            root,
            "/var/lib/apt/lists/Packages",
            expected="regular",
        )


def test_unsealed_external_host_bootstrap_keyring_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    keyring = tmp_path / "outside-bootstrap.gpg"
    forbidden = b"EXTERNAL-UNSEALED-KEYRING"
    keyring.write_bytes(forbidden)
    digest, _size = _stable_digest(keyring)
    service, project = _capture_service(
        tmp_path,
        monkeypatch,
        archive_keyring=keyring,
        archive_keyring_sha256=digest,
    )

    with pytest.raises(ValueError, match="sealed run copy"):
        service._seal_source(
            "keyring",
            keyring,
            extra="host-bootstrap",
        )

    _assert_bytes_absent(project.output_dir, forbidden)


def test_only_the_content_addressed_host_bootstrap_copy_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original = tmp_path / "outside-bootstrap.gpg"
    original.write_bytes(b"PINNED-BOOTSTRAP-KEYRING")
    digest, size = _stable_digest(original)
    service, _project = _capture_service(
        tmp_path,
        monkeypatch,
        archive_keyring=original,
        archive_keyring_sha256=digest,
    )
    sealed = service._run_dir / "apt/blobs/keyring" / digest
    sealed.parent.mkdir(parents=True)
    sealed.write_bytes(original.read_bytes())
    service.archive_keyring = sealed

    record = service._seal_source(
        "keyring",
        sealed,
        extra="host-bootstrap",
    )

    assert record["sha256"] == digest
    assert record["size"] == size
    assert record["path"] == f"apt/blobs/keyring/{digest}"
