from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

import pytest

import distroforge.core.package_causality as package_causality_module
from distroforge.core.command import CommandResult, CommandRunner, CommandSpec
from distroforge.core.package_causality import (
    MAX_DATA_TAR_BYTES_PER_DEB,
    MAX_DEB_IDENTITY_BYTES,
    PACKAGE_FILESYSTEM_CAUSALITY_FILENAME,
    PACKAGE_FILESYSTEM_CAUSALITY_SCHEMA,
    PackageFilesystemCausalityError,
    validate_package_filesystem_causality,
    write_package_filesystem_causality,
)
from distroforge.core.package_evidence import (
    PACKAGE_INPUTS_SCHEMA,
    PACKAGE_TRANSACTION_SCHEMA,
)
from distroforge.core.rootfs_evidence import RootfsEvidenceService

pytestmark = pytest.mark.skipif(
    shutil.which("dpkg-deb") is None,
    reason="dpkg-deb is required for the rootless offline .deb proof fixture",
)

_RUN_ID = "m3-causality-fixture"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _identity(path: Path, run_dir: Path, **extra: object) -> dict[str, object]:
    result: dict[str, object] = {
        "path": str(path.relative_to(run_dir)),
        "size": path.stat().st_size,
        "sha256": _sha256(path),
    }
    result.update(extra)
    return result


def _build_deb(
    tmp_path: Path,
    package: str,
    files: dict[str, bytes],
    *,
    version: str = "1.0-1",
    symlinks: dict[str, str] | None = None,
    hardlinks: dict[str, str] | None = None,
) -> tuple[Path, dict[str, str]]:
    package_root = tmp_path / f"{package}-package-root"
    control = package_root / "DEBIAN" / "control"
    control.parent.mkdir(parents=True)
    control.write_text(
        "\n".join(
            (
                f"Package: {package}",
                f"Version: {version}",
                "Architecture: all",
                "Maintainer: DistroForge maintainers <maintainers@distroforge.invalid>",
                "Description: rootless offline package-causality fixture",
                "",
            )
        ),
        encoding="utf-8",
    )
    for relative, content in files.items():
        target = package_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(0o644)
    for relative, target_text in (symlinks or {}).items():
        target = package_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(target_text)
    for relative, source in (hardlinks or {}).items():
        target = package_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        os.link(package_root / source, target)

    deb = tmp_path / f"{package}_{version}_all.deb"
    completed = subprocess.run(
        ("dpkg-deb", "--build", str(package_root), str(deb)),
        check=False,
        text=True,
        capture_output=True,
        env={**os.environ, "SOURCE_DATE_EPOCH": "1700000000"},
    )
    if completed.returncode != 0:
        pytest.fail(f"dpkg-deb fixture build failed: {completed.stderr}")
    return deb, {
        "package": package,
        "version": version,
        "architecture": "all",
    }


def _extract_debs(debs: list[Path], rootfs: Path) -> None:
    for deb in debs:
        completed = subprocess.run(
            ("dpkg-deb", "--extract", str(deb), str(rootfs)),
            check=False,
            text=True,
            capture_output=True,
        )
        if completed.returncode != 0:
            pytest.fail(f"dpkg-deb fixture extraction failed: {completed.stderr}")


def _write_package_inputs(
    run_dir: Path,
    debs: list[tuple[Path, dict[str, str]]],
    *,
    source_mode: str = "bootstrap",
) -> list[Path]:
    blobs = run_dir / "apt" / "blobs" / "deb"
    blobs.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    copied: list[Path] = []
    inventory: list[dict[str, str]] = []
    for source, package_identity in debs:
        digest = _sha256(source)
        target = blobs / f"{digest}.deb"
        shutil.copy2(source, target)
        records.append(
            _identity(
                target,
                run_dir,
                kind="deb",
                source_path=f"/var/cache/apt/archives/{source.name}",
                extra="",
            )
        )
        copied.append(target)
        inventory.append(package_identity)

    transaction = {
        "schema": PACKAGE_TRANSACTION_SCHEMA,
        "run_id": _RUN_ID,
        "id": "bootstrap",
        "kind": "bootstrap" if source_mode == "bootstrap" else "apt-state",
        "fresh_rootfs": source_mode == "bootstrap",
        "records": records,
        "inventory": inventory,
        "complete": True,
        "issues": [],
    }
    transaction_path = run_dir / "apt" / "transactions" / "bootstrap.json"
    transaction_path.parent.mkdir(parents=True, exist_ok=True)
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    package_inputs = {
        "schema": PACKAGE_INPUTS_SCHEMA,
        "run_id": _RUN_ID,
        "scope": "target-root",
        "source_mode": source_mode,
        "capture_mode": "dpkg-pre-install-sealed-copy",
        "fresh_rootfs": source_mode == "bootstrap",
        "transactions": [_identity(transaction_path, run_dir)],
        "baseline_inventory": [],
        "final_inventory": inventory,
    }
    (run_dir / "PACKAGE-INPUTS.json").write_text(
        json.dumps(package_inputs, indent=2) + "\n",
        encoding="utf-8",
    )
    return copied


def _capture_rootfs(run_dir: Path, rootfs: Path) -> None:
    RootfsEvidenceService(rootfs, run_id=_RUN_ID).capture_before_packing(
        run_dir / "ROOTFS-MANIFEST.json"
    )


class _LimitRecordingRunner(CommandRunner):
    def __init__(self) -> None:
        super().__init__(dry_run=False)
        self.binary_limits: list[int] = []
        self.binary_commands: list[tuple[str, ...]] = []

    def run_binary_to_file(
        self,
        spec: CommandSpec,
        output: BinaryIO,
        *,
        max_output_bytes: int,
        check: bool = True,
    ) -> CommandResult:
        self.binary_limits.append(max_output_bytes)
        self.binary_commands.append(spec.argv)
        return super().run_binary_to_file(
            spec,
            output,
            max_output_bytes=max_output_bytes,
            check=check,
        )


def test_real_deb_payload_is_measured_but_never_promoted(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    deb, package_identity = _build_deb(
        tmp_path,
        "causal-exact",
        {"usr/share/causal/exact": b"authenticated payload\n"},
        symlinks={"usr/bin/causal-link": "../share/causal/exact"},
        hardlinks={"usr/share/causal/exact-copy": "usr/share/causal/exact"},
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([deb], rootfs)
    _write_package_inputs(run_dir, [(deb, package_identity)])
    _capture_rootfs(run_dir, rootfs)
    runner = _LimitRecordingRunner()

    artifact = write_package_filesystem_causality(run_dir, _RUN_ID, runner)
    validation = validate_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        CommandRunner(dry_run=False),
    )

    assert artifact == run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME
    report = json.loads(artifact.read_text(encoding="utf-8"))
    assert report["schema"] == PACKAGE_FILESYSTEM_CAUSALITY_SCHEMA
    assert report["run_id"] == _RUN_ID
    assert report["scope"].startswith("sealed-recorded-deb-")
    assert "independently" in report["assurance_dependency"]
    assert report["payload_identity"] == "verified"
    assert report["filesystem_causality"] == "unverified"
    assert report["release_ready"] is False
    assert report["counts"]["exact"] == 3
    assert report["counts"]["ambiguous"] == 0
    assert report["counts"]["modified"] == 0
    assert report["counts"]["structural"] > 0
    assert validation.ok
    assert validation.payload_identity == "verified"
    assert validation.filesystem_causality == "unverified"
    assert validation.release_ready is False
    assert runner.binary_limits == [
        MAX_DEB_IDENTITY_BYTES,
        MAX_DATA_TAR_BYTES_PER_DEB,
    ]
    assert [spec.argv[1] for spec in runner.history] == [
        "--show",
        "--fsys-tarfile",
    ]
    assert any("scripts" in limit for limit in report["limits"])
    assert any("triggers" in limit for limit in report["limits"])
    assert any("diversions" in limit for limit in report["limits"])
    assert any("conffiles" in limit for limit in report["limits"])
    assert any("customizers" in limit for limit in report["limits"])
    assert any("final_inventory" in limit and "post-host" in limit for limit in report["limits"])
    assert any("source ISO" in limit for limit in report["limits"])


def test_duplicate_final_identity_is_refused_before_second_payload_extraction(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    first, package_identity = _build_deb(
        tmp_path / "first",
        "causal-duplicate-identity",
        {"usr/share/causal/value": b"first\n"},
    )
    second, second_identity = _build_deb(
        tmp_path / "second",
        "causal-duplicate-identity",
        {"usr/share/causal/value": b"second\n"},
    )
    assert second_identity == package_identity
    rootfs = tmp_path / "rootfs"
    _extract_debs([first], rootfs)
    _write_package_inputs(
        run_dir,
        [(first, package_identity), (second, second_identity)],
    )
    package_inputs_path = run_dir / "PACKAGE-INPUTS.json"
    package_inputs = json.loads(package_inputs_path.read_text(encoding="utf-8"))
    package_inputs["final_inventory"] = [package_identity]
    package_inputs_path.write_text(
        json.dumps(package_inputs, indent=2) + "\n",
        encoding="utf-8",
    )
    _capture_rootfs(run_dir, rootfs)
    runner = _LimitRecordingRunner()

    with pytest.raises(PackageFilesystemCausalityError, match="different .deb bytes"):
        write_package_filesystem_causality(run_dir, _RUN_ID, runner)

    assert sum("--fsys-tarfile" in command for command in runner.binary_commands) == 1
    assert not (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).exists()


def test_one_final_deb_at_two_paths_is_refused_before_second_payload_extraction(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    deb, package_identity = _build_deb(
        tmp_path,
        "causal-duplicate-path",
        {"usr/share/causal/value": b"one payload\n"},
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([deb], rootfs)
    copied = _write_package_inputs(run_dir, [(deb, package_identity)])[0]
    duplicate = run_dir / "apt/blobs/deb/duplicate-copy.deb"
    shutil.copy2(copied, duplicate)
    transaction_path = run_dir / "apt/transactions/bootstrap.json"
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    transaction["records"].append(
        _identity(
            duplicate,
            run_dir,
            kind="deb",
        )
    )
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    package_inputs_path = run_dir / "PACKAGE-INPUTS.json"
    package_inputs = json.loads(package_inputs_path.read_text(encoding="utf-8"))
    package_inputs["transactions"] = [_identity(transaction_path, run_dir)]
    package_inputs_path.write_text(
        json.dumps(package_inputs, indent=2) + "\n",
        encoding="utf-8",
    )
    _capture_rootfs(run_dir, rootfs)
    runner = _LimitRecordingRunner()

    with pytest.raises(PackageFilesystemCausalityError, match="multiple paths"):
        write_package_filesystem_causality(run_dir, _RUN_ID, runner)

    assert sum("--fsys-tarfile" in command for command in runner.binary_commands) == 1
    assert not (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).exists()


def test_classifies_modified_missing_and_unattributed_paths(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    deb, package_identity = _build_deb(
        tmp_path,
        "causal-drift",
        {
            "usr/share/causal/exact": b"same\n",
            "usr/share/causal/modified": b"before\n",
            "usr/share/causal/missing": b"removed\n",
        },
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([deb], rootfs)
    (rootfs / "usr/share/causal/modified").write_bytes(b"after\n")
    (rootfs / "usr/share/causal/missing").unlink()
    (rootfs / "usr/share/causal/unattributed").write_bytes(b"local writer\n")
    _write_package_inputs(run_dir, [(deb, package_identity)])
    _capture_rootfs(run_dir, rootfs)

    artifact = write_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        CommandRunner(dry_run=False),
    )

    report = json.loads(artifact.read_text(encoding="utf-8"))
    by_path = {entry["path"]: entry["classification"] for entry in report["paths"]}
    assert by_path["usr/share/causal/exact"] == "exact"
    assert by_path["usr/share/causal/modified"] == "modified"
    assert by_path["usr/share/causal/missing"] == "missing"
    assert by_path["usr/share/causal/unattributed"] == "unattributed"
    assert report["payload_identity"] == "verified"
    assert "static payload identity is verified" in report["detail"]
    assert report["filesystem_causality"] == "unverified"
    assert report["release_ready"] is False


def test_two_final_packages_claiming_one_path_are_ambiguous(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    first, first_identity = _build_deb(
        tmp_path,
        "causal-first",
        {"usr/share/causal/shared": b"first\n"},
    )
    second, second_identity = _build_deb(
        tmp_path,
        "causal-second",
        {"usr/share/causal/shared": b"second\n"},
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([first, second], rootfs)
    _write_package_inputs(
        run_dir,
        [(first, first_identity), (second, second_identity)],
    )
    _capture_rootfs(run_dir, rootfs)

    artifact = write_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        CommandRunner(dry_run=False),
    )

    report = json.loads(artifact.read_text(encoding="utf-8"))
    shared = next(entry for entry in report["paths"] if entry["path"] == "usr/share/causal/shared")
    assert shared["classification"] == "ambiguous"
    assert len(shared["payloads"]) == 2
    assert report["counts"]["ambiguous"] == 1
    assert report["payload_identity"] == "verified"
    assert report["release_ready"] is False


def test_manifest_exclusion_is_explicit_and_payload_identity_becomes_partial(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    deb, package_identity = _build_deb(
        tmp_path,
        "causal-excluded",
        {"dev/causal-excluded": b"outside semantic scan\n"},
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([deb], rootfs)
    _write_package_inputs(run_dir, [(deb, package_identity)])
    _capture_rootfs(run_dir, rootfs)

    artifact = write_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        CommandRunner(dry_run=False),
    )

    report = json.loads(artifact.read_text(encoding="utf-8"))
    excluded = next(item for item in report["paths"] if item["path"] == "dev/causal-excluded")
    assert excluded["classification"] == "excluded"
    assert excluded["rootfs"] is None
    assert report["counts"]["excluded"] == 1
    assert report["payload_identity"] == "partial"
    assert report["filesystem_causality"] == "unverified"
    assert report["release_ready"] is False


def test_unsupported_final_rootfs_object_makes_payload_identity_partial(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    deb, package_identity = _build_deb(
        tmp_path,
        "causal-unsupported",
        {"usr/share/causal/exact": b"authenticated payload\n"},
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([deb], rootfs)
    fifo = rootfs / "usr/share/causal/fifo"
    fifo.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(fifo)
    _write_package_inputs(run_dir, [(deb, package_identity)])
    _capture_rootfs(run_dir, rootfs)

    artifact = write_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        CommandRunner(dry_run=False),
    )

    report = json.loads(artifact.read_text(encoding="utf-8"))
    fifo_entry = next(item for item in report["paths"] if item["path"] == "usr/share/causal/fifo")
    assert fifo_entry["classification"] == "unsupported"
    assert report["counts"]["unsupported"] == 1
    assert report["payload_identity"] == "partial"
    assert report["filesystem_causality"] == "unverified"
    assert report["release_ready"] is False


def _exact_fixture(
    tmp_path: Path,
) -> tuple[Path, Path]:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    deb, package_identity = _build_deb(
        tmp_path,
        "causal-tamper",
        {"usr/share/causal/value": b"sealed\n"},
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([deb], rootfs)
    copied = _write_package_inputs(run_dir, [(deb, package_identity)])[0]
    _capture_rootfs(run_dir, rootfs)
    write_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        CommandRunner(dry_run=False),
    )
    return run_dir, copied


def _tamper_report(run_dir: Path, _deb: Path) -> None:
    path = run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["counts"]["exact"] += 1
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _tamper_report_whitespace(run_dir: Path, _deb: Path) -> None:
    path = run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME
    path.write_text(
        "\n" + path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )


def _tamper_deb(_run_dir: Path, deb: Path) -> None:
    with deb.open("ab") as handle:
        handle.write(b"tampered")


def _tamper_package_inputs(run_dir: Path, _deb: Path) -> None:
    path = run_dir / "PACKAGE-INPUTS.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["unbound-field"] = "tampered"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _tamper_rootfs_manifest(run_dir: Path, _deb: Path) -> None:
    path = run_dir / "ROOTFS-MANIFEST.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["unbound-field"] = "tampered"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _forge_release_promotion(run_dir: Path, _deb: Path) -> None:
    path = run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["filesystem_causality"] = "verified"
    payload["release_ready"] = True
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


@pytest.mark.parametrize(
    "tamper",
    (
        _tamper_report,
        _tamper_report_whitespace,
        _tamper_deb,
        _tamper_package_inputs,
        _tamper_rootfs_manifest,
        _forge_release_promotion,
    ),
)
def test_validator_refuses_any_bound_input_or_report_tamper(
    tmp_path: Path,
    tamper: Callable[[Path, Path], None],
) -> None:
    run_dir, deb = _exact_fixture(tmp_path)
    tamper(run_dir, deb)

    validation = validate_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        CommandRunner(dry_run=False),
    )

    assert not validation.ok
    assert validation.filesystem_causality == "unverified"
    assert validation.release_ready is False


def test_validator_refuses_a_different_expected_run_id(
    tmp_path: Path,
) -> None:
    run_dir, _deb = _exact_fixture(tmp_path)

    validation = validate_package_filesystem_causality(
        run_dir,
        "another-run",
        CommandRunner(dry_run=False),
    )

    assert not validation.ok
    assert "another" in validation.detail or "run" in validation.detail
    assert validation.release_ready is False


@pytest.mark.parametrize("unsafe_run_id", (".", ".."))
def test_dot_run_ids_are_refused(
    tmp_path: Path,
    unsafe_run_id: str,
) -> None:
    validation = validate_package_filesystem_causality(
        tmp_path,
        unsafe_run_id,
        CommandRunner(dry_run=False),
    )

    assert not validation.ok
    assert "unsafe" in validation.detail
    with pytest.raises(PackageFilesystemCausalityError, match="unsafe"):
        write_package_filesystem_causality(
            tmp_path,
            unsafe_run_id,
            CommandRunner(dry_run=False),
        )


@pytest.mark.parametrize("symlink_kind", ("run-dir", "ancestor"))
def test_executing_paths_refuse_a_symlinked_run_directory(
    tmp_path: Path,
    symlink_kind: str,
) -> None:
    actual_parent = tmp_path / "actual"
    actual_run = actual_parent / _RUN_ID
    actual_run.mkdir(parents=True)
    if symlink_kind == "run-dir":
        run_dir = tmp_path / "linked-run"
        run_dir.symlink_to(actual_run, target_is_directory=True)
    else:
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(actual_parent, target_is_directory=True)
        run_dir = linked_parent / _RUN_ID

    validation = validate_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        CommandRunner(dry_run=False),
    )

    assert not validation.ok
    assert "symlinked" in validation.detail
    with pytest.raises(PackageFilesystemCausalityError, match="symlinked"):
        write_package_filesystem_causality(
            run_dir,
            _RUN_ID,
            CommandRunner(dry_run=False),
        )


class _TarOverrideRunner(CommandRunner):
    def __init__(self, payload: bytes) -> None:
        super().__init__(dry_run=False)
        self.payload = payload
        self.limit: int | None = None

    def run_binary_to_file(
        self,
        spec: CommandSpec,
        output: BinaryIO,
        *,
        max_output_bytes: int,
        check: bool = True,
    ) -> CommandResult:
        if "--fsys-tarfile" not in spec.argv:
            return super().run_binary_to_file(
                spec,
                output,
                max_output_bytes=max_output_bytes,
                check=check,
            )
        self.history.append(spec)
        self.limit = max_output_bytes
        if len(self.payload) > max_output_bytes:
            output.write(self.payload[:max_output_bytes])
            output.flush()
            return CommandResult(
                spec=spec,
                returncode=125,
                stdout=f"<{max_output_bytes} binary bytes captured>\n",
                stderr=(f"binary stdout exceeded the {max_output_bytes}-byte capture limit\n"),
            )
        output.write(self.payload)
        output.flush()
        return CommandResult(
            spec=spec,
            returncode=0,
            stdout=f"<{len(self.payload)} binary bytes captured>\n",
            stderr="",
        )


def _tar_bytes(names: tuple[str, ...]) -> bytes:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        for name in names:
            info = tarfile.TarInfo(name)
            info.mode = 0o644
            info.uid = os.getuid()
            info.gid = os.getgid()
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
    return payload.getvalue()


def _compressed_tar_bytes() -> bytes:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        info = tarfile.TarInfo("usr/share/causal/compressed")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))
    return payload.getvalue()


def _invalid_numeric_pax_tar_bytes() -> bytes:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("usr/share/causal/pax")
        info.size = 1
        info.pax_headers = {"uid": "not-a-number"}
        archive.addfile(info, io.BytesIO(b"x"))
    return payload.getvalue()


def _recursive_solaris_pax_tar_bytes() -> bytes:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        for index in range(33):
            info = tarfile.TarInfo(f"pax-{index}")
            info.type = b"X"
            info.size = 0
            archive.addfile(info)
        ordinary = tarfile.TarInfo("usr/share/causal/ordinary")
        ordinary.size = 1
        archive.addfile(ordinary, io.BytesIO(b"x"))
    return payload.getvalue()


def _gnu_sparse_tar_bytes() -> bytes:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        info = tarfile.TarInfo("usr/share/causal/sparse")
        info.type = tarfile.GNUTYPE_SPARSE
        info.size = 0
        archive.addfile(info)
    return payload.getvalue()


def _gnu_sparse_pax_tar_bytes() -> bytes:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("usr/share/causal/pax-sparse")
        info.size = 1
        info.pax_headers = {
            "GNU.sparse.map": "0,1",
            "GNU.sparse.size": "1",
        }
        archive.addfile(info, io.BytesIO(b"x"))
    return payload.getvalue()


@pytest.mark.parametrize(
    ("names", "message"),
    (
        (("../escape",), "unsafe"),
        (("/absolute",), "absolute"),
        (("usr/share/duplicate", "usr/share/duplicate"), "duplicate"),
    ),
)
def test_tar_member_traversal_absolute_and_duplicates_are_refused(
    tmp_path: Path,
    names: tuple[str, ...],
    message: str,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    deb, package_identity = _build_deb(
        tmp_path,
        "causal-hostile",
        {"usr/share/causal/ordinary": b"ordinary\n"},
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([deb], rootfs)
    _write_package_inputs(run_dir, [(deb, package_identity)])
    _capture_rootfs(run_dir, rootfs)
    runner = _TarOverrideRunner(_tar_bytes(names))

    with pytest.raises(PackageFilesystemCausalityError, match=message):
        write_package_filesystem_causality(run_dir, _RUN_ID, runner)

    assert runner.limit is not None and runner.limit > 0
    assert not (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).exists()


@pytest.mark.parametrize(
    ("payload_factory", "message"),
    (
        (_compressed_tar_bytes, "tar"),
        (_invalid_numeric_pax_tar_bytes, "PAX uid"),
        (_recursive_solaris_pax_tar_bytes, "extension metadata"),
        (_gnu_sparse_tar_bytes, "sparse"),
        (_gnu_sparse_pax_tar_bytes, "sparse PAX"),
    ),
)
def test_hostile_tar_encoding_is_fail_closed_for_writer_and_validator(
    tmp_path: Path,
    payload_factory: Callable[[], bytes],
    message: str,
) -> None:
    run_dir, _copied = _exact_fixture(tmp_path)
    runner = _TarOverrideRunner(payload_factory())

    validation = validate_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        runner,
    )

    assert not validation.ok
    assert message.lower() in validation.detail.lower()
    (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).unlink()
    with pytest.raises(PackageFilesystemCausalityError, match=message):
        write_package_filesystem_causality(run_dir, _RUN_ID, runner)
    assert not (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).exists()


def test_hardlink_resolution_is_iterative_and_groups_are_precomputed() -> None:
    regular = {
        "type": "regular",
        "archive_type": "regular",
        "mode": "0644",
        "uid": 0,
        "gid": 0,
        "size": 1,
        "sha256": "a" * 64,
    }
    raw: dict[str, dict[str, object]] = {"target": regular}
    chain_length = 5_000
    for index in reversed(range(chain_length)):
        raw[f"link-{index}"] = {
            "type": "hardlink",
            "archive_type": "hardlink",
            "mode": "0644",
            "uid": 0,
            "gid": 0,
            "target": "target" if index == chain_length - 1 else f"link-{index + 1}",
        }

    resolved = package_causality_module._resolve_hardlinks(raw, "deep-chain.deb")

    assert len(resolved) == chain_length + 1
    assert all(item["type"] == "regular" for item in resolved)
    assert all(item["link_count"] == chain_length + 1 for item in resolved)


@pytest.mark.parametrize(
    ("raw", "message"),
    (
        (
            {
                "a": {"type": "hardlink", "target": "b"},
                "b": {"type": "hardlink", "target": "a"},
            },
            "cyclic",
        ),
        (
            {"a": {"type": "hardlink", "target": "absent"}},
            "absent",
        ),
    ),
)
def test_hardlink_cycle_and_absent_target_are_refused(
    raw: dict[str, dict[str, object]],
    message: str,
) -> None:
    with pytest.raises(PackageFilesystemCausalityError, match=message):
        package_causality_module._resolve_hardlinks(raw, "hostile.deb")


def test_parent_swap_between_reference_parse_and_open_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir, _copied = _exact_fixture(tmp_path)
    (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).unlink()
    transactions = run_dir / "apt/transactions"
    outside = tmp_path / "outside-transactions"
    shutil.copytree(transactions, outside)
    parked = run_dir / "apt/transactions-parked"
    load_json = package_causality_module._load_json_stable
    swapped = False

    def swap_parent(run, relative: str, label: str):
        nonlocal swapped
        if label == "package transaction" and not swapped:
            transactions.rename(parked)
            transactions.symlink_to(outside, target_is_directory=True)
            swapped = True
        return load_json(run, relative, label)

    monkeypatch.setattr(
        package_causality_module,
        "_load_json_stable",
        swap_parent,
    )

    with pytest.raises(PackageFilesystemCausalityError, match="traversed"):
        write_package_filesystem_causality(
            run_dir,
            _RUN_ID,
            CommandRunner(dry_run=False),
        )

    assert swapped
    assert not (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).exists()


def test_leaf_replacement_before_run_seal_is_refused_and_output_is_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir, _copied = _exact_fixture(tmp_path)
    (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).unlink()
    recompute = package_causality_module._recompute_payload

    def replace_input(run, expected_run_id: str, runner: CommandRunner):
        payload = recompute(run, expected_run_id, runner)
        (run_dir / "PACKAGE-INPUTS.json").write_text("{}\n", encoding="utf-8")
        return payload

    monkeypatch.setattr(
        package_causality_module,
        "_recompute_payload",
        replace_input,
    )

    with pytest.raises(PackageFilesystemCausalityError, match="changed"):
        write_package_filesystem_causality(
            run_dir,
            _RUN_ID,
            CommandRunner(dry_run=False),
        )

    assert not (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).exists()


def test_pathological_json_integer_is_invalid_instead_of_escaping_the_validator(
    tmp_path: Path,
) -> None:
    run_dir, _copied = _exact_fixture(tmp_path)
    nested = '{"nested":' + ("9" * 10_000) + "}\n"
    (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).write_text(
        nested,
        encoding="utf-8",
    )

    validation = validate_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        CommandRunner(dry_run=False),
    )

    assert not validation.ok
    assert "unreadable" in validation.detail


def test_output_size_bound_refuses_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    monkeypatch.setattr(package_causality_module, "MAX_EVIDENCE_JSON_BYTES", 16)

    with package_causality_module._RunDirectoryWitness(run_dir) as run:
        with pytest.raises(PackageFilesystemCausalityError, match="size bound"):
            run.write_new_text("oversized.json", "x" * 17, "oversized report")

    assert not (run_dir / "oversized.json").exists()


@pytest.mark.parametrize(
    ("constant", "value", "message"),
    (
        ("MAX_TOTAL_TRANSACTION_JSON_BYTES", 1, "transaction-byte"),
        ("MAX_TOTAL_SELECTED_DEB_BYTES", 1, "captured .deb records"),
        ("MAX_TOTAL_DATA_TAR_BYTES", 1, "tar streams"),
        ("MAX_TOTAL_LOGICAL_PAYLOAD_BYTES", 0, "logical payloads"),
        ("MAX_TOTAL_PAYLOAD_MEMBER_JSON_BYTES", 1, "member metadata"),
        ("MAX_TOTAL_CLAIM_JSON_BYTES", 1, "payload claims"),
        ("MAX_TOTAL_CLASSIFICATION_JSON_BYTES", 1, "classifications"),
        ("MAX_TOTAL_PACKAGE_JSON_BYTES", 1, "package summaries"),
        ("MAX_TOTAL_PAYLOAD_MEMBERS", 0, "member bound"),
        ("MAX_TOTAL_ROOTFS_ENTRIES", 0, "rootfs manifest"),
    ),
)
def test_aggregate_resource_budgets_fail_before_report_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    message: str,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    deb, package_identity = _build_deb(
        tmp_path,
        "causal-budget",
        {"usr/share/causal/budget": b"bounded\n"},
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([deb], rootfs)
    _write_package_inputs(run_dir, [(deb, package_identity)])
    _capture_rootfs(run_dir, rootfs)
    monkeypatch.setattr(package_causality_module, constant, value)

    with pytest.raises(PackageFilesystemCausalityError, match=message):
        write_package_filesystem_causality(
            run_dir,
            _RUN_ID,
            CommandRunner(dry_run=False),
        )

    assert not (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).exists()


def test_remaining_tar_budget_is_the_capture_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    deb, package_identity = _build_deb(
        tmp_path,
        "causal-tar-budget",
        {"usr/share/causal/budget": b"bounded\n"},
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([deb], rootfs)
    _write_package_inputs(run_dir, [(deb, package_identity)])
    _capture_rootfs(run_dir, rootfs)
    payload = _tar_bytes(("usr/share/causal/budget",))
    remaining = len(payload) - 1
    monkeypatch.setattr(
        package_causality_module,
        "MAX_TOTAL_DATA_TAR_BYTES",
        remaining,
    )
    runner = _TarOverrideRunner(payload)

    with pytest.raises(PackageFilesystemCausalityError, match="tar streams"):
        write_package_filesystem_causality(run_dir, _RUN_ID, runner)

    assert runner.limit == remaining
    assert not (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).exists()


@pytest.mark.parametrize(
    ("constant", "message"),
    (
        ("MAX_TOTAL_PAYLOAD_MEMBERS", "member bound"),
        ("MAX_TOTAL_LOGICAL_PAYLOAD_BYTES", "logical payloads"),
        ("MAX_TOTAL_PAYLOAD_MEMBER_JSON_BYTES", "member metadata"),
    ),
)
def test_exhausted_parser_budget_refuses_before_payload_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    message: str,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    deb, package_identity = _build_deb(
        tmp_path,
        "causal-preparse-budget",
        {"usr/share/causal/budget": b"bounded\n"},
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([deb], rootfs)
    _write_package_inputs(run_dir, [(deb, package_identity)])
    _capture_rootfs(run_dir, rootfs)
    monkeypatch.setattr(package_causality_module, constant, 0)
    runner = _LimitRecordingRunner()

    with pytest.raises(PackageFilesystemCausalityError, match=message):
        write_package_filesystem_causality(run_dir, _RUN_ID, runner)

    assert all("--fsys-tarfile" not in command for command in runner.binary_commands)
    assert not (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).exists()


def test_iso_classification_budget_is_enforced_incrementally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    rootfs = tmp_path / "rootfs"
    (rootfs / "usr/share").mkdir(parents=True)
    (rootfs / "usr/share/baseline").write_bytes(b"source ISO bytes\n")
    _write_package_inputs(run_dir, [], source_mode="iso")
    _capture_rootfs(run_dir, rootfs)
    monkeypatch.setattr(
        package_causality_module,
        "MAX_TOTAL_CLASSIFICATION_JSON_BYTES",
        1,
    )

    with pytest.raises(PackageFilesystemCausalityError, match="classifications"):
        write_package_filesystem_causality(
            run_dir,
            _RUN_ID,
            CommandRunner(dry_run=False),
        )

    assert not (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).exists()


def test_transaction_id_and_reference_path_are_bounded_before_use(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    deb, package_identity = _build_deb(
        tmp_path,
        "causal-transaction-bound",
        {"usr/share/causal/budget": b"bounded\n"},
    )
    rootfs = tmp_path / "rootfs"
    _extract_debs([deb], rootfs)
    _write_package_inputs(run_dir, [(deb, package_identity)])
    _capture_rootfs(run_dir, rootfs)
    transaction_path = run_dir / "apt/transactions/bootstrap.json"
    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
    transaction["id"] = "x" * (package_causality_module.MAX_TRANSACTION_ID_BYTES + 1)
    transaction_path.write_text(
        json.dumps(transaction, indent=2) + "\n",
        encoding="utf-8",
    )
    package_inputs_path = run_dir / "PACKAGE-INPUTS.json"
    package_inputs = json.loads(package_inputs_path.read_text(encoding="utf-8"))
    package_inputs["transactions"] = [_identity(transaction_path, run_dir)]
    package_inputs_path.write_text(
        json.dumps(package_inputs, indent=2) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(PackageFilesystemCausalityError, match="id is unsafe"):
        write_package_filesystem_causality(
            run_dir,
            _RUN_ID,
            CommandRunner(dry_run=False),
        )

    package_inputs["transactions"][0]["path"] = "x" * (
        package_causality_module.MAX_RUN_RELATIVE_PATH_BYTES + 1
    )
    package_inputs_path.write_text(
        json.dumps(package_inputs, indent=2) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(PackageFilesystemCausalityError, match="size or depth"):
        write_package_filesystem_causality(
            run_dir,
            _RUN_ID,
            CommandRunner(dry_run=False),
        )

    package_inputs["transactions"][0]["path"] = "/".join(
        ["x"] * (package_causality_module.MAX_RUN_RELATIVE_PATH_COMPONENTS + 1)
    )
    package_inputs_path.write_text(
        json.dumps(package_inputs, indent=2) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(PackageFilesystemCausalityError, match="size or depth"):
        write_package_filesystem_causality(
            run_dir,
            _RUN_ID,
            CommandRunner(dry_run=False),
        )

    assert not (run_dir / PACKAGE_FILESYSTEM_CAUSALITY_FILENAME).exists()


def test_source_iso_is_recorded_as_explicitly_unsupported(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / _RUN_ID
    run_dir.mkdir()
    rootfs = tmp_path / "rootfs"
    (rootfs / "usr/share").mkdir(parents=True)
    (rootfs / "usr/share/baseline").write_bytes(b"source ISO bytes\n")
    _write_package_inputs(run_dir, [], source_mode="iso")
    _capture_rootfs(run_dir, rootfs)

    artifact = write_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        CommandRunner(dry_run=False),
    )
    validation = validate_package_filesystem_causality(
        run_dir,
        _RUN_ID,
        CommandRunner(dry_run=False),
    )

    report = json.loads(artifact.read_text(encoding="utf-8"))
    assert report["status"] == "unsupported-unverified"
    assert report["payload_identity"] == "partial"
    assert report["counts"]["unsupported"] == report["rootfs_manifest"]["object_count"]
    assert validation.ok
    assert validation.payload_identity == "partial"
    assert validation.filesystem_causality == "unverified"
    assert validation.release_ready is False
