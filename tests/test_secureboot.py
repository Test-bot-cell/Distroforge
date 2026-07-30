"""Unit tests for :mod:`distroforge.core.secureboot`.

Secure Boot signing is dry-run auditable like everything else: the service records
the chroot installs, the per-module ``sign-file`` invocations, and the review samples
as CommandSpecs. The kernel selector and the target-path rewriter are pinned too, since
both feed the argv an operator reads before signing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from distroforge.core.command import CommandRunner
from distroforge.core.secureboot import (
    SecureBootOptions,
    SecureBootService,
    _latest_kernel,
)


def _make_modules(root: Path, kernel: str, names: list[str]) -> None:
    modules_dir = root / "lib" / "modules" / kernel
    modules_dir.mkdir(parents=True)
    for name in names:
        (modules_dir / name).write_text("", encoding="utf-8")


def _argvs(runner: CommandRunner) -> list[tuple[str, ...]]:
    return [spec.argv for spec in runner.history]


def test_disabled_service_does_nothing(tmp_path: Path) -> None:
    runner = CommandRunner(dry_run=True)
    service = SecureBootService(runner, tmp_path, SecureBootOptions(enabled=False), use_sudo=False)

    service.apply()

    assert runner.history == []


def test_enabled_installs_tools_and_samples_modules(tmp_path: Path) -> None:
    _make_modules(tmp_path, "6.8.0-1-generic", ["nvidia.ko", "ext4.ko.xz", "not-a-module.txt"])
    runner = CommandRunner(dry_run=True)
    service = SecureBootService(
        runner, tmp_path, SecureBootOptions(enabled=True, sign_modules=False), use_sudo=False
    )

    service.apply()

    argvs = _argvs(runner)
    assert ("chroot", str(tmp_path), "apt-get", "-y", "install", "sbsigntool", "mokutil") in argvs
    sample = next(a for a in argvs if a[0] == "secureboot-modules-sample")
    assert sample[1] == "6.8.0-1-generic"
    # Only kernel modules are sampled, and they are sorted.
    assert set(sample[2:]) == {
        "/lib/modules/6.8.0-1-generic/ext4.ko.xz",
        "/lib/modules/6.8.0-1-generic/nvidia.ko",
    }


def test_sign_modules_without_key_emits_warning(tmp_path: Path) -> None:
    _make_modules(tmp_path, "6.8.0-1-generic", ["ext4.ko"])
    runner = CommandRunner(dry_run=True)
    service = SecureBootService(
        runner,
        tmp_path,
        SecureBootOptions(enabled=True, sign_modules=True, warn_unsigned_modules=False),
        use_sudo=False,
    )

    service.apply()

    argvs = _argvs(runner)
    assert any(a[0] == "secureboot-warning" for a in argvs)
    # No sign-file invocation happened without a key/cert pair.
    assert not any("sign-file" in part for a in argvs for part in a)


def test_sign_modules_signs_each_kernel_module(tmp_path: Path) -> None:
    kernel = "6.8.0-1-generic"
    _make_modules(tmp_path, kernel, ["a.ko", "b.ko.xz", "skip.txt"])
    key = tmp_path / "mok.key"
    cert = tmp_path / "mok.crt"
    key.write_text("", encoding="utf-8")
    cert.write_text("", encoding="utf-8")
    runner = CommandRunner(dry_run=True)
    service = SecureBootService(
        runner,
        tmp_path,
        SecureBootOptions(
            enabled=True,
            sign_modules=True,
            warn_unsigned_modules=False,
            mok_key=str(key),
            mok_cert=str(cert),
        ),
        use_sudo=False,
    )

    service.apply()

    sign_tool = f"/usr/src/linux-headers-{kernel}/scripts/sign-file"
    signed = [a for a in _argvs(runner) if sign_tool in a]
    assert len(signed) == 2
    signed_modules = {a[-1] for a in signed}
    assert signed_modules == {
        f"/lib/modules/{kernel}/a.ko",
        f"/lib/modules/{kernel}/b.ko.xz",
    }
    # Keys inside the root are rewritten to their in-target absolute path.
    # argv is (chroot, root, sign-tool, "sha256", key, cert, module).
    for spec in signed:
        assert spec[3] == "sha256"
        assert spec[4] == "/mok.key"
        assert spec[5] == "/mok.crt"


def test_target_path_leaves_outside_paths_untouched(tmp_path: Path) -> None:
    service = SecureBootService(runner=CommandRunner(dry_run=True), root=tmp_path, options=SecureBootOptions(), use_sudo=False)

    outside = Path("/etc/keys/mok.key")
    assert service._target_path(outside) == "/etc/keys/mok.key"


def test_latest_kernel_picks_highest_sorted(tmp_path: Path) -> None:
    for kernel in ("6.8.0-1-generic", "6.8.0-10-generic", "6.8.0-2-generic"):
        (tmp_path / "lib" / "modules" / kernel).mkdir(parents=True)

    # String sort is what the code uses; "-2-" sorts after "-10-".
    assert _latest_kernel(tmp_path) == "6.8.0-2-generic"


def test_latest_kernel_requires_modules_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="No /lib/modules directory"):
        _latest_kernel(tmp_path)


def test_latest_kernel_requires_an_installed_kernel(tmp_path: Path) -> None:
    (tmp_path / "lib" / "modules").mkdir(parents=True)

    with pytest.raises(ValueError, match="No installed kernels"):
        _latest_kernel(tmp_path)
