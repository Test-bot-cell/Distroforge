from __future__ import annotations

import stat

from distroforge.core.apt import AptService, PackagePlan
from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.chroot import BIND_MOUNTS, POLICY_RC_D, ChrootService, resolve_chroot_backend
from distroforge.core.command import CommandRunner
from distroforge.core.project import Project


def test_mount_runtime_isolates_propagation_for_every_bind(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)
    root = tmp_path / "rootfs"

    ChrootService(runner, root, use_sudo=False).mount_runtime()

    argvs = [spec.argv for spec in runner.history]
    for _, target in BIND_MOUNTS:
        assert ("mount", "--make-rslave", str(root / target)) in argvs
    assert sum(1 for argv in argvs if argv[:2] == ("mount", "--make-rslave")) == len(BIND_MOUNTS)
    assert not root.exists()


def test_mount_blocks_service_starts_and_unmount_removes_it(tmp_path) -> None:
    root = tmp_path / "rootfs"
    policy = str(root / POLICY_RC_D)

    mount_runner = CommandRunner(dry_run=True)
    ChrootService(mount_runner, root, use_sudo=False).mount_runtime()
    assert ("write-file", policy) in [spec.argv for spec in mount_runner.history]
    assert not (root / POLICY_RC_D).exists()

    umount_runner = CommandRunner(dry_run=True)
    ChrootService(umount_runner, root, use_sudo=False).unmount_runtime()
    assert ("rm", "-f", policy) in [spec.argv for spec in umount_runner.history]


def test_nspawn_backend_uses_systemd_nspawn_without_bind_mounts(tmp_path) -> None:
    root = tmp_path / "rootfs"
    runner = CommandRunner(dry_run=True)
    chroot = ChrootService(runner, root, use_sudo=False, backend="nspawn")

    chroot.mount_runtime()
    command = chroot.command("apt-get", "update")
    chroot.unmount_runtime()

    argvs = [spec.argv for spec in runner.history]
    assert command.argv[:6] == (
        "systemd-nspawn",
        "--quiet",
        "--register=no",
        "--as-pid2",
        "--directory",
        str(root),
    )
    assert command.argv[-2:] == ("apt-get", "update")
    assert not any(argv[:2] == ("mount", "--bind") for argv in argvs)
    assert ("write-file", str(root / POLICY_RC_D)) in argvs
    assert ("rm", "-f", str(root / POLICY_RC_D)) in argvs


def test_auto_backend_prefers_nspawn_when_available(monkeypatch) -> None:
    monkeypatch.setattr(
        "distroforge.core.chroot.CommandRunner.has_binary",
        lambda name: name == "systemd-nspawn",
    )

    assert resolve_chroot_backend("auto") == "nspawn"


def test_auto_backend_falls_back_to_chroot(monkeypatch) -> None:
    monkeypatch.setattr("distroforge.core.chroot.CommandRunner.has_binary", lambda _name: False)

    assert resolve_chroot_backend("auto") == "chroot"


def test_service_block_writes_exit_101_and_is_removable(tmp_path) -> None:
    root = tmp_path / "rootfs"
    chroot = ChrootService(CommandRunner(dry_run=False), root, use_sudo=False)

    chroot._block_service_starts()
    policy = root / POLICY_RC_D
    assert policy.read_text(encoding="utf-8") == "#!/bin/sh\nexit 101\n"
    assert stat.S_IMODE(policy.stat().st_mode) == 0o755

    chroot._unblock_service_starts()
    assert not policy.exists()


def test_apt_operations_are_noninteractive(tmp_path) -> None:
    project = Project.create("AptNoninteractive", tmp_path / "apt-ni", "26.04")
    runner = CommandRunner(dry_run=True)
    apt = AptService(runner, project.squashfs_root, project.release, use_sudo=False)

    apt.update()
    apt.apply_plan(PackagePlan(install=["curl"], remove=["nano"]))

    apt_cmds = [spec.argv for spec in runner.history if "apt-get" in spec.argv]
    assert apt_cmds
    for argv in apt_cmds:
        index = argv.index("apt-get")
        assert argv[index - 2:index] == ("env", "DEBIAN_FRONTEND=noninteractive")


def test_full_dry_run_build_hardens_the_chroot(tmp_path) -> None:
    project = Project.create("ChrootHardening", tmp_path / "ch", "26.04")
    project.source_mode = "bootstrap"
    runner = CommandRunner(dry_run=True)

    BuildOrchestrator(project, runner, BuildOptions()).run()

    policy = str(project.squashfs_root / POLICY_RC_D)
    argvs = [spec.argv for spec in runner.history]
    assert any("--make-rslave" in argv for argv in argvs)
    assert ("write-file", policy) in argvs
    assert ("rm", "-f", policy) in argvs
    assert any("DEBIAN_FRONTEND=noninteractive" in argv and "apt-get" in argv for argv in argvs)
