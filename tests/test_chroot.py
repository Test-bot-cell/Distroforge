from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

import pytest

from distroforge.core.apt import AptService, PackagePlan
from distroforge.core.build import BuildOptions, BuildOrchestrator
from distroforge.core.chroot import (
    BIND_MOUNTS,
    POLICY_RC_D,
    PRIVATE_RUN_DIRECTORIES,
    PRIVATE_TMPFS,
    PRIVATE_TMPFS_OPTIONS,
    ChrootService,
    resolve_chroot_backend,
    resolver_seed_path,
)
from distroforge.core.command import CommandRunner
from distroforge.core.project import Project

REPO_ROOT = Path(__file__).resolve().parents[1]

# What a real systemd-resolved host lends the target, in the shape it really has: twenty
# lines of generated header before three directives. The stub address answers from inside
# the chroot because the chroot shares the host's network namespace.
_HOST_RESOLVER = """# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).
# Do not edit.
#
# Third party programs should typically not access this file directly, but only
# through the symlink at /etc/resolv.conf.

nameserver 127.0.0.53
nameserver 192.0.2.53
options edns0 trust-ad
search example.invalid
"""

# What may be copied out of it: the servers, never the build machine's search domain.
_SEEDED_RESOLVER = "nameserver 127.0.0.53\nnameserver 192.0.2.53\n"


def _target_with_resolver(tmp_path, link: str | None = None, *, regular: bool = False) -> Path:
    """A target rootfs whose /etc/resolv.conf is what a real phase would find there."""
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True, exist_ok=True)
    if regular:
        (root / "etc" / "resolv.conf").write_text(_HOST_RESOLVER, encoding="utf-8")
    elif link is not None:
        (root / "etc" / "resolv.conf").symlink_to(link)
    return root


def _host_resolver(monkeypatch, tmp_path, content: str = _HOST_RESOLVER) -> None:
    """Point the service at a fixture instead of this machine's own resolver.

    Reading the real /etc/resolv.conf would make these tests say something different on
    a developer's desktop than in a container that has none.
    """
    host = tmp_path / "host-resolv.conf"
    if content:
        host.write_text(content, encoding="utf-8")
    monkeypatch.setattr("distroforge.core.chroot.HOST_RESOLV_CONF", host)


def _writes(runner: CommandRunner) -> list[str]:
    return [spec.argv[1] for spec in runner.history if spec.argv[0] == "write-file"]


def _seed_skips(runner: CommandRunner) -> list[str]:
    return [spec.argv[1] for spec in runner.history if spec.argv[0] == "resolver-seed-skip"]


def _tmpfs_mount(root: Path) -> tuple[str, ...]:
    return ("mount", "-t", "tmpfs", "-o", PRIVATE_TMPFS_OPTIONS, "tmpfs", str(root / "run"))


def test_mount_runtime_isolates_propagation_for_every_bind(tmp_path) -> None:
    runner = CommandRunner(dry_run=True)
    root = tmp_path / "rootfs"

    ChrootService(runner, root, use_sudo=False).mount_runtime()

    argvs = [spec.argv for spec in runner.history]
    for _, target in BIND_MOUNTS:
        assert ("mount", "--make-rslave", str(root / target)) in argvs
    for target in PRIVATE_TMPFS:
        assert ("mount", "--make-rslave", str(root / target)) in argvs
    expected = len(BIND_MOUNTS) + len(PRIVATE_TMPFS)
    assert sum(1 for argv in argvs if argv[:2] == ("mount", "--make-rslave")) == expected
    assert not root.exists()


def test_the_host_run_is_never_bound_into_the_target(tmp_path) -> None:
    """The target gets a /run of its own, not the build machine's.

    The host's /run holds the control sockets of the host's own daemons, so binding it
    let any maintainer script in the target command this machine as root. policy-rc.d
    does not close that: udev, dbus, snapd, polkitd, accountsservice and
    networkd-dispatcher all call `systemctl --system daemon-reload` or `try-restart`
    directly, outside invoke-rc.d. A desktop seed runs hundreds of such scripts.
    """
    runner = CommandRunner(dry_run=True)
    root = tmp_path / "rootfs"

    ChrootService(runner, root, use_sudo=False).mount_runtime()

    argvs = [spec.argv for spec in runner.history]
    assert "/run" not in [source for source, _ in BIND_MOUNTS]
    assert not any(argv[:3] == ("mount", "--bind", "/run") for argv in argvs)
    assert _tmpfs_mount(root) in argvs


def test_the_private_run_carries_the_options_a_real_run_carries(tmp_path) -> None:
    """A bare tmpfs is 1777 with suid, dev and exec allowed; the /run it replaced is not.

    Measured, not assumed: `mount -t tmpfs tmpfs <dir>` with no -o comes up mode 1777, and
    this host's own /run is mode=755,nosuid,nodev,noexec. Coming up world-writable would
    widen exactly what a private /run was meant to tighten -- any uid on the build machine
    could then rewrite the resolver seeded into it, which every apt call of the phase reads.
    """
    runner = CommandRunner(dry_run=True)
    root = tmp_path / "rootfs"

    ChrootService(runner, root, use_sudo=False).mount_runtime()

    assert _tmpfs_mount(root) in [spec.argv for spec in runner.history]
    for option in ("mode=0755", "nosuid", "nodev", "noexec"):
        assert option in PRIVATE_TMPFS_OPTIONS.split(",")


def test_var_lock_still_resolves_once_the_tmpfs_hides_run_lock(tmp_path) -> None:
    """/var/lock is a symlink to /run/lock, and the mount hid what it points at.

    base-files.postinst creates /run/lock on the persistent rootfs during the bootstrap, so
    mounting over /run left /var/lock dangling from the second phase onward and any flock()
    under it failing with ENOENT. Measured in the failed desktop run's rootfs: var/lock ->
    /run/lock, with run/lock underneath the mount that hid it.
    """
    runner = CommandRunner(dry_run=True)
    root = tmp_path / "rootfs"

    ChrootService(runner, root, use_sudo=False).mount_runtime()

    argvs = [spec.argv for spec in runner.history]
    assert PRIVATE_RUN_DIRECTORIES == (("run/lock", "1777"),)
    for target, mode in PRIVATE_RUN_DIRECTORIES:
        provided = ("install", "-d", "-m", mode, str(root / target))
        assert provided in argvs
        # After the mount, or the mount buries it again.
        assert argvs.index(_tmpfs_mount(root)) < argvs.index(provided)


def test_the_private_run_is_unmounted_when_the_phase_ends(tmp_path) -> None:
    # Left mounted, it would be one more thing under the rootfs at pack time -- which
    # SquashfsService now refuses outright, after a surviving /proc bind mount once
    # made mksquashfs walk into /proc/kcore.
    runner = CommandRunner(dry_run=True)
    root = tmp_path / "rootfs"

    ChrootService(runner, root, use_sudo=False).unmount_runtime()

    argvs = [spec.argv for spec in runner.history]
    assert ("umount", "-lf", str(root / "run")) in argvs


def test_the_resolver_is_reseeded_in_the_private_run_of_every_phase(tmp_path, monkeypatch) -> None:
    """An empty /run costs the target its DNS, and a build died of it.

    systemd-resolved's postinst replaces /etc/resolv.conf with a symlink to
    ../run/systemd/resolve/stub-resolv.conf and copies the working content there. That
    copy lands on the tmpfs, so it dies with the phase, and the next phase mounts a fresh
    empty tmpfs under a dangling symlink: apt-get update then fails with "Temporary
    failure resolving". Every phase reseeds, so no phase inherits a broken resolver.
    """
    _host_resolver(monkeypatch, tmp_path)
    root = _target_with_resolver(tmp_path, "../run/systemd/resolve/stub-resolv.conf")
    runner = CommandRunner(dry_run=True)

    ChrootService(runner, root, use_sudo=False).mount_runtime()

    seeded = str(root / "run" / "systemd" / "resolve" / "stub-resolv.conf")
    argvs = [spec.argv for spec in runner.history]
    assert seeded in _writes(runner)
    # After the tmpfs, never before: a seed written first is erased by the mount over it.
    assert argvs.index(_tmpfs_mount(root)) < argvs.index(("write-file", seeded))


def test_the_seed_carries_the_host_nameservers_and_not_its_search_domain(
    tmp_path, monkeypatch
) -> None:
    """The target needs the servers. It has no use for where the build machine looks.

    A verbatim copy would hand the chroot this build machine's search domain -- on the
    machine this was measured on, a hypervisor NAT zone neither the build nor the operator
    controls -- and every single-label lookup in the phase would be answered from there.
    """
    _host_resolver(monkeypatch, tmp_path)
    root = _target_with_resolver(tmp_path, "/run/systemd/resolve/stub-resolv.conf")

    ChrootService(CommandRunner(dry_run=False), root, use_sudo=False)._seed_resolver()

    # An absolute link is read as root-relative: inside the chroot /run is <root>/run, so
    # following it as written would have the build machine seed its own /run instead.
    seeded = root / "run" / "systemd" / "resolve" / "stub-resolv.conf"
    assert seeded.read_text(encoding="utf-8") == _SEEDED_RESOLVER
    assert "search" not in seeded.read_text(encoding="utf-8")
    assert stat.S_IMODE(seeded.stat().st_mode) == 0o644


def test_a_resolver_reached_through_a_linked_directory_is_still_seeded(
    tmp_path, monkeypatch
) -> None:
    """The link that leads into /run can be a directory component, not the file.

    This is the resolvconf layout, which Debian targets can carry: /etc/resolv.conf ->
    /etc/resolvconf/run/resolv.conf, where /etc/resolvconf/run is itself a link to
    /run/resolvconf. The terminus is on the volatile mount, so it needs the same repair --
    and reading only the last link would have called this "lives on the rootfs, needs no
    help". It also pins the containment: that absolute intermediate link must be read as
    <root>/run/resolvconf, never as the build machine's own /run/resolvconf.
    """
    _host_resolver(monkeypatch, tmp_path)
    root = _target_with_resolver(tmp_path, "/etc/resolvconf/run/resolv.conf")
    (root / "etc" / "resolvconf").mkdir()
    (root / "etc" / "resolvconf" / "run").symlink_to("/run/resolvconf")

    assert resolver_seed_path(root) == root / "run" / "resolvconf" / "resolv.conf"


def test_climbing_out_of_the_target_root_lands_at_the_target_root(tmp_path, monkeypatch) -> None:
    """".." at the target's / stays there, exactly as the kernel treats "/.." in a chroot.

    So a link can be as greedy as it likes -- /run/systemd/../../../../../run/user is just
    /run/user seen from inside -- and the seed still cannot leave <root>. That containment is
    structural here, not a check that has to be right: the walk only ever descends from
    <root>. A lexical normpath, by contrast, computes the build machine's own /run/user for
    this link and then has to remember to reject it.
    """
    _host_resolver(monkeypatch, tmp_path)
    root = _target_with_resolver(tmp_path, "/run/systemd/../../../../../run/user")

    assert resolver_seed_path(root) == root / "run" / "user"


def test_a_resolver_symlink_loop_is_refused_rather_than_followed(tmp_path, monkeypatch) -> None:
    # A rootfs is input: a chain that never terminates must end the walk, not the build.
    _host_resolver(monkeypatch, tmp_path)
    root = _target_with_resolver(tmp_path, "/run/systemd/loop-a")
    (root / "run" / "systemd").mkdir(parents=True)
    (root / "run" / "systemd" / "loop-a").symlink_to("/run/systemd/loop-b")
    (root / "run" / "systemd" / "loop-b").symlink_to("/run/systemd/loop-a")

    assert resolver_seed_path(root) is None


def test_a_resolver_on_the_persistent_rootfs_is_left_alone(tmp_path, monkeypatch) -> None:
    """A regular /etc/resolv.conf survives the phase by itself, so nothing rewrites it.

    It would also be the wrong place to write: unlike the tmpfs, /etc is packed into the
    image, and the build machine's nameserver and search domain have no business shipping
    to whoever boots the ISO.
    """
    _host_resolver(monkeypatch, tmp_path)
    root = _target_with_resolver(tmp_path, regular=True)
    runner = CommandRunner(dry_run=True)

    ChrootService(runner, root, use_sudo=False).mount_runtime()

    assert resolver_seed_path(root) is None
    assert _writes(runner) == [str(root / POLICY_RC_D)]
    assert _seed_skips(runner) == ["resolver-is-not-on-the-private-run"]


@pytest.mark.parametrize(
    "link",
    [
        "../../../../etc/passwd",  # climbs, and lands back on the persistent rootfs
        "/run/../etc/shadow",  # starts under /run and leaves it again
        "/etc/resolvconf/run/resolv.conf",  # a chain whose terminus never reaches /run
        "/run",  # the mount point itself, which is a directory
    ],
)
def test_a_resolver_symlink_may_not_lead_the_seed_out_of_the_private_run(
    tmp_path, monkeypatch, link
) -> None:
    """The link comes from the target rootfs, so it is input, not instruction.

    A rootfs is assembled from thousands of packages and could name anything here. The
    seed is written as root, so a terminus outside the volatile mount must be declined
    rather than written -- otherwise a broken or hostile target picks the file, and the
    write goes to a path on the persistent rootfs that nothing here made volatile.
    """
    _host_resolver(monkeypatch, tmp_path)
    root = _target_with_resolver(tmp_path, link)
    runner = CommandRunner(dry_run=True)

    ChrootService(runner, root, use_sudo=False).mount_runtime()

    assert resolver_seed_path(root) is None
    assert _writes(runner) == [str(root / POLICY_RC_D)]
    assert _seed_skips(runner) == ["resolver-is-not-on-the-private-run"]


def test_a_host_with_no_resolver_of_its_own_seeds_nothing_and_says_so(
    tmp_path, monkeypatch
) -> None:
    """A build machine that cannot resolve names has nothing to lend -- and must say so.

    The target resolves through the mount this phase just emptied, so apt is already doomed;
    an empty resolv.conf there would read as "no nameservers" rather than "not configured".
    Skipping silently is how the operator would meet this as apt's "Temporary failure
    resolving" instead, which is the diagnosis that cost a full desktop build once.
    """
    _host_resolver(monkeypatch, tmp_path, content="")
    root = _target_with_resolver(tmp_path, "../run/systemd/resolve/stub-resolv.conf")
    runner = CommandRunner(dry_run=True)

    ChrootService(runner, root, use_sudo=False).mount_runtime()

    assert _writes(runner) == [str(root / POLICY_RC_D)]
    assert _seed_skips(runner) == ["no-nameserver-on-the-build-machine"]


# Two real phases, in a user namespace, so the bug can be reproduced rather than described.
# Every other test here is dry-run: no tmpfs is ever mounted, so the destruction that starts
# the failure -- the phase ending and taking its /run with it -- cannot happen, and all they
# can pin is the order of recorded argv. This one mounts, writes what systemd-resolved's
# postinst writes, unmounts, and mounts again, then reads /etc/resolv.conf the way apt does.
#
# BIND_MOUNTS is emptied in the child because a user namespace refuses to bind /dev, /proc
# and /sys (measured: "wrong fs type, bad option, bad superblock on /dev"). They are not
# what this proves, and everything that is -- the tmpfs, /run/lock, the seed -- is reached
# through the real mount_runtime, not around it.
_TWO_PHASE_PROBE = """
import json, os, stat, sys
from pathlib import Path
from distroforge.core import chroot as chroot_module
from distroforge.core.command import CommandRunner

root, host = Path(sys.argv[1]), Path(sys.argv[2])
chroot_module.BIND_MOUNTS = ()
chroot_module.HOST_RESOLV_CONF = host
service = chroot_module.ChrootService(CommandRunner(dry_run=False), root, use_sudo=False)
resolver = root / "etc" / "resolv.conf"

service.mount_runtime()
# What systemd-resolved's postinst does, in the phase that installs it: copy the working
# resolver onto /run and point /etc/resolv.conf at the copy.
stub = root / "run" / "systemd" / "resolve" / "stub-resolv.conf"
stub.parent.mkdir(parents=True)
stub.write_text("nameserver 10.53.53.53\\n", encoding="utf-8")
resolver.symlink_to("../run/systemd/resolve/stub-resolv.conf")
first = resolver.read_text(encoding="utf-8").strip()
lock = stat.S_IMODE((root / "run" / "lock").stat().st_mode)
service.unmount_runtime()

# The phase is over. Its /run went with it, and the symlink now points at nothing.
between = resolver.exists()

service.mount_runtime()
second = resolver.read_text(encoding="utf-8").strip()
mode = stat.S_IMODE(stub.stat().st_mode)
service.unmount_runtime()

print(json.dumps({"first": first, "between": between, "second": second,
                  "lock": lock, "mode": mode}))
"""


@lru_cache(maxsize=1)
def _user_namespace_mounts() -> bool:
    with tempfile.TemporaryDirectory() as probe:
        try:
            done = subprocess.run(
                ["unshare", "--user", "--map-root-user", "--mount",
                 "mount", "-t", "tmpfs", "tmpfs", probe],
                capture_output=True,
                check=False,
            )
        except OSError:
            return False
    return done.returncode == 0


@pytest.mark.skipif(
    not _user_namespace_mounts(),
    reason="needs unshare with a user namespace that may mount a tmpfs",
)
def test_two_real_phases_leave_the_target_able_to_resolve_names(tmp_path) -> None:
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    host = tmp_path / "host-resolv.conf"
    host.write_text(_HOST_RESOLVER, encoding="utf-8")

    done = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--mount",
         "python3", "-c", _TWO_PHASE_PROBE, str(root), str(host)],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
    )

    assert done.returncode == 0, done.stderr
    measured = json.loads(done.stdout.splitlines()[-1])
    # Phase 1 resolves through the postinst's own copy, which lives on that phase's tmpfs.
    assert measured["first"] == "nameserver 10.53.53.53"
    # Between phases the copy is gone with the mount: this is the bug, reproduced.
    assert measured["between"] is False
    # Phase 2 resolves again, through the seed, without inheriting the host's search domain.
    assert measured["second"] == _SEEDED_RESOLVER.strip()
    assert measured["mode"] == 0o644
    # And /var/lock's target came back with it, on a tmpfs that is no longer world-writable.
    assert measured["lock"] == 0o1777


def test_a_host_resolver_with_only_a_search_domain_lends_nothing(tmp_path, monkeypatch) -> None:
    # Filtering to nameserver lines must not turn "nothing to lend" into an empty seed that
    # looks configured: a file with no server in it is the same as no file.
    _host_resolver(monkeypatch, tmp_path, content="search example.invalid\noptions edns0\n")
    root = _target_with_resolver(tmp_path, "../run/systemd/resolve/stub-resolv.conf")
    runner = CommandRunner(dry_run=True)

    ChrootService(runner, root, use_sudo=False).mount_runtime()

    assert _writes(runner) == [str(root / POLICY_RC_D)]
    assert _seed_skips(runner) == ["no-nameserver-on-the-build-machine"]


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
    # No phase of a whole build may hand the target the host's /run, not just the one
    # this file constructs by hand.
    assert not any(argv[:3] == ("mount", "--bind", "/run") for argv in argvs)
    assert ("write-file", policy) in argvs
    assert ("rm", "-f", policy) in argvs
    assert any("DEBIAN_FRONTEND=noninteractive" in argv and "apt-get" in argv for argv in argvs)
