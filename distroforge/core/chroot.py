from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .command import CommandRunner, CommandSpec, sudo
from .fsops import FileSystemOps

ChrootBackend = Literal["chroot", "nspawn", "auto"]

BIND_MOUNTS = (
    ("/dev", "dev"),
    ("/dev/pts", "dev/pts"),
    ("/proc", "proc"),
    ("/sys", "sys"),
)

# /run is deliberately not in the list above. It used to be, and the host's /run holds
# the control sockets of the host's own daemons -- /run/snapd.socket,
# /run/systemd/private, /run/dbus/system_bus_socket, /run/udev/control -- so binding it
# gave every maintainer script in the target root a way to command the build machine as
# root. policy-rc.d closes the well-behaved route (invoke-rc.d, deb-systemd-invoke) and
# nothing else: measured on an Ubuntu 26.04 desktop, the postinst or postrm of udev,
# dbus, snapd, polkitd, accountsservice and networkd-dispatcher each call
# `systemctl --system daemon-reload` or `systemctl try-restart` directly. A minbase
# bootstrap runs few such scripts and a desktop seed runs hundreds. This is not a
# hypothesis about the risk either: snaps installed from a chroot phase had already
# been found landing in the build machine's own /var/lib/snapd (see core/snaps.py).
#
# The target gets an empty tmpfs instead, which is what a chroot's /run should be:
# writable, private, and gone when the phase ends. apt keeps working because the
# resolver is reached over the shared network namespace, not through /run --
# mmdebstrap copies the host's /etc/resolv.conf into the target during its essential
# step, and a stub listener on loopback is as reachable from the chroot as from here.
PRIVATE_TMPFS = ("run",)

# Mounted with the options a real /run carries, because "an empty tmpfs" was not enough on
# its own: `mount -t tmpfs tmpfs <dir>` with no -o comes up 1777, sticky, with suid, dev and
# exec all permitted and no size cap -- measured, not assumed. The host's own /run is
# mode=755,nosuid,nodev,noexec,size=1584752k, which is 10% of this machine's 15847488 kB of
# RAM, so a bare tmpfs would have widened exactly what the change to a private /run was
# tightening: any uid on the build machine could write into the target's /run for the whole
# phase -- including over the resolver seeded below, which every apt call in that phase then
# reads. With mode=0755 the mount is root's, so the seed goes through the privilege helper
# like every other write into the target root, and no unprivileged process can plant a
# symlink for it to follow.
PRIVATE_TMPFS_OPTIONS = "mode=0755,nosuid,nodev,noexec,size=10%"

# What a fresh tmpfs has to be given back before the phase can use it. The bootstrap leaves
# /run/lock on the persistent rootfs -- base-files.postinst creates it mode 1777, and Debian
# Policy makes /var/lock a symlink to it -- and mounting over /run hides it, so from the
# second phase onward /var/lock dangled and any flock() or lockfile under it failed with
# ENOENT. Measured in the rootfs of the failed desktop run: var/lock -> /run/lock, with
# run/lock sitting underneath the mount that hid it. Same shape as the resolver bug below,
# one level down, which is why both are repaired in the same place.
PRIVATE_RUN_DIRECTORIES = (("run/lock", "1777"),)

# That tmpfs starts empty, and an empty /run costs the target its name resolution.
# systemd-resolved's postinst -- which every desktop seed installs -- moves
# /etc/resolv.conf aside and replaces it with a symlink to
# ../run/systemd/resolve/stub-resolv.conf, copying the working content to that path on
# the way. The copy lands on the tmpfs, so it dies with the phase that made it, and the
# next phase mounts a fresh empty tmpfs under a symlink that now dangles: apt fails with
# "Temporary failure resolving". Measured rather than deduced -- a from-scratch desktop
# build died exactly there, with the postinst's own .resolv.conf.systemd-resolved.bak
# left in the rootfs to prove which branch it had taken. The host bind used to hide this
# by making /run outlive the phase, at the price of that same cp landing in the build
# machine's own /run/systemd/resolve.
#
# So every phase reseeds the resolver, and only ever inside the tmpfs it just mounted:
# that mount is the one thing this service made volatile, so it is the one thing this
# service repairs. A resolv.conf living on the persistent rootfs is left alone -- nothing
# here broke it, and writing there would put the build machine's nameserver and search
# domain into the shipped image.
#
# Both halves of this are what the reference implementation does. systemd-nspawn(1)
# "will mount file systems private to the container to /dev/, /run/", and its
# --resolv-conf=auto -- the default -- says that "if systemd-resolved.service is running
# its stub resolv.conf file is used [...] the file is copied if the image is writable".
# Private /run plus the host's stub content, copied in. Note where nspawn stops rather than
# assuming it would have saved us: the copy modes are documented to copy "unless the file
# exists already and is not a regular file (e.g. a symlink)", and a symlink is precisely
# what the postinst leaves behind, so nspawn's default would decline the same repair this
# does. Only the replace-* modes overwrite a symlink, and they overwrite it in the image.
HOST_RESOLV_CONF = Path("/etc/resolv.conf")

# How far a chain of symlinks is followed before the shape is called dishonest. A loop would
# otherwise spin forever, and no legitimate /etc/resolv.conf needs sixteen hops.
SYMLINK_HOP_BUDGET = 16

POLICY_RC_D = "usr/sbin/policy-rc.d"
_POLICY_RC_D_BODY = "#!/bin/sh\nexit 101\n"


@dataclass(frozen=True)
class ChrootBackendCapability:
    name: str
    available: bool
    selected: bool
    active: bool
    detail: str
    package: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "available": self.available,
            "selected": self.selected,
            "active": self.active,
            "detail": self.detail,
            "package": self.package,
        }


def resolve_chroot_backend(backend: ChrootBackend) -> Literal["chroot", "nspawn"]:
    if backend == "auto":
        return "nspawn" if CommandRunner.has_binary("systemd-nspawn") else "chroot"
    return backend


def detect_chroot_backends(backend: ChrootBackend = "auto") -> tuple[ChrootBackendCapability, ...]:
    selected = resolve_chroot_backend(backend)
    return (
        ChrootBackendCapability(
            "auto",
            True,
            backend == "auto",
            False,
            f"selects {selected} on this host",
            "",
        ),
        ChrootBackendCapability(
            "chroot",
            CommandRunner.has_binary("chroot"),
            backend == "chroot",
            selected == "chroot",
            "classic maintainer shell and package-operation backend",
            "coreutils",
        ),
        ChrootBackendCapability(
            "nspawn",
            CommandRunner.has_binary("systemd-nspawn"),
            backend == "nspawn",
            selected == "nspawn",
            "optional stronger maintainer shell via systemd-nspawn",
            "systemd-container",
        ),
    )


def host_resolver_content() -> str:
    """The build machine's nameservers, and nothing else about the build machine.

    Read through any symlink, so a systemd-resolved host yields the stub file's
    "nameserver 127.0.0.53" rather than the link itself. That address answers from inside
    the chroot because the chroot shares the host's network namespace, which is also why
    the copy mmdebstrap makes during bootstrap works.

    Only the nameserver lines are kept. The host's search domain is not the target's -- this
    build machine offers "search mshome.net", a hypervisor NAT zone that neither the build
    nor the operator controls -- and a seed carrying it would have every single-label lookup
    inside the chroot answered from there, for the whole phase. Empty when the host has no
    readable resolver or none of its lines names a server, and empty means seed nothing: a
    host that cannot resolve names has nothing to lend.
    """
    try:
        content = HOST_RESOLV_CONF.read_text(encoding="utf-8")
    except OSError:
        return ""
    return "".join(
        f"{line.strip()}\n" for line in content.splitlines() if line.split()[:1] == ["nameserver"]
    )


def resolve_in_root(root: Path, inside: str) -> Path | None:
    """Resolve a target-root path the way the chroot's own kernel would, without leaving it.

    Symlinks are expanded here rather than left to the filesystem because inside a chroot an
    absolute link target starts at <root>, while every syscall the build machine makes starts
    it at the build machine's own /. Following a target's links as written is how a write
    meant for <root>/run reaches the build machine's /run instead -- and a link in a
    directory component is enough, so the whole path is walked, not just its last element.

    ".." at <root> stays at <root>, which is what the kernel does with "/..", so this cannot
    return a path outside <root> by construction rather than by a check that has to be right.
    None when the chain outlasts the hop budget: a loop, or a shape not worth guessing at.
    """
    resolved = root
    pending = _path_parts(inside)
    hops = 0
    while pending:
        part = pending.pop(0)
        if part == "..":
            resolved = root if resolved == root else resolved.parent
            continue
        candidate = resolved / part
        try:
            target = os.readlink(candidate)
        except OSError:
            # Not a symlink, not readable, or not there at all: this component is the answer.
            resolved = candidate
            continue
        hops += 1
        if hops > SYMLINK_HOP_BUDGET:
            return None
        if target.startswith("/"):
            resolved = root
        pending = _path_parts(target) + pending
    return resolved


def _path_parts(path: str) -> list[str]:
    return [part for part in path.split("/") if part and part != "."]


def resolver_seed_path(root: Path) -> Path | None:
    """Where a phase must write the resolver for the target to resolve names, if anywhere.

    Answers only when the target's /etc/resolv.conf leads, through however many links, into
    the private /run: that mount is the one thing this service makes volatile, so it is the
    one thing this service repairs.

    Everything else is left alone, and deliberately. A resolver that lives on the persistent
    rootfs survives the phase without help. One that is missing entirely was not made missing
    here -- writing to /etc to invent it would ship this build machine's nameserver inside the
    image, and deleting /etc/resolv.conf is ordinary live-image hygiene for a chroot hook to
    do. Both cases are reported rather than silently skipped; see _seed_resolver.
    """
    seeded = resolve_in_root(root, "etc/resolv.conf")
    run = root / "run"
    if seeded is None or seeded == run or not seeded.is_relative_to(run):
        return None
    return seeded


@dataclass
class ChrootService:
    runner: CommandRunner
    root: Path
    use_sudo: bool = True
    backend: ChrootBackend = "chroot"

    def resolved_backend(self) -> Literal["chroot", "nspawn"]:
        return resolve_chroot_backend(self.backend)

    def mount_runtime(self) -> None:
        if self.resolved_backend() == "nspawn":
            self._block_service_starts()
            return
        for source, target in BIND_MOUNTS:
            destination = self.root / target
            FileSystemOps(self.runner, self.use_sudo).mkdir(destination, f"Create bind mount target {target}")
            self.runner.run(
                CommandSpec(
                    argv=sudo(
                        ("mount", "--bind", source, str(destination)), self.use_sudo
                    ),
                    needs_root=self.use_sudo,
                    description=f"Bind mount {source}",
                )
            )
            self._isolate_propagation(destination, target)
        for target in PRIVATE_TMPFS:
            destination = self.root / target
            FileSystemOps(self.runner, self.use_sudo).mkdir(destination, f"Create private mount target {target}")
            self.runner.run(
                CommandSpec(
                    argv=sudo(
                        (
                            "mount",
                            "-t",
                            "tmpfs",
                            "-o",
                            PRIVATE_TMPFS_OPTIONS,
                            "tmpfs",
                            str(destination),
                        ),
                        self.use_sudo,
                    ),
                    needs_root=self.use_sudo,
                    description=f"Mount a private {target} for the target root",
                )
            )
            self._isolate_propagation(destination, target)
        self._provide_run_directories()
        self._seed_resolver()
        self._block_service_starts()

    def _provide_run_directories(self) -> None:
        for target, mode in PRIVATE_RUN_DIRECTORIES:
            self.runner.run(
                CommandSpec(
                    argv=sudo(
                        ("install", "-d", "-m", mode, str(self.root / target)), self.use_sudo
                    ),
                    needs_root=self.use_sudo,
                    description=f"Restore /{target} on the private tmpfs that hides it",
                )
            )

    def _seed_resolver(self) -> None:
        seed = resolver_seed_path(self.root)
        if seed is None:
            self._record_seed_skip("resolver-is-not-on-the-private-run")
            return
        content = host_resolver_content()
        if not content:
            # The target resolves names through the mount this phase just emptied, and this
            # build machine has no nameserver to lend it, so apt is already doomed. Say it
            # here instead of leaving the operator with apt's "Temporary failure resolving".
            self._record_seed_skip("no-nameserver-on-the-build-machine")
            return
        FileSystemOps(self.runner, self.use_sudo).write_text(
            seed,
            content,
            f"Seed the target resolver at /{seed.relative_to(self.root)}",
            mode="0644",
        )

    def _record_seed_skip(self, reason: str) -> None:
        # Every other decision in mount_runtime is a CommandSpec that the plan, the JSONL log
        # and the audit tests can all see. A bare `return` here is how a phase would start
        # with no resolver and no record of why, and this failure cost a full desktop build to
        # find once already. Virtual verb: recorded, never executed.
        self.runner.run(
            CommandSpec(
                argv=("resolver-seed-skip", reason, str(self.root)),
                description=f"No resolver seeded for the target root: {reason}",
            )
        )

    def _isolate_propagation(self, destination: Path, target: str) -> None:
        # Detach propagation so an unmount or new mount inside the chroot can
        # never leak into the host namespace (systemd shares / by default).
        self.runner.run(
            CommandSpec(
                argv=sudo(("mount", "--make-rslave", str(destination)), self.use_sudo),
                needs_root=self.use_sudo,
                description=f"Isolate mount propagation for {target}",
            )
        )

    def unmount_runtime(self) -> None:
        self._unblock_service_starts()
        if self.resolved_backend() == "nspawn":
            return
        for target in reversed(PRIVATE_TMPFS):
            self._unmount(target)
        for _, target in reversed(BIND_MOUNTS):
            self._unmount(target)

    def _unmount(self, target: str) -> None:
        self.runner.run(
            CommandSpec(
                argv=sudo(("umount", "-lf", str(self.root / target)), self.use_sudo),
                needs_root=self.use_sudo,
                description=f"Unmount {target}",
            ),
            check=False,
        )

    def _block_service_starts(self) -> None:
        # Package postinst scripts call invoke-rc.d to start daemons; inside a
        # chroot with no real init that hangs or fails, so policy-rc.d exits 101.
        FileSystemOps(self.runner, self.use_sudo).write_text(
            self.root / POLICY_RC_D,
            _POLICY_RC_D_BODY,
            "Block service starts during chroot package operations",
            mode="0755",
        )

    def _unblock_service_starts(self) -> None:
        FileSystemOps(self.runner, self.use_sudo).remove(
            self.root / POLICY_RC_D,
            "Remove chroot service-start block",
        )

    def command(self, *argv: str) -> CommandSpec:
        if self.resolved_backend() == "nspawn":
            return CommandSpec(
                argv=sudo(
                    (
                        "systemd-nspawn",
                        "--quiet",
                        "--register=no",
                        "--as-pid2",
                        "--directory",
                        str(self.root),
                        *argv,
                    ),
                    self.use_sudo,
                ),
                needs_root=self.use_sudo,
                description="Run command in target root with systemd-nspawn",
            )
        return CommandSpec(
            argv=sudo(("chroot", str(self.root), *argv), self.use_sudo),
            needs_root=self.use_sudo,
            description="Run command in target root",
        )

    def run(self, *argv: str) -> None:
        self.runner.run(self.command(*argv))

    def shell(self, shell: str = "/bin/bash") -> CommandSpec:
        return self.command(shell)
