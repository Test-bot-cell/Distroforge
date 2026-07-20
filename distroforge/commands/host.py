from __future__ import annotations

from distroforge.commands.catalog import render_chroot_backends, render_host_capabilities


def register_host_commands(sub) -> None:
    host_parser = sub.add_parser("host", help="Show host build capabilities")
    host_parser.add_argument("--json", action="store_true")

    chroot_backends_parser = sub.add_parser("chroot-backends", help="Show maintainer chroot backend availability")
    chroot_backends_parser.add_argument("--json", action="store_true")


def render_host_command(args) -> str | None:
    if args.command == "host":
        return render_host_capabilities(args.json)
    if args.command == "chroot-backends":
        return render_chroot_backends(args.json)
    return None
