from __future__ import annotations

from pathlib import Path

ISO_COMMANDS = {"iso-toolchain", "iso-doctor", "iso-build", "iso-accept", "demo-iso"}


def register_iso_commands(subparsers) -> None:
    iso_toolchain_parser = subparsers.add_parser("iso-toolchain", help="Check or install ISO build host tools")
    iso_toolchain_parser.add_argument("--install", action="store_true")
    iso_toolchain_parser.add_argument("--no-sudo", action="store_true")
    iso_toolchain_parser.add_argument("--json", action="store_true")

    iso_doctor_parser = subparsers.add_parser("iso-doctor", help="Diagnose the next step to produce an ISO")
    iso_doctor_parser.add_argument("root", type=Path)
    iso_doctor_parser.add_argument("--definition", type=Path)
    iso_doctor_parser.add_argument("--json", action="store_true")

    iso_build_parser = subparsers.add_parser("iso-build", help="Run the guarded one-command ISO build path")
    iso_build_parser.add_argument("root", type=Path)
    iso_build_parser.add_argument("--definition", type=Path)
    iso_build_parser.add_argument("--execute", action="store_true")
    iso_build_parser.add_argument("--output-iso", type=Path)
    iso_build_parser.add_argument("--boot-proof", default="none", choices=["none", "auto", "qemu", "iso-scan"])
    iso_build_parser.add_argument("--json", action="store_true")

    iso_accept_parser = subparsers.add_parser("iso-accept", help="Accept or block a produced ISO for publication")
    iso_accept_parser.add_argument("root", type=Path)
    iso_accept_parser.add_argument("--definition", type=Path)
    iso_accept_parser.add_argument("--iso", type=Path)
    iso_accept_parser.add_argument("--output-dir", type=Path)
    iso_accept_parser.add_argument("--json", action="store_true")

    demo_iso_parser = subparsers.add_parser("demo-iso", help="Create and run a minimal demo ISO path")
    demo_iso_parser.add_argument("root", type=Path)
    demo_iso_parser.add_argument("--name")
    demo_iso_parser.add_argument("--release", default="26.04")
    demo_iso_parser.add_argument("--execute", action="store_true")
    demo_iso_parser.add_argument("--json", action="store_true")


def render_iso_command(args) -> tuple[str, bool] | None:
    if args.command == "iso-toolchain":
        from distroforge.commands.iso_toolchain import render_iso_toolchain

        rendered, blocked = render_iso_toolchain(args.install, args.no_sudo, args.json)
        return rendered, blocked
    if args.command == "iso-doctor":
        from distroforge.commands.iso_doctor import render_iso_doctor

        return render_iso_doctor(args.root, args.definition, args.json), False
    if args.command == "iso-build":
        from distroforge.commands.iso_build import render_iso_build

        return render_iso_build(args.root, args.definition, args.execute, args.output_iso, args.boot_proof, args.json), False
    if args.command == "iso-accept":
        from distroforge.commands.iso_accept import render_iso_accept

        rendered, blocked = render_iso_accept(args.root, args.definition, args.iso, args.output_dir, args.json)
        return rendered, blocked
    if args.command == "demo-iso":
        from distroforge.commands.demo_iso import render_demo_iso

        rendered, blocked = render_demo_iso(args.root, args.name, args.release, args.execute, args.json)
        return rendered, blocked
    return None
