from __future__ import annotations

from distroforge.core.command import CommandRunner
from distroforge.core.doctor import (
    apt_install_command,
    install_debian_dev_missing,
    install_missing,
    install_packages_for,
    install_packages_for_debian_dev,
    manual_install_packages_for_debian_dev,
    python_package_versions,
    run_debian_dev_doctor,
    run_doctor,
    run_python_doctor,
)
from distroforge.core.rich_console import TableData, print_status, print_table, rows


def run_doctor_command(
    *,
    fix_python: bool,
    python: bool,
    debian_dev: bool,
    install: bool,
    include_optional: bool,
    no_sudo: bool,
) -> None:
    if fix_python:
        print("Recommended Python environment:")
        print("  python3 -m venv .venv")
        print("  .venv/bin/python -m pip install -e '.[dev,typer,pyqt6]'")
        print("\nThen run:")
        print("  .venv/bin/python -m distroforge doctor --python")
        return
    if python:
        versions = python_package_versions()
        report = run_python_doctor()
        table = TableData(
            "Python Dependencies",
            ("State", "Package", "Version", "Reason"),
            rows(
                (
                    "ok" if item.available else "missing",
                    item.binary,
                    versions.get(item.binary, "-"),
                    item.reason,
                )
                for item in report
            ),
        )
        if not print_table(table):
            for item in report:
                mark = "ok" if item.available else "missing"
                print(f"{mark:8} {item.binary:18} {versions.get(item.binary, '-'):12} {item.reason}")
        return
    if debian_dev:
        runner = CommandRunner(dry_run=not install)
        report = run_debian_dev_doctor(runner)
        table = TableData(
            "Debian/Ubuntu Maintainer Tooling",
            ("State", "Group", "Tool", "APT package", "Reason"),
            rows(
                (
                    "ok" if item.available else "missing",
                    item.group,
                    item.binary,
                    item.apt_package,
                    item.reason,
                )
                for item in report
            ),
        )
        if not print_table(table):
            for item in report:
                mark = "ok" if item.available else "missing"
                print(f"{mark:8} {item.group:10} {item.binary:22} {item.apt_package:22} {item.reason}")
        packages = install_packages_for_debian_dev(report)
        if packages:
            if not print_status("\nMissing apt packages:", "bold yellow"):
                print("\nMissing apt packages:")
            print("  " + " ".join(packages))
            if not print_status("\nInstall command:", "bold green"):
                print("\nInstall command:")
            print("  " + apt_install_command(packages).replace("apt install", "apt install --no-remove"))
        manual_packages = manual_install_packages_for_debian_dev(report)
        if manual_packages:
            if not print_status("\nManual review packages:", "bold yellow"):
                print("\nManual review packages:")
            print("  " + " ".join(manual_packages))
            print("  Install manually only if you accept possible initramfs/live-media package changes.")
        if install:
            install_debian_dev_missing(
                runner,
                report,
                include_manual=include_optional,
                use_sudo=not no_sudo,
            )
        return
    runner = CommandRunner(dry_run=not install)
    report = run_doctor(runner)
    table = TableData(
        "Host Dependencies",
        ("State", "Tool", "Reason"),
        rows(("ok" if item.available else "missing", item.binary, item.reason) for item in report),
    )
    if not print_table(table):
        for item in report:
            mark = "ok" if item.available else "missing"
            print(f"{mark:8} {item.binary:18} {item.reason}")
    packages = install_packages_for(report, include_optional=include_optional)
    if packages:
        if not print_status("\nMissing apt packages:", "bold yellow"):
            print("\nMissing apt packages:")
        print("  " + " ".join(packages))
        if not print_status("\nInstall command:", "bold green"):
            print("\nInstall command:")
        print("  " + apt_install_command(packages))
    if install:
        install_missing(
            runner,
            report,
            include_optional=include_optional,
            use_sudo=not no_sudo,
        )
