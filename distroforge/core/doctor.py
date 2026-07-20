from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from importlib.util import find_spec
from pathlib import Path

from .command import CommandRunner, CommandSpec, sudo


@dataclass(frozen=True)
class DoctorItem:
    binary: str
    available: bool
    reason: str


@dataclass(frozen=True)
class DebianDevTool:
    binary: str
    apt_package: str
    group: str
    reason: str
    manual_install: bool = False
    check_path: str | None = None


@dataclass(frozen=True)
class DebianDevDoctorItem:
    binary: str
    available: bool
    apt_package: str
    group: str
    reason: str
    manual_install: bool = False


REQUIRED_TOOLS = {
    "xorriso": "ISO extraction and rebuild",
    "unsquashfs": "live filesystem extraction",
    "mksquashfs": "live filesystem rebuild",
    "qemu-system-x86_64": "QEMU preview",
    "chroot": "target shell and package operations",
    "apt-get": "package operations",
}

OPTIONAL_TOOLS = {
    "synaptic": "graphical package manager integration",
    "kvm": "hardware acceleration",
    "systemd-nspawn": "stronger isolated target shell",
    "PyQt6-or-PySide6": "Qt Python bindings for DistroForge GUI",
}

PYTHON_PACKAGES = {
    "pydantic": "definition schema validation",
    "yaml": "YAML definition loading via PyYAML",
    "rich": "terminal tables and status output",
    "pluggy": "Python plugin hook integration",
    "typer": "modern optional CLI facade",
}

PYTHON_DISTRIBUTIONS = {
    "yaml": "PyYAML",
}

APT_PACKAGES = {
    "xorriso": "xorriso",
    "unsquashfs": "squashfs-tools",
    "mksquashfs": "squashfs-tools",
    "qemu-system-x86_64": "qemu-system-x86",
    "chroot": "coreutils",
    "apt-get": "apt",
    "synaptic": "synaptic",
    "kvm": "qemu-kvm",
    "systemd-nspawn": "systemd-container",
    "PyQt6-or-PySide6": "python3-pyqt6",
}

DEBIAN_DEV_TOOLS: tuple[DebianDevTool, ...] = (
    DebianDevTool("debuild", "devscripts", "packaging", "Debian source/binary package build wrapper"),
    DebianDevTool("dpkg-buildpackage", "dpkg-dev", "packaging", "Canonical Debian package build entrypoint"),
    DebianDevTool("dh", "debhelper", "packaging", "Debhelper sequence runner"),
    DebianDevTool("pybuild", "dh-python", "packaging", "Python package build integration"),
    DebianDevTool("fakeroot", "fakeroot", "packaging", "Root-like package ownership during local builds"),
    DebianDevTool("gbp", "git-buildpackage", "packaging", "Git-buildpackage release workflow"),
    DebianDevTool("pristine-tar", "pristine-tar", "packaging", "Recreate exact upstream tarballs"),
    DebianDevTool("quilt", "quilt", "packaging", "Debian patch queue maintenance"),
    DebianDevTool("equivs-build", "equivs", "packaging", "Generate local dependency meta-packages"),
    DebianDevTool("dh_make", "dh-make", "packaging", "Bootstrap Debian packaging skeletons"),
    DebianDevTool("lintian", "lintian", "qa", "Debian policy and packaging lint"),
    DebianDevTool("autopkgtest", "autopkgtest", "qa", "Run Debian package integration tests"),
    DebianDevTool("sbuild", "sbuild", "qa", "Clean chroot package builds"),
    DebianDevTool("schroot", "schroot", "qa", "Manage sbuild chroot sessions"),
    DebianDevTool("pbuilder", "pbuilder", "qa", "Alternative clean package build backend"),
    DebianDevTool("mmdebstrap", "mmdebstrap", "qa", "Rootless Debian chroot/bootstrap backend"),
    DebianDevTool("debootstrap", "debootstrap", "qa", "Classic Debian/Ubuntu bootstrap backend"),
    DebianDevTool("ruff", "ruff", "lint", "Fast Python lint and import sorting"),
    DebianDevTool("black", "black", "lint", "Python formatting compatibility check"),
    DebianDevTool("mypy", "mypy", "lint", "Python static type checking"),
    DebianDevTool("codespell", "codespell", "lint", "Typo checks for source and docs"),
    DebianDevTool("reuse", "reuse", "lint", "REUSE license metadata compliance"),
    DebianDevTool("pre-commit", "pre-commit", "lint", "Local hook runner"),
    DebianDevTool("shellcheck", "shellcheck", "lint", "Shell script lint"),
    DebianDevTool("desktop-file-validate", "desktop-file-utils", "lint", "Desktop entry validation"),
    DebianDevTool("appstreamcli", "appstream", "lint", "AppStream metadata validation"),
    DebianDevTool("xorriso", "xorriso", "iso", "ISO extraction and rebuild"),
    DebianDevTool("mksquashfs", "squashfs-tools", "iso", "SquashFS live filesystem creation"),
    DebianDevTool("qemu-system-x86_64", "qemu-system-x86", "iso", "QEMU ISO boot preview"),
    DebianDevTool("qemu-img", "qemu-utils", "iso", "QEMU disk image utilities"),
    DebianDevTool("lb", "live-build", "iso", "Debian live image build frontend", manual_install=True),
    DebianDevTool(
        "isolinux.bin",
        "isolinux",
        "iso",
        "BIOS bootloader payload for live media",
        check_path="/usr/lib/ISOLINUX/isolinux.bin",
    ),
    DebianDevTool("mcopy", "mtools", "iso", "FAT image manipulation for boot media"),
    DebianDevTool("genisoimage", "genisoimage", "iso", "Legacy ISO metadata tooling"),
    DebianDevTool("dput", "dput-ng", "publish", "Upload source packages to archives"),
    DebianDevTool("reprepro", "reprepro", "publish", "Manage local APT repositories"),
    DebianDevTool("aptly", "aptly", "publish", "Snapshot and publish APT repositories"),
    DebianDevTool("gpg", "gnupg2", "publish", "Signing keys and release signatures"),
    DebianDevTool("ccache", "ccache", "build", "Compiler cache for repeated native builds"),
    DebianDevTool("ld.lld", "lld", "build", "LLVM linker for native components"),
    DebianDevTool("meson", "meson", "build", "Meson native build system"),
    DebianDevTool("ninja", "ninja-build", "build", "Ninja native build executor"),
    DebianDevTool("cmake", "cmake", "build", "CMake native build system"),
    DebianDevTool("help2man", "help2man", "docs", "Generate manpages from CLI help"),
    DebianDevTool("xmlto", "xmlto", "docs", "XML documentation conversion"),
    DebianDevTool("asciidoc", "asciidoc-base", "docs", "AsciiDoc documentation conversion"),
    DebianDevTool("pandoc", "pandoc", "docs", "Documentation format conversion"),
)


def run_doctor(runner: CommandRunner) -> list[DoctorItem]:
    items: list[DoctorItem] = []
    for binary, reason in REQUIRED_TOOLS.items():
        items.append(DoctorItem(binary, runner.has_binary(binary), reason))
    for binary, reason in OPTIONAL_TOOLS.items():
        available = _has_qt_binding() if binary == "PyQt6-or-PySide6" else runner.has_binary(binary)
        items.append(DoctorItem(binary, available, f"optional: {reason}"))
    return items


def run_python_doctor() -> list[DoctorItem]:
    items = [
        DoctorItem(name, find_spec(name) is not None, reason)
        for name, reason in PYTHON_PACKAGES.items()
    ]
    items.append(
        DoctorItem(
            "PyQt6-or-PySide6",
            _has_qt_binding(),
            "optional: Qt Python bindings for DistroForge GUI",
        )
    )
    return items


def run_debian_dev_doctor(runner: CommandRunner) -> list[DebianDevDoctorItem]:
    return [
        DebianDevDoctorItem(
            binary=tool.binary,
            available=_debian_dev_tool_available(tool, runner),
            apt_package=tool.apt_package,
            group=tool.group,
            reason=tool.reason,
            manual_install=tool.manual_install,
        )
        for tool in DEBIAN_DEV_TOOLS
    ]


def python_package_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for module_name in [*PYTHON_PACKAGES, "PyQt6", "PySide6"]:
        dist_name = PYTHON_DISTRIBUTIONS.get(module_name, module_name)
        try:
            versions[module_name] = version(dist_name)
        except PackageNotFoundError:
            versions[module_name] = "-"
    versions["PyQt6-or-PySide6"] = (
        versions["PyQt6"] if versions["PyQt6"] != "-" else versions["PySide6"]
    )
    return versions


def _has_qt_binding() -> bool:
    return find_spec("PySide6") is not None or find_spec("PyQt6") is not None


def _debian_dev_tool_available(tool: DebianDevTool, runner: CommandRunner) -> bool:
    if runner.has_binary(tool.binary):
        return True
    return bool(tool.check_path and Path(tool.check_path).exists())


def missing_required(items: list[DoctorItem]) -> list[DoctorItem]:
    required = set(REQUIRED_TOOLS)
    return [item for item in items if item.binary in required and not item.available]


def install_packages_for(items: list[DoctorItem], include_optional: bool = False) -> list[str]:
    selected = [
        item
        for item in items
        if not item.available and (include_optional or item.binary in REQUIRED_TOOLS)
    ]
    packages = {APT_PACKAGES[item.binary] for item in selected if item.binary in APT_PACKAGES}
    return sorted(packages)


def install_packages_for_debian_dev(items: list[DebianDevDoctorItem], *, include_manual: bool = False) -> list[str]:
    packages = {
        item.apt_package
        for item in items
        if not item.available and (include_manual or not item.manual_install)
    }
    return sorted(packages)


def manual_install_packages_for_debian_dev(items: list[DebianDevDoctorItem]) -> list[str]:
    return sorted({item.apt_package for item in items if not item.available and item.manual_install})


def apt_install_command(packages: list[str]) -> str:
    if not packages:
        return ""
    return "sudo apt update && sudo apt install -y " + " ".join(packages)


def install_missing(
    runner: CommandRunner,
    items: list[DoctorItem],
    include_optional: bool = False,
    use_sudo: bool = True,
) -> None:
    packages = install_packages_for(items, include_optional=include_optional)
    if not packages:
        return
    runner.run(
        CommandSpec(
            argv=sudo(("apt-get", "update"), use_sudo),
            needs_root=use_sudo,
            description="Update apt package index before installing DistroForge dependencies",
        )
    )
    runner.run(
        CommandSpec(
            argv=sudo(("apt-get", "install", "-y", *packages), use_sudo),
            needs_root=use_sudo,
            description="Install missing DistroForge host dependencies",
        )
    )


def install_debian_dev_missing(
    runner: CommandRunner,
    items: list[DebianDevDoctorItem],
    *,
    include_manual: bool = False,
    use_sudo: bool = True,
) -> None:
    packages = install_packages_for_debian_dev(items, include_manual=include_manual)
    if not packages:
        return
    runner.run(
        CommandSpec(
            argv=sudo(("apt-get", "update"), use_sudo),
            needs_root=use_sudo,
            description="Update apt package index before installing Debian/Ubuntu maintainer tooling",
        )
    )
    runner.run(
        CommandSpec(
            argv=sudo(("apt-get", "install", "--no-remove", "-y", *packages), use_sudo),
            needs_root=use_sudo,
            description="Install missing Debian/Ubuntu maintainer tooling",
        )
    )
