from __future__ import annotations

import hashlib
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from .capture_report import CaptureReport
from .capture_sanitize import ConfigCapturePolicy, classify_config_with_policy
from .capture_schema import CapturedSystemProfile
from .capture_sources import capture_apt_sources


class InstalledSystemCaptureService:
    def capture(
        self,
        target: Path,
        sanitize: str = "strict",
        include_configs: list[Path] | None = None,
        include_config_globs: list[str] | None = None,
    ) -> CapturedSystemProfile:
        root = target.resolve()
        report = CaptureReport()
        include_values = [str(path) for path in include_configs or []]
        include_globs = include_config_globs or []
        os_release = _read_os_release(root)
        release = os_release.get("VERSION_ID", "26.04").strip('"')
        codename = os_release.get("VERSION_CODENAME") or os_release.get("UBUNTU_CODENAME")
        family = _family(os_release)
        name = os_release.get("PRETTY_NAME", root.name if str(root) != "/" else "installed-system")

        packages = _manual_packages(root, report)
        repositories, source_findings = capture_apt_sources(root)
        report.extend(source_findings)
        customization = {
            "hostname": _read_first(root / "etc/hostname"),
            "locale": _read_locale(root),
            "timezone": _read_first(root / "etc/timezone"),
            "keyboard_layout": _read_keyboard(root),
            "display_manager": _read_display_manager(root),
        }
        customization = {key: value for key, value in customization.items() if value}
        services = _service_state(root, report)
        configs, config_files = _capture_configs(root, include_configs or [], include_globs, report)
        drivers = _driver_hints(root, packages)

        report.add("home", "/home", "ignored", "Home directories are never captured by default")
        report.add("secrets", "/etc/shadow", "dangerous", "Password hashes are excluded")
        report.add("machine-id", "/etc/machine-id", "dangerous", "Machine identity is excluded")
        report.add("logs", "/var/log", "ignored", "Logs are excluded")

        definition: dict[str, object] = {
            "schema": "distroforge.preset.v1",
            "metadata": {
                "name": f"Captured {name}",
                "kind": "captured-system-profile",
                "release": release,
                "family": family,
                "codename": codename,
                "architecture": platform.machine(),
                "generated_by": "DistroForge capture",
                "created_at": datetime.now(UTC).isoformat(),
            },
            "source_mode": "bootstrap",
            "packages": packages,
            "repositories": repositories,
            "customization": customization,
            "systemd": services,
            "drivers": drivers,
            "sanitize": _sanitize_options(sanitize),
            "capture_configs": configs,
            "capture_config_files": config_files,
        }
        return CapturedSystemProfile(definition, report, root, sanitize, include_values, include_globs)


def _read_os_release(root: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    for path in (root / "etc/os-release", root / "usr/lib/os-release"):
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                data[key] = value.strip().strip('"')
        break
    return data


def _family(os_release: dict[str, str]) -> str:
    values = " ".join(
        [os_release.get("ID", ""), os_release.get("ID_LIKE", ""), os_release.get("NAME", "")]
    ).lower()
    if "debian" in values and "ubuntu" not in values:
        return "debian"
    return "ubuntu"


def _manual_packages(root: Path, report: CaptureReport) -> list[str]:
    if root == Path("/"):
        result = _run(("apt-mark", "showmanual"))
        if result.returncode == 0:
            packages = sorted(line.strip() for line in result.stdout.splitlines() if line.strip())
            report.add("packages", "apt-mark showmanual", "captured", f"{len(packages)} manual packages")
            return packages
        report.add("packages", "apt-mark showmanual", "needs review", result.stderr.strip())
    status = root / "var/lib/dpkg/status"
    if not status.exists():
        report.add("packages", "/var/lib/dpkg/status", "not reproducible", "No dpkg status found")
        return []
    packages: list[str] = []
    current: dict[str, str] = {}
    for line in status.read_text(encoding="utf-8", errors="replace").splitlines() + [""]:
        if not line:
            if current.get("Status") == "install ok installed" and current.get("Package"):
                packages.append(current["Package"])
            current = {}
            continue
        if ": " in line:
            key, value = line.split(": ", 1)
            current[key] = value
    packages = sorted(set(packages))
    report.add("packages", "/var/lib/dpkg/status", "needs review", "Manual package intent unavailable offline")
    return packages


def _read_first(path: Path) -> str | None:
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = line.strip()
        if value:
            return value
    return None


def _read_locale(root: Path) -> str | None:
    path = root / "etc/default/locale"
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("LANG="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def _read_keyboard(root: Path) -> str | None:
    path = root / "etc/default/keyboard"
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("XKBLAYOUT="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def _read_display_manager(root: Path) -> str | None:
    value = _read_first(root / "etc/X11/default-display-manager")
    if not value:
        return None
    return Path(value).name


def _service_state(root: Path, report: CaptureReport) -> dict[str, list[str]]:
    if root == Path("/"):
        result = _run(("systemctl", "list-unit-files", "--type=service", "--state=enabled,disabled", "--no-legend"))
        if result.returncode == 0:
            enable: list[str] = []
            disable: list[str] = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    if parts[1] == "enabled":
                        enable.append(parts[0])
                    elif parts[1] == "disabled":
                        disable.append(parts[0])
            report.add("services", "systemctl", "captured", f"{len(enable)} enabled services")
            return {"enable": sorted(enable), "disable": sorted(disable), "mask": []}
    wants = root / "etc/systemd/system/multi-user.target.wants"
    enable = sorted(path.name for path in wants.glob("*.service")) if wants.exists() else []
    report.add("services", "/etc/systemd", "needs review", "Offline service scan is approximate")
    return {"enable": enable, "disable": [], "mask": []}


def _capture_configs(
    root: Path,
    include_configs: list[Path],
    include_globs: list[str],
    report: CaptureReport,
) -> tuple[list[str], list[dict[str, object]]]:
    captured: list[str] = []
    files: list[dict[str, object]] = []
    paths = _expand_config_paths(root, include_configs, include_globs)
    whitelist = [str(path) for path in include_configs] + include_globs
    policy = ConfigCapturePolicy.from_user_paths(whitelist)
    for path in paths:
        finding = classify_config_with_policy(_target_path(root, path), root, policy)
        report.add(finding.category, finding.path, finding.status, finding.message)
        if finding.status == "captured":
            captured.append(finding.path)
            file_data = _config_file_data(_target_path(root, path), root)
            if file_data:
                files.append(file_data)
    for relative in ("etc/default/locale", "etc/default/keyboard", "etc/timezone", "etc/hostname"):
        path = root / relative
        if path.exists():
            finding = classify_config_with_policy(path, root, policy)
            report.add(finding.category, finding.path, finding.status, finding.message)
            if finding.status == "captured":
                captured.append(finding.path)
                file_data = _config_file_data(path, root)
                if file_data:
                    files.append(file_data)
    unique_files = {str(item["path"]): item for item in files}
    return sorted(set(captured)), [unique_files[key] for key in sorted(unique_files)]


def _expand_config_paths(root: Path, include_configs: list[Path], include_globs: list[str]) -> list[Path]:
    paths: list[Path] = []
    for path in include_configs:
        target = _target_path(root, path)
        if target.is_dir():
            paths.extend(sorted(item for item in target.rglob("*") if item.exists()))
        else:
            paths.append(path)
    for pattern in include_globs:
        normalized = pattern.lstrip("/")
        paths.extend(sorted(root.glob(normalized)))
    return sorted(set(paths), key=str)


def _target_path(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def _config_file_data(path: Path, root: Path) -> dict[str, object] | None:
    if not path.exists() or not path.is_file() or path.is_symlink():
        return None
    data = path.read_bytes()
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    relative = "/" + str(path.relative_to(root))
    return {
        "path": relative,
        "mode": oct(path.stat().st_mode & 0o777),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "content": content,
    }


def _driver_hints(root: Path, packages: list[str]) -> dict[str, object]:
    package_set = set(packages)
    proprietary_hints = sorted(
        value for value in package_set if value.startswith(("nvidia-", "firmware-", "amd64-microcode", "intel-microcode"))
    )
    return {"auto": bool(proprietary_hints)}


def _sanitize_options(mode: str) -> dict[str, bool]:
    strict = mode == "strict"
    return {
        "apt_lists": strict,
        "logs": strict,
        "shell_history": strict,
        "machine_id": strict,
        "temp_files": strict,
        "ssh_host_keys": strict,
    }


def _run(argv: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=False)
