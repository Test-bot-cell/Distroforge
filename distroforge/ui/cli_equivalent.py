from __future__ import annotations

from typing import Protocol

from distroforge.core.project import Project


class CliEquivalentWindow(Protocol):
    project: Project | None

    def _sync_project_from_ui(self) -> None: ...


def build_cli_equivalent(window: CliEquivalentWindow) -> str:
    if not window.project:
        return "distroforge new NAME PATH"
    window._sync_project_from_ui()
    assert window.project
    args = ["distroforge", "build", str(window.project.root)]
    if window.project.source_iso:
        args.extend(["--source-iso", str(window.project.source_iso)])
    if window.project.source_mode == "bootstrap":
        args.append("--from-scratch")
    for package in _split_packages(window.install_edit.toPlainText()):
        args.extend(["--install", package])
    for package in _split_packages(window.remove_edit.toPlainText()):
        args.extend(["--remove", package])
    desktop = window.desktop_combo.currentData()
    if desktop:
        args.extend(["--desktop", str(desktop)])
    if window.source_iso_sha256_edit.text().strip():
        args.extend(["--source-iso-sha256", window.source_iso_sha256_edit.text().strip()])
    if window.source_iso_signature_edit.text().strip():
        args.extend(["--source-iso-signature", window.source_iso_signature_edit.text().strip()])
    if window.source_iso_gpg_fingerprint_edit.text().strip():
        args.extend(
            ["--source-iso-gpg-fingerprint", window.source_iso_gpg_fingerprint_edit.text().strip()]
        )
    if window.require_source_checksum_check.isChecked():
        args.append("--require-source-iso-checksum")
    if window.require_source_signature_check.isChecked():
        args.append("--require-source-iso-signature")
    if window.mirrors_check.isChecked():
        args.append("--mirrors")
    if window.mirror_archive_edit.text().strip():
        args.extend(["--mirror-archive", window.mirror_archive_edit.text().strip()])
    if window.mirror_security_edit.text().strip():
        args.extend(["--mirror-security", window.mirror_security_edit.text().strip()])
    if window.mirror_country_edit.text().strip():
        args.extend(["--mirror-country", window.mirror_country_edit.text().strip()])
    if window.mirror_allow_http_check.isChecked():
        args.append("--mirror-allow-http")
    if window.mirror_override_security_check.isChecked():
        args.append("--mirror-override-ubuntu-security")
    if window.policy_strict_check.isChecked():
        args.append("--policy-strict")
    args.extend(["--brand-compliance-mode", str(window.brand_compliance_mode_combo.currentData())])
    return " ".join(_shell_quote(part) for part in args)


def _split_packages(text: str) -> list[str]:
    packages: list[str] = []
    for raw_line in text.replace(",", "\n").splitlines():
        item = raw_line.strip()
        if item and not item.startswith("#"):
            packages.append(item)
    return packages


def _shell_quote(value: str) -> str:
    if not value or any(char.isspace() for char in value):
        return "'" + value.replace("'", "'\"'\"'") + "'"
    return value
