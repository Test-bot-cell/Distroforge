from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CommandGuiMapping:
    command: str
    label: str
    gui_surface: str
    progress_required: bool = False


@dataclass(frozen=True)
class OptionGuiException:
    option: str
    reason: str


CLI_GUI_COMMANDS: tuple[CommandGuiMapping, ...] = (
    CommandGuiMapping("releases", "List known Ubuntu releases", "Command Center"),
    CommandGuiMapping("profiles", "List built-in remix profiles", "Packages page"),
    CommandGuiMapping("derivative-profiles", "List derivative distro profiles", "Packages page"),
    CommandGuiMapping("derivative-profile", "Plan/export derivative distro profile", "Packages page"),
    CommandGuiMapping("profile", "Create/apply/diff distro profiles", "Packages page", True),
    CommandGuiMapping("personas", "List workflow personas", "Packages page"),
    CommandGuiMapping("desktops", "List desktop targets", "Desktop & Identity page"),
    CommandGuiMapping("source-starters", "List source starters", "Source page"),
    CommandGuiMapping("branding-palettes", "List branding palettes", "Desktop & Identity page"),
    CommandGuiMapping("mirrors", "Diagnose and manage APT mirrors", "Source page", True),
    CommandGuiMapping("branding", "Audit branding compliance and clearance", "Quality Lab page", True),
    CommandGuiMapping("debrand", "Scan and apply source debranding", "Quality Lab page", True),
    CommandGuiMapping("frameworks", "Show framework status", "Command Center"),
    CommandGuiMapping("doctor", "Check host/Python dependencies", "Toolbar Doctor", True),
    CommandGuiMapping("host", "Show host build capabilities", "Command Center"),
    CommandGuiMapping("chroot-backends", "Show maintainer chroot backend availability", "Maintainer page"),
    CommandGuiMapping("presets", "List/export presets", "Presets page"),
    CommandGuiMapping("compat", "Check release compatibility", "Command Center", True),
    CommandGuiMapping("ci", "Run CI checks", "Build & Release page", True),
    CommandGuiMapping("iso-toolchain", "Check or install ISO build host tools", "Build & Release page", True),
    CommandGuiMapping("iso-doctor", "Diagnose next ISO build step", "Build & Release page"),
    CommandGuiMapping("iso-build", "Run guarded one-command ISO build path", "Build & Release page", True),
    CommandGuiMapping("iso-accept", "Accept or block a produced ISO for publication", "Build & Release page", True),
    CommandGuiMapping("demo-iso", "Create and run a minimal demo ISO path", "Build & Release page", True),
    CommandGuiMapping("artifact-paths", "Show host artifact paths", "Artifacts page"),
    CommandGuiMapping("release-readiness", "Summarize release readiness", "Artifacts page", True),
    CommandGuiMapping("evidence-status", "Summarize maintainer evidence without building", "Maintainer page"),
    CommandGuiMapping("evidence-verify", "Validate an evidence bundle contract", "Artifacts page"),
    CommandGuiMapping("release-gate", "Check maintainer release publication gate", "Artifacts page", True),
    CommandGuiMapping("publish-bundle", "Create maintainer publish inspection bundle", "Artifacts page", True),
    CommandGuiMapping("sign-release", "Generate manifest and sign publish bundle", "Artifacts page", True),
    CommandGuiMapping("release-notes", "Write maintainer release notes and changelog", "Artifacts page", True),
    CommandGuiMapping("verify-release", "Verify maintainer publish bundle", "Artifacts page", True),
    CommandGuiMapping("explain-release", "Explain maintainer release evidence", "Artifacts page", True),
    CommandGuiMapping("publish-drill", "Run safe maintainer publish drill", "Artifacts page", True),
    CommandGuiMapping("publish-drill-diff", "Compare publish drill reports", "Artifacts page", True),
    CommandGuiMapping("publish-drill-baseline", "Promote publish drill baseline", "Artifacts page", True),
    CommandGuiMapping("release-pipeline", "Run maintainer release publish pipeline", "Artifacts page", True),
    CommandGuiMapping("boot-proof", "Run or plan normalized ISO boot proof", "Artifacts page", True),
    CommandGuiMapping("qemu-smoke-plan", "Plan QEMU install smoke matrix", "Artifacts page"),
    CommandGuiMapping("preview", "Launch or plan interactive ISO preview", "Virtualization page", True),
    CommandGuiMapping("qemu-interaction", "Plan or run declarative QMP-driven ISO interaction", "Virtualization page", True),
    CommandGuiMapping("buildinfo-report", "Inspect Debian buildinfo taint", "Artifacts page"),
    CommandGuiMapping("packaging-policy", "Inspect packaging release policy", "Artifacts page"),
    CommandGuiMapping("debian-package", "Build Debian package and maintainer checks", "Artifacts page", True),
    CommandGuiMapping("autopkgtest-doctor", "Diagnose autopkgtest run/testbed failures", "Artifacts page", True),
    CommandGuiMapping("hermetic-build-plan", "Plan hermetic Debian package build", "Artifacts page"),
    CommandGuiMapping("hermetic-release-bundle", "Create hermetic local package release bundle", "Artifacts page", True),
    CommandGuiMapping("restore-snapshot", "Restore rollback snapshot", "Command Center", True),
    CommandGuiMapping("autoinstall-templates", "Render autoinstall templates", "Advanced Modules page"),
    CommandGuiMapping("plugins", "List local plugins", "Extensions page"),
    CommandGuiMapping("secureboot-assist", "Plan Secure Boot MOK workflow", "Quality Lab page", True),
    CommandGuiMapping("init-definition", "Write an example definition", "Presets page"),
    CommandGuiMapping("recipe", "Suggest a definition from prompt", "Presets page"),
    CommandGuiMapping("explain", "Explain build", "Toolbar Explain"),
    CommandGuiMapping("ux-audit", "Audit CLI/GUI parity", "Quality Lab page", True),
    CommandGuiMapping("readiness", "Show build readiness", "Quality Lab page", True),
    CommandGuiMapping("journey", "Show guided distro build journey", "Command Center"),
    CommandGuiMapping("beginner-iso", "Prepare a safe beginner source-to-ISO path", "Start page", True),
    CommandGuiMapping("poweruser-iso", "Prepare guarded advanced source-to-ISO path", "Start page", True),
    CommandGuiMapping("dry-run-report", "Render structured dry-run", "Build & Release page", True),
    CommandGuiMapping("explain-risk", "Explain risky options", "Quality Lab page"),
    CommandGuiMapping("glossary", "Explain ISO build terms", "First Run / docs"),
    CommandGuiMapping("build-phases", "Show build phase contracts", "Command Center"),
    CommandGuiMapping("guided-recipe", "List guided recipes", "Presets page"),
    CommandGuiMapping("ai-review", "Review current plan", "Maintainer page"),
    CommandGuiMapping("forgeadvisor", "Explain logs and build findings", "Maintainer page"),
    CommandGuiMapping("export-recipe", "Export project recipe", "Presets page"),
    CommandGuiMapping("export-build-preset", "Export build preset", "Presets page"),
    CommandGuiMapping("capture", "Capture installed system intent", "Capture & Images page", True),
    CommandGuiMapping("capture-diff", "Review captured profile diff", "Capture & Images page"),
    CommandGuiMapping("rebuild-from-capture", "Create project from captured profile", "Capture & Images page", True),
    CommandGuiMapping("live-build-plan", "Plan Debian live-build config", "Capture & Images page"),
    CommandGuiMapping("livefs-iso-plan", "Plan Ubuntu livefs ISO pipeline", "Capture & Images page"),
    CommandGuiMapping("livefs-iso-build", "Write livefs ISO workspace", "Capture & Images page", True),
    CommandGuiMapping("upgrade-media", "Run upgrade media preflight", "Capture & Images page", True),
    CommandGuiMapping("image-plan", "Plan OEM/systemd image workflow", "Capture & Images page"),
    CommandGuiMapping("new", "Create project", "Start page"),
    CommandGuiMapping("plan", "Show build plan", "Toolbar Plan"),
    CommandGuiMapping("validate", "Validate project and host", "Build & Release page", True),
    CommandGuiMapping("build", "Run or dry-run build", "Build & Release page", True),
    CommandGuiMapping("gui", "Launch Qt UI", "Application entrypoint"),
)


CLI_GUI_OPTION_EXCEPTIONS: tuple[OptionGuiException, ...] = (
    OptionGuiException("--help", "argparse-generated help"),
    OptionGuiException("--definition", "covered by import build preset"),
    OptionGuiException("--execute", "covered by explicit Execute confirmation"),
    OptionGuiException("--ci", "covered by CI mode checkbox"),
    OptionGuiException("--privilege", "covered by sudo/pkexec controls"),
)

CLI_GUI_OPTION_ALIASES: dict[str, tuple[str, ...]] = {
    "--desktop-source-no-install-debs": ("desktop_source_install_debs_check",),
    "--kernel-no-install-debs": ("kernel_install_debs_check",),
    "--no-html-report": ("html_report_check",),
    "--no-kernel-pgp": ("kernel_verify_pgp_check",),
    "--no-prune-obsolete-packages": ("prune_packages_check",),
    "--no-release-artifacts": ("release_artifacts_check",),
    "--no-sanitize": ("sanitize_check",),
    "--no-sudo": ("sudo_check",),
    "--ppa-no-auto-key": ("ppa_auto_key_check",),
    "--mirror-allow-http": ("mirror_allow_http_check",),
    "--mirror-override-ubuntu-security": ("mirror_override_security_check",),
    "--prebuild-vm-no-screenshot": ("prebuild_vm_screenshot_check",),
    "--require-source-iso-checksum": ("require_source_checksum_check",),
    "--require-source-iso-signature": ("require_source_signature_check",),
    "--system-sync-no-fallback": ("system_sync_fallback_check",),
    "--system-sync-no-post-install-tool": ("system_sync_post_install_tool_check",),
}


def command_names() -> tuple[str, ...]:
    return tuple(command.command for command in CLI_GUI_COMMANDS)


def gui_parity_report() -> str:
    lines = ["CLI command -> GUI surface"]
    for command in CLI_GUI_COMMANDS:
        progress = "progressbar" if command.progress_required else "status"
        lines.append(f"{command.command:22} {command.gui_surface:24} {progress}")
    return "\n".join(lines)


def commands_requiring_progress() -> tuple[str, ...]:
    return tuple(command.command for command in CLI_GUI_COMMANDS if command.progress_required)


def gui_option_parity_report(options: dict[str, str], gui_source: str) -> str:
    exceptions = {item.option: item.reason for item in CLI_GUI_OPTION_EXCEPTIONS}
    missing: list[str] = []
    lines = ["Build option -> GUI coverage"]
    for option, dest in sorted(options.items()):
        if option in exceptions:
            lines.append(f"{option:34} exception: {exceptions[option]}")
            continue
        token = dest.replace("-", "_")
        aliases = CLI_GUI_OPTION_ALIASES.get(option, ())
        matched = token if token in gui_source else next((alias for alias in aliases if alias in gui_source), "")
        if matched:
            lines.append(f"{option:34} widget:{matched}")
        else:
            missing.append(option)
            lines.append(f"{option:34} MISSING")
    if missing:
        lines.append("")
        lines.append("Missing options: " + ", ".join(missing))
    return "\n".join(lines)
