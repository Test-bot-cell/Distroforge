from __future__ import annotations

from distroforge.core.build import BuildPhase
from distroforge.ui.qt import QApplication, QIcon, QStyle

# Logical icon vocabulary -> freedesktop "symbolic" icon name. The GUI defers to
# the active desktop icon theme (Adwaita on GNOME) instead of bundling a private
# set, so every glyph matches what the user's distro ships -- one source of
# truth -- and the symbols recolor with the theme.
_THEME_NAMES: dict[str, str] = {
    "archive": "package-x-generic-symbolic",
    "badge": "emblem-important-symbolic",
    "box": "package-x-generic-symbolic",
    "chart": "view-paged-symbolic",
    "check-circle": "object-select-symbolic",
    "circle": "media-record-symbolic",
    "code": "applications-engineering-symbolic",
    "cpu": "applications-utilities-symbolic",
    "database": "drive-harddisk-symbolic",
    "diff": "edit-find-replace-symbolic",
    "disc": "media-optical-symbolic",
    "eraser": "edit-clear-symbolic",
    "eye": "view-reveal-symbolic",
    "factory": "applications-engineering-symbolic",
    "file-check": "object-select-symbolic",
    "file-code": "accessories-text-editor-symbolic",
    "file-text": "text-x-generic-symbolic",
    "folder": "folder-symbolic",
    "git-branch": "media-playlist-shuffle-symbolic",
    "hash": "view-more-symbolic",
    "heart-pulse": "dialog-information-symbolic",
    "image": "image-x-generic-symbolic",
    "key": "dialog-password-symbolic",
    "list": "view-list-symbolic",
    "lock": "changes-prevent-symbolic",
    "monitor": "video-display-symbolic",
    "monitor-check": "computer-symbolic",
    "network": "network-workgroup-symbolic",
    "package": "package-x-generic-symbolic",
    "refresh": "view-refresh-symbolic",
    "repeat": "media-playlist-repeat-symbolic",
    "scroll": "text-x-generic-symbolic",
    "server": "network-server-symbolic",
    "settings": "emblem-system-symbolic",
    "shield-check": "security-high-symbolic",
    "sliders": "applications-system-symbolic",
    "snapshot": "camera-photo-symbolic",
    "terminal": "utilities-terminal-symbolic",
    "test-tube": "applications-science-symbolic",
    "users": "system-users-symbolic",
    # Toolbar / button action verbs, resolved through the same symbolic theme
    # so every glyph in the window comes from one source of truth.
    "new": "document-new-symbolic",
    "open": "document-open-symbolic",
    "home": "go-home-symbolic",
    "save": "document-save-symbolic",
    "doctor": "dialog-information-symbolic",
    "help": "help-browser-symbolic",
    "plan": "view-list-symbolic",
    "explain": "accessories-text-editor-symbolic",
    "audit": "dialog-warning-symbolic",
    "dry": "media-playback-start-symbolic",
    "cancel": "process-stop-symbolic",
    "start": "media-playback-start-symbolic",
    "stop": "media-playback-stop-symbolic",
    "clear": "edit-clear-symbolic",
}

_FALLBACK = "circle"

# When the desktop icon theme cannot supply a glyph (no Qt SVG icon engine, or
# the Adwaita theme is absent), action verbs degrade to the nearest built-in Qt
# standard pixmap rather than a generic file icon.
_STANDARD_FALLBACK: dict[str, QStyle.StandardPixmap] = {
    "new": QStyle.StandardPixmap.SP_FileDialogNewFolder,
    "open": QStyle.StandardPixmap.SP_DialogOpenButton,
    "home": QStyle.StandardPixmap.SP_DirHomeIcon,
    "save": QStyle.StandardPixmap.SP_DialogSaveButton,
    "doctor": QStyle.StandardPixmap.SP_MessageBoxInformation,
    "help": QStyle.StandardPixmap.SP_DialogHelpButton,
    "plan": QStyle.StandardPixmap.SP_FileDialogDetailedView,
    "explain": QStyle.StandardPixmap.SP_FileIcon,
    "audit": QStyle.StandardPixmap.SP_MessageBoxWarning,
    "dry": QStyle.StandardPixmap.SP_MediaPlay,
    "cancel": QStyle.StandardPixmap.SP_DialogCancelButton,
    "start": QStyle.StandardPixmap.SP_MediaPlay,
    "stop": QStyle.StandardPixmap.SP_MediaStop,
    "clear": QStyle.StandardPixmap.SP_DialogResetButton,
}

_PHASE_ICONS: dict[BuildPhase, str] = {
    BuildPhase.VALIDATE: "shield-check",
    BuildPhase.CONSISTENCY: "shield-check",
    BuildPhase.POLICY: "lock",
    BuildPhase.COMPATIBILITY: "check-circle",
    BuildPhase.IMPORT_SCRIPTS: "file-code",
    BuildPhase.DIFF_PREVIEW: "diff",
    BuildPhase.PREPARE: "folder",
    BuildPhase.BOOTSTRAP_ROOTFS: "box",
    BuildPhase.EXTRACT_ISO: "archive",
    BuildPhase.UNPACK_FILESYSTEM: "archive",
    BuildPhase.CONFIGURE_APT: "server",
    BuildPhase.APT_CACHE: "database",
    BuildPhase.PPA: "key",
    BuildPhase.RELEASE_TRACK: "git-branch",
    BuildPhase.SYSTEM_SYNC: "refresh",
    BuildPhase.AUTODRIVERS: "cpu",
    BuildPhase.APPLY_PACKAGES: "package",
    BuildPhase.DESKTOP_SOURCE: "code",
    BuildPhase.INSTALL_SNAPS: "package",
    BuildPhase.SIZE_ANALYSIS: "chart",
    BuildPhase.VULN_SCAN: "shield-check",
    BuildPhase.CUSTOMIZE_SYSTEM: "sliders",
    BuildPhase.BRANDING: "badge",
    BuildPhase.USERS: "users",
    BuildPhase.SYSTEMD: "settings",
    BuildPhase.NETWORK: "network",
    BuildPhase.KIOSK: "monitor",
    BuildPhase.OEM: "factory",
    BuildPhase.KERNEL_MODULE: "cpu",
    BuildPhase.SECURE_BOOT: "lock",
    BuildPhase.REPRODUCIBLE: "repeat",
    BuildPhase.SNAPSHOT: "snapshot",
    BuildPhase.RUN_HOOKS: "terminal",
    BuildPhase.SANITIZE_TARGET: "eraser",
    BuildPhase.HEALTH: "heart-pulse",
    BuildPhase.AUTOINSTALL: "file-check",
    BuildPhase.SEEDS: "list",
    BuildPhase.UPDATE_METADATA: "file-check",
    BuildPhase.REPACK_FILESYSTEM: "box",
    BuildPhase.UPDATE_CHECKSUMS: "hash",
    BuildPhase.REBUILD_ISO: "disc",
    BuildPhase.PREBUILD_VM: "monitor-check",
    BuildPhase.RELEASE_ARTIFACTS: "file-check",
    BuildPhase.BOOTCHECK: "monitor-check",
    BuildPhase.QEMU_SCREENSHOT: "image",
    BuildPhase.PROVENANCE: "scroll",
    BuildPhase.HTML_REPORT: "file-text",
    BuildPhase.QA_MATRIX: "test-tube",
    BuildPhase.PREVIEW: "eye",
}

_COMMAND_ICONS = {
    "mirrors": "server",
    "branding": "badge",
    "debrand": "eraser",
    "profile": "sliders",
    "build": "disc",
    "doctor": "heart-pulse",
}


class IconRegistry:
    def icon(self, name: str) -> QIcon:
        theme_name = _THEME_NAMES.get(name) or _THEME_NAMES[_FALLBACK]
        themed = QIcon.fromTheme(theme_name)
        if not themed.isNull():
            return themed
        fallback = _STANDARD_FALLBACK.get(name, QStyle.StandardPixmap.SP_FileIcon)
        return QApplication.style().standardIcon(fallback)

    def phase_icon(self, phase: BuildPhase | str) -> QIcon:
        value = phase if isinstance(phase, BuildPhase) else BuildPhase(str(phase))
        return self.icon(_PHASE_ICONS.get(value, _FALLBACK))

    def command_icon(self, command: str) -> QIcon:
        return self.icon(_COMMAND_ICONS.get(command, _FALLBACK))


_REGISTRY = IconRegistry()


def icon(name: str) -> QIcon:
    return _REGISTRY.icon(name)


def phase_icon(phase: BuildPhase | str) -> QIcon:
    return _REGISTRY.phase_icon(phase)


def command_icon(command: str) -> QIcon:
    return _REGISTRY.command_icon(command)
