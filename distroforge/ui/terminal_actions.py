from __future__ import annotations

from distroforge.commands.catalog import render_chroot_backends
from distroforge.core.chroot import ChrootService
from distroforge.core.command import CommandRunner
from distroforge.core.terminal import (
    ChrootTerminalSpec,
    LocalTerminalBackend,
    TerminalBackendUnavailable,
)


def start_terminal_action(window) -> None:
    if not window._require_project():
        return
    assert window.project
    if window.terminal_session and window.terminal_session.is_alive():
        window.terminal_view.appendPlainText("Terminal already running; stop it before starting another session.")
        return
    if not window.project.squashfs_root.exists():
        window.terminal_view.appendPlainText(
            f"Target rootfs is not prepared yet: {window.project.squashfs_root}"
        )
        return
    log_path = window.project.root / "logs" / "chroot-terminal.log"
    spec = ChrootTerminalSpec(
        window.project.squashfs_root,
        use_sudo=window.sudo_check.isChecked(),
        mount_runtime=True,
        log_path=log_path,
        backend=str(window.terminal_backend_combo.currentData() or "auto"),
    )
    backend = spec.resolved_backend()
    window.terminal_view.appendPlainText(spec.command().display())
    if backend == "nspawn":
        window.terminal_view.appendPlainText(
            "Starting maintainer shell with systemd-nspawn isolation."
        )
    else:
        window.terminal_view.appendPlainText("Mounting /dev, /dev/pts, /proc, /sys and /run for maintainer shell.")
    window.terminal_view.appendPlainText(f"Session log: {log_path}")
    try:
        window.terminal_session = LocalTerminalBackend().open(spec)
    except TerminalBackendUnavailable as exc:
        window.terminal_view.appendPlainText(str(exc))
        return
    except Exception as exc:
        window.terminal_view.appendPlainText(f"Failed to start terminal: {exc}")
        return
    window.terminal_timer.start()
    window.terminal_status.setText(f"Running {backend} pid={window.terminal_session.pid} log={log_path}")
    window.terminal_view.appendPlainText(f"Started {backend} PTY session pid={window.terminal_session.pid}")


def show_chroot_backend_status_action(window) -> None:
    selected = str(window.terminal_backend_combo.currentData() or "auto")
    window.terminal_view.setPlainText(render_chroot_backends())
    window.terminal_status.setText(f"Backend mode: {selected}")
    window._open_surface("maintainer")


def send_terminal_input_action(window) -> None:
    if not window.terminal_session or not window.terminal_session.is_alive():
        window.terminal_view.appendPlainText("No active terminal session.")
        window.terminal_session = None
        window.terminal_status.setText("Chroot terminal idle")
        return
    text = window.terminal_input.text()
    window.terminal_input.clear()
    window.terminal_session.write((text + "\n").encode("utf-8"))


def poll_terminal_action(window) -> None:
    if not window.terminal_session:
        window.terminal_timer.stop()
        return
    chunk = window.terminal_session.read()
    if chunk:
        window.terminal_view.insertPlainText(chunk.decode("utf-8", errors="replace"))
    if not window.terminal_session.is_alive():
        backend = window.terminal_session.spec.resolved_backend()
        code = window.terminal_session.returncode
        window.terminal_session.terminate()
        window.terminal_session = None
        window.terminal_timer.stop()
        window.terminal_status.setText("Chroot terminal exited")
        suffix = "" if code in (0, None) else f" (exit code {code})"
        cleanup = "runtime guard was cleaned up" if backend == "nspawn" else "runtime mounts were cleaned up"
        window.terminal_view.appendPlainText(
            f"\nTerminal exited{suffix}; {cleanup}."
        )


def stop_terminal_action(window) -> None:
    if window.terminal_session:
        window.terminal_session.terminate()
        window.terminal_session = None
    window.terminal_timer.stop()
    window.terminal_status.setText("Chroot terminal stopped")
    window.terminal_view.appendPlainText("Terminal stopped.")


def mount_terminal_runtime_action(window) -> None:
    if not window._require_project():
        return
    assert window.project
    if not window.project.squashfs_root.exists():
        window.terminal_view.appendPlainText(f"Target rootfs is not prepared yet: {window.project.squashfs_root}")
        return
    squashfs_root = window.project.squashfs_root
    use_sudo = window.sudo_check.isChecked()
    backend = str(window.terminal_backend_combo.currentData() or "auto")
    resolved = ChrootService(CommandRunner(dry_run=True), squashfs_root, use_sudo, backend=backend).resolved_backend()

    def _work():
        ChrootService(CommandRunner(dry_run=False), squashfs_root, use_sudo, backend=backend).mount_runtime()

    def _done(_):
        if resolved == "nspawn":
            window.terminal_status.setText("Runtime guard active")
            window.terminal_view.appendPlainText("Installed policy-rc.d guard for nspawn maintainer operations.")
        else:
            window.terminal_status.setText("Runtime mounts active")
            window.terminal_view.appendPlainText("Mounted /dev, /dev/pts, /proc, /sys and /run.")

    window._run_in_worker(_work, _done, "Preparing maintainer runtime…")


def unmount_terminal_runtime_action(window) -> None:
    if not window._require_project():
        return
    assert window.project
    squashfs_root = window.project.squashfs_root
    use_sudo = window.sudo_check.isChecked()
    backend = str(window.terminal_backend_combo.currentData() or "auto")
    resolved = ChrootService(CommandRunner(dry_run=True), squashfs_root, use_sudo, backend=backend).resolved_backend()

    def _work():
        ChrootService(CommandRunner(dry_run=False), squashfs_root, use_sudo, backend=backend).unmount_runtime()

    def _done(_):
        if resolved == "nspawn":
            window.terminal_status.setText("Runtime guard released")
            window.terminal_view.appendPlainText("Removed policy-rc.d guard for nspawn maintainer operations.")
        else:
            window.terminal_status.setText("Runtime mounts released")
            window.terminal_view.appendPlainText("Unmounted runtime filesystems.")

    window._run_in_worker(_work, _done, "Releasing maintainer runtime…")
