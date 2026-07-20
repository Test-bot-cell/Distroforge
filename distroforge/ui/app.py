from __future__ import annotations

import sys


def run() -> int:
    try:
        from .qt import QApplication, QIcon
    except ImportError:
        print(
            "Qt Python bindings are not installed.\n"
            "On Ubuntu, run:\n"
            "  sudo apt update\n"
            "  sudo apt install -y python3-pyqt6\n\n"
            "If you use a virtualenv instead, run:\n"
            '  pip install -e ".[gui]"',
            file=sys.stderr,
        )
        return 2

    from .main_window import MainWindow
    from .theme import apply_theme

    app = QApplication(sys.argv)
    app.setApplicationName("DistroForge")
    # Associate the window with the installed desktop entry so Wayland/X11 shells
    # show the launcher icon (hicolor "distroforge") in the window list too.
    app.setDesktopFileName("distroforge")
    app.setWindowIcon(QIcon.fromTheme("distroforge"))
    # Mirror the forced Adwaita Sans typography: pin the Adwaita icon theme so
    # functional glyphs are GNOME-native regardless of the host desktop theme.
    # Set after the launcher icon, which keeps resolving via the hicolor fallback.
    QIcon.setThemeName("Adwaita")
    apply_theme(app)
    window = MainWindow()

    screen = app.primaryScreen()
    if screen is not None:
        available = screen.availableGeometry()
        width = min(1280, max(900, int(available.width() * 0.82)))
        height = min(820, max(640, int(available.height() * 0.82)))
        window.resize(width, height)
    else:
        window.resize(1100, 720)

    window.show()
    return app.exec()
