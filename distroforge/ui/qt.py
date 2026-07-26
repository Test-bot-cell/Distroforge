# ruff: noqa: F401
"""The single import surface for Qt, and the one place that knows two bindings exist.

The runtime prefers PySide6 and falls back to PyQt6; that has to stay, because the
developer venvs and the CI matrix run PySide6 while the .deb depends on python3-pyqt6.
What could not stay is asking mypy to read that fallback. A try/except import shim gives
every name two definitions, and mypy is asymmetric about which order it tolerates: when
the try branch resolves, the except branch redefining the same names is 35 "Incompatible
import" errors, while the reverse -- the branch mypy can resolve redefining names that
came from an unresolvable import -- is silent. So the tree was clean on a PyQt6 machine
and had 35 errors plus a long tail of stub disagreements on a PySide6 one, and the CI
Typecheck step had to be pinned to one binding to stay green.

`if TYPE_CHECKING` removes the asymmetry instead of working around it: mypy sees exactly
one definition per name -- PyQt6, the binding the package ships -- and never looks at
PySide6 at all, so the result no longer depends on which binding is installed. The
runtime `else` branch is untouched and still picks whichever is present.

The cost is stated rather than hidden: mypy now type-checks the tree against PyQt6's
signatures only, so a call PyQt6 accepts and PySide6 rejects is not a type error here.
The eight-way runtime matrix is what covers that, and tests/test_qt_shim.py keeps the
two branches from drifting apart -- nothing else would notice a name added to one and
forgotten in the other.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6.QtCore import QSize, Qt, QTimer
    from PyQt6.QtGui import QIcon, QKeySequence, QShortcut
    from PyQt6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QCompleter,
        QDialog,
        QDialogButtonBox,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QInputDialog,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMessageBox,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QScrollArea,
        QSizePolicy,
        QSplitter,
        QStackedWidget,
        QStyle,
        QToolBar,
        QVBoxLayout,
        QWidget,
    )
else:
    try:
        from PySide6.QtCore import QSize, Qt, QTimer
        from PySide6.QtGui import QIcon, QKeySequence, QShortcut
        from PySide6.QtWidgets import (
            QApplication,
            QCheckBox,
            QComboBox,
            QCompleter,
            QDialog,
            QDialogButtonBox,
            QFileDialog,
            QFormLayout,
            QFrame,
            QGridLayout,
            QHBoxLayout,
            QInputDialog,
            QLabel,
            QLineEdit,
            QListWidget,
            QListWidgetItem,
            QMainWindow,
            QMessageBox,
            QPlainTextEdit,
            QProgressBar,
            QPushButton,
            QScrollArea,
            QSizePolicy,
            QSplitter,
            QStackedWidget,
            QStyle,
            QToolBar,
            QVBoxLayout,
            QWidget,
        )
    except ImportError:
        from PyQt6.QtCore import QSize, Qt, QTimer
        from PyQt6.QtGui import QIcon, QKeySequence, QShortcut
        from PyQt6.QtWidgets import (
            QApplication,
            QCheckBox,
            QComboBox,
            QCompleter,
            QDialog,
            QDialogButtonBox,
            QFileDialog,
            QFormLayout,
            QFrame,
            QGridLayout,
            QHBoxLayout,
            QInputDialog,
            QLabel,
            QLineEdit,
            QListWidget,
            QListWidgetItem,
            QMainWindow,
            QMessageBox,
            QPlainTextEdit,
            QProgressBar,
            QPushButton,
            QScrollArea,
            QSizePolicy,
            QSplitter,
            QStackedWidget,
            QStyle,
            QToolBar,
            QVBoxLayout,
            QWidget,
        )
