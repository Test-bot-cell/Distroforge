from __future__ import annotations

from collections.abc import Callable

from distroforge.ui.icons import icon as themed_icon
from distroforge.ui.qt import (
    QComboBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QIcon,
    QLabel,
    QPushButton,
    QScrollArea,
    QSize,
    QSizePolicy,
    Qt,
    QToolBar,
    QVBoxLayout,
    QWidget,
)


def button(text: str, slot: Callable[[], None], icon: str = "", primary: bool = False) -> QPushButton:
    action = QPushButton(text)
    if icon:
        action.setIcon(standard_icon(icon))
    if primary:
        action.setObjectName("PrimaryButton")
    action.clicked.connect(slot)
    action.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
    return action


def toolbar_action(toolbar: QToolBar, text: str, slot: Callable[[], None], icon: str = "") -> None:
    action = toolbar.addAction(standard_icon(icon), text)
    if action is None:
        # Loud rather than silent: swallowing this would ship a toolbar button that
        # looks right and does nothing, which is the hardest kind of defect to notice.
        raise RuntimeError(f"Qt refused to add the toolbar action {text!r}")
    action.triggered.connect(slot)


def standard_icon(name: str):
    # One resolver for the whole window: defer to the Adwaita symbolic theme
    # (icons.icon), which itself degrades to a built-in Qt standard pixmap when
    # the theme cannot supply the glyph. Keeps the toolbar GNOME-native instead
    # of falling back to Qt's own widget-style icon set.
    if not name:
        return QIcon()
    return themed_icon(name)


class ElidingLabel(QLabel):
    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self._full_text = text
        self.setToolTip(text)

    def setText(self, text: str | None) -> None:  # noqa: N802
        # QLabel.setText accepts None to clear the label, so narrowing the parameter to
        # str broke substitutability: any code holding a QLabel could pass None and land
        # here. Normalising to "" keeps _full_text a str for _elide().
        value = text or ""
        self._full_text = value
        self.setToolTip(value)
        self._elide()

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._elide()

    def _elide(self) -> None:
        metrics = self.fontMetrics()
        width = max(24, self.contentsRect().width())
        elided = metrics.elidedText(self._full_text, Qt.TextElideMode.ElideRight, width)
        if elided != super().text():
            QLabel.setText(self, elided)


def section(title: str, *items) -> QFrame:
    frame = QFrame()
    frame.setObjectName("Section")
    frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(12, 10, 12, 12)
    layout.setSpacing(8)
    label = ElidingLabel(title)
    label.setObjectName("SectionTitle")
    label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
    layout.addWidget(label)
    for item in items:
        if isinstance(item, (QHBoxLayout, QVBoxLayout, QFormLayout)):
            layout.addLayout(item)
        else:
            layout.addWidget(item)
    return frame


class ResponsiveRow(QWidget):
    """A row that flows its children onto as many columns as actually fit.

    The number of columns is derived from the width the row is *given* and the
    natural width of its children -- never from the row's own size hint. This
    avoids the classic latch where a multi-column grid inflates the widget past
    every breakpoint (so it can never collapse) and the overflow is clipped by
    an enclosing scroll area. The row also reports a single-column minimum width
    so an enclosing QScrollArea can always shrink it to the viewport.
    """

    def __init__(self, *widgets: QWidget, breakpoint: int = 960, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._widgets = [w for w in widgets if w is not None]
        # Kept for call-site compatibility; now only a soft floor on column width.
        self._breakpoint = breakpoint
        self._columns: int | None = None
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(10)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        # Start single-column: the safe, non-inflating direction. The first
        # resizeEvent widens it to however many columns the viewport allows.
        self._relayout(0)

    def _column_width(self) -> int:
        widths = [
            max(w.sizeHint().width(), w.minimumSizeHint().width(), w.minimumWidth())
            for w in self._widgets
        ]
        return max(widths) if widths else 0

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        base = super().minimumSizeHint()
        return QSize(self._column_width(), base.height())

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._relayout(self.width())

    def _relayout(self, available: int) -> None:
        if not self._widgets:
            return
        spacing = self._grid.spacing()
        column_width = max(self._column_width(), 1)
        fit = (available + spacing) // (column_width + spacing)
        columns = max(1, min(len(self._widgets), int(fit)))
        if columns == self._columns:
            return
        self._columns = columns
        # takeAt() returning None is the documented terminator. Driving the loop from it
        # rather than from count() removes the assumption that the two agree: the old
        # form dereferenced whatever takeAt handed back, so a disagreement would have
        # been an AttributeError inside a resize handler.
        while (item := self._grid.takeAt(0)) is not None:
            widget = item.widget()
            if widget is not None:
                widget.setParent(self)
        for index, widget in enumerate(self._widgets):
            self._grid.addWidget(widget, index // columns, index % columns)
        for column in range(len(self._widgets)):
            self._grid.setColumnStretch(column, 1 if column < columns else 0)
        self.updateGeometry()


def responsive_row(*widgets: QWidget, breakpoint: int = 960) -> ResponsiveRow:
    return ResponsiveRow(*widgets, breakpoint=breakpoint)


class ReflowingCardGrid(QWidget):
    """A 1/2-column card grid that collapses to one column below a breakpoint.

    The goal hub and the journey spine each own a grid of equal cards that flows
    onto two columns when wide and one when narrow; only the breakpoint and how
    the cards are produced differ. Subclasses call :meth:`set_cards` with the
    cards they built; the grid arithmetic -- two stretched columns above the
    breakpoint, one below -- lives here once so the two surfaces cannot drift.
    """

    def __init__(self, compact_width: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._compact_width = compact_width
        self._cards: list[QWidget] = []
        self._compact: bool | None = None
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(10)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    def set_cards(self, cards: list[QWidget]) -> None:
        self._cards = cards
        self._reflow(force=True)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._reflow()

    def _reflow(self, force: bool = False) -> None:
        compact = self.width() < self._compact_width
        if not force and compact == self._compact:
            return
        self._compact = compact
        while (item := self._grid.takeAt(0)) is not None:
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
        columns = 1 if compact else 2
        for index, card in enumerate(self._cards):
            self._grid.addWidget(card, index // columns, index % columns)
        for column in range(2):
            self._grid.setColumnStretch(column, 1 if column < columns else 0)


def button_group(title: str, *items: QWidget, breakpoint: int = 720) -> QWidget:
    """A captioned cluster of related actions for use inside a section.

    Heavy pages used to pour a dozen-plus buttons into one flat row; splitting
    them into small labelled groups lets the eye find the right action without
    renaming any button or the enclosing section title.
    """
    group = QWidget()
    group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    box = QVBoxLayout(group)
    box.setContentsMargins(0, 0, 0, 0)
    box.setSpacing(6)
    caption = ElidingLabel(title)
    caption.setObjectName("GroupLabel")
    caption.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
    box.addWidget(caption)
    box.addWidget(ResponsiveRow(*items, breakpoint=breakpoint))
    return group


def responsive_form() -> QFormLayout:
    form = QFormLayout()
    form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
    form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
    form.setFormAlignment(Qt.AlignmentFlag.AlignTop)
    form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
    return form


def scroll_page(content: QWidget) -> QWidget:
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    # AsNeeded (not AlwaysOff): responsive rows now report a single-column
    # minimum so content fits the viewport, but if any single element is still
    # wider than the viewport it must stay reachable rather than be clipped.
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setWidget(content)

    wrapper = QWidget()
    layout = QVBoxLayout(wrapper)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(scroll)
    return wrapper


def stat(label: str, value: QLabel) -> QFrame:
    frame = QFrame()
    frame.setObjectName("Stat")
    frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    # The value carries an Ignored size policy, so it contributes nothing to the
    # tile's natural width; without a floor the ResponsiveRow packs equal narrow
    # columns and the wider Adwaita Sans metrics clip a value like "Ubuntu 26.04
    # skeleton". This floor keeps columns wide enough to show typical values in
    # full; an ElidingLabel value still degrades to ellipsis+tooltip below it.
    frame.setMinimumWidth(230)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(10, 8, 10, 8)
    layout.setSpacing(2)
    value.setObjectName("StatValue")
    value.setWordWrap(False)
    value.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
    caption = ElidingLabel(label)
    caption.setObjectName("StatLabel")
    caption.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
    layout.addWidget(value)
    layout.addWidget(caption)
    return frame


def set_combo_data(combo: QComboBox, value: str) -> None:
    index = combo.findData(value)
    combo.setCurrentIndex(index if index >= 0 else 0)


def tame_combo(combo: QComboBox, visible_chars: int = 16) -> None:
    """Stop a long item from dictating a huge minimum width.

    Without this a combo's minimumSizeHint grows to its widest item (e.g. a
    "label - long summary" entry), which forces the whole page wider than the
    viewport. AdjustToMinimumContentsLengthWithIcon sizes the box to a small
    visible length while the field still grows to fill available space; the
    full text remains visible in the drop-down popup.
    """
    combo.setSizeAdjustPolicy(
        QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
    )
    combo.setMinimumContentsLength(visible_chars)
    combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)


def tame_all_combos(owner: object) -> None:
    for value in list(vars(owner).values()):
        if isinstance(value, QComboBox):
            tame_combo(value)
