from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QWidget, QHBoxLayout


class ResultField(QWidget):
    """
    Displays a title-value pair.

    Example

    IOC          google.com
    """

    def __init__(self, title: str):
        super().__init__()

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)

        self.title_label = QLabel(title)
        self.title_label.setMinimumWidth(120)

        self.value_label = QLabel("-")
        self.value_label.setAlignment(Qt.AlignLeft)

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addStretch()

    def set_value(self, value: str):
        self.value_label.setText(value)

    def clear(self):
        self.value_label.setText("-")