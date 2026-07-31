from PySide6.QtCore import Qt
from services.detector_service import IOCDetector
from services.validator_service import IOCValidator
from PySide6.QtWidgets import QFormLayout
from PySide6.QtWidgets import QGroupBox
from gui.widgets import ResultField

from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QHBoxLayout,
    QProgressBar,
)


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Threat Intelligence IOC Scanner")
        self.resize(850, 650)

        self.setup_ui()

    def setup_ui(self):

        central = QWidget()

        self.setCentralWidget(central)

        layout = QVBoxLayout()

        title = QLabel("Threat Intelligence IOC Scanner")
        title.setAlignment(Qt.AlignCenter)

        self.ioc_input = QLineEdit()
        self.ioc_input.setPlaceholderText(
            "Enter IP, Domain, URL or Hash..."
        )

        self.scan_button = QPushButton("Scan IOC")

        file_layout = QHBoxLayout()

        self.file_label = QLabel("No file selected")

        self.file_button = QPushButton("Choose File")
    

        file_layout.addWidget(self.file_button)
        file_layout.addWidget(self.file_label)

        self.progress = QProgressBar()
        self.progress.setValue(0)

        result_layout = QFormLayout()

        self.ioc_field = ResultField("IOC")
        self.type_field = ResultField("Type")
        self.validation_field = ResultField("Validation")
        self.message_field = ResultField("Status")

        result_layout.addRow(self.ioc_field)
        result_layout.addRow(self.type_field)
        result_layout.addRow(self.validation_field)
        result_layout.addRow(self.message_field)

        result_group = QGroupBox("Result")
        result_group.setLayout(result_layout)

        layout.addWidget(title)
        layout.addWidget(self.ioc_input)
        layout.addWidget(self.scan_button)
        layout.addLayout(file_layout)
        layout.addWidget(self.progress)
        layout.addWidget(result_group)


        

        central.setLayout(layout)

        self.file_button.clicked.connect(self.choose_file)
        self.scan_button.clicked.connect(
                    self.detect_ioc
                )

    def choose_file(self):

        filename, _ = QFileDialog.getOpenFileName(self)

        if filename:
            self.file_label.setText(filename)

    def detect_ioc(self):

        value = self.ioc_input.text().strip()

        if not value:
            return

        ioc_type = IOCDetector.detect(value)

        validation = IOCValidator.validate(
            value,
            ioc_type
        )

        self.ioc_field.set_value(value)
        self.type_field.set_value(ioc_type.value)

        if validation.is_valid:
            self.validation_field.set_value("✅ Valid")
        else:
            self.validation_field.set_value("❌ Invalid")

        self.message_field.set_value(validation.message)