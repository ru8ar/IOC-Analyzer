from PySide6.QtCore import Qt
from services.scan_service import ScanService
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
        self.malicious_field = ResultField("Malicious")
        self.harmless_field = ResultField("Harmless")
        self.suspicious_field = ResultField("Suspicious")
        self.undetected_field = ResultField("Undetected")

        result_layout.addRow(self.ioc_field)
        result_layout.addRow(self.type_field)
        result_layout.addRow(self.validation_field)
        result_layout.addRow(self.message_field)
        result_layout.addRow(self.malicious_field)
        result_layout.addRow(self.harmless_field)
        result_layout.addRow(self.suspicious_field)
        result_layout.addRow(self.undetected_field)

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
                    self.scan_ioc
                )

    def choose_file(self):

        filename, _ = QFileDialog.getOpenFileName(self)

        if filename:
            self.file_label.setText(filename)

    def scan_ioc(self):

        value = self.ioc_input.text().strip()

        if not value:
            return

        result = ScanService.scan(value)

        self.ioc_field.set_value(result.value)

        self.type_field.set_value(result.ioc_type.value)

        if result.validation.is_valid:
            self.validation_field.set_value("✅ Valid")
        else:
            self.validation_field.set_value("❌ Invalid")

        self.message_field.set_value(result.validation.message)

        self.clear_vt_results()

        if result.vt_result and result.vt_result.success:

            self.malicious_field.set_value(
                str(result.vt_result.malicious)
            )

            self.harmless_field.set_value(
                str(result.vt_result.harmless)
            )

            self.suspicious_field.set_value(
                str(result.vt_result.suspicious)
            )

            self.undetected_field.set_value(
                str(result.vt_result.undetected)
            )
        
    def clear_vt_results(self):

        self.malicious_field.clear()
        self.harmless_field.clear()
        self.suspicious_field.clear()
        self.undetected_field.clear()