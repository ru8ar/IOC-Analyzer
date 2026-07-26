from PySide6.QtCore import Qt
from services.detector_service import IOCDetector
from services.validator_service import IOCValidator

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

        self.results = QTextEdit()
        self.results.setReadOnly(True)

        layout.addWidget(title)
        layout.addWidget(self.ioc_input)
        layout.addWidget(self.scan_button)
        layout.addLayout(file_layout)
        layout.addWidget(self.progress)
        layout.addWidget(self.results)

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
            self.results.setPlainText("Please enter an IOC.")
            return

        ioc_type = IOCDetector.detect(value)

        validation = IOCValidator.validate(value, ioc_type)

        result_text = (
            f"IOC           : {value}\n"
            f"Type          : {ioc_type.value}\n"
            f"Valid         : {validation.is_valid}\n"
            f"Message       : {validation.message}"
        )

        self.results.setPlainText(result_text)