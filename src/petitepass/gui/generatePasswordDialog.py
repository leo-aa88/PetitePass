from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
)

from petitepass.core.utils import CHARSET_CHOICES, generate_password


class GeneratePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        self.setFixedHeight(200)
        self.setFixedWidth(400)
        self.setWindowTitle("Generate password")

    def initUI(self):
        layout = QFormLayout(self)
        self.generatedPasswordLabel = QLabel("Generated password:")
        self.generatedPasswordBox = QLineEdit(self)
        self.generatedPasswordBox.setReadOnly(True)

        self.lengthField = QLineEdit(self)
        self.lengthField.setValidator(QIntValidator(1, 1024))
        self.charsetCombo = QComboBox(self)
        self.charsetCombo.addItems(CHARSET_CHOICES)
        layout.addRow(QLabel("Length:"), self.lengthField)
        layout.addRow(QLabel("Character Set:"), self.charsetCombo)

        self.generateButton = QPushButton("Generate", self)
        self.generateButton.clicked.connect(self.generatePassword)
        layout.addWidget(self.generateButton)
        layout.addRow(self.generatedPasswordLabel)
        layout.addRow(self.generatedPasswordBox)

    def generatePassword(self):
        try:
            length = int(self.lengthField.text())
        except ValueError:
            QMessageBox.warning(self, "Error", "The length cannot be empty.")
            return
        try:
            self.generatedPasswordBox.setText(
                generate_password(self.charsetCombo.currentText(), length))
        except ValueError as exc:
            QMessageBox.warning(self, "Error", str(exc))
