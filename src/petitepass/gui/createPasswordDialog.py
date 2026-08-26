from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QDialog, QFormLayout, QLabel, QLineEdit, QMessageBox, QPushButton

from petitepass.core.strength import check_master_policy
from petitepass.core.vault import VAULT, VaultError


class CreatePasswordDialog(QDialog):
    password_created = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        self.setFixedHeight(100)
        self.setFixedWidth(400)
        self.setWindowTitle("Create master password")

    def initUI(self):
        layout = QFormLayout(self)
        self.passwordField = QLineEdit(self)
        self.passwordField.setEchoMode(QLineEdit.Password)
        self.confirmPasswordField = QLineEdit(self)
        self.confirmPasswordField.setEchoMode(QLineEdit.Password)
        layout.addRow(QLabel("New Password:"), self.passwordField)
        layout.addRow(QLabel("Confirm Password:"), self.confirmPasswordField)
        self.createButton = QPushButton("Create Password", self)
        self.createButton.clicked.connect(self.createPassword)
        layout.addWidget(self.createButton)

    def createPassword(self):
        password = self.passwordField.text()
        confirm_password = self.confirmPasswordField.text()

        if password != confirm_password:
            QMessageBox.warning(self, "Error", "The passwords do not match.")
            return

        policy_error = check_master_policy(password)
        if policy_error is not None:
            QMessageBox.warning(self, "Weak master password", policy_error)
            return

        try:
            VAULT.create(password)
        except VaultError as exc:
            QMessageBox.critical(self, "Error", str(exc))
            self.reject()
            return

        self.password_created.emit()
        self.accept()
