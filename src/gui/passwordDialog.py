from peewee import IntegrityError
from PyQt5.QtWidgets import QDialog, QFormLayout, QLabel, QLineEdit, QMessageBox, QPushButton

from core.database import Password


class PasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        self.setWindowTitle("Create new password entry")

    def initUI(self):
        layout = QFormLayout(self)
        self.nameField = QLineEdit(self)
        self.usernameField = QLineEdit(self)
        self.passwordField = QLineEdit(self)
        self.passwordField.setEchoMode(QLineEdit.Password)
        layout.addRow(QLabel("Name:"), self.nameField)
        layout.addRow(QLabel("Username:"), self.usernameField)
        layout.addRow(QLabel("Password:"), self.passwordField)
        self.buttons = QPushButton("Save", self)
        self.buttons.clicked.connect(self.savePassword)
        layout.addWidget(self.buttons)

    def savePassword(self):
        name = self.nameField.text()
        username = self.usernameField.text()
        password = self.passwordField.text()

        if not name:
            QMessageBox.warning(self, "Error", "The name cannot be empty.")
            return
        if not password:
            QMessageBox.warning(self, "Error", "The password cannot be empty.")
            return

        try:
            # Uniqueness is enforced by the DB constraint, not a racy pre-check.
            Password.create(name=name, username=username, password=password)
        except IntegrityError:
            QMessageBox.warning(
                self, "Error",
                "That name already exists. Please choose another name.")
            return
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))
            return

        QMessageBox.information(
            self, "Success", "Password record created successfully!")
        self.accept()
