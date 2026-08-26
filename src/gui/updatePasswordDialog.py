from datetime import datetime

from peewee import DoesNotExist
from PyQt5.QtWidgets import QDialog, QFormLayout, QLabel, QLineEdit, QMessageBox, QPushButton

from core.database import Password


class UpdatePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        self.setWindowTitle("Update password entry")

    def initUI(self):
        layout = QFormLayout(self)
        self.nameField = QLineEdit(self)
        self.usernameField = QLineEdit(self)
        self.passwordField = QLineEdit(self)
        self.passwordField.setEchoMode(QLineEdit.Password)
        layout.addRow(QLabel("Name:"), self.nameField)
        layout.addRow(QLabel("Username:"), self.usernameField)
        layout.addRow(QLabel("Password:"), self.passwordField)
        self.buttons = QPushButton("Update", self)
        self.buttons.clicked.connect(self.updatePassword)
        layout.addWidget(self.buttons)

    def updatePassword(self):
        name = self.nameField.text()
        username = self.usernameField.text()
        password = self.passwordField.text()

        try:
            entry = Password.get(Password.name == name)
        except DoesNotExist:
            QMessageBox.warning(
                self, "Error",
                "The name does not exist! Please type an existing name.")
            return
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))
            return

        if username != "":
            entry.username = username
        if password != "":
            entry.password = password
        entry.updated = datetime.now()
        try:
            entry.save()
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))
            return

        QMessageBox.information(
            self, "Success", "Password record updated successfully!")
        self.accept()
