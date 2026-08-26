from PyQt5.QtWidgets import QDialog, QFormLayout, QLabel, QLineEdit, QMessageBox, QPushButton

from core.vault import VAULT, CredentialNotFoundError, VaultError


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
        try:
            VAULT.update(self.nameField.text(), self.usernameField.text(),
                         self.passwordField.text())
        except CredentialNotFoundError:
            QMessageBox.warning(
                self, "Error",
                "The name does not exist! Please type an existing name.")
            return
        except VaultError as exc:
            QMessageBox.warning(self, "Error", str(exc))
            return

        QMessageBox.information(
            self, "Success", "Password record updated successfully!")
        self.accept()
