from PyQt5.QtWidgets import QDialog, QFormLayout, QLabel, QLineEdit, QMessageBox, QPushButton

from core.vault import VAULT, DuplicateCredentialError, VaultError


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
        try:
            VAULT.add(self.nameField.text(), self.usernameField.text(),
                      self.passwordField.text())
        except DuplicateCredentialError:
            QMessageBox.warning(
                self, "Error",
                "That name already exists. Please choose another name.")
            return
        except VaultError as exc:
            QMessageBox.warning(self, "Error", str(exc))
            return
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))
            return

        QMessageBox.information(
            self, "Success", "Password record created successfully!")
        self.accept()
