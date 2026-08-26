from PyQt5.QtWidgets import QDialog, QFormLayout, QLabel, QLineEdit, QMessageBox, QPushButton

from petitepass.core.vault import VAULT, CredentialNotFoundError, VaultError


class DeletePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        self.setWindowTitle("Delete password entry")

    def initUI(self):
        layout = QFormLayout(self)
        self.nameField = QLineEdit(self)
        layout.addRow(QLabel("Name:"), self.nameField)
        self.buttons = QPushButton("Delete", self)
        self.buttons.clicked.connect(self.deletePassword)
        layout.addWidget(self.buttons)

    def deletePassword(self):
        name = self.nameField.text()

        # Confirm before a destructive, irreversible operation.
        confirm = QMessageBox.question(
            self, "Confirm deletion",
            f"Permanently delete the entry '{name}'?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return

        try:
            VAULT.delete(name)
        except CredentialNotFoundError:
            QMessageBox.warning(
                self, "Error",
                "The name does not exist! Please type an existing name.")
            return
        except VaultError as exc:
            QMessageBox.warning(self, "Error", str(exc))
            return

        QMessageBox.information(
            self, "Success", "Password record deleted successfully!")
        self.accept()
