from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
)

from petitepass.core.strength import check_master_policy
from petitepass.core.vault import VAULT, VaultAuthError, VaultError, VaultRotatedError


class ModifyMasterPasswordDialog(QDialog):
    """Rotate the master password through the Vault.

    There is no sidecar verifier to update, so the verifier/vault desync that
    could previously lock the user out is gone. The Vault rekeys a temporary
    copy and atomically replaces the vault with it, so a failure at any point
    leaves the original vault openable under the current password.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        self.setFixedHeight(150)
        self.setFixedWidth(400)
        self.setWindowTitle("Modify master password")

    def initUI(self):
        layout = QFormLayout(self)
        self.currentPasswordField = QLineEdit(self)
        self.currentPasswordField.setEchoMode(QLineEdit.Password)
        self.passwordField = QLineEdit(self)
        self.passwordField.setEchoMode(QLineEdit.Password)
        self.confirmPasswordField = QLineEdit(self)
        self.confirmPasswordField.setEchoMode(QLineEdit.Password)
        layout.addRow(QLabel("Current Password:"), self.currentPasswordField)
        layout.addRow(QLabel("New Password:"), self.passwordField)
        layout.addRow(QLabel("Confirm Password:"), self.confirmPasswordField)
        self.createButton = QPushButton("Update password", self)
        self.createButton.clicked.connect(self.modifyMasterPassword)
        layout.addWidget(self.createButton)

    def modifyMasterPassword(self):
        current_password = self.currentPasswordField.text()
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
            VAULT.rekey(current_password, password)
        except VaultRotatedError as exc:
            # The rotation committed on disk but the session could not be
            # rebound. Do NOT claim the current password was wrong; the vault is
            # now keyed with the new password. Tell the user and restart.
            QMessageBox.critical(self, "Restart required", str(exc))
            QApplication.quit()
            return
        except VaultAuthError:
            QMessageBox.warning(
                self, "Error", "The current password is incorrect.")
            return
        except VaultError as exc:
            QMessageBox.critical(self, "Error", str(exc))
            return

        QMessageBox.information(
            self, "Success", "The master password was modified successfully.")
        self.accept()
