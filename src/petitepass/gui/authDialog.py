from PyQt5.QtCore import QTimer, pyqtSignal
from PyQt5.QtWidgets import QDialog, QFormLayout, QLabel, QLineEdit, QMessageBox, QPushButton

from petitepass.core.vault import VAULT, VaultAuthError, VaultError
from petitepass.gui.createPasswordDialog import CreatePasswordDialog


class AuthDialog(QDialog):
    """Unlocks the vault. Authentication == the vault decrypts, nothing else."""

    login_successful = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._first_run_started = False
        self.initUI()
        self.setFixedHeight(80)
        self.setFixedWidth(400)
        self.setWindowTitle("Login")

    def initUI(self):
        # Build widgets only. The first-run create flow is deliberately NOT run
        # from __init__: at that point PasswordManagerApp has not connected the
        # login_successful signal and exec_() has not started, so an accept()
        # here would be discarded by QDialog::exec()'s result reset.
        layout = QFormLayout(self)
        self.passwordField = QLineEdit(self)
        self.passwordField.setEchoMode(QLineEdit.Password)
        self.passwordField.returnPressed.connect(self.handleLogin)
        layout.addRow(QLabel("Password:"), self.passwordField)
        self.buttons = QPushButton("Login", self)
        self.buttons.clicked.connect(self.handleLogin)
        layout.addWidget(self.buttons)

    def showEvent(self, event):
        super().showEvent(event)
        # Runs once, after the dialog is shown and the signal is connected.
        if not self._first_run_started and not VAULT.exists():
            self._first_run_started = True
            QTimer.singleShot(0, self.handleNewPasswordCreation)

    def handleNewPasswordCreation(self):
        dialog = CreatePasswordDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            # CreatePasswordDialog leaves the newly created vault open.
            self.login_successful.emit()
            self.accept()
        else:
            QMessageBox.warning(
                self, "Error", "Vault creation was cancelled or failed.")
            self.reject()

    def handleLogin(self):
        password = self.passwordField.text()
        try:
            VAULT.open(password)
        except VaultAuthError:
            QMessageBox.warning(self, "Login Failed", "Incorrect password.")
            self.passwordField.clear()
            return
        except VaultError as exc:
            QMessageBox.critical(self, "Error", str(exc))
            return
        self.login_successful.emit()
        self.accept()
