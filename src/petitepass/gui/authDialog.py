from PyQt5.QtCore import QSize, Qt, QTimer, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
)

from petitepass.core.vault import VAULT, VaultAuthError, VaultError
from petitepass.gui.createPasswordDialog import CreatePasswordDialog

# Fixed size of the login dialog.
_LOGIN_SIZE = QSize(460, 150)


class AuthDialog(QDialog):
    """Unlocks the vault. Authentication == the vault decrypts, nothing else."""

    login_successful = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._first_run_started = False
        self._enforcing_size = False
        # Window flags MUST be set before the size is fixed: setWindowFlags
        # recreates the native window and discards the size constraints, which is
        # why doing it afterwards left the dialog huge and resizable.
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowMaximizeButtonHint)
        self.setWindowTitle("Login")
        self.initUI()
        # Fixed size. setFixedSize handles well-behaved window managers;
        # resizeEvent below re-pins the size for the ones (e.g. weston under
        # WSLg) that ignore the min==max hint and let the user drag.
        self.setFixedSize(_LOGIN_SIZE)

    def initUI(self):
        # Build widgets only. The first-run create flow is deliberately NOT run
        # from __init__: at that point PasswordManagerApp has not connected the
        # login_successful signal and exec_() has not started, so an accept()
        # here would be discarded by QDialog::exec()'s result reset.
        layout = QFormLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(18)
        self.passwordField = QLineEdit(self)
        self.passwordField.setEchoMode(QLineEdit.Password)
        self.passwordField.setPlaceholderText("Master password")
        self.passwordField.setMinimumWidth(320)
        self.passwordField.setMinimumHeight(32)
        self.passwordField.returnPressed.connect(self.handleLogin)
        layout.addRow(QLabel("Password:"), self.passwordField)
        self.buttons = QPushButton("Login", self)
        self.buttons.setMinimumHeight(34)
        self.buttons.clicked.connect(self.handleLogin)
        layout.addRow(self.buttons)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Some compositors (weston under WSLg) ignore the fixed-size hint and let
        # the user drag the border. Snap straight back to the fixed size. The
        # re-entrancy guard stops the resize() we issue from looping.
        if self.size() != _LOGIN_SIZE and not self._enforcing_size:
            self._enforcing_size = True
            self.setFixedSize(_LOGIN_SIZE)
            self._enforcing_size = False

    def _center_on_screen(self):
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        frame = self.frameGeometry()
        frame.moveCenter(screen.availableGeometry().center())
        self.move(frame.topLeft())

    def showEvent(self, event):
        super().showEvent(event)
        self._center_on_screen()
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
        # Drop the widget-held copy as soon as the vault has the secret.
        self.passwordField.clear()
        self.login_successful.emit()
        self.accept()
