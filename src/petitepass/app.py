import sys

from PyQt5.QtWidgets import QApplication, QDialog, QMainWindow, QStyleFactory, QWidget

from petitepass.core.vault import VAULT
from petitepass.gui.authDialog import AuthDialog
from petitepass.gui.mainWindow import MainWindow


class PasswordManagerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setStyle(QStyleFactory.create("Fusion"))
        self.mainWindow = None
        if not self._authenticate():
            sys.exit()

    def _authenticate(self) -> bool:
        """Run the login/create dialog; return True on success."""
        dialog = AuthDialog()
        dialog.login_successful.connect(self.onLoginSuccess)
        return dialog.exec_() == QDialog.Accepted

    def onLoginSuccess(self):
        self.mainWindow = MainWindow()
        self.mainWindow.locked.connect(self.onLocked)
        self.setCentralWidget(self.mainWindow)
        self.setGeometry(300, 300, 900, 600)
        self.setWindowTitle("PetitePass")
        self.show()

    def onLocked(self):
        # Auto-lock: drop the vault and the window, then require re-authentication.
        VAULT.close()
        self.hide()
        self.mainWindow = None
        self.setCentralWidget(QWidget())
        if not self._authenticate():
            QApplication.quit()


def main() -> int:
    """Console entry point (``petitepass``)."""
    app = QApplication(sys.argv)
    _ = PasswordManagerApp()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
