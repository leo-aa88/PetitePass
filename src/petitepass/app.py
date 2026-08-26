import os
import sys

from petitepass import __version__

_USAGE = "usage: petitepass [--version] [--help]\n\nLaunches the PetitePass GUI."


def _selftest() -> int:
    """Verify a packaged/frozen build end to end, Qt-free.

    Checks the bundled common-password list resolves, and that SQLCipher
    actually encrypts and decrypts on this platform (a real create → add →
    reopen → read round-trip in a throwaway directory). This is what proves the
    native SQLCipher extension is bundled and working in the release binary.
    """
    import shutil
    import tempfile

    from petitepass.core.paths import common_password_file
    from petitepass.core.strength import is_common
    from petitepass.core.vault import Vault

    location = common_password_file()
    if not location:
        print("selftest FAIL: bundled common-password list not found")
        return 1
    if not is_common("password"):
        print("selftest FAIL: common-password list not readable")
        return 1

    workdir = tempfile.mkdtemp(prefix="petitepass-selftest-")
    try:
        path = os.path.join(workdir, "selftest.db")
        master = "selftest correct horse battery staple"
        v = Vault(path)
        v.create(master)
        v.add("svc", "user", "s3cret")
        v.close()
        v2 = Vault(path)
        v2.open(master)
        ok = v2.get_password("svc") == "s3cret"
        v2.close()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if not ok:
        print("selftest FAIL: SQLCipher round-trip did not return the stored value")
        return 1
    print(f"selftest OK: petitepass {__version__}; wordlist + SQLCipher round-trip passed")
    return 0


def _run_gui() -> int:
    # Qt (and everything that pulls it in) is imported lazily so that
    # `--version` / `--help` work in the frozen binary without a display or the
    # Qt system libraries being present.
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
            # Auto-lock: drop the vault and window, then require re-auth.
            VAULT.close()
            self.hide()
            self.mainWindow = None
            self.setCentralWidget(QWidget())
            if not self._authenticate():
                QApplication.quit()

    app = QApplication(sys.argv)
    _ = PasswordManagerApp()
    return app.exec_()


def main() -> int:
    """Console entry point (``petitepass``)."""
    args = sys.argv[1:]
    if "--version" in args or "-V" in args:
        print(f"petitepass {__version__}")
        return 0
    if "--help" in args or "-h" in args:
        print(_USAGE)
        return 0
    if "--selftest" in args:
        return _selftest()
    return _run_gui()


if __name__ == "__main__":
    sys.exit(main())
