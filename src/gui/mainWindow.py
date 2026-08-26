from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QApplication,
    QHeaderView,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.vault import VAULT, VaultError
from gui.checkPasswordDialog import CheckPasswordDialog
from gui.deletePasswordDialog import DeletePasswordDialog
from gui.generatePasswordDialog import GeneratePasswordDialog
from gui.modifyMasterPasswordDialog import ModifyMasterPasswordDialog
from gui.passwordDialog import PasswordDialog
from gui.updatePasswordDialog import UpdatePasswordDialog

# Fixed-width mask so the displayed placeholder does not leak the exact
# password length to anyone glancing at the screen.
_MASK = "•" * 8
# Clear the clipboard this many milliseconds after a copy.
_CLIPBOARD_CLEAR_MS = 15000


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self._copied_secret = None
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout(self)

        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.clear_clipboard)

        self.table = QTableWidget(self)
        layout.addWidget(self.table)
        self.populatePasswordTable()

    # -- dialogs -----------------------------------------------------------

    def checkPasswordStrength(self):
        CheckPasswordDialog(self).exec_()

    def addPassword(self):
        if PasswordDialog(self).exec_() == PasswordDialog.Accepted:
            self.populatePasswordTable()

    def updatePassword(self):
        if UpdatePasswordDialog(self).exec_() == UpdatePasswordDialog.Accepted:
            self.populatePasswordTable()

    def deletePassword(self):
        if DeletePasswordDialog(self).exec_() == DeletePasswordDialog.Accepted:
            self.populatePasswordTable()

    def generatePassword(self):
        GeneratePasswordDialog(self).exec_()

    def modifyMasterPassword(self):
        ModifyMasterPasswordDialog(self).exec_()

    # -- table -------------------------------------------------------------

    def populatePasswordTable(self):
        self.table.clearContents()
        self.table.setRowCount(0)
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ["Name", "Username", "Password", "Created", "Updated",
             "Visibility", "Copy"])
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents)

        try:
            # The Vault returns passwordless summaries, so plaintext is never
            # loaded merely to render the (masked) table.
            credentials = VAULT.list_credentials()
        except VaultError as exc:
            QMessageBox.critical(
                self, "Vault error",
                f"Could not read the vault: {exc}")
            return

        for row, cred in enumerate(credentials):
            self.table.insertRow(row)
            self._set_readonly(row, 0, cred.name)
            self._set_readonly(row, 1, cred.username)
            self._set_readonly(row, 2, _MASK)
            self._set_readonly(row, 3, cred.created)
            self._set_readonly(row, 4, cred.updated)
            self.addPasswordButton(row, cred.name)
            self.addCopyButton(row, cred.name)

    def _set_readonly(self, row, col, text):
        item = QTableWidgetItem(text)
        item.setFlags(item.flags() & ~Qt.ItemIsEditable)
        self.table.setItem(row, col, item)

    # -- clipboard ---------------------------------------------------------

    def addCopyButton(self, row, name):
        button = QPushButton("Copy", self)
        button.clicked.connect(lambda _=False, n=name: self.copyToClipboard(n))
        self.table.setCellWidget(row, 6, button)

    def copyToClipboard(self, name):
        try:
            secret = VAULT.get_password(name)
        except VaultError as exc:
            QMessageBox.critical(self, "Error", str(exc))
            return
        QApplication.clipboard().setText(secret)
        self._copied_secret = secret
        self.timer.start(_CLIPBOARD_CLEAR_MS)
        QMessageBox.information(
            self, "Copied",
            "Password copied to clipboard. It will be cleared in "
            f"{_CLIPBOARD_CLEAR_MS // 1000} seconds.")

    def clear_clipboard(self):
        # Only clear if the clipboard still holds the secret we placed there,
        # so we never wipe something the user copied afterwards. Uses Qt (no
        # external process/shell), so it works on X11, Wayland, macOS, Windows.
        clipboard = QApplication.clipboard()
        if self._copied_secret is not None \
                and clipboard.text() == self._copied_secret:
            clipboard.clear()
        self._copied_secret = None

    # -- show/hide ---------------------------------------------------------

    def addPasswordButton(self, row, name):
        button = QPushButton("Show", self)
        button.clicked.connect(
            lambda _=False, r=row, n=name: self.togglePasswordVisibility(r, n))
        self.table.setCellWidget(row, 5, button)

    def togglePasswordVisibility(self, row, name):
        button = self.table.cellWidget(row, 5)
        if button.text() == "Show":
            try:
                secret = VAULT.get_password(name)
            except VaultError as exc:
                QMessageBox.critical(self, "Error", str(exc))
                return
            button.setText("Hide")
            self._set_readonly(row, 2, secret)
        else:
            button.setText("Show")
            self._set_readonly(row, 2, _MASK)

    # -- context menu ------------------------------------------------------

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        actions = {
            menu.addAction("Add password"): self.addPassword,
            menu.addAction("Update password"): self.updatePassword,
            menu.addAction("Delete password"): self.deletePassword,
            menu.addAction("Generate password"): self.generatePassword,
            menu.addAction("Check password strength"): self.checkPasswordStrength,
            menu.addAction("Modify master password"): self.modifyMasterPassword,
        }
        chosen = menu.exec_(self.mapToGlobal(event.pos()))
        handler = actions.get(chosen)
        if handler is not None:
            handler()
