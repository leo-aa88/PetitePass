from PyQt5.QtCore import QEvent, Qt, QTimer, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHeaderView,
    QInputDialog,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.vault import VAULT, VaultAuthError, VaultError, VaultRestoredError
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
# Auto-lock the vault after this much inactivity.
_AUTOLOCK_MS = 5 * 60 * 1000

_COLUMNS = ["Name", "Username", "Password", "Created", "Updated",
            "Visibility", "Copy", "Copy user"]
_COL_NAME, _COL_USER, _COL_PW = 0, 1, 2
_COL_SHOW, _COL_COPY, _COL_COPYUSER = 5, 6, 7


class MainWindow(QWidget):
    # Emitted when the vault auto-locks; the application returns to login.
    locked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._copied_secret = None
        self.initUI()
        self._install_autolock()

    def initUI(self):
        layout = QVBoxLayout(self)

        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.clear_clipboard)

        # Search / filter box.
        self.searchField = QLineEdit(self)
        self.searchField.setPlaceholderText("Filter by name or username…")
        self.searchField.setClearButtonEnabled(True)
        self.searchField.textChanged.connect(self.applyFilter)
        layout.addWidget(self.searchField)

        self.table = QTableWidget(self)
        self.table.cellDoubleClicked.connect(self._editRow)
        layout.addWidget(self.table)
        self.populatePasswordTable()

    # -- auto-lock ---------------------------------------------------------

    def _install_autolock(self):
        self.inactivityTimer = QTimer(self)
        self.inactivityTimer.setSingleShot(True)
        self.inactivityTimer.timeout.connect(self._on_inactivity)
        self.inactivityTimer.start(_AUTOLOCK_MS)
        QApplication.instance().installEventFilter(self)

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.MouseButtonPress, QEvent.KeyPress,
                             QEvent.MouseMove, QEvent.Wheel):
            self.inactivityTimer.start(_AUTOLOCK_MS)  # reset on activity
        return super().eventFilter(obj, event)

    def _on_inactivity(self):
        # Never tear the window down while a modal dialog (copy/backup/restore/
        # update/file dialog) is on the stack -- that would destroy the dialog's
        # parent under its nested event loop. Defer the lock until it closes.
        if QApplication.activeModalWidget() is not None:
            self.inactivityTimer.start(_AUTOLOCK_MS)
            return
        self._lock()

    def _lock(self):
        # Actually lock: stop timers, detach the app-wide filter, clear the
        # clipboard, re-mask any revealed passwords, CLOSE the vault, and hand
        # control back for re-authentication.
        self.inactivityTimer.stop()
        self.timer.stop()
        QApplication.instance().removeEventFilter(self)
        self.clear_clipboard()
        for row in range(self.table.rowCount()):
            self._set_readonly(row, _COL_PW, _MASK)
            button = self.table.cellWidget(row, _COL_SHOW)
            if button is not None:
                button.setText("Show")
        VAULT.close()
        self.locked.emit()

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

    def _editRow(self, row, _col):
        nameItem = self.table.item(row, _COL_NAME)
        if nameItem is None:
            return
        userItem = self.table.item(row, _COL_USER)
        dialog = UpdatePasswordDialog(
            self, name=nameItem.text(),
            username=userItem.text() if userItem else "")
        if dialog.exec_() == QDialog.Accepted:
            self.populatePasswordTable()

    # -- backup / restore --------------------------------------------------

    def backupVault(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save encrypted vault backup", "petitepass-backup.db",
            "Vault backup (*.db);;All files (*)")
        if not path:
            return
        try:
            VAULT.backup_to(path)
        except VaultError as exc:
            QMessageBox.critical(self, "Backup failed", str(exc))
            return
        QMessageBox.information(
            self, "Backup", "Encrypted backup saved successfully.")

    def restoreVault(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Restore vault from backup", "",
            "Vault backup (*.db);;All files (*)")
        if not path:
            return
        confirm = QMessageBox.question(
            self, "Confirm restore",
            "Restoring REPLACES your current vault with the backup. Continue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return
        master, ok = QInputDialog.getText(
            self, "Backup master password",
            "Enter the master password for that backup:", QLineEdit.Password)
        if not ok:
            return
        try:
            VAULT.restore_from(path, master)
        except VaultRestoredError as exc:
            # Committed on disk but the session could not be rebound: do NOT
            # blame the password. Tell the user and restart.
            QMessageBox.critical(self, "Restart required", str(exc))
            QApplication.quit()
            return
        except VaultAuthError:
            QMessageBox.warning(
                self, "Restore failed",
                "Incorrect master password for that backup.")
            return
        except VaultError as exc:
            QMessageBox.critical(self, "Restore failed", str(exc))
            return
        self.populatePasswordTable()
        QMessageBox.information(self, "Restore", "Vault restored from backup.")

    # -- table -------------------------------------------------------------

    def populatePasswordTable(self):
        self.table.clearContents()
        self.table.setRowCount(0)
        self.table.setColumnCount(len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeToContents)

        try:
            # The Vault returns passwordless summaries, so plaintext is never
            # loaded merely to render the (masked) table.
            credentials = VAULT.list_credentials()
        except VaultError as exc:
            QMessageBox.critical(
                self, "Vault error", f"Could not read the vault: {exc}")
            return

        for row, cred in enumerate(credentials):
            self.table.insertRow(row)
            self._set_readonly(row, _COL_NAME, cred.name)
            self._set_readonly(row, _COL_USER, cred.username)
            self._set_readonly(row, _COL_PW, _MASK)
            self._set_readonly(row, 3, cred.created)
            self._set_readonly(row, 4, cred.updated)
            self.addPasswordButton(row, cred.name)
            self.addCopyButton(row, cred.name)
            self.addCopyUserButton(row, cred.username)
        self.applyFilter(self.searchField.text())

    def _set_readonly(self, row, col, text):
        item = QTableWidgetItem(text)
        item.setFlags(item.flags() & ~Qt.ItemIsEditable)
        self.table.setItem(row, col, item)

    def applyFilter(self, text):
        needle = (text or "").strip().lower()
        for row in range(self.table.rowCount()):
            name = self.table.item(row, _COL_NAME)
            user = self.table.item(row, _COL_USER)
            haystack = f"{name.text() if name else ''} {user.text() if user else ''}".lower()
            self.table.setRowHidden(row, needle not in haystack)

    # -- clipboard ---------------------------------------------------------

    def addCopyButton(self, row, name):
        button = QPushButton("Copy", self)
        button.clicked.connect(lambda _=False, n=name: self.copyToClipboard(n))
        self.table.setCellWidget(row, _COL_COPY, button)

    def addCopyUserButton(self, row, username):
        button = QPushButton("Copy user", self)
        button.clicked.connect(
            lambda _=False, u=username: self.copyUsernameToClipboard(u))
        self.table.setCellWidget(row, _COL_COPYUSER, button)

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

    def copyUsernameToClipboard(self, username):
        # A username is not a secret, so it is not auto-cleared; and it is not
        # tracked as `_copied_secret`, so it won't trip the password auto-clear.
        QApplication.clipboard().setText(username)
        QMessageBox.information(self, "Copied", "Username copied to clipboard.")

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
        self.table.setCellWidget(row, _COL_SHOW, button)

    def togglePasswordVisibility(self, row, name):
        button = self.table.cellWidget(row, _COL_SHOW)
        if button.text() == "Show":
            try:
                secret = VAULT.get_password(name)
            except VaultError as exc:
                QMessageBox.critical(self, "Error", str(exc))
                return
            button.setText("Hide")
            self._set_readonly(row, _COL_PW, secret)
        else:
            button.setText("Show")
            self._set_readonly(row, _COL_PW, _MASK)

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
        menu.addSeparator()
        actions[menu.addAction("Back up vault…")] = self.backupVault
        actions[menu.addAction("Restore from backup…")] = self.restoreVault
        chosen = menu.exec_(self.mapToGlobal(event.pos()))
        handler = actions.get(chosen)
        if handler is not None:
            handler()
