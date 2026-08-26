"""Headless end-to-end smoke test driving the real GUI classes offscreen.

Run with: QT_QPA_PLATFORM=offscreen python tests/smoke_gui.py
Uses a temporary HOME so the real vault is never touched.
"""
import os
import sys
import tempfile

# Redirect HOME *before* importing anything that computes the vault path.
_TMP = tempfile.mkdtemp()
os.environ["HOME"] = _TMP
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from PyQt5.QtWidgets import QApplication, QMessageBox  # noqa: E402

# Stub modal dialogs so slots don't block waiting for a human.
QMessageBox.information = staticmethod(lambda *a, **k: QMessageBox.Ok)
QMessageBox.warning = staticmethod(lambda *a, **k: QMessageBox.Ok)
QMessageBox.critical = staticmethod(lambda *a, **k: QMessageBox.Ok)
QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.Yes)

from core.database import Password  # noqa: E402
from core.vault import VAULT, VaultAuthError  # noqa: E402
from gui.createPasswordDialog import CreatePasswordDialog  # noqa: E402
from gui.deletePasswordDialog import DeletePasswordDialog  # noqa: E402
from gui.mainWindow import MainWindow  # noqa: E402
from gui.modifyMasterPasswordDialog import ModifyMasterPasswordDialog  # noqa: E402
from gui.passwordDialog import PasswordDialog  # noqa: E402

MASTER = "correct horse battery staple 7"
NEW_MASTER = "an even longer new passphrase 42"
checks = []


def check(label, ok):
    checks.append((label, ok))
    print(("PASS" if ok else "FAIL"), label)


app = QApplication(sys.argv)

# 1. Create the vault through the real dialog slot.
cpd = CreatePasswordDialog()
cpd.passwordField.setText(MASTER)
cpd.confirmPasswordField.setText(MASTER)
cpd.createPassword()
check("vault created by CreatePasswordDialog", VAULT.exists() and VAULT.is_open)

# 2. Main window with an empty vault.
win = MainWindow()
check("empty table populates", win.table.rowCount() == 0)

# 3. Add a credential via the real dialog slot.
pd = PasswordDialog(win)
pd.nameField.setText("github")
pd.usernameField.setText("me@example.com")
pd.passwordField.setText("s3cr'et\"\\pw")
pd.savePassword()
win.populatePasswordTable()
check("row added and shown", win.table.rowCount() == 1)
check("password masked by default", win.table.item(0, 2).text() == "•" * 8)

# 4. Duplicate name rejected by the DB constraint (no crash).
pd2 = PasswordDialog(win)
pd2.nameField.setText("github")
pd2.passwordField.setText("other")
pd2.savePassword()
check("duplicate name rejected", Password.select().count() == 1)

# 5. Copy -> clipboard holds the secret; clearing only wipes our own value.
win.copyToClipboard("github")
check("clipboard holds secret", app.clipboard().text() == "s3cr'et\"\\pw")
app.clipboard().setText("user typed something else")
win.clear_clipboard()
check("clear does NOT wipe user's newer clipboard",
      app.clipboard().text() == "user typed something else")
win.copyToClipboard("github")
win.clear_clipboard()
check("clear wipes our secret when still present", app.clipboard().text() == "")

# 6. Show/hide toggles plaintext then re-masks.
win.togglePasswordVisibility(0, "github")
check("show reveals plaintext", win.table.item(0, 2).text() == "s3cr'et\"\\pw")
win.togglePasswordVisibility(0, "github")
check("hide re-masks", win.table.item(0, 2).text() == "•" * 8)

# 7. Rekey through the real dialog slot, then reopen with the new master.
mm = ModifyMasterPasswordDialog(win)
mm.currentPasswordField.setText(MASTER)
mm.passwordField.setText(NEW_MASTER)
mm.confirmPasswordField.setText(NEW_MASTER)
mm.modifyMasterPassword()
VAULT.close()
try:
    VAULT.open(MASTER)
    check("old master rejected after rekey", False)
except VaultAuthError:
    check("old master rejected after rekey", True)
VAULT.open(NEW_MASTER)
check("new master opens; data survived",
      Password.get(Password.name == "github").password == "s3cr'et\"\\pw")

# 8. Delete (auto-confirmed) removes the row.
dd = DeletePasswordDialog(win)
dd.nameField.setText("github")
dd.deletePassword()
check("delete removes record", Password.select().count() == 0)

VAULT.close()
failed = [label for label, ok in checks if not ok]
print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
sys.exit(1 if failed else 0)
