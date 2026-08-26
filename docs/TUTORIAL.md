# PetitePass — Tutorial

A step-by-step walkthrough, from install to daily use. For how it works under the hood, see [DESIGN.md](DESIGN.md).

- [1. Install and launch](#1-install-and-launch)
- [2. Create your master password](#2-create-your-master-password)
- [3. Add a credential](#3-add-a-credential)
- [4. Find, copy, and reveal](#4-find-copy-and-reveal)
- [5. Edit and delete](#5-edit-and-delete)
- [6. Generate a strong password](#6-generate-a-strong-password)
- [7. Change your master password](#7-change-your-master-password)
- [8. Back up and restore](#8-back-up-and-restore)
- [9. Auto-lock](#9-auto-lock)
- [10. Troubleshooting](#10-troubleshooting)

* * *

## 1. Install and launch

Install the package and run the command (see the [README](../README.md) for other options):

```bash
pip install .
petitepass
```

The first time you run it, PetitePass sees that no vault exists and asks you to create a master password.

## 2. Create your master password

Enter and confirm a master password. It must:

- be at least **12 characters**,
- not appear in the bundled list of the 10 000 most common passwords, and
- clear a minimum [zxcvbn](https://github.com/dropbox/zxcvbn) guessability score.

A memorable **passphrase** of several unrelated words is both easier to remember and harder to guess than a short string of symbols.

> **There is no recovery.** PetitePass never stores your master password. If you forget it, the vault cannot be decrypted — there is no reset link, no backdoor, and no support that can help. Consider writing it down and storing the paper somewhere physically safe.

When you confirm, an encrypted vault is created (mode `0600`) in your platform's data directory and you are taken to the main window.

## 3. Add a credential

Right-click the table and choose **Add password**. Fill in:

- **Name** — a unique label for the entry (e.g. `github`). Names must be unique.
- **Username** — optional (e.g. an email address).
- **Password** — the secret. Use **Generate password** (see §6) if you want a strong random one.

Click **Save**. The row appears with the password masked (`••••••••`).

## 4. Find, copy, and reveal

- **Filter:** type in the search box to show only rows whose name or username matches.
- **Copy:** the **Copy** button puts the password on your clipboard and shows how long until it auto-clears. The clipboard is only wiped if it still holds that password — anything you copy afterwards is left alone.
- **Copy user:** copies the username (usernames are not secrets and are not auto-cleared).
- **Show / Hide:** reveals the password in the table cell; click again (or let auto-lock fire) to re-mask it.

## 5. Edit and delete

- **Edit:** double-click a row (or right-click → **Update password**). The name is fixed; change the username and/or password. Leaving a field blank keeps the current value.
- **Delete:** right-click → **Delete password**. You will be asked to confirm — deletion is permanent.

## 6. Generate a strong password

Right-click → **Generate password**. Choose a length and a character set, then **Generate**. The generator uses Python's `secrets` module (a cryptographically secure RNG). Copy the result into a credential's password field.

You can also right-click → **Check password strength** to see a zxcvbn estimate and an approximate crack time for any password.

## 7. Change your master password

Right-click → **Modify master password**. Enter your current password and a new one (twice). The new password must satisfy the same policy as at creation.

Under the hood this rekeys the entire database atomically on a verified copy — if anything fails, your old password still works. On success the change is immediate.

## 8. Back up and restore

**Back up:** right-click → **Back up vault…** and choose a destination file. The backup is the encrypted vault, protected by the same master password, and PetitePass verifies it is decryptable before writing it. Store it somewhere safe; it is useless to anyone without your master password.

**Restore:** right-click → **Restore from backup…**, pick a backup file, confirm, and enter *that backup's* master password. The current vault is replaced only after the backup is verified. If the backup used a different master password, you will use that password from then on.

## 9. Auto-lock

After a period of inactivity, PetitePass closes the vault, clears the clipboard, re-masks any revealed passwords, and returns you to the login screen. Unlock again with your master password to continue.

## 10. Troubleshooting

| Symptom                                              | Cause / fix                                                                                     |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| "Incorrect master password, or not a valid vault"    | Wrong password, or the file is not a PetitePass vault. Master passwords cannot be recovered.    |
| Login screen appears again unexpectedly              | The vault auto-locked after inactivity. This is normal; log back in.                            |
| "The backup destination must differ from the vault"  | You chose the live vault file as a backup target. Pick a different path.                        |
| "Restart PetitePass and unlock with the … password"  | A rekey or restore committed on disk but the session could not reopen. Restart and use the new master password. |
| Moved to a new machine                               | Copy the vault file to the same data directory (see the README), or use **Restore from backup**. |
