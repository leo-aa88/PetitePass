# PetitePass Security & Architecture Audit

*Audit date: 2026-08-26. Scope: full working tree at `main` (`9c050ad`) plus git history. No code was modified.*

---

## 1. Executive Summary

**Would I trust PetitePass with real passwords today? No.**

Not because SQLCipher is weak — it isn't — but because PetitePass has bolted a **second, weaker authentication system on the side** of SQLCipher and made *that* the source of truth, and because the one operation that touches the encryption key (changing the master password) is **non-atomic, injectable through string-formatted SQL, and irrecoverable on failure.** A user who picks a master password containing a `'` and then tries to change it can permanently lose access to every credential they own. That is a data-loss defect in the one place a password manager is not allowed to have one.

The uncomfortable specifics:

- **Authentication is decided by a sidecar bcrypt file (`5f4dcc3b5aa765d61d8327deb882cf99` — literally the MD5 of the word "password"), not by whether the vault decrypts.** The app can say "login successful" and then crash the moment it touches the database, because it never verified the two are in sync.
- **The master-password change writes the new verifier to disk *before* the SQLCipher `rekey` runs, with no transaction and no rollback.** Crash, quote, or any exception in between = verifier and vault permanently disagree = lockout.
- **`PRAGMA key`/`PRAGMA rekey` are built with f-strings.** Quotes, backslashes, and other characters in the master password break the SQL. This is both a correctness bug and a redundant, dangerous re-implementation of what the library already does safely.
- **The verifier and the encrypted database are written world-readable** in a predictable `/home/<user>/PetitePass/` path with no permission hardening. The bcrypt file is an *offline password oracle* an attacker can grind independently of SQLCipher.
- **The password-strength engine is Shannon entropy of a single string's character frequencies.** It rates `abcdefgh` as 100% strong and `Password1!Password1!` as weak. It measures nothing relevant to guessability.
- **`requirements.txt` is a committed `pip freeze`** dragging in NumPy, Numba, LLVMlite, gTTS, pydub, pyttsx3, matplotlib's font stack, and requests into a local password manager. Enormous, unjustified supply-chain surface.

**Is the design salvageable?** The *product* is — a small local SQLCipher vault with a Qt front-end is a perfectly reasonable thing to build. The *security core* is not salvageable by patching. The bcrypt-verifier concept, the f-string PRAGMA handling, the GUI-owns-crypto structure, and the non-atomic rekey are not independent bugs; they are one architectural mistake (**no Vault abstraction; authentication and encryption treated as two systems**) expressed six different ways.

**Recommendation: Option C — REBUILD CORE.** Keep the Qt dialogs and the product concept; replace the vault/auth/crypto layer wholesale. Details in §21.

---

## 2. Current Architecture

There are two parallel implementations. `src/gui/*` (the live PyQt app, entry point `src/main.py`) and `src/core/main.py` + `src/core/utils.py`'s CLI functions (a dead, broken text-menu CLI). `src/core/database.py` is shared by the GUI (for the `Password` model) *and* the dead CLI (for `create_password`/`update_password`/etc.).

```mermaid
flowchart TD
    subgraph Entry
        M[src/main.py<br/>PasswordManagerApp]
    end
    subgraph DeadCLI["src/core/main.py — DEAD/BROKEN CLI"]
        C1["import from 'utils'/'database'<br/>(wrong module roots → ImportError)"]
        C2["Password._meta.is_auth<br/>(attribute never defined)"]
    end
    M --> AD[gui/authDialog.py<br/>AuthDialog]
    AD -->|db file missing| CP[gui/createPasswordDialog.py<br/>CreatePasswordDialog]
    AD -->|login| AUTH{{"bcrypt.checkpw(pw, sidecar file)"}}
    AUTH -->|pass| BIND["global db = SqlCipherDatabase(passphrase)<br/>Password._meta.database = db<br/>(NOT connected / NOT verified yet)"]
    AUTH -->|fail| STOP[Incorrect password]
    BIND --> MW[gui/mainWindow.py<br/>MainWindow]
    MW --> TBL["populatePasswordTable()<br/>Password.select() → decrypts ALL rows<br/>(first actual DB access = first real key test)"]
    TBL --> CLIP["copyToClipboard → Qt clipboard<br/>QTimer 3s → subprocess 'xsel -bc' shell=True"]
    TBL --> SHOW["togglePasswordVisibility → plaintext into table cell"]
    MW --> MOD[gui/modifyMasterPasswordDialog.py]
    MOD --> REKEY["write NEW bcrypt verifier to disk<br/>THEN db.execute_sql(f\"PRAGMA key='{cur}'\")<br/>THEN db.execute_sql(f\"PRAGMA rekey='{new}'\")<br/>(no transaction, no rollback)"]

    subgraph FS["/home/&lt;user&gt;/PetitePass  (mode 0755, files 0644)"]
        F1["48cccca3...db  — SQLCipher vault"]
        F2["5f4dcc3b5aa765d61d8327deb882cf99 — bcrypt verifier<br/>(filename = MD5 'password')"]
    end
    CP --> F1
    CP --> F2
    AUTH --> F2
    BIND --> F1
    REKEY --> F1
    REKEY --> F2
```

**Where plaintext secrets live along the path:** master password → `QLineEdit.text()` → local `str`/`bytes` → passed to bcrypt *and* interpolated into SQL strings → held on the `SqlCipherDatabase.passphrase` attribute for the whole session. Stored passwords → decrypted in bulk by `Password.select()` → held on every `Password` model instance for the session → duplicated into `QTableWidgetItem`s (masked) and into per-row `lambda` closures for the Copy buttons → on "Show", written in cleartext into a visible table cell → on "Copy", written to the OS clipboard (and to any clipboard-manager history).

---

## 3. Threat Model

| Threat | PetitePass posture | Verdict |
|---|---|---|
| **A. Stolen vault only** | SQLCipher 4 default KDF (PBKDF2-HMAC-SHA512, 256k iters, per-DB salt). Brute force cost ≈ master-password strength. The policy engine (§4) actively permits weak masters, so real-world entropy is often low. | **Partially protected** — only as strong as the master password, which the app fails to enforce. |
| **B. Stolen vault + sidecar verifier** | The bcrypt file is a *second, independent* offline oracle over the **same** master password. bcrypt(gensalt default cost 12) is far cheaper to grind than SQLCipher's 256k-iteration KDF, and it leaks the answer that also decrypts the vault. Extra file makes offline attack **strictly easier**. | **Regression** — the verifier *reduces* security vs. attacking SQLCipher alone. |
| **C. Malicious local process (same user)** | Clipboard readable by any process; plaintext resident in Qt widgets and Python objects for the whole session; "Show" paints cleartext on screen; no memory hygiene. | **Cannot protect** — and makes it worse than necessary by loading the whole vault eagerly. |
| **D. Untrusted DB contents** | `name`/`username`/`password` are `TextField`; rendered into Qt items and `'*' * len(password)`. No SQL is built from row data (peewee parameterizes). Low risk, but `len()` on a masked field leaks exact password length to the screen. | **Mostly protected**, minor length leak. |
| **E. Filesystem attacker** | Predictable path + predictable filenames, world-readable, no atomic writes, no `fsync`, no symlink protection, in-place verifier overwrite. | **Not protected.** |
| **F. Supply chain** | `pip freeze` committed; ~40 runtime deps for a job needing ~4; a committed PyInstaller binary in history. | **Large, unjustified surface.** |

**What it fundamentally cannot defend against:** a compromised local account (C) — no local password manager can, once secrets are decrypted in the user's own session. Everything else on this list is self-inflicted and fixable.

---

## 4. Master-Password Policy — the strength engine is meaningless

**Files:** `src/core/utils.py:33-45` (`entropy`, `entropy_ideal`); consumed by `createPasswordDialog.py:51-71`, `modifyMasterPasswordDialog.py:54-74`, `checkPasswordDialog.py:41-66`.

```python
def entropy(labels, base=None):
    value, counts = np.unique(labels, return_counts=True)
    norm_counts = counts / counts.sum()
    return -(norm_counts * np.log(norm_counts)/np.log(base)).sum()
```

This computes the Shannon entropy of the **character-frequency distribution of the one string being tested**, then divides by `log(length)` and calls the ratio a strength percentage.

**Why it is wrong:** it measures *how evenly distinct characters are spread within the string*, not how hard the string is to guess.
- `abcdefgh` → 8 distinct chars, ratio **100%** ("strong"). It is in every wordlist-adjacent brute space and trivially guessable.
- `Password1!Password1!` → repeated chars → ratio **well below 85%** ("weak"), despite being longer.
- A 40-character diceware passphrase of common words scores high on repetition-evenness yet is rejected anyway for lacking an uppercase/symbol.
- The composition rules (`< 8`, must-have special/lower/upper) reject strong passphrases and accept `Aa1!aaaa`.
- `entropy_ideal(1, ...) = 0` → the ratio does `x/0` → `nan` (numpy, no crash, but a nonsense display); `checkPasswordDialog` computes this before the length guard.

**Severity: HIGH** (a password manager that gives users false confidence about master-password strength, while rejecting genuinely strong ones).

**Remediation:** delete the entropy code entirely. Adopt: minimum length ≥ 12 (prefer ≥ 16 for passphrases), a check against the bundled common-password list, drop mandatory character-class rules, and use `zxcvbn` for an *advisory* guessability estimate shown to the user (never as a hard gate that blocks passphrases). Keep this UI heuristic conceptually separate from SQLCipher's KDF, which does the actual key stretching.

---

## 5. Cryptography Review

### 5.1 SQLCipher configuration — relies entirely on defaults (acceptable *today*, fragile tomorrow)
**Files:** `createPasswordDialog.py:87`, `authDialog.py:71`, `modifyMasterPasswordDialog.py:92`, dep `sqlcipher3-binary==0.6.0`.

The app never sets `cipher_page_size`, `kdf_iter`, `cipher_hmac_algorithm`, `cipher_kdf_algorithm`, or `cipher_compatibility`. It relies on the bundled SQLCipher's compile-time defaults (SQLCipher 4: AES-256-CBC, PBKDF2-HMAC-SHA512 × 256,000, HMAC-SHA512, 4096-byte pages). Those defaults are **fine right now**.

The risk is **silent divergence**: creation and reopen both use bare `SqlCipherDatabase(path, passphrase=...)`, so they agree *as long as the linked SQLCipher version never changes its defaults*. If a future `sqlcipher3-binary` bump changes a default, old vaults become unreadable with no migration path, because nothing is pinned in the file. **Severity: MEDIUM (Needs Investigation for the exact bundled defaults on the target machine).** Remediation: pin the cipher parameters explicitly via PRAGMAs at both create and open time so the configuration is a property of *your* code, not the library build.

### 5.2 f-string `PRAGMA key`/`PRAGMA rekey` — injection + breakage + redundancy — **CRITICAL**
**Files:** `modifyMasterPasswordDialog.py:93-94`, and dead-CLI twin `core/utils.py`→`database.py:128-129`.

```python
db = SqlCipherDatabase(database_path, passphrase=current_password)  # library binds passphrase SAFELY
db.execute_sql(f"PRAGMA key = '{current_password}';")               # redundant + unsafe
db.execute_sql(f"PRAGMA rekey = '{password}';")                     # unsafe
```

The constructor already hands the passphrase to the library through its safe binding path. The two manual `execute_sql` calls **re-do the keying by hand via string interpolation.** Test vectors:

- Master password `it's-a-secret` → `PRAGMA key = 'it's-a-secret';` → SQL syntax error → exception.
- Backslash, `\x00`, or an unbalanced quote → malformed statement.
- `a' --` style content → statement corruption.

Because a single `execute_sql` compiles one statement, the realistic outcomes are (a) an exception, or (b) rekey to a **truncated** value (e.g. `ab` from `ab'cd`). Both are catastrophic in this code path — see §5.3. **Severity: CRITICAL.** Remediation: delete both manual PRAGMA lines; rekey through the library's supported mechanism, never string formatting.

### 5.3 Non-atomic rekey + separate verifier = permanent lockout — **CRITICAL**
**File:** `modifyMasterPasswordDialog.py:77-97`. Sequence:

1. line 90: **overwrite** the bcrypt verifier file with the *new* password's hash.
2. line 92-93: open DB with **current** password, `PRAGMA key = current`.
3. line 94: `PRAGMA rekey = new`.

If anything between step 1 and a *successful* step 3 fails — a quote in the new password (§5.2), a crash, a full disk, an interrupted page rewrite — the verifier now attests the **new** password while the vault is still encrypted with the **old** key. Login (§6) checks only the verifier, so it *accepts* the new password, then fails to decrypt the vault. **The user is locked out of every credential, permanently, with no recovery path.** There is no transaction, no temp-file-and-rename, no rollback, no re-derivation-from-vault fallback. **Severity: CRITICAL.**

Crash-window analysis requested in the brief:
- **before verifier update:** safe (nothing changed).
- **after verifier update, before rekey completes:** **lockout** (verifier=new, vault=old).
- **during page rewrite:** SQLCipher rekey rewrites every page; interruption can corrupt the DB *and* the verifier already points to new → **lockout + possible corruption**.
- **immediately after rekey:** safe *only if* verifier write (step 1) already flushed; but the ordering is backwards regardless.

Remediation: rekey the vault **first**; only after the library confirms success and the DB reopens cleanly with the new key, write the verifier — atomically (temp file + `fsync` + `os.replace`). Better: eliminate the verifier entirely (§5.4) so there is nothing to desynchronize.

### 5.4 Why a separate bcrypt verifier at all? — it should not exist
**Files:** written in `createPasswordDialog.py:74,82-83`; read in `authDialog.py:65-67` and `modifyMasterPasswordDialog.py:81-83`.

The bcrypt sidecar provides **no useful authentication that SQLCipher doesn't already provide**, and it introduces four failure modes: (1) an extra, *cheaper* offline oracle over the same secret (§3B); (2) desync with the vault key (§5.3); (3) "verifier accepts but vault won't decrypt"; (4) "vault rekeyed but verifier not updated." It also silently **truncates the master password to 72 bytes** (bcrypt's limit) while SQLCipher uses the full string — so two long passphrases sharing a 72-byte prefix are indistinguishable to the verifier but distinct to the vault. **Severity: HIGH (compounds the CRITICALs).** Remediation: delete the verifier. Authentication = "did the vault decrypt?" — verified by opening SQLCipher and running a cheap sentinel query (e.g. `SELECT count(*) FROM sqlite_master`). That is the only source of truth that cannot desynchronize.

---

## 6. Authentication Review

**File:** `authDialog.py:60-85`.

"Authenticated" currently means **`bcrypt.checkpw` succeeded against the sidecar file** — line 67. On success it constructs a lazy `SqlCipherDatabase` and rebinds `Password._meta.database` (global mutable model state), then emits `login_successful`. **The vault is never actually opened or verified here** — peewee connects lazily, so the first genuine key test is `Password.select()` inside `MainWindow.populatePasswordTable()` (`mainWindow.py:78`), which has no error handling. Consequences of the decoupling, by scenario:

| Scenario | Actual behavior | Should be |
|---|---|---|
| Correct password | works | works |
| Wrong password | bcrypt rejects | rejected via failed vault decrypt |
| **Verifier present, DB absent** | `initUI` (db-missing branch) launches *create* dialog → **new verifier overwrites old**, new empty DB created | detect + refuse |
| **DB present, verifier absent** | `authenticateUser` does `open(passwd_path)` with **no guard** → `FileNotFoundError` → unhandled crash | detect + refuse/recover |
| **Verifier/DB key mismatch** (post-failed-rekey) | bcrypt **accepts**, then `Password.select()` throws "file is not a database" unhandled → traceback/crash | reject: vault is the authority |
| Corrupt DB | login "succeeds", crashes on first query | reject at open |
| Empty verifier file | `str.encode(f.readline())` → bcrypt error/exception unhandled | reject |
| Unreadable files (perms) | unhandled `PermissionError` | reject with message |

**Severity: CRITICAL** (authentication does not demonstrate vault access; it can green-light a session that cannot decrypt). The property the brief asks for — *authentication proven by opening the encrypted vault* — is **not** satisfied. Remediation folds into §5.4: open the vault, run a sentinel query inside a `try`, and treat success as the sole authentication signal.

---

## 7. Secret Lifecycle Review

- **Eager bulk decryption:** `mainWindow.py:78` `Password.select()` decrypts **every** record at once merely to show a masked table. All plaintext passwords then live on `Password` instances for the whole session, and each is captured again inside a per-row `lambda: self.copyToClipboard(password)` / `togglePasswordVisibility` closure (`mainWindow.py:102-107,121`). **Severity: MEDIUM.** Load rows lazily; decrypt a single password only at copy/show time.
- **Show-in-place:** `togglePasswordVisibility` (`:124-136`) paints the cleartext into a visible cell that persists until toggled back; masked mode uses `'*' * len(password)`, leaking exact length. **MEDIUM.**
- **Clipboard (`mainWindow.py:110-117`):** `QApplication.clipboard().setText(password)`; `self.copied_password = password` (retains plaintext on the widget); `QTimer(3000)` → `subprocess.run('xsel -bc', shell=True, check=True)`. Problems, all confirmed:
  - **Clobbers the user's newer clipboard:** after 3s it wipes the clipboard unconditionally; if the user copied something else in that window, that value is destroyed. It never checks whether the clipboard still holds *the secret it placed* (that's exactly what `self.copied_password` is for, and it's ignored).
  - **`xsel` is X11-only:** no-op/failure on Wayland (`wl-copy`), macOS, Windows. `check=True` turns a missing `xsel` into an unhandled `CalledProcessError`/`FileNotFoundError` inside a Qt timer callback → crash.
  - **`shell=True` is unjustified** — no shell features are used; it only adds injection surface and portability cost.
  - **Redundant:** Qt already owns the clipboard cross-platform. Clearing via a separate external tool that doesn't share Qt's view is why the "still ours?" check was dropped.
  - Clipboard managers may retain the secret regardless. **Severity: MEDIUM-HIGH.** Remediation: clear via `QApplication.clipboard()`, and only if its current text still equals the secret; drop `xsel`/`subprocess` entirely; don't stash `copied_password` longer than needed.
- **Exception messages:** dialogs do `QMessageBox.critical(self, "Error", str(e))` — raw DB/exception text to the user; low risk of secret leakage but leaks internals. **LOW.**

---

## 8. Database / Data-Integrity Review

**File:** `core/database.py`.

- **No uniqueness constraint.** `name = TextField()` with `class Meta: pass`. "Name already exists" is enforced only by application-level `Password.get()` lookups, which race and can't stop duplicates. **MEDIUM.**
- **Exception-as-control-flow, dangerous form** (`database.py:21-33`):
  ```python
  try:
      if Password.get(Password.name == input_name) is not None:
          print("already exists")
      else:
          Password.create(...)
  except Exception as e:
      Password.create(...)   # ANY error → create anyway
  ```
  `Password.get` **raises `DoesNotExist`** when absent (it never returns `None`, so the `else` and the `is not None` are dead). The intended "not found → create" path only works *by falling into the bare `except`* — which also fires on a locked DB, a decryption failure, or any transient error, silently creating a (possibly duplicate) record and masking real faults. **Severity: HIGH** (a real DB error is indistinguishable from "record absent" and results in a write).
- **GUI CRUD dead branches:** `updatePasswordDialog.py:37`, `deletePasswordDialog.py:30` check `if existing_entry is None:` — unreachable, since `get` raises. Harmless but reveals the author's mental model was wrong about the API.
- **No transactions** around create/update/delete; no atomicity for multi-step ops. **LOW-MEDIUM.**
- **`print_passwords` (`database.py:36-45`)** builds an `np.zeros((n,5), dtype=object)` array to hold **plaintext passwords** and prints them via `tabulate` — dead CLI, but it's a NumPy dependency and a plaintext dump rolled into one.

---

## 9. Filesystem / Storage Review

**Files:** the string `f"/home/{getpass.getuser()}/PetitePass"` appears in **six** places: `core/main.py:9`, `core/database.py:78`, `authDialog.py:32,43,61`, `createPasswordDialog.py:75`, `modifyMasterPasswordDialog.py:78`. The two magic filenames appear alongside each.

- **Hard-coded Linux path.** Breaks on macOS (`/Users/...`), Windows entirely. **HIGH for portability**, and the app is otherwise cross-platform Qt.
- **`getpass.getuser()` under sudo** returns whatever `$USER`/`$LOGNAME` says — can point at root's or the wrong user's home; combined with root-owned file creation this produces files the real user can't read. **MEDIUM.**
- **No permission hardening.** Directory created `os.makedirs(path)` (0755), files written with default umask (0644). **The bcrypt verifier and the encrypted DB are world-readable.** On a multi-user box, any user reads the vault and grinds the verifier offline. **Severity: HIGH.** Remediation: create the dir `0700`, files `0600`.
- **Predictable filenames.** `5f4dcc3b5aa765d61d8327deb882cf99` = `MD5("password")`; the `.db` name is a fixed constant. Not a vulnerability by itself (security ≠ obscurity), but it's a tell and it's copy-pasted everywhere.
- **No atomic writes / no `fsync`.** Verifier written in place with `open(..., "wb")`; a crash mid-write corrupts it → lockout. **MEDIUM.**
- **No symlink/O_NOFOLLOW protection**, predictable path → a local attacker can pre-plant a symlink at the known location. **MEDIUM.**

Remediation: use `platformdirs.user_data_dir("PetitePass")` (already a transitive dep!), enforce `0700`/`0600`, write via temp-file + `fsync` + `os.replace`, and centralize all of this in one `paths.py`.

---

## 10. Secret Lifecycle / Clipboard — see §7. (Consolidated there.)

---

## 11. Dependency / Supply-Chain Review

`requirements.txt` is a committed `pip freeze` (58 pins). Classification of what the **runtime** actually imports:

| Genuinely required (runtime) | Why |
|---|---|
| `PyQt5`, `PyQt5-Qt5`, `PyQt5-sip` | GUI |
| `peewee` | ORM |
| `sqlcipher3-binary` | encrypted DB |
| `bcrypt` | verifier (to be removed — then this goes too) |
| `numpy` | **only** for the entropy calc + `print_passwords` — removable with the entropy code |
| `tabulate` | only dead CLI `print_passwords` |
| `pyperclip` | imported in `mainWindow.py:1` and **never used** (clipboard goes through Qt/xsel) |

| Should not be here (build/dev/unused/pip-freeze noise) |
|---|
| `numba`, `llvmlite` — JIT compiler stack, unused |
| `gTTS`, `pydub`, `pyttsx3` — text-to-speech, entirely unrelated |
| `matplotlib` support cast: `fonttools`, `kiwisolver`, `cycler`, `pyparsing` — no plotting in app |
| `requests`, `urllib3`, `certifi`, `charset-normalizer`, `idna`, `pooch` — no network code exists |
| `joblib`, `threadpoolctl`, `decorator` — scientific transitive noise |
| `pyinstaller-hooks-contrib`, `altgraph` — build-only |
| `pip-upgrader`, `virtualenv`, `autopep8`, `pycodestyle`, `distlib`, `filelock`, `docopt`, `colorclass`, `terminaltables` — dev/tooling |
| `Jinja2`, `MarkupSafe`, `itsdangerous`, `click`, `asgiref`, `sqlparse` — web-framework transitives, unrelated |
| `platformdirs`, `appdirs` — present transitively; `platformdirs` *should* be used (it isn't) |

**A local password manager is pulling in a JIT compiler, a plotting font engine, an HTTP stack, and two TTS libraries.** Every one is attack surface and a Dependabot treadmill (the entire recent git history is Dependabot bumps to `zipp`, `virtualenv`, `pip-upgrader` — packages the app never imports). **Severity: MEDIUM (supply-chain surface + maintenance drag).** Remediation: replace with a curated ~5-line runtime list (`PyQt5`, `peewee`, `sqlcipher3-binary`, `platformdirs`, `zxcvbn`) and a separate `requirements-dev.txt`. A `pip-audit` run should be added to CI against the *curated* list; I could not run it here (no venv), so **the specific CVE surface is Needs Investigation**, but shrinking the list is the correct first move regardless.

**History:** a PyInstaller binary `petitepass_package/bin/petitepass` was committed and later removed (`4260344` add, `88b2963` remove). It remains in git history (blob `97d8b52…`) — bloat, and a reproducibility/trust concern (opaque binary in VCS). No real `.db` or verifier files were ever committed, and I found **no plaintext secrets, keys, or tokens** in history. The maintainer's email in the Debian `control` file is public-by-design, not a leak.

---

## 12. Password Generator Review

**File:** `core/utils.py:21-30, 48-83`.

- **RNG: correct.** `secrets.choice` — cryptographically secure, no modulo bias. ✅
- **Length validation:** `< 2` rejected; GUI `QIntValidator(1,1024)` caps it. The `< 2` floor is arbitrary but harmless.
- **`RANDOM_STRING_CHARS = string.printable` minus whitespace** — includes shell/JSON/SQL-hostile characters (`'"\`\`$;|&<>`). Cryptographically fine; an **interoperability** hazard in terminals, web forms, and — ironically — in *this app's own* f-string PRAGMA path (§5.2). Distinguish strength from usability: keep a strong default alphabet but make the "all printable" set opt-in with a warning.
- The generator recomputes the meaningless entropy ratio (`:78-80`) and discards it — dead computation, another NumPy tie-in.
- **Severity: LOW** (generator is cryptographically sound; only interop polish needed).

---

## 13. GUI Correctness & Security

- **GUI state as source of truth** (`Password._meta.database` rebinding, global `db`, `login_successful` signal as the auth authority) — the central architectural defect; see §6, §14.
- **`populatePasswordTable` runs `Password.select()` on the UI thread** with no error handling — a wrong key or corrupt DB throws an unhandled exception during window setup. **HIGH** (crash + it's the de-facto real auth check that nobody guards).
- **Missing `return` after the weak-password check** (`createPasswordDialog.py:70-71`, `modifyMasterPasswordDialog.py:73-74`): the `entropy_ratio < 85` branch warns but **falls through and creates/rekeys anyway**. The "too simple" gate is toothless. **MEDIUM.**
- **Destructive ops unconfirmed:** delete removes a record with no "are you sure?"; modify-master has no backup step before an irreversible rekey. **MEDIUM.**
- `pyperclip` imported unused; PyQt widget wildcard imports copied into every file. **LOW.**
- `PasswordDialog.savePassword` (`passwordDialog.py:34-44`): if `Password.get` *succeeds* (name exists) it warns but **does not `return`** and does not `reject` — the dialog just sits; acceptable but sloppy. Password field has no `setEchoMode(Password)` in create/update dialogs, so new passwords are typed in cleartext on screen. **LOW-MEDIUM.**

---

## 14. Error Handling & Corruption Resistance

Operations classified by atomicity need:

| Operation | Needs atomicity? | Current state |
|---|---|---|
| Initial vault creation | Yes (verifier + DB must agree) | verifier written unconditionally, DB only if absent; mismatch windows exist |
| Password insert/update/delete | Yes (single-row, but should be transactional) | no explicit transaction; broad `except` masks failures |
| **Master-password rekey** | **Critically yes** | **non-atomic, verifier-first, no rollback → §5.3 lockout** |
| Backup/restore | Yes | **does not exist** (README TODO) |

Broad `except Exception` audit — every occurrence and its risk:
- `database.py:29` → **creates a record on any error** (§8). Worst offender.
- `database.py:58,71` (CLI) → swallow, print `e`. Dead code.
- `createPasswordDialog.py:95`, `modifyMasterPasswordDialog.py:98`, `passwordDialog.py:42`, `updatePasswordDialog.py:50`, `deletePasswordDialog.py:38`, `generatePasswordDialog.py:43` → convert any failure into a message box; in the master-password paths this means a **partly-applied rekey is reported to the user as a generic error with the verifier already changed** (§5.3).

**Silent data loss paths:** failed rekey (lockout), verifier overwrite on the DB-absent login branch, non-atomic verifier writes. **Severity: CRITICAL in aggregate.**

---

## 15. Testing Gaps

There are **zero** tests. CI (`python-app.yml`) only runs flake8 and installs the bloated requirements. Minimum critical suite, focused on invariants and data survival (integration against **real** SQLCipher, not mocks):

**Authentication:** correct pw opens vault; wrong pw refused; Unicode master pw round-trips; master pw containing `'`, `"`, `\`, spaces round-trips; missing verifier handled; missing DB handled; corrupt DB refused (no crash); verifier/DB mismatch refused (asserts vault is the authority).

**Rekey (the highest-value tests):** correct current pw rekeys and the DB **reopens** with the new key; wrong current pw refused with no change; new pw with special chars round-trips; **simulated crash between verifier-write and rekey leaves a *recoverable* state** (this test should fail today and drive the redesign); reopen-after-rekey across a fresh process.

**Vault ops:** create; duplicate create rejected **by a DB constraint**; update persists; delete persists; all survive a process restart.

**Clipboard:** secret is cleared after the interval; a value the user copied *after* PetitePass is **not** erased.

**Generator:** exact length; alphabet honored; asserts `secrets` (CSPRNG) is the source; length edge cases.

**Filesystem:** dir is `0700`, files `0600`; missing dirs created; read-only FS surfaces a clean error; corrupt/empty verifier handled.

---

## 16. Testing Gaps — (consolidated into §15)

---

## 17. Repository / Packaging Problems

- **README clone URL is wrong:** `github.com/araujo88/PetitePass` (repo is `leo-aa88/PetitePass`); Debian `control` `Homepage` too. **LOW.**
- **Makefile is broken:** `setup` does `source env/bin/activate` but creates `.env`; `build` copies to `petitepass_package/bin/petitepass` (dir not in repo); `install` copies `dist/PetitePass` but build produced `dist/petitepass`, and installs to `/usr/bin/PetitePass` while `mkdir /opt/PetitePass` unused. None of it runs cleanly. **MEDIUM.**
- **`make build` re-commits a binary** into `petitepass_package/bin/` — the exact artifact already scrubbed from history once. **MEDIUM.**
- **`10k-most-common.txt` lives at `petitepass_package/usr/share/`** but code reads `/usr/share/10k-most-common.txt` (only present after `.deb` install) — running from source, the "too common" check silently fails (caught `FileNotFoundError` → returns `False`). **MEDIUM.** Duplicated source-of-truth risk if the file is ever also shipped elsewhere.
- **Python pinned to 3.10** in CI and README while deps have moved on; no `mypy`/`ruff`/`pip-audit`/`pytest` in CI. **LOW.**
- `.gitignore` correctly ignores the vault/verifier filenames — good. No secrets found in history (§11).

---

## 18. Remediation Roadmap

### Phase 0 — Stop-the-bleeding (before anyone stores a real credential)
1. Remove the two manual `PRAGMA key`/`PRAGMA rekey` f-string calls; rekey only through the library API (§5.2).
2. Make rekey atomic and vault-first: rekey → reopen with new key → only then write verifier via temp+`fsync`+`os.replace`; on any failure, leave the old state intact (§5.3).
3. Harden permissions: dir `0700`, files `0600` (§9).
4. Fix the clipboard: clear via Qt only if it still holds our secret; drop `xsel`/`shell=True` (§7).
5. Add the missing `return` on the weak-password branches, or (better) replace the policy — see Phase 1.

### Phase 1 — Establish security invariants
1. **Delete the bcrypt verifier;** authentication = successful SQLCipher open + sentinel query (§5.4, §6).
2. Introduce a single `Vault` service that owns open/create/rekey/CRUD with transactions and atomic file I/O.
3. Replace the entropy engine with a length/passphrase policy + `zxcvbn` advisory (§4).
4. Pin cipher parameters explicitly so config is owned by code (§5.1).
5. Land the §15 test suite against real SQLCipher, especially the rekey-crash and quote-in-password cases.

### Phase 2 — Architecture cleanup
1. Delete the dead CLI (`core/main.py`, CLI functions in `utils.py`/`database.py`).
2. Centralize paths/filenames (six copies → one `paths.py` on `platformdirs`).
3. Remove `import *`; move all DB logic out of dialogs into the `Vault` service.
4. Lazy-load rows; decrypt one password only on copy/show.

### Phase 3 — Modernization
Curated `requirements.txt` (~5 runtime deps) + `requirements-dev.txt`; add `ruff`, `mypy`, `pytest`, `pip-audit` to CI; fix Makefile/README/packaging; stop committing binaries; cross-platform paths.

### Phase 4 — Optional product improvements
Backup/restore (encrypted, atomic), auto-lock timeout, password history, search, per-entry copy-username.

---

## 19. Deletion List

Delete rather than refactor:
- `src/core/main.py` — dead, broken CLI (wrong import roots, references undefined `Password._meta.is_auth`).
- `create_password`, `update_password`, `delete_password`, `change_db_password`, `print_passwords` in `core/database.py` — dead CLI logic; the model stays, the functions go.
- `entropy`, `entropy_ideal`, `verify_password`, `cls`, `check_privileges` in `core/utils.py` — meaningless or unused.
- The entire bcrypt sidecar mechanism (`5f4dcc…` file + all its readers/writers) — replaced by vault-decrypt auth.
- Both manual `PRAGMA key`/`PRAGMA rekey` string-built statements.
- `pyperclip` import; the `xsel`/`subprocess` clipboard clear.
- `requirements.txt` as-is → regenerate curated. Drop `numba`, `llvmlite`, `gTTS`, `pydub`, `pyttsx3`, `matplotlib` font stack, `requests`+HTTP transitives, `numpy`, `tabulate`, dev tooling.
- `make build`'s binary-into-repo step; scrub the historical `petitepass_package/bin/petitepass` blob if history is ever rewritten.

---

## 20. Findings Table

| ID | Severity | Component | Finding | Root Cause | Recommended Fix |
|----|----------|-----------|---------|------------|-----------------|
| F1 | CRITICAL | `modifyMasterPasswordDialog.py:90-94` | Non-atomic rekey writes verifier before rekey; failure → permanent lockout | No transactional rotation; auth ≠ encryption | Rekey→reopen→then atomic verifier write; ideally drop verifier |
| F2 | CRITICAL | `modifyMasterPasswordDialog.py:93-94`, `database.py:128-129` | `PRAGMA key/rekey` built with f-strings; quotes break/mangle key | Reimplementing library keying via string interpolation | Delete manual PRAGMAs; use library key API |
| F3 | CRITICAL | `authDialog.py:60-85` + `mainWindow.py:78` | Auth decided by sidecar bcrypt, not by vault decrypt; mismatch → crash/false-accept | Authentication and encryption treated as separate systems | Auth = open SQLCipher + sentinel query |
| F4 | HIGH | verifier file, `createPasswordDialog.py:82` / `authDialog.py:65` | Separate bcrypt file is a cheaper offline oracle + desync source + 72-byte truncation | Redundant second auth system | Remove verifier entirely |
| F5 | HIGH | `core/utils.py:33-45` + all 3 dialogs | Shannon-frequency "strength" is security-meaningless; rejects strong passphrases | Misunderstanding of entropy vs guessability | Replace with length policy + common-list + zxcvbn advisory |
| F6 | HIGH | `core/database.py:29-31` | `except Exception: create_anyway` — any DB error creates a record | Exception-as-control-flow | Use `DoesNotExist` narrowly; DB unique constraint |
| F7 | HIGH | `authDialog.py:32`, `createPasswordDialog.py:75`, +4 | World-readable verifier+DB in predictable hard-coded Linux path | No permission hardening; no platformdirs | `0700`/`0600`; `platformdirs`; centralize |
| F8 | MEDIUM | `mainWindow.py:110-117` | Clipboard cleared unconditionally via `xsel -bc` shell=True; clobbers user's clipboard; non-portable; crashes if xsel absent | External tool duplicating Qt; ignores `copied_password` | Qt-only clear guarded by "still ours"; drop subprocess |
| F9 | MEDIUM | `mainWindow.py:78,124-136` | Whole vault decrypted eagerly; plaintext resident in models/closures; Show paints cleartext + length leak | GUI holds decrypted state | Lazy load; decrypt per-action |
| F10 | MEDIUM | `core/database.py:11-19` | `name` not unique at DB level; dup prevention is racy app logic | No schema constraint | `unique=True` + handle IntegrityError |
| F11 | MEDIUM | `createPasswordDialog.py:70`, `modifyMasterPasswordDialog.py:73` | Missing `return` → weak password accepted despite warning | Copy-paste elif chain | Restructure validation to hard-gate |
| F12 | MEDIUM | `requirements.txt` | Committed `pip freeze`: ~40 unused deps incl. Numba/gTTS/requests | `pip freeze` as dependency management | Curated runtime list + dev list; pip-audit in CI |
| F13 | MEDIUM | `Makefile`, README, `control` | Broken build/install targets; wrong clone URL; binary re-commit | Unmaintained packaging | Fix or replace packaging; wheel/pipx |
| F14 | MEDIUM | `checkPasswordDialog.py:50` etc. | Common-password file read from `/usr/share` absent when run from source → check silently no-ops | Path/source-of-truth split | Bundle file as package data; single path |
| F15 | LOW | `core/utils.py:16-17,54-55` | Generator "all printable" includes shell/SQL-hostile chars | Strength/interop conflated | Strong default alphabet; opt-in with warning |
| F16 | LOW | many | `import *`, unused `pyperclip`, dead CLI, dead `is None` branches | Legacy cruft | Delete dead code; explicit imports |
| F17 | LOW | `create/updatePasswordDialog` | New-password fields not masked; delete unconfirmed | UX oversight | `setEchoMode`; confirm destructive ops |
| F18 | INFO | git history | PyInstaller binary in history; no secrets found | Committed artifact | Optional history scrub |

---

## 21. Final Decision

**C — REBUILD CORE.**

The product concept and the Qt front-end are worth keeping. The security core is not patchable in place because its defects are not independent — F1, F2, F3, F4, and the F14/clipboard/permission issues all descend from **one** decision: *there is no Vault abstraction, so authentication (a bcrypt sidecar) and encryption (SQLCipher) were built as two systems that must be kept in sync by hand, and the GUI dialogs own that hand-syncing.* You cannot incrementally fix "the verifier can desync from the vault" while the verifier exists; you cannot incrementally fix "rekey isn't atomic" while dialogs run raw `execute_sql`; you cannot incrementally fix auth while the source of truth is a file named after the MD5 of "password."

The right move is a small, single `Vault` service (open/create/rekey/CRUD, atomic file I/O, vault-decrypt as the sole auth signal, cipher params pinned in code), the bcrypt verifier deleted, the entropy engine replaced, dependencies cut to the handful actually imported, and the dead CLI removed. The dialogs then call the Vault instead of doing crypto. That is a **core rebuild behind the existing UI**, not a refactor of the existing core — and until it's done, PetitePass should not hold anyone's real passwords.
