# PetitePass — Design & Threat Model

This document describes how PetitePass is built and what it defends against. It is the reference for the invariants that security-relevant changes must preserve.

- [1. Design goals](#1-design-goals)
- [2. Architecture](#2-architecture)
- [3. The core invariant: authentication is decryption](#3-the-core-invariant-authentication-is-decryption)
- [4. Cryptography](#4-cryptography)
- [5. Vault-file operations and durability](#5-vault-file-operations-and-durability)
- [6. Secret lifecycle](#6-secret-lifecycle)
- [7. Filesystem & storage](#7-filesystem--storage)
- [8. Threat model](#8-threat-model)
- [9. Invariants (do not regress)](#9-invariants-do-not-regress)

* * *

## 1. Design goals

1. **Local and offline.** No network code exists. The trust boundary is the user's account and disk.
2. **One source of truth.** The encrypted vault file is authoritative. Nothing else (no sidecar hash, no config) can grant or deny access.
3. **Fail safe.** Any operation that rewrites the vault must be atomic, committing at a single `os.replace`: a failure *before* the commit leaves the previous vault openable; a failure *after* it is reported distinctly (the new vault is now in place). Never a torn or ambiguous state. See §5.
4. **Small and auditable.** A handful of runtime dependencies; the GUI is a thin shell over a single service.

## 2. Architecture

```
                         ┌──────────────────────────────────────────┐
   PyQt5 GUI (gui/)      │                core/                     │
 ┌───────────────────┐   │  ┌────────────────────────────────────┐  │
 │ AuthDialog        │──▶│  │ Vault (vault.py)                   │  │
 │ MainWindow        │   │  │  create / open / rekey             │  │
 │ *Dialog widgets   │──▶│  │  backup_to / restore_from          │  │
 └───────────────────┘   │  │  list / get / add / update / delete│  │
        │ calls only      │  └───────────────┬────────────────────┘  │
        │ VAULT.* and      │                 │ binds                  │
        │ pure helpers     │  ┌──────────────▼─────────┐             │
        ▼                   │  │ Password model (peewee)│             │
  strength.py, utils.py     │  └──────────────┬─────────┘             │
  (no vault access)         │  paths.py  ─────┘  credential.py         │
                            └──────────────────────────────────────────┘
                                             │ SQLCipher (pinned pragmas)
                                             ▼
                                    encrypted vault file
```

**Responsibility boundaries**

| Module                | Owns                                                                                  |
| --------------------- | ------------------------------------------------------------------------------------- |
| `core/vault.py`       | The connection, the master password (in memory only), all vault-file operations, CRUD |
| `core/database.py`    | The peewee `Password` schema — an implementation detail of the Vault                  |
| `core/credential.py`  | `Credential`, a **passwordless** domain object used for listing                        |
| `core/paths.py`       | Data directory, file permissions, legacy migration, fsync helpers                     |
| `core/strength.py`    | Master-password policy (length + common list + zxcvbn score)                          |
| `core/utils.py`       | CSPRNG password generation                                                            |
| `gui/*`               | Presentation only — talks to `VAULT.*` and the pure helpers, never to peewee          |

The GUI does not import `peewee` or the `Password` model. This is enforced by keeping all credential operations on the `Vault`.

## 3. The core invariant: authentication is decryption

Older versions kept a bcrypt hash of the master password in a sidecar file and treated "bcrypt matched" as authenticated. That is a second, weaker oracle that can desynchronize from the SQLCipher key. It has been removed.

Authentication now works like this:

1. `Vault.open(master)` constructs a SQLCipher connection with `master` as the passphrase.
2. It runs a **sentinel query** — `SELECT 1 FROM password LIMIT 1`.
   - Resolving the table forces SQLCipher to decrypt page 1, so a wrong key raises `DatabaseError` (HMAC failure).
   - Requiring the application table additionally rejects a *hollow* file (a 0-byte or empty SQLite file, which SQLCipher would otherwise initialize under any key).
3. Only if the sentinel succeeds is the global model bound to the connection. A failed unlock never leaves the model pointing at a closed, wrong-key connection.

An empty master password is refused up front (`_require_nonempty`): peewee omits `PRAGMA key` for a falsy passphrase, which would produce a *plaintext* database. A NUL byte is refused for the same reason (peewee raises `ValueError` from `PRAGMA key='%s'`).

## 4. Cryptography

- **Library:** SQLCipher 4 via `sqlcipher3-binary`, bound through `playhouse.sqlcipher_ext`.
- **Passphrase handling:** the master password reaches SQLCipher only through peewee's quote-escaping `passphrase=` / `rekey()` path (`PRAGMA key='%s'` with `'` doubled). The application never builds `PRAGMA` statements with its own string interpolation — that was the historical injection/corruption bug.
- **Pinned cipher parameters** (set on every connection via `_make_db`, so a future library default change cannot silently make old vaults unreadable):

  | Parameter                | Value                |
  | ------------------------ | -------------------- |
  | `cipher_page_size`       | 4096                 |
  | `kdf_iter`               | 256000               |
  | `cipher_hmac_algorithm`  | HMAC_SHA512          |
  | `cipher_kdf_algorithm`   | PBKDF2_HMAC_SHA512   |

  These are the SQLCipher 4 defaults, so vaults created before pinning open unchanged.

- **Key stretching vs. UI policy.** SQLCipher's KDF does the cryptographic stretching. `strength.py` is a *UI policy* layer (minimum length, common-password blocklist, minimum zxcvbn score) and is deliberately independent of the KDF.

## 5. Vault-file operations and durability

Any operation that replaces the vault file uses the same discipline:

```
1. work on a COPY, never the live file in place
2. fsync the copy               (fatal — a failed flush aborts before the commit)
3. os.replace(copy, vault)      (the single atomic commit point)
4. fsync the directory          (best-effort, post-commit)
5. reopen / verify              (post-commit failures are reported distinctly)
```

**Rekey (`rekey`)** copies the closed vault to `<vault>.rekey.tmp`, rekeys and verifies that copy on a fresh connection, then `os.replace`s it in. A crash before the replace leaves the original under the old key; the temp file is inert garbage that `open()` deletes. If the post-commit reopen fails, `VaultRotatedError` is raised (never an auth error) so the UI does not tell the user their current password was wrong after the key already changed.

**Restore (`restore_from`)** verifies the backup decrypts under the supplied master *before* touching anything, copies it to `<vault>.restore.tmp`, re-verifies the copy, then `os.replace`s it in. Post-commit reopen failure raises `VaultRestoredError`. A leftover `.restore.tmp` is cleaned by `open()`.

**Backup (`backup_to`)** copies the vault to `<dest>.tmp`, opens that copy under the current master to prove it is a decryptable vault, then commits it to `dest`. It refuses a destination that resolves to the live vault file.

**Legacy migration** (`paths._migrate`) uses the identical shape: fatal fsync of the copy, atomic replace, best-effort post-commit cleanup, and it deletes the old vault only after the new one is committed. If migration cannot complete, the legacy path is used in place — the user is never shown an empty vault.

## 6. Secret lifecycle

- The master password is held only on the live `Vault` (in memory) while unlocked; `close()` drops it.
- The table lists **passwordless** `Credential` summaries — `list_credentials()` selects only `name`/`username`/timestamps, so plaintext is never loaded merely to render the (masked) list.
- A password is fetched (`get_password`) only when the user copies or reveals one.
- Copied passwords are auto-cleared, and only if the clipboard still holds the value PetitePass placed there.
- Auto-lock closes the vault, re-masks any revealed cells, and clears the clipboard.

## 7. Filesystem & storage

- Data directory: `platformdirs.user_data_dir("PetitePass", appauthor=False)` — `~/.local/share`, Application Support, or `%LOCALAPPDATA%`.
- Directory mode `0700`, vault-file mode `0600` (POSIX; no-ops on Windows).
- The vault filename is a fixed constant kept for backward compatibility.
- Writes that matter are atomic (temp + `fsync` + `os.replace`).

## 8. Threat model

| # | Scenario                                         | Can PetitePass defend?                                                                                          |
| - | ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| A | Attacker steals the vault file                   | **Partially** — cost equals the master password against PBKDF2-HMAC-SHA512 × 256 000. Choose a strong master.   |
| B | Attacker steals vault + any auxiliary files      | **Yes** — there is no sidecar verifier; nothing cheaper than SQLCipher to attack.                              |
| C | Malicious process under the same user account    | **No** — once unlocked, secrets are in the session; no local manager can prevent this. Auto-lock narrows it.    |
| D | Untrusted / corrupt vault contents               | **Yes** — wrong-key, hollow, and non-vault files are refused at unlock; peewee parameterizes row SQL.           |
| E | Filesystem attacker (perms, races, replacement)  | **Mostly** — `0600`/`0700`, atomic writes. A user who can already write your files can still tamper.            |
| F | Supply chain                                     | **Reduced** — a curated ~5-package runtime; `pip-audit` gates CI.                                              |

What PetitePass fundamentally **cannot** do: protect decrypted secrets from other code running as you (C). Everything else on this list is addressed by design.

## 9. Invariants (do not regress)

A change that violates any of these is a security regression, regardless of whether tests pass:

1. Authentication succeeds **only** if the vault decrypts and the `password` table is present.
2. The master password reaches SQLCipher **only** through peewee's escaping API — never application-built `PRAGMA` strings.
3. An empty or NUL master password is refused before any file is created or replaced.
4. Every vault-replacing operation (rekey, restore, migration) is atomic: it works on a verified copy and commits with a single `os.replace`. The `fsync` of the copy is fatal (never swallowed). **Before** the commit, any failure leaves the previous vault openable under the current master and restores the session. **After** the commit, the vault is the new one — see invariant 5.
5. A failure to reopen the session **after** the `os.replace` commit is reported as a distinct error (`VaultRotatedError` for rekey, `VaultRestoredError` for restore), never as an auth/"wrong password" error. The rotation/restore has committed: the old master no longer opens the vault, and the user must unlock with the new/backup master. (Only `paths._migrate`, whose post-commit steps are pure cleanup, never flips its result after the commit.)
6. The GUI never accesses the ORM directly; all credential access goes through the `Vault`.
7. The credential list never loads password ciphertext to render the table.
8. New security-relevant behavior ships with tests against **real** SQLCipher.
