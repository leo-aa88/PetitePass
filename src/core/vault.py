"""The single Vault abstraction: authentication *is* decryption.

This replaces the old design where a sidecar bcrypt file
(``5f4dcc3b5aa765d61d8327deb882cf99``) was the authentication authority, kept
in sync with the SQLCipher key by hand across several GUI dialogs. That design
allowed a session to be reported "authenticated" while the vault could not
decrypt, and let the verifier desynchronize from the key.

Here the only proof of authentication is successfully decrypting the vault. The
master password reaches SQLCipher only through peewee's quote-escaping
passphrase/rekey API (``PRAGMA key='%s'`` with ``'`` doubled), never through
the application's own unescaped f-strings, which was the historical injection
and vault-corruption bug.

Durability of the master-password change: SQLCipher's ``rekey`` rewrites every
page and is journaled, but to be safe against a failure part-way through we
take an on-disk backup first and restore it if the rekey cannot be verified
with the new key on a fresh connection.
"""
import os
import shutil

from peewee import DatabaseError, IntegrityError
from playhouse.sqlcipher_ext import SqlCipherDatabase

from core.database import Password
from core.paths import db_path, secure_existing_file


class VaultError(Exception):
    """Base class for vault failures."""


class VaultAuthError(VaultError):
    """The master password is wrong, or the vault is corrupt/unreadable."""


class VaultMissingError(VaultError):
    """No vault file exists yet."""


class VaultExistsError(VaultError):
    """A vault already exists and would be overwritten."""


# Cheap query that forces SQLCipher to decrypt page 1; raises DatabaseError on
# a wrong key. This is what makes "the key is correct" observable.
_SENTINEL = "SELECT count(*) FROM sqlite_master"

# Table name peewee derives from the Password model; used for schema migration.
_TABLE = Password._meta.table_name


class Vault:
    """Owns the encrypted database connection and the model binding."""

    def __init__(self, path=None):
        self._path = str(path) if path is not None else str(db_path())
        self._db = None
        self._master = None  # held in memory only while unlocked

    # -- lifecycle ---------------------------------------------------------

    def exists(self) -> bool:
        return os.path.exists(self._path)

    @property
    def is_open(self) -> bool:
        return self._db is not None

    def create(self, master: str) -> "Vault":
        """Create a brand-new encrypted vault. Refuses to clobber an existing one."""
        self._require_nonempty(master)
        if self.is_open:
            raise VaultError("A vault is already open.")
        if self.exists():
            raise VaultExistsError("A vault already exists at this location.")

        previous = Password._meta.database
        db = SqlCipherDatabase(self._path, passphrase=master)
        # create_tables acts through the model's bound database, so binding must
        # precede it here; on failure we restore the previous bind and remove
        # the half-written file so a retry is not blocked by VaultExistsError.
        Password._meta.database = db
        try:
            db.connect()
            db.create_tables([Password])
        except DatabaseError as exc:
            self._safe_close(db)
            Password._meta.database = previous
            self._unlink_quiet(self._path)
            raise VaultError(f"Could not create vault: {exc}") from exc

        secure_existing_file(self._path)
        self._db = db
        self._master = master
        return self

    def open(self, master: str) -> "Vault":
        """Unlock the vault. Raises VaultAuthError unless the vault decrypts.

        The global model is (re)bound only *after* the sentinel query proves the
        key is correct, so a failed unlock never leaves the model pointing at a
        closed, wrong-key connection.
        """
        self._require_nonempty(master)
        if self.is_open:
            raise VaultError("A vault is already open.")
        if not self.exists():
            raise VaultMissingError("No vault file exists.")

        db = SqlCipherDatabase(self._path, passphrase=master)
        try:
            db.connect()
            db.execute_sql(_SENTINEL).fetchone()  # force decryption before binding
        except DatabaseError as exc:
            self._safe_close(db)
            raise VaultAuthError(
                "Incorrect master password, or the vault is corrupt."
            ) from exc

        Password._meta.database = db
        self._db = db
        self._master = master
        self._migrate_schema()
        secure_existing_file(self._path)
        return self

    def rekey(self, current: str, new: str) -> "Vault":
        """Change the master password on the open vault.

        ``current`` is checked against the in-memory master as a UX guard (not a
        cryptographic check -- the vault is already unlocked). The on-disk change
        is a single SQLCipher ``rekey``; a backup is restored if the result
        cannot be verified with the new key on a fresh connection, and the
        in-memory master is advanced only after that verification succeeds.
        """
        if not self.is_open:
            raise VaultError("Vault is not open.")
        self._require_nonempty(new)
        if current != self._master:
            raise VaultAuthError("The current master password is incorrect.")

        backup = self._path + ".rekey.bak"
        shutil.copy2(self._path, backup)
        secure_existing_file(backup)

        try:
            self._db.rekey(new)
        except Exception as exc:
            self._restore(backup)
            raise VaultError("Rekey failed; the vault was left unchanged.") from exc

        # Prove the new key decrypts the vault on a *fresh* connection, not just
        # on the connection that performed the rewrite.
        self._safe_close(self._db)
        self._db = None
        fresh = SqlCipherDatabase(self._path, passphrase=new)
        try:
            fresh.connect()
            fresh.execute_sql(_SENTINEL).fetchone()
        except DatabaseError as exc:
            self._safe_close(fresh)
            self._restore(backup)
            self._reopen(current)  # keep the session usable on the old key
            raise VaultError(
                "Rekey could not be verified; the vault was restored."
            ) from exc

        Password._meta.database = fresh
        self._db = fresh
        self._master = new
        self._unlink_quiet(backup)
        return self

    def close(self) -> None:
        self._safe_close(self._db)
        self._db = None
        self._master = None
        Password._meta.database = None

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _require_nonempty(master) -> None:
        # An empty passphrase makes SQLCipher create/keep a *plaintext* database
        # (peewee skips PRAGMA key when the passphrase is falsy). Refuse it.
        if not master:
            raise VaultError("The master password must not be empty.")

    def _migrate_schema(self) -> None:
        # Vaults created before name uniqueness was enforced have a plain
        # ``name TEXT`` column. Add the unique index so duplicate names are
        # rejected by the database on legacy vaults too. If the vault already
        # contains duplicate names the index cannot be built; leave the vault
        # open and rely on the dialog's application-level check.
        try:
            self._db.execute_sql(
                f"CREATE UNIQUE INDEX IF NOT EXISTS "
                f"{_TABLE}_name_unique ON {_TABLE} (name)")
        except (DatabaseError, IntegrityError):
            pass

    def _reopen(self, master: str) -> None:
        db = SqlCipherDatabase(self._path, passphrase=master)
        db.connect()
        Password._meta.database = db
        self._db = db
        self._master = master

    def _restore(self, backup: str) -> None:
        if os.path.exists(backup):
            shutil.copy2(backup, self._path)
            secure_existing_file(self._path)
            self._unlink_quiet(backup)

    @staticmethod
    def _unlink_quiet(path: str) -> None:
        try:
            os.remove(path)
        except OSError:
            pass

    @staticmethod
    def _safe_close(db) -> None:
        if db is None:
            return
        try:
            if not db.is_closed():
                db.close()
        except Exception:
            pass


# Process-wide singleton: the one owner of the open connection. GUI dialogs
# authenticate through it and perform CRUD through the bound Password model.
VAULT = Vault()
