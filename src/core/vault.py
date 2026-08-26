"""The single Vault abstraction: authentication *is* decryption.

This replaces the old design where a sidecar bcrypt file
(``5f4dcc3b5aa765d61d8327deb882cf99``) was the authentication authority, kept
in sync with the SQLCipher key by hand across several GUI dialogs. That design
allowed:

* a session to be reported "authenticated" while the vault could not decrypt,
* the verifier to desynchronize from the key during a non-atomic rekey,
* the master password to be interpolated into ``PRAGMA`` SQL via f-strings.

Here, the only proof of authentication is successfully decrypting the vault,
and rekeying is a single atomic SQLCipher operation with no second file to
desynchronize. The master password reaches SQLCipher only through peewee's
parameter-escaping passphrase/rekey API, never through string formatting.
"""
from peewee import DatabaseError
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


class Vault:
    """Owns the encrypted database connection and the model binding."""

    def __init__(self, path=None):
        self._path = str(path) if path is not None else str(db_path())
        self._db = None
        self._master = None  # held in memory only while unlocked

    # -- lifecycle ---------------------------------------------------------

    def exists(self) -> bool:
        import os
        return os.path.exists(self._path)

    @property
    def is_open(self) -> bool:
        return self._db is not None

    def create(self, master: str) -> "Vault":
        """Create a brand-new encrypted vault. Refuses to clobber an existing one."""
        if self.exists():
            raise VaultExistsError("A vault already exists at this location.")
        db = SqlCipherDatabase(self._path, passphrase=master)
        Password._meta.database = db
        try:
            db.connect()
            db.create_tables([Password])
        except DatabaseError as exc:  # pragma: no cover - creation is local
            self._safe_close(db)
            raise VaultError(f"Could not create vault: {exc}") from exc
        secure_existing_file(self._path)
        self._db = db
        self._master = master
        return self

    def open(self, master: str) -> "Vault":
        """Unlock the vault. Raises VaultAuthError unless the vault decrypts."""
        if not self.exists():
            raise VaultMissingError("No vault file exists.")
        db = SqlCipherDatabase(self._path, passphrase=master)
        Password._meta.database = db
        try:
            db.connect()
            db.execute_sql(_SENTINEL).fetchone()  # force decryption
        except DatabaseError as exc:
            self._safe_close(db)
            raise VaultAuthError(
                "Incorrect master password, or the vault is corrupt."
            ) from exc
        secure_existing_file(self._path)
        self._db = db
        self._master = master
        return self

    def rekey(self, current: str, new: str) -> "Vault":
        """Change the master password on the currently-open vault, atomically.

        The vault must already be open. ``current`` is checked against the
        in-memory master (no second file, no second oracle); the change is a
        single SQLCipher ``rekey`` that either fully succeeds or leaves the old
        key in place. Success is confirmed by re-decrypting with the new key.
        """
        if not self.is_open:
            raise VaultError("Vault is not open.")
        if current != self._master:
            raise VaultAuthError("The current master password is incorrect.")

        self._db.rekey(new)  # library escapes the passphrase; atomic per-page rewrite
        self._master = new

        # Confirm the new key actually decrypts the vault before reporting success.
        try:
            self._db.execute_sql(_SENTINEL).fetchone()
        except DatabaseError as exc:  # pragma: no cover - should not happen
            raise VaultError(
                "Rekey completed but the vault could not be re-verified."
            ) from exc
        return self

    def close(self) -> None:
        self._safe_close(self._db)
        self._db = None
        self._master = None

    # -- helpers -----------------------------------------------------------

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
