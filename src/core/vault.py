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

Master-password rotation (:meth:`Vault.rekey`) never mutates the live vault in
place. It copies the closed vault to a temporary file, rekeys and verifies that
*copy*, then atomically ``os.replace``\\s it over the real path. Consequences:

* A crash before the replace leaves the original vault fully intact under the
  old key; the temp file is inert garbage that :meth:`open` deletes.
* ``os.replace`` is atomic, so a crash during the swap yields either the whole
  old vault or the whole new vault, never a torn file.
* A crash after the swap leaves the whole new vault under the new key.

There is therefore no second file whose relationship to the real vault
``open()`` must adjudicate: ``self._path`` is always a complete, openable vault.
"""
import datetime
import os
import shutil
from contextlib import contextmanager

from peewee import DatabaseError, DoesNotExist, IntegrityError
from playhouse.sqlcipher_ext import SqlCipherDatabase

from core.credential import Credential
from core.database import Password
from core.paths import db_path, fsync_dir, fsync_file, secure_existing_file


class VaultError(Exception):
    """Base class for vault failures."""


class VaultAuthError(VaultError):
    """The master password is wrong, or the vault is corrupt/unreadable."""


class VaultMissingError(VaultError):
    """No vault file exists yet."""


class VaultExistsError(VaultError):
    """A vault already exists and would be overwritten."""


class VaultRotatedError(VaultError):
    """Rekey committed on disk, but the session could not be rebound.

    The vault is now encrypted with the *new* master password; the current
    session is unusable and the application must be restarted. This is distinct
    from VaultAuthError so callers never tell the user the current password was
    wrong after a rotation has already been committed.
    """


class VaultLockedError(VaultError):
    """A credential operation was attempted while the vault was closed."""


class DuplicateCredentialError(VaultError):
    """A credential with the same name already exists."""


class CredentialNotFoundError(VaultError):
    """No credential exists with the requested name."""


# Table name peewee derives from the Password model.
_TABLE = Password._meta.table_name

# Sentinel query proving "this is our vault AND it decrypts under this key".
# Reading the schema to resolve the table forces page-1 decryption, so a wrong
# key raises DatabaseError (HMAC failure); requiring the application table
# additionally rejects a hollow file (0-byte / empty SQLCipher db with no
# password table), which SQLCipher would otherwise initialize under ANY key.
_SENTINEL = f"SELECT 1 FROM {_TABLE} LIMIT 1"

# Suffix for the transient rekey working copy (see module docstring).
_REKEY_TMP_SUFFIX = ".rekey.tmp"

# SQLCipher cipher parameters, pinned explicitly rather than inherited from
# whatever the linked sqlcipher3 build happens to default to. These are the
# SQLCipher 4 defaults, so existing vaults created before pinning open
# unchanged; owning them in code means a future library bump that changes a
# default cannot silently make old vaults unreadable. Applied on every
# connection (peewee runs them right after PRAGMA key).
_CIPHER_PRAGMAS = [
    ("cipher_page_size", 4096),
    ("kdf_iter", 256000),
    ("cipher_hmac_algorithm", "HMAC_SHA512"),
    ("cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512"),
]


def _make_db(path, master):
    """Construct a SqlCipherDatabase with the pinned cipher configuration."""
    return SqlCipherDatabase(str(path), passphrase=master, pragmas=_CIPHER_PRAGMAS)


class Vault:
    """Owns the encrypted database connection and the model binding."""

    def __init__(self, path=None):
        # Resolve the default path lazily (on first use), so constructing the
        # module-level VAULT singleton at import time does not trigger data-dir
        # creation or legacy migration as a side effect.
        self._explicit_path = str(path) if path is not None else None
        self._resolved_path = None
        self._db = None
        self._master = None  # held in memory only while unlocked

    @property
    def _path(self) -> str:
        # Resolve once and cache, so db_path() (and any legacy migration it
        # performs) runs a single time rather than on every attribute access --
        # in particular, rekey must not re-enter migration while a connection is
        # live.
        if self._resolved_path is None:
            self._resolved_path = self._explicit_path or str(db_path())
        return self._resolved_path

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
        db = _make_db(self._path, master)
        # create_tables acts through the model's bound database, so binding must
        # precede it here; on failure we restore the previous bind and remove
        # the half-written file so a retry is not blocked by VaultExistsError.
        Password._meta.database = db
        try:
            db.connect()
            db.create_tables([Password])
        except Exception as exc:
            # Any failure -- not only DatabaseError. peewee raises ValueError for
            # a NUL in the passphrase, which must not be allowed to leave a
            # 0-byte file that exists() would then treat as a vault.
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

        # A leftover working copy can only be pre-replace garbage (the real vault
        # is authoritative and intact); remove it so it cannot accumulate.
        self._unlink_quiet(self._path + _REKEY_TMP_SUFFIX)

        db = self._connect_verified(self._path, master)  # raises VaultAuthError
        Password._meta.database = db
        self._db = db
        self._master = master
        self._migrate_schema()
        secure_existing_file(self._path)
        return self

    def rekey(self, current: str, new: str) -> "Vault":
        """Change the master password on the open vault, crash-safely.

        ``current`` is checked against the in-memory master as a UX guard (not a
        cryptographic check -- the vault is already unlocked). The rotation is
        performed on a temporary copy and swapped in with an atomic replace.
        Before the ``os.replace`` commit, any failure leaves the vault openable
        under ``current`` (``VaultError``). After the commit the vault is keyed
        with ``new``; if the session cannot then be rebound, ``VaultRotatedError``
        is raised and the caller must reopen with ``new``.
        """
        if not self.is_open:
            raise VaultError("Vault is not open.")
        self._require_nonempty(new)
        if current != self._master:
            raise VaultAuthError("The current master password is incorrect.")

        tmp = self._path + _REKEY_TMP_SUFFIX
        self._unlink_quiet(tmp)

        # Release the live file so the on-disk copy is transactionally consistent.
        self._safe_close(self._db)
        self._db = None

        try:
            shutil.copy2(self._path, tmp)
            secure_existing_file(tmp)
            fsync_file(tmp)

            work = self._connect_verified(tmp, current)  # current must open the copy
            try:
                work.rekey(new)
            finally:
                self._safe_close(work)

            # Prove the new key decrypts the copy on a fresh connection.
            self._safe_close(self._connect_verified(tmp, new))
            fsync_file(tmp)
        except Exception as exc:
            # The original vault was never touched; drop the copy and restore the
            # session on the old key.
            self._unlink_quiet(tmp)
            self._reopen(current)
            raise VaultError("Rekey failed; the vault was left unchanged.") from exc

        # Swap the verified copy into place atomically. os.replace IS the commit
        # point: everything before it can fail with the vault "left unchanged";
        # everything after it means the rotation has happened on disk.
        try:
            os.replace(tmp, self._path)
        except OSError as exc:
            self._unlink_quiet(tmp)
            self._reopen(current)  # original untouched; restore the old session
            raise VaultError(
                "Rekey could not be committed; the vault was left unchanged."
            ) from exc

        # Committed. The on-disk vault is now keyed with `new` whether or not the
        # session can be rebound, so advance the master and report a *rotation*
        # failure (not an auth failure) if reopening fails.
        fsync_dir(os.path.dirname(self._path) or ".")
        secure_existing_file(self._path)
        self._master = new
        try:
            self._reopen(new)
        except VaultAuthError as exc:
            self._db = None
            Password._meta.database = None
            raise VaultRotatedError(
                "The master password was changed, but the vault could not be "
                "reopened in this session. Restart PetitePass and unlock with "
                "the NEW master password."
            ) from exc
        return self

    def close(self) -> None:
        self._safe_close(self._db)
        self._db = None
        self._master = None
        Password._meta.database = None

    # -- credential CRUD ---------------------------------------------------
    #
    # The Vault is the credential boundary: the GUI calls these instead of
    # reaching into the ORM, so business rules (name uniqueness, "credential
    # must exist", not loading every password to draw a list) live here. Every
    # method raises only VaultError (or a subclass) -- peewee exceptions,
    # including any DatabaseError from a persistence failure on an open vault,
    # are translated here so callers can catch VaultError and mean it.

    def list_credentials(self) -> list:
        """Return every credential as a passwordless :class:`Credential`.

        The password column is intentionally not selected, so plaintext is not
        loaded merely to render the (masked) list.
        """
        self._require_open()
        with self._as_vault_error():
            rows = Password.select(
                Password.name, Password.username,
                Password.timestamp, Password.updated
            ).order_by(Password.name)
            return [
                Credential(
                    name=row.name,
                    username=row.username or "",
                    created=self._fmt(row.timestamp),
                    updated=self._fmt(row.updated),
                )
                for row in rows
            ]

    def get_password(self, name: str) -> str:
        """Return the plaintext password for ``name`` (fetched on demand)."""
        self._require_open()
        with self._as_vault_error():
            try:
                return Password.get(Password.name == name).password
            except DoesNotExist as exc:
                raise CredentialNotFoundError(
                    f"No credential named {name!r}.") from exc

    def add(self, name: str, username: str, password: str) -> None:
        """Create a credential. Raises DuplicateCredentialError on a clash."""
        self._require_open()
        if not name:
            raise VaultError("The name cannot be empty.")
        if not password:
            raise VaultError("The password cannot be empty.")
        with self._as_vault_error():
            # DB unique index is the real guard; the pre-check covers legacy
            # vaults whose index could not be built (see _migrate_schema).
            if Password.select().where(Password.name == name).exists():
                raise DuplicateCredentialError(
                    f"A credential named {name!r} already exists.")
            try:
                Password.create(
                    name=name, username=username, password=password)
            except IntegrityError as exc:
                raise DuplicateCredentialError(
                    f"A credential named {name!r} already exists.") from exc

    def update(self, name: str, username=None, password=None) -> None:
        """Update a credential in place.

        ``username``/``password`` that are None or empty are left unchanged,
        preserving the historical dialog behaviour.
        """
        self._require_open()
        with self._as_vault_error():
            try:
                entry = Password.get(Password.name == name)
            except DoesNotExist as exc:
                raise CredentialNotFoundError(
                    f"No credential named {name!r}.") from exc
            if username:
                entry.username = username
            if password:
                entry.password = password
            entry.updated = datetime.datetime.now()
            entry.save()

    def delete(self, name: str) -> None:
        """Delete a credential. Raises CredentialNotFoundError if absent."""
        self._require_open()
        with self._as_vault_error():
            try:
                entry = Password.get(Password.name == name)
            except DoesNotExist as exc:
                raise CredentialNotFoundError(
                    f"No credential named {name!r}.") from exc
            entry.delete_instance()

    # -- helpers -----------------------------------------------------------

    def _require_open(self) -> None:
        if not self.is_open:
            raise VaultLockedError("The vault is not open.")

    @staticmethod
    @contextmanager
    def _as_vault_error():
        """Translate any peewee DatabaseError into a VaultError.

        VaultError subclasses (DuplicateCredentialError, CredentialNotFoundError)
        raised inside the block pass through unchanged; only a genuine
        persistence failure (I/O, OperationalError, a dropped connection) is
        wrapped, so the GUI's ``except VaultError`` covers every failure mode.
        """
        try:
            yield
        except VaultError:
            raise
        except DatabaseError as exc:
            raise VaultError(f"Vault operation failed: {exc}") from exc

    @staticmethod
    def _fmt(value) -> str:
        # A NULL datetime (e.g. never-updated) must not render as the string
        # "None"; present it as empty instead.
        return "" if value is None else str(value)

    @staticmethod
    def _require_nonempty(master) -> None:
        # An empty passphrase makes SQLCipher create/keep a *plaintext* database
        # (peewee skips PRAGMA key when the passphrase is falsy). Refuse it.
        if not master:
            raise VaultError("The master password must not be empty.")
        # peewee interpolates the passphrase into PRAGMA key='%s'; a NUL raises
        # ValueError from the driver, so reject it before it can throw past a
        # handler and leave a half-written file behind.
        if "\x00" in master:
            raise VaultError("The master password must not contain a null character.")

    def _connect_verified(self, path: str, master: str) -> SqlCipherDatabase:
        """Connect and prove the key decrypts, or raise VaultAuthError.

        Returns an open, unbound connection; the caller owns its lifecycle.
        """
        db = _make_db(path, master)
        try:
            db.connect()
            db.execute_sql(_SENTINEL).fetchone()
        except DatabaseError as exc:
            self._safe_close(db)
            raise VaultAuthError(
                "Incorrect master password, or the file is not a valid "
                "PetitePass vault."
            ) from exc
        return db

    def _reopen(self, master: str) -> None:
        """Re-establish the bound session on ``self._path`` under ``master``."""
        db = self._connect_verified(self._path, master)
        Password._meta.database = db
        self._db = db
        self._master = master

    def _migrate_schema(self) -> None:
        # Vaults created before name uniqueness was enforced have a plain
        # ``name TEXT`` column. Add the unique index so duplicate names are
        # rejected by the database on legacy vaults too. If the vault already
        # contains duplicate names the index cannot be built; leave the vault
        # open and rely on the application-level check in add().
        try:
            self._db.execute_sql(
                f"CREATE UNIQUE INDEX IF NOT EXISTS "
                f"{_TABLE}_name_unique ON {_TABLE} (name)")
        except (DatabaseError, IntegrityError):
            pass

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
# authenticate and perform all credential CRUD through its methods.
VAULT = Vault()
