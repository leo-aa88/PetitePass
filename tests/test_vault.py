"""Security-invariant tests for the Vault, run against real SQLCipher."""
import os
import stat

import pytest

from core.database import Password
from core.vault import (
    Vault,
    VaultAuthError,
    VaultError,
    VaultExistsError,
    VaultMissingError,
    VaultRotatedError,
)

MASTER = "correct horse battery staple"
# Deliberately hostile: quotes, double-quotes, backslash, unicode, whitespace.
TRICKY = "it's a \"weird\" \\pass wörd; DROP--"


@pytest.fixture
def vault_path(tmp_path):
    return str(tmp_path / "vault.db")


def _fresh(path, master):
    v = Vault(path)
    v.create(master)
    return v


def test_create_then_open_roundtrip(vault_path):
    v = _fresh(vault_path, MASTER)
    Password.create(name="gh", username="me", password="s3cret")
    v.close()

    v2 = Vault(vault_path)
    v2.open(MASTER)
    assert Password.get(Password.name == "gh").password == "s3cret"
    v2.close()


def test_wrong_password_is_rejected(vault_path):
    _fresh(vault_path, MASTER).close()
    with pytest.raises(VaultAuthError):
        Vault(vault_path).open("not the password")


def test_unicode_and_quote_master_password(vault_path):
    v = Vault(vault_path)
    v.create(TRICKY)
    Password.create(name="a", password="b")
    v.close()

    v2 = Vault(vault_path)
    v2.open(TRICKY)  # must not raise despite quotes/backslash/unicode
    assert Password.get(Password.name == "a").password == "b"
    v2.close()


def test_open_missing_vault_raises(vault_path):
    with pytest.raises(VaultMissingError):
        Vault(vault_path).open(MASTER)


def test_create_refuses_to_clobber(vault_path):
    _fresh(vault_path, MASTER).close()
    with pytest.raises(VaultExistsError):
        Vault(vault_path).create("another")


def test_corrupt_vault_is_rejected_not_crash(vault_path):
    _fresh(vault_path, MASTER).close()
    with open(vault_path, "r+b") as f:
        f.seek(0)
        f.write(b"\x00" * 64)  # smash the header/first page
    with pytest.raises(VaultAuthError):
        Vault(vault_path).open(MASTER)


def test_rekey_changes_key_and_preserves_data(vault_path):
    v = _fresh(vault_path, MASTER)
    Password.create(name="gh", password="s3cret")
    v.rekey(MASTER, TRICKY)
    v.close()

    # Old password must no longer work; new (tricky) password must.
    with pytest.raises(VaultAuthError):
        Vault(vault_path).open(MASTER)

    v2 = Vault(vault_path)
    v2.open(TRICKY)
    assert Password.get(Password.name == "gh").password == "s3cret"
    v2.close()


def test_rekey_wrong_current_leaves_vault_untouched(vault_path):
    v = _fresh(vault_path, MASTER)
    Password.create(name="gh", password="s3cret")
    with pytest.raises(VaultAuthError):
        v.rekey("wrong current", "new-master-passphrase")
    v.close()

    # The original password must still open the vault (no partial change).
    v2 = Vault(vault_path)
    v2.open(MASTER)
    assert Password.get(Password.name == "gh").password == "s3cret"
    v2.close()


def test_name_uniqueness_enforced_by_db(vault_path):
    from peewee import IntegrityError
    v = _fresh(vault_path, MASTER)
    Password.create(name="dup", password="a")
    with pytest.raises(IntegrityError):
        Password.create(name="dup", password="b")
    v.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_vault_file_is_owner_only(vault_path):
    _fresh(vault_path, MASTER).close()
    mode = stat.S_IMODE(os.stat(vault_path).st_mode)
    assert mode == 0o600, oct(mode)


def test_empty_master_refused_and_no_file_created(vault_path):
    from core.vault import VaultError
    with pytest.raises(VaultError):
        Vault(vault_path).create("")
    # An empty passphrase would have produced a *plaintext* SQLite file.
    assert not os.path.exists(vault_path)


def test_created_vault_is_not_plaintext(vault_path):
    _fresh(vault_path, MASTER).close()
    with open(vault_path, "rb") as f:
        header = f.read(16)
    assert header != b"SQLite format 3\x00", "vault must be encrypted"


def test_open_refuses_when_already_open(vault_path):
    from core.vault import VaultError
    v = _fresh(vault_path, MASTER)
    with pytest.raises(VaultError):
        v.open(MASTER)
    v.close()


def test_failed_open_leaves_clean_state(vault_path):
    _fresh(vault_path, MASTER).close()
    v = Vault(vault_path)
    with pytest.raises(VaultAuthError):
        v.open("wrong")
    # A failed unlock must not report the vault as open.
    assert v.is_open is False
    # ...and the global model must not be left bound to a closed connection.
    assert Password._meta.database is None


def test_legacy_vault_without_unique_index_is_migrated(vault_path):
    from peewee import IntegrityError
    from playhouse.sqlcipher_ext import SqlCipherDatabase

    # Build a pre-uniqueness vault: name has no UNIQUE index.
    raw = SqlCipherDatabase(vault_path, passphrase=MASTER)
    raw.connect()
    raw.execute_sql(
        "CREATE TABLE password (id INTEGER PRIMARY KEY, name TEXT, "
        "username TEXT, password TEXT, timestamp DATETIME, updated DATETIME)")
    raw.execute_sql("INSERT INTO password (name, password) VALUES ('a', '1')")
    raw.close()

    Vault(vault_path).open(MASTER)  # must migrate in the unique index
    with pytest.raises(IntegrityError):
        Password.create(name="a", password="2")


def test_vault_cipher_params_are_load_bearing(vault_path):
    # Opening the vault with a mismatched kdf_iter must fail, proving the pinned
    # parameters actually govern key derivation (and are not cosmetic).
    from peewee import DatabaseError
    from playhouse.sqlcipher_ext import SqlCipherDatabase

    _fresh(vault_path, MASTER).close()

    mismatched = SqlCipherDatabase(
        vault_path, passphrase=MASTER, pragmas=[("kdf_iter", 64000)])
    mismatched.connect()
    with pytest.raises(DatabaseError):
        mismatched.execute_sql("SELECT 1 FROM password LIMIT 1").fetchone()
    mismatched.close()

    # The Vault (pinned to the correct params) opens it fine.
    v = Vault(vault_path)
    v.open(MASTER)
    v.close()


def test_legacy_default_created_vault_still_opens(vault_path):
    # A vault created by the bare library (no explicit cipher pragmas), as older
    # PetitePass versions did, must still open under the now-pinned Vault.
    from playhouse.sqlcipher_ext import SqlCipherDatabase

    raw = SqlCipherDatabase(vault_path, passphrase=MASTER)  # no pragmas
    Password._meta.database = raw
    raw.connect()
    raw.create_tables([Password])
    Password.create(name="gh", password="s3cret")
    raw.close()

    v = Vault(vault_path)
    v.open(MASTER)
    assert Password.get(Password.name == "gh").password == "s3cret"
    v.close()


def test_create_null_byte_master_rejected_leaves_no_file(vault_path):
    # A NUL makes peewee raise ValueError from PRAGMA key='%s'. It must be
    # rejected before any file is written, so exists() cannot later treat a
    # 0-byte leftover as a vault.
    with pytest.raises(VaultError):
        Vault(vault_path).create("correct horse\x00battery staple")
    assert not os.path.exists(vault_path)
    # A subsequent create must not be blocked by a phantom VaultExistsError.
    v = Vault(vault_path)
    v.create(MASTER)
    v.close()


def test_create_nondatabaseerror_failure_unlinks_partial(vault_path, monkeypatch):
    # Any create failure (not just DatabaseError) must restore the bind and
    # remove the half-written file.
    from playhouse.sqlcipher_ext import SqlCipherDatabase

    previous = Password._meta.database

    def boom(self, models):
        raise ValueError("simulated non-DatabaseError create failure")

    monkeypatch.setattr(SqlCipherDatabase, "create_tables", boom)
    with pytest.raises(VaultError):
        Vault(vault_path).create(MASTER)
    monkeypatch.undo()

    assert not os.path.exists(vault_path)
    assert Password._meta.database is previous  # bind restored
    v = Vault(vault_path)
    v.create(MASTER)  # not blocked by VaultExistsError
    v.close()


def test_open_rejects_zero_byte_file(vault_path):
    # A hollow file must not authenticate under an arbitrary password. SQLCipher
    # initializes a 0-byte file as an empty db under any key; the sentinel must
    # still refuse it because it has no password table.
    open(vault_path, "wb").close()
    v = Vault(vault_path)
    with pytest.raises(VaultAuthError):
        v.open("any nonempty passphrase at all")
    assert v.is_open is False
    assert Password._meta.database is None


def test_open_rejects_valid_sqlcipher_db_without_password_table(vault_path):
    from playhouse.sqlcipher_ext import SqlCipherDatabase

    # A real, correctly-keyed SQLCipher db that is NOT a PetitePass vault.
    raw = SqlCipherDatabase(vault_path, passphrase=MASTER)
    raw.connect()
    raw.execute_sql("CREATE TABLE other (x)")
    raw.close()

    with pytest.raises(VaultAuthError):
        Vault(vault_path).open(MASTER)  # right key, but not our vault


def _tmp_of(path):
    return path + ".rekey.tmp"


def test_successful_rekey_leaves_no_temp_file(vault_path):
    v = _fresh(vault_path, MASTER)
    Password.create(name="gh", password="s3cret")
    v.rekey(MASTER, TRICKY)
    assert not os.path.exists(_tmp_of(vault_path))
    v.close()


def test_open_cleans_and_ignores_stale_temp(vault_path):
    # Simulates a crash *before* the atomic replace: the real vault is intact and
    # a leftover working copy sits beside it. open() must succeed on the real
    # vault and clear the stale copy, never treat the copy as authoritative.
    _fresh(vault_path, MASTER).close()
    with open(_tmp_of(vault_path), "wb") as f:
        f.write(b"garbage not a vault")
    v = Vault(vault_path)
    v.open(MASTER)
    assert not os.path.exists(_tmp_of(vault_path))
    v.close()


def test_rekey_operation_failure_leaves_vault_unchanged(vault_path, monkeypatch):
    # SQLCipher rekey raises after the copy exists. Original must be untouched,
    # the session must stay usable on the current key, and no spare is orphaned.
    from playhouse.sqlcipher_ext import SqlCipherDatabase

    v = _fresh(vault_path, MASTER)
    Password.create(name="gh", password="s3cret")

    def boom(self, passphrase):
        raise RuntimeError("simulated rekey crash mid-rewrite")

    monkeypatch.setattr(SqlCipherDatabase, "rekey", boom)
    with pytest.raises(VaultError):
        v.rekey(MASTER, "a different long master phrase")

    assert v.is_open
    assert Password.get(Password.name == "gh").password == "s3cret"
    assert not os.path.exists(_tmp_of(vault_path))
    v.close()
    v2 = Vault(vault_path)
    v2.open(MASTER)  # old master must still work
    assert Password.select().count() == 1
    v2.close()


def test_rekey_new_key_verification_failure_restores(vault_path, monkeypatch):
    # The fresh-connection sentinel on the NEW key fails. The rotation must be
    # abandoned and the vault left openable under the current password.
    from core import vault as vaultmod

    new_master = "yet another long master phrase"
    v = _fresh(vault_path, MASTER)
    Password.create(name="gh", password="s3cret")

    original = vaultmod.Vault._connect_verified

    def flaky(self, path, master):
        if master == new_master:
            raise vaultmod.VaultAuthError("simulated verify failure")
        return original(self, path, master)

    monkeypatch.setattr(vaultmod.Vault, "_connect_verified", flaky)
    with pytest.raises(VaultError):
        v.rekey(MASTER, new_master)

    assert v.is_open
    assert Password.get(Password.name == "gh").password == "s3cret"
    assert not os.path.exists(_tmp_of(vault_path))
    v.close()
    v2 = Vault(vault_path)
    with pytest.raises(VaultAuthError):
        v2.open(new_master)  # the never-committed new key must NOT open
    v2.open(MASTER)
    assert Password.select().count() == 1
    v2.close()


def test_rekey_replace_failure_leaves_vault_unchanged(vault_path, monkeypatch):
    # Failure exactly at the atomic-replace boundary, after the copy is verified.
    import os as os_module

    v = _fresh(vault_path, MASTER)
    Password.create(name="gh", password="s3cret")

    real_replace = os_module.replace

    def failing_replace(src, dst, *a, **k):
        if src.endswith(".rekey.tmp"):
            raise OSError("simulated replace failure")
        return real_replace(src, dst, *a, **k)

    monkeypatch.setattr(os_module, "replace", failing_replace)
    with pytest.raises(VaultError):
        v.rekey(MASTER, "a committed-boundary master phrase")

    assert v.is_open
    assert Password.get(Password.name == "gh").password == "s3cret"
    assert not os.path.exists(_tmp_of(vault_path))
    v.close()
    v2 = Vault(vault_path)
    v2.open(MASTER)
    assert Password.select().count() == 1
    v2.close()


def test_rekey_reopen_failure_after_commit_reports_rotated(vault_path, monkeypatch):
    # Failure of the post-commit _reopen(new): the rotation IS committed on disk,
    # so this must be reported as a rotation (restart) failure, NOT as a wrong
    # current password, and the on-disk vault must be keyed with the NEW password.
    from core import vault as vaultmod

    new_master = "the committed new master phrase"
    v = _fresh(vault_path, MASTER)
    Password.create(name="gh", password="s3cret")

    original = vaultmod.Vault._connect_verified

    def flaky(self, path, master):
        # Allow the copy-open (current) and the new-key verify on the tmp copy;
        # fail only the reopen of the *real* path with the new key (post-commit).
        if master == new_master and path == self._path:
            raise vaultmod.VaultAuthError("simulated post-commit reopen failure")
        return original(self, path, master)

    monkeypatch.setattr(vaultmod.Vault, "_connect_verified", flaky)
    with pytest.raises(VaultRotatedError):
        v.rekey(MASTER, new_master)

    assert v.is_open is False
    assert Password._meta.database is None

    # Drop the injected failure before verifying the real on-disk state.
    monkeypatch.undo()

    v2 = Vault(vault_path)
    with pytest.raises(VaultAuthError):
        v2.open(MASTER)  # old key must NOT open -- rotation committed
    v2.open(new_master)
    assert Password.select().count() == 1
    v2.close()


def test_rekey_fsync_failure_leaves_vault_unchanged(vault_path, monkeypatch):
    # A failed fsync of the working copy must abort before os.replace destroys
    # the original, leaving the vault openable under the current password.
    import os as os_module

    v = _fresh(vault_path, MASTER)
    Password.create(name="gh", password="s3cret")

    def failing_fsync(fd):
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(os_module, "fsync", failing_fsync)
    with pytest.raises(VaultError):
        v.rekey(MASTER, "an fsync boundary master phrase")

    assert v.is_open
    assert Password.get(Password.name == "gh").password == "s3cret"
    assert not os.path.exists(_tmp_of(vault_path))
    v.close()
    v2 = Vault(vault_path)
    v2.open(MASTER)
    assert Password.select().count() == 1
    v2.close()


def test_legacy_vault_with_existing_dupes_still_opens(vault_path):
    from playhouse.sqlcipher_ext import SqlCipherDatabase

    raw = SqlCipherDatabase(vault_path, passphrase=MASTER)
    raw.connect()
    raw.execute_sql(
        "CREATE TABLE password (id INTEGER PRIMARY KEY, name TEXT, "
        "username TEXT, password TEXT, timestamp DATETIME, updated DATETIME)")
    raw.execute_sql("INSERT INTO password (name, password) VALUES ('a', '1')")
    raw.execute_sql("INSERT INTO password (name, password) VALUES ('a', '2')")
    raw.close()

    # Index can't be built, but the vault must still open (not lock the user out).
    v = Vault(vault_path)
    v.open(MASTER)
    assert Password.select().count() == 2
    v.close()
