"""Security-invariant tests for the Vault, run against real SQLCipher."""
import os
import stat

import pytest

from core.database import Password
from core.vault import Vault, VaultAuthError, VaultExistsError, VaultMissingError

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
