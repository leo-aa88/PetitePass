"""Tests for Vault encrypted backup / restore (Phase 4)."""
import os
import stat

import pytest

from core.vault import Vault, VaultAuthError, VaultError, VaultLockedError, VaultRestoredError

MASTER = "correct horse battery staple"
OTHER = "an entirely different passphrase"


@pytest.fixture
def vault(tmp_path):
    v = Vault(str(tmp_path / "vault.db"))
    v.create(MASTER)
    yield v
    v.close()


def test_backup_creates_openable_copy(vault, tmp_path):
    vault.add("github", "me", "s3cret")
    dest = tmp_path / "backup.db"
    vault.backup_to(str(dest))

    assert dest.exists()
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(dest).st_mode) == 0o600

    # The backup is a full vault openable under the same master.
    b = Vault(str(dest))
    b.open(MASTER)
    assert b.get_password("github") == "s3cret"
    b.close()


def test_backup_requires_open_vault(tmp_path):
    v = Vault(str(tmp_path / "vault.db"))
    v.create(MASTER)
    v.close()
    with pytest.raises(VaultLockedError):
        v.backup_to(str(tmp_path / "b.db"))


def test_restore_reverts_to_backup_contents(vault, tmp_path):
    vault.add("github", "me", "s3cret")
    dest = tmp_path / "backup.db"
    vault.backup_to(str(dest))

    # Diverge from the backup.
    vault.add("gitlab", "me2", "other")
    vault.delete("github")

    vault.restore_from(str(dest), MASTER)

    names = {c.name for c in vault.list_credentials()}
    assert names == {"github"}
    assert vault.get_password("github") == "s3cret"


def test_restore_with_wrong_master_leaves_vault_unchanged(vault, tmp_path):
    vault.add("github", "me", "s3cret")
    dest = tmp_path / "backup.db"
    vault.backup_to(str(dest))
    vault.add("gitlab", "me2", "other")

    with pytest.raises(VaultAuthError):
        vault.restore_from(str(dest), "the wrong master password")

    # Current vault must be intact and usable.
    assert vault.is_open
    names = {c.name for c in vault.list_credentials()}
    assert names == {"github", "gitlab"}


def test_restore_from_backup_with_different_master(vault, tmp_path):
    # A backup taken from a vault with a different master password.
    other_db = tmp_path / "other.db"
    o = Vault(str(other_db))
    o.create(OTHER)
    o.add("account", "u", "p")
    backup = tmp_path / "other-backup.db"
    o.backup_to(str(backup))
    o.close()

    vault.restore_from(str(backup), OTHER)

    # The active vault is now the restored one, keyed with OTHER.
    assert vault.get_password("account") == "p"
    vault.close()
    with pytest.raises(VaultAuthError):
        Vault(str(vault._path)).open(MASTER)  # old master no longer works
    Vault(str(vault._path)).open(OTHER).close()


def test_restore_from_nonvault_file_rejected(vault, tmp_path):
    vault.add("github", "me", "s3cret")
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a vault at all")

    with pytest.raises(VaultError):
        vault.restore_from(str(junk), MASTER)
    assert vault.is_open
    assert vault.get_password("github") == "s3cret"  # unchanged


def test_restore_missing_file_rejected(vault, tmp_path):
    with pytest.raises(VaultError):
        vault.restore_from(str(tmp_path / "nope.db"), MASTER)
    assert vault.is_open


def test_restore_requires_open_vault(tmp_path):
    v = Vault(str(tmp_path / "vault.db"))
    v.create(MASTER)
    backup = tmp_path / "b.db"
    v.backup_to(str(backup))
    v.close()
    with pytest.raises(VaultLockedError):
        v.restore_from(str(backup), MASTER)


def test_restore_rejects_plaintext_impostor_with_empty_master(vault, tmp_path):
    # A plaintext SQLite file with a `password` table + empty master must not
    # be installed in place of the encrypted vault.
    import sqlite3
    vault.add("github", "me", "s3cret")
    evil = tmp_path / "evil.db"
    c = sqlite3.connect(str(evil))
    c.execute("CREATE TABLE password (id INTEGER PRIMARY KEY, name TEXT, "
              "username TEXT, password TEXT, timestamp TEXT, updated TEXT)")
    c.execute("INSERT INTO password (name, password) VALUES ('x', 'plain')")
    c.commit()
    c.close()

    with pytest.raises(VaultError):
        vault.restore_from(str(evil), "")

    assert vault.is_open
    assert vault.get_password("github") == "s3cret"
    with open(vault._path, "rb") as f:
        assert f.read(16) != b"SQLite format 3\x00"  # still encrypted


def test_restore_nul_master_is_vault_error(vault, tmp_path):
    vault.add("a", "u", "p")
    backup = tmp_path / "b.db"
    vault.backup_to(str(backup))
    with pytest.raises(VaultError):  # not a bare ValueError from peewee
        vault.restore_from(str(backup), "ab\x00cd")
    assert vault.is_open


def test_restore_reopen_failure_after_commit_reports_restored(vault, tmp_path, monkeypatch):
    from core import vault as vaultmod
    from core.database import Password

    vault.add("github", "me", "s3cret")
    backup = tmp_path / "b.db"
    vault.backup_to(str(backup))
    vault.add("gitlab", "me2", "other")  # diverge; restore should drop this

    original = vaultmod.Vault._connect_verified

    def flaky(self, path, master):
        if path == self._path:  # only the post-commit reopen of the live path
            raise vaultmod.VaultAuthError("simulated post-commit reopen failure")
        return original(self, path, master)

    monkeypatch.setattr(vaultmod.Vault, "_connect_verified", flaky)
    with pytest.raises(VaultRestoredError):
        vault.restore_from(str(backup), MASTER)

    assert vault.is_open is False
    assert Password._meta.database is None
    monkeypatch.undo()

    # The on-disk vault is the backup, keyed with MASTER.
    v2 = Vault(str(vault._path))
    v2.open(MASTER)
    assert {c.name for c in v2.list_credentials()} == {"github"}
    v2.close()


def test_open_cleans_leftover_restore_tmp(tmp_path):
    p = tmp_path / "vault.db"
    Vault(str(p)).create(MASTER).close()
    tmp = str(p) + ".restore.tmp"
    with open(tmp, "wb") as f:
        f.write(b"garbage")
    v = Vault(str(p))
    v.open(MASTER)
    assert not os.path.exists(tmp)
    v.close()


def test_backup_to_live_path_rejected(vault):
    vault.add("a", "u", "p")
    with pytest.raises(VaultError):
        vault.backup_to(vault._path)
    # The live session must remain writable (not turned read-only).
    vault.add("b", "u", "p")
    assert {c.name for c in vault.list_credentials()} == {"a", "b"}
