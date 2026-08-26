"""Tests for the Vault credential CRUD service (Phase 2)."""
import pytest

from petitepass.core.credential import Credential
from petitepass.core.vault import (
    CredentialNotFoundError,
    DuplicateCredentialError,
    Vault,
    VaultError,
    VaultLockedError,
)

MASTER = "correct horse battery staple"


@pytest.fixture
def vault(tmp_path):
    v = Vault(str(tmp_path / "vault.db"))
    v.create(MASTER)
    yield v
    v.close()


def test_add_and_list(vault):
    vault.add("github", "me@example.com", "s3cret")
    creds = vault.list_credentials()
    assert len(creds) == 1
    assert isinstance(creds[0], Credential)
    assert creds[0].name == "github"
    assert creds[0].username == "me@example.com"


def test_credential_dataclass_has_no_password_field(vault):
    # Shape check only: the domain object cannot carry a password by construction.
    vault.add("github", "me", "s3cret")
    assert not hasattr(vault.list_credentials()[0], "password")


def test_list_query_excludes_password_column(vault, monkeypatch):
    # The security-relevant claim: the SELECT does not fetch the password column,
    # so plaintext is not decrypted merely to render the list. This would break
    # if list_credentials() reverted to Password.select() (all columns).
    from petitepass.core import vault as vaultmod

    vault.add("github", "me", "s3cret")

    captured = {}
    original = vaultmod.Password.select

    def spy(*fields):
        captured["fields"] = fields
        return original(*fields)

    monkeypatch.setattr(vaultmod.Password, "select", spy)
    vault.list_credentials()

    # Compare by column name -- peewee Field.__eq__ builds expressions, so a
    # normal `in` membership test cannot be used on Field objects.
    selected = {getattr(f, "name", None) for f in captured["fields"]}
    assert "password" not in selected
    assert "name" in selected and "username" in selected


def test_persistence_failure_surfaces_as_vault_error(vault, monkeypatch):
    # A DatabaseError on an OPEN vault must be translated to VaultError, not
    # leaked as a raw peewee exception (the GUI catches only VaultError).
    from peewee import OperationalError

    from petitepass.core import vault as vaultmod

    def boom(*a, **k):
        raise OperationalError("simulated disk I/O error")

    monkeypatch.setattr(vaultmod.Password, "select", boom)
    with pytest.raises(VaultError):
        vault.list_credentials()

    monkeypatch.setattr(vaultmod.Password, "get", boom)
    with pytest.raises(VaultError):
        vault.get_password("github")


def test_list_is_ordered_by_name(vault):
    for name in ("charlie", "alpha", "bravo"):
        vault.add(name, "", "x")
    assert [c.name for c in vault.list_credentials()] == ["alpha", "bravo", "charlie"]


def test_never_updated_credential_has_empty_updated_not_none(vault):
    # A NULL 'updated' must not surface as the string "None".
    vault.add("github", "me", "s3cret")
    cred = vault.list_credentials()[0]
    assert cred.updated == ""
    assert cred.created not in ("", "None")


def test_updated_is_populated_after_update(vault):
    vault.add("github", "me", "s3cret")
    vault.update("github", "", "newpw")
    cred = vault.list_credentials()[0]
    assert cred.updated not in ("", "None")


def test_get_password_returns_secret(vault):
    vault.add("github", "me", "s3cr'et\"\\pw")
    assert vault.get_password("github") == "s3cr'et\"\\pw"


def test_get_password_missing_raises(vault):
    with pytest.raises(CredentialNotFoundError):
        vault.get_password("nope")


def test_add_duplicate_raises(vault):
    vault.add("github", "me", "a")
    with pytest.raises(DuplicateCredentialError):
        vault.add("github", "other", "b")
    # The original must be untouched.
    assert vault.get_password("github") == "a"


def test_add_empty_name_or_password_rejected(vault):
    with pytest.raises(VaultError):
        vault.add("", "u", "p")
    with pytest.raises(VaultError):
        vault.add("name", "u", "")


def test_update_changes_fields(vault):
    vault.add("github", "old", "oldpw")
    vault.update("github", "new@example.com", "newpw")
    assert vault.get_password("github") == "newpw"
    assert vault.list_credentials()[0].username == "new@example.com"


def test_update_empty_fields_are_left_unchanged(vault):
    vault.add("github", "keep", "keep")
    vault.update("github", "", "")  # blank means "leave as-is"
    assert vault.get_password("github") == "keep"
    assert vault.list_credentials()[0].username == "keep"


def test_update_missing_raises(vault):
    with pytest.raises(CredentialNotFoundError):
        vault.update("nope", "u", "p")


def test_delete_removes(vault):
    vault.add("github", "me", "a")
    vault.delete("github")
    assert vault.list_credentials() == []


def test_delete_missing_raises(vault):
    with pytest.raises(CredentialNotFoundError):
        vault.delete("nope")


def test_crud_requires_open_vault(tmp_path):
    v = Vault(str(tmp_path / "vault.db"))
    v.create(MASTER)
    v.close()
    for op in (
        lambda: v.list_credentials(),
        lambda: v.get_password("x"),
        lambda: v.add("x", "y", "z"),
        lambda: v.update("x", "y", "z"),
        lambda: v.delete("x"),
    ):
        with pytest.raises(VaultLockedError):
            op()


def test_crud_persists_across_reopen(tmp_path):
    path = str(tmp_path / "vault.db")
    v = Vault(path)
    v.create(MASTER)
    v.add("github", "me", "s3cret")
    v.close()

    v2 = Vault(path)
    v2.open(MASTER)
    assert v2.get_password("github") == "s3cret"
    v2.close()
