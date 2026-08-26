"""Tests for the Vault credential CRUD service (Phase 2)."""
import pytest

from core.credential import Credential
from core.vault import (
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


def test_list_summaries_carry_no_password(vault):
    vault.add("github", "me", "s3cret")
    cred = vault.list_credentials()[0]
    assert not hasattr(cred, "password")


def test_list_is_ordered_by_name(vault):
    for name in ("charlie", "alpha", "bravo"):
        vault.add(name, "", "x")
    assert [c.name for c in vault.list_credentials()] == ["alpha", "bravo", "charlie"]


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
