"""Tests for data-directory resolution and legacy vault migration."""
import os
import stat

import pytest

from core import paths
from core.vault import Vault

MASTER = "correct horse battery staple"


@pytest.fixture
def isolated_dirs(tmp_path, monkeypatch):
    """Point HOME and the platformdirs data dir at throwaway locations."""
    home = tmp_path / "home"
    data = tmp_path / "xdg-data"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    return home, data


def test_data_dir_uses_platformdirs_and_is_0700(isolated_dirs):
    home, data = isolated_dirs
    d = paths.data_dir()
    assert str(d).startswith(str(data))
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


def test_fresh_install_uses_new_location(isolated_dirs):
    home, data = isolated_dirs
    assert str(paths.db_path()).startswith(str(data))


def test_legacy_vault_is_migrated_and_opens(isolated_dirs):
    home, data = isolated_dirs

    # Create a real vault at the legacy ~/PetitePass location.
    legacy_dir = home / "PetitePass"
    legacy_dir.mkdir()
    legacy_db = legacy_dir / paths.DB_FILENAME
    v = Vault(str(legacy_db))
    v.create(MASTER)
    v.add("github", "me", "s3cret")
    v.close()

    resolved = paths.db_path()

    # Migrated into the new location, legacy removed, and still openable.
    assert str(resolved).startswith(str(data))
    assert resolved.exists()
    assert not legacy_db.exists()
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(resolved).st_mode) == 0o600

    v2 = Vault(str(resolved))
    v2.open(MASTER)
    assert v2.get_password("github") == "s3cret"
    v2.close()


def test_migration_does_not_run_when_new_vault_exists(isolated_dirs):
    home, data = isolated_dirs

    # A vault already present in the new location.
    new_db = paths.data_dir() / paths.DB_FILENAME
    Vault(str(new_db)).create(MASTER).close()

    # A different legacy vault must be ignored (new location wins, untouched).
    legacy_dir = home / "PetitePass"
    legacy_dir.mkdir()
    legacy_db = legacy_dir / paths.DB_FILENAME
    Vault(str(legacy_db)).create("a different master phrase").close()

    resolved = paths.db_path()
    assert resolved == new_db
    assert legacy_db.exists()  # left untouched
    Vault(str(resolved)).open(MASTER).close()  # still the original new vault


def test_vault_singleton_uses_resolved_path(isolated_dirs):
    home, data = isolated_dirs
    # A Vault constructed with no explicit path resolves through db_path().
    v = Vault()
    assert str(v._path).startswith(str(data))
