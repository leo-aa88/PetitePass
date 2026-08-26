"""Tests for data-directory resolution and legacy vault migration."""
import os
import stat

import pytest

from core import paths
from core.vault import Vault

MASTER = "correct horse battery staple"


@pytest.fixture
def isolated_dirs(tmp_path, monkeypatch):
    """Point every platform's data-dir source at throwaway locations.

    Linux/macOS derive from HOME (+ XDG_DATA_HOME on Linux); Windows uses
    LOCALAPPDATA. All three are redirected so the suite cannot touch a real
    vault regardless of the platform it runs on. ``tmp_path`` is the common
    isolation root, since the exact per-platform layout below it differs.
    """
    home = tmp_path / "home"
    data = tmp_path / "xdg-data"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    monkeypatch.setenv("LOCALAPPDATA", str(data))
    return tmp_path, home


def _legacy_db(home):
    legacy_dir = home / "PetitePass"
    legacy_dir.mkdir(exist_ok=True)
    return legacy_dir / paths.DB_FILENAME


def test_data_dir_is_isolated_and_0700(isolated_dirs):
    root, _ = isolated_dirs
    d = paths.data_dir()
    assert str(d).startswith(str(root))  # never the developer's real dir
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


def test_data_dir_is_not_nested_appname(isolated_dirs):
    # appauthor=False: the directory must end in a single "PetitePass" segment,
    # not the doubled "PetitePass/PetitePass" the default would produce.
    d = paths.data_dir()
    assert d.name == "PetitePass"
    assert d.parent.name != "PetitePass"


def test_fresh_install_uses_data_dir(isolated_dirs):
    assert paths.db_path() == paths.data_dir() / paths.DB_FILENAME


def test_legacy_vault_is_migrated_and_opens(isolated_dirs):
    root, home = isolated_dirs
    legacy_db = _legacy_db(home)
    v = Vault(str(legacy_db))
    v.create(MASTER)
    v.add("github", "me", "s3cret")
    v.close()

    resolved = paths.db_path()
    assert resolved == paths.data_dir() / paths.DB_FILENAME
    assert resolved.exists()
    assert not legacy_db.exists()
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(resolved).st_mode) == 0o600

    v2 = Vault(str(resolved))
    v2.open(MASTER)
    assert v2.get_password("github") == "s3cret"
    v2.close()


def test_migration_not_run_when_new_vault_exists(isolated_dirs):
    root, home = isolated_dirs
    new_db = paths.data_dir() / paths.DB_FILENAME
    Vault(str(new_db)).create(MASTER).close()

    legacy_db = _legacy_db(home)
    Vault(str(legacy_db)).create("a different master phrase").close()

    resolved = paths.db_path()
    assert resolved == new_db
    assert legacy_db.exists()  # left untouched
    Vault(str(resolved)).open(MASTER).close()  # still the original new vault


def test_migration_fsync_failure_aborts_and_keeps_legacy(isolated_dirs, monkeypatch):
    # A failed durability flush must abort BEFORE the original is removed, and
    # db_path() must keep the user on their legacy vault.
    root, home = isolated_dirs
    legacy_db = _legacy_db(home)
    Vault(str(legacy_db)).create(MASTER).close()

    def failing_fsync(fd):
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(os, "fsync", failing_fsync)

    resolved = paths.db_path()
    assert resolved == legacy_db                 # fell back to legacy
    assert legacy_db.exists()                    # original NOT deleted
    assert not (paths.data_dir() / paths.DB_FILENAME).exists()
    assert not (paths.data_dir() / (paths.DB_FILENAME + ".migrating")).exists()


def test_migration_postcommit_failure_still_commits(isolated_dirs, monkeypatch):
    # A failure AFTER os.replace must not flip the result back to the legacy
    # path (that would be split-brain: new exists but the process ignores it).
    root, home = isolated_dirs
    legacy_db = _legacy_db(home)
    v = Vault(str(legacy_db))
    v.create(MASTER)
    v.add("gh", "u", "p")
    v.close()

    def boom(_path):
        raise OSError("simulated post-commit failure")

    monkeypatch.setattr(paths, "secure_existing_file", boom)

    new_db = paths.data_dir() / paths.DB_FILENAME
    resolved = paths.db_path()
    assert resolved == new_db      # committed, not legacy
    assert new_db.exists()


def test_vault_singleton_uses_resolved_path(isolated_dirs):
    root, _ = isolated_dirs
    v = Vault()  # no explicit path
    assert str(v._path).startswith(str(root))
