"""Centralized filesystem locations, secure file helpers, and legacy migration.

Single source of truth for where PetitePass keeps its data. Previously the data
directory and the database filename were string-interpolated in six different
modules (``f"/home/{getpass.getuser()}/PetitePass"``), which broke on
macOS/Windows and under ``sudo``, and the files were created world-readable.

The vault now lives in the platform's standard per-user data directory
(``platformdirs``): ``~/.local/share/PetitePass`` on Linux, Application Support
on macOS, ``%LOCALAPPDATA%`` on Windows. A vault created by an older version
under ``~/PetitePass`` is migrated on first use (see :func:`db_path`).
"""
import os
import shutil
import stat
from pathlib import Path

import platformdirs

APP_NAME = "PetitePass"

# Kept identical to the historical name so existing vaults keep opening.
DB_FILENAME = "48cccca3bab2ad18832233ee8dff1b0b.db"

# Bundled list of the 10k most common passwords. The copy shipped alongside the
# code is authoritative and always present (source checkout and PyInstaller
# bundle alike); the install locations are fallbacks.
_COMMON_PASSWORD_LOCATIONS = (
    str(Path(__file__).resolve().parent / "data" / "10k-most-common.txt"),
    "/usr/share/10k-most-common.txt",
    str(Path(__file__).resolve().parents[2]
        / "petitepass_package" / "usr" / "share" / "10k-most-common.txt"),
)


def data_dir() -> Path:
    """Return the PetitePass data directory, creating it 0700 if needed."""
    d = Path(platformdirs.user_data_dir(APP_NAME))
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdir's mode is subject to umask and is ignored if the dir already
    # existed, so enforce the permission explicitly (no-op on Windows).
    _harden(d, 0o700)
    return d


def legacy_data_dir() -> Path:
    """The pre-platformdirs location, ``~/PetitePass``."""
    return Path.home() / APP_NAME


def db_path() -> Path:
    """Absolute path to the encrypted vault file.

    Resolves to the standard data directory. If no vault exists there yet but a
    legacy ``~/PetitePass`` vault does, it is migrated first; if the migration
    cannot be completed, the legacy path is returned so the user keeps working
    against their existing vault rather than being shown an empty one.
    """
    new = data_dir() / DB_FILENAME
    if new.exists():
        return new
    legacy = legacy_data_dir() / DB_FILENAME
    if legacy.exists():
        return new if _migrate(legacy, new) else legacy
    return new


def common_password_file():
    """Path to the bundled common-password list, or None if not found."""
    for candidate in _COMMON_PASSWORD_LOCATIONS:
        if os.path.exists(candidate):
            return candidate
    return None


def secure_existing_file(path) -> None:
    """Restrict an existing file to owner read/write (0600)."""
    _harden(Path(path), stat.S_IRUSR | stat.S_IWUSR)


# -- internals ------------------------------------------------------------

def _migrate(legacy: Path, new: Path) -> bool:
    """Copy a legacy vault to the new location atomically. Returns success.

    The original is left untouched until the copy is durably in place under an
    atomic rename, and is removed only afterwards, so an interrupted migration
    can never lose the vault.
    """
    tmp = new.with_name(new.name + ".migrating")
    try:
        shutil.copy2(legacy, tmp)
        _harden(tmp, stat.S_IRUSR | stat.S_IWUSR)
        _fsync_path(tmp)
        os.replace(tmp, new)          # atomic within the data dir
        _fsync_path(new.parent)
        secure_existing_file(new)
    except OSError:
        _unlink_quiet(tmp)
        return False
    # New copy is committed; drop the legacy vault (and its dir if now empty).
    _unlink_quiet(legacy)
    try:
        legacy.parent.rmdir()
    except OSError:
        pass
    return True


def _harden(path: Path, mode: int) -> None:
    """Best-effort ``chmod``; POSIX-only semantics, silently skipped elsewhere."""
    if os.name != "posix":
        return
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _fsync_path(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _unlink_quiet(path: Path) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
