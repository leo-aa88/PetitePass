"""Centralized filesystem locations and secure file helpers.

Single source of truth for where PetitePass keeps its data. Previously the
data directory and the database filename were string-interpolated in six
different modules (``f"/home/{getpass.getuser()}/PetitePass"``), which broke on
macOS/Windows and under ``sudo``, and the files were created world-readable.
"""
import os
import stat
from pathlib import Path

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
    """Return the PetitePass data directory, creating it 0700 if needed.

    Uses ``Path.home()`` so it is correct on Linux, macOS and Windows instead
    of a hard-coded ``/home/<user>`` prefix.
    """
    d = Path.home() / "PetitePass"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdir's mode is subject to umask and is ignored if the dir already
    # existed, so enforce the permission explicitly (no-op on Windows).
    _harden(d, 0o700)
    return d


def db_path() -> Path:
    """Absolute path to the encrypted vault file."""
    return data_dir() / DB_FILENAME


def common_password_file() -> str | None:
    """Path to the bundled common-password list, or None if not found."""
    for candidate in _COMMON_PASSWORD_LOCATIONS:
        if os.path.exists(candidate):
            return candidate
    return None


def _harden(path: Path, mode: int) -> None:
    """Best-effort ``chmod``; POSIX-only semantics, silently skipped elsewhere."""
    if os.name != "posix":
        return
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def secure_existing_file(path) -> None:
    """Restrict an existing file to owner read/write (0600)."""
    _harden(Path(path), stat.S_IRUSR | stat.S_IWUSR)
