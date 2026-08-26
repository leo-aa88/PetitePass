"""Password-strength estimation and master-password policy.

The previous implementation computed the Shannon entropy of a *single string's*
character-frequency distribution and divided by ``log(length)``. That measures
how evenly distinct characters are spread within the string, not how hard it is
to guess: ``abcdefgh`` scored 100% ("strong") while ``Password1!Password1!``
scored "weak". It also enforced mandatory upper/lower/special character classes
that reject strong passphrases.

This module is the master-password *policy*. It has three hard gates --
minimum length, a common-password blocklist, and a minimum zxcvbn score -- and
zxcvbn also supplies human-readable advice for the strength dialog. It is a
policy layer only: cryptographic key stretching is done entirely by SQLCipher's
KDF and is independent of anything decided here.
"""
from dataclasses import dataclass

from zxcvbn import zxcvbn

from core.paths import common_password_file

# Minimum master-password length. Length dominates guessability far more than
# character-class variety, so this is the single hard length gate.
MIN_MASTER_LENGTH = 12

# zxcvbn score (0-4) required for a master password. 3 == "safely unguessable
# without an offline fast-hash attack".
MIN_MASTER_SCORE = 3


@dataclass
class Strength:
    score: int            # zxcvbn 0..4
    crack_time: str       # human-readable estimate for an offline slow hash
    warning: str          # zxcvbn feedback warning (may be empty)
    suggestions: list     # zxcvbn feedback suggestions


def evaluate(password: str) -> Strength:
    """Return a guessability estimate for advisory display."""
    result = zxcvbn(password)
    feedback = result.get("feedback", {}) or {}
    crack = result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
    return Strength(
        score=int(result["score"]),
        crack_time=str(crack),
        warning=feedback.get("warning") or "",
        suggestions=list(feedback.get("suggestions") or []),
    )


def is_common(password: str) -> bool:
    """True if the password appears in the bundled common-password list."""
    path = common_password_file()
    if path is None:
        return False
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return any(password == line.rstrip("\n") for line in f)
    except OSError:
        return False


def check_master_policy(password: str) -> str | None:
    """Validate a candidate master password.

    Returns an error message if it is unacceptable, or None if it passes.
    Only length, the common-password blocklist, and an overall guessability
    floor are enforced -- no mandatory character-class rules.
    """
    if len(password) < MIN_MASTER_LENGTH:
        return (f"Your master password must be at least "
                f"{MIN_MASTER_LENGTH} characters long.")
    if is_common(password):
        return "That password is in the list of most common passwords."
    result = evaluate(password)
    if result.score < MIN_MASTER_SCORE:
        hint = result.warning or (result.suggestions[0] if result.suggestions else "")
        return "That password is too easy to guess." + (f" {hint}" if hint else "")
    return None
