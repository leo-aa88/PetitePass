"""Cryptographically secure password generation.

The Shannon-entropy helpers, the CLI ``verify_password``/``cls``/
``check_privileges`` functions and the NumPy/tabulate dependencies that used to
live here have been removed. Strength estimation now lives in
:mod:`core.strength`; there is no CLI.
"""
import secrets
import string

ONLY_NUMBERS = "0123456789"
ONLY_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
ONLY_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ONLY_LETTERS = ONLY_LOWERCASE + ONLY_UPPERCASE
LOWERCASE_AND_NUMBERS = ONLY_LOWERCASE + ONLY_NUMBERS
UPPERCASE_AND_NUMBERS = ONLY_UPPERCASE + ONLY_NUMBERS
LETTERS_AND_NUMBERS = ONLY_LETTERS + ONLY_NUMBERS
SPECIAL_CHARS = """!"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"""
NO_ACCENTS = LETTERS_AND_NUMBERS + "-_(){[}]|/?,.!@$#&+%*<=>:;"
# string.printable minus whitespace.
RANDOM_STRING_CHARS = string.printable.translate(
    {ord(c): None for c in " \t\n\r\x0b\x0c"}
)

_CHARSETS = {
    "All printable characters": RANDOM_STRING_CHARS,
    "All characters except accents": NO_ACCENTS,
    "All letters and numbers": LETTERS_AND_NUMBERS,
    "Only uppercase letters and numbers": UPPERCASE_AND_NUMBERS,
    "Only uppercase letters": ONLY_UPPERCASE,
    "Only lowercase letters and numbers": LOWERCASE_AND_NUMBERS,
    "Only lowercase letters": ONLY_LOWERCASE,
    "Only special characters": SPECIAL_CHARS,
    "Only letters": ONLY_LETTERS,
    "Only numbers": ONLY_NUMBERS,
}

CHARSET_CHOICES = tuple(_CHARSETS.keys())


def get_random_string(length: int, allowed_chars: str = RANDOM_STRING_CHARS) -> str:
    """Return a securely generated random string.

    Uses :mod:`secrets` (a CSPRNG); ``secrets.choice`` is uniform over
    ``allowed_chars`` with no modulo bias.
    """
    return "".join(secrets.choice(allowed_chars) for _ in range(length))


def generate_password(charset_name: str, length: int) -> str:
    if length is None or length == "":
        raise ValueError("The password length cannot be empty.")
    if length < 2:
        raise ValueError("The length must be greater than 1.")
    try:
        char_set = _CHARSETS[charset_name]
    except KeyError:
        raise ValueError("Invalid character-set option.")
    return get_random_string(length, allowed_chars=char_set)
