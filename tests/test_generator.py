from collections import Counter

import pytest

from petitepass.core.utils import ONLY_NUMBERS, generate_password, get_random_string


def test_length_is_honored():
    assert len(generate_password("All letters and numbers", 20)) == 20


def test_charset_is_respected():
    pw = generate_password("Only numbers", 50)
    assert set(pw) <= set(ONLY_NUMBERS)


def test_rejects_tiny_length():
    with pytest.raises(ValueError):
        generate_password("Only numbers", 1)


def test_rejects_unknown_charset():
    with pytest.raises(ValueError):
        generate_password("nonsense", 10)


def test_uses_secrets_module():
    # The generator must draw from the CSPRNG, not random.random.
    import inspect
    assert "secrets.choice" in inspect.getsource(get_random_string)


def test_distribution_is_not_obviously_degenerate():
    # Sanity check that it is not returning a constant character.
    counts = Counter(get_random_string(5000, ONLY_NUMBERS))
    assert len(counts) == 10
