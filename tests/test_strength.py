from core.strength import MIN_MASTER_LENGTH, check_master_policy, evaluate, is_common


def test_short_password_rejected():
    assert check_master_policy("aA1!x") is not None


def test_common_list_is_actually_loaded():
    # Guards against is_common silently returning False (missing/unshipped list).
    assert is_common("password") is True
    assert is_common("this-string-is-not-in-any-common-list-xyzzy") is False


def test_long_common_password_rejected_by_policy():
    # >= MIN_MASTER_LENGTH so it passes the length gate and actually reaches the
    # common-list check (the old test used 8-char "password", which never did).
    assert len("unbelievable") >= MIN_MASTER_LENGTH
    assert check_master_policy("unbelievable") is not None


def test_long_passphrase_accepted_without_symbols():
    # The old policy rejected this for lacking upper/special chars; a real
    # strength estimator must accept a long, high-entropy passphrase.
    assert check_master_policy("correct horse battery staple mountain") is None


def test_sequential_string_is_not_strong():
    # The old Shannon-ratio scored 'abcdefgh...' as 100%; zxcvbn must not.
    assert check_master_policy("abcdefghijkl") is not None


def test_common_password_rejected():
    assert check_master_policy("password") is not None


def test_min_length_constant_is_reasonable():
    assert MIN_MASTER_LENGTH >= 12


def test_evaluate_returns_score_range():
    s = evaluate("Tr0ub4dour&3xample longer phrase")
    assert 0 <= s.score <= 4
