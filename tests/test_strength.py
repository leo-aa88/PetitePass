from petitepass.core.strength import (
    MIN_MASTER_LENGTH,
    ZXCVBN_MAX_LENGTH,
    check_master_policy,
    evaluate,
    is_common,
)


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


def test_exactly_at_zxcvbn_limit_does_not_raise():
    # Boundary: zxcvbn rejects only inputs *longer* than its limit.
    pw = "Tr0ub4dour&3xample".ljust(ZXCVBN_MAX_LENGTH, "x")
    assert len(pw) == ZXCVBN_MAX_LENGTH
    s = evaluate(pw)
    assert 0 <= s.score <= 4


def test_evaluate_does_not_raise_above_zxcvbn_limit():
    # zxcvbn 4.5.0 raises ValueError above 72 chars; evaluate() must degrade to
    # an advisory score instead of letting the exception escape (#37).
    pw = "Zx9!" * 250
    assert len(pw) > ZXCVBN_MAX_LENGTH
    s = evaluate(pw)
    assert 0 <= s.score <= 4


def test_long_diceware_passphrase_is_accepted():
    # The exact case a security-conscious user reaches for: a passphrase longer
    # than zxcvbn's internal limit must pass the master policy (#37).
    pw = "correct horse battery staple diceware seven words plus more entropy here now yes"
    assert len(pw) > ZXCVBN_MAX_LENGTH
    assert check_master_policy(pw) is None


def test_long_repetitive_password_is_still_rejected():
    # Truncating for scoring must not turn a weak repeated string into an
    # accepted master password.
    pw = "passwordpassword" * 10
    assert len(pw) > ZXCVBN_MAX_LENGTH
    assert check_master_policy(pw) is not None

