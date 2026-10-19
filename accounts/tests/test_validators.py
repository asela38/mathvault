import secrets
import time

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import (
    get_default_password_validators,
    password_validators_help_texts,
    validate_password,
)
from django.core.exceptions import ValidationError

from accounts.pwned import hibp
from accounts.validators import (
    BloomPwnedValidator,
    ContextSpecificValidator,
    HIBPRangeApiValidator,
    MaximumLengthValidator,
    canonicalize,
)

from .conftest import KNOWN_BAD

STRONG = "the integral of e to the minus x squared is root pi"


def codes(exc: ValidationError) -> set[str]:
    return {e.code for e in exc.error_list}


# --- the full chain ---------------------------------------------------------
def test_strong_passphrase_passes_whole_chain():
    validate_password(STRONG)


@pytest.mark.parametrize("pw", KNOWN_BAD)
def test_known_bad_rejected_by_chain(pw):
    with pytest.raises(ValidationError) as ei:
        validate_password(pw)
    assert codes(ei.value) & {"password_pwned", "password_too_common", "password_too_short"}


def test_breached_but_long_password_is_caught_only_by_bloom():
    # 25 chars, not in Django's list, not a maths term: only the HIBP layer can reject it.
    with pytest.raises(ValidationError) as ei:
        validate_password("correcthorsebatterystaple")
    assert codes(ei.value) == {"password_pwned"}


def test_numeric_password_validator_is_not_configured():
    names = [type(v).__name__ for v in get_default_password_validators()]
    assert "NumericPasswordValidator" not in names, "composition rule — NIST SHALL NOT"
    validate_password("8317509926341758203")  # 19 digits, random: no composition rule rejects it


def test_minimum_length_is_15_and_counts_code_points():
    with pytest.raises(ValidationError) as ei:
        validate_password("fourteen-chars")
    assert "password_too_short" in codes(ei.value)
    validate_password("∫∂∇∞πΣ√∛∜∮∯∰∱∲∳")  # 15 code points, several bytes each
    validate_password("αβγδεζηθικλμνξο-passphrase")


def test_help_texts_mention_every_rule():
    text = " ".join(password_validators_help_texts()).lower()
    for needle in ("15", "256", "data breach", "site name", "commonly used"):
        assert needle in text


# --- MaximumLengthValidator -------------------------------------------------
def test_maximum_length_allows_at_least_64():
    with pytest.raises(ValueError):
        MaximumLengthValidator(max_length=63)
    v = MaximumLengthValidator(max_length=256)
    v.validate("x" * 64)
    v.validate("x" * 256)
    with pytest.raises(ValidationError) as ei:
        v.validate("x" * 257)
    assert codes(ei.value) == {"password_too_long"}


# --- BloomPwnedValidator ----------------------------------------------------
def test_bloom_validator_rejects_and_accepts(demo_bloom_path):
    v = BloomPwnedValidator(path=str(demo_bloom_path))
    for pw in KNOWN_BAD:
        with pytest.raises(ValidationError) as ei:
            v.validate(pw)
        assert codes(ei.value) == {"password_pwned"}
    for _ in range(100):
        v.validate(secrets.token_urlsafe(24))


def test_bloom_validator_fail_open_and_fail_closed(tmp_path, settings, caplog):
    missing = tmp_path / "nope.bloom"
    BloomPwnedValidator(path=str(missing), fail_closed=False).validate("password")  # fail open: no error
    assert "pwned_bloom_unavailable" in caplog.text
    with pytest.raises(ValidationError) as ei:
        BloomPwnedValidator(path=str(missing), fail_closed=True).validate("password")
    assert codes(ei.value) == {"password_check_unavailable"}
    # settings-driven default
    settings.PWNED_BLOOM_PATH = missing
    settings.PWNED_FAIL_CLOSED = True
    with pytest.raises(ValidationError):
        BloomPwnedValidator().validate("password")


def test_bloom_validator_is_fast_once_mapped(demo_bloom_path):
    v = BloomPwnedValidator(path=str(demo_bloom_path))
    v.validate(STRONG)
    t = time.perf_counter()
    for _ in range(2000):
        v.validate(STRONG)
    assert (time.perf_counter() - t) / 2000 < 1e-3  # well under a millisecond per check


# --- HIBPRangeApiValidator --------------------------------------------------
def _fake_fetch_factory(pwned_password: str, count: int = 42, calls: list | None = None):
    sha1 = hibp.sha1_digest(pwned_password).hex().upper()

    def fetch(url: str, timeout: float) -> str:
        if calls is not None:
            calls.append(url)
        assert url.endswith("/" + sha1[:5]), "only the 5-char prefix may be sent"
        assert sha1 not in url and sha1[5:] not in url
        padding = "\r\n".join(f"{'0' * 35}:0" for _ in range(3))  # Add-Padding rows
        return f"{padding}\r\n{sha1[5:]}:{count}\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:7\r\n"

    return fetch


def test_api_client_sends_only_prefix_and_ignores_padding(monkeypatch):
    calls = []
    monkeypatch.setattr(hibp, "_urllib_fetch", _fake_fetch_factory("hunter2", 17, calls))
    assert hibp.breach_count("hunter2") == 17
    assert len(calls) == 1 and calls[0].startswith("https://api.pwnedpasswords.com/range/")


def test_api_validator_rejects_when_found_and_passes_otherwise(monkeypatch, settings):
    settings.PWNED_API_ENABLED = True
    monkeypatch.setattr(hibp, "_urllib_fetch", _fake_fetch_factory("hunter2"))
    v = HIBPRangeApiValidator()
    with pytest.raises(ValidationError) as ei:
        v.validate("hunter2")
    assert codes(ei.value) == {"password_pwned"}
    # a different password with the same prefix would need a matching suffix; this one has a different prefix
    monkeypatch.setattr(hibp, "_urllib_fetch", lambda url, timeout: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:3\r\n")
    v.validate(STRONG)


def test_api_validator_noop_when_disabled(monkeypatch, settings):
    settings.PWNED_API_ENABLED = False

    def boom(url, timeout):
        raise AssertionError("must not call the network when disabled")

    monkeypatch.setattr(hibp, "_urllib_fetch", boom)
    HIBPRangeApiValidator().validate("hunter2")


def test_api_validator_fail_open_and_closed(monkeypatch, settings, caplog):
    settings.PWNED_API_ENABLED = True

    def down(url, timeout):
        raise hibp.HIBPUnavailable("connection refused")

    monkeypatch.setattr(hibp, "_urllib_fetch", down)
    HIBPRangeApiValidator(fail_closed=False).validate("hunter2")
    assert "pwned_api_unavailable" in caplog.text
    with pytest.raises(ValidationError) as ei:
        HIBPRangeApiValidator(fail_closed=True).validate("hunter2")
    assert codes(ei.value) == {"password_check_unavailable"}


def test_parse_range_drops_padding_rows():
    body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:12\r\nshort:3\r\n"
    assert hibp.parse_range(body) == {"B" * 35: 12}


# --- ContextSpecificValidator ----------------------------------------------
@pytest.mark.parametrize(
    "raw, expected",
    [
        ("MathVault2026!", "mathvault"),
        ("M@th-V4ult", "mathvault"),
        ("  Pythagoras_1 ", "pythagoras"),
        ("R13mann!!", "riemann"),
        ("3.14159265358979", ""),  # all digits/punctuation strip to nothing → never matches
        ("e^(i*pi)+1=0", "e^(i*pi"),  # trailing punctuation/digits stripped; inner symbols kept
    ],
)
def test_canonicalize(raw, expected):
    assert canonicalize(raw) == expected


@pytest.mark.parametrize(
    "pw",
    ["MathVault2026!", "mathvault", "M@thV4ult", "math-vault", "Pythagoras1", "EULER", "riemann-hypothesis-2026", "fermats last theorem", "GoldenRatio!"],
)
def test_context_specific_rejects_service_and_maths_terms(pw):
    v = ContextSpecificValidator(terms_path="accounts/context_terms.txt")
    with pytest.raises(ValidationError) as ei:
        v.validate(pw)
    assert codes(ei.value) == {"password_context_specific"}


@pytest.mark.parametrize(
    "pw",
    [
        "the mathvault of pythagoras is great",  # contains terms but is not one (whole-password rule)
        "riemann hypothesis is probably true but euler never knew",
        STRONG,
        "mathvault-is-where-i-keep-my-lemmas",
    ],
)
def test_context_specific_does_not_do_substring_matching(pw):
    ContextSpecificValidator(terms_path="accounts/context_terms.txt").validate(pw)


def test_context_specific_includes_site_name_and_explicit_terms(settings):
    settings.SITE_NAME = "ProofBox"
    v = ContextSpecificValidator(terms=["Hilbert Space"])
    with pytest.raises(ValidationError):
        v.validate("proofbox2027")
    with pytest.raises(ValidationError):
        v.validate("hilbert-space!")
    v.validate("hilbert space is complete and so am i")


def test_user_attribute_similarity_still_covers_username_and_email(db):
    user = get_user_model()(username="sophie.germain", email="sophie.germain@example.org")
    with pytest.raises(ValidationError) as ei:
        validate_password("sophie.germain2026", user)
    assert "password_too_similar" in codes(ei.value)
