import unicodedata

import pytest
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import identify_hasher

User = get_user_model()
pytestmark = pytest.mark.django_db

COMPOSED = "café au lait sur la terrasse"  # é as one code point (NFC)
DECOMPOSED = "café au lait sur la terrasse"  # e + combining acute (NFD)


def test_nfc_normalisation_on_set_and_check():
    assert COMPOSED != DECOMPOSED and unicodedata.normalize("NFC", DECOMPOSED) == COMPOSED
    user = User.objects.create(username="ada")
    user.set_password(DECOMPOSED)
    user.save()
    assert user.check_password(COMPOSED)
    assert user.check_password(DECOMPOSED)
    assert not user.check_password("cafe au lait sur la terrasse")


def test_authenticate_accepts_either_form(rf):
    User.objects.create_user("ada2", password=COMPOSED)
    request = rf.post("/accounts/login/")
    assert authenticate(request=request, username="ada2", password=DECOMPOSED) is not None


def test_argon2id_is_the_production_hasher(settings):
    from config import settings as prod

    settings.PASSWORD_HASHERS = prod.PASSWORD_HASHERS

    assert prod.PASSWORD_HASHERS[0].endswith("Argon2PasswordHasher")
    from django.contrib.auth.hashers import Argon2PasswordHasher

    encoded = Argon2PasswordHasher().encode("a passphrase of fifteen+", Argon2PasswordHasher().salt())
    assert encoded.startswith("argon2$argon2id$")
    assert identify_hasher(encoded).algorithm == "argon2"
    # NIST: salt SHALL be at least 32 bits. Django's default salt entropy is 128 bits.
    assert Argon2PasswordHasher.salt_entropy >= 32


def test_compromise_flag_roundtrip():
    user = User.objects.create_user("bob", password="a long enough passphrase")
    assert not user.must_change_password
    user.mark_password_compromised()
    assert User.objects.get(pk=user.pk).must_change_password
    user.clear_password_compromised()
    assert not User.objects.get(pk=user.pk).must_change_password
