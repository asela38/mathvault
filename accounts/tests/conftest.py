import pytest

from accounts.pwned.bloom import BloomBuilder
from accounts.validators import BloomPwnedValidator

# Known-bad passwords from the article's test plan plus a few that are *not* in
# Django's 20k list, so the Bloom layer is what rejects them.
KNOWN_BAD = ["password", "123456", "P@ssw0rd", "Summer2024!", "correcthorsebatterystaple", "Tr0ub4dor&3"]


@pytest.fixture(scope="session")
def demo_bloom_path(tmp_path_factory):
    path = tmp_path_factory.mktemp("pwned") / "test.bloom"
    with BloomBuilder.create(path, n=1000, p=1e-4) as b:
        b.add_passwords(KNOWN_BAD)
    return path


@pytest.fixture(autouse=True)
def password_settings(settings, demo_bloom_path):
    """Every test runs against the tiny Bloom filter, with the network API off
    and a fast hasher. Individual tests override what they need."""
    settings.PWNED_BLOOM_PATH = demo_bloom_path
    settings.PWNED_API_ENABLED = False
    settings.PWNED_FAIL_CLOSED = False
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    BloomPwnedValidator.reset_cache()
    yield
    BloomPwnedValidator.reset_cache()
