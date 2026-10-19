"""
Django settings for MathVault, a reference implementation of NIST SP 800-63B
Rev. 4 (Section 3.1.1.2) password screening.

Everything password-related is grouped under "PASSWORD POLICY" below and is
cross-referenced from docs/COMPLIANCE.md.
"""

import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-insecure-secret-key-change-me")
DEBUG = env_bool("DJANGO_DEBUG", True)
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

SITE_NAME = "MathVault"

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "axes",
    "accounts",
    "problems",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # NIST 3.1.1.2: force a change only on evidence of compromise (never periodically).
    "accounts.middleware.CompromisedPasswordMiddleware",
    # django-axes must be last: it only renders lockout responses.
    "axes.middleware.AxesMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "accounts.context_processors.site",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_USER_MODEL = "accounts.User"

AUTHENTICATION_BACKENDS = [
    # Axes first so lockouts are enforced before credentials are checked.
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "problems:list"
LOGOUT_REDIRECT_URL = "problems:list"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# PASSWORD POLICY  (NIST SP 800-63B Rev. 4, Section 3.1.1.2)
# ---------------------------------------------------------------------------

# Storage: "Passwords SHALL be salted and hashed using a suitable password
# hashing scheme" with the cost factor "as high as practical". Argon2id is the
# recommended memory-hard scheme; PBKDF2 stays listed so legacy hashes verify
# and are transparently upgraded on next login.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

# Offline HIBP Bloom filter (see accounts/pwned/bloom.py and docs/OPERATIONS.md).
PWNED_BLOOM_PATH = Path(os.environ.get("PWNED_BLOOM_PATH", BASE_DIR / "data" / "pwned" / "current.bloom"))
# Fail-open keeps logins working if the file is missing; Django's common list
# and the API check (if enabled) still apply. Fail-closed is the conservative
# choice for high-assurance deployments.
PWNED_FAIL_CLOSED = env_bool("PWNED_FAIL_CLOSED", False)
# Alert threshold for a stale filter: one missed monthly refresh.
PWNED_BLOOM_MAX_AGE = timedelta(days=45)

# Online HIBP k-anonymity range API. Only the first 5 hex characters of the
# SHA-1 ever leave the application. Disable in air-gapped deployments.
PWNED_API_ENABLED = env_bool("PWNED_API_ENABLED", True)
PWNED_API_URL = os.environ.get("PWNED_API_URL", "https://api.pwnedpasswords.com/range/")
PWNED_API_TIMEOUT = float(os.environ.get("PWNED_API_TIMEOUT", "2.0"))

# Passwords that are *expected* on a mathematics site: the service name, its
# derivatives and the vocabulary every user here shares. Whole-password match
# after canonicalisation (see accounts/validators.py).
CONTEXT_TERMS_PATH = BASE_DIR / "accounts" / "context_terms.txt"

AUTH_PASSWORD_VALIDATORS = [
    # Expected: username, e-mail, names (SHALL: context-specific words).
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    # SHALL: minimum 15 characters for single-factor password login. Django
    # counts len(str), i.e. Unicode code points, as NIST requires.
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 15},
    },
    # SHOULD: permit at least 64 characters. We allow 256; the cap exists only
    # to bound hashing work, it is not a usability limit.
    {
        "NAME": "accounts.validators.MaximumLengthValidator",
        "OPTIONS": {"max_length": 256},
    },
    # Commonly used: Django's bundled 20k list (cheap, offline, case-insensitive).
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    # Compromised: full HIBP corpus via local Bloom filter (no network).
    {"NAME": "accounts.validators.BloomPwnedValidator"},
    # Compromised (alternative/additional): HIBP k-anonymity API. Toggle with
    # PWNED_API_ENABLED; the validator is a no-op when disabled.
    {"NAME": "accounts.validators.HIBPRangeApiValidator"},
    # Expected: service name, derivatives, and mathematics vocabulary.
    {
        "NAME": "accounts.validators.ContextSpecificValidator",
        "OPTIONS": {"terms_path": str(CONTEXT_TERMS_PATH)},
    },
    # NOTE: NumericPasswordValidator is deliberately absent. Rejecting
    # all-numeric passwords is a composition rule, which Rev. 4 says verifiers
    # SHALL NOT impose. A 15-character minimum plus the breach blocklist already
    # reject every realistic PIN-style password.
]

# ---------------------------------------------------------------------------
# RATE LIMITING  (NIST SP 800-63B Rev. 4, Section 3.2.2) via django-axes
# ---------------------------------------------------------------------------
# "The verifier SHALL limit consecutive failed authentication attempts ... on a
# single subscriber account to no more than 100 by disabling that authenticator."
AXES_ENABLED = env_bool("AXES_ENABLED", True)
AXES_FAILURE_LIMIT = 100
# Track per account (NIST) *and* per source address (defence in depth).
AXES_LOCKOUT_PARAMETERS = ["username", "ip_address"]
AXES_RESET_ON_SUCCESS = True
# A lockout is lifted after this cool-off, or earlier by an administrator with
# `manage.py axes_reset_username <name>`. NIST allows the verifier to choose
# how a disabled authenticator is re-enabled.
AXES_COOLOFF_TIME = timedelta(hours=24)
AXES_LOCKOUT_TEMPLATE = "accounts/locked_out.html"
# Credentials never go to the log; axes stores only username/IP/user-agent.
AXES_SENSITIVE_PARAMETERS = ["password", "password1", "password2", "new_password1", "new_password2", "old_password"]

# ---------------------------------------------------------------------------
# Logging: password-screening events feed the monitoring signals in
# docs/OPERATIONS.md. Nothing here ever includes the password itself.
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "plain"}},
    "loggers": {
        "mathvault.password_screening": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}

# Production hardening toggles (irrelevant for the local dev server).
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = env_bool("DJANGO_SSL_REDIRECT", True)
    SECURE_HSTS_SECONDS = 31536000
