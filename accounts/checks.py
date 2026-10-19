"""
Django system checks that surface the monitoring signals from the operations
guide: a missing/corrupt Bloom file, or one older than one missed refresh.
Run with ``manage.py check`` (also runs on ``runserver`` and ``migrate``).
"""

from django.conf import settings
from django.core.checks import Error, Tags, Warning, register

from .pwned.bloom import BloomFilter, BloomFormatError


@register(Tags.security, deploy=False)
def check_pwned_bloom(app_configs, **kwargs):
    issues = []
    path = getattr(settings, "PWNED_BLOOM_PATH", None)
    if not path:
        return issues
    try:
        bf = BloomFilter(path)
    except (OSError, BloomFormatError) as exc:
        level = Error if getattr(settings, "PWNED_FAIL_CLOSED", False) else Warning
        issues.append(
            level(
                f"HIBP Bloom filter unavailable at {path}: {exc}",
                hint="Run `manage.py build_pwned_bloom` (see docs/OPERATIONS.md). "
                "With PWNED_FAIL_CLOSED=0 the validator fails open and only Django's "
                "20k common-password list and the HIBP API (if enabled) screen passwords.",
                id="accounts.W001" if level is Warning else "accounts.E001",
            )
        )
        return issues
    try:
        age = bf.age()
        max_age = getattr(settings, "PWNED_BLOOM_MAX_AGE", None)
        if age is not None and max_age is not None and age > max_age.total_seconds():
            issues.append(
                Warning(
                    f"HIBP Bloom filter at {path} is {age / 86400:.0f} days old (limit {max_age.days}).",
                    hint="A monthly refresh appears to have been missed.",
                    id="accounts.W002",
                )
            )
    finally:
        bf.close()
    return issues
