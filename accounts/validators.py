"""
Password validators that close the gaps in Django's built-ins for NIST SP
800-63B Rev. 4 §3.1.1.2.

Chain (see config/settings.py AUTH_PASSWORD_VALIDATORS):

    UserAttributeSimilarityValidator   expected: username / e-mail / names
    MinimumLengthValidator(15)         SHALL: 15 chars for password-only login
    MaximumLengthValidator(256)        SHOULD: allow ≥ 64 (we allow 256)
    CommonPasswordValidator            commonly used: Django's 20k list
    BloomPwnedValidator                compromised: full HIBP corpus, offline
    HIBPRangeApiValidator              compromised: HIBP k-anonymity API
    ContextSpecificValidator           expected: service name + maths vocabulary

Every validator here compares the *whole* password (after canonicalisation
where noted) — never substrings — and every rejection states its reason, as
the standard requires.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from django.utils.translation import ngettext

from .pwned import hibp
from .pwned.bloom import BloomFilter, BloomFormatError, sha1_digest

log = logging.getLogger("mathvault.password_screening")

# Shared rejection text: NIST SHALL "provide the reason for rejection".
PWNED_MESSAGE = _(
    "This password has appeared in a data breach and is on the blocklist. "
    "Attackers try breached passwords first, so please choose a different one."
)
PWNED_HELP = _("Your password must not appear in known data breaches (checked against Have I Been Pwned).")
UNAVAILABLE_MESSAGE = _("The breached-password check is temporarily unavailable. Please try again in a moment.")


def fail_closed_default() -> bool:
    return bool(getattr(settings, "PWNED_FAIL_CLOSED", False))


# ---------------------------------------------------------------------------
class MaximumLengthValidator:
    """NIST: verifiers SHOULD permit at least 64 characters and SHALL NOT
    truncate. We accept far more than 64; the cap only bounds hashing work
    (Django itself refuses anything over 4096 bytes since CVE-2013-1443).
    Length is counted in Unicode code points, as NIST specifies."""

    def __init__(self, max_length: int = 256):
        if max_length < 64:
            raise ValueError("NIST SP 800-63B requires allowing at least 64 characters")
        self.max_length = max_length

    def validate(self, password: str, user=None):
        if len(password) > self.max_length:
            raise ValidationError(
                ngettext(
                    "This password is too long. It may contain at most %(max_length)d character.",
                    "This password is too long. It may contain at most %(max_length)d characters.",
                    self.max_length,
                ),
                code="password_too_long",
                params={"max_length": self.max_length},
            )

    def get_help_text(self):
        return ngettext(
            "Your password may be up to %(max_length)d character long.",
            "Your password may be up to %(max_length)d characters long — long passphrases are encouraged.",
            self.max_length,
        ) % {"max_length": self.max_length}


# ---------------------------------------------------------------------------
class BloomPwnedValidator:
    """Rejects passwords present in the HIBP corpus using a local Bloom filter
    built by ``manage.py build_pwned_bloom`` (see docs/OPERATIONS.md).

    The filter is memory-mapped once per process and shared by every worker
    on the node through the page cache. No network access at validation time.
    False negatives: none. False positives: the rate chosen at build time
    (default 1 in 10,000); the cost is one extra attempt for that user.
    """

    _filters: dict[str, BloomFilter] = {}  # path -> open filter, per process

    def __init__(self, path: str | None = None, fail_closed: bool | None = None):
        self._path = path
        self._fail_closed = fail_closed

    @property
    def path(self) -> Path:
        return Path(self._path or settings.PWNED_BLOOM_PATH)

    @property
    def fail_closed(self) -> bool:
        return fail_closed_default() if self._fail_closed is None else self._fail_closed

    @classmethod
    def reset_cache(cls) -> None:
        for f in cls._filters.values():
            f.close()
        cls._filters.clear()

    def _filter(self) -> BloomFilter:
        key = str(self.path)
        bf = self._filters.get(key)
        if bf is None:
            bf = self._filters[key] = BloomFilter(self.path)
        return bf

    def validate(self, password: str, user=None):
        try:
            bf = self._filter()
        except (OSError, BloomFormatError) as exc:  # missing, unreadable or corrupt
            log.error("pwned_bloom_unavailable path=%s error=%s fail_closed=%s", self.path, exc, self.fail_closed)
            if self.fail_closed:
                raise ValidationError(UNAVAILABLE_MESSAGE, code="password_check_unavailable") from exc
            return  # fail open: CommonPasswordValidator / API check still apply
        if bf.contains_digest(sha1_digest(password)):
            log.info("pwned_rejected source=bloom")
            raise ValidationError(PWNED_MESSAGE, code="password_pwned")

    def get_help_text(self):
        return PWNED_HELP


# ---------------------------------------------------------------------------
class HIBPRangeApiValidator:
    """Rejects passwords found via the HIBP k-anonymity range API.

    Sends only the first 5 hex characters of the SHA-1; asks for padded
    responses. A no-op when ``settings.PWNED_API_ENABLED`` is False so the
    same validator list serves online and air-gapped deployments.
    """

    def __init__(self, timeout: float | None = None, fail_closed: bool | None = None, min_count: int = 1):
        self._timeout = timeout
        self._fail_closed = fail_closed
        self.min_count = max(1, min_count)

    @property
    def enabled(self) -> bool:
        return bool(getattr(settings, "PWNED_API_ENABLED", False))

    @property
    def fail_closed(self) -> bool:
        return fail_closed_default() if self._fail_closed is None else self._fail_closed

    def validate(self, password: str, user=None):
        if not self.enabled:
            return
        try:
            count = hibp.breach_count(
                password,
                base_url=getattr(settings, "PWNED_API_URL", hibp.DEFAULT_URL),
                timeout=self._timeout if self._timeout is not None else getattr(settings, "PWNED_API_TIMEOUT", 2.0),
            )
        except hibp.HIBPUnavailable as exc:
            log.error("pwned_api_unavailable error=%s fail_closed=%s", exc, self.fail_closed)
            if self.fail_closed:
                raise ValidationError(UNAVAILABLE_MESSAGE, code="password_check_unavailable") from exc
            return
        if count >= self.min_count:
            log.info("pwned_rejected source=api")
            raise ValidationError(PWNED_MESSAGE, code="password_pwned")

    def get_help_text(self):
        return PWNED_HELP


# ---------------------------------------------------------------------------
_LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "|": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t"})
_EDGE_DECORATION = re.compile(r"^[\W\d_]+|[\W\d_]+$")
_SEPARATORS = re.compile(r"[\s\-_.]+")


def canonicalize(text: str) -> str:
    """Reduce a password (or term) to its 'core' so that trivial derivatives
    collide: ``MathVault2026!`` → ``mathvault``, ``M@th-V4ult`` → ``mathvault``.

    Steps: NFC → casefold → drop separators → strip leading/trailing digits and
    punctuation → undo common leetspeak. The result is compared for *equality*
    with the term list, so this still honours NIST's whole-password rule: a
    passphrase that merely contains a term is not affected.
    """
    s = unicodedata.normalize("NFC", text).casefold()
    s = _SEPARATORS.sub("", s)
    s = _EDGE_DECORATION.sub("", s)
    return s.translate(_LEET)


def load_terms(path: str | Path) -> frozenset[str]:
    terms = set()
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            terms.add(canonicalize(line))
    return frozenset(t for t in terms if t)


class ContextSpecificValidator:
    """NIST blocklists SHALL cover "context-specific words, such as the name of
    the service, the username, and derivatives thereof".

    Django's UserAttributeSimilarityValidator handles the username and e-mail.
    This validator handles the service name, its derivatives, and the shared
    vocabulary of this site's community (famous theorems, constants and
    mathematicians) — the passwords a mathematics portal should *expect*.

    Matching is whole-password after canonicalisation, never substring.
    """

    def __init__(self, terms=(), terms_path: str | None = None, include_site_name: bool = True):
        canon = {canonicalize(t) for t in terms}
        if terms_path:
            canon |= load_terms(terms_path)
        if include_site_name:
            site = getattr(settings, "SITE_NAME", "")
            if site:
                canon.add(canonicalize(site))
        self.terms = frozenset(t for t in canon if t)

    def validate(self, password: str, user=None):
        if canonicalize(password) in self.terms:
            raise ValidationError(
                _(
                    "This password is too closely tied to this site or to mathematics "
                    "(for example the site name, a famous theorem, constant or mathematician). "
                    "Anyone guessing passwords here would try it early."
                ),
                code="password_context_specific",
            )

    def get_help_text(self):
        return _(
            "Your password can't be the site name, a well-known mathematical term, "
            "constant or mathematician's name, or a simple variation of one."
        )
