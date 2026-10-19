"""
Client for the Have I Been Pwned Pwned Passwords *range* API (k-anonymity).

Only the first five hex characters of the SHA-1 are sent. HIBP returns every
suffix sharing that prefix (~800), and the match happens locally. With
``Add-Padding: true`` the response is padded to 800–1,000 rows (count 0) so the
response size leaks nothing either. The API needs no key, has no rate limit
and no attribution requirement (https://haveibeenpwned.com/API/v3#PwnedPasswords).
"""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable

from .bloom import sha1_digest

DEFAULT_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "mathvault-password-screening/1.0 (+https://github.com/example/mathvault)"

Fetcher = Callable[[str, float], str]


class HIBPUnavailable(Exception):
    """Network/HTTP failure. The caller decides fail-open vs fail-closed."""


def _urllib_fetch(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"Add-Padding": "true", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https host
            return resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HIBPUnavailable(str(exc)) from exc


def parse_range(body: str) -> dict[str, int]:
    """``SUFFIX:COUNT`` lines → {suffix: count}; padded rows (count 0) dropped."""
    out: dict[str, int] = {}
    for line in body.splitlines():
        suffix, _, count = line.strip().partition(":")
        if len(suffix) == 35 and count.strip().isdigit():
            c = int(count)
            if c > 0:
                out[suffix.upper()] = c
    return out


def breach_count(
    password: str,
    *,
    base_url: str = DEFAULT_URL,
    timeout: float = 2.0,
    fetch: Fetcher | None = None,
) -> int:
    """Number of times ``password`` appears in the HIBP corpus (0 = not found).

    Raises ``HIBPUnavailable`` if the API cannot be reached. Never logs or
    transmits the password or its full hash.
    """
    sha1 = sha1_digest(password).hex().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    body = (fetch or _urllib_fetch)(base_url.rstrip("/") + "/" + prefix, timeout)
    return parse_range(body).get(suffix, 0)
