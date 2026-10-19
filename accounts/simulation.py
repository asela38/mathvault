"""
Interactive simulation of the HIBP Bloom filter: build one from a short list
of passwords, then check candidates against it. The page is purely
educational, but every number it shows comes from the *real* implementation:
``accounts.pwned.bloom`` for sizing, hashing and bit positions, and
``BloomPwnedValidator`` for the rejection message. Filters are built in a
temporary directory per request and never touch ``PWNED_BLOOM_PATH``.
"""

from __future__ import annotations

import json
import math
import secrets
import tempfile
from pathlib import Path

from django.core.exceptions import ValidationError
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST

from .pwned.bloom import HEADER_SIZE, BloomBuilder, BloomFilter, estimated_fp_rate, positions, sha1_digest, sizing
from .validators import BloomPwnedValidator

MAX_PASSWORDS = 300
MAX_BITS = 4096  # keeps the bit grid drawable (64 columns × 64 rows)
MAX_HUNT_TRIES = 200_000

DEFAULT_PASSWORDS = [
    "password", "123456", "P@ssw0rd", "Summer2024!", "qwerty", "letmein",
    "correcthorsebatterystaple", "Pythagoras1", "iloveyou", "dragon",
]


@ensure_csrf_cookie
def simulation_page(request):
    return render(request, "accounts/simulation.html", {"default_passwords": "\n".join(DEFAULT_PASSWORDS)})


# --- helpers ----------------------------------------------------------------
def _payload(request) -> dict:
    try:
        body = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        raise ValueError("invalid JSON")
    raw = body.get("passwords", [])
    if isinstance(raw, str):
        raw = raw.splitlines()
    seen, passwords = set(), []
    for item in raw:
        if isinstance(item, str):
            item = item.strip()
            if item and item not in seen and len(item) <= 256:
                seen.add(item)
                passwords.append(item)
    if not passwords:
        raise ValueError("give at least one password")
    if len(passwords) > MAX_PASSWORDS:
        raise ValueError(f"at most {MAX_PASSWORDS} passwords in the simulation")
    try:
        p = float(body.get("fp_rate", 0.01))
    except (TypeError, ValueError):
        raise ValueError("fp_rate must be a number")
    if not (1e-4 <= p <= 0.5):
        raise ValueError("fp_rate must be between 0.0001 and 0.5")
    body["passwords"], body["fp_rate"] = passwords, p
    return body


def trace(password: str, m: int, k: int) -> dict:
    """Everything the formula does to one password, for display."""
    d = sha1_digest(password)
    h1 = int.from_bytes(d[0:8], "big")
    h2 = int.from_bytes(d[8:16], "big") | 1
    return {
        "password": password,
        "sha1": d.hex().upper(),
        "h1_hex": d[0:8].hex().upper(),
        "h2_hex": d[8:16].hex().upper(),
        "h1": str(h1),
        "h2": str(h2),
        "positions": list(positions(d, m, k)),
    }


class SimFilter:
    """A tiny real filter built with BloomBuilder into a temp dir."""

    def __init__(self, passwords: list[str], p: float):
        self.n = len(passwords)
        self.m, self.k = sizing(self.n, p)
        if self.m > MAX_BITS:
            raise ValueError(f"that needs m = {self.m:,} bits; use fewer passwords or a higher false-positive rate (max {MAX_BITS:,} bits)")
        self.p = p
        self.tmp = tempfile.TemporaryDirectory(prefix="bloom-sim-")
        self.path = Path(self.tmp.name) / "sim.bloom"
        with BloomBuilder.create(self.path, n=self.n, p=p) as b:
            b.add_passwords(passwords)
        self.filter = BloomFilter(self.path)

    def set_bits(self) -> list[int]:
        data = self.path.read_bytes()[HEADER_SIZE:]
        return [i for i in range(self.m) if data[i >> 3] & (1 << (i & 7))]

    def bit(self, pos: int) -> bool:
        data = self.path.read_bytes()[HEADER_SIZE:]
        return bool(data[pos >> 3] & (1 << (pos & 7)))

    def measured_fp(self, samples: int = 20_000) -> float:
        """Empirical false-positive rate over random never-inserted strings.

        At toy sizes this is *higher* than the formula: with m of a few dozen
        bits the k double-hashed positions of two different passwords are
        correlated (both are arithmetic progressions mod m), so the
        independence assumption behind (1 - e^(-kn/m))^k breaks. At the
        production size (3.6e10 bits) the formula holds; the test suite checks
        it at n = 20,000."""
        hits = sum(self.filter.contains_password(secrets.token_urlsafe(9)) for _ in range(samples))
        return hits / samples

    def close(self):
        self.filter.close()
        self.tmp.cleanup()


def _sizing_block(n: int, p: float, m: int, k: int) -> dict:
    raw_m = -n * math.log(p) / math.log(2) ** 2
    return {
        "n": n,
        "p": p,
        "m_raw": raw_m,
        "m": m,
        "k_raw": m / n * math.log(2),
        "k": k,
        "bytes": HEADER_SIZE + m // 8,
    }


# --- endpoints --------------------------------------------------------------
@require_POST
def api_build(request):
    try:
        body = _payload(request)
        sim = SimFilter(body["passwords"], body["fp_rate"])
    except ValueError as exc:
        return HttpResponseBadRequest(str(exc))
    try:
        items = [trace(pw, sim.m, sim.k) for pw in body["passwords"]]
        set_bits = sim.set_bits()
        return JsonResponse(
            {
                "sizing": _sizing_block(sim.n, sim.p, sim.m, sim.k),
                "items": items,
                "set_bits": set_bits,
                "fill_ratio": len(set_bits) / sim.m,
                "estimated_fp": estimated_fp_rate(sim.m, sim.k, sim.n),
                "measured_fp": sim.measured_fp(),
                "measured_samples": 20_000,
                "header": sim.filter.header.pack()[:HEADER_SIZE].hex().upper(),
            }
        )
    finally:
        sim.close()


@require_POST
def api_check(request):
    try:
        body = _payload(request)
        probe = body.get("probe", "")
        if not isinstance(probe, str) or not probe:
            raise ValueError("probe password is required")
        sim = SimFilter(body["passwords"], body["fp_rate"])
    except ValueError as exc:
        return HttpResponseBadRequest(str(exc))
    try:
        return JsonResponse(_check(sim, body["passwords"], probe))
    finally:
        sim.close()


def _check(sim: SimFilter, passwords: list[str], probe: str) -> dict:
    t = trace(probe, sim.m, sim.k)
    bits = []
    first_zero = None
    for i, pos in enumerate(t["positions"]):
        is_set = sim.bit(pos)
        bits.append({"i": i, "pos": pos, "set": is_set})
        if not is_set and first_zero is None:
            first_zero = i
    in_filter = sim.filter.contains_password(probe)
    assert in_filter == (first_zero is None)
    validator = BloomPwnedValidator(path=str(sim.path), fail_closed=True)
    try:
        validator.validate(probe)
        message, code = None, None
    except ValidationError as exc:
        message, code = exc.messages[0], exc.error_list[0].code
    in_list = probe in passwords
    return {
        "trace": t,
        "bits": bits,
        "first_zero": first_zero,
        "verdict": "reject" if in_filter else "pass",
        "kind": "true_positive" if (in_filter and in_list) else "false_positive" if in_filter else "true_negative",
        "in_list": in_list,
        "validator": {"message": message, "code": code, "help_text": validator.get_help_text()},
        "sizing": _sizing_block(sim.n, sim.p, sim.m, sim.k),
    }


@require_POST
def api_hunt(request):
    """Find a false positive by brute force, to make the p in the formula tangible."""
    try:
        body = _payload(request)
        sim = SimFilter(body["passwords"], body["fp_rate"])
    except ValueError as exc:
        return HttpResponseBadRequest(str(exc))
    try:
        for tries in range(1, MAX_HUNT_TRIES + 1):
            candidate = secrets.token_urlsafe(9)
            if sim.filter.contains_password(candidate) and candidate not in body["passwords"]:
                result = _check(sim, body["passwords"], candidate)
                result["tries"] = tries
                result["expected_tries"] = 1 / max(sim.measured_fp(), 1e-9)
                return JsonResponse(result)
        return JsonResponse({"tries": MAX_HUNT_TRIES, "verdict": None, "expected_tries": 1 / max(sim.measured_fp(), 1e-9)})
    finally:
        sim.close()
