"""Write a demo password list: Django's bundled 20k common passwords plus a few
well-known breached strings that are *not* in Django's list, so the Bloom
layer visibly adds coverage in development. Production builds use the real
HIBP corpus instead (scripts/refresh_pwned.sh)."""

import gzip
import sys
from pathlib import Path

import django.contrib.auth.password_validation as pv

EXTRA = [
    "Summer2024!", "Summer2025!", "Summer2026!", "Winter2026!", "P@ssw0rd", "P@ssw0rd123",
    "Password123!", "Welcome123!", "Qwerty123456!", "Letmein2026!", "Iloveyou12345",
    "correcthorsebatterystaple", "Tr0ub4dor&3", "ThisIsMyPassword1", "passwordpassword",
    "mathematics123", "pythagoras123", "Euler2026", "3.14159265358979",
]

out = Path(sys.argv[1])
out.parent.mkdir(parents=True, exist_ok=True)
with gzip.open(Path(pv.__file__).resolve().parent / "common-passwords.txt.gz", "rt", encoding="utf-8") as f:
    common = [ln.strip() for ln in f if ln.strip()]
out.write_text("\n".join(common + EXTRA) + "\n", encoding="utf-8")
print(f"{len(common) + len(EXTRA)} passwords → {out}")
