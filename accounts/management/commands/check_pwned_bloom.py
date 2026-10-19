"""
Report on the deployed Bloom filter for monitoring. Exit status 1 if the file
is missing/corrupt or older than PWNED_BLOOM_MAX_AGE, so it slots into a
health check or cron alert.
"""

from django.conf import settings
from django.core.management.base import BaseCommand

from accounts.pwned.bloom import BloomFilter, BloomFormatError


class Command(BaseCommand):
    help = "Print Bloom filter metadata and age; non-zero exit if unavailable or stale."

    def add_arguments(self, parser):
        parser.add_argument("--path", default=None)
        parser.add_argument("--probe", action="append", default=[], help="password to test (repeatable)")

    def handle(self, *args, **opts):
        path = opts["path"] or settings.PWNED_BLOOM_PATH
        try:
            bf = BloomFilter(path)
        except (OSError, BloomFormatError) as exc:
            self.stderr.write(self.style.ERROR(f"UNAVAILABLE {path}: {exc}"))
            raise SystemExit(1)
        h = bf.header
        age = bf.age()
        self.stdout.write(f"path       {path}")
        self.stdout.write(f"size       {h.size_bytes:,} bytes")
        self.stdout.write(f"m / k / n  {h.m:,} / {h.k} / {h.n:,}")
        self.stdout.write(f"target p   {h.p:.2e}   estimated p {h.estimated_fp_rate:.2e}")
        self.stdout.write(f"built_at   {h.built_at_datetime}   age {age / 86400:.1f} days" if age is not None else "built_at   unknown")
        for pw in opts["probe"]:
            self.stdout.write(f"probe {pw!r}: {'IN corpus (probably)' if bf.contains_password(pw) else 'not in corpus'}")
        stale = age is not None and age > settings.PWNED_BLOOM_MAX_AGE.total_seconds()
        bf.close()
        if stale:
            self.stderr.write(self.style.ERROR("STALE: older than PWNED_BLOOM_MAX_AGE"))
            raise SystemExit(1)
        self.stdout.write(self.style.SUCCESS("OK"))
