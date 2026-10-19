"""
Offline build of the HIBP Bloom filter. Runs in the refresh job, never on the
request path. Three input modes:

  --hashes-dir DIR   output of `haveibeenpwned-downloader hashes -p 64`
                     (1,048,576 files 00000.txt … FFFFF.txt); needs numpy
  --single FILE      output of `haveibeenpwned-downloader --single`; needs numpy
  --passwords FILE   plain-text password list (one per line) — for demos/tests;
                     pure Python, no numpy

Sizing: --expected-items (n) and --fp-rate (p). The filter is written to a
temporary file and renamed into place, with a .sha256 alongside.

    manage.py build_pwned_bloom --hashes-dir /scratch/hashes \
        --expected-items 1900000000 --fp-rate 0.0001 --out /data/pwned/pwned-202610.bloom
"""

import hashlib
import os
import sys
import time
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from accounts.pwned.bloom import BloomBuilder, sizing


class Command(BaseCommand):
    help = "Build the Have I Been Pwned Bloom filter used by BloomPwnedValidator."

    def add_arguments(self, parser):
        src = parser.add_mutually_exclusive_group(required=True)
        src.add_argument("--hashes-dir", help="directory of PREFIX.txt range files")
        src.add_argument("--single", help="single-file corpus (SHA1:count per line)")
        src.add_argument("--passwords", help="plain-text password list (demo/test)")
        parser.add_argument("--out", required=True, help="output .bloom path")
        parser.add_argument("--expected-items", type=int, help="n (default: count the input first)")
        parser.add_argument("--fp-rate", type=float, default=1e-4, help="target false-positive rate (default 1e-4)")
        parser.add_argument("--min-count", type=int, default=0, help="only include hashes seen >= N times in breaches")

    def handle(self, *args, **opts):
        out = Path(opts["out"])
        tmp = out.with_name(out.name + ".tmp")
        n = opts["expected_items"]
        started = time.time()

        if opts["passwords"]:
            passwords = [ln.rstrip("\r\n") for ln in Path(opts["passwords"]).read_text(encoding="utf-8").splitlines() if ln.strip()]
            n = n or len(passwords)
            self.stdout.write(f"Building from {len(passwords)} passwords: n={n} p={opts['fp_rate']}")
            with BloomBuilder.create(tmp, n=n, p=opts["fp_rate"]) as b:
                b.add_passwords(passwords)
        else:
            try:
                import numpy  # noqa: F401
            except ImportError as exc:
                raise CommandError("numpy is required for corpus builds: uv sync --extra build") from exc
            if n is None:
                raise CommandError("--expected-items is required for corpus builds (≈1.9e9 for the full SHA-1 corpus)")
            m, k = sizing(n, opts["fp_rate"])
            self.stdout.write(f"n={n:,} p={opts['fp_rate']} → m={m:,} bits ({m / 8 / 2**30:.2f} GiB), k={k}")
            with BloomBuilder.create(tmp, n=n, p=opts["fp_rate"]) as b:
                if opts["hashes_dir"]:
                    b.add_range_directory(
                        opts["hashes_dir"],
                        min_count=opts["min_count"],
                        progress=lambda i, total: print(f"{i}/{total} ranges", file=sys.stderr),
                    )
                else:
                    b.add_single_file(opts["single"], min_count=opts["min_count"])

        header = BloomBuilder(tmp, _read_header(tmp)).header  # re-read the finalized header
        digest = hashlib.sha256()
        with open(tmp, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        os.replace(tmp, out)
        out.with_suffix(out.suffix + ".sha256").write_text(f"{digest.hexdigest()}  {out.name}\n")
        self.stdout.write(
            self.style.SUCCESS(
                f"Wrote {out} ({out.stat().st_size:,} bytes): m={header.m:,} k={header.k} n={header.n:,} "
                f"est. fp={header.estimated_fp_rate:.2e} in {time.time() - started:.1f}s"
            )
        )


def _read_header(path):
    from accounts.pwned.bloom import HEADER_SIZE, Header

    with open(path, "rb") as f:
        return Header.unpack(f.read(HEADER_SIZE))
