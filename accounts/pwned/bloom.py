"""
Bloom filter over the Have I Been Pwned (HIBP) Pwned Passwords SHA-1 corpus.

One module holds *both* the file format and the bit-position formula so the
offline builder and the request-time validator can never drift apart. A parity
test (accounts/tests/test_bloom.py) builds a tiny filter and checks the
validator rejects exactly the passwords that went in.

File layout (little-endian, 64-byte header, then the bit array):

    offset  size  field
    0       8     magic  b"HIBPBLM1"
    8       8     m      number of bits
    16      4     k      number of hash functions
    20      8     n      items inserted (0 if unknown)
    28      8     built_at  unix timestamp of the build
    36      8     p      target false-positive rate (float64)
    44..64        reserved (zero)

The first 20 bytes are identical to the format in the source article, so a
reader that only understands ``magic + <QI`` still works.

Bit positions use Kirsch–Mitzenmacher double hashing on the SHA-1 digest
itself: h1 = bytes 0..8, h2 = bytes 8..16 | 1, pos_i = (h1 + i*h2) mod 2^64 mod m.
SHA-1 output is already uniform, so no further hashing is needed; the explicit
mod 2^64 keeps pure-Python and numpy uint64 arithmetic in step.
"""

from __future__ import annotations

import hashlib
import math
import mmap
import os
import struct
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

MAGIC = b"HIBPBLM1"
HEADER_SIZE = 64
HEADER = struct.Struct("<8sQIQQd")  # magic, m, k, n, built_at, p  (44 bytes)
MASK64 = (1 << 64) - 1


class BloomFormatError(OSError):
    """The file is not a Bloom filter in the format this module understands."""


def sha1_digest(password: str) -> bytes:
    """HIBP keys the corpus by SHA-1 of the UTF-8 bytes. SHA-1 is only a lookup
    key here; it has nothing to do with how Django stores passwords."""
    return hashlib.sha1(password.encode("utf-8")).digest()


def sizing(n: int, p: float) -> tuple[int, int]:
    """Return (m bits, k hashes) for n items at false-positive rate p.

    m = -n ln p / (ln 2)^2, rounded up to a multiple of 64; k = (m/n) ln 2.
    """
    if n <= 0 or not (0 < p < 1):
        raise ValueError("n must be positive and 0 < p < 1")
    m = int(math.ceil(-n * math.log(p) / (math.log(2) ** 2)))
    m = (m + 63) // 64 * 64
    k = max(1, round(m / n * math.log(2)))
    return m, k


def estimated_fp_rate(m: int, k: int, n: int) -> float:
    """Theoretical false-positive rate once n items are inserted."""
    if n <= 0:
        return 0.0
    return (1 - math.exp(-k * n / m)) ** k


def positions(digest: bytes, m: int, k: int) -> Iterator[int]:
    h1 = int.from_bytes(digest[0:8], "big")
    h2 = int.from_bytes(digest[8:16], "big") | 1
    for i in range(k):
        yield ((h1 + i * h2) & MASK64) % m


@dataclass(frozen=True)
class Header:
    m: int
    k: int
    n: int
    built_at: int
    p: float

    @property
    def built_at_datetime(self) -> datetime | None:
        if not self.built_at:
            return None
        return datetime.fromtimestamp(self.built_at, tz=timezone.utc)

    @property
    def size_bytes(self) -> int:
        return HEADER_SIZE + self.m // 8

    @property
    def estimated_fp_rate(self) -> float:
        return estimated_fp_rate(self.m, self.k, self.n)

    def pack(self) -> bytes:
        return HEADER.pack(MAGIC, self.m, self.k, self.n, self.built_at, self.p).ljust(HEADER_SIZE, b"\0")

    @classmethod
    def unpack(cls, raw: bytes) -> "Header":
        if len(raw) < HEADER_SIZE or raw[:8] != MAGIC:
            raise BloomFormatError("not a HIBPBLM1 Bloom filter")
        magic, m, k, n, built_at, p = HEADER.unpack_from(raw, 0)
        if m == 0 or m % 8 or k == 0:
            raise BloomFormatError("corrupt Bloom header")
        return cls(m=m, k=k, n=n, built_at=built_at, p=p)


class BloomFilter:
    """Read-only, memory-mapped filter. Open once per process and share."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        with open(self.path, "rb") as f:
            self._mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            self.header = Header.unpack(self._mm[:HEADER_SIZE])
        except BloomFormatError:
            self._mm.close()
            raise
        if len(self._mm) < self.header.size_bytes:
            self._mm.close()
            raise BloomFormatError("Bloom file is truncated")

    def contains_digest(self, digest: bytes) -> bool:
        mm, m, k = self._mm, self.header.m, self.header.k
        for pos in positions(digest, m, k):
            if not mm[HEADER_SIZE + (pos >> 3)] & (1 << (pos & 7)):
                return False  # definitely not in the corpus
        return True  # probably in the corpus (rate = header.p)

    def contains_password(self, password: str) -> bool:
        return self.contains_digest(sha1_digest(password))

    __contains__ = contains_password

    def age(self, now: float | None = None) -> float | None:
        """Seconds since the build, or None if the header has no timestamp."""
        if not self.header.built_at:
            return None
        return (now if now is not None else time.time()) - self.header.built_at

    def close(self) -> None:
        self._mm.close()


class BloomBuilder:
    """Write a filter. Pure Python for small inputs (tests, demos); numpy
    paths for the 1.9-billion-hash corpus. Both share ``positions``.

    Usage::

        with BloomBuilder.create("out.bloom", n=1_900_000_000, p=1e-4) as b:
            b.add_range_directory("hashes/")   # numpy
    """

    def __init__(self, path: Path, header: Header):
        self.path = path
        self.header = header
        self._f = open(path, "r+b")
        self._mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_WRITE)
        self.count = 0

    @classmethod
    def create(cls, path: str | os.PathLike, n: int, p: float = 1e-4) -> "BloomBuilder":
        m, k = sizing(n, p)
        header = Header(m=m, k=k, n=0, built_at=0, p=p)
        path = Path(path)
        with open(path, "wb") as f:
            f.write(header.pack())
            f.truncate(header.size_bytes)
        return cls(path, header)

    # -- pure Python -------------------------------------------------------
    def add_digest(self, digest: bytes) -> None:
        mm, m, k = self._mm, self.header.m, self.header.k
        for pos in positions(digest, m, k):
            idx = HEADER_SIZE + (pos >> 3)
            mm[idx] |= 1 << (pos & 7)
        self.count += 1

    def add_digests(self, digests: Iterable[bytes]) -> None:
        for d in digests:
            self.add_digest(d)

    def add_passwords(self, passwords: Iterable[str]) -> None:
        self.add_digests(sha1_digest(p) for p in passwords)

    # -- numpy (offline build job) ----------------------------------------
    def _bits_array(self):
        import numpy as np

        return np.frombuffer(self._mm, dtype=np.uint8, offset=HEADER_SIZE)

    def add_hex_batch(self, hexes: str) -> None:
        """Insert a concatenated string of 40-hex-char SHA-1s (vectorised)."""
        import numpy as np

        if not hexes:
            return
        raw = np.frombuffer(bytes.fromhex(hexes), dtype=np.uint8).reshape(-1, 20)
        h1 = raw[:, 0:8].copy().view(">u8").ravel().astype(np.uint64)
        h2 = raw[:, 8:16].copy().view(">u8").ravel().astype(np.uint64) | np.uint64(1)
        bits = self._bits_array()
        M = np.uint64(self.header.m)
        with np.errstate(over="ignore"):  # uint64 wrap == the "& MASK64" above
            for i in range(self.header.k):
                pos = (h1 + np.uint64(i) * h2) % M
                np.bitwise_or.at(
                    bits,
                    (pos >> np.uint64(3)).astype(np.int64),
                    (np.uint8(1) << (pos & np.uint64(7)).astype(np.uint8)),
                )
        self.count += raw.shape[0]

    def add_range_file(self, path: Path, prefix: str, min_count: int = 0) -> None:
        """One ``PREFIX.txt`` from the HIBP downloader: lines ``SUFFIX35:count``."""
        text = path.read_text()
        if min_count > 1:
            lines = [ln for ln in text.split() if int(ln.partition(":")[2] or 0) >= min_count]
        else:
            lines = text.split()
        self.add_hex_batch("".join(prefix + ln[:35] for ln in lines))

    def add_range_directory(self, src_dir: str | os.PathLike, min_count: int = 0, progress=None) -> None:
        """All 1,048,576 ``00000.txt`` … ``FFFFF.txt`` files from
        ``haveibeenpwned-downloader hashes``."""
        files = sorted(Path(src_dir).glob("*.txt"))
        for i, path in enumerate(files):
            self.add_range_file(path, path.stem.upper(), min_count)
            if progress and i % 10_000 == 0:
                progress(i, len(files))

    def add_single_file(self, path: str | os.PathLike, min_count: int = 0, batch: int = 200_000) -> None:
        """The ``--single`` downloader output: lines ``SHA1HEX40:count``."""
        buf: list[str] = []
        with open(path, "r", encoding="ascii") as f:
            for line in f:
                h, _, c = line.strip().partition(":")
                if len(h) != 40:
                    continue
                if min_count > 1 and int(c or 0) < min_count:
                    continue
                buf.append(h)
                if len(buf) >= batch:
                    self.add_hex_batch("".join(buf))
                    buf.clear()
        if buf:
            self.add_hex_batch("".join(buf))

    # -- finish ------------------------------------------------------------
    def finalize(self) -> Header:
        self.header = Header(
            m=self.header.m, k=self.header.k, n=self.count, built_at=int(time.time()), p=self.header.p
        )
        self._mm[:HEADER_SIZE] = self.header.pack()
        self._mm.flush()
        self._mm.close()
        self._f.close()
        return self.header

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.finalize()
        else:
            self._mm.close()
            self._f.close()
        return False
