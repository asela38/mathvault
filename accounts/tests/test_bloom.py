"""Builder/validator parity, sizing, known-bad/known-good and the empirical
false-positive rate — the test plan from the source article."""

import math
import secrets

import numpy as np
import pytest

from accounts.pwned.bloom import (
    HEADER_SIZE,
    BloomBuilder,
    BloomFilter,
    BloomFormatError,
    Header,
    estimated_fp_rate,
    positions,
    sha1_digest,
    sizing,
)

from .conftest import KNOWN_BAD


def test_sizing_matches_article_table():
    # n = 1.9e9, p = 1e-4 → ~4.3 GB (4.24 GiB) and 13 hash functions
    m, k = sizing(1_900_000_000, 1e-4)
    assert k == 13
    assert 4.2 < m / 8 / 2**30 < 4.3
    assert sizing(1_900_000_000, 1e-3)[1] == 10
    assert sizing(1_900_000_000, 1e-6)[1] == 20
    assert m % 64 == 0


def test_header_roundtrip_and_article_compatible_prefix():
    h = Header(m=1024, k=7, n=5, built_at=1_700_000_000, p=1e-4)
    raw = h.pack()
    assert len(raw) == HEADER_SIZE
    assert raw[:8] == b"HIBPBLM1"
    import struct

    assert struct.unpack_from("<QI", raw, 8) == (1024, 7)  # the article's reader still works
    assert Header.unpack(raw) == h


def test_positions_wrap_at_64_bits():
    digest = bytes([0xFF] * 20)
    m, k = 1_000_003, 5
    pos = list(positions(digest, m, k))
    assert all(0 <= p < m for p in pos)
    h1 = int.from_bytes(digest[:8], "big")
    h2 = int.from_bytes(digest[8:16], "big") | 1
    assert pos[3] == ((h1 + 3 * h2) % 2**64) % m


def test_known_bad_rejected_and_known_good_pass(demo_bloom_path):
    bf = BloomFilter(demo_bloom_path)
    for pw in KNOWN_BAD:
        assert pw in bf
    for _ in range(100):
        assert secrets.token_urlsafe(24) not in bf
    bf.close()


def test_builder_numpy_and_python_paths_are_bit_identical(tmp_path):
    passwords = [f"parity-{i}" for i in range(500)]
    digests = [sha1_digest(p) for p in passwords]
    py, npy = tmp_path / "py.bloom", tmp_path / "np.bloom"
    with BloomBuilder.create(py, n=500, p=1e-3) as b:
        b.add_digests(digests)
    with BloomBuilder.create(npy, n=500, p=1e-3) as b:
        b.add_hex_batch("".join(d.hex() for d in digests))
    assert py.read_bytes()[HEADER_SIZE:] == npy.read_bytes()[HEADER_SIZE:]
    bf = BloomFilter(npy)
    assert all(p in bf for p in passwords)
    assert bf.header.n == 500
    bf.close()


def test_range_directory_build_uses_prefix_and_count_threshold(tmp_path):
    hashes = tmp_path / "hashes"
    hashes.mkdir()
    pw_hex = {pw: sha1_digest(pw).hex().upper() for pw in ["range-a", "range-b", "range-c"]}
    counts = {"range-a": 5, "range-b": 1, "range-c": 300}
    for pw, hx in pw_hex.items():
        (hashes / f"{hx[:5]}.txt").write_text(f"{hx[5:]}:{counts[pw]}\r\n")
    out = tmp_path / "ranges.bloom"
    with BloomBuilder.create(out, n=10, p=1e-3) as b:
        b.add_range_directory(hashes, min_count=2)
    bf = BloomFilter(out)
    assert "range-a" in bf and "range-c" in bf
    assert "range-b" not in bf  # seen once, below threshold
    assert bf.header.n == 2
    bf.close()


def test_single_file_build(tmp_path):
    single = tmp_path / "single.txt"
    single.write_text("\n".join(f"{sha1_digest(f's{i}').hex().upper()}:{i + 1}" for i in range(50)))
    out = tmp_path / "single.bloom"
    with BloomBuilder.create(out, n=50, p=1e-3) as b:
        b.add_single_file(single, batch=7)
    bf = BloomFilter(out)
    assert all(f"s{i}" in bf for i in range(50))
    bf.close()


@pytest.mark.slow
def test_empirical_false_positive_rate(tmp_path):
    """Build at p = 1 % with 20k random items, probe 100k random strings; the
    observed rate must sit near 1 % (binomial 99.9 % band ≈ 0.9–1.1 %)."""
    n, p, probes = 20_000, 1e-2, 100_000
    out = tmp_path / "fp.bloom"
    with BloomBuilder.create(out, n=n, p=p) as b:
        rng = np.random.default_rng(42)
        b.add_hex_batch(rng.bytes(20 * n).hex())
    bf = BloomFilter(out)
    hits = sum(bf.contains_digest(secrets.token_bytes(20)) for _ in range(probes))
    rate = hits / probes
    bf.close()
    expected = estimated_fp_rate(bf.header.m, bf.header.k, n)
    sigma = math.sqrt(expected * (1 - expected) / probes)
    assert abs(rate - expected) < 5 * sigma, f"observed {rate:.4%}, expected {expected:.4%}"


def test_corrupt_or_missing_file_raises(tmp_path):
    bad = tmp_path / "bad.bloom"
    bad.write_bytes(b"not a bloom filter at all, definitely longer than 64 bytes ........")
    with pytest.raises(BloomFormatError):
        BloomFilter(bad)
    with pytest.raises(FileNotFoundError):
        BloomFilter(tmp_path / "missing.bloom")
    truncated = tmp_path / "trunc.bloom"
    truncated.write_bytes(Header(m=8 * 1024, k=3, n=0, built_at=0, p=0.01).pack() + b"\0" * 10)
    with pytest.raises(BloomFormatError):
        BloomFilter(truncated)
