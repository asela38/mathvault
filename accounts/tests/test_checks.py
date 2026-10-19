import time

from django.core.checks import Error, Warning
from django.core.management import call_command

from accounts.checks import check_pwned_bloom
from accounts.pwned.bloom import HEADER_SIZE, BloomFilter, Header


def test_missing_file_warns_or_errors(settings, tmp_path):
    settings.PWNED_BLOOM_PATH = tmp_path / "missing.bloom"
    settings.PWNED_FAIL_CLOSED = False
    [issue] = check_pwned_bloom(None)
    assert isinstance(issue, Warning) and issue.id == "accounts.W001"
    settings.PWNED_FAIL_CLOSED = True
    [issue] = check_pwned_bloom(None)
    assert isinstance(issue, Error) and issue.id == "accounts.E001"


def test_stale_file_warns(settings, tmp_path, demo_bloom_path):
    stale = tmp_path / "stale.bloom"
    data = bytearray(demo_bloom_path.read_bytes())
    h = Header.unpack(bytes(data[:HEADER_SIZE]))
    old = Header(m=h.m, k=h.k, n=h.n, built_at=int(time.time()) - 60 * 86400, p=h.p)
    data[:HEADER_SIZE] = old.pack()
    stale.write_bytes(bytes(data))
    settings.PWNED_BLOOM_PATH = stale
    [issue] = check_pwned_bloom(None)
    assert issue.id == "accounts.W002"
    assert BloomFilter(stale).age() > 45 * 86400


def test_fresh_file_is_clean(settings, demo_bloom_path):
    settings.PWNED_BLOOM_PATH = demo_bloom_path
    assert check_pwned_bloom(None) == []


def test_build_and_check_commands_roundtrip(tmp_path, settings, capsys):
    src = tmp_path / "pw.txt"
    src.write_text("hunter2\nletmein\n")
    out = tmp_path / "cmd.bloom"
    call_command("build_pwned_bloom", "--passwords", str(src), "--out", str(out), "--fp-rate", "0.001")
    assert out.exists() and out.with_suffix(".bloom.sha256").exists()
    settings.PWNED_BLOOM_PATH = out
    call_command("check_pwned_bloom", "--probe", "hunter2", "--probe", "not-in-there")
    text = capsys.readouterr().out
    assert "probe 'hunter2': IN corpus" in text and "probe 'not-in-there': not in corpus" in text and "OK" in text
