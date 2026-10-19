# Operations: the HIBP Bloom filter

The web app's only runtime cost is one read-only ~4.3 GB file per node,
memory-mapped once per process and shared through the page cache. All heavy
work (download, build) happens in a scheduled job that never touches the
request path.

## 1. Build host

* ~100 GB scratch space (the SHA-1 corpus is ~75 GB as text; the downloader
  keeps an ETag index so later runs fetch only changed ranges).
* 8+ cores help the parallel download; the numpy build is single-threaded and
  takes an hour or more over ~1.9 billion hashes. Port the loop in
  `BloomBuilder.add_hex_batch` to Go/Rust if that matters — the file format
  and bit formula are documented in `accounts/pwned/bloom.py`.
* .NET 10 for the official downloader:
  `dotnet tool install --global haveibeenpwned-downloader`.

```bash
uv sync --extra build                                   # numpy
haveibeenpwned-downloader /scratch/pwned/hashes -p 64   # 1,048,576 files 00000.txt … FFFFF.txt
uv run python manage.py build_pwned_bloom \
    --hashes-dir /scratch/pwned/hashes \
    --expected-items 1900000000 --fp-rate 0.0001 \
    --out /data/pwned/pwned-$(date -u +%Y%m).bloom
```

The command writes to a `.tmp` file, renames it into place and writes a
`.sha256` next to it. `scripts/refresh_pwned.sh` wraps all of this.

### Sizing (n = 1.9 billion)

| False-positive rate | Filter size | Hash functions |
|---|---|---|
| 1 in 1,000 | ~3.2 GB | 10 |
| 1 in 10,000 | ~4.3 GB | 13 |
| 1 in 1,000,000 | ~6.5 GB | 20 |

`--expected-items` only needs to be in the right ballpark; the header records
the real count and `check_pwned_bloom` prints the resulting estimated rate.
Re-estimate once a year from the corpus size (text bytes ÷ ~42 per line).

## 2. Deployment

1. Upload `pwned-YYYYMM.bloom` and `.sha256` to object storage.
2. On each node (or a shared read-only volume): download, verify the
   checksum, then atomically repoint `current.bloom` (symlink swap or rename).
3. Rolling restart of the app processes. Running workers keep the old mapping
   until they exit, so there is never a partial read.
4. Keep the previous file for one cycle so rollback is a symlink change.

Kubernetes sketch:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata: { name: pwned-refresh }
spec:
  schedule: "0 3 1 * *"          # monthly
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: refresh
              image: ghcr.io/example/mathvault-build:latest
              command: ["scripts/refresh_pwned.sh"]
              env: [{ name: SCRATCH, value: /scratch/pwned }, { name: OUT_DIR, value: /data/pwned }]
              volumeMounts:
                - { name: scratch, mountPath: /scratch }
                - { name: pwned, mountPath: /data/pwned }
          volumes:
            - name: scratch
              ephemeral: { volumeClaimTemplate: { spec: { resources: { requests: { storage: 120Gi } }, accessModes: [ReadWriteOnce] } } }
            - name: pwned
              persistentVolumeClaim: { claimName: pwned-filters }   # mounted read-only by the web pods
```

## 3. Settings

| Setting | Default | Meaning |
|---|---|---|
| `PWNED_BLOOM_PATH` | `data/pwned/current.bloom` | file the validator maps |
| `PWNED_FAIL_CLOSED` | `False` | reject with "temporarily unavailable" when the file (or API) is unusable |
| `PWNED_BLOOM_MAX_AGE` | 45 days | system check W002 / `check_pwned_bloom` exit 1 beyond this |
| `PWNED_API_ENABLED` | `True` | also query the HIBP range API; set `0` in air-gapped deployments |
| `PWNED_API_TIMEOUT` | 2.0 s | per-request timeout; failure follows the fail-open/closed rule |

## 4. Monitoring

| Signal | Source | Alert when |
|---|---|---|
| Age of `current.bloom` | `manage.py check_pwned_bloom` (exit 1), system check `accounts.W002` | older than ~45 days (one missed refresh) |
| Validator load failures | log `mathvault.password_screening` → `pwned_bloom_unavailable`, `pwned_api_unavailable`; system check `accounts.W001/E001` | any occurrence |
| Rejection rate after a refresh | log events `pwned_rejected source=bloom|api` | jumps sharply (bad build) |
| Build job | CronJob status, runtime | fails, or runtime more than doubles |

Nothing in those log lines includes the password, its hash, or the user.

## 5. Resource sizing per app node

| Resource | Expectation |
|---|---|
| Disk | ~4.3 GB for the current file; double during a swap if the previous is kept |
| Memory | ~4.3 GB of page cache shared by every process mapping the file; mapped pages may count toward container memory accounting, so allow headroom |
| Lookup latency | 13 random reads; microseconds once warm; first lookups after a restart may touch disk |

## 6. Testing the pipeline without the corpus

```bash
make demo-bloom      # ~20k passwords, 47 KB — same format, same code paths
make check           # probes: password / P@ssw0rd rejected, passphrase accepted
uv run pytest accounts/tests/test_bloom.py   # parity, range-file build, fp rate
```

To exercise the numpy range-file path on real data, download a single range
(`curl https://api.pwnedpasswords.com/range/5BAA6 > hashes/5BAA6.txt`) and
build with `--hashes-dir hashes --expected-items 1000`; `password` (SHA-1
prefix 5BAA6) must then be rejected.
