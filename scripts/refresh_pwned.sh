#!/usr/bin/env bash
# Monthly refresh job: download the HIBP corpus incrementally, rebuild the
# Bloom filter, publish it with a checksum. Intended for a CronJob on a host
# with ~100 GB scratch space. See docs/OPERATIONS.md for the node-side swap.
#
# Requirements: dotnet tool `haveibeenpwned-downloader`, Python env with numpy
# (uv sync --extra build).
set -euo pipefail

SCRATCH="${SCRATCH:-/scratch/pwned}"          # keeps the ETag index between runs
OUT_DIR="${OUT_DIR:-/data/pwned}"
N_ITEMS="${N_ITEMS:-1900000000}"              # ≈ corpus size; re-estimate yearly
FP_RATE="${FP_RATE:-0.0001}"
STAMP="$(date -u +%Y%m)"
OUT="$OUT_DIR/pwned-$STAMP.bloom"

mkdir -p "$SCRATCH" "$OUT_DIR"

echo "[1/4] downloading changed ranges into $SCRATCH/hashes"
haveibeenpwned-downloader "$SCRATCH/hashes" -p 64 -o

echo "[2/4] building $OUT"
uv run python manage.py build_pwned_bloom \
    --hashes-dir "$SCRATCH/hashes" --expected-items "$N_ITEMS" --fp-rate "$FP_RATE" --out "$OUT"

echo "[3/4] verifying checksum"
(cd "$OUT_DIR" && sha256sum -c "$(basename "$OUT").sha256")

echo "[4/4] atomic swap of current.bloom (previous kept for rollback)"
if [ -e "$OUT_DIR/current.bloom" ]; then
    ln -sfn "$(readlink "$OUT_DIR/current.bloom" || echo current.bloom)" "$OUT_DIR/previous.bloom"
fi
ln -sfn "$(basename "$OUT")" "$OUT_DIR/current.bloom.tmp" && mv -Tf "$OUT_DIR/current.bloom.tmp" "$OUT_DIR/current.bloom"
uv run python manage.py check_pwned_bloom --path "$OUT_DIR/current.bloom"
echo "done — roll the app processes so workers map the new file"
