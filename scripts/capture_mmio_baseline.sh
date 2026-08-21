#!/bin/bash
# Capture MMIO dump from dmesg (run after loading snd-quantum).
# Writes notes/MMIO_baseline_YYYYMMDD_HHMM.txt

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NOTES="$REPO_ROOT/notes"
STAMP="$(date +%Y%m%d_%H%M)"
OUT="$NOTES/MMIO_baseline_$STAMP.txt"

mkdir -p "$NOTES"
echo "Capturing MMIO lines from dmesg..." >&2
sudo dmesg | grep -E "snd-quantum.*MMIO|quantum.*MMIO" | tail -64 > "$OUT" || true
if [ ! -s "$OUT" ]; then
  echo "No MMIO lines found. Load the driver first: sudo modprobe snd-quantum" >&2
  exit 1
fi
echo "Saved to $OUT" >&2
cat "$OUT"
