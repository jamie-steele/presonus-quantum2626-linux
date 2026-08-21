#!/bin/bash
# Reload snd-quantum: stop audio, mask pipewire, kill anything using ANY Quantum card, rmmod, insmod, unmask, start audio.
# Handles multiple Quantum cards simultaneously.
# Run with: ./scripts/reload_quantum_driver.sh
# Optional: MODPARAMS="reg_srate_offset=0x108 reg_srate_value=48000" ./scripts/reload_quantum_driver.sh
# Optional: RELOAD_ONLY=1 ... (do not start pipewire at the end)

set -e
DRIVER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/driver"

# 1. Detect ALL Quantum cards (returns a list of IDs, e.g., "0\n1")
# Filters to ensure we only take the header line (starts with a number) containing 'quantum'
# If no card is found, we exit early or proceed to rmmod just in case.
mapfile -t CARDS < <(awk '/quantum/ && $1 ~ /^[0-9]+$/ {print $1}' /proc/asound/cards 2>/dev/null)

if [ ${#CARDS[@]} -eq 0 ]; then
  echo "No Quantum cards found in /proc/asound/cards. Proceeding to module reload anyway..."
  # Fallback: try to rmmod/insmod without specific card targeting
  CARDS=()
else
  echo "Found ${#CARDS[@]} Quantum card(s): ${CARDS[*]}"
fi

# Stop socket first so nothing restarts pipewire when we stop it
echo "Stopping user audio (socket, then services)..."
systemctl --user stop pipewire.socket 2>/dev/null || true
systemctl --user stop pipewire-pulse 2>/dev/null || true
systemctl --user stop pipewire 2>/dev/null || true
systemctl --user stop wireplumber 2>/dev/null || true
sleep 3

# Always mask during release so pipewire/wireplumber cannot respawn and grab the cards
echo "Masking user audio (prevents respawn)..."
systemctl --user mask pipewire.socket pipewire pipewire-pulse wireplumber 2>/dev/null || true
sleep 2

# 2. Kill processes holding ANY of the detected cards open
echo "Killing processes holding Quantum card(s) open..."
MAX_TRIES=12
for try in $(seq 1 $MAX_TRIES); do
  # Stop again each time (wireplumber/pipewire can respawn)
  systemctl --user stop pipewire.socket pipewire-pulse pipewire wireplumber 2>/dev/null || true
  sleep 2

  still_open=0

  # Iterate over each detected card
  for CARD in "${CARDS[@]}"; do
    for dev in /dev/snd/controlC$CARD /dev/snd/pcmC${CARD}D0p /dev/snd/pcmC${CARD}D0c; do
      if [ -e "$dev" ]; then
        pids=$(sudo fuser "$dev" 2>/dev/null || true)
        for pid in $pids; do
          if [ -n "$pid" ]; then
            sudo kill -9 "$pid" 2>/dev/null && echo "  [try $try/$MAX_TRIES] Killed PID $pid on card $CARD ($dev)"
          fi
        done
      fi
    done
  done

  # Check if ANY card is still busy
  for CARD in "${CARDS[@]}"; do
    still=$(sudo lsof /dev/snd/controlC"$CARD" /dev/snd/pcmC"${CARD}"D0p /dev/snd/pcmC"${CARD}"D0c 2>/dev/null || true)
    if [ -n "$still" ]; then
      echo "  [try $try/$MAX_TRIES] Card $CARD still busy:"
      echo "$still"
      still_open=1
    fi
  done

  if [ $still_open -eq 0 ]; then
    if [ ${#CARDS[@]} -gt 0 ]; then
      echo "All Quantum cards free after $try attempt(s)."
    else
      echo "No card to check, proceeding."
    fi
    break
  fi

  if [ "$try" -eq $MAX_TRIES ]; then
    echo "ERROR: After $MAX_TRIES tries, some Quantum card(s) are still busy."
    echo ""
    echo "Last resort: log out, switch to TTY2 (Ctrl+Alt+F2), run:"
    echo "  sudo rmmod snd_quantum && sudo insmod $DRIVER_DIR/snd-quantum.ko"
    systemctl --user unmask pipewire.socket pipewire pipewire-pulse wireplumber 2>/dev/null || true
    exit 1
  fi
  sleep 1
done

# Final verification loop
final_busy=0
for CARD in "${CARDS[@]}"; do
  still=$(sudo lsof /dev/snd/controlC"$CARD" /dev/snd/pcmC"${CARD}"D0p /dev/snd/pcmC"${CARD}"D0c 2>/dev/null || true)
  if [ -n "$still" ]; then
    echo "ERROR: Card $CARD is still open:"
    echo "$still"
    final_busy=1
  fi
done

if [ $final_busy -eq 1 ]; then
  systemctl --user unmask pipewire.socket pipewire pipewire-pulse wireplumber 2>/dev/null || true
  exit 1
fi

echo "Unloading module (if loaded)..."
# Attempt to remove. Ignore "not found" (not loaded), fail on "in use" (should not happen after kill loop)
if ! sudo rmmod snd_quantum 2>/dev/null; then
  # Check if the module is actually loaded. If not, it's a success (nothing to do).
  if ! lsmod | grep -q "^snd_quantum"; then
    echo "Module was not loaded. Skipping unload step."
  else
    # It is loaded but rmmod failed (unexpected given the kill loop)
    echo "ERROR: Failed to unload module. It is likely still in use."
    echo "Try running 'sudo lsof /dev/snd/*' to find the culprit."
    systemctl --user unmask pipewire.socket pipewire pipewire-pulse wireplumber 2>/dev/null || true
    exit 1
  fi
else
  echo "Module unloaded successfully."
fi

echo "Loading module..."
if [ -n "${MODPARAMS:-}" ]; then
  echo "  with params: $MODPARAMS"
  sudo insmod "$DRIVER_DIR/snd-quantum.ko" "$MODPARAMS"
else
  sudo insmod "$DRIVER_DIR/snd-quantum.ko"
fi

# Verify new cards appeared (optional sanity check)
# FIX: Use the same robust awk command as the initial detection to avoid double-counting
sleep 2
new_cards=()
mapfile -t new_cards < <(awk '/quantum/ && $1 ~ /^[0-9]+$/ {print $1}' /proc/asound/cards 2>/dev/null)
echo "Detected ${#new_cards[@]} Quantum card(s) after reload."

echo "Unmasking user audio..."
systemctl --user unmask pipewire.socket pipewire pipewire-pulse wireplumber 2>/dev/null || true

if [ -z "${RELOAD_ONLY:-}" ]; then
  echo "Starting user audio..."
  systemctl --user start pipewire pipewire-pulse wireplumber 2>/dev/null || true
fi

echo "Done."
