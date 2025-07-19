#!/bin/bash

# === USER CONFIGURATION ===
SURICATA_CONFIG="/opt/homebrew/etc/suricata/suricata.yaml"
INTERFACE="en0"
LOG_PATH="/opt/homebrew/var/log/suricata/eve.json"

# === CLEAN THE LOG FILE ===
echo "🧹 Clearing Suricata log: $LOG_PATH"
if sudo truncate -s 0 "$LOG_PATH"; then
    echo "✅ Log cleared"
else
    echo "❌ Failed to clear log"
    exit 1
fi

# === START SURICATA ===
echo "🚀 Starting Suricata on $INTERFACE using config $SURICATA_CONFIG"
sudo suricata -c "$SURICATA_CONFIG" -i "$INTERFACE" -v

# === END OF SCRIPT ===
echo "✅ Suricata exited (or is running in background)"

