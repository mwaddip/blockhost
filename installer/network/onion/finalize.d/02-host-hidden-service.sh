#!/bin/bash
# label: Configuring host hidden service
# Onion plugin finalization step 2 — configure the host's own .onion for the
# signup page + admin panel. Per-VM hidden services are created on demand by
# the onion-service-add root-agent action.
set -euo pipefail

HIDDEN_SERVICE_DIR=/var/lib/tor/blockhost-host
TORRC=/etc/tor/torrc
BLOCK_MARKER='# BlockHost — host hidden service (admin/signup)'
TIMEOUT=30

mkdir -p "$HIDDEN_SERVICE_DIR"
chmod 0700 "$HIDDEN_SERVICE_DIR"
chown -R debian-tor:debian-tor "$HIDDEN_SERVICE_DIR"

if ! grep -qF "HiddenServiceDir $HIDDEN_SERVICE_DIR" "$TORRC"; then
    {
        echo ""
        echo "$BLOCK_MARKER"
        echo "HiddenServiceDir $HIDDEN_SERVICE_DIR"
        echo "HiddenServicePort 80 127.0.0.1:80"
    } >> "$TORRC"
fi

systemctl enable tor@default
systemctl reload-or-restart tor@default

# Wait for tor to publish the hostname.
deadline=$(( $(date +%s) + TIMEOUT ))
while [ ! -f "$HIDDEN_SERVICE_DIR/hostname" ] && [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 0.5
done
if [ ! -f "$HIDDEN_SERVICE_DIR/hostname" ]; then
    echo "tor did not publish $HIDDEN_SERVICE_DIR/hostname within ${TIMEOUT}s" >&2
    exit 1
fi
