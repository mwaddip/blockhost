#!/bin/bash
# label: Writing https.json
# Onion plugin finalization step 3 — read the generated .onion hostname and
# persist it to /etc/blockhost/https.json so downstream consumers (engine NFT
# mint, signup-page generator, nginx config) have a hostname.
set -euo pipefail

HIDDEN_SERVICE_DIR=/var/lib/tor/blockhost-host
HTTPS_JSON=/etc/blockhost/https.json

if [ ! -f "$HIDDEN_SERVICE_DIR/hostname" ]; then
    echo "missing $HIDDEN_SERVICE_DIR/hostname — host hidden service not set up?" >&2
    exit 1
fi
ONION=$(cat "$HIDDEN_SERVICE_DIR/hostname")

mkdir -p /etc/blockhost
cat > "$HTTPS_JSON" <<EOF
{
  "hostname": "$ONION",
  "tls_mode": "onion",
  "use_dns_zone": false,
  "use_sslip": false,
  "ipv6_address": ""
}
EOF
