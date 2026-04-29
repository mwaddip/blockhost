#!/bin/bash
# label: Installing tor
# Onion plugin finalization step 1 — ensure tor is installed.
set -euo pipefail

if command -v tor >/dev/null 2>&1; then
    exit 0
fi
apt-get install -y tor
