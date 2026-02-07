#!/bin/bash
#
# Verify all BlockHost .deb packages exist with non-zero size.
# Used by CI after build-packages.sh to confirm build output.
#
# Exit 1 if any package is missing or empty.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

HOST_DIR="$PROJECT_DIR/packages/host"
TEMPLATE_DIR="$PROJECT_DIR/packages/template"

ERRORS=0

check_package() {
    local dir="$1" pattern="$2" label="$3"
    local found
    found=$(find "$dir" -maxdepth 1 -name "$pattern" -type f 2>/dev/null | head -1)

    if [ -z "$found" ]; then
        echo "MISSING: $label ($dir/$pattern)"
        ERRORS=$(( ERRORS + 1 ))
        return
    fi

    local size
    size=$(stat -c%s "$found" 2>/dev/null || echo 0)
    if [ "$size" -eq 0 ]; then
        echo "EMPTY:   $label ($found)"
        ERRORS=$(( ERRORS + 1 ))
        return
    fi

    echo "OK:      $label ($(basename "$found"), ${size} bytes)"
}

echo "Verifying BlockHost packages..."
echo ""

# Host packages (5)
check_package "$HOST_DIR" "blockhost-common_*.deb"        "blockhost-common"
check_package "$HOST_DIR" "libpam-web3-tools_*.deb"       "libpam-web3-tools"
check_package "$HOST_DIR" "blockhost-provisioner_*.deb"    "blockhost-provisioner"
check_package "$HOST_DIR" "blockhost-engine_*.deb"         "blockhost-engine"
check_package "$HOST_DIR" "blockhost-broker-client_*.deb"  "blockhost-broker-client"

# Template packages (1)
check_package "$TEMPLATE_DIR" "libpam-web3_*.deb"          "libpam-web3"

echo ""
if [ "$ERRORS" -gt 0 ]; then
    echo "FAILED: $ERRORS package(s) missing or empty"
    exit 1
fi

echo "All 6 packages verified."
