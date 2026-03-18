#!/bin/bash
#
# Verify all BlockHost .deb packages exist with non-zero size.
# Used by CI after build-packages.sh to confirm build output.
#
# Usage: ./scripts/ci-verify-packages.sh --backend <name> [--engine <name>]
#
# Exit 1 if any package is missing or empty.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKEND=""
ENGINE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --backend)
            BACKEND="$2"
            shift 2
            ;;
        --backend=*)
            BACKEND="${1#*=}"
            shift
            ;;
        --engine)
            ENGINE="$2"
            shift 2
            ;;
        --engine=*)
            ENGINE="${1#*=}"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 --backend <provisioner-name> [--engine <engine-name>]"
            exit 1
            ;;
    esac
done

if [ -z "$BACKEND" ]; then
    echo "Error: --backend is required"
    echo "Usage: $0 --backend <provisioner-name> [--engine <engine-name>]"
    exit 1
fi

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

# Host packages (4)
check_package "$HOST_DIR" "blockhost-common_*.deb"        "blockhost-common"
check_package "$HOST_DIR" "blockhost-provisioner-${BACKEND}_*.deb" "blockhost-provisioner-${BACKEND}"
# Use specific engine name if provided, wildcard otherwise
if [ -n "$ENGINE" ]; then
    check_package "$HOST_DIR" "blockhost-engine-${ENGINE}_*.deb" "blockhost-engine-${ENGINE}"
else
    check_package "$HOST_DIR" "blockhost-engine-*_*.deb"         "blockhost-engine"
fi
check_package "$HOST_DIR" "blockhost-broker-client_*.deb"  "blockhost-broker-client"
check_package "$HOST_DIR" "blockhost-watchdog_*.deb"      "blockhost-watchdog"

# Template packages
check_package "$TEMPLATE_DIR" "libpam-web3_*.deb"          "libpam-web3"
if [ -n "$ENGINE" ]; then
    check_package "$TEMPLATE_DIR" "libpam-web3-${ENGINE}_*.deb" "libpam-web3-${ENGINE}"
fi

echo ""
if [ "$ERRORS" -gt 0 ]; then
    echo "FAILED: $ERRORS package(s) missing or empty"
    exit 1
fi

echo "All packages verified."
