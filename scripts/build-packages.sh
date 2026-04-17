#!/bin/bash
#
# Build all BlockHost packages from submodules
#
# This script builds .deb packages from each submodule and copies them to:
#   packages/host/     - Packages to install on Proxmox host
#   packages/template/ - Packages for VM template (libpam-web3)
#
# Usage: ./scripts/build-packages.sh --backend <provisioner-name> --engine <engine-name>
#
# Example: ./scripts/build-packages.sh --backend proxmox --engine evm
#          ./scripts/build-packages.sh --backend libvirt --engine opnet
#
# The --backend flag tells the script which provisioner submodule to build.
# It looks for ./blockhost-provisioner-<name>/ and runs its build-deb.sh.
#
# The --engine flag tells the script which engine submodule to build.
# It looks for ./blockhost-engine-<name>/ and runs its packaging/build.sh.
#
# Prerequisites:
#   - Rust toolchain (for libpam-web3)
#   - Node.js 22+ LTS (for blockhost-engine, via NodeSource)
#   - dpkg-deb
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
            echo "Usage: $0 --backend <provisioner-name> --engine <engine-name>"
            exit 1
            ;;
    esac
done

if [ -z "$BACKEND" ]; then
    echo "Error: --backend is required"
    echo "Usage: $0 --backend <provisioner-name> --engine <engine-name>"
    exit 1
fi

if [ -z "$ENGINE" ]; then
    echo "Error: --engine is required"
    echo "Usage: $0 --backend <provisioner-name> --engine <engine-name>"
    exit 1
fi

PROVISIONER_DIR="$PROJECT_DIR/blockhost-provisioner-${BACKEND}"
if [ ! -d "$PROVISIONER_DIR" ]; then
    echo "Error: Provisioner directory not found: $PROVISIONER_DIR"
    exit 1
fi

# Output directories
HOST_PKG_DIR="$PROJECT_DIR/packages/host"
TEMPLATE_PKG_DIR="$PROJECT_DIR/packages/template"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[BUILD]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Clean and recreate output directories (no stale packages from previous builds)
rm -rf "$HOST_PKG_DIR" "$TEMPLATE_PKG_DIR"
mkdir -p "$HOST_PKG_DIR" "$TEMPLATE_PKG_DIR"

log "Building BlockHost packages..."
log "Host packages will go to: $HOST_PKG_DIR"
log "Template packages will go to: $TEMPLATE_PKG_DIR"
echo ""

# Track what we've built
BUILT_PACKAGES=()
FAILED_PACKAGES=()

#
# 1. libpam-web3 (for VM template)
#
# NOTE: libpam-web3-tools is no longer built — bhcrypt is shipped by the engine package.
# cargo build --release (run by build-deb.sh) still compiles the binary
# as a side effect — the engine build picks it up from target/release/.
#
log "=== Building libpam-web3 (PAM module + ${ENGINE} plugin for VMs) ==="
if [ -d "$PROJECT_DIR/libpam-web3" ] && [ -f "$PROJECT_DIR/libpam-web3/build.sh" ]; then
    cd "$PROJECT_DIR/libpam-web3"
    rm -f packaging/libpam-web3_*.deb
    rm -f plugins/*/packaging/libpam-web3-*_*.deb 2>/dev/null
    if ./build.sh --with-backends="$ENGINE"; then
        # Copy core PAM module
        DEB=$(find packaging -maxdepth 1 -name "libpam-web3_*.deb" -type f | head -1)
        if [ -n "$DEB" ]; then
            cp "$DEB" "$TEMPLATE_PKG_DIR/"
            BUILT_PACKAGES+=("libpam-web3")
            log "Built: $(basename "$DEB") (for VM template)"
        fi
        # Copy chain plugin .deb if built
        PLUGIN_DEB=$(find plugins -name "libpam-web3-*_*.deb" -type f 2>/dev/null | head -1)
        if [ -n "$PLUGIN_DEB" ]; then
            cp "$PLUGIN_DEB" "$TEMPLATE_PKG_DIR/"
            BUILT_PACKAGES+=("$(basename "$PLUGIN_DEB" | sed 's/_.*$//')")
            log "Built: $(basename "$PLUGIN_DEB") (for VM template)"
        fi
    else
        FAILED_PACKAGES+=("libpam-web3")
        warn "Failed to build libpam-web3"
    fi
else
    warn "libpam-web3 submodule not found"
fi
echo ""

#
# 2. blockhost-common
#
log "=== Building blockhost-common ==="
if [ -f "$PROJECT_DIR/blockhost-common/build.sh" ]; then
    cd "$PROJECT_DIR/blockhost-common"
    rm -f "$PROJECT_DIR"/blockhost-common_*.deb
    if ./build.sh; then
        DEB=$(find .. -maxdepth 1 -name "blockhost-common_*.deb" -type f | head -1)
        if [ -n "$DEB" ]; then
            mv "$DEB" "$HOST_PKG_DIR/"
            BUILT_PACKAGES+=("blockhost-common")
            log "Built: $(basename "$DEB")"
        fi
    else
        FAILED_PACKAGES+=("blockhost-common")
        warn "Failed to build blockhost-common"
    fi
else
    warn "blockhost-common/build.sh not found"
fi
echo ""

#
# 3. blockhost-provisioner-${BACKEND}
#
PROV_PKG="blockhost-provisioner-${BACKEND}"
log "=== Building ${PROV_PKG} ==="
if [ -f "${PROVISIONER_DIR}/build-deb.sh" ]; then
    cd "$PROVISIONER_DIR"
    rm -rf build
    if ./build-deb.sh; then
        DEB=$(find build -name "${PROV_PKG}_*.deb" -type f | head -1)
        if [ -n "$DEB" ]; then
            cp "$DEB" "$HOST_PKG_DIR/"
            BUILT_PACKAGES+=("${PROV_PKG}")
            log "Built: $(basename "$DEB")"
        fi
    else
        FAILED_PACKAGES+=("${PROV_PKG}")
        warn "Failed to build ${PROV_PKG}"
    fi
else
    warn "${PROV_PKG}/build-deb.sh not found"
fi
echo ""

#
# 4. blockhost-engine-<ENGINE> (selected via --engine flag)
#
ENGINE_DIR="$PROJECT_DIR/blockhost-engine-${ENGINE}"
if [ ! -d "$ENGINE_DIR" ]; then
    # Fallback: pre-rename EVM engine at blockhost-engine/ (no suffix)
    if [ -d "$PROJECT_DIR/blockhost-engine" ] && [ -f "$PROJECT_DIR/blockhost-engine/packaging/build.sh" ]; then
        ENGINE_DIR="$PROJECT_DIR/blockhost-engine"
    else
        error "Engine directory not found: $ENGINE_DIR"
    fi
fi

ENGINE_NAME=$(basename "$ENGINE_DIR")

log "=== Building ${ENGINE_NAME} ==="
if [ -f "${ENGINE_DIR}/packaging/build.sh" ]; then
    cd "$ENGINE_DIR"
    rm -f packaging/blockhost-engine*_*.deb
    rm -f packaging/blockhost-auth-svc_*.deb
    if ./packaging/build.sh; then
        DEB=$(find packaging -name "blockhost-engine*_*.deb" -type f | head -1)
        if [ -n "$DEB" ]; then
            cp "$DEB" "$HOST_PKG_DIR/"
            BUILT_PACKAGES+=("$ENGINE_NAME")
            log "Built: $(basename "$DEB")"
        fi
        # Template package: blockhost-auth-svc (for VMs)
        TEMPLATE_DEB=$(find packaging -name "blockhost-auth-svc_*.deb" -type f | head -1)
        if [ -n "$TEMPLATE_DEB" ]; then
            cp "$TEMPLATE_DEB" "$TEMPLATE_PKG_DIR/"
            BUILT_PACKAGES+=("blockhost-auth-svc")
            log "Built: $(basename "$TEMPLATE_DEB") (for VM template)"
        else
            warn "blockhost-auth-svc template package not built (bun required)"
        fi
    else
        FAILED_PACKAGES+=("$ENGINE_NAME")
        warn "Failed to build $ENGINE_NAME"
    fi
else
    error "${ENGINE_NAME}/packaging/build.sh not found"
fi
echo ""

#
# 5. blockhost-broker-client
#
log "=== Building blockhost-broker-client ==="
if [ -f "$PROJECT_DIR/blockhost-broker/scripts/build-deb.sh" ]; then
    cd "$PROJECT_DIR/blockhost-broker/scripts"
    rm -rf build
    if ./build-deb.sh; then
        DEB=$(find build -name "blockhost-broker-client_*.deb" -type f | head -1)
        if [ -n "$DEB" ]; then
            cp "$DEB" "$HOST_PKG_DIR/"
            BUILT_PACKAGES+=("blockhost-broker-client")
            log "Built: $(basename "$DEB")"
        fi
    else
        FAILED_PACKAGES+=("blockhost-broker-client")
        warn "Failed to build blockhost-broker-client"
    fi
else
    warn "blockhost-broker/scripts/build-deb.sh not found"
fi
echo ""

#
# 6. blockhost-watchdog (from blockhost-monitor submodule)
#
log "=== Building blockhost-watchdog (from blockhost-monitor) ==="
if [ -f "$PROJECT_DIR/blockhost-monitor/build.sh" ]; then
    cd "$PROJECT_DIR/blockhost-monitor"
    rm -rf build
    if ./build.sh; then
        DEB=$(find build -name "blockhost-watchdog_*.deb" -type f | head -1)
        if [ -n "$DEB" ]; then
            cp "$DEB" "$HOST_PKG_DIR/"
            BUILT_PACKAGES+=("blockhost-watchdog")
            log "Built: $(basename "$DEB")"
        fi
    else
        FAILED_PACKAGES+=("blockhost-watchdog")
        warn "Failed to build blockhost-watchdog"
    fi
else
    warn "blockhost-monitor/build.sh not found"
fi
echo ""

#
# Summary
#
log "=========================================="
log "Build Summary"
log "=========================================="
echo ""
log "Host packages (install on Proxmox):"
ls -la "$HOST_PKG_DIR/"*.deb 2>/dev/null || echo "  (none)"
echo ""
log "Template packages (for VM template):"
ls -la "$TEMPLATE_PKG_DIR/"*.deb 2>/dev/null || echo "  (none)"
echo ""

if [ ${#BUILT_PACKAGES[@]} -gt 0 ]; then
    log "Successfully built: ${BUILT_PACKAGES[*]}"
fi

if [ ${#FAILED_PACKAGES[@]} -gt 0 ]; then
    warn "Failed to build: ${FAILED_PACKAGES[*]}"
    exit 1
fi

log "Done!"
