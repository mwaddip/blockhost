#!/bin/bash
#
# Build all BlockHost packages from submodules
#
# This script builds .deb packages from each submodule and copies them to:
#   packages/host/     - Packages to install on Proxmox host
#   packages/template/ - Packages for VM template (libpam-web3)
#
# Usage: ./scripts/build-packages.sh
#
# Prerequisites:
#   - Rust toolchain (for libpam-web3)
#   - Node.js 18+ (for blockhost-engine)
#   - dpkg-deb
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

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
# 1. libpam-web3-tools (for Proxmox host)
#
log "=== Building libpam-web3-tools ==="
if [ -d "$PROJECT_DIR/libpam-web3/packaging" ]; then
    cd "$PROJECT_DIR/libpam-web3"
    rm -f packaging/libpam-web3-tools_*.deb
    if ./packaging/build-deb-tools.sh; then
        DEB=$(find packaging -name "libpam-web3-tools_*.deb" -type f | head -1)
        if [ -n "$DEB" ]; then
            cp "$DEB" "$HOST_PKG_DIR/"
            BUILT_PACKAGES+=("libpam-web3-tools")
            log "Built: $(basename "$DEB")"
        fi
    else
        FAILED_PACKAGES+=("libpam-web3-tools")
        warn "Failed to build libpam-web3-tools"
    fi
else
    warn "libpam-web3 submodule not found"
fi
echo ""

#
# 2. libpam-web3 (for VM template)
#
log "=== Building libpam-web3 (PAM module for VMs) ==="
if [ -d "$PROJECT_DIR/libpam-web3/packaging" ]; then
    cd "$PROJECT_DIR/libpam-web3"
    rm -f packaging/libpam-web3_*.deb
    if ./packaging/build-deb.sh; then
        DEB=$(find packaging -name "libpam-web3_*.deb" -type f | head -1)
        if [ -n "$DEB" ]; then
            cp "$DEB" "$TEMPLATE_PKG_DIR/"
            BUILT_PACKAGES+=("libpam-web3")
            log "Built: $(basename "$DEB") (for VM template)"
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
# 3. blockhost-common
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
# 4. blockhost-provisioner-proxmox
#
log "=== Building blockhost-provisioner-proxmox ==="
if [ -f "$PROJECT_DIR/blockhost-provisioner-proxmox/build-deb.sh" ]; then
    cd "$PROJECT_DIR/blockhost-provisioner-proxmox"
    rm -rf build
    if ./build-deb.sh; then
        DEB=$(find build -name "blockhost-provisioner-proxmox_*.deb" -type f | head -1)
        if [ -n "$DEB" ]; then
            cp "$DEB" "$HOST_PKG_DIR/"
            BUILT_PACKAGES+=("blockhost-provisioner-proxmox")
            log "Built: $(basename "$DEB")"
        fi
    else
        FAILED_PACKAGES+=("blockhost-provisioner-proxmox")
        warn "Failed to build blockhost-provisioner-proxmox"
    fi
else
    warn "blockhost-provisioner-proxmox/build-deb.sh not found"
fi
echo ""

#
# 5. blockhost-engine
#
log "=== Building blockhost-engine ==="
if [ -f "$PROJECT_DIR/blockhost-engine/packaging/build.sh" ]; then
    cd "$PROJECT_DIR/blockhost-engine"
    rm -f packaging/blockhost-engine_*.deb
    if ./packaging/build.sh; then
        DEB=$(find packaging -name "blockhost-engine_*.deb" -type f | head -1)
        if [ -n "$DEB" ]; then
            cp "$DEB" "$HOST_PKG_DIR/"
            BUILT_PACKAGES+=("blockhost-engine")
            log "Built: $(basename "$DEB")"
        fi
    else
        FAILED_PACKAGES+=("blockhost-engine")
        warn "Failed to build blockhost-engine"
    fi
else
    warn "blockhost-engine/packaging/build.sh not found"
fi
echo ""

#
# 6. blockhost-broker-client
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
