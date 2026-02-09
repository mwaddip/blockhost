#!/bin/bash
#
# Install BlockHost packages on the Proxmox host
#
# This script installs pre-built .deb packages from packages/host/
# and copies template packages to /var/lib/blockhost/template-packages/
#
# Usage: ./scripts/install-packages.sh
#
# Called by first-boot.sh after Proxmox installation
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Package directories
HOST_PKG_DIR="$PROJECT_DIR/packages/host"
TEMPLATE_PKG_DIR="$PROJECT_DIR/packages/template"

# Where to store packages for VM templates
TEMPLATE_DEST="/var/lib/blockhost/template-packages"

log() {
    echo "[INSTALL] $1"
}

error() {
    echo "[ERROR] $1"
    exit 1
}

log "Installing BlockHost packages..."

#
# Install host packages in dependency order
#
if [ -d "$HOST_PKG_DIR" ] && ls "$HOST_PKG_DIR"/*.deb >/dev/null 2>&1; then
    log "Installing host packages from $HOST_PKG_DIR"

    # Auto-detect provisioner package name
    PROV_PKG=""
    PROV_DEB=$(find "$HOST_PKG_DIR" -maxdepth 1 -name "blockhost-provisioner-*_*.deb" -type f 2>/dev/null | head -1)
    if [ -n "$PROV_DEB" ]; then
        PROV_PKG=$(basename "$PROV_DEB" | sed 's/_.*$//')
    fi

    # Install in order: common first (dependency), then others
    INSTALL_ORDER=(
        "blockhost-common"
        "libpam-web3-tools"
    )
    [ -n "$PROV_PKG" ] && INSTALL_ORDER+=("$PROV_PKG")
    INSTALL_ORDER+=(
        "blockhost-engine"
        "blockhost-broker-client"
    )

    for pkg in "${INSTALL_ORDER[@]}"; do
        DEB=$(find "$HOST_PKG_DIR" -name "${pkg}_*.deb" -type f | head -1)
        if [ -n "$DEB" ] && [ -f "$DEB" ]; then
            log "Installing: $(basename "$DEB")"
            dpkg -i "$DEB" || apt-get install -f -y
        fi
    done
else
    log "No host packages found in $HOST_PKG_DIR"
fi

#
# Copy template packages for VM provisioning
#
if [ -d "$TEMPLATE_PKG_DIR" ] && ls "$TEMPLATE_PKG_DIR"/*.deb >/dev/null 2>&1; then
    log "Copying template packages to $TEMPLATE_DEST"
    mkdir -p "$TEMPLATE_DEST"
    cp "$TEMPLATE_PKG_DIR"/*.deb "$TEMPLATE_DEST/"
    chmod 644 "$TEMPLATE_DEST"/*.deb
    log "Template packages available at: $TEMPLATE_DEST"
    ls -la "$TEMPLATE_DEST"
else
    log "No template packages found in $TEMPLATE_PKG_DIR"
fi

log "Package installation complete!"
