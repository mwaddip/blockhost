#!/bin/bash
#
# BlockHost ISO Builder
#
# Creates a preseeded Debian 12 ISO that:
# 1. Auto-installs Debian
# 2. Installs BlockHost first-boot service
# 3. On first boot: installs Proxmox VE and runs web installer
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
ISO_EXTRACT="${BUILD_DIR}/iso-extract"
VERSION="${VERSION:-0.1.0}"

# Source Debian ISO
DEBIAN_ISO="${DEBIAN_ISO:-${BUILD_DIR}/debian-12-netinst.iso}"
OUTPUT_ISO="${BUILD_DIR}/blockhost_${VERSION}.iso"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[BUILD]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_dependencies() {
    log "Checking dependencies..."

    local missing=()
    command -v xorriso >/dev/null 2>&1 || missing+=("xorriso")
    command -v cpio >/dev/null 2>&1 || missing+=("cpio")
    command -v gzip >/dev/null 2>&1 || missing+=("gzip")

    if [ ${#missing[@]} -ne 0 ]; then
        error "Missing: ${missing[*]}\nInstall with: sudo apt install ${missing[*]}"
    fi

    if [ ! -f "$DEBIAN_ISO" ]; then
        error "Debian ISO not found: $DEBIAN_ISO\nDownload with: wget https://cdimage.debian.org/cdimage/archive/12.9.0/amd64/iso-cd/debian-12.9.0-amd64-netinst.iso -O $DEBIAN_ISO"
    fi
}

extract_iso() {
    log "Extracting Debian ISO..."
    rm -rf "$ISO_EXTRACT"
    mkdir -p "$ISO_EXTRACT"

    xorriso -osirrox on -indev "$DEBIAN_ISO" -extract / "$ISO_EXTRACT" 2>/dev/null
    chmod -R u+w "$ISO_EXTRACT"
}

add_preseed() {
    log "Adding preseed configuration..."

    # Copy preseed file
    cp "${PROJECT_DIR}/preseed/blockhost.preseed" "${ISO_EXTRACT}/preseed.cfg"

    # Modify GRUB to use preseed
    GRUB_CFG="${ISO_EXTRACT}/boot/grub/grub.cfg"
    if [ -f "$GRUB_CFG" ]; then
        # Add auto-install menu entry at the top
        cat > "${GRUB_CFG}.new" << 'EOF'
set timeout=5
set default=0

menuentry "BlockHost Auto Install" {
    linux /install.amd/vmlinuz auto=true priority=critical preseed/file=/cdrom/preseed.cfg --- quiet
    initrd /install.amd/initrd.gz
}

EOF
        cat "$GRUB_CFG" >> "${GRUB_CFG}.new"
        mv "${GRUB_CFG}.new" "$GRUB_CFG"
        log "Updated GRUB configuration"
    fi

    # Modify isolinux for BIOS boot
    ISOLINUX_CFG="${ISO_EXTRACT}/isolinux/isolinux.cfg"
    if [ -f "$ISOLINUX_CFG" ]; then
        cat > "$ISOLINUX_CFG" << 'EOF'
default blockhost
timeout 50
prompt 0

label blockhost
    menu label ^BlockHost Auto Install
    kernel /install.amd/vmlinuz
    append auto=true priority=critical preseed/file=/cdrom/preseed.cfg initrd=/install.amd/initrd.gz --- quiet
EOF
        log "Updated isolinux configuration"
    fi

    # Also update txt.cfg if it exists
    TXT_CFG="${ISO_EXTRACT}/isolinux/txt.cfg"
    if [ -f "$TXT_CFG" ]; then
        cat > "$TXT_CFG" << 'EOF'
default blockhost
label blockhost
    menu label ^BlockHost Auto Install
    kernel /install.amd/vmlinuz
    append auto=true priority=critical preseed/file=/cdrom/preseed.cfg initrd=/install.amd/initrd.gz --- quiet
EOF
    fi
}

add_blockhost_files() {
    log "Adding BlockHost files..."

    mkdir -p "${ISO_EXTRACT}/blockhost"

    # Copy installer Python package
    cp -r "${PROJECT_DIR}/installer" "${ISO_EXTRACT}/blockhost/"

    # Copy first-boot script
    cp "${PROJECT_DIR}/scripts/first-boot.sh" "${ISO_EXTRACT}/blockhost/"
    chmod +x "${ISO_EXTRACT}/blockhost/first-boot.sh"

    # Copy systemd service
    cp "${PROJECT_DIR}/systemd/blockhost-firstboot.service" "${ISO_EXTRACT}/blockhost/"

    log "BlockHost files added to /blockhost/"
}

rebuild_iso() {
    log "Rebuilding ISO..."

    # Calculate MD5 sums
    cd "$ISO_EXTRACT"
    find . -type f ! -name md5sum.txt -exec md5sum {} \; > md5sum.txt 2>/dev/null || true
    cd - > /dev/null

    # Rebuild ISO
    xorriso -as mkisofs \
        -o "$OUTPUT_ISO" \
        -r -J -joliet-long \
        -V "BLOCKHOST" \
        -b isolinux/isolinux.bin \
        -c isolinux/boot.cat \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
        -eltorito-alt-boot \
        -e boot/grub/efi.img \
        -no-emul-boot \
        -isohybrid-gpt-basdat \
        "$ISO_EXTRACT"

    log "ISO created: $OUTPUT_ISO"
    ls -lh "$OUTPUT_ISO"
}

cleanup() {
    log "Cleaning up..."
    rm -rf "$ISO_EXTRACT"
}

main() {
    log "BlockHost ISO Builder v${VERSION}"
    log "Building from Debian 12 base"

    check_dependencies
    extract_iso
    add_preseed
    add_blockhost_files
    rebuild_iso
    cleanup

    log ""
    log "=========================================="
    log "Build complete!"
    log "=========================================="
    log "Output: $OUTPUT_ISO"
}

main "$@"
