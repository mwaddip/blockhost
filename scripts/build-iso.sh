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

# Testing mode settings
TESTING_MODE=false
BUILD_DEBS=false
APT_PROXY="http://192.168.122.1:3142"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[BUILD]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --build-deb  Build all .deb packages from submodules before ISO creation"
    echo "  --testing    Enable testing mode (apt proxy, SSH root login)"
    echo "  --help       Show this help message"
    echo ""
    echo "Testing mode enables:"
    echo "  - apt proxy at $APT_PROXY for faster package downloads"
    echo "  - PermitRootLogin yes in sshd_config for easier debugging"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --build-deb)
                BUILD_DEBS=true
                shift
                ;;
            --testing)
                TESTING_MODE=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1\nUse --help for usage"
                ;;
        esac
    done
}

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

    # Copy install-packages script
    mkdir -p "${ISO_EXTRACT}/blockhost/scripts"
    cp "${PROJECT_DIR}/scripts/install-packages.sh" "${ISO_EXTRACT}/blockhost/scripts/"
    chmod +x "${ISO_EXTRACT}/blockhost/scripts/install-packages.sh"

    # Copy systemd service
    cp "${PROJECT_DIR}/systemd/blockhost-firstboot.service" "${ISO_EXTRACT}/blockhost/"

    log "BlockHost files added to /blockhost/"
}

add_packages() {
    log "Adding BlockHost packages..."

    # Check if packages exist
    HOST_PKG_DIR="${PROJECT_DIR}/packages/host"
    TEMPLATE_PKG_DIR="${PROJECT_DIR}/packages/template"

    if [ ! -d "$HOST_PKG_DIR" ] || [ -z "$(ls -A $HOST_PKG_DIR/*.deb 2>/dev/null)" ]; then
        warn "No host packages found in $HOST_PKG_DIR"
        warn "Run ./scripts/build-packages.sh first"
        return 1
    fi

    # Create package directories on ISO
    mkdir -p "${ISO_EXTRACT}/blockhost/packages/host"
    mkdir -p "${ISO_EXTRACT}/blockhost/packages/template"

    # Copy host packages
    cp "$HOST_PKG_DIR"/*.deb "${ISO_EXTRACT}/blockhost/packages/host/"
    log "Added host packages:"
    ls -la "${ISO_EXTRACT}/blockhost/packages/host/"

    # Copy template packages if they exist
    if [ -d "$TEMPLATE_PKG_DIR" ] && ls "$TEMPLATE_PKG_DIR"/*.deb >/dev/null 2>&1; then
        cp "$TEMPLATE_PKG_DIR"/*.deb "${ISO_EXTRACT}/blockhost/packages/template/"
        log "Added template packages:"
        ls -la "${ISO_EXTRACT}/blockhost/packages/template/"
    fi

    log "Packages added to ISO"
}


configure_testing_mode() {
    if [ "$TESTING_MODE" != "true" ]; then
        return
    fi

    log "Configuring testing mode..."

    # Read SSH public key for passwordless access (from repo testing key)
    SSH_PUBKEY_FILE="${PROJECT_DIR}/testing/blockhost-test-key.pub"
    SSH_PUBKEY=""
    if [ -f "$SSH_PUBKEY_FILE" ]; then
        SSH_PUBKEY=$(cat "$SSH_PUBKEY_FILE")
        log "Found SSH public key: $SSH_PUBKEY_FILE"
    else
        warn "SSH public key not found at $SSH_PUBKEY_FILE - password auth only"
        warn "Generate with: ssh-keygen -t ed25519 -f testing/blockhost-test-key -N ''"
    fi

    # Ensure apt proxy is set in preseed
    PRESEED_FILE="${ISO_EXTRACT}/preseed.cfg"
    if [ -f "$PRESEED_FILE" ]; then
        # Update or add apt proxy
        if grep -q "mirror/http/proxy" "$PRESEED_FILE"; then
            sed -i "s|d-i mirror/http/proxy string.*|d-i mirror/http/proxy string ${APT_PROXY}|" "$PRESEED_FILE"
        else
            echo "d-i mirror/http/proxy string ${APT_PROXY}" >> "$PRESEED_FILE"
        fi
        log "Set apt proxy to: $APT_PROXY"
    fi

    # Add late_command to enable SSH root login
    # We need to append to the existing late_command or create a new one
    if [ -f "$PRESEED_FILE" ]; then
        # Create a script that will be run during late_command to configure SSH
        mkdir -p "${ISO_EXTRACT}/blockhost/scripts"
        cat > "${ISO_EXTRACT}/blockhost/scripts/configure-testing.sh" << TESTING_EOF
#!/bin/bash
# Testing mode configuration

# Enable SSH root login with password
if [ -f /etc/ssh/sshd_config ]; then
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    # Also handle sshd_config.d directory if it exists
    if [ -d /etc/ssh/sshd_config.d ]; then
        echo "PermitRootLogin yes" > /etc/ssh/sshd_config.d/99-testing.conf
    fi
fi

# Add SSH public key for passwordless access
if [ -n "${SSH_PUBKEY}" ]; then
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    echo "${SSH_PUBKEY}" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    echo "SSH public key added to /root/.ssh/authorized_keys" >> /var/log/blockhost-install.log
fi

# Set apt proxy for post-install
mkdir -p /etc/apt/apt.conf.d
echo 'Acquire::http::Proxy "http://192.168.122.1:3142";' > /etc/apt/apt.conf.d/00proxy

# Ensure SSH is always accessible in testing mode (bypass pve-firewall)
# Persist across reboots via /etc/network/interfaces post-up or iptables-persistent
mkdir -p /etc/iptables
iptables -I INPUT -p tcp --dport 22 -j ACCEPT -m comment --comment "blockhost-testing" 2>/dev/null || true
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

# Create testing mode marker for validation script
mkdir -p /etc/blockhost
touch /etc/blockhost/.testing-mode
chmod 0644 /etc/blockhost/.testing-mode

echo "Testing mode configured" >> /var/log/blockhost-install.log
TESTING_EOF
        chmod +x "${ISO_EXTRACT}/blockhost/scripts/configure-testing.sh"

        # Add to the late_command - append script execution
        # We need to modify the preseed to also run our testing script
        sed -i "s|echo \"Files copied successfully\" >> /target/var/log/blockhost-install.log|echo \"Files copied successfully\" >> /target/var/log/blockhost-install.log; if [ -f \"\$CDROM/blockhost/scripts/configure-testing.sh\" ]; then cp \"\$CDROM/blockhost/scripts/configure-testing.sh\" /target/tmp/; in-target /bin/bash /tmp/configure-testing.sh; fi|" "$PRESEED_FILE"

        log "Added SSH root login and apt proxy configuration"
    fi
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
    parse_args "$@"

    log "BlockHost ISO Builder v${VERSION}"
    log "Building from Debian 12 base"

    if [ "$TESTING_MODE" = "true" ]; then
        log "TESTING MODE ENABLED"
        log "  - apt proxy: $APT_PROXY"
        log "  - SSH root login: enabled"
    fi

    if [ "$BUILD_DEBS" = "true" ]; then
        log "Building .deb packages from submodules..."
        if ! "${SCRIPT_DIR}/build-packages.sh"; then
            error "Package build failed. Fix errors above and retry."
        fi
        log "All packages built successfully"
        echo ""
    fi

    check_dependencies
    extract_iso
    add_preseed
    add_blockhost_files
    add_packages
    configure_testing_mode
    rebuild_iso
    cleanup

    log ""
    log "=========================================="
    log "Build complete!"
    log "=========================================="
    log "Output: $OUTPUT_ISO"

    if [ "$TESTING_MODE" = "true" ]; then
        log ""
        log "Testing mode features:"
        log "  - Root password: blockhost"
        log "  - SSH root login: enabled"
        log "  - apt proxy: $APT_PROXY"
    fi
}

main "$@"
