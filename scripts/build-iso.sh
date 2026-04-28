#!/bin/bash
#
# BlockHost ISO Builder
#
# Creates a preseeded Debian 12 ISO that:
# 1. Auto-installs Debian
# 2. Installs BlockHost first-boot service
# 3. On first boot: installs provisioner backend and runs web installer
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
ISO_EXTRACT="${BUILD_DIR}/iso-extract"
VERSION="${VERSION:-0.5.0}"

# Source Debian ISO
DEBIAN_ISO="${DEBIAN_ISO:-${BUILD_DIR}/debian-12-netinst.iso}"
OUTPUT_ISO="${BUILD_DIR}/blockhost_${VERSION}.iso"

# Build settings
TESTING_MODE=false
BUILD_DEBS=false
BACKEND=""
ENGINE=""
APT_PROXY=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[BUILD]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

usage() {
    echo "Usage: $0 --backend <name> --engine <name> [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  --backend <name>  Provisioner backend (e.g., proxmox, libvirt)"
    echo "  --engine <name>   Blockchain engine (e.g., evm, opnet)"
    echo ""
    echo "Options:"
    echo "  --build-deb       Build all .deb packages from submodules before ISO creation"
    echo "  --testing         Enable testing mode (SSH root login, testing marker)"
    echo "  --apt-proxy <url> Use apt-cacher-ng proxy (e.g. http://192.168.122.1:3142)"
    echo "  --help            Show this help message"
    echo ""
    echo "Testing mode enables:"
    echo "  - PermitRootLogin yes in sshd_config for easier debugging"
    echo "  - /etc/blockhost/.testing-mode marker for validation scripts"
    echo "  - apt proxy for faster package downloads (only with --apt-proxy)"
    echo "  - Btrfs root (replaces LVM) with snapshots at each first-boot stage"
    echo "  - 'revert' command on VM for instant rollback to any snapshot"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --build-deb)
                BUILD_DEBS=true
                shift
                ;;
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
            --testing)
                TESTING_MODE=true
                shift
                ;;
            --apt-proxy)
                APT_PROXY="$2"
                shift 2
                ;;
            --apt-proxy=*)
                APT_PROXY="${1#*=}"
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

    # Copy pre-install disclaimer text (shown by isolinux's `display` directive
    # before the boot prompt — pre-d-i, pre-ncurses).
    mkdir -p "${ISO_EXTRACT}/isolinux"
    cp "${PROJECT_DIR}/preseed/disclaimer.txt" "${ISO_EXTRACT}/isolinux/disclaimer.txt"

    # Modify GRUB to use preseed.
    # UEFI grub doesn't support the isolinux-style typed-label confirmation,
    # so the disclaimer rides in the menuentry title and there's no auto-boot
    # — the operator has to actively select the entry to proceed.
    GRUB_CFG="${ISO_EXTRACT}/boot/grub/grub.cfg"
    if [ -f "$GRUB_CFG" ]; then
        cat > "${GRUB_CFG}.new" << 'EOF'
set timeout=-1

menuentry "WARNING: this WIPES the disk. Press Enter to install BlockHost; ESC to cancel." {
    linux /install.amd/vmlinuz auto=true priority=critical preseed/file=/cdrom/preseed.cfg --- quiet
    initrd /install.amd/initrd.gz
}

EOF
        cat "$GRUB_CFG" >> "${GRUB_CFG}.new"
        mv "${GRUB_CFG}.new" "$GRUB_CFG"
        log "Updated GRUB configuration"
    fi

    # Modify isolinux for BIOS boot.
    # Prompt-mode boot: display the disclaimer, require the operator to type
    # `Understood` (case-insensitive — syslinux LABELs are matched that way)
    # at the boot prompt. Pressing Enter alone tries to load the non-existent
    # `read-the-disclaimer` label and bounces back to the prompt, so accidental
    # confirmation isn't possible. IMPLICIT 0 blocks treating typed input as
    # arbitrary kernel filenames.
    ISOLINUX_CFG="${ISO_EXTRACT}/isolinux/isolinux.cfg"
    if [ -f "$ISOLINUX_CFG" ]; then
        cat > "$ISOLINUX_CFG" << 'EOF'
default read-the-disclaimer
prompt 1
timeout 0
implicit 0
display disclaimer.txt

label Understood
    kernel /install.amd/vmlinuz
    append auto=true priority=critical preseed/file=/cdrom/preseed.cfg initrd=/install.amd/initrd.gz --- quiet
EOF
        log "Updated isolinux configuration"
    fi

    # Also update txt.cfg if it exists (Debian's stock isolinux.cfg INCLUDEs
    # this; ours is self-contained, but keep txt.cfg consistent as a hedge).
    TXT_CFG="${ISO_EXTRACT}/isolinux/txt.cfg"
    if [ -f "$TXT_CFG" ]; then
        cat > "$TXT_CFG" << 'EOF'
default read-the-disclaimer

label Understood
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

    # Copy admin panel
    cp -r "${PROJECT_DIR}/admin" "${ISO_EXTRACT}/blockhost/"

    # Copy first-boot script
    cp "${PROJECT_DIR}/scripts/first-boot.sh" "${ISO_EXTRACT}/blockhost/"
    chmod +x "${ISO_EXTRACT}/blockhost/first-boot.sh"

    # Copy preseed late_command body + first-boot helper scripts
    mkdir -p "${ISO_EXTRACT}/blockhost/scripts"
    cp "${PROJECT_DIR}/scripts/install-packages.sh" "${ISO_EXTRACT}/blockhost/scripts/"
    cp "${PROJECT_DIR}/scripts/late-install.sh" "${ISO_EXTRACT}/blockhost/scripts/"
    chmod +x "${ISO_EXTRACT}/blockhost/scripts/install-packages.sh"
    chmod +x "${ISO_EXTRACT}/blockhost/scripts/late-install.sh"

    # Copy systemd services
    cp "${PROJECT_DIR}/systemd/blockhost-firstboot.service" "${ISO_EXTRACT}/blockhost/"
    cp "${PROJECT_DIR}/systemd/blockhost-admin.service" "${ISO_EXTRACT}/blockhost/"

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

    PRESEED_FILE="${ISO_EXTRACT}/preseed.cfg"

    # --- Btrfs: swap LVM for btrfs in the preseed copy ---
    if [ -f "$PRESEED_FILE" ]; then
        log "Switching preseed from LVM to btrfs..."

        # Replace partitioning method
        sed -i 's/^d-i partman-auto\/method string lvm$/d-i partman-auto\/method string regular/' "$PRESEED_FILE"

        # Remove LVM-specific lines
        sed -i '/^d-i partman-auto-lvm\//d' "$PRESEED_FILE"
        sed -i '/^d-i partman-lvm\//d' "$PRESEED_FILE"
        sed -i '/^d-i partman-md\//d' "$PRESEED_FILE"

        # Set default filesystem to btrfs
        sed -i '/^d-i partman-auto\/choose_recipe/i d-i partman\/default_filesystem string btrfs' "$PRESEED_FILE"

        # Add btrfs-progs to package list
        sed -i 's/bash-completion$/bash-completion \\\n    btrfs-progs/' "$PRESEED_FILE"

        log "Preseed updated for btrfs"
    fi

    # --- Copy revert and resume scripts to ISO ---
    REVERT_SCRIPT="${PROJECT_DIR}/scripts/blockhost-revert"
    RESUME_SCRIPT="${PROJECT_DIR}/scripts/blockhost-resume"
    if [ -f "$REVERT_SCRIPT" ]; then
        cp "$REVERT_SCRIPT" "${ISO_EXTRACT}/blockhost/scripts/blockhost-revert"
        chmod +x "${ISO_EXTRACT}/blockhost/scripts/blockhost-revert"
        log "Revert script added to ISO"
    else
        warn "Revert script not found at $REVERT_SCRIPT"
    fi
    if [ -f "$RESUME_SCRIPT" ]; then
        cp "$RESUME_SCRIPT" "${ISO_EXTRACT}/blockhost/scripts/blockhost-resume"
        chmod +x "${ISO_EXTRACT}/blockhost/scripts/blockhost-resume"
        log "Resume script added to ISO"
    else
        warn "Resume script not found at $RESUME_SCRIPT"
    fi

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

    # Set apt proxy in preseed if provided
    if [ -n "$APT_PROXY" ] && [ -f "$PRESEED_FILE" ]; then
        if grep -q "mirror/http/proxy" "$PRESEED_FILE"; then
            sed -i "s#d-i mirror/http/proxy string.*#d-i mirror/http/proxy string ${APT_PROXY}#" "$PRESEED_FILE"
        else
            echo "d-i mirror/http/proxy string ${APT_PROXY}" >> "$PRESEED_FILE"
        fi
        log "Set apt proxy to: $APT_PROXY"
    fi

    # Add testing-mode helper scripts. late-install.sh detects late-testing.sh
    # on the CDROM and invokes it; no preseed surgery needed.
    mkdir -p "${ISO_EXTRACT}/blockhost/scripts"
    cp "${PROJECT_DIR}/scripts/late-testing.sh" "${ISO_EXTRACT}/blockhost/scripts/"
    cp "${PROJECT_DIR}/scripts/configure-testing.sh" "${ISO_EXTRACT}/blockhost/scripts/"
    cp "${PROJECT_DIR}/scripts/setup-btrfs-snapshots.sh" "${ISO_EXTRACT}/blockhost/scripts/"
    chmod +x "${ISO_EXTRACT}/blockhost/scripts/late-testing.sh"
    chmod +x "${ISO_EXTRACT}/blockhost/scripts/configure-testing.sh"
    chmod +x "${ISO_EXTRACT}/blockhost/scripts/setup-btrfs-snapshots.sh"

    # Build-time values for configure-testing.sh (sourced inside the chroot).
    cat > "${ISO_EXTRACT}/blockhost/scripts/late-testing.env" <<EOF
SSH_PUBKEY="${SSH_PUBKEY}"
APT_PROXY="${APT_PROXY}"
EOF

    log "Added testing-mode scripts and env file"
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

    if [ -z "$BACKEND" ]; then
        error "--backend is required\nUse --help for usage"
    fi

    if [ -z "$ENGINE" ]; then
        error "--engine is required\nUse --help for usage"
    fi

    log "BlockHost ISO Builder v${VERSION}"
    log "Building from Debian 12 base"
    log "Backend: $BACKEND"
    log "Engine: $ENGINE"

    if [[ -n "$APT_PROXY" ]] && ! [[ "$APT_PROXY" =~ ^https?:// ]]; then
        error "--apt-proxy must be an http:// or https:// URL"
    fi

    if [ "$TESTING_MODE" = "true" ]; then
        log "TESTING MODE ENABLED"
        log "  - SSH root login: enabled"
        log "  - Btrfs root + snapshots (replaces LVM)"
        if [ -n "$APT_PROXY" ]; then
            log "  - apt proxy: $APT_PROXY"
        fi
    fi

    if [ "$BUILD_DEBS" = "true" ]; then
        log "Building .deb packages from submodules..."
        if ! "${SCRIPT_DIR}/build-packages.sh" --backend "$BACKEND" --engine "$ENGINE"; then
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
        log "  - Btrfs root with first-boot snapshots"
        log "  - 'revert <name>' on VM to rollback + swap .debs"
        if [ -n "$APT_PROXY" ]; then
            log "  - apt proxy: $APT_PROXY"
        fi
    fi
}

main "$@"
