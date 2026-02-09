#!/bin/bash
#
# BlockHost Build Dependency Checker
#
# Checks for all dependencies required to build the BlockHost ISO
# and optionally installs missing ones.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
MISSING_CMDS=()
MISSING_FILES=()
MISSING_PKGS=()
WARNINGS=()

log_ok() { echo -e "  ${GREEN}[OK]${NC} $1"; }
log_missing() { echo -e "  ${RED}[MISSING]${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
log_section() { echo -e "\n${BLUE}==> $1${NC}"; }

check_command() {
    local cmd=$1
    local pkg=${2:-$1}
    if command -v "$cmd" >/dev/null 2>&1; then
        log_ok "$cmd"
        return 0
    else
        log_missing "$cmd (install: $pkg)"
        MISSING_CMDS+=("$cmd")
        MISSING_PKGS+=("$pkg")
        return 1
    fi
}

check_file() {
    local file=$1
    local desc=$2
    if [ -f "$file" ]; then
        log_ok "$desc: $file"
        return 0
    else
        log_missing "$desc: $file"
        MISSING_FILES+=("$file")
        return 1
    fi
}

check_dir() {
    local dir=$1
    local desc=$2
    if [ -d "$dir" ]; then
        log_ok "$desc: $dir"
        return 0
    else
        log_missing "$desc: $dir"
        MISSING_FILES+=("$dir")
        return 1
    fi
}

check_debs() {
    local dir=$1
    local desc=$2
    if [ -d "$dir" ] && ls "$dir"/*.deb >/dev/null 2>&1; then
        local count=$(ls "$dir"/*.deb 2>/dev/null | wc -l)
        log_ok "$desc: $dir ($count packages)"
        return 0
    else
        log_warn "$desc: $dir (no .deb files)"
        WARNINGS+=("No packages in $dir")
        return 1
    fi
}

main() {
    echo "======================================"
    echo " BlockHost Build Dependency Checker"
    echo "======================================"

    # ----------------------------------------
    log_section "Required Commands (ISO build)"
    # ----------------------------------------

    # ISO building
    check_command xorriso xorriso
    check_command cpio cpio
    check_command gzip gzip
    check_command md5sum coreutils

    # Package handling
    check_command dpkg-deb dpkg
    check_command dpkg dpkg

    # Misc utilities
    check_command mktemp coreutils
    check_command find findutils
    check_command sed sed
    check_command chmod coreutils
    # Need wget OR curl for ISO download
    if command -v wget >/dev/null 2>&1; then
        log_ok "wget (for ISO download)"
    elif command -v curl >/dev/null 2>&1; then
        log_ok "curl (for ISO download)"
    else
        log_missing "wget or curl (for ISO download)"
        MISSING_CMDS+=("wget")
        MISSING_PKGS+=("wget")
    fi

    # ----------------------------------------
    log_section "Required Commands (package builds)"
    # ----------------------------------------

    # Rust toolchain (libpam-web3, libpam-web3-tools)
    if command -v cargo >/dev/null 2>&1; then
        log_ok "cargo ($(cargo --version 2>/dev/null | head -1))"
    else
        log_missing "cargo (install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh)"
        MISSING_CMDS+=("cargo")
    fi

    # Foundry / forge (libpam-web3-tools, blockhost-engine contracts)
    if command -v forge >/dev/null 2>&1 || [ -x "$HOME/.foundry/bin/forge" ]; then
        local forge_bin="${HOME}/.foundry/bin/forge"
        command -v forge >/dev/null 2>&1 && forge_bin="forge"
        log_ok "forge ($($forge_bin --version 2>/dev/null | head -1))"
    else
        log_missing "forge (install: curl -L https://foundry.paradigm.xyz | bash && foundryup)"
        MISSING_CMDS+=("forge")
    fi

    # Node.js (blockhost-engine)
    if command -v node >/dev/null 2>&1; then
        local node_ver
        node_ver=$(node --version 2>/dev/null)
        local node_major
        node_major=$(echo "$node_ver" | sed 's/v//' | cut -d. -f1)
        if [ "$node_major" -ge 18 ] 2>/dev/null; then
            log_ok "node ($node_ver)"
        else
            log_missing "node >= 18 (found $node_ver)"
            MISSING_CMDS+=("node")
        fi
    else
        log_missing "node (install: https://nodejs.org/ or via nvm)"
        MISSING_CMDS+=("node")
    fi

    # npm (blockhost-engine)
    check_command npm npm

    # Python 3 (blockhost-provisioner-proxmox, blockhost-broker)
    if command -v python3 >/dev/null 2>&1; then
        log_ok "python3 ($(python3 --version 2>/dev/null))"
    else
        log_missing "python3 (install: python3)"
        MISSING_CMDS+=("python3")
        MISSING_PKGS+=("python3")
    fi

    # git (submodule operations, forge dependencies)
    check_command git git

    # curl (Foundry installer, various downloads)
    check_command curl curl

    # ----------------------------------------
    log_section "Required Files"
    # ----------------------------------------

    # ISOLINUX for hybrid ISO
    check_file "/usr/lib/ISOLINUX/isohdpfx.bin" "ISOLINUX MBR"
    if [ ! -f "/usr/lib/ISOLINUX/isohdpfx.bin" ]; then
        MISSING_PKGS+=("isolinux")
    fi

    # Preseed file
    check_file "${PROJECT_DIR}/preseed/blockhost.preseed" "Preseed config"

    # First-boot script
    check_file "${PROJECT_DIR}/scripts/first-boot.sh" "First-boot script"

    # Install packages script
    check_file "${PROJECT_DIR}/scripts/install-packages.sh" "Install packages script"

    # Systemd service
    check_file "${PROJECT_DIR}/systemd/blockhost-firstboot.service" "First-boot service"

    # Installer Python package
    check_dir "${PROJECT_DIR}/installer" "Installer package"
    check_file "${PROJECT_DIR}/installer/web/app.py" "Web installer"

    # ----------------------------------------
    log_section "Debian ISO"
    # ----------------------------------------

    DEBIAN_ISO="${BUILD_DIR}/debian-12-netinst.iso"
    if [ -f "$DEBIAN_ISO" ]; then
        log_ok "Debian ISO: $DEBIAN_ISO"
    else
        log_missing "Debian ISO: $DEBIAN_ISO"
        echo ""
        echo "  Download with:"
        echo "    mkdir -p ${BUILD_DIR}"
        echo "    wget https://cdimage.debian.org/cdimage/archive/12.9.0/amd64/iso-cd/debian-12.9.0-amd64-netinst.iso -O $DEBIAN_ISO"
        MISSING_FILES+=("$DEBIAN_ISO")
    fi

    # ----------------------------------------
    log_section "BlockHost Packages"
    # ----------------------------------------

    check_debs "${PROJECT_DIR}/packages/host" "Host packages"
    check_debs "${PROJECT_DIR}/packages/template" "Template packages"

    # Check for specific required packages
    echo ""
    echo "  Checking specific packages..."

    local required_host_pkgs=(
        "blockhost-common"
        "libpam-web3-tools"
        "blockhost-provisioner-proxmox"
        "blockhost-engine"
        "blockhost-broker-client"
    )

    for pkg in "${required_host_pkgs[@]}"; do
        if ls "${PROJECT_DIR}/packages/host/${pkg}_"*.deb >/dev/null 2>&1; then
            log_ok "  $pkg"
        else
            log_warn "  $pkg not found"
            WARNINGS+=("Package $pkg not found in packages/host/")
        fi
    done

    # ----------------------------------------
    log_section "Testing Dependencies (Optional)"
    # ----------------------------------------

    if [ -f "${PROJECT_DIR}/testing/blockhost-test-key" ]; then
        log_ok "Testing SSH key"
    else
        log_warn "Testing SSH key not found (generate with: ssh-keygen -t ed25519 -f testing/blockhost-test-key -N '')"
        WARNINGS+=("No testing SSH key")
    fi

    # ----------------------------------------
    log_section "Summary"
    # ----------------------------------------

    echo ""

    if [ ${#MISSING_CMDS[@]} -eq 0 ] && [ ${#MISSING_FILES[@]} -eq 0 ]; then
        echo -e "${GREEN}All required dependencies are present!${NC}"
    else
        if [ ${#MISSING_CMDS[@]} -gt 0 ]; then
            echo -e "${RED}Missing commands:${NC} ${MISSING_CMDS[*]}"
        fi
        if [ ${#MISSING_FILES[@]} -gt 0 ]; then
            echo -e "${RED}Missing files:${NC}"
            for f in "${MISSING_FILES[@]}"; do
                echo "  - $f"
            done
        fi
    fi

    if [ ${#WARNINGS[@]} -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}Warnings:${NC}"
        for w in "${WARNINGS[@]}"; do
            echo "  - $w"
        done
    fi

    # ----------------------------------------
    # Installation command
    # ----------------------------------------

    if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
        # Remove duplicates
        UNIQUE_PKGS=($(echo "${MISSING_PKGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

        echo ""
        echo -e "${BLUE}Install missing packages with:${NC}"
        echo "  sudo apt update && sudo apt install -y ${UNIQUE_PKGS[*]}"
    fi

    # Exit with error if critical dependencies missing
    if [ ${#MISSING_CMDS[@]} -gt 0 ] || [ ${#MISSING_FILES[@]} -gt 0 ]; then
        exit 1
    fi

    exit 0
}

# Allow --install flag to auto-install missing packages
if [ "$1" = "--install" ]; then
    # First run check to get missing packages
    MISSING_PKGS=()

    # ISO build deps
    command -v xorriso >/dev/null 2>&1 || MISSING_PKGS+=("xorriso")
    command -v cpio >/dev/null 2>&1 || MISSING_PKGS+=("cpio")
    command -v gzip >/dev/null 2>&1 || MISSING_PKGS+=("gzip")
    command -v dpkg-deb >/dev/null 2>&1 || MISSING_PKGS+=("dpkg")
    command -v wget >/dev/null 2>&1 || command -v curl >/dev/null 2>&1 || MISSING_PKGS+=("curl")
    [ -f "/usr/lib/ISOLINUX/isohdpfx.bin" ] || MISSING_PKGS+=("isolinux")

    # Package build deps (apt-installable only)
    command -v python3 >/dev/null 2>&1 || MISSING_PKGS+=("python3")
    command -v git >/dev/null 2>&1 || MISSING_PKGS+=("git")
    command -v curl >/dev/null 2>&1 || MISSING_PKGS+=("curl")
    command -v pkg-config >/dev/null 2>&1 || MISSING_PKGS+=("pkg-config")
    command -v gcc >/dev/null 2>&1 || MISSING_PKGS+=("build-essential")

    if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
        # Remove duplicates
        UNIQUE_PKGS=($(echo "${MISSING_PKGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        echo "Installing missing system packages: ${UNIQUE_PKGS[*]}"
        sudo apt update && sudo apt install -y "${UNIQUE_PKGS[@]}"
    else
        echo "All system packages already installed"
    fi

    # Install Rust toolchain if missing
    if ! command -v cargo >/dev/null 2>&1; then
        echo ""
        echo "Installing Rust toolchain..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi

    # Install Foundry if missing
    if ! command -v forge >/dev/null 2>&1 && [ ! -x "$HOME/.foundry/bin/forge" ]; then
        echo ""
        echo "Installing Foundry..."
        curl -L https://foundry.paradigm.xyz | bash
        "$HOME/.foundry/bin/foundryup"
    fi

    # Check Node.js
    if ! command -v node >/dev/null 2>&1; then
        echo ""
        echo "Node.js 18+ is required but not installed."
        echo "Install via: https://nodejs.org/ or nvm (https://github.com/nvm-sh/nvm)"
    else
        node_major=$(node --version | sed 's/v//' | cut -d. -f1)
        if [ "$node_major" -lt 18 ] 2>/dev/null; then
            echo ""
            echo "Node.js 18+ required, found $(node --version). Please upgrade."
        fi
    fi

    # Download Debian ISO if missing
    DEBIAN_ISO="${BUILD_DIR}/debian-12-netinst.iso"
    if [ ! -f "$DEBIAN_ISO" ]; then
        echo ""
        echo "Downloading Debian ISO..."
        mkdir -p "$BUILD_DIR"
        DEBIAN_URL="https://cdimage.debian.org/cdimage/archive/12.9.0/amd64/iso-cd/debian-12.9.0-amd64-netinst.iso"
        if command -v wget >/dev/null 2>&1; then
            wget -q --show-progress "$DEBIAN_URL" -O "$DEBIAN_ISO"
        elif command -v curl >/dev/null 2>&1; then
            curl -L --progress-bar "$DEBIAN_URL" -o "$DEBIAN_ISO"
        else
            echo "Error: Neither wget nor curl available for download"
            exit 1
        fi
    fi

    echo ""
    echo "Running dependency check..."
    echo ""
fi

main
