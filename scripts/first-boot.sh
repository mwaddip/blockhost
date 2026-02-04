#!/bin/bash
#
# BlockHost First-Boot Script
#
# Runs on first boot after Debian installation to:
# 1. Install Proxmox VE
# 2. Configure network
# 3. Generate and display OTP
# 4. Start web installer for final configuration
#
# Tracks progress so it can resume if interrupted.
#

BLOCKHOST_DIR="/opt/blockhost"
STATE_DIR="/var/lib/blockhost"
RUN_DIR="/run/blockhost"
MARKER_FILE="${STATE_DIR}/.setup-complete"
LOG_FILE="/var/log/blockhost-firstboot.log"
CONSOLE="/dev/tty1"

# Step markers
STEP_HOSTNAME="${STATE_DIR}/.step-hostname"
STEP_PROXMOX="${STATE_DIR}/.step-proxmox"
STEP_NETWORK="${STATE_DIR}/.step-network"
STEP_OTP="${STATE_DIR}/.step-otp"

# Trap SIGHUP to prevent premature termination from TTY issues
trap '' HUP

# Create directories early (needed for logging)
mkdir -p "$STATE_DIR" "$RUN_DIR"

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE"
    # Also output to console if available
    if [ -e "$CONSOLE" ]; then
        echo "$msg" > "$CONSOLE" 2>/dev/null || true
    fi
}

# Check if already completed
if [ -f "$MARKER_FILE" ]; then
    log "BlockHost setup already complete. Exiting."
    exit 0
fi

log "First-boot script starting..."

# Stop getty on tty1 so we can use the console exclusively
systemctl stop getty@tty1.service 2>/dev/null || true

# Wait for system to settle
log "Waiting for system to settle..."
sleep 5

log "=========================================="
log "BlockHost First-Boot Starting"
log "=========================================="

# Export Python path
export PYTHONPATH="${BLOCKHOST_DIR}:${PYTHONPATH}"

#
# Step 1: Configure hostname for Proxmox
#
# CRITICAL: Proxmox requires the hostname to resolve to the real IP address,
# NOT to 127.0.1.1 (which Debian preseed creates by default).
# If /etc/hosts has "127.0.1.1 hostname", pve-cluster service will fail.
#
if [ ! -f "$STEP_HOSTNAME" ]; then
    log "Step 1: Configuring hostname for Proxmox..."

    # Wait for network with retry
    for i in {1..30}; do
        CURRENT_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        [ -n "$CURRENT_IP" ] && break
        log "Waiting for network... ($i/30)"
        sleep 2
    done

    if [ -z "$CURRENT_IP" ]; then
        log "ERROR: No network after 60 seconds"
        exit 1
    fi

    HOSTNAME=$(hostname)
    FQDN="${HOSTNAME}.local"

    # Fix /etc/hosts for Proxmox:
    # 1. Remove any 127.0.1.1 line (Debian default that breaks Proxmox)
    # 2. Ensure hostname resolves to real IP (required by pve-cluster)
    log "Fixing /etc/hosts for Proxmox (IP: $CURRENT_IP)..."

    # Remove the 127.0.1.1 line that Debian creates
    sed -i '/^127\.0\.1\.1/d' /etc/hosts

    # Remove any existing line for our hostname (in case of re-run with different IP)
    sed -i "/[[:space:]]${HOSTNAME}$/d" /etc/hosts
    sed -i "/[[:space:]]${HOSTNAME}[[:space:]]/d" /etc/hosts

    # Add correct entry with real IP (must be before localhost for Proxmox)
    # Insert after the 127.0.0.1 localhost line
    sed -i "/^127\.0\.0\.1/a ${CURRENT_IP}\t${FQDN}\t${HOSTNAME}" /etc/hosts

    log "Updated /etc/hosts:"
    cat /etc/hosts | tee -a "$LOG_FILE"

    touch "$STEP_HOSTNAME"
    log "Step 1 complete."
else
    log "Step 1: Hostname already configured, skipping."
fi

#
# Step 2: Install Proxmox VE
#
if [ ! -f "$STEP_PROXMOX" ]; then
    log "Step 2: Installing Proxmox VE..."

    # Configure apt proxy if available (for faster installs during testing)
    APT_PROXY="http://192.168.122.1:3142"
    if curl -s --connect-timeout 2 "$APT_PROXY" >/dev/null 2>&1; then
        log "Using apt proxy: $APT_PROXY"
        echo "Acquire::http::Proxy \"$APT_PROXY\";" > /etc/apt/apt.conf.d/00proxy
    fi

    # Add Proxmox repository
    if [ ! -f /etc/apt/sources.list.d/pve-install-repo.list ]; then
        log "Adding Proxmox VE repository..."
        echo "deb [arch=amd64] http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > /etc/apt/sources.list.d/pve-install-repo.list
    fi

    # Add Proxmox GPG key
    if [ ! -f /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg ]; then
        log "Adding Proxmox GPG key..."
        wget -q https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg -O /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg
    fi

    # Update and install
    log "Updating package lists..."
    apt-get update

    log "Installing Proxmox VE packages (this will take a while)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y proxmox-ve postfix open-iscsi chrony

    # Update grub
    update-grub

    touch "$STEP_PROXMOX"
    log "Step 2 complete - Proxmox VE installed!"
else
    log "Step 2: Proxmox VE already installed, skipping."
fi

#
# Step 2b: Install BlockHost packages
#
STEP_PACKAGES="${STATE_DIR}/.step-packages"
if [ ! -f "$STEP_PACKAGES" ]; then
    log "Step 2b: Installing BlockHost packages..."

    if [ -x "$BLOCKHOST_DIR/scripts/install-packages.sh" ]; then
        "$BLOCKHOST_DIR/scripts/install-packages.sh" 2>&1 | tee -a "$LOG_FILE"
    elif [ -d "$BLOCKHOST_DIR/packages/host" ]; then
        # Fallback: install packages directly
        log "Installing host packages..."
        for pkg in blockhost-common libpam-web3-tools blockhost-provisioner blockhost-engine blockhost-broker-client; do
            DEB=$(find "$BLOCKHOST_DIR/packages/host" -name "${pkg}_*.deb" -type f 2>/dev/null | head -1)
            if [ -n "$DEB" ] && [ -f "$DEB" ]; then
                log "Installing: $(basename "$DEB")"
                dpkg -i "$DEB" || apt-get install -f -y
            fi
        done

        # Copy template packages
        TEMPLATE_SRC="$BLOCKHOST_DIR/packages/template"
        TEMPLATE_DEST="/var/lib/blockhost/template-packages"
        if [ -d "$TEMPLATE_SRC" ] && ls "$TEMPLATE_SRC"/*.deb >/dev/null 2>&1; then
            mkdir -p "$TEMPLATE_DEST"
            cp "$TEMPLATE_SRC"/*.deb "$TEMPLATE_DEST/"
            log "Template packages copied to $TEMPLATE_DEST"
        fi
    else
        log "No packages found to install, skipping."
    fi

    touch "$STEP_PACKAGES"
    log "Step 2b complete - BlockHost packages installed!"
else
    log "Step 2b: Packages already installed, skipping."
fi

#
# Step 2c: Install Foundry (for contract deployment)
#
STEP_FOUNDRY="${STATE_DIR}/.step-foundry"
if [ ! -f "$STEP_FOUNDRY" ]; then
    log "Step 2c: Installing Foundry..."

    if ! command -v cast &> /dev/null; then
        log "Downloading Foundry binaries..."

        # Download pre-built binaries directly (non-interactive)
        FOUNDRY_DIR="/usr/local/lib/foundry"
        mkdir -p "$FOUNDRY_DIR"

        # Get latest release from GitHub
        FOUNDRY_VERSION=$(curl -s https://api.github.com/repos/foundry-rs/foundry/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [ -z "$FOUNDRY_VERSION" ]; then
            FOUNDRY_VERSION="nightly"
        fi
        log "Installing Foundry version: $FOUNDRY_VERSION"

        # Download and extract
        FOUNDRY_URL="https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/foundry_${FOUNDRY_VERSION}_linux_amd64.tar.gz"
        log "Downloading from: $FOUNDRY_URL"

        if curl -L "$FOUNDRY_URL" -o /tmp/foundry.tar.gz 2>&1; then
            tar -xzf /tmp/foundry.tar.gz -C "$FOUNDRY_DIR"
            rm /tmp/foundry.tar.gz

            # Create symlinks in /usr/local/bin
            for tool in forge cast anvil chisel; do
                if [ -f "$FOUNDRY_DIR/$tool" ]; then
                    chmod +x "$FOUNDRY_DIR/$tool"
                    ln -sf "$FOUNDRY_DIR/$tool" "/usr/local/bin/$tool"
                    log "Installed: $tool"
                fi
            done
        else
            log "WARNING: Failed to download Foundry, contract deployment may fail"
        fi
    else
        log "Foundry already installed: $(cast --version 2>/dev/null || echo 'unknown version')"
    fi

    touch "$STEP_FOUNDRY"
    log "Step 2c complete - Foundry installed!"
else
    log "Step 2c: Foundry already installed, skipping."
fi

#
# Step 3: Verify Network
#
if [ ! -f "$STEP_NETWORK" ]; then
    log "Step 3: Verifying network..."

    CURRENT_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

    if [ -z "$CURRENT_IP" ]; then
        log "No IP address. Attempting DHCP..."
        DEFAULT_IFACE=$(ip -o link show | awk -F': ' '$2 !~ /^(lo|veth|docker|br-|virbr|vmbr)/ {print $2; exit}')
        if [ -n "$DEFAULT_IFACE" ]; then
            dhclient -v "$DEFAULT_IFACE" 2>&1 || true
            sleep 5
            CURRENT_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        fi
    fi

    if [ -z "$CURRENT_IP" ]; then
        log "ERROR: No network connectivity!"
        exit 1
    fi

    log "Network OK: $CURRENT_IP"
    touch "$STEP_NETWORK"
else
    log "Step 3: Network already verified, skipping."
fi

#
# Step 4: Generate OTP
#
CURRENT_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

if [ ! -f "$STEP_OTP" ] || [ ! -f "$RUN_DIR/otp.json" ]; then
    log "Step 4: Generating OTP..."

    OTP_CODE=$(python3 -c "
import sys
sys.path.insert(0, '${BLOCKHOST_DIR}')
from installer.common.otp import OTPManager
otp = OTPManager()
print(otp.generate())
" 2>/dev/null)

    if [ -z "$OTP_CODE" ]; then
        log "ERROR: Failed to generate OTP"
        exit 1
    fi

    log "OTP generated: $OTP_CODE"
    touch "$STEP_OTP"
else
    # Get existing OTP
    OTP_CODE=$(python3 -c "
import sys
sys.path.insert(0, '${BLOCKHOST_DIR}')
from installer.common.otp import OTPManager
otp = OTPManager()
code = otp.get_code()
if code:
    print(code)
else:
    print(otp.generate())
" 2>/dev/null)
    log "Using existing OTP: $OTP_CODE"
fi

#
# Step 5: Start Web Installer (in background)
#
log "Step 5: Starting web installer..."

# Determine HTTP or HTTPS
if echo "$CURRENT_IP" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
    SCHEME="http"
    PORT="80"
else
    SCHEME="https"
    PORT="443"
fi

URL="${SCHEME}://${CURRENT_IP}/"
PVE_URL="https://${CURRENT_IP}:8006/"

# Kill any existing Flask process
pkill -f "installer.web.app" 2>/dev/null || true
sleep 1

# Start Flask in background using setsid to fully detach from this session
# Explicitly pass PYTHONPATH to ensure module is found
cd "$BLOCKHOST_DIR"
if [ "$SCHEME" = "https" ]; then
    PYTHONPATH="$BLOCKHOST_DIR" setsid python3 -m installer.web.app --host 0.0.0.0 --port "$PORT" --https >> "$LOG_FILE" 2>&1 &
else
    PYTHONPATH="$BLOCKHOST_DIR" setsid python3 -m installer.web.app --host 0.0.0.0 --port "$PORT" >> "$LOG_FILE" 2>&1 &
fi

sleep 3

# Verify Flask started by checking port
if ss -tlnp | grep -q ":${PORT}.*python"; then
    FLASK_PID=$(pgrep -f "installer.web.app" | head -1)
    echo "$FLASK_PID" > "$RUN_DIR/flask.pid"
    log "Web installer running (PID: $FLASK_PID)"
else
    log "ERROR: Web installer failed to start"
    exit 1
fi

#
# Display OTP on console via /etc/issue (persists with getty)
#
cat > /etc/issue << EOF

  ╔══════════════════════════════════════════════════════════════╗
  ║                   BlockHost Installer                        ║
  ╚══════════════════════════════════════════════════════════════╝

  Proxmox VE has been installed!

  ┌────────────────────────────────────────────────────────────┐
  │  Web Installer:  $URL
  │  Proxmox Web UI: $PVE_URL
  └────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────┐
  │                                                            │
  │   ACCESS CODE:   $OTP_CODE                                 │
  │                                                            │
  └────────────────────────────────────────────────────────────┘

  1. Open a web browser
  2. Go to $URL
  3. Enter the access code above

  Code expires in 4 hours. Max 10 attempts.

EOF

log "Setup display complete. Web installer running at $URL"
log "OTP: $OTP_CODE"

# Restart getty on tty1 so user can log in
# Getty will display /etc/issue above the login prompt
systemctl start getty@tty1.service 2>/dev/null || true

exit 0
