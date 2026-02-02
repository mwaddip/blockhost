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

# Step markers
STEP_HOSTNAME="${STATE_DIR}/.step-hostname"
STEP_PROXMOX="${STATE_DIR}/.step-proxmox"
STEP_NETWORK="${STATE_DIR}/.step-network"
STEP_OTP="${STATE_DIR}/.step-otp"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check if already completed
if [ -f "$MARKER_FILE" ]; then
    log "BlockHost setup already complete. Exiting."
    exit 0
fi

# Create directories
mkdir -p "$STATE_DIR" "$RUN_DIR"

log "=========================================="
log "BlockHost First-Boot Starting"
log "=========================================="

# Export Python path
export PYTHONPATH="${BLOCKHOST_DIR}:${PYTHONPATH}"

#
# Step 1: Configure hostname for Proxmox
#
if [ ! -f "$STEP_HOSTNAME" ]; then
    log "Step 1: Configuring hostname..."

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

    # Update /etc/hosts for Proxmox
    if ! grep -q "$FQDN" /etc/hosts; then
        echo "$CURRENT_IP $FQDN $HOSTNAME" >> /etc/hosts
        log "Updated /etc/hosts: $CURRENT_IP $FQDN $HOSTNAME"
    fi

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

# Start Flask in background
cd "$BLOCKHOST_DIR"
if [ "$SCHEME" = "https" ]; then
    nohup python3 -m installer.web.app --host 0.0.0.0 --port "$PORT" --https >> "$LOG_FILE" 2>&1 &
else
    nohup python3 -m installer.web.app --host 0.0.0.0 --port "$PORT" >> "$LOG_FILE" 2>&1 &
fi

FLASK_PID=$!
echo $FLASK_PID > "$RUN_DIR/flask.pid"
sleep 2

# Verify Flask started
if kill -0 $FLASK_PID 2>/dev/null; then
    log "Web installer running (PID: $FLASK_PID)"
else
    log "ERROR: Web installer failed to start"
    exit 1
fi

#
# Display OTP on console
#
clear
cat << EOF

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

  Web installer is running in background.
  You can log in to this console as root.

EOF

log "Setup display complete. Web installer running at $URL"
log "OTP: $OTP_CODE"

exit 0
