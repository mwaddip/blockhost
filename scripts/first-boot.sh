#!/bin/bash
#
# BlockHost First-Boot Script
#
# Runs on first boot after Debian installation to:
# 1. Wait for network
# 2. Install BlockHost packages
# 3. Run provisioner first-boot hook (installs hypervisor software)
# 4. Install Foundry, verify network
# 5. Generate and display OTP
# 6. Start web installer for final configuration
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
STEP_NETWORK_WAIT="${STATE_DIR}/.step-network-wait"
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
# Step 1: Wait for network
#
if [ ! -f "$STEP_NETWORK_WAIT" ]; then
    log "Step 1: Waiting for network..."

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

    log "Network up: $CURRENT_IP"
    touch "$STEP_NETWORK_WAIT"
fi

#
# Step 2: Install BlockHost packages
#
# Packages must be installed before the provisioner hook because the hook
# script and manifest are shipped inside blockhost-provisioner-proxmox.deb.
#
STEP_PACKAGES="${STATE_DIR}/.step-packages"
if [ ! -f "$STEP_PACKAGES" ]; then
    log "Step 2: Installing BlockHost packages..."

    if [ -x "$BLOCKHOST_DIR/scripts/install-packages.sh" ]; then
        "$BLOCKHOST_DIR/scripts/install-packages.sh" 2>&1 | tee -a "$LOG_FILE"
    elif [ -d "$BLOCKHOST_DIR/packages/host" ]; then
        # Fallback: install packages directly
        log "Installing host packages..."
        for pkg in blockhost-common libpam-web3-tools blockhost-provisioner-proxmox blockhost-engine blockhost-broker-client; do
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
    log "Step 2 complete - BlockHost packages installed!"
else
    log "Step 2: Packages already installed, skipping."
fi

#
# Step 2b: Verify blockhost user (created by blockhost-common .deb)
#
log "Step 2b: Verifying blockhost user..."
if id -u blockhost >/dev/null 2>&1; then
    log "Step 2b complete - blockhost user exists"
else
    log "ERROR: blockhost user not found (should be created by blockhost-common postinst)"
    exit 1
fi

#
# Step 2c: Verify root agent (installed by blockhost-common .deb)
#
log "Step 2c: Verifying root agent..."
if ! systemctl is-active --quiet blockhost-root-agent; then
    systemctl start blockhost-root-agent || log "WARNING: Failed to start root agent"
fi

for i in $(seq 1 10); do
    [ -S /run/blockhost/root-agent.sock ] && break
    sleep 1
done

if [ -S /run/blockhost/root-agent.sock ]; then
    log "Step 2c complete - Root agent socket ready"
else
    log "WARNING: Root agent socket not ready after 10s"
fi

#
# Step 3: Run provisioner first-boot hook
#
# The provisioner hook handles installing hypervisor-specific software
# (e.g. Proxmox VE, Terraform). Discovered from the provisioner manifest
# installed by blockhost-provisioner-proxmox.deb in Step 2.
#
STEP_PROVISIONER_HOOK="${STATE_DIR}/.step-provisioner-hook"
if [ ! -f "$STEP_PROVISIONER_HOOK" ]; then
    log "Step 3: Running provisioner first-boot hook..."

    PROVISIONER_HOOK=""
    MANIFEST="/usr/share/blockhost/provisioner.json"

    if [ -f "$MANIFEST" ]; then
        PROVISIONER_HOOK=$(python3 -c "import json; print(json.load(open('$MANIFEST')).get('setup',{}).get('first_boot_hook',''))" 2>/dev/null)
    fi

    if [ -n "$PROVISIONER_HOOK" ] && [ -x "$PROVISIONER_HOOK" ]; then
        log "Running provisioner hook: $PROVISIONER_HOOK"
        export STATE_DIR LOG_FILE
        "$PROVISIONER_HOOK" 2>&1 | tee -a "$LOG_FILE"
        HOOK_RC=${PIPESTATUS[0]}
        if [ "$HOOK_RC" -ne 0 ]; then
            log "ERROR: Provisioner hook failed (exit $HOOK_RC)"
            exit 1
        fi
    else
        log "ERROR: No provisioner hook found at manifest path"
        log "Expected manifest at: $MANIFEST"
        exit 1
    fi

    touch "$STEP_PROVISIONER_HOOK"
    log "Step 3 complete - Provisioner hook finished!"
else
    log "Step 3: Provisioner hook already completed, skipping."
fi

#
# Step 3b: Install Foundry (for contract deployment)
#
STEP_FOUNDRY="${STATE_DIR}/.step-foundry"
if [ ! -f "$STEP_FOUNDRY" ]; then
    log "Step 3b: Installing Foundry..."

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
    log "Step 3b complete - Foundry installed!"
else
    log "Step 3b: Foundry already installed, skipping."
fi

#
# Step 4: Verify Network
#
if [ ! -f "$STEP_NETWORK" ]; then
    log "Step 4: Verifying network..."

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
    log "Step 4: Network already verified, skipping."
fi

#
# Step 5: Generate OTP
#
CURRENT_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

if [ ! -f "$STEP_OTP" ] || [ ! -f "$RUN_DIR/otp.json" ]; then
    log "Step 5: Generating OTP..."

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
# Step 6: Start Web Installer (in background)
#
log "Step 6: Starting web installer..."

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
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$BLOCKHOST_DIR" setsid python3 -m installer.web.app --host 0.0.0.0 --port "$PORT" --https >> "$LOG_FILE" 2>&1 &
else
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$BLOCKHOST_DIR" setsid python3 -m installer.web.app --host 0.0.0.0 --port "$PORT" >> "$LOG_FILE" 2>&1 &
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

  Setup complete — ready for configuration.

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
