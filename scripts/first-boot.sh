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

# Check if held after a snapshot revert (testing mode)
if [ -f "${STATE_DIR}/.firstboot-hold" ]; then
    log "First-boot held (post-revert). Upload new .debs, then run: resume"
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
# Snapshot helper — takes a read-only snapshot before each major step
#
snapshot_if_testing() {
    local name="$1"
    [ -f /etc/blockhost/.testing-mode ] || return 0
    [ "$(stat -f -c %T /)" = "btrfs" ] || return 0

    local root_dev root_subvol
    root_dev=$(findmnt -no SOURCE / | sed 's/\[.*$//')
    # Extract subvolume path from mount options (e.g. "subvol=/@rootfs" → "@rootfs")
    root_subvol=$(findmnt -no OPTIONS / | grep -oP 'subvol=/\K[^,]+')

    if [ -z "$root_subvol" ]; then
        log "Snapshot: cannot detect root subvolume, skipping $name"
        return 0
    fi

    mkdir -p /mnt/btrfs-top
    mount -o subvolid=5 "$root_dev" /mnt/btrfs-top

    if [ -d "/mnt/btrfs-top/@snapshots" ] && [ ! -d "/mnt/btrfs-top/@snapshots/$name" ]; then
        btrfs subvolume snapshot "/mnt/btrfs-top/$root_subvol" "/mnt/btrfs-top/@snapshots/$name"
        log "Snapshot: $name"
    fi

    umount /mnt/btrfs-top
}

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
# script and manifest are shipped inside the provisioner .deb.
#
snapshot_if_testing "pre-packages"

STEP_PACKAGES="${STATE_DIR}/.step-packages"
if [ ! -f "$STEP_PACKAGES" ]; then
    log "Step 2: Installing BlockHost packages..."

    if [ -x "$BLOCKHOST_DIR/scripts/install-packages.sh" ]; then
        "$BLOCKHOST_DIR/scripts/install-packages.sh" 2>&1 | tee -a "$LOG_FILE"
    elif [ -d "$BLOCKHOST_DIR/packages/host" ]; then
        # Fallback: install packages directly
        log "Installing host packages..."

        # Auto-detect provisioner package
        PROV_DEB=$(find "$BLOCKHOST_DIR/packages/host" -name "blockhost-provisioner-*_*.deb" -type f 2>/dev/null | head -1)
        PROV_PKG=""
        if [ -n "$PROV_DEB" ]; then
            PROV_PKG=$(basename "$PROV_DEB" | sed 's/_.*$//')
        fi

        # Auto-detect engine package in fallback path
        FALLBACK_ENGINE_DEB=$(find "$BLOCKHOST_DIR/packages/host" -name "blockhost-engine*_*.deb" -type f 2>/dev/null | head -1)
        FALLBACK_ENGINE_PKG=""
        if [ -n "$FALLBACK_ENGINE_DEB" ]; then
            FALLBACK_ENGINE_PKG=$(basename "$FALLBACK_ENGINE_DEB" | sed 's/_.*$//')
        fi

        # Engine is deferred — depends on nodejs (>= 22) from step 3b-pre
        FALLBACK_ORDER=(blockhost-common)
        [ -n "$PROV_PKG" ] && FALLBACK_ORDER+=("$PROV_PKG")
        FALLBACK_ORDER+=(blockhost-broker-client)
        FALLBACK_ORDER+=(blockhost-watchdog)

        for pkg in "${FALLBACK_ORDER[@]}"; do
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
# installed by the provisioner .deb in Step 2.
#
snapshot_if_testing "pre-provisioner-hook"

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
# Step 3a: Create network bridge
#
# Creates a Linux bridge before the wizard starts. The provisioner will discover
# the existing bridge and use it — no provisioner-specific bridge code needed.
# Brief network disruption during IP migration is safe here (all packages installed,
# no wizard running yet).
#
STEP_BRIDGE="${STATE_DIR}/.step-bridge"
if [ ! -f "$STEP_BRIDGE" ]; then
    log "Step 3a: Creating network bridge..."

    # If the provisioner manages its own bridge, skip creation.
    # Provisioner hooks write /etc/blockhost/bridge-managed to signal this.
    if [ -f /etc/blockhost/bridge-managed ]; then
        log "Provisioner manages bridge (/etc/blockhost/bridge-managed exists) — skipping"
        touch "$STEP_BRIDGE"
        log "Step 3a complete!"
    else

    # Skip if a bridge with a global IPv4 address already exists
    EXISTING_BRIDGE=""
    for brdir in /sys/class/net/*/bridge; do
        [ -d "$brdir" ] || continue
        BR_DEV=$(basename "$(dirname "$brdir")")
        if ip -4 addr show "$BR_DEV" scope global 2>/dev/null | grep -q 'inet '; then
            EXISTING_BRIDGE="$BR_DEV"
            break
        fi
    done

    if [ -n "$EXISTING_BRIDGE" ]; then
        log "Bridge already exists: $EXISTING_BRIDGE — skipping creation"
        echo "$EXISTING_BRIDGE" > "$RUN_DIR/bridge"
    else
        # Detect primary NIC from default route
        PRIMARY_NIC=$(ip -j route show default 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['dev'])" 2>/dev/null)

        if [ -z "$PRIMARY_NIC" ]; then
            log "WARNING: No default route — cannot create bridge, continuing without"
        elif [ -d "/sys/class/net/${PRIMARY_NIC}/wireless" ]; then
            log "WARNING: Primary NIC $PRIMARY_NIC is wireless — cannot bridge, continuing without"
        else
            # Capture current IP config
            BRIDGE_IP=$(ip -j addr show "$PRIMARY_NIC" 2>/dev/null | python3 -c "
import sys, json
for iface in json.load(sys.stdin):
    for a in iface.get('addr_info', []):
        if a.get('family') == 'inet' and a.get('scope') == 'global':
            print(f\"{a['local']}/{a['prefixlen']}\")
            sys.exit(0)
" 2>/dev/null)
            BRIDGE_GW=$(ip -j route show default 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)[0].get('gateway',''))" 2>/dev/null)

            if [ -z "$BRIDGE_IP" ] || [ -z "$BRIDGE_GW" ]; then
                log "WARNING: Cannot determine IP ($BRIDGE_IP) or gateway ($BRIDGE_GW) — skipping bridge"
            else
                log "Creating br0: IP=$BRIDGE_IP GW=$BRIDGE_GW NIC=$PRIMARY_NIC"

                # Create bridge and migrate IP
                brctl addbr br0
                brctl addif br0 "$PRIMARY_NIC"
                brctl stp br0 off
                brctl setfd br0 0
                # Inherit NIC's MAC so DHCP renews the same lease after bridge creation
                ip link set br0 address "$(cat /sys/class/net/${PRIMARY_NIC}/address)"
                ip link set br0 up
                ip addr del "$BRIDGE_IP" dev "$PRIMARY_NIC" 2>/dev/null
                ip addr add "$BRIDGE_IP" dev br0
                ip route add default via "$BRIDGE_GW" dev br0 2>/dev/null

                # Verify connectivity
                if ping -c 1 -W 5 "$BRIDGE_GW" >/dev/null 2>&1; then
                    log "Bridge br0 operational — connectivity verified"
                    echo "br0" > "$RUN_DIR/bridge"

                    # Persist to /etc/network/interfaces
                    if [ -f /etc/network/interfaces ]; then
                        # Comment out ALL existing NIC stanzas (auto, allow-hotplug, iface)
                        sed -i "s/^auto ${PRIMARY_NIC}$/# auto ${PRIMARY_NIC}  # moved to br0/" /etc/network/interfaces
                        sed -i "s/^allow-hotplug ${PRIMARY_NIC}$/# allow-hotplug ${PRIMARY_NIC}  # moved to br0/" /etc/network/interfaces
                        sed -i "s/^iface ${PRIMARY_NIC} inet/# iface ${PRIMARY_NIC} inet/" /etc/network/interfaces
                    fi
                    NIC_MAC=$(cat /sys/class/net/${PRIMARY_NIC}/address)
                    cat >> /etc/network/interfaces << BREOF

# Bridge created by BlockHost first-boot
iface ${PRIMARY_NIC} inet manual

auto br0
iface br0 inet dhcp
    hwaddress ether ${NIC_MAC}
    bridge_ports ${PRIMARY_NIC}
    bridge_stp off
    bridge_fd 0
BREOF

                    log "Bridge persisted to /etc/network/interfaces"
                else
                    # Rollback — restore IP to NIC, destroy bridge
                    log "WARNING: Bridge connectivity check failed — rolling back"
                    ip link set br0 down 2>/dev/null
                    brctl delif br0 "$PRIMARY_NIC" 2>/dev/null
                    brctl delbr br0 2>/dev/null
                    ip addr add "$BRIDGE_IP" dev "$PRIMARY_NIC" 2>/dev/null
                    ip route add default via "$BRIDGE_GW" dev "$PRIMARY_NIC" 2>/dev/null
                    log "WARNING: Continuing without bridge"
                fi
            fi
        fi
    fi

    touch "$STEP_BRIDGE"
    log "Step 3a complete!"
    fi  # end bridge-managed else
else
    log "Step 3a: Bridge already configured, skipping."
    # Ensure /run/blockhost/bridge is populated on resume
    if [ ! -f "$RUN_DIR/bridge" ]; then
        for brdir in /sys/class/net/*/bridge; do
            [ -d "$brdir" ] || continue
            BR_DEV=$(basename "$(dirname "$brdir")")
            if ip -4 addr show "$BR_DEV" scope global 2>/dev/null | grep -q 'inet '; then
                echo "$BR_DEV" > "$RUN_DIR/bridge"
                break
            fi
        done
    fi
fi

#
# Step 3b-pre: Install Node.js 22 LTS via NodeSource
#
# Required by the engine's monitor service and CLI tools.
# NodeSource provides stable .deb packages for Node 22 LTS.
#
STEP_NODEJS="${STATE_DIR}/.step-nodejs"
if [ ! -f "$STEP_NODEJS" ]; then
    if command -v node >/dev/null 2>&1; then
        NODE_MAJOR=$(node --version 2>/dev/null | sed 's/v//' | cut -d. -f1)
        if [ "$NODE_MAJOR" -ge 22 ] 2>/dev/null; then
            log "Step 3b-pre: Node.js $(node --version) already installed, skipping."
            touch "$STEP_NODEJS"
        fi
    fi

    if [ ! -f "$STEP_NODEJS" ]; then
        log "Step 3b-pre: Installing Node.js 22 LTS via NodeSource..."
        if curl -fsSL https://deb.nodesource.com/setup_22.x | bash - 2>&1 | tee -a "$LOG_FILE"; then
            apt-get install -y nodejs 2>&1 | tee -a "$LOG_FILE"
            if command -v node >/dev/null 2>&1; then
                log "Step 3b-pre complete - Node.js $(node --version) installed"
            else
                log "ERROR: Node.js installation failed"
                exit 1
            fi
        else
            log "ERROR: NodeSource setup failed"
            exit 1
        fi
        touch "$STEP_NODEJS"
    fi
else
    log "Step 3b-pre: Node.js already installed, skipping."
fi

#
# Step 3b-post: Install engine package (deferred from step 2)
#
# The engine depends on nodejs (>= 22), python3-pycryptodome, python3-ecdsa.
# Node was just installed above; pycryptodome and ecdsa come from Debian repos.
# We deferred the engine from install-packages.sh because dpkg -i fails when
# dependencies are missing, and apt-get -f install "fixes" it by removing the package.
#
snapshot_if_testing "pre-engine"

STEP_ENGINE="${STATE_DIR}/.step-engine"
if [ ! -f "$STEP_ENGINE" ]; then
    log "Step 3b-post: Installing engine package..."

    ENGINE_DEB=$(find "$BLOCKHOST_DIR/packages/host" -maxdepth 1 -name "blockhost-engine*_*.deb" -type f 2>/dev/null | head -1)
    if [ -n "$ENGINE_DEB" ] && [ -f "$ENGINE_DEB" ]; then
        # Install APT dependencies first so dpkg -i succeeds
        apt-get install -y python3-pycryptodome python3-ecdsa 2>&1 | tee -a "$LOG_FILE"
        log "Installing: $(basename "$ENGINE_DEB")"
        dpkg -i "$ENGINE_DEB" 2>&1 | tee -a "$LOG_FILE"
        ENGINE_PKG_NAME=$(dpkg-deb -f "$ENGINE_DEB" Package)
        if dpkg -s "$ENGINE_PKG_NAME" >/dev/null 2>&1; then
            log "Step 3b-post complete - Engine installed ($ENGINE_PKG_NAME)"
        else
            log "ERROR: Engine package installation failed ($ENGINE_PKG_NAME)"
            exit 1
        fi
    else
        log "WARNING: No engine package found in $BLOCKHOST_DIR/packages/host"
    fi

    touch "$STEP_ENGINE"
else
    log "Step 3b-post: Engine already installed, skipping."
fi

#
# Step 3c: Run engine first-boot hook
#
# The engine hook handles installing engine-specific host dependencies
# (e.g. Foundry for EVM). Discovered from the engine manifest installed
# by the engine .deb in step 3b-post.
#
snapshot_if_testing "pre-engine-hook"

STEP_ENGINE_HOOK="${STATE_DIR}/.step-engine-hook"
if [ ! -f "$STEP_ENGINE_HOOK" ]; then
    log "Step 3c: Running engine first-boot hook..."

    ENGINE_HOOK=""
    ENGINE_MANIFEST="/usr/share/blockhost/engine.json"

    if [ -f "$ENGINE_MANIFEST" ]; then
        ENGINE_HOOK=$(python3 -c "import json; print(json.load(open('$ENGINE_MANIFEST')).get('setup',{}).get('first_boot_hook',''))" 2>/dev/null)
    fi

    if [ -n "$ENGINE_HOOK" ] && [ -x "$ENGINE_HOOK" ]; then
        log "Running engine hook: $ENGINE_HOOK"
        export STATE_DIR LOG_FILE
        "$ENGINE_HOOK" 2>&1 | tee -a "$LOG_FILE"
        HOOK_RC=${PIPESTATUS[0]}
        if [ "$HOOK_RC" -ne 0 ]; then
            log "ERROR: Engine hook failed (exit $HOOK_RC)"
            exit 1
        fi
    elif [ -n "$ENGINE_HOOK" ]; then
        log "WARNING: Engine hook declared but not executable: $ENGINE_HOOK"
    else
        log "Step 3c: No engine hook declared, skipping."
    fi

    touch "$STEP_ENGINE_HOOK"
    log "Step 3c complete!"
else
    log "Step 3c: Engine hook already completed, skipping."
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

snapshot_if_testing "pre-wizard"

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
