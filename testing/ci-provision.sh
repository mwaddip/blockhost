#!/usr/bin/env bash
# =============================================================================
# BlockHost CI Provisioning — VM Lifecycle Script
#
# Creates a VM from the BlockHost ISO, waits for preseed + first-boot,
# retrieves OTP, submits wizard config via /api/setup-test, and polls
# finalization until complete (or it fails, which it will, because
# that's what software does).
#
# Usage:
#   ./testing/ci-provision.sh --iso <path> --config <json-file>
#   ./testing/ci-provision.sh --destroy <vm-name>
#
# Prerequisites:
#   - libvirt/virsh/virt-install
#   - sshpass, jq, curl
#   - Default NAT network (virbr0) with DHCP
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
VM_NAME="blockhost-ci-$$"
ISO_PATH=""
CONFIG_FILE=""
DESTROY_VM=""
RAM_MB=8192
VCPUS=4
DISK_GB=64
NETWORK="default"
LIBVIRT_URI="qemu:///system"
SSH_PASS="blockhost"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

# Wrappers to ensure system connection (default network lives in qemu:///system)
virsh()        { command virsh --connect "$LIBVIRT_URI" "$@"; }
virt_install() { command virt-install --connect "$LIBVIRT_URI" "$@"; }

# Timeouts (seconds)
PRESEED_TIMEOUT=900     # 15 min for preseed install
FIRSTBOOT_TIMEOUT=1200  # 20 min for first-boot (Proxmox install etc)
FINALIZE_TIMEOUT=1800   # 30 min for finalization (contracts, template build)
POLL_INTERVAL=15

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COOKIE_JAR=$(mktemp /tmp/blockhost-ci-cookies.XXXXXX)
START_TIME=$(date +%s)

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
info()  { echo "[INFO]  $(date +%H:%M:%S) $*"; }
pass()  { echo "[PASS]  $(date +%H:%M:%S) $*"; }
fail()  { echo "[FAIL]  $(date +%H:%M:%S) $*" >&2; exit 1; }
wait_() { echo "[WAIT]  $(date +%H:%M:%S) $*"; }

refresh_ip() {
    # Use ARP table — DHCP leases are unreliable after Proxmox installs a bridge.
    # The bridge (vmbr0) gets a new DHCP lease with a different client ID that
    # doesn't always show in virsh net-dhcp-leases. ARP reflects actual reality.
    local new_ip
    # First try ARP (works once the VM has talked on the network)
    new_ip=$(arp -an 2>/dev/null | grep -i "$MAC" | grep -oP '\(\K[0-9.]+(?=\))' | tail -1 || true)
    # Fall back to DHCP leases if ARP has nothing yet (early boot)
    if [ -z "$new_ip" ]; then
        new_ip=$(virsh net-dhcp-leases "$NETWORK" 2>/dev/null | \
            grep -i "$MAC" | awk '{print $5}' | cut -d'/' -f1 | tail -1 || true)
    fi
    if [ -n "$new_ip" ] && [ "$new_ip" != "$VM_IP" ]; then
        [ -n "$VM_IP" ] && info "IP changed: $VM_IP -> $new_ip"
        VM_IP="$new_ip"
    fi
}

elapsed() {
    local secs=$(( $(date +%s) - START_TIME ))
    printf "%dm %02ds" $(( secs / 60 )) $(( secs % 60 ))
}

cleanup() {
    rm -f "$COOKIE_JAR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --iso)      ISO_PATH="$2"; shift 2 ;;
        --config)   CONFIG_FILE="$2"; shift 2 ;;
        --name)     VM_NAME="$2"; shift 2 ;;
        --destroy)  DESTROY_VM="$2"; shift 2 ;;
        --ram)      RAM_MB="$2"; shift 2 ;;
        --vcpus)    VCPUS="$2"; shift 2 ;;
        --disk)     DISK_GB="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 --iso <path> --config <config.json> [--name <vm-name>]"
            echo "       $0 --destroy <vm-name>"
            echo ""
            echo "Options:"
            echo "  --iso <path>       Path to BlockHost ISO"
            echo "  --config <file>    JSON config for /api/setup-test"
            echo "  --name <name>      VM name (default: blockhost-ci-PID)"
            echo "  --destroy <name>   Destroy a VM and remove storage"
            echo "  --ram <MB>         RAM in MB (default: 8192)"
            echo "  --vcpus <N>        vCPUs (default: 4)"
            echo "  --disk <GB>        Disk in GB (default: 64)"
            exit 0
            ;;
        *) fail "Unknown argument: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# Destroy mode
# ---------------------------------------------------------------------------
if [ -n "$DESTROY_VM" ]; then
    info "Destroying VM: $DESTROY_VM"
    virsh destroy "$DESTROY_VM" 2>/dev/null || true
    virsh undefine "$DESTROY_VM" --remove-all-storage 2>/dev/null || true
    pass "VM $DESTROY_VM destroyed"
    exit 0
fi

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
[ -n "$ISO_PATH" ]    || fail "--iso is required"
[ -f "$ISO_PATH" ]    || fail "ISO not found: $ISO_PATH"
[ -n "$CONFIG_FILE" ] || fail "--config is required"
[ -f "$CONFIG_FILE" ] || fail "Config file not found: $CONFIG_FILE"

command -v /usr/bin/virsh >/dev/null         || fail "virsh not found"
command -v /usr/bin/virt-install >/dev/null   || fail "virt-install not found"
command -v sshpass >/dev/null        || fail "sshpass not found"
command -v jq >/dev/null             || fail "jq not found"
command -v curl >/dev/null           || fail "curl not found"
command -v cast >/dev/null           || fail "cast not found (install Foundry)"

# Validate config is valid JSON with required fields
jq -e '.otp' "$CONFIG_FILE" > /dev/null 2>&1 && \
    fail "Config file should NOT contain 'otp' — OTP is read from the VM at runtime"
jq -e '.blockchain' "$CONFIG_FILE" > /dev/null 2>&1 || \
    fail "Config file must contain 'blockchain' section"

# Secrets from environment — deployer key funds contract deployment + gas
[ -n "${DEPLOYER_KEY:-}" ]          || fail "DEPLOYER_KEY env var required (deployer private key)"

# Derive admin wallet address from deployer key
ADMIN_WALLET=$(cast wallet address --private-key "$DEPLOYER_KEY")
[ -n "$ADMIN_WALLET" ] || fail "Could not derive wallet address from DEPLOYER_KEY"
info "Admin wallet: $ADMIN_WALLET"

info "VM name:    $VM_NAME"
info "ISO:        $ISO_PATH"
info "Config:     $CONFIG_FILE"
echo ""

# =============================================================================
# Phase 1 — Create VM
# =============================================================================
info "Phase 1: Creating VM"

# Clean up any leftover with same name
virsh destroy "$VM_NAME" 2>/dev/null || true
virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null || true

virt_install \
    --name "$VM_NAME" \
    --ram "$RAM_MB" \
    --vcpus "$VCPUS" \
    --disk "size=${DISK_GB},format=qcow2" \
    --cdrom "$ISO_PATH" \
    --os-variant debian12 \
    --network "network=${NETWORK}" \
    --graphics vnc,listen=127.0.0.1 \
    --noautoconsole \
    --boot cdrom,hd

pass "VM created: $VM_NAME"

# Get MAC address for later DHCP lookup
MAC=$(virsh domiflist "$VM_NAME" | awk '/network/ {print $5}' | head -1)
[ -n "$MAC" ] || fail "Could not determine VM MAC address"
info "MAC address: $MAC"

# =============================================================================
# Phase 2 — Wait for preseed install to complete
# =============================================================================
info "Phase 2: Waiting for preseed install (timeout: ${PRESEED_TIMEOUT}s)"

ELAPSED=0
while [ "$ELAPSED" -lt "$PRESEED_TIMEOUT" ]; do
    STATE=$(virsh domstate "$VM_NAME" 2>/dev/null || echo "unknown")
    if [ "$STATE" = "shut off" ]; then
        break
    fi
    wait_ "VM state: $STATE (${ELAPSED}s / ${PRESEED_TIMEOUT}s)"
    sleep "$POLL_INTERVAL"
    ELAPSED=$(( ELAPSED + POLL_INTERVAL ))
done

STATE=$(virsh domstate "$VM_NAME" 2>/dev/null || echo "unknown")
if [ "$STATE" != "shut off" ]; then
    fail "Preseed install did not complete within ${PRESEED_TIMEOUT}s (state: $STATE)"
fi

pass "Preseed install complete ($(elapsed))"

# =============================================================================
# Phase 3 — Remove ISO, boot from HDD
# =============================================================================
info "Phase 3: Booting from HDD"

# Detach CDROM (change media to empty)
virsh change-media "$VM_NAME" hda --eject 2>/dev/null || \
    virsh change-media "$VM_NAME" sda --eject 2>/dev/null || \
    info "Could not eject CDROM (may already be detached)"

virsh start "$VM_NAME"
pass "VM started (first-boot beginning)"

# =============================================================================
# Phase 4 — Wait for first-boot + SSH availability
# =============================================================================
info "Phase 4: Waiting for first-boot to complete (timeout: ${FIRSTBOOT_TIMEOUT}s)"

VM_IP=""
ELAPSED=0

while [ "$ELAPSED" -lt "$FIRSTBOOT_TIMEOUT" ]; do
    refresh_ip

    if [ -n "$VM_IP" ]; then
        # Try SSH connection
        if sshpass -p "$SSH_PASS" ssh $SSH_OPTS -o ConnectTimeout=5 \
            "root@${VM_IP}" "test -f /run/blockhost/otp.json" 2>/dev/null; then
            break
        fi
        wait_ "SSH not ready yet at $VM_IP (${ELAPSED}s / ${FIRSTBOOT_TIMEOUT}s)"
    else
        wait_ "Waiting for DHCP lease... (${ELAPSED}s / ${FIRSTBOOT_TIMEOUT}s)"
    fi

    sleep "$POLL_INTERVAL"
    ELAPSED=$(( ELAPSED + POLL_INTERVAL ))
done

[ -n "$VM_IP" ] || fail "VM never got a DHCP lease within ${FIRSTBOOT_TIMEOUT}s"

# Final SSH check
sshpass -p "$SSH_PASS" ssh $SSH_OPTS -o ConnectTimeout=10 \
    "root@${VM_IP}" "test -f /run/blockhost/otp.json" 2>/dev/null || \
    fail "OTP file not found — first-boot may not have completed. Check: virsh console $VM_NAME"

pass "First-boot complete, SSH available at $VM_IP ($(elapsed))"

# =============================================================================
# Phase 5 — Get OTP
# =============================================================================
info "Phase 5: Reading OTP from VM"

OTP_JSON=$(sshpass -p "$SSH_PASS" ssh $SSH_OPTS "root@${VM_IP}" \
    "cat /run/blockhost/otp.json")

OTP_CODE=$(echo "$OTP_JSON" | jq -r '.code')
[ -n "$OTP_CODE" ] && [ "$OTP_CODE" != "null" ] || fail "Could not read OTP code"

pass "OTP: $OTP_CODE"

# Lock the IP — networking is stable after first-boot completes.
# DHCP lease table becomes unreliable after Proxmox reconfigures bridges.
STABLE_IP="$VM_IP"
info "Locking IP to $STABLE_IP for remaining phases"

# =============================================================================
# Phase 6 — Submit wizard config via /api/setup-test
# =============================================================================
info "Phase 6: Submitting wizard config"

# Generate admin signature (same as MetaMask wallet-connect in wizard)
ADMIN_PUBLIC_SECRET=$(jq -r '.admin_public_secret // "blockhost-access"' "$CONFIG_FILE")
ADMIN_SIGNATURE=$(cast wallet sign "$ADMIN_PUBLIC_SECRET" --private-key "$DEPLOYER_KEY")
[ -n "$ADMIN_SIGNATURE" ] || fail "Could not generate admin signature"

# Inject OTP + secrets into config (contracts deployed fresh by wizard)
SUBMIT_JSON=$(jq \
    --arg otp "$OTP_CODE" \
    --arg deployer_key "$DEPLOYER_KEY" \
    --arg admin_wallet "$ADMIN_WALLET" \
    --arg admin_sig "$ADMIN_SIGNATURE" \
    '. + {
        otp: $otp,
        admin_wallet: $admin_wallet,
        admin_signature: $admin_sig
    } | .blockchain += {
        deployer_key: $deployer_key
    }' "$CONFIG_FILE")

RESPONSE=$(curl -s -w "\n%{http_code}" \
    -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    -X POST "http://${VM_IP}/api/setup-test" \
    -H "Content-Type: application/json" \
    -d "$SUBMIT_JSON")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "404" ]; then
    fail "API returned 404 — ISO was not built with --testing flag"
fi

if [ "$HTTP_CODE" != "200" ]; then
    ERROR=$(echo "$BODY" | jq -r '.error // .message // "unknown error"' 2>/dev/null || echo "$BODY")
    fail "API returned $HTTP_CODE: $ERROR"
fi

STATUS=$(echo "$BODY" | jq -r '.status')
pass "Wizard submitted (status: $STATUS)"

# =============================================================================
# Phase 7 — Poll finalization until complete
# =============================================================================
info "Phase 7: Polling finalization (timeout: ${FINALIZE_TIMEOUT}s)"

ELAPSED=0
while [ "$ELAPSED" -lt "$FINALIZE_TIMEOUT" ]; do
    POLL=$(curl -s \
        -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
        "http://${VM_IP}/api/finalize/status" 2>/dev/null || echo '{}')

    STATUS=$(echo "$POLL" | jq -r '.status // "unknown"')
    STEP=$(echo "$POLL" | jq -r '.current_step // "none"')
    PROGRESS=$(echo "$POLL" | jq -r '.progress // 0')

    case "$STATUS" in
        completed)
            break
            ;;
        failed)
            ERROR=$(echo "$POLL" | jq -r '.error // "unknown"')
            FAILED_STEP=$(echo "$POLL" | jq -r '.failed_step // "unknown"')
            fail "Finalization failed at step '$FAILED_STEP': $ERROR"
            ;;
        *)
            wait_ "Finalization: ${PROGRESS}% (step: $STEP, ${ELAPSED}s / ${FINALIZE_TIMEOUT}s)"
            ;;
    esac

    sleep "$POLL_INTERVAL"
    ELAPSED=$(( ELAPSED + POLL_INTERVAL ))
done

if [ "$STATUS" != "completed" ]; then
    fail "Finalization did not complete within ${FINALIZE_TIMEOUT}s (status: $STATUS, step: $STEP)"
fi

pass "Finalization complete ($(elapsed))"

# =============================================================================
# Phase 8 — Read deployed contract addresses from VM
# =============================================================================
info "Phase 8: Reading deployed contract addresses"

NFT_CONTRACT=$(sshpass -p "$SSH_PASS" ssh $SSH_OPTS "root@${VM_IP}" \
    "python3 -c \"import yaml; c=yaml.safe_load(open('/etc/blockhost/web3-defaults.yaml')); print(c['blockchain']['nft_contract'])\"")
[ -n "$NFT_CONTRACT" ] && [ "$NFT_CONTRACT" != "None" ] || fail "Could not read NFT contract address from VM"
pass "NFT contract: $NFT_CONTRACT"

# =============================================================================
# Output — VM details for subsequent CI jobs
# =============================================================================
echo ""
echo "=== PROVISION COMPLETE ($(elapsed)) ==="
echo ""
echo "VM_NAME=$VM_NAME"
echo "VM_IP=$VM_IP"
echo "VM_MAC=$MAC"
echo "NFT_CONTRACT=$NFT_CONTRACT"
echo ""

# Write outputs for GitHub Actions
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "vm_name=$VM_NAME" >> "$GITHUB_OUTPUT"
    echo "vm_ip=$VM_IP" >> "$GITHUB_OUTPUT"
    echo "nft_contract=$NFT_CONTRACT" >> "$GITHUB_OUTPUT"
fi
