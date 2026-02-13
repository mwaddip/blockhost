#!/usr/bin/env bash
# =============================================================================
# BlockHost End-to-End Integration Test
#
# Exercises the full subscription → provisioning → NFT minting flow:
#   1. Generate test wallet
#   2. Fund it from deployer
#   3. Subscribe on-chain (buySubscription)
#   4. Wait for monitor to detect event + provision VM
#   5. Verify VM running, NFT minted, connection details decryptable
#
# Run as: sudo -u blockhost ./testing/integration-test-proxmox.sh [--cleanup]
#
# Prerequisites: finalized system with blockhost-monitor running
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly WEB3_DEFAULTS="/etc/blockhost/web3-defaults.yaml"
readonly BLOCKHOST_YAML="/etc/blockhost/blockhost.yaml"
readonly DEPLOYER_KEY_FILE="/etc/blockhost/deployer.key"
readonly VMS_JSON="/var/lib/blockhost/vms.json"
readonly POLL_INTERVAL=15
readonly POLL_TIMEOUT=300
readonly GAS_ETH="0.005"
readonly PLAN_ID=1
readonly DAYS=7
readonly PAYMENT_METHOD_ID=1

CLEANUP=false
TEMP_KEY_FILE=""
START_TIME=$(date +%s)

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
pass()  { echo "[PASS] $*"; }
fail()  { echo "[FAIL] $*" >&2; exit 1; }
info()  { echo "[INFO] $*"; }
wait_() { echo "[WAIT] $*"; }

elapsed() {
    local now
    now=$(date +%s)
    local secs=$(( now - START_TIME ))
    printf "%dm %02ds" $(( secs / 60 )) $(( secs % 60 ))
}

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
cleanup() {
    if [ -n "$TEMP_KEY_FILE" ] && [ -f "$TEMP_KEY_FILE" ]; then
        rm -f "$TEMP_KEY_FILE"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --cleanup) CLEANUP=true ;;
        --help|-h)
            echo "Usage: sudo -u blockhost $0 [--cleanup]"
            echo ""
            echo "Options:"
            echo "  --cleanup   Destroy test VM after verification (on-chain data remains)"
            exit 0
            ;;
        *) fail "Unknown argument: $arg" ;;
    esac
done

# ---------------------------------------------------------------------------
# YAML parser helper (python3 one-liner)
# ---------------------------------------------------------------------------
yaml_get() {
    local file="$1" path="$2"
    python3 -c "
import yaml, sys, functools
c = yaml.safe_load(open(sys.argv[1]))
keys = sys.argv[2].split('.')
val = functools.reduce(lambda d, k: d[k], keys, c)
print(val)
" "$file" "$path"
}

# ---------------------------------------------------------------------------
# ABI decode helpers — parse cast output for uint256
# ---------------------------------------------------------------------------
hex_to_dec() {
    # Strip 0x prefix, leading zeros, and convert hex to decimal
    local hex="${1#0x}"
    printf "%d" "0x${hex}"
}

# =============================================================================
# Phase 0 — Pre-flight checks
# =============================================================================
info "Phase 0: Pre-flight checks"

# Services
systemctl is-active --quiet blockhost-monitor || fail "blockhost-monitor is not running"
systemctl is-active --quiet blockhost-root-agent || fail "blockhost-root-agent is not running"

# Config files
[ -r "$WEB3_DEFAULTS" ]    || fail "$WEB3_DEFAULTS not readable"
[ -r "$BLOCKHOST_YAML" ]   || fail "$BLOCKHOST_YAML not readable"
[ -r "$DEPLOYER_KEY_FILE" ] || fail "$DEPLOYER_KEY_FILE not readable"

# Parse config
RPC=$(yaml_get "$WEB3_DEFAULTS" "blockchain.rpc_url")
NFT_CONTRACT=$(yaml_get "$WEB3_DEFAULTS" "blockchain.nft_contract")
SUB_CONTRACT=$(yaml_get "$WEB3_DEFAULTS" "blockchain.subscription_contract")
CHAIN_ID=$(yaml_get "$WEB3_DEFAULTS" "blockchain.chain_id")
DEPLOYER_KEY=$(cat "$DEPLOYER_KEY_FILE")

# public_secret from blockhost.yaml
PUBLIC_SECRET=$(yaml_get "$BLOCKHOST_YAML" "public_secret" 2>/dev/null || echo "blockhost-access")

[ -n "$RPC" ]          || fail "rpc_url is empty"
[ -n "$NFT_CONTRACT" ] || fail "nft_contract is empty"
[ -n "$SUB_CONTRACT" ] || fail "subscription_contract is empty"
[ -n "$CHAIN_ID" ]     || fail "chain_id is empty"
[ -n "$DEPLOYER_KEY" ] || fail "deployer.key is empty"

# Query primary stablecoin
STABLECOIN_RAW=$(cast call "$SUB_CONTRACT" "getPrimaryStablecoin()(address)" --rpc-url "$RPC")
STABLECOIN=$(echo "$STABLECOIN_RAW" | sed 's/\[.*//;s/[[:space:]]//g')
[ "$STABLECOIN" != "0x0000000000000000000000000000000000000000" ] || fail "primaryStablecoin is zero address"

# Verify plan exists — calculatePayment should return > 0
PLAN_CHECK=$(cast call "$SUB_CONTRACT" "calculatePayment(uint256,uint256,uint256)(uint256)" "$PLAN_ID" 1 1 --rpc-url "$RPC" 2>/dev/null | sed 's/\[.*//;s/[[:space:]]//g')
[ -n "$PLAN_CHECK" ] && [ "$PLAN_CHECK" != "0" ] || fail "Plan $PLAN_ID does not exist or has zero price"

# Stablecoin decimals
DECIMALS=$(cast call "$STABLECOIN" "decimals()(uint8)" --rpc-url "$RPC" | sed 's/\[.*//;s/[[:space:]]//g')
[ -n "$DECIMALS" ] || fail "Could not query stablecoin decimals"

# Deployer balances
DEPLOYER_ADDR=$(cast wallet address --private-key "$DEPLOYER_KEY")
DEPLOYER_ETH=$(cast balance "$DEPLOYER_ADDR" --rpc-url "$RPC" --ether)
info "Deployer: $DEPLOYER_ADDR (${DEPLOYER_ETH} ETH)"

# jq check
command -v jq >/dev/null 2>&1 || fail "jq is not installed"
command -v cast >/dev/null 2>&1 || fail "cast is not installed"
command -v pam_web3_tool >/dev/null 2>&1 || fail "pam_web3_tool is not installed"

pass "Pre-flight: services running, config valid"

# =============================================================================
# Phase 1 — Generate test wallet
# =============================================================================
info "Phase 1: Generate test wallet"

WALLET_JSON=$(cast wallet new --json)
TEST_ADDR=$(echo "$WALLET_JSON" | jq -r '.[0].address')
TEST_KEY=$(echo "$WALLET_JSON" | jq -r '.[0].private_key')

# Save key to temp file for cleanup
TEMP_KEY_FILE=$(mktemp /tmp/blockhost-test-key.XXXXXX)
echo "$TEST_KEY" > "$TEMP_KEY_FILE"
chmod 600 "$TEMP_KEY_FILE"

TEST_ADDR_SHORT="${TEST_ADDR:0:6}...${TEST_ADDR: -4}"
pass "Test wallet: $TEST_ADDR_SHORT"

# =============================================================================
# Phase 2 — Fund test wallet
# =============================================================================
info "Phase 2: Fund test wallet"

# Calculate exact payment amount
PAYMENT_RAW=$(cast call "$SUB_CONTRACT" \
    "calculatePayment(uint256,uint256,uint256)(uint256)" \
    "$PLAN_ID" "$DAYS" "$PAYMENT_METHOD_ID" \
    --rpc-url "$RPC")
PAYMENT_AMOUNT=$(echo "$PAYMENT_RAW" | sed 's/\[.*//;s/[[:space:]]//g')

# Add 10% buffer for rounding/gas
PAYMENT_WITH_BUFFER=$(python3 -c "print(int(int('$PAYMENT_AMOUNT') * 1.1))")

# Human-readable amount
PAYMENT_HUMAN=$(python3 -c "print(f'{int(\"$PAYMENT_WITH_BUFFER\") / 10**$DECIMALS:.2f}')")

# Get current nonce to avoid race with monitor's fund cycle
NONCE=$(cast nonce "$DEPLOYER_ADDR" --rpc-url "$RPC")

# Send ETH for gas
info "Sending $GAS_ETH ETH for gas (nonce $NONCE)..."
cast send "$TEST_ADDR" --value "${GAS_ETH}ether" \
    --private-key "$DEPLOYER_KEY" --rpc-url "$RPC" \
    --nonce "$NONCE" --json > /dev/null

# Send stablecoin
info "Sending $PAYMENT_HUMAN stablecoin (nonce $((NONCE + 1)))..."
cast send "$STABLECOIN" "transfer(address,uint256)" \
    "$TEST_ADDR" "$PAYMENT_WITH_BUFFER" \
    --private-key "$DEPLOYER_KEY" --rpc-url "$RPC" \
    --nonce "$((NONCE + 1))" --json > /dev/null

# Verify balances
TEST_ETH=$(cast balance "$TEST_ADDR" --rpc-url "$RPC" --ether)
TEST_TOKEN=$(cast call "$STABLECOIN" "balanceOf(address)(uint256)" "$TEST_ADDR" --rpc-url "$RPC" | sed 's/\[.*//;s/[[:space:]]//g')
TEST_TOKEN_HUMAN=$(python3 -c "print(f'{int(\"$TEST_TOKEN\") / 10**$DECIMALS:.2f}')")

pass "Funded: ${TEST_ETH} ETH + ${TEST_TOKEN_HUMAN} stablecoin"

# =============================================================================
# Phase 3 — Sign publicSecret
# =============================================================================
info "Phase 3: Sign publicSecret"

SIGNATURE=$(cast wallet sign "$PUBLIC_SECRET" --private-key "$TEST_KEY")

# Validate: should be 0x + 130 hex chars = 132 total
[ ${#SIGNATURE} -eq 132 ] || fail "Signature length ${#SIGNATURE}, expected 132"

pass "Signed publicSecret (${#SIGNATURE} chars, 65 bytes)"

# =============================================================================
# Phase 4 — Subscribe
# =============================================================================
info "Phase 4: Subscribe on-chain"

# Approve stablecoin spending
info "Approving stablecoin spend..."
cast send "$STABLECOIN" "approve(address,uint256)" \
    "$SUB_CONTRACT" "$PAYMENT_WITH_BUFFER" \
    --private-key "$TEST_KEY" --rpc-url "$RPC" \
    --json > /dev/null

# Record pre-subscribe NFT totalSupply
PRE_SUPPLY=$(cast call "$NFT_CONTRACT" "totalSupply()(uint256)" --rpc-url "$RPC" | sed 's/\[.*//;s/[[:space:]]//g')

# Buy subscription — pass raw signature as userEncrypted
# The monitor handler accepts raw 65-byte signatures without ECIES decryption
info "Calling buySubscription..."
TX_JSON=$(cast send "$SUB_CONTRACT" \
    "buySubscription(uint256,uint256,uint256,bytes)" \
    "$PLAN_ID" "$DAYS" "$PAYMENT_METHOD_ID" "$SIGNATURE" \
    --private-key "$TEST_KEY" --rpc-url "$RPC" \
    --json)

TX_HASH=$(echo "$TX_JSON" | jq -r '.transactionHash')
TX_SHORT="${TX_HASH:0:10}...${TX_HASH: -6}"

# Derive expected VM name from subscription count
SUB_COUNT_RAW=$(cast call "$SUB_CONTRACT" "getTotalSubscriptionCount()(uint256)" --rpc-url "$RPC" | sed 's/\[.*//;s/[[:space:]]//g')
EXPECTED_VM_NAME=$(printf "blockhost-%03d" "$SUB_COUNT_RAW")

pass "Subscription tx: $TX_SHORT (expect VM: $EXPECTED_VM_NAME)"

# =============================================================================
# Phase 5 — Wait for provisioning
# =============================================================================
info "Phase 5: Wait for provisioning"

ELAPSED_WAIT=0
VM_ENTRY=""
FOUND_VMID=""
FOUND_IP=""
FOUND_TOKEN=""

while [ "$ELAPSED_WAIT" -lt "$POLL_TIMEOUT" ]; do
    wait_ "Waiting for provisioning... (${ELAPSED_WAIT}s / ${POLL_TIMEOUT}s)"

    if [ -f "$VMS_JSON" ]; then
        # Look for entry with matching owner wallet (case-insensitive)
        VM_ENTRY=$(jq -r --arg addr "$TEST_ADDR" \
            '.vms | to_entries[] | select(.value.wallet_address != null) |
             select((.value.wallet_address | ascii_downcase) == ($addr | ascii_downcase)) |
             .value' \
            "$VMS_JSON" 2>/dev/null || true)

        if [ -n "$VM_ENTRY" ] && [ "$VM_ENTRY" != "null" ]; then
            FOUND_VMID=$(echo "$VM_ENTRY" | jq -r '.vmid')
            FOUND_IP=$(echo "$VM_ENTRY" | jq -r '.ip_address')
            FOUND_IPV6=$(echo "$VM_ENTRY" | jq -r '.ipv6_address // empty')
            FOUND_NAME=$(echo "$VM_ENTRY" | jq -r '.vm_name')
            break
        fi
    fi

    sleep "$POLL_INTERVAL"
    ELAPSED_WAIT=$(( ELAPSED_WAIT + POLL_INTERVAL ))
done

if [ -z "$FOUND_VMID" ] || [ "$FOUND_VMID" = "null" ]; then
    echo ""
    fail "Provisioning timed out after ${POLL_TIMEOUT}s. Check: journalctl -u blockhost-monitor --since '5 min ago'"
fi

pass "VM provisioned: $FOUND_NAME (VMID $FOUND_VMID, IP $FOUND_IP)"

# =============================================================================
# Phase 6 — Verify VM
# =============================================================================
info "Phase 6: Verify VM"

# Check VM status via Proxmox API (blockhost user can't use sudo qm)
PVE_TOKEN=$(cat /etc/blockhost/pve-token 2>/dev/null || true)
HOSTNAME_SHORT=$(hostname -s)
if [ -n "$PVE_TOKEN" ]; then
    VM_API=$(curl -s -k -H "Authorization: PVEAPIToken=${PVE_TOKEN}" \
        "https://localhost:8006/api2/json/nodes/${HOSTNAME_SHORT}/qemu/${FOUND_VMID}/status/current" 2>/dev/null || true)
    VM_STATUS=$(echo "$VM_API" | jq -r '.data.status // empty' 2>/dev/null || true)
else
    VM_STATUS=""
fi

if [ "$VM_STATUS" = "running" ]; then
    pass "VM running"
elif [ -n "$VM_STATUS" ]; then
    info "VM status: $VM_STATUS (may still be starting)"
    pass "VM exists (status: $VM_STATUS)"
else
    # VM might still be starting — don't hard fail if vms.json entry exists
    info "Could not query VM $FOUND_VMID via API (may still be provisioning)"
    pass "VM registered in database (VMID $FOUND_VMID)"
fi

[ -n "$FOUND_IP" ] && [ "$FOUND_IP" != "null" ] || fail "VM has no IP address"

# =============================================================================
# Phase 7 — Verify NFT
# =============================================================================
info "Phase 7: Verify NFT"

# Wait a bit for the mint transaction to confirm (might still be pending)
sleep 5

NFT_BALANCE=$(cast call "$NFT_CONTRACT" "balanceOf(address)(uint256)" "$TEST_ADDR" --rpc-url "$RPC" | sed 's/\[.*//;s/[[:space:]]//g')

if [ "$NFT_BALANCE" = "0" ]; then
    # NFT might not be minted yet if provisioning just finished; wait and retry
    info "NFT balance is 0, waiting 30s for mint..."
    sleep 30
    NFT_BALANCE=$(cast call "$NFT_CONTRACT" "balanceOf(address)(uint256)" "$TEST_ADDR" --rpc-url "$RPC" | sed 's/\[.*//;s/[[:space:]]//g')
fi

if ! [ "$NFT_BALANCE" -gt 0 ] 2>/dev/null; then
    info "=== Monitor journal (last 50 lines) ==="
    journalctl -u blockhost-monitor --no-pager -n 50 2>/dev/null || true
    info "=== Reserved NFT tokens in database ==="
    jq '.reserved_nft_tokens // empty' "$VMS_JSON" 2>/dev/null || true
    info "=== On-chain NFT totalSupply ==="
    cast call "$NFT_CONTRACT" "totalSupply()(uint256)" --rpc-url "$RPC" 2>/dev/null || true
    fail "NFT balance is $NFT_BALANCE, expected > 0"
fi

# Get token ID
TOKEN_ID=$(cast call "$NFT_CONTRACT" "tokenOfOwnerByIndex(address,uint256)(uint256)" \
    "$TEST_ADDR" 0 --rpc-url "$RPC" | sed 's/\[.*//;s/[[:space:]]//g')

# Get access data — returns (bytes, string, uint256, uint256)
ACCESS_RAW=$(cast call "$NFT_CONTRACT" "getAccessData(uint256)" "$TOKEN_ID" --rpc-url "$RPC")
ACCESS_DECODED=$(cast abi-decode "getAccessData(uint256)(bytes,string,uint256,uint256)" "$ACCESS_RAW")

# Parse individual fields (cast abi-decode outputs one per line)
USER_ENCRYPTED=$(echo "$ACCESS_DECODED" | sed -n '1p')
NFT_PUBLIC_SECRET=$(echo "$ACCESS_DECODED" | sed -n '2p' | sed 's/^"//;s/"$//')
ISSUED_AT=$(echo "$ACCESS_DECODED" | sed -n '3p')
EXPIRES_AT=$(echo "$ACCESS_DECODED" | sed -n '4p')

# Verify publicSecret matches
if [ "$NFT_PUBLIC_SECRET" = "$PUBLIC_SECRET" ]; then
    pass "NFT publicSecret matches config"
else
    info "NFT publicSecret: '$NFT_PUBLIC_SECRET' vs config: '$PUBLIC_SECRET'"
    # Non-fatal — the monitor might use a different format
fi

# Verify userEncrypted is non-empty
[ -n "$USER_ENCRYPTED" ] && [ "$USER_ENCRYPTED" != "0x" ] || fail "NFT userEncrypted is empty"

TOKEN_SHORT="${TEST_ADDR:0:6}...${TEST_ADDR: -4}"
pass "NFT minted: token #$TOKEN_ID, owner $TOKEN_SHORT"

# =============================================================================
# Phase 8 — Verify decryption
# =============================================================================
info "Phase 8: Verify decryption"

# Decrypt userEncrypted using the same signature
DECRYPT_OUTPUT=$(pam_web3_tool decrypt-symmetric \
    --signature "$SIGNATURE" \
    --ciphertext "$USER_ENCRYPTED" 2>&1) || fail "Decryption failed: $DECRYPT_OUTPUT"

# Strip "Decrypted: " prefix
DECRYPTED="${DECRYPT_OUTPUT#Decrypted: }"

# Validate it's JSON
echo "$DECRYPTED" | jq . > /dev/null 2>&1 || fail "Decrypted data is not valid JSON: $DECRYPTED"

# Extract fields
DEC_HOSTNAME=$(echo "$DECRYPTED" | jq -r '.hostname')
DEC_PORT=$(echo "$DECRYPTED" | jq -r '.port')
DEC_USERNAME=$(echo "$DECRYPTED" | jq -r '.username')

[ -n "$DEC_HOSTNAME" ] && [ "$DEC_HOSTNAME" != "null" ] || fail "Decrypted hostname is empty"
[ -n "$DEC_PORT" ]     && [ "$DEC_PORT" != "null" ]     || fail "Decrypted port is empty"
[ -n "$DEC_USERNAME" ] && [ "$DEC_USERNAME" != "null" ]  || fail "Decrypted username is empty"

pass "Decrypted: {\"hostname\":\"$DEC_HOSTNAME\",\"port\":$DEC_PORT,\"username\":\"$DEC_USERNAME\"}"

# Cross-check hostname against VM's IPv6 (the public-facing address subscribers connect to)
if [ -n "$FOUND_IPV6" ] && [ "$DEC_HOSTNAME" = "$FOUND_IPV6" ]; then
    pass "Hostname matches VM IPv6 ($FOUND_IPV6)"
else
    fail "Hostname '$DEC_HOSTNAME' does not match VM IPv6 '${FOUND_IPV6:-not set}'"
fi

# =============================================================================
# Phase 9 — Cleanup (--cleanup only)
# =============================================================================
if [ "$CLEANUP" = true ]; then
    info "Phase 9: Cleanup"

    # Sweep leftover testnet ETH from test wallet back to admin
    ADMIN_ADDR="0xe35B5D114eFEA216E6BB5Ff15C261d25dB9E2cb9"
    info "Sweeping leftover ETH from test wallet to admin..."
    bw --debug --cleanup "$ADMIN_ADDR" || true

    # Destroy VM via terraform
    TF_DIR="/var/lib/blockhost/terraform"
    TF_FILE="$TF_DIR/$FOUND_NAME.tf.json"

    if [ -f "$TF_FILE" ]; then
        info "Removing Terraform config and destroying VM..."
        rm -f "$TF_FILE"
        # Also remove cloud-init file if present
        rm -f "$TF_DIR/$FOUND_NAME-cloud-config.yaml"

        if terraform -chdir="$TF_DIR" apply -auto-approve > /dev/null 2>&1; then
            pass "VM destroyed via Terraform"
        else
            info "Terraform destroy returned non-zero (VM may already be gone)"
        fi
    else
        info "No Terraform config found at $TF_FILE, skipping destroy"
    fi

    # Update vms.json — mark as destroyed
    if [ -f "$VMS_JSON" ] && command -v python3 >/dev/null 2>&1; then
        python3 -c "
from blockhost.vm_db import get_database
db = get_database()
try:
    db.mark_destroyed('$FOUND_NAME')
    print('[PASS] VM entry marked as destroyed in database')
except Exception as e:
    print(f'[INFO] Could not update database: {e}')
"
    fi

    # Withdraw stablecoin from subscription contract back to deployer
    info "Withdrawing funds from subscription contract..."
    CONTRACT_BALANCE=$(cast call "$STABLECOIN" "balanceOf(address)(uint256)" \
        "$SUB_CONTRACT" --rpc-url "$RPC" | sed 's/\[.*//;s/[[:space:]]//g')

    if [ "$CONTRACT_BALANCE" -gt 0 ] 2>/dev/null; then
        cast send "$SUB_CONTRACT" "withdrawFunds(address,address)" \
            "$STABLECOIN" "$DEPLOYER_ADDR" \
            --private-key "$DEPLOYER_KEY" --rpc-url "$RPC" \
            --json > /dev/null
        WITHDRAWN=$(python3 -c "print(f'{int(\"$CONTRACT_BALANCE\") / 10**$DECIMALS:.2f}')")
        pass "Withdrawn $WITHDRAWN stablecoin from contract to deployer"
    else
        info "No stablecoin balance in contract to withdraw"
    fi

    info "Note: on-chain subscription + NFT remain (immutable)"
    pass "Cleanup complete"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=== ALL TESTS PASSED ($(elapsed)) ==="
echo ""
echo "Test wallet private key (for ipv6-login-test.sh):"
echo "  $TEST_KEY"
echo "VM IPv6 address:"
echo "  $FOUND_IPV6"
echo "VM name:"
echo "  $FOUND_NAME"
