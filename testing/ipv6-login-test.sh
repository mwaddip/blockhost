#!/usr/bin/env bash
# =============================================================================
# BlockHost IPv6 Connectivity + PAM Web3 Login Test
#
# Tests external IPv6 connectivity and full PAM web3 SSH login from an
# ADB-connected Android phone with carrier IPv6. Proves that a real
# subscriber on the internet can reach and authenticate to their VM.
#
# Prerequisites:
#   - ADB-connected Android phone with carrier IPv6 (ssh, ping6, nc)
#   - Developer machine with: adb, cast (foundry), python3, jq
#   - SSH access to Proxmox host (testing/blockhost-test-key)
#   - Provisioned VM with PAM web3 auth + IPv6 (from integration test)
#   - Test wallet private key that owns the NFT (from integration test)
#
# Usage:
#   ./testing/ipv6-login-test.sh --host <proxmox-ip> --private-key <0x...>
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SSH_KEY="${SCRIPT_DIR}/blockhost-test-key"

# Defaults
HOST=""
PRIVATE_KEY=""
VM_IPV6=""
VM_NAME=""
SKIP_HTTP=false
START_TIME=$(date +%s)

# ---------------------------------------------------------------------------
# Output helpers (matching integration-test.sh style)
# ---------------------------------------------------------------------------
pass()  { echo "[PASS] $*"; }
fail()  { echo "[FAIL] $*" >&2; exit 1; }
info()  { echo "[INFO] $*"; }

elapsed() {
    local now
    now=$(date +%s)
    local secs=$(( now - START_TIME ))
    printf "%dm %02ds" $(( secs / 60 )) $(( secs % 60 ))
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --host)       HOST="$2"; shift 2 ;;
        --private-key) PRIVATE_KEY="$2"; shift 2 ;;
        --ipv6)       VM_IPV6="$2"; shift 2 ;;
        --vm-name)    VM_NAME="$2"; shift 2 ;;
        --skip-http)  SKIP_HTTP=true; shift ;;
        --help|-h)
            echo "Usage: $0 --host <proxmox-ip> --private-key <0x...> [--ipv6 <addr> --vm-name <name>] [--skip-http]"
            echo ""
            echo "Options:"
            echo "  --host         Proxmox host IP (SSH access required, unless --ipv6/--vm-name given)"
            echo "  --private-key  Test wallet private key (must own NFT on the VM)"
            echo "  --ipv6         VM IPv6 address (skip Proxmox SSH lookup)"
            echo "  --vm-name      VM name (skip Proxmox SSH lookup)"
            echo "  --skip-http    Skip signing page HTTP check"
            exit 0
            ;;
        *) fail "Unknown argument: $1" ;;
    esac
done

[ -n "$PRIVATE_KEY" ] || fail "Missing --private-key <0x...>"

# If IPv6 and vm-name provided directly, skip Proxmox SSH entirely
if [ -n "$VM_IPV6" ] && [ -n "$VM_NAME" ]; then
    DIRECT_MODE=true
else
    DIRECT_MODE=false
    [ -n "$HOST" ] || fail "Missing --host <proxmox-ip> (or provide --ipv6 and --vm-name)"
fi

PX_SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $SSH_KEY root@$HOST"

# =============================================================================
# Phase 1 — Pre-flight checks
# =============================================================================
info "Phase 1: Pre-flight checks"

# ADB device
adb devices 2>/dev/null | grep -qw "device" || fail "No ADB device connected"

# Phone tools
adb shell "command -v ssh && command -v ping6 && command -v nc" > /dev/null 2>&1 \
    || fail "Phone missing required tools (ssh, ping6, nc)"

# Local tools
command -v cast   > /dev/null 2>&1 || fail "cast (foundry) not found"
command -v python3 > /dev/null 2>&1 || fail "python3 not found"
command -v jq     > /dev/null 2>&1 || fail "jq not found"
[ -f "$SSH_KEY" ] || fail "SSH key not found: $SSH_KEY"

# Derive wallet address
WALLET_ADDR=$(cast wallet address --private-key "$PRIVATE_KEY" 2>/dev/null) \
    || fail "Invalid private key"
WALLET_SHORT="${WALLET_ADDR:0:6}...${WALLET_ADDR: -4}"
info "Test wallet: $WALLET_SHORT"

if [ "$DIRECT_MODE" = true ]; then
    pass "Pre-flight: VM $VM_NAME at $VM_IPV6 (direct mode)"
else
    # SSH to Proxmox
    $PX_SSH "hostname" > /dev/null 2>&1 || fail "Cannot SSH to Proxmox host at $HOST"

    # Read VM data and find matching VM
    VM_JSON=$($PX_SSH "cat /var/lib/blockhost/vms.json" 2>/dev/null) \
        || fail "Cannot read vms.json from Proxmox host"

    VM_ENTRY=$(echo "$VM_JSON" | jq -r --arg addr "$WALLET_ADDR" \
        '[.vms | to_entries[] | select(.value.status == "active") |
         select((.value.wallet_address | ascii_downcase) == ($addr | ascii_downcase)) |
         .value] | first' 2>/dev/null)

    [ -n "$VM_ENTRY" ] && [ "$VM_ENTRY" != "null" ] \
        || fail "No active VM found for wallet $WALLET_SHORT"

    VM_IPV6=$(echo "$VM_ENTRY" | jq -r '.ipv6_address')
    VM_NAME=$(echo "$VM_ENTRY" | jq -r '.vm_name')
    VMID=$(echo "$VM_ENTRY" | jq -r '.vmid')

    [ -n "$VM_IPV6" ] && [ "$VM_IPV6" != "null" ] \
        || fail "VM $VM_NAME has no IPv6 address"

    pass "Pre-flight: VM $VM_NAME (VMID $VMID) at $VM_IPV6"
fi

# =============================================================================
# Phase 2 — IPv6 ping from phone
# =============================================================================
info "Phase 2: IPv6 ping from phone"

PING_OUT=$(adb shell "ping6 -c 3 -W 5 $VM_IPV6" 2>&1) || true
PING_RX=$(echo "$PING_OUT" | grep -oP '\d+ received' | grep -oP '\d+' || echo "0")

if [ "$PING_RX" -gt 0 ] 2>/dev/null; then
    pass "IPv6 ping: ${PING_RX}/3 packets received"
else
    echo "$PING_OUT" >&2
    fail "IPv6 ping to $VM_IPV6 failed (0 packets received)"
fi

# =============================================================================
# Phase 3 — SSH port check from phone
# =============================================================================
info "Phase 3: SSH port check from phone"

adb shell "nc -z -w 5 $VM_IPV6 22" > /dev/null 2>&1 \
    || fail "SSH port 22 not reachable at $VM_IPV6 from phone"

pass "Port 22: reachable from external IPv6"

# =============================================================================
# Phase 4 — PAM web3 SSH login from phone
# =============================================================================
info "Phase 4: PAM web3 SSH login from phone"

LOGIN_RESULT=$(VM_IPV6="$VM_IPV6" PRIVATE_KEY="$PRIVATE_KEY" VM_NAME="$VM_NAME" \
    python3 << 'PYTHON_EOF'
import os
import re
import select
import subprocess
import sys
import time

VM_IPV6 = os.environ["VM_IPV6"]
PRIVATE_KEY = os.environ["PRIVATE_KEY"]
VM_NAME = os.environ["VM_NAME"]

TIMEOUT = 30
READ_CHUNK = 4096


def read_until(fd, pattern, timeout):
    """Read from fd until regex pattern matches or timeout."""
    buf = b""
    deadline = time.monotonic() + timeout
    compiled = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)

    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select([fd], [], [], min(remaining, 0.5))
        if ready:
            try:
                chunk = os.read(fd, READ_CHUNK)
                if not chunk:
                    break
                buf += chunk
                if compiled.search(buf):
                    return buf.decode("utf-8", errors="replace"), True
            except OSError:
                break

    return buf.decode("utf-8", errors="replace"), False


def main():
    master_fd, slave_fd = os.openpty()

    cmd = [
        "adb", "shell", "-tt",
        "ssh", "-tt",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        f"admin@{VM_IPV6}",
    ]

    proc = subprocess.Popen(
        cmd,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
    )
    os.close(slave_fd)

    try:
        # Wait for PAM signature prompt
        output, found = read_until(master_fd, r"Paste signature:", TIMEOUT)

        if not found:
            print(f"FAIL:Never got signature prompt. Output: {output[:500]}", file=sys.stderr)
            sys.exit(1)

        # Extract OTP code
        otp_match = re.search(r"Code:\s*(\S+)", output)
        if not otp_match:
            print(f"FAIL:Could not extract OTP. Output: {output[:500]}", file=sys.stderr)
            sys.exit(1)

        otp_code = otp_match.group(1)

        # Verify machine ID
        machine_match = re.search(r"Machine:\s*(\S+)", output)
        if machine_match and machine_match.group(1) != VM_NAME:
            print(
                f"WARN:Machine ID mismatch: got '{machine_match.group(1)}', "
                f"expected '{VM_NAME}'",
                file=sys.stderr,
            )

        # Sign the authentication message
        message = f"Authenticate to {VM_NAME} with code: {otp_code}"

        sign_result = subprocess.run(
            ["cast", "wallet", "sign", message, "--private-key", PRIVATE_KEY],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if sign_result.returncode != 0:
            print(f"FAIL:cast wallet sign failed: {sign_result.stderr}", file=sys.stderr)
            sys.exit(1)

        signature = sign_result.stdout.strip()

        if not re.match(r"^0x[0-9a-fA-F]{130}$", signature):
            print(f"FAIL:Invalid signature format: {signature[:20]}...", file=sys.stderr)
            sys.exit(1)

        # Feed signature into PTY
        os.write(master_fd, (signature + "\n").encode())

        # Wait for auth to complete and shell to appear
        time.sleep(3)

        # Verify shell access
        os.write(master_fd, b"whoami\n")
        whoami_output, found = read_until(master_fd, r"admin", 10)

        if "admin" in whoami_output:
            print("LOGIN_SUCCESS")
            os.write(master_fd, b"exit\n")
            time.sleep(0.5)
        else:
            # Check for auth failure indicators
            if "Permission denied" in whoami_output or "Authentication failed" in whoami_output:
                print(f"FAIL:Authentication rejected. Output: {whoami_output[:500]}", file=sys.stderr)
            else:
                print(f"FAIL:Shell verify failed. Output: {whoami_output[:500]}", file=sys.stderr)
            sys.exit(1)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        os.close(master_fd)


if __name__ == "__main__":
    main()
PYTHON_EOF
) || true

if echo "$LOGIN_RESULT" | grep -q "LOGIN_SUCCESS"; then
    pass "PAM web3 login: authenticated as admin via IPv6"
else
    # Extract failure reason from stderr captured in LOGIN_RESULT
    FAIL_MSG=$(echo "$LOGIN_RESULT" | grep "FAIL:" | head -1 | sed 's/^FAIL://')
    fail "PAM web3 login failed: ${FAIL_MSG:-unknown error}"
fi

# =============================================================================
# Phase 5 — Signing page accessibility (optional)
# =============================================================================
if [ "$SKIP_HTTP" = false ]; then
    info "Phase 5: Signing page accessibility from phone"

    HTTP_CODE=$(adb shell "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 'http://[$VM_IPV6]:8080/'" 2>/dev/null || echo "000")
    # Strip any whitespace/carriage returns from adb output
    HTTP_CODE=$(echo "$HTTP_CODE" | tr -d '[:space:]')

    if [ "$HTTP_CODE" = "200" ]; then
        pass "Signing page: HTTP 200 at http://[$VM_IPV6]:8080/"
    else
        info "Signing page: HTTP $HTTP_CODE (non-fatal, may not be running)"
    fi
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "=== ALL TESTS PASSED ($(elapsed)) ==="
