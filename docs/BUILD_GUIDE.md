# BlockHost Build Guide

**Version**: 0.1.0
**Last Updated**: 2026-02-03
**Base**: Proxmox VE 8.4

---

## Overview

BlockHost adds a first-boot web installer to Proxmox VE. On first boot after installation:
1. Network is configured (DHCP or console wizard)
2. OTP code is displayed on the console
3. Web installer starts for final configuration

---

## Project Structure

```
blockhost/
├── installer/
│   ├── common/           # Shared utilities
│   │   ├── detection.py  # Boot medium detection
│   │   ├── network.py    # Network configuration
│   │   └── otp.py        # OTP authentication
│   ├── console/          # Console (whiptail) fallback
│   │   ├── main.py
│   │   ├── whiptail.py
│   │   └── screens/
│   │       └── network.py
│   └── web/              # Flask web installer
│       ├── app.py
│       └── templates/
├── scripts/
│   ├── first-boot.sh     # Main first-boot script
│   └── build-iso.sh      # ISO builder
├── systemd/
│   └── blockhost-firstboot.service
└── docs/
    └── BUILD_GUIDE.md
```

---

## Prerequisites

```bash
sudo apt install -y \
    xorriso \
    squashfs-tools \
    python3 \
    python3-flask \
    whiptail
```


---

## How It Works

### First-Boot Flow

```
┌─────────────────────────────────────────────────────────┐
│                    first-boot.sh                        │
├─────────────────────────────────────────────────────────┤
│  1. Try DHCP on default interface                       │
│         ↓                                               │
│  2. If DHCP fails → launch console wizard (whiptail)    │
│         ↓                                               │
│  3. Generate OTP → display on TTY1                      │
│         ↓                                               │
│  4. Start Flask web server                              │
│         ↓                                               │
│  5. User completes wizard → creates marker file         │
│         ↓                                               │
│  6. Service won't run on next boot                      │
└─────────────────────────────────────────────────────────┘
```

### Key Files

| File | Purpose |
|------|---------|
| `scripts/first-boot.sh` | Main orchestrator - runs everything |
| `systemd/blockhost-firstboot.service` | Runs first-boot.sh on boot |
| `installer/common/otp.py` | OTP generation (6-char, 4hr timeout) |
| `installer/common/network.py` | DHCP and static IP config |
| `installer/console/main.py` | Whiptail network wizard |
| `installer/web/app.py` | Flask web installer |

---

## Building the ISO

### 1. Download Proxmox VE ISO

```bash
mkdir -p build
cd build
wget https://enterprise.proxmox.com/iso/proxmox-ve_8.4-1.iso
```

### 2. Build Custom ISO

```bash
./scripts/build-iso.sh
```

This:
1. Extracts the Proxmox ISO
2. Copies BlockHost files to `/blockhost/` on the ISO
3. Creates `install-blockhost.sh` hook
4. Rebuilds the ISO

Output: `build/blockhost-pve_0.1.0.iso`

---

## Components

### OTP System

- 6 characters, alphanumeric (no confusing chars like 0/O, 1/I)
- 4-hour timeout
- 10 attempts max before lockout
- Stored in `/run/blockhost/otp.json`

```python
from installer.common.otp import OTPManager
otp = OTPManager()
code = otp.generate()      # "X7KM3P"
otp.verify("X7KM3P")       # (True, "OTP verified")
```

### Network Manager

```python
from installer.common.network import NetworkManager
net = NetworkManager()
net.detect_interfaces()     # List all interfaces
net.run_dhcp("eth0")        # Try DHCP
net.configure_static(...)   # Static IP
net.is_private_ip("10.0.0.1")  # True (determines HTTP vs HTTPS)
```

### Console Wizard

Whiptail-based fallback when DHCP fails:
- Interface selection
- DHCP retry or manual IP entry
- DNS configuration

### Web Installer

Flask app with:
- OTP login
- Network config
- Disk selection
- Package selection
- Installation summary

HTTP for private IPs, HTTPS (self-signed) for public IPs.

---

## Testing

### Test Modules Locally

```bash
# OTP
python3 -c "
from installer.common.otp import OTPManager
import tempfile
from pathlib import Path
otp = OTPManager(state_dir=Path(tempfile.mkdtemp()))
code = otp.generate()
print(f'Code: {code}')
print(otp.verify(code))
"

# Network (list interfaces)
python3 -m installer.common.network interfaces

# Web app (dev server)
python3 -m installer.web.app --port 8080
```

### Test in VM

```bash
sudo virt-install \
    --name blockhost-test \
    --ram 4096 \
    --vcpus 2 \
    --disk size=32 \
    --cdrom build/blockhost-pve_0.1.0.iso \
    --network network=default \
    --graphics vnc
```

---

## Critical Implementation Notes

These issues were discovered during testing and MUST be handled correctly:

### 1. /etc/hosts - Proxmox Hostname Resolution (CRITICAL)

**Problem**: Debian preseed creates `/etc/hosts` with:
```
127.0.1.1    blockhost.local    blockhost
```

This causes `pve-cluster.service` to fail because Proxmox requires the hostname to resolve to the **real IP address**, not a loopback.

**Symptoms**: After reboot, console shows:
```
[FAILED] Failed to start pve-cluster.service - The Proxmox VE cluster filesystem.
[FAILED] Failed to start pvestatd.service - PVE Status Daemon.
[FAILED] Failed to start pve-firewall.service - Proxmox VE firewall.
... (cascade of failures)
```

**Fix in first-boot.sh**:
```bash
# Remove the 127.0.1.1 line that Debian creates
sed -i '/^127\.0\.1\.1/d' /etc/hosts

# Add correct entry with real IP
sed -i "/^127\.0\.0\.1/a ${CURRENT_IP}\t${FQDN}\t${HOSTNAME}" /etc/hosts
```

**Correct /etc/hosts**:
```
127.0.0.1       localhost
192.168.1.100   blockhost.local    blockhost
```

---

### 2. Systemd Service - TTY and Getty Conflict

**Problem**: The service needs tty1 but getty is also trying to use it.

**Symptoms**: Service fails with SIGHUP, or getty doesn't start after setup completes.

**Important**: Do NOT use `Conflicts=getty@tty1.service` in the unit file. When combined
with `ConditionPathExists`, it can prevent getty from starting even when the condition
fails and the service doesn't run.

**Fix**: Handle getty manually in the script:
```bash
# At start of first-boot.sh:
systemctl stop getty@tty1.service 2>/dev/null || true

# At end of first-boot.sh:
systemctl start getty@tty1.service 2>/dev/null || true
```

And use `After=getty@tty1.service` in the unit file so our service runs after getty starts:
```ini
[Unit]
After=network-online.target getty@tty1.service

[Service]
StandardInput=tty
StandardOutput=tty
StandardError=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
```

---

### 3. Flask Process Dies When Script Exits

**Problem**: Using `nohup ... &` isn't enough - Flask dies when first-boot.sh exits because it's still in the same session.

**Fix**: Use `setsid` with explicit PYTHONPATH:
```bash
PYTHONPATH="$BLOCKHOST_DIR" setsid python3 -m installer.web.app --host 0.0.0.0 --port 80 >> "$LOG_FILE" 2>&1 &
```

---

### 4. Web Wizard - DHCP Error When Network Already Configured

**Problem**: Clicking "Apply & Continue" with DHCP selected fails with "No DHCP client available" because dhclient is already running.

**Fix in app.py**: Check if network is already working before running DHCP:
```python
if method == 'dhcp':
    current_ip = net_manager.get_current_ip()
    if current_ip and net_manager.test_connectivity():
        flash(f'Network already configured: {current_ip}', 'success')
        return redirect(url_for('wizard_storage'))
    # ... else run DHCP
```

---

### 5. VM Shuts Down Instead of Rebooting After Installation

**Problem**: libvirt/QEMU interprets the guest's reboot request as shutdown during installation.

**This is a VM testing limitation, not a BlockHost bug.**

**Workaround for testing**: Manually start the VM after installation:
```bash
sudo virsh start blockhost-test
```

On real hardware, the system reboots normally.

---

### 6. Install Step Stuck at 50%

**Problem**: The `/api/install/status` endpoint was a placeholder always returning `status: 'running'`.

**Fix**: Since Proxmox is already installed by first-boot.sh, the install endpoint should just mark setup complete:
```python
@app.route('/api/install/status/<job_id>')
def api_install_status(job_id):
    return jsonify({
        'status': 'completed',
        'progress': 100,
        'message': 'Setup complete!',
    })
```

---

## Troubleshooting

### No OTP on Console
Check: `journalctl -u blockhost-firstboot`

### Web Installer Unreachable
1. Verify IP: `ip addr`
2. Check service: `systemctl status blockhost-firstboot`
3. Check logs: `/var/log/blockhost-firstboot.log`

### DHCP Failed, No Console Wizard
The script needs TTY access. Check the systemd service has `TTYPath=/dev/tty1`.

### Proxmox Services Failing After Reboot
Check `/etc/hosts` - hostname must resolve to real IP, not 127.0.1.1:
```bash
cat /etc/hosts
# Should have: 192.168.x.x  blockhost.local  blockhost
# Should NOT have: 127.0.1.1  blockhost.local  blockhost
```

### Flask Not Running After First Boot
Check if process survived:
```bash
ps aux | grep flask
ss -tlnp | grep :80
```
If not running, check `/var/log/blockhost-firstboot.log` for errors.

---

## Architecture Notes

**Why a single first-boot.sh instead of multiple services?**
- Runs once, never again
- Simpler to debug
- No complex service dependencies
- Everything in one place

**Why HTTP for private IPs?**
- Self-signed certs cause browser warnings
- Private networks are trusted
- Reduces friction for home/lab use

---

## BlockHost Packages

BlockHost consists of several packages built from submodules:

### Package Overview

| Package | Source | Install Location | Purpose |
|---------|--------|------------------|---------|
| libpam-web3-tools | libpam-web3 | Proxmox host | Admin tools, signing page generator |
| libpam-web3 | libpam-web3 | VM template | PAM module for VMs |
| blockhost-common | blockhost-common | Proxmox host | Shared config and database modules |
| blockhost-provisioner | blockhost-provisioner | Proxmox host | VM creation scripts |
| blockhost-engine | blockhost-engine | Proxmox host | Blockchain event monitor |
| blockhost-broker-client | blockhost-broker | Proxmox host | Broker client for requests |

### Building Packages

From the blockhost root directory:

```bash
./scripts/build-packages.sh
```

This builds all packages and places them in:
- `packages/host/` - Packages for the Proxmox host
- `packages/template/` - Packages for VM templates (libpam-web3)

### Build Prerequisites

```bash
# For libpam-web3 (Rust)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# For blockhost-engine (Node.js)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# For all packages
sudo apt install -y dpkg-deb
```

### Individual Build Commands

Each submodule has its own build script:

```bash
# libpam-web3-tools (for host)
cd libpam-web3 && ./packaging/build-deb-tools.sh

# libpam-web3 (for VM template)
cd libpam-web3 && ./packaging/build-deb.sh

# blockhost-common
cd blockhost-common && ./build.sh

# blockhost-provisioner
cd blockhost-provisioner && ./build-deb.sh

# blockhost-engine
cd blockhost-engine && ./packaging/build.sh

# blockhost-broker-client
cd blockhost-broker/scripts && ./build-deb.sh
```

### Installation During First Boot

The `first-boot.sh` script automatically installs packages after Proxmox installation:

1. Installs host packages from `/opt/blockhost/packages/host/`
2. Copies template packages to `/var/lib/blockhost/template-packages/`

Installation order respects dependencies:
1. blockhost-common (no deps)
2. libpam-web3-tools (no deps)
3. blockhost-provisioner (depends on common, tools)
4. blockhost-engine (depends on common, tools)
5. blockhost-broker-client (no deps)

### Template Package Usage

The `libpam-web3` package is stored at `/var/lib/blockhost/template-packages/` and is used when building VM templates with `blockhost-build-template`. It gets installed inside VMs to enable NFT-based authentication

---

## Web Wizard - Package Configuration

After first-boot installs Proxmox VE and BlockHost packages, the web wizard guides users through package configuration. This section documents the wizard steps and configuration files created.

### Wizard Flow (7 Steps + Wallet Gate)

```
[OTP Login] → [Wallet Gate: Connect MetaMask + Sign]
1. Network     → DHCP or static IP
2. Storage     → Disk selection
3. Blockchain  → Chain, wallet, contracts
4. Proxmox     → Storage, bridge, VM pools
5. IPv6        → Broker or manual prefix
6. Admin       → Admin commands, port knock config
7. Summary     → Review and finalize
```

### Step 3: Blockchain Configuration

**Template**: `installer/web/templates/wizard/blockchain.html`

**User Inputs**:
| Setting | Default | Description |
|---------|---------|-------------|
| Chain ID | 11155111 | Blockchain network (Sepolia, Mainnet, Polygon) |
| RPC URL | Public endpoint | JSON-RPC endpoint for blockchain access |
| Wallet Mode | Generate | Generate new or import existing private key |
| Contract Mode | Deploy | Deploy new contracts or use existing addresses |

**API Endpoints**:
- `POST /api/blockchain/generate-wallet` - Generate secp256k1 keypair
- `POST /api/blockchain/validate-key` - Validate imported private key
- `POST /api/blockchain/deploy` - Start async contract deployment
- `GET /api/blockchain/deploy-status/<job_id>` - Check deployment progress
- `POST /api/blockchain/set-contracts` - Set existing contract addresses

### Step 4: Proxmox Configuration

**Template**: `installer/web/templates/wizard/proxmox.html`

**User Inputs**:
| Setting | Default | Description |
|---------|---------|-------------|
| API URL | https://127.0.0.1:8006 | Auto-detected |
| Node Name | (hostname) | Auto-detected |
| Storage | local-lvm | Dropdown from pvesm |
| Bridge | vmbr0 | Dropdown from ip link |
| VMID Range | 100-999 | Pool for auto-provisioned VMs |
| IP Pool | 192.168.122.200-250 | Private IPs for VMs |
| Gateway | 192.168.122.1 | VM network gateway |

**API Endpoints**:
- `GET /api/proxmox/detect` - Auto-detect storage pools, bridges, node name

### Step 5: IPv6 Configuration

**Template**: `installer/web/templates/wizard/ipv6.html`

IPv6 is **required** - each VM needs a public IPv6 address for direct client access.

**User Inputs**:
| Setting | Description |
|---------|-------------|
| Mode | Broker (request from network) or Manual (own prefix) |
| Broker Registry | Contract address for broker network |
| Manual Prefix | IPv6 prefix if not using broker (e.g., 2001:db8::/48) |
| Allocation Size | Prefix length per VM (/64 recommended) |

**API Endpoints**:
- `POST /api/ipv6/broker-request` - Request allocation from broker network
- `POST /api/ipv6/manual` - Set manual IPv6 prefix
- `GET /api/ipv6/status` - Check allocation status

### Step 6: Summary & Finalization

**Template**: `installer/web/templates/wizard/summary.html`

The summary page shows all configuration and runs the finalization process:

**Finalization Steps**:
1. **keypair** - Generate server secp256k1 keypair (`/etc/blockhost/server.key`)
2. **wallet** - Save deployer wallet (`/etc/blockhost/deployer.key`)
3. **contracts** - Deploy contracts or verify existing addresses
4. **config** - Write configuration files (see below)
5. **token** - Create Proxmox API token via pveum
6. **ipv6** - Configure WireGuard tunnel (if using broker)
7. **template** - Build VM template (runs build-template.sh)
8. **services** - Enable and start blockhost-engine
9. **finalize** - Create `.setup-complete` marker, disable first-boot service

**API Endpoints**:
- `POST /api/finalize` - Start async finalization
- `GET /api/finalize/status/<job_id>` - Check progress (returns current_step, completed_steps, progress)

### Configuration Files Created

| File | Created By | Contents |
|------|------------|----------|
| `/etc/blockhost/db.yaml` | Wizard | VMID pool, IP pool, IPv6 prefix |
| `/etc/blockhost/web3-defaults.yaml` | Wizard | Chain ID, RPC URL, contract addresses |
| `/etc/blockhost/blockhost.yaml` | Wizard | Server pubkey, deployer ref, Proxmox settings |
| `/etc/blockhost/server.key` | Wizard | Server private key (mode 600) |
| `/etc/blockhost/deployer.key` | Wizard | Deployer private key (mode 600) |
| `/var/lib/blockhost/terraform/terraform.tfvars` | Wizard | Proxmox API credentials |
| `/etc/blockhost/broker-allocation.json` | Wizard | IPv6 allocation info (if broker mode) |

**Example db.yaml**:
```yaml
terraform_dir: "/var/lib/blockhost/terraform"
vmid_pool:
  start: 100
  end: 999
ip_pool:
  network: "192.168.122.0/24"
  start: "192.168.122.200"
  end: "192.168.122.250"
  gateway: "192.168.122.1"
ipv6:
  prefix: "2001:db8:400::/48"
  allocation_size: 64
```

**Example web3-defaults.yaml**:
```yaml
chain_id: 11155111
rpc_url: "https://ethereum-sepolia-rpc.publicnode.com"
contracts:
  nft: "0x1234567890abcdef..."
  subscription: "0xfedcba0987654321..."
```

**Example blockhost.yaml**:
```yaml
server:
  address: "0xServerAddress..."
  key_file: "/etc/blockhost/server.key"
deployer:
  key_file: "/etc/blockhost/deployer.key"
proxmox:
  node: "blockhost"
  storage: "local-lvm"
  bridge: "vmbr0"
```

**Example terraform.tfvars**:
```hcl
proxmox_api_url = "https://127.0.0.1:8006/api2/json"
proxmox_api_token_id = "root@pam!blockhost"
proxmox_api_token_secret = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
proxmox_node = "blockhost"
proxmox_storage = "local-lvm"
proxmox_bridge = "vmbr0"
```

### Post-Setup Architecture

After the wizard completes, the system operates autonomously:

```
User → Blockchain (purchase subscription)
              ↓
       Smart Contract emits event
              ↓
       blockhost-engine (monitors events)
              ↓
       blockhost-provisioner (creates VM via Terraform)
              ↓
       VM with NFT auth (libpam-web3)
              ↓
       User connects via IPv6 + NFT signature
```

**No manual VM management** - everything is driven by blockchain events.

### Web Installer Files Modified

| File | Changes |
|------|---------|
| `installer/web/app.py` | Added wizard routes (blockchain, proxmox, ipv6), API endpoints, config writers, finalization logic |
| `installer/web/templates/base.html` | Added CSS styles for radio groups, status indicators, progress lists |
| `installer/web/templates/wizard/blockchain.html` | New - blockchain configuration step |
| `installer/web/templates/wizard/proxmox.html` | New - Proxmox configuration step |
| `installer/web/templates/wizard/ipv6.html` | New - IPv6 configuration step |
| `installer/web/templates/wizard/summary.html` | Updated - comprehensive summary with finalization progress |
| `installer/web/templates/wizard/packages.html` | Replaced by blockchain.html |

### Troubleshooting

**Wallet generation fails**:
- Check if eth-keys library is installed: `pip3 install eth-keys`
- Fallback uses hashlib but won't produce valid Ethereum addresses

**Contract deployment stuck**:
- Check deployer wallet has sufficient funds for gas
- Verify RPC endpoint is accessible
- Check `/var/log/blockhost-firstboot.log` for hardhat errors

**Proxmox resources not detected**:
- Ensure pvesm and ip commands are available
- Check Proxmox services are running: `systemctl status pve-cluster`

**IPv6 broker request fails**:
- Verify blockhost-broker-client is installed
- Check broker registry contract address is correct for the chain
- Ensure network connectivity to blockchain RPC

**Template build times out**:
- Template building can take up to 30 minutes
- Check disk space and network connectivity
- Review build script output: `/opt/blockhost-provisioner/scripts/build-template.sh`

---

## Bug Fixes (2026-02-03)

### Issue 1: Network/Storage pages had old 4-step breadcrumbs

**Files Modified**: `installer/web/templates/wizard/network.html`, `installer/web/templates/wizard/storage.html`

**Problem**: Network and Storage pages showed old 4-step breadcrumbs (Network → Storage → Packages → Summary) instead of the new 6-step flow.

**Fix**: Updated progress steps to match blockchain.html: Network → Storage → Blockchain → Proxmox → IPv6 → Summary

### Issue 2: Copy button doesn't work in Firefox/Waterfox

**File Modified**: `installer/web/templates/wizard/blockchain.html`

**Problem**: `navigator.clipboard.writeText()` fails silently in Firefox because the Clipboard API requires a secure context (HTTPS) or specific user gesture handling.

**Fix**: Added fallback using `document.execCommand('copy')` with a temporary textarea element:
```javascript
function fallbackCopyToClipboard(text, btn) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
}
```

### Issue 3: Wallet generator doesn't show private key

**File Modified**: `installer/web/templates/wizard/blockchain.html`

**Problem**: Only shows deployer address, not the private key needed for backup.

**Fix**: Added a visible field to display the generated private key with its own copy button:
```html
<label>Private Key <span style="color: var(--danger);">*</span></label>
<div class="address-box">
    <span id="deployer-private-key">-</span>
    <button onclick="copyToClipboard('deployer-private-key', this)">Copy</button>
</div>
```

### Issue 4: No confirmation to save private key before continuing

**File Modified**: `installer/web/templates/wizard/blockchain.html`

**Problem**: User can click Continue without being reminded to save the private key.

**Fix**: Added confirmation dialog on form submit:
```javascript
if (!confirm('Have you saved your private key?\n\nThis private key cannot be recovered later...')) {
    e.preventDefault();
    return;
}
```

### Issue 5: Proxmox API endpoint field unnecessary

**File Modified**: `installer/web/templates/wizard/proxmox.html`

**Problem**: Shows editable API endpoint field, but it's always local (https://127.0.0.1:8006).

**Fix**: Removed the visible field and replaced with hidden input:
```html
<input type="hidden" name="pve_api_url" value="https://127.0.0.1:8006">
<input type="hidden" name="pve_user" value="root@pam">
```

### Issue 7: API Authentication section unnecessary

**File Modified**: `installer/web/templates/wizard/proxmox.html`

**Problem**: Shows API auth options but we're running as root locally.

**Fix**: Removed the entire API Authentication section. Token is created automatically during finalization without user input.

### Issue 8: Add wallet balance check before proceeding

**Files Modified**: `installer/web/templates/wizard/blockchain.html`, `installer/web/app.py`

**Problem**: User can proceed without funding wallet, causing contract deployment to fail.

**Fix**:
1. Added balance display section that polls every 10 seconds
2. Continue button disabled until balance > 0 (when deploying new contracts)
3. New API endpoint: `GET /api/blockchain/balance?address=0x...`

```python
@app.route('/api/blockchain/balance')
def api_blockchain_balance():
    # Uses JSON-RPC eth_getBalance to check wallet balance
    balance = _get_wallet_balance(address, rpc_url)
    return jsonify({'balance': str(balance / 1e18), ...})
```

### Issue 9: Fetch broker registry contract from GitHub

**Files Modified**: `installer/web/templates/wizard/ipv6.html`, `installer/web/app.py`

**Problem**: Broker registry address is hardcoded placeholder.

**Fix**: Added API endpoint to fetch from GitHub:
```python
@app.route('/api/ipv6/broker-registry')
def api_ipv6_broker_registry():
    # Fetches from https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry.json
    registry = _fetch_broker_registry_from_github(chain_id)
    return jsonify({'registry': registry, ...})
```

Added "Auto-fetch from GitHub" button in the UI.

### Issue 10 & 11: Remove broker request button from IPv6 step

**File Modified**: `installer/web/templates/wizard/ipv6.html`

**Problem**: "Request IPv6 Allocation" button fails because client isn't installed and contracts aren't deployed yet. Continue button was blocked without successful request.

**Fix**:
1. Removed the broker request button and result display
2. Simplified to just mode selection (broker vs manual) + registry address input
3. Added note explaining allocation happens during finalization
4. Allow Continue with just mode selection - actual broker request happens during finalization step

### Summary of API Changes

**New Endpoints Added**:
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/blockchain/balance` | GET | Check wallet balance via RPC |
| `/api/ipv6/broker-registry` | GET | Fetch broker registry from GitHub |

**New Helper Functions**:
| Function | Purpose |
|----------|---------|
| `_get_wallet_balance(address, rpc_url)` | JSON-RPC call to eth_getBalance |
| `_fetch_broker_registry_from_github(chain_id)` | Fetch registry.json from GitHub |

---

## Finalization System (2026-02-03)

### Persistent State Management

The finalization process now uses disk-based state persistence to track progress and enable recovery from failures.

**State File**: `/var/lib/blockhost/setup-state.json`

**State Structure**:
```json
{
  "status": "running",
  "started_at": "2026-02-03T10:00:00",
  "completed_at": null,
  "current_step": "config",
  "steps": {
    "keypair": {"status": "completed", "error": null, "completed_at": "..."},
    "wallet": {"status": "completed", "error": null, "completed_at": "..."},
    "contracts": {"status": "completed", "error": null, "completed_at": "..."},
    "config": {"status": "in_progress", "error": null, "completed_at": null},
    "token": {"status": "pending", "error": null, "completed_at": null},
    "ipv6": {"status": "pending", "error": null, "completed_at": null},
    "template": {"status": "pending", "error": null, "completed_at": null},
    "services": {"status": "pending", "error": null, "completed_at": null},
    "finalize": {"status": "pending", "error": null, "completed_at": null}
  },
  "config": { /* stored configuration from session */ }
}
```

### Finalization Steps

| Step ID | Name | Description |
|---------|------|-------------|
| `keypair` | Generate server keypair | Creates `/etc/blockhost/server.key` |
| `wallet` | Configure deployer wallet | Saves deployer key to `/etc/blockhost/deployer.key` |
| `contracts` | Deploy/verify contracts | Deploys new contracts or validates existing addresses |
| `config` | Write configuration | Creates db.yaml, web3-defaults.yaml, blockhost.yaml |
| `token` | Create Proxmox API token | Creates API token via `pveum` and writes terraform.tfvars |
| `ipv6` | Configure IPv6 | Sets up broker allocation or manual prefix |
| `template` | Build VM template | Runs build-template.sh (may take several minutes) |
| `services` | Start services | Enables and starts blockhost-engine |
| `finalize` | Finalize setup | Creates `.setup-complete` marker, disables first-boot |

### API Endpoints

**New/Updated Finalization Endpoints**:
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/finalize` | POST | Start or resume finalization |
| `/api/finalize/status` | GET | Get current state (from disk) |
| `/api/finalize/retry` | POST | Retry failed step or resume |
| `/api/finalize/reset` | POST | Reset state and start over |

**POST /api/finalize Request Body**:
```json
{
  "resume": true,      // Optional: resume from stored config
  "retry_step": "token" // Optional: specific step to retry
}
```

**GET /api/finalize/status Response**:
```json
{
  "status": "running",
  "progress": 44,
  "current_step": "config",
  "completed_steps": ["keypair", "wallet", "contracts"],
  "steps": { /* detailed step states */ },
  "failed_step": null,
  "error": null
}
```

### Resume Capability

If the finalization process is interrupted (browser close, network issue, etc.):

1. On page reload, the wizard checks `/api/finalize/status`
2. If partial progress exists, shows "Resume Setup" option
3. User can resume from where they left off
4. Configuration is stored in state file, not just session

### Retry Capability

If a step fails:

1. The error is displayed with details
2. A "Retry" button appears on the failed step
3. User can retry just that step (other completed steps are preserved)
4. Alternatively, user can "Start Over" to reset all progress

### UI Features

**Progress Display**:
- Overall progress bar (percentage)
- Per-step status indicators:
  - ○ Pending (gray circle)
  - ⟳ In Progress (spinning animation)
  - ✓ Completed (green checkmark)
  - ✗ Failed (red X with error message)

**Error Handling**:
- Failed step highlighted in red
- Error message displayed in dedicated section
- "Retry Failed Step" and "Start Over" buttons

**State Recovery**:
- Automatic state detection on page load
- "Previous setup incomplete" notice if interrupted
- Resume or restart options

### SetupState Class

The `SetupState` class in `app.py` manages state persistence:

```python
class SetupState:
    def __init__(self):
        self.state = self._load()  # Load from disk

    def save(self):
        # Write to /var/lib/blockhost/setup-state.json

    def reset(self):
        # Reset to default state

    def get_completed_steps(self) -> list:
        # Return list of completed step IDs

    def get_failed_step(self) -> Optional[str]:
        # Return failed step ID if any

    def get_next_step(self) -> Optional[str]:
        # Return next pending step

    def mark_step_running(self, step_id: str):
        # Mark step as in_progress and save

    def mark_step_completed(self, step_id: str):
        # Mark step as completed with timestamp

    def mark_step_failed(self, step_id: str, error: str):
        # Mark step as failed with error message

    def to_api_response(self) -> dict:
        # Convert to API response format
```

### Files Modified

| File | Changes |
|------|---------|
| `installer/web/app.py` | Added SetupState class, updated finalization endpoints |
| `installer/web/templates/wizard/summary.html` | Complete rewrite with step tracking, retry UI |

### Troubleshooting

**Setup stuck at a step**:
- Check `/var/lib/blockhost/setup-state.json` for current state
- Check `/var/log/blockhost-firstboot.log` for detailed errors
- Use "Retry" button or API to retry failed step

**State file corrupted**:
- Delete `/var/lib/blockhost/setup-state.json`
- Reload wizard page to start fresh

**Step keeps failing on retry**:
- Check underlying service/command that the step runs
- Some steps may have dependencies (e.g., template build needs network)
- Use "Start Over" to reset and try again with different configuration

---

## Contract Deployment (2026-02-03)

### Architecture

Smart contracts are compiled in submodules during .deb package builds, then deployed during the web wizard finalization step using Foundry.

**Contract Sources**:
| Contract | Source Submodule | Package |
|----------|------------------|---------|
| AccessCredentialNFT | libpam-web3/contracts/ | libpam-web3-tools |
| BlockHostSubscription | blockhost-engine/contracts/ | blockhost-engine |

**Build Flow**:
```
1. Submodule builds .deb with compiled contracts in /usr/share/blockhost/contracts/
2. build-iso.sh extracts contracts from .deb packages to /blockhost/contracts/
3. first-boot.sh installs Foundry and copies contracts to /var/lib/blockhost/contracts/
4. Web wizard finalization deploys contracts using `cast send --create`
```

### Foundry Installation (first-boot.sh)

Added Step 2c to install Foundry tools during first-boot:

```bash
# Step 2c: Install Foundry (for contract deployment)
STEP_FOUNDRY="${STATE_DIR}/.step-foundry"
if [ ! -f "$STEP_FOUNDRY" ]; then
    log "Step 2c: Installing Foundry..."

    # Install foundryup
    curl -L https://foundry.paradigm.xyz | bash
    export PATH="$HOME/.foundry/bin:$PATH"
    foundryup

    # Add to system-wide path
    ln -sf "$HOME/.foundry/bin/forge" /usr/local/bin/forge
    ln -sf "$HOME/.foundry/bin/cast" /usr/local/bin/cast
    ln -sf "$HOME/.foundry/bin/anvil" /usr/local/bin/anvil

    # Copy contract artifacts
    cp -r "$BLOCKHOST_DIR/contracts"/* "/var/lib/blockhost/contracts/"

    touch "$STEP_FOUNDRY"
fi
```

### Contract Artifacts on ISO (build-iso.sh)

Added `add_contracts()` function to extract contract artifacts from .deb packages:

```bash
add_contracts() {
    mkdir -p "${ISO_EXTRACT}/blockhost/contracts"
    TEMP_EXTRACT=$(mktemp -d)

    # Extract from libpam-web3-tools (NFT contract)
    TOOLS_DEB=$(find "${PROJECT_DIR}/packages/host" -name "libpam-web3-tools_*.deb" | head -1)
    if [ -n "$TOOLS_DEB" ]; then
        dpkg-deb -x "$TOOLS_DEB" "$TEMP_EXTRACT"
        cp -r "$TEMP_EXTRACT/usr/share/blockhost/contracts"/* "${ISO_EXTRACT}/blockhost/contracts/"
    fi

    # Extract from blockhost-engine (Subscription contract)
    ENGINE_DEB=$(find "${PROJECT_DIR}/packages/host" -name "blockhost-engine_*.deb" | head -1)
    if [ -n "$ENGINE_DEB" ]; then
        dpkg-deb -x "$ENGINE_DEB" "$TEMP_EXTRACT"
        cp -r "$TEMP_EXTRACT/usr/share/blockhost/contracts"/* "${ISO_EXTRACT}/blockhost/contracts/"
    fi

    rm -rf "$TEMP_EXTRACT"
}
```

### Contract Deployment (app.py)

The `_finalize_contracts()` function deploys contracts using Foundry's `cast` tool:

```python
def _finalize_contracts(config: dict) -> tuple[bool, Optional[str]]:
    if blockchain.get('contract_mode') == 'existing':
        # Use provided addresses
        config['contracts'] = {
            'nft': blockchain.get('nft_contract'),
            'subscription': blockchain.get('subscription_contract'),
        }
    else:
        # Deploy new contracts using Foundry
        nft_address, err = _deploy_contract_with_forge(
            contracts_dir / 'AccessCredentialNFT.json',
            rpc_url, deployer_key, constructor_args=[]
        )

        sub_address, err = _deploy_contract_with_forge(
            contracts_dir / 'BlockHostSubscription.json',
            rpc_url, deployer_key, constructor_args=[nft_address]
        )

        config['contracts'] = {'nft': nft_address, 'subscription': sub_address}
```

**Deployment Method** (`_deploy_contract_with_forge`):
1. Load contract artifact JSON (contains ABI and bytecode)
2. If constructor args needed, ABI-encode them with `cast abi-encode`
3. Append encoded args to bytecode
4. Deploy with `cast send --rpc-url $RPC --private-key $KEY --create $BYTECODE --json`
5. Parse contract address from JSON output

### Contract Artifact Format

Expected JSON format (Foundry output):
```json
{
  "contractName": "AccessCredentialNFT",
  "abi": [...],
  "bytecode": {
    "object": "0x608060405234801561001057600080fd5b50..."
  }
}
```

Or Hardhat format:
```json
{
  "contractName": "AccessCredentialNFT",
  "abi": [...],
  "bytecode": "0x608060405234801561001057600080fd5b50..."
}
```

### Submodule Changes Required

**For libpam-web3** - Update `packaging/build-deb-tools.sh`:
```bash
# Compile contracts
cd contracts
forge build

# Include in package
mkdir -p "$PKG_DIR/usr/share/blockhost/contracts"
cp out/AccessCredentialNFT.sol/AccessCredentialNFT.json \
   "$PKG_DIR/usr/share/blockhost/contracts/"
```

**For blockhost-engine** - Update `packaging/build.sh`:
```bash
# Compile contracts
cd contracts
forge build

# Include in package
mkdir -p "$PKG_DIR/usr/share/blockhost/contracts"
cp out/BlockHostSubscription.sol/BlockHostSubscription.json \
   "$PKG_DIR/usr/share/blockhost/contracts/"
```

### Files Modified

| File | Changes |
|------|---------|
| `scripts/first-boot.sh` | Added Step 2c for Foundry installation |
| `scripts/build-iso.sh` | Added `add_contracts()` function |
| `installer/web/app.py` | Updated `_finalize_contracts()` with real deployment, added `_deploy_contract_with_forge()` |

### Troubleshooting

**"Contract artifact not found"**:
- Ensure submodule packages include compiled contracts
- Check `/var/lib/blockhost/contracts/` for .json files
- Rebuild packages with `forge build` step

**"No bytecode found in artifact"**:
- Verify artifact JSON has `bytecode` or `bytecode.object` field
- Check contract compiled successfully (no Solidity errors)

**"Deployment failed" / timeout**:
- Check wallet has sufficient ETH for gas
- Verify RPC endpoint is responsive: `cast block-number --rpc-url $RPC`
- Check network connectivity from VM

**"Could not parse deployed address"**:
- Check `cast` output format matches expected JSON
- Verify Foundry version is recent: `cast --version`

---

## Bug Fixes (2026-02-03 - Batch 2)

### Issue 1: Storage Pool displays "0.0 GB"

**File Modified**: `installer/web/app.py`

**Problem**: The Proxmox step Storage Pool dropdown showed "local (dir) - 0.0 GB" instead of actual available space.

**Root Cause**: `pvesm status` output format:
```
Name             Type     Status           Total            Used       Available        %
local             dir     active       102297016        8654608        88423628    8.46%
```
The values are in **KB (kibibytes)**, not bytes. The code was treating the value as bytes and dividing by 1024³, resulting in near-zero values.

**Fix**: Updated `_detect_proxmox_resources()` to multiply KB values by 1024 before converting to GB:
```python
# Available is in KB, convert to bytes then to GB
try:
    avail_kb = int(parts[avail_col])
    avail_bytes = avail_kb * 1024  # KB to bytes
    avail_gb = avail_bytes / (1024**3)
except (ValueError, IndexError):
    avail_bytes = 0
    avail_gb = 0.0
```

### Issue 2: Contract artifact not found during deployment (BLOCKING)

**Files Modified**:
- `preseed/blockhost.preseed`
- `installer/web/app.py`

**Problem**: During the finalization step "Deploy smart contracts", the error occurred:
```
NFT contract deployment failed: Contract artifact not found: /var/lib/blockhost/contracts/AccessCredentialNFT.json
```

**Root Cause**: The preseed `late_command` only copied `installer/` and `first-boot.sh` to `/opt/blockhost/`, but NOT:
- `contracts/` directory
- `packages/` directory
- `scripts/` directory

**Fix 1** - Updated preseed late_command to copy all required directories:
```bash
# Old (missing directories):
cp -r "$CDROM/blockhost/installer" /target/opt/blockhost/
cp "$CDROM/blockhost/first-boot.sh" /target/opt/blockhost/

# New (includes all directories):
cp -r "$CDROM/blockhost/installer" /target/opt/blockhost/
cp -r "$CDROM/blockhost/contracts" /target/opt/blockhost/
cp -r "$CDROM/blockhost/packages" /target/opt/blockhost/
cp -r "$CDROM/blockhost/scripts" /target/opt/blockhost/
cp "$CDROM/blockhost/first-boot.sh" /target/opt/blockhost/
```

**Fix 2** - Updated contract path in `_finalize_contracts()`:
```python
# Old:
contracts_dir = Path('/var/lib/blockhost/contracts')

# New (matches preseed destination):
contracts_dir = Path('/opt/blockhost/contracts')
```

### Verification Steps

After applying these fixes:

1. **Rebuild ISO**:
```bash
./scripts/build-iso.sh --testing
```

2. **Recreate test VM**:
```bash
sudo virsh destroy blockhost-test 2>/dev/null
sudo virsh undefine blockhost-test --remove-all-storage 2>/dev/null
sudo virt-install \
    --name blockhost-test \
    --ram 4096 \
    --vcpus 2 \
    --disk size=32 \
    --cdrom build/blockhost-pve_*.iso \
    --network network=default \
    --graphics vnc
```

3. **Complete wizard flow** and verify:
   - Storage pool shows actual available space (e.g., "84.3 GB")
   - Contract deployment succeeds without "artifact not found" error

4. **Check files were copied correctly** (on installed system):
```bash
ls -la /opt/blockhost/
# Should show: contracts/  installer/  packages/  scripts/  first-boot.sh
```

### Issue 3: Foundry `cast` not installed (contract deployment fails)

**File Modified**: `scripts/first-boot.sh`

**Problem**: The Foundry installation step used `curl -L https://foundry.paradigm.xyz | bash` which requires interactive shell and doesn't work in the non-interactive first-boot environment.

**Error**: `NFT contract deployment failed: [Errno 2] No such file or directory: 'cast'`

**Fix**: Download pre-built Foundry binaries directly from GitHub releases instead of using the interactive installer:

```bash
# Download pre-built binaries directly (non-interactive)
FOUNDRY_DIR="/usr/local/lib/foundry"
mkdir -p "$FOUNDRY_DIR"

# Get latest release from GitHub
FOUNDRY_VERSION=$(curl -s https://api.github.com/repos/foundry-rs/foundry/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

# Download and extract
FOUNDRY_URL="https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/foundry_${FOUNDRY_VERSION}_linux_amd64.tar.gz"
curl -L "$FOUNDRY_URL" -o /tmp/foundry.tar.gz
tar -xzf /tmp/foundry.tar.gz -C "$FOUNDRY_DIR"

# Create symlinks
for tool in forge cast anvil chisel; do
    ln -sf "$FOUNDRY_DIR/$tool" "/usr/local/bin/$tool"
done
```

### Issue 4: NFT contract constructor requires arguments

**File Modified**: `installer/web/app.py`

**Problem**: Contract deployment failed with "execution reverted" because the NFT contract constructor requires 3 string arguments but we passed none.

**Constructor signature**: `(string name, string symbol, string defaultImageUri)`

**Fix**: Pass constructor arguments to the NFT deployment:
```python
nft_address, err = _deploy_contract_with_forge(
    contracts_dir / 'AccessCredentialNFT.json',
    rpc_url,
    deployer_key,
    constructor_args=['BlockHost Access', 'BHAC', '']
)
```

### Issue 5: Wrong wallet address shown in wizard

**File Modified**: `installer/web/app.py`

**Problem**: The wizard showed a different wallet address than `cast wallet address` for the same private key.

**Root Cause**: The `_get_address_from_key()` fallback used SHA256 instead of proper secp256k1/keccak256 derivation when eth-keys library wasn't available.

**Fix**: Use Foundry's `cast wallet address` as the fallback:
```python
# Fallback: use Foundry's cast if available
result = subprocess.run(
    ['cast', 'wallet', 'address', '--private-key', '0x' + key],
    capture_output=True, text=True, timeout=10
)
if result.returncode == 0:
    return result.stdout.strip()
```

### Issue 6: Broker IPv6 request not automated

**File Modified**: `installer/web/app.py`

**Problem**: The `_finalize_ipv6` step only saved config but didn't actually request an IPv6 allocation from the broker network.

**Fix**: Updated `_finalize_ipv6` to call `broker-client request` with the deployed NFT contract address and registry:
```python
cmd = [
    'broker-client', 'request',
    '--registry-contract', registry,
    '--nft-contract', nft_contract,
    '--wallet-key', '/etc/blockhost/deployer.key',
    '--configure-wg',
]
result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
```

### Issue 7: Imported wallet key not used (wrong key saved)

**File Modified**: `installer/web/app.py`

**Problem**: When user generates a wallet, then switches to "Import" mode and enters their own key, the generated key is used instead of the imported one.

**Root Cause**: The form has two fields:
- `deployer_key` (hidden) - filled when "Generate Wallet" is clicked
- `import_key` - filled when importing

The code used `request.form.get('deployer_key') or request.form.get('import_key')`, but if the user clicked Generate before switching to Import, `deployer_key` was non-empty and took precedence.

**Fix**: Check `wallet_mode` to determine which field to use:
```python
wallet_mode = request.form.get('wallet_mode')
if wallet_mode == 'import':
    deployer_key = request.form.get('import_key')
else:
    deployer_key = request.form.get('deployer_key')
```

---

## VM Template Building (2026-02-04)

### Overview

The VM template building implementation automates the creation of a base Debian VM template with libpam-web3 during wizard finalization, enabling automated VM provisioning via Terraform.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    First-Boot (Step 2d)                      │
│    Install Terraform + libguestfs-tools from HashiCorp repo  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                   Web Wizard Finalization                    │
│                                                              │
│  1. keypair                                                  │
│  2. wallet                                                   │
│  3. contracts                                                │
│  4. config                                                   │
│  5. token         → Creates Proxmox API token               │
│  6. terraform     → NEW: Sets up Terraform provider          │
│  7. ipv6          → Broker/manual IPv6 config               │
│  8. template      → UPDATED: Builds VM template locally      │
│  9. services                                                 │
│  10. finalize                                                │
└─────────────────────────────────────────────────────────────┘
```

### Step 2d: Terraform Installation (first-boot.sh)

Added after Foundry installation to set up Terraform and libguestfs-tools:

```bash
#
# Step 2d: Install Terraform and libguestfs-tools
#
STEP_TERRAFORM="${STATE_DIR}/.step-terraform"
if [ ! -f "$STEP_TERRAFORM" ]; then
    log "Step 2d: Installing Terraform and libguestfs-tools..."

    # Add HashiCorp GPG key and repository
    if [ ! -f /usr/share/keyrings/hashicorp-archive-keyring.gpg ]; then
        wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com bookworm main" > /etc/apt/sources.list.d/hashicorp.list
        apt-get update
    fi

    DEBIAN_FRONTEND=noninteractive apt-get install -y terraform libguestfs-tools

    touch "$STEP_TERRAFORM"
fi
```

### Step 6: Terraform Finalization (_finalize_terraform)

New finalization step that configures Terraform for VM provisioning:

**Actions**:
1. Creates `/var/lib/blockhost/terraform/` directory
2. Generates SSH keypair at `/etc/blockhost/terraform_ssh_key` (ed25519)
3. Adds public key to `/root/.ssh/authorized_keys`
4. Writes `provider.tf.json` with bpg/proxmox provider configuration
5. Writes `variables.tf.json` with wizard values
6. Runs `terraform init`

**provider.tf.json**:
```json
{
  "terraform": {
    "required_providers": {
      "proxmox": {
        "source": "bpg/proxmox",
        "version": ">= 0.50.0"
      }
    }
  },
  "provider": {
    "proxmox": {
      "endpoint": "https://127.0.0.1:8006",
      "api_token": "${var.proxmox_api_token}",
      "insecure": true,
      "ssh": {
        "agent": false,
        "private_key": "${file(\"/etc/blockhost/terraform_ssh_key\")}",
        "node": [
          {
            "name": "blockhost",
            "address": "127.0.0.1"
          }
        ]
      }
    }
  }
}
```

**variables.tf.json**:
```json
{
  "variable": {
    "proxmox_api_token": { "type": "string", "sensitive": true },
    "proxmox_node": { "type": "string", "default": "blockhost" },
    "proxmox_storage": { "type": "string", "default": "local-lvm" },
    "proxmox_bridge": { "type": "string", "default": "vmbr0" },
    "template_vmid": { "type": "number", "default": 9001 },
    "vmid_start": { "type": "number", "default": 100 },
    "vmid_end": { "type": "number", "default": 999 }
  }
}
```

### Step 8: Template Building (_finalize_template)

Updated to build VM template locally with environment variables:

**Changes**:
1. Checks if template already exists (via `qm status <VMID>`)
2. Finds libpam-web3 .deb in `/var/lib/blockhost/template-packages/`
3. Passes environment variables to build-template.sh:
   - `TEMPLATE_VMID` - VMID for the template (default: 9001)
   - `STORAGE` - Storage pool name
   - `LIBPAM_WEB3_DEB` - Path to libpam-web3 package
   - `PROXMOX_HOST` - Set to `localhost` for local execution

```python
def _finalize_template(config: dict) -> tuple[bool, Optional[str]]:
    proxmox = config.get('proxmox', {})
    template_vmid = proxmox.get('template_vmid', 9001)
    storage = proxmox.get('storage', 'local-lvm')

    # Check if template already exists
    template_check = subprocess.run(
        ['qm', 'status', str(template_vmid)],
        capture_output=True, text=True, timeout=10
    )
    if template_check.returncode == 0:
        return True, None  # Skip if exists

    # Find libpam-web3 .deb
    template_pkg_dir = Path('/var/lib/blockhost/template-packages')
    debs = list(template_pkg_dir.glob('libpam-web3_*.deb'))
    libpam_deb = str(sorted(debs, key=lambda p: p.stat().st_mtime, reverse=True)[0]) if debs else None

    # Build template with environment variables
    env = os.environ.copy()
    env['TEMPLATE_VMID'] = str(template_vmid)
    env['STORAGE'] = storage
    env['PROXMOX_HOST'] = 'localhost'
    if libpam_deb:
        env['LIBPAM_WEB3_DEB'] = libpam_deb

    result = subprocess.run(
        ['/opt/blockhost-provisioner/scripts/build-template.sh'],
        env=env, capture_output=True, text=True, timeout=1800
    )
```

### Proxmox Wizard: Template VMID Field

Added new form field in `installer/web/templates/wizard/proxmox.html`:

```html
<!-- VM Template Configuration -->
<div class="form-section">
    <h3>VM Template</h3>
    <div class="form-group">
        <label for="template_vmid">Template VMID</label>
        <input type="number" id="template_vmid" name="template_vmid"
               value="9001" min="100" max="999999">
        <p class="text-muted">
            VMID for the base Debian template with libpam-web3. Default: 9001
        </p>
    </div>
</div>
```

### Updated Finalization Step Order

The finalization now has 10 steps (was 9):

| # | Step ID | Name |
|---|---------|------|
| 1 | keypair | Generate server keypair |
| 2 | wallet | Configure deployer wallet |
| 3 | contracts | Deploy/verify contracts |
| 4 | config | Write configuration files |
| 5 | token | Create Proxmox API token |
| 6 | **terraform** | **NEW: Configure Terraform provider** |
| 7 | ipv6 | Configure IPv6 |
| 8 | template | Build VM template (updated) |
| 9 | services | Start services |
| 10 | finalize | Finalize setup |

### Files Modified

| File | Changes |
|------|---------|
| `scripts/first-boot.sh` | Added Step 2d: Install Terraform + libguestfs-tools |
| `installer/web/app.py` | Added `_finalize_terraform()`, updated `_finalize_template()`, updated step order, added `terraform` to SetupState |
| `installer/web/templates/wizard/proxmox.html` | Added template_vmid field |

### Submodule Changes Required (blockhost-provisioner)

The `scripts/build-template.sh` in the blockhost-provisioner submodule needs updates for local execution:

1. Default `PROXMOX_HOST` to `localhost` instead of SSH target
2. Default `LIBPAM_WEB3_DEB` to `/var/lib/blockhost/template-packages/libpam-web3_*.deb`
3. Remove SSH/SCP operations (script runs locally now)
4. Execute `qm` commands directly instead of via SSH

**See "Submodule Change Prompt" section for the full prompt to send to the blockhost-provisioner Claude session.**

### Verification

After implementation, verify:

1. **After first-boot**:
```bash
terraform --version  # Should show Terraform version
virt-customize --version  # Should show libguestfs version
```

2. **After finalization**:
```bash
ls -la /var/lib/blockhost/terraform/
# Should show: provider.tf.json, variables.tf.json, .terraform/

ls -la /etc/blockhost/terraform_ssh_key*
# Should show: terraform_ssh_key, terraform_ssh_key.pub

qm list
# Should show template VM at VMID 9001 (or configured VMID)
```

3. **End-to-end test**:
```bash
blockhost-vm-create test-vm --owner-wallet 0x...
# Should create VM from template
```

### Troubleshooting

**Terraform init fails**:
- Check network connectivity to Terraform registry
- Verify HashiCorp apt repository was added correctly
- Check `/var/log/blockhost-firstboot.log` for errors

**SSH key not in authorized_keys**:
- Check `/etc/blockhost/terraform_ssh_key.pub` exists
- Verify `/root/.ssh/authorized_keys` contains the key
- Check file permissions (600 for private key, 644 for public)

**Template build fails**:
- Verify libpam-web3 .deb exists in `/var/lib/blockhost/template-packages/`
- Check build-template.sh supports the new environment variables
- Review provisioner script output for specific errors

**Template VMID conflict**:
- If VMID 9001 is already in use, change the template_vmid in wizard
- The finalization will skip building if the VMID already exists

### Submodule Change Prompt (blockhost-provisioner)

Copy and paste the following prompt to the blockhost-provisioner Claude session:

---

**Update `scripts/build-template.sh` for local execution on Proxmox host**

The script currently runs remotely via SSH. Update it to run locally when called from the BlockHost web wizard finalization.

**Requirements:**

1. **Environment Variables** (with sensible defaults):
   - `PROXMOX_HOST` - Default to `localhost` (previously hardcoded SSH target)
   - `TEMPLATE_VMID` - Default to `9001`
   - `STORAGE` - Default to `local-lvm`
   - `LIBPAM_WEB3_DEB` - Default to `/var/lib/blockhost/template-packages/libpam-web3_*.deb`

2. **Local Execution Mode**:
   - When `PROXMOX_HOST=localhost`, execute `qm`, `pvesm`, and `virt-customize` commands directly
   - Remove SSH wrapper for local commands
   - Remove SCP operations (files are already local)

3. **Remote Execution Mode** (preserve for development):
   - When `PROXMOX_HOST` is not `localhost`, use SSH as before
   - This allows testing from a development machine

4. **Command Changes**:
   - Replace `ssh root@$PROXMOX_HOST 'qm ...'` with conditional: if localhost, run `qm ...` directly
   - Replace `scp file root@$PROXMOX_HOST:path` with conditional: if localhost, `cp file path`

5. **Example Pattern**:
```bash
run_on_host() {
    if [ "$PROXMOX_HOST" = "localhost" ]; then
        "$@"
    else
        ssh "root@$PROXMOX_HOST" "$@"
    fi
}

copy_to_host() {
    local src="$1"
    local dest="$2"
    if [ "$PROXMOX_HOST" = "localhost" ]; then
        cp "$src" "$dest"
    else
        scp "$src" "root@$PROXMOX_HOST:$dest"
    fi
}

# Usage:
run_on_host qm create "$TEMPLATE_VMID" --name "debian-template" --memory 2048
copy_to_host "$LIBPAM_WEB3_DEB" "/tmp/libpam-web3.deb"
```

6. **Expected Environment When Called**:
   - Running as root on Proxmox host
   - `TEMPLATE_VMID`, `STORAGE`, `LIBPAM_WEB3_DEB` set by caller
   - `PROXMOX_HOST=localhost` set by caller

---

## Wizard Updates (2026-02-05)

### Summary

Updated the web wizard (`installer/web/app.py`) to generate correct configuration formats for all submodules after end-to-end testing revealed format mismatches.

### Changes Made

#### 1. Config Format Fixes

**db.yaml** - Fixed to use canonical format:
- Changed `vmid_pool` to `vmid_range`
- Convert IP pool start/end to integers (last octet)
- Added `db_file`, `ipv6_pool`, `default_expiry_days`

**web3-defaults.yaml** - Fixed to use nested structure:
```yaml
blockchain:
  chain_id: <int>
  rpc_url: <string>
  nft_contract: <address>
  subscription_contract: <address>
auth:
  otp_length: 6
  otp_ttl_seconds: 300
  decrypt_message: "blockhost-access"
signing_page:
  html_path: /usr/share/libpam-web3-tools/signing-page/index.html
deployer:
  private_key_file: /etc/blockhost/deployer.key
server:
  public_key: <hex>
```

**provider.tf.json** - Added SSH username:
```json
"ssh": {
  "agent": false,
  "username": "root",
  "private_key": "${file(\"/etc/blockhost/terraform_ssh_key\")}",
  ...
}
```

#### 2. New Finalization Steps

Added to the wizard finalization process:

1. **HTTPS Setup** (`_finalize_https`):
   - Reads IPv6 prefix from broker allocation
   - Generates sslip.io hostname from IPv6
   - Runs certbot for Let's Encrypt certificate
   - Falls back to self-signed if no IPv6/domain

2. **Server Keypair** (`_finalize_keypair`):
   - Now generates and stores public key for ECIES encryption
   - Writes to `/etc/blockhost/server.pubkey`

3. **Default Plan Creation** (`_create_default_plan`):
   - Creates "Basic VM" plan on subscription contract
   - $1/day, 1 CPU, 512MB RAM, 10GB disk

**Note**: NFT #0 minting is NOT implemented yet. It requires the wallet
connection step (after OTP auth) to be built first. NFT #0 should be
minted to the admin's connected wallet, not the deployer wallet.

#### 3. UI Updates

Updated `templates/wizard/summary.html`:
- Added `terraform` step display
- Added `https` step display
- Updated JavaScript step order to match backend

### Files Modified

- `installer/web/app.py` - Main wizard application
- `installer/web/templates/wizard/summary.html` - Finalization UI
- `SESSION_CONTEXT.md` - Updated status

### Verification

```bash
# Check Python syntax
python3 -m py_compile installer/web/app.py

# Test wizard locally (requires Flask)
cd installer/web && python3 -m flask run --port 8080
```

---

## Wizard Updates (2026-02-05) - Part 2

### Changes Made

#### 1. Removed Services Step from UI

The "services" step was removed from the visible finalization progress.
Services are enabled via `systemctl enable` in `_finalize_complete()` but
don't need a dedicated UI step since they only start after reboot anyway.

**Files modified**:
- `installer/web/app.py` - Removed `_finalize_services()`, merged enables into `_finalize_complete()`
- `installer/web/templates/wizard/summary.html` - Removed services from stepOrder/stepNames

#### 2. Auto-fetch Broker Registry on IPv6 Page

The IPv6 configuration page now automatically fetches the broker registry
contract address from GitHub when the page loads, instead of requiring the
user to click a button.

**Behavior**:
- On page load, if broker mode is selected and registry field is empty, auto-fetch runs silently
- If auto-fetch fails, no error alert (silent failure)
- Manual "Auto-fetch from GitHub" button remains as fallback
- Button click shows error alerts if fetch fails

**File modified**: `installer/web/templates/wizard/ipv6.html`

```javascript
// fetchBrokerRegistry now accepts silent parameter
async function fetchBrokerRegistry(silent = false) { ... }

// Auto-fetch on page load
document.addEventListener('DOMContentLoaded', function() {
    const brokerMode = document.querySelector('input[name="ipv6_mode"][value="broker"]');
    const registryInput = document.getElementById('broker_registry');
    if (brokerMode && brokerMode.checked && registryInput && !registryInput.value.trim()) {
        fetchBrokerRegistry(true);  // silent=true
    }
});
```

#### 3. Let's Encrypt Without Email

Changed certbot to register without requiring an email address:

**File modified**: `installer/web/app.py`

```python
# Old (broken - admin@localhost won't work):
'--email', 'admin@localhost',

# New (no email required):
'--register-unsafely-without-email',
```

This avoids the privacy-invading email requirement. Users won't receive
expiration notices, but `certbot renew` handles auto-renewal anyway.

#### 4. Signup Page Generation Step

Added new finalization step to generate and serve the signup page.

**Changes**:
- Added `_finalize_signup()` function to `app.py`
- Added 'signup' step to `SetupState` default steps
- Added 'signup' to step order in finalization
- Updated `summary.html` with signup step UI

**What it does**:
1. Calls `blockhost-generate-signup` to create `/var/www/blockhost/signup.html`
2. Creates a systemd service (`blockhost-signup.service`) to serve it
3. Uses HTTPS (port 443) if TLS is configured, HTTP (port 8080) otherwise
4. Enables and starts the service

#### 5. Fixed blockhost.yaml Config

Added `server_public_key` and `decrypt_message` to `blockhost.yaml` output.
These fields are required by `blockhost-generate-signup`.

```yaml
# Now included in blockhost.yaml:
server_public_key: '04...'  # Uncompressed secp256k1 public key (no 0x prefix)
decrypt_message: 'blockhost-access'
```

---

## Testing Mode Validation (Added Session 3)

### Purpose

When the ISO is built with `--testing` flag, the wizard runs a comprehensive
system validation as the final step. This catches configuration errors before
reboot rather than having to debug a broken system.

### Files Created

**`installer/web/validate_system.py`** - Comprehensive validation module

### What It Validates

**File Existence and Permissions:**
- `/etc/blockhost/server.key` - 0600, valid hex
- `/etc/blockhost/deployer.key` - 0600, valid hex
- `/etc/blockhost/terraform_ssh_key` - 0600
- `/etc/blockhost/ssl/key.pem` - 0600

**YAML Configuration:**
- `/etc/blockhost/db.yaml` - syntax + required keys (vmid_range, ip_pool, etc.)
- `/etc/blockhost/web3-defaults.yaml` - syntax + required keys (chain_id, rpc_url, nft_contract)
- `/etc/blockhost/blockhost.yaml` - syntax + required keys (key files, proxmox settings)

**JSON Configuration:**
- `/etc/blockhost/https.json` - syntax + required keys
- `/etc/blockhost/broker-allocation.json` - syntax (if exists)
- `/var/lib/blockhost/setup-state.json` - status = completed

**Terraform:**
- `/var/lib/blockhost/terraform/provider.tf.json` - valid JSON
- `/var/lib/blockhost/terraform/variables.tf.json` - valid JSON
- `/var/lib/blockhost/terraform/terraform.tfvars` - exists
- `/var/lib/blockhost/terraform/.terraform/` - initialized

**Services:**
- `blockhost-signup` - enabled and running
- `blockhost-monitor` - enabled
- `blockhost-gc.timer` - enabled
- `blockhost-first-boot` - disabled

**Network:**
- Bridge (vmbr0) exists
- Bridge has IP address

**SSH:**
- Terraform public key in `/root/.ssh/authorized_keys`

**Web:**
- `/var/www/blockhost/signup.html` exists and has content

### Testing Mode Detection

The validation only runs on ISOs built with `--testing`. Detection uses:
1. Primary: `/etc/blockhost/.testing-mode` marker file (created by build-iso.sh)
2. Fallback: `/etc/apt/apt.conf.d/00proxy` (apt proxy config)

### Changes to `scripts/build-iso.sh`

Added marker file creation in testing mode configuration:

```bash
# Create testing mode marker for validation script
mkdir -p /etc/blockhost
touch /etc/blockhost/.testing-mode
chmod 0644 /etc/blockhost/.testing-mode
```

### Changes to `installer/web/app.py`

1. Added 'validate' step to `_default_state()` steps dict
2. Added 'validate' to `step_order` list
3. Added validate step to finalization steps list
4. Added `_finalize_validate()` function

### Changes to `installer/web/templates/wizard/summary.html`

1. Added 'validate' to `stepOrder` and `stepNames` JavaScript arrays
2. Added HTML list item for validate step

### Running Validation Manually

The validation module can be run directly:

```bash
cd /opt/blockhost/installer/web
python3 validate_system.py
```

This runs regardless of testing mode and outputs a detailed report.

## Wizard Updates (2026-02-06) - Admin Wallet & Commands

### Overview

Added mandatory admin wallet connection gate after OTP login, and a new Admin Commands
wizard step for configuring blockchain-based port knocking and future admin commands.

### Changes Made

#### 1. Admin Wallet Gate (Post-OTP)

After OTP login, admin must connect MetaMask and sign a decrypt message before proceeding
to the wizard. This captures:
- Admin wallet address (stored in session and config)
- Signature (used to derive AES key for NFT #0 encryption)
- Decrypt message (format: `libpam-web3:<address>:<nonce>`)

**New file**: `installer/web/templates/wizard/wallet.html`

**Route**: `GET/POST /wizard/wallet` (no step bar - pre-wizard gate)

**Redirect chain**: OTP success → `/wizard/wallet` → `/wizard/network`

#### 2. Admin Commands Wizard Step (Step 6)

New wizard step between IPv6 and Summary for configuring on-chain admin commands.

**New file**: `installer/web/templates/wizard/admin_commands.html`

**Route**: `GET/POST /wizard/admin-commands`

**User Inputs**:
| Setting | Default | Description |
|---------|---------|-------------|
| admin_enabled | yes | Enable/disable admin commands |
| destination_mode | self | How to filter admin transactions (any/self/server/null) |
| knock_command | random hex | Secret command name for port knocking |
| knock_ports | 22, 8006 | Ports to open on knock |
| knock_timeout | 300 | Seconds to wait for login before closing ports |
| knock_max_duration | 600 | Max time ports stay open after login |

#### 3. Config File Generation

**`/etc/blockhost/blockhost.yaml`** now includes:
```yaml
admin:
  wallet_address: "0x..."
  max_command_age: 300
  destination_mode: "self"
```

**`/etc/blockhost/admin-commands.json`** (new file):
```json
{
  "commands": {
    "<secret_name>": {
      "action": "knock",
      "description": "Open SSH and Proxmox ports temporarily",
      "params": {
        "allowed_ports": [22, 8006],
        "max_duration": 600,
        "default_duration": 300
      }
    }
  }
}
```

**`/etc/blockhost/admin-signature.key`** (new file):
Admin's raw signature, used during install to encrypt connection details
into NFT #0 via `keccak256(signature)` → AES-256-GCM key.

#### 4. Step Bar Updates

All wizard templates updated from 6 steps to 7 (added "Admin" at position 6,
Summary moved to 7).

**Files modified**:
- `installer/web/templates/wizard/network.html` - Step bar
- `installer/web/templates/wizard/storage.html` - Step bar
- `installer/web/templates/wizard/blockchain.html` - Step bar
- `installer/web/templates/wizard/proxmox.html` - Step bar
- `installer/web/templates/wizard/ipv6.html` - Step bar
- `installer/web/templates/wizard/summary.html` - Step bar + admin summary section + back button
- `installer/web/app.py` - Routes, redirects, config generation

#### 5. Engine Submodule Update

Updated `blockhost-engine` submodule to include:
- NFT decryption on signup page (auto-populate from wallet, offline/paranoid mode)
- Admin command infrastructure (monitor, command database, knock handler)

Config format coordinated between installer and engine:
- Engine reads `admin.wallet_address` from `blockhost.yaml`
- Engine reads command definitions from `admin-commands.json`
