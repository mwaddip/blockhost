# BlockHost Build Guide

**Version**: 0.1.0
**Last Updated**: 2026-02-07
**Base**: Debian 12 (Bookworm) → Proxmox VE 8.4

---

## Overview

BlockHost turns a bare-metal server into an autonomous VM hosting platform driven by blockchain events. Users purchase subscriptions on-chain; the system detects the event, provisions a VM, mints an NFT with encrypted connection details, and the user connects via IPv6 + web3 signature authentication.

**What the ISO does**: Auto-installs Debian 12, runs a first-boot script that installs Proxmox VE and BlockHost packages, then launches a web wizard for configuration.

---

## Quick Start

```bash
# 1. Check and install build dependencies
./scripts/check-build-deps.sh --install

# 2. Build all .deb packages from submodules
./scripts/build-packages.sh

# 3. Build the ISO (with testing conveniences)
./scripts/build-iso.sh --testing

# Or combine steps 2+3:
./scripts/build-iso.sh --build-deb --testing
```

Output: `build/blockhost_0.1.0.iso`

---

## Project Structure

```
blockhost/
├── installer/
│   ├── web/                  # Flask web installer
│   │   ├── app.py            # Routes, wizard logic, finalization
│   │   ├── validate_system.py # Post-install validation (testing mode)
│   │   └── templates/        # Jinja2 templates
│   │       ├── base.html
│   │       ├── login.html
│   │       ├── macros/
│   │       │   └── wizard_steps.html  # Shared step bar macro
│   │       └── wizard/
│   │           ├── wallet.html        # Admin wallet gate (pre-wizard)
│   │           ├── network.html       # Step 1
│   │           ├── storage.html       # Step 2
│   │           ├── blockchain.html    # Step 3
│   │           ├── proxmox.html       # Step 4
│   │           ├── ipv6.html          # Step 5
│   │           ├── admin_commands.html # Step 6
│   │           ├── summary.html       # Step 7 + finalization
│   │           └── install.html       # Post-finalization reboot
│   └── common/               # Shared logic (OTP, detection, config)
├── preseed/
│   └── blockhost.preseed     # Debian auto-install config
├── scripts/
│   ├── build-iso.sh          # ISO builder
│   ├── build-packages.sh     # Build all .deb packages
│   ├── install-packages.sh   # Install packages on target
│   ├── check-build-deps.sh   # Dependency checker
│   ├── first-boot.sh         # First boot orchestration
│   └── ssh-test.sh           # SSH wrapper for test VMs
├── systemd/
│   └── blockhost-firstboot.service
├── packages/
│   ├── host/                 # .deb packages for Proxmox host
│   └── template/             # .deb packages for VM templates
├── testing/
│   ├── blockhost-test-key    # SSH key for test VMs
│   └── blockhost-test-key.pub
└── docs/
    └── BUILD_GUIDE.md        # This file
```

### Submodules (separate repos, not edited here)

| Submodule | Package(s) | Purpose |
|-----------|------------|---------|
| `libpam-web3/` | libpam-web3-tools (host), libpam-web3 (template) | PAM module, signing page, crypto tools |
| `blockhost-common/` | blockhost-common | Shared config loading, VM database |
| `blockhost-provisioner/` | blockhost-provisioner | VM creation via Terraform, NFT minting |
| `blockhost-engine/` | blockhost-engine | Blockchain event monitor, signup page generator |
| `blockhost-broker/` | blockhost-broker-client | IPv6 tunnel broker client |

---

## Build Dependencies

### ISO Build (system packages)

```
xorriso cpio gzip dpkg isolinux coreutils findutils sed wget/curl
```

### Package Build (development tools)

| Tool | Required By | Install |
|------|------------|---------|
| cargo | libpam-web3 | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| forge | libpam-web3-tools, blockhost-engine | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| node 18+ | blockhost-engine | https://nodejs.org/ or nvm |
| npm | blockhost-engine | (comes with node) |
| python3 | blockhost-provisioner, blockhost-broker | `apt install python3` |
| git | submodule operations | `apt install git` |
| curl | various downloads | `apt install curl` |

Run `./scripts/check-build-deps.sh` to verify, or `--install` to auto-install what's missing.

---

## Package Build

```bash
./scripts/build-packages.sh
```

Builds 6 packages in dependency order:

| # | Package | Source | Build Command | Destination |
|---|---------|--------|---------------|-------------|
| 1 | libpam-web3-tools | libpam-web3/ | `packaging/build-deb-tools.sh` | packages/host/ |
| 2 | libpam-web3 | libpam-web3/ | `packaging/build-deb.sh` | packages/template/ |
| 3 | blockhost-common | blockhost-common/ | `build.sh` | packages/host/ |
| 4 | blockhost-provisioner | blockhost-provisioner/ | `build-deb.sh` | packages/host/ |
| 5 | blockhost-engine | blockhost-engine/ | `packaging/build.sh` | packages/host/ |
| 6 | blockhost-broker-client | blockhost-broker/ | `scripts/build-deb.sh` | packages/host/ |

Packages must be rebuilt whenever a submodule changes. The ISO copies pre-built `.deb` files — it does not rebuild them.

---

## ISO Build

```bash
./scripts/build-iso.sh [--build-deb] [--testing]
```

**Flags:**
- `--build-deb` — Run `build-packages.sh` first
- `--testing` — Enable apt proxy (`http://192.168.122.1:3142`), SSH root login, testing mode marker

**What it does:**
1. Extracts Debian 12 netinst ISO
2. Adds preseed for automated Debian install
3. Copies BlockHost files to `/blockhost/` on the ISO:
   - `installer/` — Flask web app
   - `packages/` — Pre-built .deb files
   - `contracts/` — Compiled contract artifacts (extracted from .deb packages)
   - `scripts/` — install-packages.sh
   - `first-boot.sh` — First boot orchestrator
   - `blockhost-firstboot.service` — systemd unit
4. Configures GRUB + isolinux for auto-install
5. Rebuilds hybrid ISO (BIOS + UEFI)

**Note:** The ISO builder does not require root. If a previous ISO exists owned by root, remove it first with `sudo rm`.

---

## Installation Flow

### Phase 1: Debian Auto-Install (preseed)

The preseed configures:
- Full-disk LVM partitioning
- Root password: `blockhost`
- Locale: `en_US.UTF-8`, timezone: UTC
- Apt proxy (testing mode only)

**Late command** copies all BlockHost files from the CD to `/opt/blockhost/` on the target and enables the first-boot service.

### Phase 2: First Boot (`first-boot.sh`)

Runs once via `blockhost-firstboot.service` (condition: `/var/lib/blockhost/.setup-complete` must not exist). Each step is idempotent with marker files for crash recovery.

| Step | Description |
|------|-------------|
| 1. Hostname | Fix `/etc/hosts` — hostname must resolve to real IP, not `127.0.1.1` (Proxmox requirement) |
| 2. Proxmox | Add PVE repo, install `proxmox-ve postfix open-iscsi chrony python3-ecdsa` |
| 2b. Packages | Install BlockHost `.deb` packages via `install-packages.sh` |
| 2c. Foundry | Download pre-built Foundry binaries (forge, cast, anvil) to `/usr/local/lib/foundry` |
| 2d. Terraform | Add HashiCorp repo, install `terraform libguestfs-tools` |
| 3. Network | Wait for connectivity, run DHCP if needed |
| 4. OTP | Generate 6-char access code (4hr timeout, 10 attempts max) |
| 5. Web installer | Launch Flask wizard on port 80, display OTP on console |

Package install order (respects dependencies):
1. blockhost-common
2. libpam-web3-tools
3. blockhost-provisioner
4. blockhost-engine
5. blockhost-broker-client

Template packages (libpam-web3) are copied to `/var/lib/blockhost/template-packages/`.

### Phase 3: Web Wizard

Access via browser at the IP shown on console. Enter OTP to authenticate.

**Pre-wizard gate:** Admin connects MetaMask wallet and signs a message. This captures the admin wallet address and signature (used later for NFT #0 encryption).

**Wizard steps:**

| # | Step | What it configures |
|---|------|--------------------|
| 1 | Network | DHCP or static IP (usually already configured) |
| 2 | Storage | Disk selection for Proxmox |
| 3 | Blockchain | Chain ID, RPC URL, deployer wallet (generate/import), contracts (deploy/existing) |
| 4 | Proxmox | Storage pool, bridge, VMID range, IP pool, template VMID |
| 5 | IPv6 | Broker allocation or manual prefix |
| 6 | Admin | Admin commands, port knock config |
| 7 | Summary | Review all settings, start finalization |

The step bar is data-driven from `WIZARD_STEPS` in `app.py` — add/remove steps in one place.

### Phase 4: Finalization

Triggered from the summary page. 14 steps with persistent state in `/var/lib/blockhost/setup-state.json` — supports resume and retry on failure.

| # | Step ID | Description |
|---|---------|-------------|
| 1 | `keypair` | Generate server secp256k1 keypair |
| 2 | `wallet` | Save deployer private key |
| 3 | `contracts` | Deploy contracts via `cast` or verify existing addresses |
| 4 | `config` | Write config files (see below) |
| 5 | `token` | Create Proxmox API token via `pveum` |
| 6 | `terraform` | Generate provider/variables `.tf.json`, run `terraform init` |
| 7 | `bridge` | Create `vmbr0` bridge via PVE API (`pvesh`) |
| 8 | `ipv6` | Request broker allocation + install WireGuard tunnel, or configure manual prefix |
| 9 | `https` | Generate sslip.io hostname from IPv6, get Let's Encrypt cert |
| 10 | `signup` | Generate signup page via `blockhost-generate-signup` |
| 11 | `mint_nft` | Mint NFT #0 to admin wallet with encrypted connection details |
| 12 | `template` | Build Debian VM template with libpam-web3 |
| 13 | `finalize` | Create `.setup-complete` marker, enable services, disable first-boot |
| 14 | `validate` | System validation (testing mode only) |

---

## Configuration Files

Created during finalization in `/etc/blockhost/`:

| File | Contents |
|------|----------|
| `server.key` | Server private key (mode 600) |
| `server.pubkey` | Server public key (uncompressed secp256k1) |
| `deployer.key` | Deployer wallet private key (mode 600) |
| `db.yaml` | VMID range, IP pool, IPv6 pool, terraform_dir |
| `web3-defaults.yaml` | Chain ID, RPC URL, contract addresses, auth settings |
| `blockhost.yaml` | Server keys, deployer ref, Proxmox settings, admin config |
| `broker-allocation.json` | IPv6 prefix, broker endpoint, WG keys (broker mode) |
| `https.json` | Hostname, cert/key paths, sslip.io flag |
| `admin-commands.json` | Secret command name → action mapping |
| `admin-signature.key` | Admin's raw signature for NFT #0 (mode 600) |
| `ssl/cert.pem` | TLS certificate |
| `ssl/key.pem` | TLS private key (mode 600) |
| `terraform_ssh_key` | Terraform SSH private key (mode 600) |
| `terraform_ssh_key.pub` | Terraform SSH public key |

Terraform state lives in `/var/lib/blockhost/terraform/`:
- `provider.tf.json` — bpg/proxmox provider config
- `variables.tf.json` — Variable definitions
- `terraform.tfvars` — API token credentials
- `.terraform/` — Initialized providers

---

## Post-Setup Architecture

```
User → Blockchain (purchase subscription)
              ↓
       SubscriptionPurchased event
              ↓
       blockhost-engine (monitors events)
              ↓
       blockhost-provisioner (creates VM via Terraform)
              ↓
       Mints NFT with encrypted connection details
              ↓
       User decrypts from NFT on signup page
              ↓
       User connects via IPv6 + web3 signature (libpam-web3)
```

### IPv6 Routing

```
Outside → Broker (NDP proxy) → WireGuard → Proxmox host
  → kernel: /128 host route via vmbr0 (more specific than /120 on wg-broker)
  → vmbr0 bridge → VM tap → VM eth0
  → VM replies via gateway on vmbr0 → Proxmox forwards → outside
```

- Gateway address (e.g., `::101`) lives as `/128` on `vmbr0` — VMs use it as their default gateway
- WireGuard tunnel has the `/120` prefix on `wg-broker` interface
- Per-VM `/128` host routes via `vmbr0` prevent routing loops

### Smart Contracts

| Contract | Purpose |
|----------|---------|
| AccessCredentialNFT | Stores encrypted connection details per user |
| BlockHostSubscription | Handles payments, emits events for the monitor |

Compiled in submodules during `.deb` builds, deployed during wizard finalization via Foundry `cast`.

### Services

| Service | Purpose |
|---------|---------|
| `blockhost-monitor` (blockhost-engine) | Watches blockchain for subscription events, provisions VMs |
| `blockhost-signup` | Serves the signup/decrypt page |
| `blockhost-gc.timer` | Periodic garbage collection of expired VMs |
| `wg-quick@wg-broker` | WireGuard tunnel to IPv6 broker |

---

## Testing

### Full test cycle

Each iteration: destroy the previous VM, remove the old ISO, rebuild, and boot fresh.

```bash
# 1. Destroy the old test VM (if it exists)
sudo virsh destroy blockhost-test 2>/dev/null
sudo virsh undefine blockhost-test --remove-all-storage

# 2. Remove the old ISO (root-owned from the build process)
sudo rm -f build/blockhost_0.1.0.iso

# 3. Rebuild packages and ISO
./scripts/build-iso.sh --build-deb --testing

# 4. Launch a fresh test VM
sudo virt-install \
    --name blockhost-test \
    --ram 4096 \
    --vcpus 2 \
    --disk size=32 \
    --cdrom build/blockhost_0.1.0.iso \
    --network network=default \
    --graphics vnc
```

After Debian installs and reboots (may need manual `virsh start` — libvirt quirk), first-boot runs and displays the OTP + URL on the console.

### SSH into test instance

```bash
# With test key (if testing mode injected it)
./scripts/ssh-test.sh <IP>

# With password
ssh root@<IP>  # password: blockhost

# Run a command
./scripts/ssh-test.sh <IP> "cat /var/log/blockhost-firstboot.log"
```

### Testing mode features

When built with `--testing`:
- Root password: `blockhost`
- SSH root login enabled
- Apt proxy at `192.168.122.1:3142` (apt-cacher-ng)
- Testing marker at `/etc/blockhost/.testing-mode`
- System validation runs as final finalization step

### Validation

The validation module checks files, permissions, configs, services, and network after finalization:

```bash
# Run manually on the target
cd /opt/blockhost/installer/web
python3 validate_system.py
```

Output saved to `/var/lib/blockhost/validation-output.txt`.

---

## Troubleshooting

### Proxmox services failing after reboot
`/etc/hosts` has `127.0.1.1` entry. Fix: hostname must resolve to real IP.
```bash
cat /etc/hosts
# Should have: 192.168.x.x  blockhost.local  blockhost
# Should NOT have: 127.0.1.1  blockhost.local  blockhost
```

### Web installer unreachable
```bash
systemctl status blockhost-firstboot
cat /var/log/blockhost-firstboot.log
ss -tlnp | grep :80
```

### Contract deployment fails
- Check deployer wallet has ETH for gas
- Verify RPC endpoint: `cast block-number --rpc-url $RPC`
- Check contract artifacts exist in `/usr/share/blockhost/contracts/`

### Template build fails
- Check libpam-web3 `.deb` exists in `/var/lib/blockhost/template-packages/`
- Verify libguestfs is installed: `virt-customize --version`
- Template build can take several minutes

### Finalization stuck or failed
```bash
# Check state
cat /var/lib/blockhost/setup-state.json | python3 -m json.tool

# Check logs
cat /var/log/blockhost-firstboot.log
```

Use the "Retry" button on the failed step in the UI, or "Start Over" to reset.

### IPv6 not working
```bash
# Check WireGuard tunnel
wg show
# Check routes
ip -6 route show | grep -v fe80
# Check forwarding
sysctl net.ipv6.conf.all.forwarding
# Check gateway address on bridge
ip -6 addr show dev vmbr0
```

### VM not reachable via IPv6
Check that the VM has a `/128` host route via `vmbr0`:
```bash
ip -6 route show | grep <vm-ipv6>
# Should show: <vm-ipv6> dev vmbr0
```

---

## Key Implementation Notes

### /etc/hosts (Critical)
Debian preseed creates `127.0.1.1 blockhost.local blockhost`. Proxmox requires the hostname to resolve to the real IP. `first-boot.sh` fixes this before Proxmox installation.

### Systemd + TTY
The first-boot service takes over tty1. Getty is stopped before the script and restarted after. Do NOT use `Conflicts=getty@tty1.service` — it prevents getty from starting even when the condition fails.

### Flask process lifetime
Flask is started with `setsid` to survive the parent script exiting. Without `setsid`, the Flask process dies when `first-boot.sh` finishes.

### Bridge creation
Uses PVE API (`pvesh`) exclusively — editing `/etc/network/interfaces` directly conflicts with PVE's management of that file. `pvesh set /nodes/<node>/network` applies staged changes.

### sslip.io hostname
Derived from the IPv6 gateway address using `ipaddress.IPv6Network`. The compressed IPv6 form with `:` replaced by `-` gives hostnames like `signup.2a11-6c7-f04-276--101.sslip.io`.
