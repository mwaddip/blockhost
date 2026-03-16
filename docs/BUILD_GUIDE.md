# BlockHost Build Guide

**Version**: 0.3.0
**Last Updated**: 2026-02-22
**Base**: Debian 12 (Bookworm) + pluggable backend (Proxmox VE or libvirt)

---

## Overview

BlockHost turns a bare-metal server into an autonomous VM hosting platform driven by blockchain events. Users purchase subscriptions on-chain; the system detects the event, provisions a VM, mints an NFT with encrypted connection details, and the user connects via IPv6 + web3 signature authentication.

**What the ISO does**: Auto-installs Debian 12, runs a first-boot script that installs the selected hypervisor backend and BlockHost packages, then launches a web wizard for configuration.

---

## Quick Start

```bash
# 1. Check and install build dependencies
./scripts/check-build-deps.sh --install

# 2. Build all .deb packages from submodules
./scripts/build-packages.sh --backend libvirt --engine opnet

# 3. Build the ISO (with testing conveniences)
sudo ./scripts/build-iso.sh --backend libvirt --engine opnet --testing

# Or combine steps 2+3:
sudo ./scripts/build-iso.sh --backend libvirt --engine opnet --build-deb --testing
```

Output: `build/blockhost_0.3.0.iso`

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
│   │           ├── network.html       # Step 1
│   │           ├── storage.html       # Step 2
│   │           ├── ipv6.html          # Step 5
│   │           ├── admin_commands.html # Step 6
│   │           ├── summary.html       # Step 7 + finalization
│   │           └── (engine/provisioner templates provided by their .deb packages)
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
│   ├── host/                 # .deb packages for host
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
| `libpam-web3/` | libpam-web3 (template) | PAM module for web3 wallet authentication |
| `blockhost-common/` | blockhost-common | Shared config loading, VM database, root agent daemon |
| `blockhost-provisioner-proxmox/` | blockhost-provisioner-proxmox | VM lifecycle (Proxmox: Terraform + PVE API) |
| `blockhost-provisioner-libvirt/` | blockhost-provisioner-libvirt | VM lifecycle (libvirt: virsh + libvirt API) |
| `blockhost-engine/` | blockhost-engine | Blockchain engine (EVM): monitor, bhcrypt, bw/ab/is CLIs, auth-svc |
| `blockhost-engine-opnet/` | blockhost-engine-opnet | Blockchain engine (OPNet): same interface for Bitcoin L1 |
| `blockhost-broker/` | blockhost-broker-client | IPv6 tunnel broker client |
| `facts/` | — | Shared interface contracts (not a package) |

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
| forge | blockhost-engine (EVM only) | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| node 22+ | blockhost-engine, blockhost-engine-opnet | NodeSource: `curl -fsSL https://deb.nodesource.com/setup_22.x \| bash -` |
| npm | blockhost-engine | (comes with node) |
| python3 | provisioners, blockhost-broker | `apt install python3` |
| git | submodule operations | `apt install git` |
| curl | various downloads | `apt install curl` |

Run `./scripts/check-build-deps.sh` to verify, or `--install` to auto-install what's missing.

---

## Package Build

```bash
./scripts/build-packages.sh --backend <provisioner> --engine <engine>
```

Builds packages in dependency order. The `--backend` and `--engine` flags select which provisioner and engine submodules to build:

| # | Package | Source | Build Command | Destination |
|---|---------|--------|---------------|-------------|
| 1 | libpam-web3 | libpam-web3/ | `packaging/build-deb.sh` | packages/template/ |
| 2 | blockhost-common | blockhost-common/ | `build.sh` | packages/host/ |
| 3 | blockhost-provisioner-\<backend\> | blockhost-provisioner-\<backend\>/ | `build-deb.sh` | packages/host/ |
| 4 | blockhost-engine-\<engine\> | blockhost-engine-\<engine\>/ | `packaging/build.sh` | packages/host/ + packages/template/ |
| 5 | blockhost-broker-client | blockhost-broker/ | `scripts/build-deb.sh` | packages/host/ |

Note: The engine build also produces template packages (e.g., `blockhost-auth-svc`) and bundles `bhcrypt` CLI inside the engine .deb.

Packages must be rebuilt whenever a submodule changes. The ISO copies pre-built `.deb` files — it does not rebuild them.

---

## ISO Build

```bash
sudo ./scripts/build-iso.sh --backend <provisioner> --engine <engine> [--build-deb] [--testing]
```

**Required:**
- `--backend <name>` — Provisioner backend (e.g., `proxmox`, `libvirt`)
- `--engine <name>` — Blockchain engine (e.g., `evm`, `opnet`)

**Flags:**
- `--build-deb` — Run `build-packages.sh` first (passes `--backend` and `--engine` through)
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

| Step | Marker | Description |
|------|--------|-------------|
| 1 | `.step-network-wait` | Wait for network (DHCP) |
| 2 | `.step-packages` | Install host `.deb` packages, copy template `.debs` to template-packages/ |
| 2b | — | Verify `blockhost` user exists (created by blockhost-common .deb) |
| 2c | — | Verify root agent running (installed by blockhost-common .deb), wait for socket |
| 3 | `.step-provisioner-hook` | Run provisioner first-boot hook (e.g. Proxmox: install PVE, Terraform, libguestfs) |
| 3a | `.step-bridge` | Create Linux bridge (br0), migrate IP from NIC, verify connectivity |
| 3b-pre | `.step-nodejs` | Install Node.js 22 LTS via NodeSource (required by engine) |
| 3b | `.step-foundry` | Install Foundry (EVM engine only — for contract deployment via cast/forge) |
| 4 | `.step-network` | Verify network connectivity (DHCP fallback) |
| 5 | `.step-otp` | Generate OTP code, display on console |
| 6 | — | Start Flask web wizard on port 80/443 |

Package install order (respects dependencies):
1. blockhost-common
2. blockhost-provisioner-\<backend\>
3. blockhost-engine-\<engine\>
4. blockhost-broker-client

Template packages (libpam-web3) are copied to `/var/lib/blockhost/template-packages/`.

### Phase 3: Web Wizard

Access via browser at the IP shown on console. Enter OTP to authenticate.

**Pre-wizard gate:** Admin connects wallet and signs a message (signing page template provided by engine). This captures the admin wallet address and signature (used later for NFT #0 encryption).

**Wizard steps** (dynamically built from `WIZARD_STEPS` in `app.py`):

| # | Step | What it configures |
|---|------|--------------------|
| 1 | Network | DHCP or static IP (usually already configured) |
| 2 | Storage | Disk selection for LVM |
| 3 | Engine | Chain-specific config (chain_id, RPC, deployer wallet, contracts, plan, revenue sharing) |
| 4 | Provisioner | Provisioner-specific config (IP pool, storage, VMID range, etc.) |
| 5 | IPv6 | Broker allocation or manual prefix |
| 6 | Admin | Admin commands, port knock config |
| 7 | Summary | Review all settings, start finalization |

The step bar is data-driven from `WIZARD_STEPS` in `app.py` — add/remove steps in one place.

### Phase 4: Finalization

Triggered from the summary page. Steps are dynamically assembled from engine and provisioner plugins, with persistent state in `/var/lib/blockhost/setup-state.json` — supports resume and retry on failure.

| Phase | Steps | Source |
|-------|-------|--------|
| Engine pre | e.g. keypair, wallet, contracts, chain_config | Engine plugin: `get_finalization_steps()` |
| Provisioner | e.g. token, terraform, template (Proxmox) or storage, network, template (libvirt) | Provisioner plugin: `get_finalization_steps()` |
| Installer post | ipv6, https, signup, nginx | Hardcoded in `finalize.py` |
| Engine post | e.g. mint_nft, plan, revenue_share | Engine plugin: `get_post_finalization_steps()` |
| Final | finalize, validate | Hardcoded in `finalize.py` |

---

## Configuration Files

Created during finalization in `/etc/blockhost/`:

| File | Contents |
|------|----------|
| `server.key` | Server private key (mode 0640, root:blockhost) |
| `server.pubkey` | Server public key |
| `deployer.key` | Deployer wallet private key (mode 0640) |
| `db.yaml` | IP pool, IPv6 pool, bridge, provisioner-specific (VMID range, terraform_dir, etc.) |
| `web3-defaults.yaml` | Chain ID, RPC URL, contract addresses, auth settings |
| `blockhost.yaml` | Server keys, deployer ref, provisioner settings, admin config |
| `addressbook.json` | Wallet directory: role → address mappings (mode 0640) |
| `revenue-share.json` | Revenue sharing config |
| `broker-allocation.json` | IPv6 prefix, broker endpoint, WG keys (broker mode) |
| `https.json` | Hostname, cert/key paths |
| `admin-commands.json` | Port knock configuration |
| `admin-signature.key` | Admin's raw signature for NFT #0 (mode 0640) |
| `ssl/cert.pem`, `ssl/key.pem` | TLS certificate + key |

All files owned `root:blockhost`. See `ARCHITECTURE.md` for full details.

---

## Post-Setup Architecture

```
User → Blockchain (purchase subscription)
              ↓
       SubscriptionCreated event
              ↓
       blockhost-monitor (detects event)
              ↓
       Decrypt → Create VM → Encrypt → Mint NFT → Update GECOS → Mark DB
              ↓
       User decrypts connection details from NFT on signup page
              ↓
       User connects via IPv6 + web3 signature (libpam-web3)
```

### IPv6 Routing

```
Outside → Broker (NDP proxy) → WireGuard → BlockHost host
  → kernel: /128 host route via bridge (more specific than /120 on wg-broker)
  → bridge (br0/vmbr0) → VM tap → VM eth0
  → VM replies via gateway on bridge → host forwards → outside
```

- Gateway address (e.g., `::101`) lives as `/128` on the bridge — VMs use it as their default gateway
- WireGuard tunnel has the `/120` prefix on `wg-broker` interface
- Per-VM `/128` host routes via bridge prevent routing loops
- Bridge name is discovered from `db.yaml` (`bridge` key, set during first-boot)

### Smart Contracts

| Contract | Purpose |
|----------|---------|
| AccessCredentialNFT | Stores encrypted connection details per user |
| BlockHostSubscription | Handles payments, emits events for the monitor |

Compiled in submodules during `.deb` builds, deployed during wizard finalization (EVM: Foundry `cast`, OPNet: engine-specific).

### Services

| Service | Purpose |
|---------|---------|
| `blockhost-root-agent` | Privileged operations daemon (runs as root) |
| `blockhost-monitor` (blockhost-engine) | Watches blockchain for subscription events, provisions VMs, fund management |
| `blockhost-admin` | Admin panel Flask app (behind nginx reverse proxy) |
| `nginx` | TLS terminator: signup page (static) + admin panel reverse proxy |
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
sudo rm -f build/blockhost_0.3.0.iso

# 3. Rebuild packages and ISO
sudo ./scripts/build-iso.sh --backend libvirt --engine opnet --build-deb --testing

# 4. Launch a fresh test VM
sudo virt-install \
    --name blockhost-test \
    --ram 4096 \
    --vcpus 2 \
    --disk size=32 \
    --cdrom build/blockhost_0.3.0.iso \
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

### Unit Tests

Three test suites run locally and in CI:

**Solidity — Forge (AccessCredentialNFT)**
```bash
cd libpam-web3/contracts
forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts --no-git
forge test -vv
```
26 tests covering minting, batch minting, data retrieval, updates (userEncrypted, expiration, animationUrl), token URIs with embedded signing pages, ERC721 enumeration/transfers, and expiration logic. Uses `vm.warp()` for time manipulation and `vm.prank()` for access control.

**Solidity — Hardhat (BlockhostSubscriptions)**
```bash
cd blockhost-engine
npm install
npm test
```
39 tests covering plan management, stablecoin/token payments with Uniswap price calculation, subscription lifecycle (create, extend, cancel, expire), fund withdrawal, and security edge cases (low liquidity, slippage). Uses mock ERC20 tokens and a mock Uniswap V2 pair.

**Rust (libpam-web3)**
```bash
cd libpam-web3
cargo test --features nft
```
Compiles and runs any tests in the PAM module and web3-auth-svc. Currently no unit tests — the authentication path is validated through the end-to-end integration test.

### Integration Test

Exercises the full subscription → provisioning → NFT flow on a finalized system:

```bash
# Run on the BlockHost machine as the blockhost user
sudo -u blockhost ./testing/integration-test-proxmox.sh [--cleanup]   # Proxmox
sudo -u blockhost ./testing/integration-test-libvirt.sh [--cleanup]  # libvirt
```

9 phases: pre-flight checks → wallet generation → funding from deployer → message signing → on-chain `buySubscription()` → wait for monitor to detect event + provision VM → verify VM running → verify NFT minted + decrypt `userEncrypted` → cleanup (optional: sweep test ETH, destroy VM, withdraw funds). Backend-specific scripts handle VM verification and cleanup differently (Proxmox uses PVE API + Terraform, libvirt uses `blockhost-vm-status` + `blockhost-vm-destroy`).

Requires: finalized system, `blockhost-engine` running, deployer key, Foundry (`cast`), `bhcrypt`.

### IPv6 Login Test

Proves external users can reach and authenticate to a provisioned VM over carrier IPv6:

```bash
./testing/ipv6-login-test.sh --host <host-ip> --private-key <wallet-key>
```

5 phases: pre-flight (ADB device, tools) → IPv6 ping from phone → SSH port reachability → full PAM login (capture prompt, sign message, feed signature, verify shell) → signing page HTTP check.

Requires: ADB-connected Android phone with carrier IPv6, SSH key to BlockHost host, test wallet key from integration test.

### CI/CD

Three GitHub Actions workflows:

| Workflow | Trigger | Runs on | What |
|----------|---------|---------|------|
| **CI — Tests & Package Build** | Push to `develop`, PR to `master` | GitHub cloud | Forge + Hardhat + Rust tests in parallel, package build + verify |
| **ISO Build** | Manual dispatch, tag push `v*` | Self-hosted (`blockhost-iso`) | Build packages, build ISO, upload artifact on tagged releases |
| **Integration Tests** | Manual dispatch | Self-hosted (`blockhost-proxmox`) | Boot VM from ISO, run wizard via API, run integration test, release IPv6 lease, destroy VM |

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

### Proxmox services failing after reboot (Proxmox backend only)
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
- Check deployer wallet has funds for gas (ETH for EVM, BTC for OPNet)
- Verify RPC endpoint is reachable
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
# Check gateway address on bridge (br0, vmbr0, etc.)
ip -6 addr show dev br0
```

### VM not reachable via IPv6
Check that the VM has a `/128` host route via the bridge:
```bash
ip -6 route show | grep <vm-ipv6>
# Should show: <vm-ipv6> dev br0 (or vmbr0 on Proxmox)
# Bridge name is in /etc/blockhost/db.yaml under 'bridge' key
```

---

## Key Implementation Notes

### /etc/hosts (Critical for Proxmox)
Debian preseed creates `127.0.1.1 blockhost.local blockhost`. Proxmox requires the hostname to resolve to the real IP. The provisioner first-boot hook fixes this before Proxmox installation.

### Systemd + TTY
The first-boot service takes over tty1. Getty is stopped before the script and restarted after. Do NOT use `Conflicts=getty@tty1.service` — it prevents getty from starting even when the condition fails.

### Flask process lifetime
Flask is started with `setsid` to survive the parent script exiting. Without `setsid`, the Flask process dies when `first-boot.sh` finishes.

### Bridge creation
First-boot Step 3a creates a Linux bridge (br0) provisioner-agnostically. On Proxmox, this may be superseded by vmbr0 created during PVE installation. The bridge name is stored in `/run/blockhost/bridge` and later in `db.yaml`.

### sslip.io hostname
Derived from the IPv6 gateway address using `ipaddress.IPv6Network`. The compressed IPv6 form with `:` replaced by `-` gives hostnames like `signup.2a11-6c7-f04-276--101.sslip.io`.
