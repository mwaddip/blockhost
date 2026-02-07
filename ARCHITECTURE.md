# ARCHITECTURE — BlockHost

> LLM-optimized reference. Dense, structured, minimal prose.
> Last updated: 2026-02-07

## FILE MAP

```
blockhost/
├── CLAUDE.md                          # Session rules, submodule constraints
├── ARCHITECTURE.md                    # THIS FILE
├── docs/BUILD_GUIDE.md                # Human build reproduction guide
├── docs/INFRASTRUCTURE.md             # Human infrastructure reference + extension guides
├── docs/STANDARDS.md                  # Development standards and conventions
├── preseed/blockhost.preseed          # Debian auto-install config (93 lines)
├── systemd/blockhost-firstboot.service # Runs first-boot.sh after install
├── scripts/
│   ├── build-iso.sh                   # ISO builder (419 lines)
│   ├── build-packages.sh             # Build all submodule .debs (213 lines)
│   ├── first-boot.sh                 # Post-install orchestrator (430 lines)
│   └── check-build-deps.sh           # Verify build toolchain
├── installer/
│   ├── __init__.py
│   ├── common/
│   │   ├── __init__.py
│   │   ├── otp.py                    # OTP generation/validation (301 lines)
│   │   ├── network.py                # Interface detection, DHCP, static (404 lines)
│   │   └── detection.py              # Boot medium detection (220 lines)
│   └── web/
│       ├── __init__.py
│       ├── app.py                    # Flask wizard + finalization (3142 lines)
│       ├── validate_system.py        # Post-install validation (778 lines)
│       ├── static/                   # CSS, JS assets
│       └── templates/
│           ├── base.html
│           ├── login.html
│           ├── macros/wizard_steps.html
│           └── wizard/
│               ├── wallet.html       # Admin wallet connect (pre-wizard)
│               ├── network.html
│               ├── storage.html
│               ├── blockchain.html   # Chain, RPC, wallet, contracts, plan
│               ├── proxmox.html
│               ├── ipv6.html
│               ├── admin_commands.html
│               └── summary.html      # Review + finalization progress UI
├── root-agent/
│   ├── blockhost_root_agent.py       # Root agent daemon (~350 lines)
│   ├── blockhost-root-agent.service  # systemd unit for root agent
│   └── client.py                     # Sync Python client for installer
├── packages/
│   ├── host/                         # .debs installed on Proxmox host
│   └── template/                     # .debs included in VM templates
└── submodules (READ-ONLY, own repos):
    ├── libpam-web3/
    ├── blockhost-common/
    ├── blockhost-provisioner/
    ├── blockhost-engine/
    └── blockhost-broker/
```

## EXECUTION PHASES

### Phase 1: ISO Build (dev machine)

```
build-packages.sh
  → libpam-web3/packaging/build-deb-tools.sh  → packages/host/libpam-web3-tools_*.deb
  → libpam-web3/packaging/build-deb.sh        → packages/template/libpam-web3_*.deb
  → blockhost-common/build.sh                 → packages/host/blockhost-common_*.deb
  → blockhost-provisioner/build-deb.sh        → packages/host/blockhost-provisioner_*.deb
  → blockhost-engine/packaging/build.sh       → packages/host/blockhost-engine_*.deb
  → blockhost-broker/scripts/build-deb.sh     → packages/host/blockhost-broker-client_*.deb

build-iso.sh [--testing] [--build-deb]
  → extract Debian 12 netinst ISO
  → inject preseed/blockhost.preseed into GRUB + isolinux
  → copy installer/, scripts/first-boot.sh, systemd unit
  → copy packages/host/*.deb, packages/template/*.deb
  → extract contract JSON from .deb artifacts → /blockhost/contracts/
  → [--testing]: apt proxy 192.168.122.1:3142, SSH root login, testing marker
  → rebuild ISO with xorriso → build/blockhost_0.1.0.iso (root-owned)
```

### Phase 2: Preseed Install (target machine, automatic)

```
blockhost.preseed:
  locale=en_US.UTF-8, timezone=UTC
  partitioning: LVM, full disk
  root password: blockhost
  packages: python3, python3-flask, curl, wget, openssh-server, sudo
  late_command:
    cp -r /cdrom/blockhost /opt/blockhost
    enable blockhost-firstboot.service
    [testing: configure apt proxy, SSH root]
  → reboot
```

### Phase 3: First Boot (target machine)

```
blockhost-firstboot.service → /opt/blockhost/first-boot.sh
  State dir: /var/lib/blockhost/
  Log: /var/log/blockhost-firstboot.log
  Completion marker: /var/lib/blockhost/.setup-complete

  Step 1 (.step-hostname):  Fix /etc/hosts for Proxmox (IP → hostname)
  Step 2 (.step-proxmox):   Install proxmox-ve, postfix, chrony
  Step 2b (.step-packages):  Install host .debs + copy template .debs to /var/lib/blockhost/template-packages/
  Step 2b1 (.step-user):     Create blockhost system user/group, chown /var/lib/blockhost, /etc/blockhost
  Step 2b2 (.step-root-agent): Install root agent daemon, enable + start service, wait for socket
  Step 2c (.step-foundry):   Install Foundry (cast, forge, anvil) → /usr/local/bin/
  Step 2d (.step-terraform): Install Terraform + libguestfs (virt-customize, virt-sysprep)
  Step 3 (.step-network):   Verify network connectivity (DHCP fallback)
  Step 4 (.step-otp):       Generate OTP → /run/blockhost/otp.json, display on /etc/issue
  Step 5:                    Start Flask wizard on :80 (private) or :443 (public)
```

### Phase 4: Web Wizard (browser interaction)

```
Entry: PYTHONPATH=/opt/blockhost python3 -m installer.web.app --host 0.0.0.0 --port 80

Pre-wizard:
  /login                  → OTP verification (6 chars, A-Z2-9, 4hr timeout, 10 attempts)
  /wizard/wallet          → Admin MetaMask wallet connect + signature

Wizard steps (WIZARD_STEPS in app.py:52-60):
  1. /wizard/network        → DHCP or static IP
  2. /wizard/storage         → Disk selection for LVM
  3. /wizard/blockchain      → chain_id, rpc_url, wallet (generate/import), contracts (deploy/existing), plan_name, plan_price_cents, revenue_share_*
  4. /wizard/proxmox         → node, storage, bridge, vmid_range, ip_pool, gc_grace_days
  5. /wizard/ipv6            → broker allocation or manual prefix
  6. /wizard/admin_commands  → port knocking config
  7. /wizard/summary         → review → POST confirm=yes → /wizard/install

All state stored in Flask session (see SESSION SCHEMA below).
```

### Phase 5: Finalization (background thread)

```
POST /api/finalize → _run_finalization_with_state() in thread
  State file: /var/lib/blockhost/setup-state.json (SetupState class, app.py:69-204)
  Poll: GET /api/finalize/status
  Retry: POST /api/finalize/retry {step_id?}
  Reset: POST /api/finalize/reset

Step dispatch (app.py:1486-1500):
  #   step_id     function                    line
  1   keypair     _finalize_keypair           1581   → server.key, server.pubkey
  2   wallet      _finalize_wallet            1610   → deployer.key
  3   contracts   _finalize_contracts         1630   → deploy via cast or verify existing
  4   config      _finalize_config            1791   → db.yaml, web3-defaults.yaml, blockhost.yaml
  5   token       _finalize_token             1951   → Proxmox API token via pveum
  6   terraform   _finalize_terraform         1994   → provider.tf.json, variables.tf.json, terraform init
  7   bridge      _finalize_bridge            2136   → vmbr0 via pvesh
  8   ipv6        _finalize_ipv6              2319   → broker-client or manual prefix, WireGuard
  9   https       _finalize_https             2485   → sslip.io hostname, Let's Encrypt cert
  10  signup      _finalize_signup            2613   → generate-signup-page.py → /var/www/blockhost/signup.html
  11  mint_nft    _finalize_mint_nft          2717   → Mint NFT #0 to admin wallet
  12  template    _finalize_template          2798   → Build Debian VM template with libpam-web3
  13  finalize    _finalize_complete          2863   → .setup-complete marker, enable services, create plan
  14  validate    _finalize_validate          2911   → System validation (testing mode only)

Each step: skip if completed, mark running → completed|failed, supports retry.
```

### Phase 6: Runtime (post-setup)

```
Services enabled by finalization step 13 (all run as User=blockhost except root-agent):
  blockhost-root-agent.service → Privileged ops daemon (root, started in Step 2b2)
  blockhost-monitor.service    → TypeScript event watcher (blockhost-engine)
  blockhost-signup.service     → Serve signup page (HTTPS)
  blockhost-gc.timer           → Daily garbage collection (2 AM)

Subscription purchase flow:
  1. User visits signup page → connects wallet → signs message
  2. Signup page calls BlockhostSubscriptions.buySubscription(planId, days, paymentMethodId, userEncrypted)
     - userEncrypted = ECIES-encrypted data blob (wallet-derived key)
  3. Contract emits SubscriptionCreated event with encrypted user data
  4. blockhost-monitor detects event → calls vm-generator.py:
     - Reserves NFT token ID (sequential, tracked in vms.json)
     - Allocates VMID + IPv4 from pool + IPv6 /128 from prefix
     - Generates .tf.json with cloud-init (nft-auth template, GECOS: nft=TOKEN_ID)
     - Runs terraform apply → VM created on Proxmox
     - Encrypts connection details: pam_web3_tool encrypt-symmetric
       Key derivation: keccak256(user_signature_bytes) → AES-256-GCM key
     - Mints NFT via cast send → mint(to, userEncrypted, publicSecret, description, imageUri, animationUrlBase64, expiresAt)
  5. User retrieves NFT → re-signs publicSecret → derives AES key → decrypts connection details
  6. VM named: blockhost-XXX (3-digit zero-padded subscription ID)

VM authentication flow (on each SSH login):
  1. SSH connect → PAM module (pam_web3.so) generates OTP
     OTP = HMAC-SHA3(machine_id + timestamp + secret_key), 6 chars
  2. User sees OTP + signing page URL
  3. User signs: "Authenticate to {machine_id} with code: {otp}"
  4. PAM recovers wallet via secp256k1 ecrecover
  5. PAM queries web3-auth-svc (Unix socket: /run/web3-auth/web3-auth.sock) for wallet's NFT token IDs
  6. Matches token ID against Linux user GECOS field (nft=TOKEN_ID)
  7. Match → access granted as that Linux user

Expiry flow:
  blockhost-gc.py (daily via systemd timer) checks expired subscriptions
    Phase 1 (suspend): QEMU shutdown, disk preserved
    Phase 2 (destroy): after gc_grace_days, delete disk + Terraform state + IPv6 host route

Extension flow:
  User calls extendSubscription() on-chain
    → monitor detects SubscriptionExtended event
    → resume suspended VM (if within grace period)

Admin commands flow:
  Admin signs command on-chain (ECIES-encrypted, anti-replay nonce)
    → blockhost-engine src/admin/ processes command
    → e.g. port knocking: temporarily open ports on VM
```

## SESSION SCHEMA

Flask session populated across wizard steps:

```python
session = {
    'authenticated': bool,
    'admin_wallet': '0x...',           # from /wizard/wallet
    'admin_signature': '0x...',        # MetaMask signature
    'admin_public_secret': str,        # ECIES shared secret
    'selected_disk': '/dev/sda',       # from /wizard/storage

    'blockchain': {                     # from /wizard/blockchain
        'chain_id': '11155111',
        'rpc_url': 'https://...',
        'wallet_mode': 'generate'|'import',
        'deployer_key': '0x...',
        'contract_mode': 'deploy'|'existing',
        'nft_contract': '0x...',       # only if existing
        'subscription_contract': '0x...',
        'plan_name': 'Basic VM',
        'plan_price_cents': 50,
        'revenue_share_enabled': bool,
        'revenue_share_percent': 1.0,
        'revenue_share_dev': bool,
        'revenue_share_broker': bool,
    },

    'proxmox': {                        # from /wizard/proxmox
        'api_url': 'https://127.0.0.1:8006',
        'node': 'proxmox',
        'storage': 'local-lvm',
        'bridge': 'vmbr0',
        'user': 'root@pam',
        'template_vmid': 9001,
        'vmid_start': 100,
        'vmid_end': 999,
        'ip_network': '192.168.122.0/24',
        'ip_start': '200',
        'ip_end': '250',
        'gateway': '192.168.122.1',
        'gc_grace_days': 7,
    },

    'ipv6': {                           # from /wizard/ipv6
        'mode': 'broker'|'manual',
        'prefix': '2001:db8::/48',
        'broker_registry': '0x...',
        'broker_node': str,
        'wg_config': str,
        'allocation_size': 64,
    },

    'admin_commands': {                 # from /wizard/admin_commands
        'enabled': bool,
        'destination_mode': 'self'|'external',
        'knock_command': 'blockhost',
        'knock_ports': [22, 8006],
        'knock_timeout': 300,
        'knock_max_duration': 600,
    },
}
```

## CONFIG FILES (written by finalization)

Directory: `/etc/blockhost/`

| File | Format | Owner:Group | Permissions | Written by step | Read by |
|------|--------|-------------|-------------|-----------------|---------|
| server.key | hex 64 chars | root:blockhost | 0640 | keypair | blockhost-engine, provisioner |
| server.pubkey | hex 0x04+... | root:blockhost | 0644 | keypair | signup page, NFT mint |
| deployer.key | hex 64 chars | root:blockhost | 0640 | wallet | contract calls (cast send) |
| db.yaml | YAML | root:blockhost | 0644 | config | blockhost-provisioner, blockhost-gc |
| web3-defaults.yaml | YAML | root:blockhost | 0644 | config | blockhost-engine, blockhost-provisioner |
| blockhost.yaml | YAML | root:blockhost | 0644 | config | blockhost-engine, signup generator |
| https.json | JSON | root:blockhost | 0644 | https | blockhost-signup |
| pve-token | text | root:blockhost | 0640 | token | blockhost-provisioner (Terraform) |
| terraform_ssh_key | PEM | root:blockhost | 0640 | token | Terraform SSH provisioner |
| terraform_ssh_key.pub | PEM | root:blockhost | 0644 | token | VM authorized_keys |
| admin-signature.key | hex | root:blockhost | 0640 | config | admin command verification |
| admin-commands.json | JSON | root:blockhost | 0644 | config | blockhost-engine src/admin/ |
| broker-allocation.json | JSON | root:blockhost | 0644 | ipv6 | blockhost-broker-client |
| addressbook.json | JSON | root:blockhost | 0640 | finalize/root-agent | blockhost-engine fund-manager, bw, ab CLIs |
| revenue-share.json | JSON | root:blockhost | 0644 | finalize | blockhost-engine fund-manager |
| hot.key | hex 64 chars | root:blockhost | 0640 | root-agent (auto) | blockhost-engine fund-manager (hot wallet signing) |

### db.yaml structure
```yaml
db_file: /var/lib/blockhost/vms.json
terraform_dir: /var/lib/blockhost/terraform
vmid_range: {start: 100, end: 999}
ip_pool: {network: '192.168.122.0/24', start: 200, end: 250, gateway: '192.168.122.1'}
ipv6_pool: {start: 2, end: 254}
default_expiry_days: 30
gc_grace_days: 7
```

### web3-defaults.yaml structure
```yaml
blockchain: {chain_id: 11155111, rpc_url: str, nft_contract: str, subscription_contract: str, usdc_address: str}
auth: {otp_length: 6, otp_ttl_seconds: 300, public_secret: 'blockhost-access'}
signing_page: {html_path: '/usr/share/libpam-web3-tools/signing-page/index.html'}
deployer: {private_key_file: '/etc/blockhost/deployer.key'}
server: {public_key: '0x04...'}
```

### blockhost.yaml structure
```yaml
server: {address: '0x...', key_file: '/etc/blockhost/server.key'}
deployer: {key_file: '/etc/blockhost/deployer.key'}
proxmox: {node: str, storage: str, bridge: str}
server_public_key: '0x04...'
public_secret: 'blockhost-access'
admin: {wallet_address: '0x...', max_command_age: 300, destination_mode: 'self'}
```

### addressbook.json structure
```json
{
  "admin":  { "address": "0x1234...abcd" },
  "server": { "address": "0x5678...ef01", "keyfile": "/etc/blockhost/deployer.key" },
  "dev":    { "address": "0xe35B5D114eFEA216E6BB5Ff15C261d25dB9E2cb9" },
  "broker": { "address": "0x6A5973DDe7E57686122Eb12DA85389c53fe2EE4b" }
}
```
Maps role names to wallet objects. Each entry has `address` (required) and optionally `keyfile` (path to private key, only for wallets whose keys live on this machine). Always written during finalization. The engine's fundManager auto-generates a `hot` entry on first launch.
- `admin`: always present — the operator's wallet, connected via MetaMask during the wizard wallet step
- `server`: always present — the deployer wallet address (derived from deployer key), with `keyfile`
- `dev`: only present when operator opted in to dev revenue sharing
- `broker`: only present when operator opted in to broker revenue sharing AND a broker allocation exists; address read from `broker_wallet` in `broker-allocation.json` (recorded by broker-client from the broker's `submitResponse` transaction sender)

### revenue-share.json structure
```json
{
  "enabled": true,
  "total_percent": 1.0,
  "recipients": [
    {"role": "dev", "percent": 0.5},
    {"role": "broker", "percent": 0.5}
  ]
}
```
Revenue sharing config. References roles by name (wallets in addressbook.json). Percent split equally among selected recipients.

## STATE FILES (runtime)

Directory: `/var/lib/blockhost/`

| File | Format | Purpose |
|------|--------|---------|
| .setup-complete | empty | Marker: setup finished (prevents re-run) |
| setup-state.json | JSON | Finalization progress (steps, status, config) |
| vms.json | JSON | VM database (vmid → metadata, IP, NFT token, subscription, expiry) |
| terraform/ | dir | Terraform state, provider config, .tfvars, per-VM .tf.json |
| template-packages/ | dir | libpam-web3_*.deb for VM template builds |
| validation-output.txt | text | Validation report (testing mode only) |
| fund-manager-state.json | JSON | Fund manager last-run timestamps (auto-created by engine) |

OTP state: `/run/blockhost/otp.json` (tmpfs, cleared on reboot)

## SUBMODULE INTERFACES

Each submodule is a separate git repo. This project consumes their .deb outputs only.

### libpam-web3

Two packages for different targets:

| Package | Build | Install target | Contents |
|---------|-------|----------------|----------|
| libpam-web3-tools | packaging/build-deb-tools.sh | Proxmox host | `pam_web3_tool` CLI, signing-page HTML, contract artifacts (AccessCredentialNFT.json, BlockhostSubscriptions.json) |
| libpam-web3 | packaging/build-deb.sh | VM template-packages/ | PAM module (`pam_web3.so`), `web3-auth-svc` daemon |

**PAM module** (Rust, installed in VMs):
- Config: `/etc/pam_web3/config.toml` (machine.id, machine.secret_key, auth.mode, blockchain.*)
- Wallet mode: file-based wallet→username mapping (`/etc/pam_web3/wallets`)
- NFT mode (v0.4.0+): ownership-based auth, no server private key needed
  - Queries `web3-auth-svc` via Unix socket `/run/web3-auth/web3-auth.sock`
  - Matches wallet's NFT token IDs against GECOS field (`nft=TOKEN_ID`)
- OTP: HMAC-SHA3(machine_id + timestamp + secret_key), 6 chars, 5min TTL
- Signature: secp256k1 ecrecover of `"Authenticate to {machine_id} with code: {otp}"`

**pam_web3_tool** CLI (on host):
- `generate-keypair` — secp256k1 keypair for ECIES
- `encrypt-symmetric` — AES-256-GCM encryption, key = keccak256(signature_bytes)
- Used by provisioner to encrypt connection details into NFT

**web3-auth-svc** (daemon in VMs):
- Handles blockchain queries for PAM module
- Communicates via Unix socket

**Contract artifacts**: extracted from libpam-web3-tools .deb during ISO build → `/opt/blockhost/contracts/`

**Encryption schemes** (ecies.rs): secp256k1 ECIES, x25519, AES-256-GCM

### blockhost-common

| Package | Build | Install target |
|---------|-------|----------------|
| blockhost-common | build.sh | Proxmox host |

**Python module** (`blockhost.*`, installed to `/usr/lib/python3/dist-packages/`):

```python
from blockhost.config import load_db_config, load_web3_config, get_terraform_dir
from blockhost.vm_db import VMDatabase, MockVMDatabase, get_database

db = get_database()          # Returns VMDatabase (prod) or MockVMDatabase (--mock)
vmid = db.allocate_vmid()    # Next available VMID from pool
db.reserve_nft_token_id()    # Sequential NFT token ID
db.mark_nft_minted(token_id) # After successful mint
db.mark_nft_failed(token_id) # If VM creation fails (never reuse failed IDs)
```

Reads: `/etc/blockhost/db.yaml`, `/etc/blockhost/web3-defaults.yaml`
Dev mode: `BLOCKHOST_DEV=1` falls back to `./config/` directory

**Dependency**: Required by blockhost-provisioner and blockhost-engine.

### blockhost-provisioner

| Package | Build | Install target |
|---------|-------|----------------|
| blockhost-provisioner | build-deb.sh | Proxmox host |

**Scripts**:

| Script | Purpose | Key args |
|--------|---------|----------|
| `vm-generator.py` | Create VM + mint NFT | `<name> --owner-wallet <0x> [--user-signature <0x> --public-secret <str>] [--apply] [--cpu N --memory N --disk N]` |
| `vm-gc.py` | Garbage collect expired VMs | `[--execute] [--suspend-only] [--grace-days N]` |
| `mint_nft.py` | Mint access NFT | `--owner-wallet <0x> --machine-id <name> [--user-encrypted <0x> --public-secret <str>] [--dry-run]` |
| `build-template.sh` | Build Debian 12 VM template | `[PROXMOX_HOST=root@ix TEMPLATE_VMID=9001]` |

**vm-generator.py workflow**:
1. Reserve sequential NFT token ID in vms.json
2. Allocate VMID + IPv4 from pool + IPv6 /128 from prefix
3. Render cloud-init from `nft-auth.yaml` template (GECOS: `nft=TOKEN_ID`)
4. Generate `.tf.json` in terraform_dir
5. `terraform apply` (if --apply)
6. On success: encrypt connection details via `pam_web3_tool encrypt-symmetric`
7. Mint NFT: `cast send <nft_contract> "mint(address,bytes,string,string,string,string,uint256)" <to> <userEncrypted> <publicSecret> <description> <imageUri> <animationUrlBase64> <expiresAt>`

**Cloud-init templates** (`cloud-init/templates/`):
- `nft-auth.yaml` — Default: web3 NFT auth, GECOS nft=TOKEN_ID
- `webserver.yaml` — Basic webserver
- `devbox.yaml` — Dev environment

**VM naming**: `blockhost-XXX` (3-digit zero-padded subscription ID)

**Dependencies**: blockhost-common, libpam-web3-tools, Terraform (bpg/proxmox provider), Foundry (cast), libguestfs-tools

### blockhost-engine

| Package | Build | Install target |
|---------|-------|----------------|
| blockhost-engine | packaging/build.sh | Proxmox host |

**Components** (TypeScript + Solidity):

| Directory | Language | Purpose |
|-----------|----------|---------|
| `contracts/` | Solidity | BlockhostSubscriptions.sol — plans, subscriptions, payments |
| `src/monitor/` | TypeScript | Blockchain event polling (watches for subscription events) |
| `src/handlers/` | TypeScript | Event handlers (calls vm-generator.py, vm-gc.py) |
| `src/admin/` | TypeScript | On-chain admin commands (ECIES-encrypted, anti-replay nonce) |
| `src/reconcile/` | TypeScript | Periodic NFT state reconciliation (health check) |
| `src/fund-manager/` | TypeScript | Automated fund withdrawal, revenue sharing, gas management |
| `src/bw/` | TypeScript | blockwallet CLI (`bw send`, `bw balance`, `bw withdraw`, `bw swap`, `bw split`) |
| `src/ab/` | TypeScript | addressbook CLI (`ab add`, `ab del`, `ab up`, `ab new`, `ab list`) |
| `scripts/generate-signup-page.py` | Python | Generates signup.html from template |
| `scripts/init-server.sh` | Bash | Generate server keys + config |

**Smart contract — BlockhostSubscriptions.sol**:

```
Admin functions:
  createPlan(string name, uint256 pricePerDayUsdCents)
  setPrimaryStablecoin(address tokenAddress)
  addPaymentMethod(address token, address uniswapPair, address stablecoin)

User functions:
  buySubscription(uint256 planId, uint256 days, uint256 paymentMethodId, bytes userEncrypted)
  extendSubscription(uint256 subscriptionId, uint256 days, uint256 paymentMethodId)
  cancelSubscription(uint256 subscriptionId)

Query functions:
  getSubscription(subscriptionId) → Subscription struct
  isSubscriptionActive(subscriptionId) → bool
  getExpiredSubscriptions(offset, limit) → array
  getSubscriptionsExpiringSoon(withinSeconds, offset, limit) → array

Events (monitored by blockhost-monitor):
  SubscriptionCreated, SubscriptionExtended, SubscriptionCancelled
  PlanCreated, PlanUpdated
  PaymentMethodAdded, PaymentMethodUpdated
```

**Payment methods**:
- ID 1 (primary stablecoin): Direct USD, no conversion. `amount = priceUsdCents * days * 10^decimals / 100`
- ID 2+ (other tokens): Uniswap V2 constant product pricing with 1% slippage buffer, $10k minimum liquidity

**Fund manager** (integrated into monitor polling loop):
- Runs fund cycle (every 24h default): withdraw contract funds → hot wallet gas top-up → server stablecoin buffer → revenue shares → remainder to admin
- Runs gas check (every 30min default): top up hot wallet ETH, swap USDC→ETH if server low
- Hot wallet auto-generated on first fund cycle, key saved to `/etc/blockhost/hot.key` (0600), added to addressbook.json as `hot` entry
- Config: `fund_manager:` key in `blockhost.yaml` (all settings have defaults, section optional)
- Reads: `addressbook.json`, `revenue-share.json`

**Services**:
- `blockhost-monitor.service` — Event watcher + fund manager (TypeScript: `npm run monitor`)
- Maintenance scheduler — suspend/destroy lifecycle for expired subscriptions

**Config reads**: `/etc/blockhost/web3-defaults.yaml`, `/etc/blockhost/blockhost.yaml`, `/etc/blockhost/admin-commands.json`, `/etc/blockhost/addressbook.json`, `/etc/blockhost/revenue-share.json`

### blockhost-broker

| Package | Build | Install target |
|---------|-------|----------------|
| blockhost-broker-client | scripts/build-deb.sh | Proxmox host (client only) |

**Client CLI** (`broker-client`, Python):

| Command | Purpose |
|---------|---------|
| `request --nft-contract <0x> --wallet-key <path>` | Request IPv6 allocation |
| `status` | Check allocation status |
| `list-brokers` | List available brokers from registry |
| `install` | Install persistent WireGuard config |
| `release --wallet-key <path> [--cleanup-wg]` | Release allocation |

**On-chain allocation flow**:
1. Client queries `BrokerRegistry` (global contract) for available brokers
2. Client generates WireGuard keypair + ECIES keypair
3. Client encrypts request with broker's public key (secp256k1 ECIES)
4. Client calls `BrokerRequests.submitRequest(nftContract, encryptedPayload)`
   - Auth: broker verifies NFT contract exists + `Ownable.owner() == msg.sender`
5. Broker daemon (Rust) detects request via lazy polling
6. Broker allocates prefix from SQLite IPAM, adds WireGuard peer
7. Broker encrypts response with client's public key
8. Broker calls `BrokerRequests.submitResponse(requestId, encryptedPayload)`
9. Client decrypts response → configures WireGuard tunnel

**Re-requests**: Same NFT contract submitting a new request gets the same allocation with updated WireGuard public key (supports key rotation without losing prefix).

**Contracts (Sepolia)**:
- BrokerRegistry: `0x0E5b567E7d5C5c36D8fD70DE8129c35B473d0Aaf`
- Registry config: https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry.json

**Broker daemon** (Rust, runs on separate VPS — NOT on Proxmox host):
- WireGuard on port 51820
- SQLite IPAM database
- Config: `/etc/blockhost-broker/config.toml` (includes `wireguard.upstream_interface` for NDP proxy)
- ECIES keypair: `/etc/blockhost-broker/ecies.key`
- Silent rejections (invalid requests just expire)
- NDP proxy: auto-manages proxy entries for allocated prefixes on upstream interface (e.g. SIT tunnels); configures `net.ipv6.conf.all.forwarding=1`, `proxy_ndp=1`, UFW rules

**Broker manager** (separate package, Flask web UI on port 8443):
- Wallet-based auth (MetaMask + nonce signing)
- View/release active leases, wallet info + ETH top-up
- Configurable session expiry (default 1hr, `SESSION_LIFETIME_HOURS`)

## KEY FUNCTIONS (app.py line index)

### Constants & Setup
| Line | Symbol |
|------|--------|
| 44 | CHAIN_NAMES dict |
| 52 | WIZARD_STEPS list |
| 66 | SETUP_STATE_FILE path |
| 69 | class SetupState |

### Routes
| Line | Route | Method |
|------|-------|--------|
| 269 | / | GET → redirect |
| 279 | /login | GET, POST |
| 314 | /wizard/wallet | GET, POST |
| 339 | /wizard/network | GET, POST |
| 388 | /wizard/storage | GET, POST |
| 404 | /wizard/blockchain | GET, POST |
| 430 | /wizard/proxmox | GET, POST |
| 458 | /wizard/ipv6 | GET, POST |
| 490 | /wizard/admin-commands | GET, POST |
| 524 | /wizard/summary | GET, POST |
| 586 | /wizard/install | GET |
| 848 | /api/finalize | POST |
| 901 | /api/finalize/status | GET |
| 908 | /api/finalize/retry | POST |
| 967 | /api/finalize/reset | POST |
| 1019 | /api/validation-output | GET |

### API endpoints (AJAX from wizard UI)
| Line | Route | Purpose |
|------|-------|---------|
| 604+ | /api/blockchain/generate-wallet | Generate new secp256k1 keypair |
| ~650 | /api/blockchain/validate-key | Validate imported private key |
| ~700 | /api/blockchain/balance | Check wallet balance via RPC |
| ~750 | /api/blockchain/deploy-contracts | Deploy contracts (unused, finalization does this) |

### Finalization functions
| Line | Function | Purpose |
|------|----------|---------|
| 1483 | _run_finalization_with_state | Step dispatcher loop |
| 1581 | _finalize_keypair | Generate server secp256k1 key |
| 1610 | _finalize_wallet | Write deployer.key |
| 1630 | _finalize_contracts | Deploy or verify contracts |
| 1693 | _deploy_contract_with_forge | Deploy contract via cast send --create |
| 1791 | _finalize_config | Write YAML config files |
| 1951 | _finalize_token | Create Proxmox API token (pveum) |
| 1994 | _finalize_terraform | Generate .tf.json, terraform init |
| 2136 | _finalize_bridge | Configure vmbr0 (pvesh) |
| 2319 | _finalize_ipv6 | Broker allocation or manual prefix |
| 2485 | _finalize_https | sslip.io hostname + Let's Encrypt |
| 2613 | _finalize_signup | generate-signup-page.py |
| 2717 | _finalize_mint_nft | Mint NFT #0 to admin wallet |
| 2798 | _finalize_template | Build Debian VM template |
| 2863 | _finalize_complete | Enable services, create subscription plan |
| 2911 | _finalize_validate | System validation (testing only) |
| 2940 | _create_default_plan | Call createPlan() on subscription contract |

### Helpers
| Line | Function | Purpose |
|------|----------|---------|
| 1040 | _detect_disks | List available disks (lsblk) |
| 1068 | _detect_proxmox_resources | Query PVE for storage, bridges |
| 1142 | _generate_secp256k1_keypair | Generate wallet keypair |
| 1229 | _get_address_from_key | Derive address from private key |
| 1267 | _is_valid_address | Validate 0x + 40 hex |
| 1298 | _get_broker_registry | Look up broker registry by chain_id |
| 1309 | _get_wallet_balance | eth_getBalance via JSON-RPC |
| 1346 | _fetch_broker_registry_from_github | Fetch registry address from GitHub |
| 1378 | _request_broker_allocation | Call blockhost-broker-client CLI |
| 3017 | _write_yaml | Write YAML file helper |

## BLOCKCHAIN INTERACTIONS

All on-chain calls from this repo use Foundry `cast` CLI:

| Action | Tool | Contract | Function | Called by |
|--------|------|----------|----------|-----------|
| Deploy NFT | cast send --create | AccessCredentialNFT | constructor(name, symbol, imageUri) | _finalize_contracts |
| Deploy Subscription | cast send --create | BlockhostSubscriptions | constructor(nftContract) | _finalize_contracts |
| Create plan | cast send | BlockhostSubscriptions | createPlan(string,uint256) | _create_default_plan |
| Set stablecoin | cast send | BlockhostSubscriptions | setPrimaryStablecoin(address) | _create_default_plan |
| Mint NFT | cast send | AccessCredentialNFT | mint(address,bytes,string,string,string,string,uint256) | provisioner mint_nft.py |
| Check balance | JSON-RPC | — | eth_getBalance | _get_wallet_balance |
| Broker allocation | broker-client | BrokerRequests | submitRequest(address,bytes) | _finalize_ipv6 |

Runtime on-chain interactions (by submodule services, not this repo):

| Action | Service | Contract | Events/Functions |
|--------|---------|----------|-----------------|
| Watch subscriptions | blockhost-monitor (TypeScript) | BlockhostSubscriptions | SubscriptionCreated, SubscriptionExtended, SubscriptionCancelled |
| Query expired | blockhost-gc (Python) | BlockhostSubscriptions | getExpiredSubscriptions() |
| Admin commands | blockhost-engine src/admin/ | — | ECIES-encrypted on-chain commands |
| NFT reconciliation | blockhost-engine src/reconcile/ | AccessCredentialNFT | Periodic ownership health check |

## NETWORK TOPOLOGY

```
Internet
  │
  ├─ eth0/ens* (physical NIC)
  │   └─ Host IP (DHCP or static, configured in wizard step 1)
  │
  ├─ vmbr0 (Linux bridge, created by finalization step 7)
  │   ├─ Host bridge IP (same subnet as VMs)
  │   └─ VM NICs (tap devices)
  │       ├─ VMs get IPv4 from ip_pool range
  │       └─ Each VM serves signing page on port 8080
  │
  └─ wg-broker (WireGuard, if broker mode)
      └─ IPv6 prefix from broker allocation
          └─ VMs get /128 from ipv6_pool range (host routes added per VM)
```

## PRIVILEGE SEPARATION

### User Model

| User | UID type | Purpose |
|------|----------|---------|
| root | system | Runs root-agent daemon only |
| blockhost | system (nologin) | Runs all other runtime services |

Created by first-boot Step 2b1. Group `blockhost` grants read access to config files in `/etc/blockhost/`.

### Root Agent Daemon

`blockhost-root-agent.service` — Python asyncio daemon running as root.

- Socket: `/run/blockhost/root-agent.sock` (root:blockhost 0660, auto-created via `RuntimeDirectory=blockhost`)
- Protocol: 4-byte big-endian length prefix + JSON payload (both directions)
- Response: `{"ok": true, ...}` or `{"ok": false, "error": "reason"}`
- Install path: `/usr/share/blockhost/root-agent/blockhost_root_agent.py`

### Root Agent Action Catalog

| Action | Params | Caller |
|--------|--------|--------|
| `qm-start` | vmid:int | provisioner (vm-resume), engine (cancellation) |
| `qm-stop` | vmid:int | provisioner (vm-gc) |
| `qm-shutdown` | vmid:int | provisioner (vm-gc) |
| `qm-destroy` | vmid:int | provisioner (vm-gc) |
| `qm-create` | vmid:int, name:str, args:list | provisioner (vm-generator) |
| `qm-importdisk` | vmid:int, disk_path:str, storage:str | provisioner |
| `qm-set` | vmid:int, options:dict | provisioner |
| `qm-template` | vmid:int | provisioner |
| `ip6-route-add` | address:str(/128), dev:str | provisioner (vm-generator) |
| `ip6-route-del` | address:str(/128), dev:str | provisioner (vm-gc) |
| `iptables-open` | port:int, proto:str, comment:str | engine (admin knock) |
| `iptables-close` | port:int, proto:str, comment:str | engine (admin knock) |
| `virt-customize` | image_path:str, commands:list | installer (template build) |
| `generate-wallet` | name:str | engine (fund-manager, ab CLI) |
| `addressbook-save` | entries:dict | engine (fund-manager, ab CLI) |

### What Runs Without Root

| Operation | Why unprivileged | Service |
|-----------|-----------------|---------|
| `terraform init/apply/destroy` | HTTP API auth, working dir owned by blockhost | provisioner |
| `cast call/send` | HTTP RPC, reads deployer key via group perm (0640) | provisioner |
| `pam_web3_tool decrypt/encrypt` | User-space binary, reads keys via group | provisioner, engine |
| `pgrep` | No privilege needed | engine (reconcile) |
| python3 db scripts | Writes to blockhost-owned `/var/lib/blockhost/` | engine |

### File Ownership Summary

| Path | Owner:Group | Mode |
|------|-------------|------|
| `/etc/blockhost/` | root:blockhost | 750 |
| `/etc/blockhost/*.key` | root:blockhost | 640 |
| `/etc/blockhost/*.yaml` | root:blockhost | 640 |
| `/var/lib/blockhost/` | blockhost:blockhost | 750 |
| `/var/lib/blockhost/terraform/` | blockhost:blockhost | 750 |
| `/run/blockhost/root-agent.sock` | root:blockhost | 660 |
| `/opt/blockhost/.env` | root:blockhost | 640 |

### Runtime Services

| Service | User | Depends on root-agent |
|---------|------|-----------------------|
| blockhost-root-agent | root | — |
| blockhost-monitor | blockhost | Yes (iptables, wallet, addressbook) |
| blockhost-gc | blockhost | Yes (qm, ip6-route) |
| blockhost-signup | blockhost | No |

## ENCRYPTION MODEL

Three distinct encryption contexts:

| Context | Scheme | Key source | Purpose |
|---------|--------|------------|---------|
| NFT user data (userEncrypted) | AES-256-GCM | keccak256(user's wallet signature of publicSecret) | Connection details (hostname, port, username) only decryptable by NFT holder |
| Broker allocation | secp256k1 ECIES | Broker's published public key / client's ephemeral key | Request/response payloads between client and broker |
| Admin commands | ECIES | Admin wallet | On-chain admin commands with anti-replay nonce |

**NFT userEncrypted format**: IV[12 bytes] || ciphertext || authTag[16 bytes] (hex-encoded)
**publicSecret format**: `"libpam-web3:<checksumAddress>:<nonce>"`

## TEMPLATE VARIABLES REFERENCE

### Summary template (summary.html) receives:
```python
summary.network.{ip, gateway}
summary.blockchain.{chain_id, network_name, rpc_url, deployer_address, deploy_contracts, nft_contract, subscription_contract, plan_name, plan_price_cents, revenue_share_enabled, revenue_share_percent, revenue_share_dev, revenue_share_broker}
summary.proxmox.{node, storage, bridge, vmid_start, vmid_end, ip_start, ip_end, gc_grace_days}
summary.ipv6.{mode, prefix, broker_node, broker_registry}
summary.admin.{wallet, enabled, destination_mode, command_count}
```

### All templates receive (via context_processor, app.py:243):
```python
wizard_steps  # WIZARD_STEPS list for step bar rendering
```
