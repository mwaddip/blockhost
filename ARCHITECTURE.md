# ARCHITECTURE — BlockHost

> LLM-optimized reference. Dense, structured, minimal prose.
> Last updated: 2026-02-20

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
│   ├── first-boot.sh                 # Post-install orchestrator (~519 lines)
│   ├── check-build-deps.sh           # Verify build toolchain
│   └── ci-verify-packages.sh         # CI: verify all 6 .debs exist
├── installer/
│   ├── __init__.py
│   ├── common/
│   │   ├── __init__.py
│   │   ├── otp.py                    # OTP generation/validation (301 lines)
│   │   ├── network.py                # Interface detection, DHCP, static (404 lines)
│   │   └── detection.py              # Boot medium detection (220 lines)
│   └── web/
│       ├── __init__.py
│       ├── app.py                    # Flask wizard + routes (~1360 lines)
│       ├── finalize.py              # Finalization pipeline + step functions (~880 lines)
│       ├── utils.py                 # Pure utilities: validation, YAML, disks (~275 lines)
│       ├── validate_system.py        # Post-install validation (~1010 lines)
│       ├── static/                   # CSS, JS assets
│       └── templates/
│           ├── base.html
│           ├── login.html
│           ├── macros/wizard_steps.html
│           └── wizard/
│               ├── network.html
│               ├── storage.html
│               ├── ipv6.html
│               ├── admin_commands.html
│               └── summary.html      # Review + finalization progress UI
├── testing/
│   ├── integration-test-proxmox.sh     # E2E test (Proxmox: PVE API + Terraform cleanup)
│   ├── integration-test-libvirt.sh     # E2E test (libvirt: vm-status + vm-destroy cleanup)
│   ├── ci-config-proxmox.json         # CI config for Proxmox backend
│   ├── ci-config-libvirt.json         # CI config for libvirt backend
│   ├── ipv6-login-test.sh             # IPv6 PAM web3 SSH login test
│   └── ci-provision.sh                # CI: VM lifecycle (create, boot, wizard, finalize)
├── admin/
│   ├── __init__.py
│   ├── __main__.py                   # python3 -m admin entry
│   ├── app.py                        # Flask app factory, session config, CLI
│   ├── auth.py                       # Wallet auth: challenge, verify (bw who), sessions, login_required
│   ├── routes.py                     # Auth routes + protected API endpoints + dashboard
│   ├── system.py                     # Data collection + system actions (~200 lines)
│   ├── templates/
│   │   ├── base.html                 # Dark theme, sidebar nav, topbar wallet + logout
│   │   ├── dashboard.html            # Single-page dashboard, all sections
│   │   └── login.html                # Standalone login: challenge code, wallet signing + paste signature
│   └── static/css/admin.css          # Style overrides (base styles in template)
├── .github/workflows/
│   ├── ci.yml                         # Push/PR: tests + package build
│   ├── iso-build.yml                  # Manual/tag: ISO build (self-hosted)
│   └── integration.yml                # Manual: full integration test (self-hosted)
├── packages/
│   ├── host/                         # .debs installed on host
│   └── template/                     # .debs included in VM templates
└── submodules (READ-ONLY, own repos):
    ├── libpam-web3/
    ├── blockhost-common/
    ├── blockhost-provisioner-proxmox/
    ├── blockhost-provisioner-libvirt/
    ├── blockhost-engine/
    ├── blockhost-engine-opnet/
    ├── blockhost-broker/
    └── facts/
```

## EXECUTION PHASES

### Phase 1: ISO Build (dev machine)

```
build-packages.sh --backend <name> --engine <name>
  → libpam-web3/packaging/build-deb.sh        → packages/template/libpam-web3_*.deb
  → blockhost-common/build.sh                 → packages/host/blockhost-common_*.deb
  → blockhost-provisioner-<backend>/build-deb.sh → packages/host/blockhost-provisioner-<backend>_*.deb
  → blockhost-engine-<engine>/packaging/build.sh → packages/host/blockhost-engine-<engine>_*.deb
  →                                              → packages/template/blockhost-auth-svc_*.deb (if engine produces one)
  → blockhost-broker/scripts/build-deb.sh     → packages/host/blockhost-broker-client_*.deb
  Note: --engine selects which engine submodule to build (e.g., evm, opnet).
        nft_tool CLI is built and shipped inside the engine .deb (replaces former libpam-web3-tools).
        OPNet engine also produces blockhost-auth-svc template package (auth-svc was formerly
        part of libpam-web3-tools which no longer exists). The provisioner's template build
        must install this package into VMs alongside libpam-web3. TODO: provisioner template
        build does not yet know about engine-supplied template packages.

build-iso.sh --backend <name> --engine <name> [--testing] [--build-deb]
  → extract Debian 12 netinst ISO
  → inject preseed/blockhost.preseed into GRUB + isolinux
  → copy installer/, scripts/first-boot.sh, systemd unit
  → copy packages/host/*.deb, packages/template/*.deb
  → extract contract JSON from .deb artifacts → /blockhost/contracts/
  → [--testing]: apt proxy 192.168.122.1:3142, SSH root login, testing marker
  → rebuild ISO with xorriso → build/blockhost_0.3.0.iso (root-owned)
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

  Step 1 (.step-network-wait):        Wait for network
  Step 2 (.step-packages):            Install host .debs + copy template .debs to /var/lib/blockhost/template-packages/
  Step 2b: Verify blockhost user exists (created by blockhost-common .deb)
  Step 2c: Verify root agent running (installed + enabled by blockhost-common .deb), wait for socket
  Step 3 (.step-provisioner-hook):    Run provisioner first-boot hook (from installed manifest)
    → Hook path: manifest.setup.first_boot_hook (e.g. provisioner-hooks/first-boot.sh)
    → Proxmox hook: hostname fix, install proxmox-ve, terraform, libguestfs-tools
    → Receives STATE_DIR, LOG_FILE as env vars; uses own step markers
    → Requires packages installed first (manifest + hook script are in blockhost-provisioner-proxmox.deb)
  Step 3a (.step-bridge):             Create Linux bridge (provisioner-agnostic)
    → Skip if bridge with global IPv4 already exists (handles Proxmox vmbr0, pre-configured systems)
    → Detect primary NIC from default route, skip wireless NICs
    → Create br0, migrate IP from NIC to bridge, verify gateway ping
    → Rollback on connectivity failure (restore IP to NIC, delete bridge)
    → Persist to /etc/network/interfaces (Proxmox will overwrite via pvesh — expected)
    → Store bridge name in /run/blockhost/bridge
  Step 3b (.step-foundry):            Install Foundry (cast, forge, anvil) → /usr/local/bin/ (EVM engine only)
  Step 4 (.step-network):             Verify network connectivity (DHCP fallback)
  Step 5 (.step-otp):                 Generate OTP → /run/blockhost/otp.json, display on /etc/issue
  Step 6:                              Start Flask wizard on :80 (private) or :443 (public)
```

### Phase 4: Web Wizard (browser interaction)

```
Entry: PYTHONPATH=/opt/blockhost python3 -m installer.web.app --host 0.0.0.0 --port 80

Pre-wizard:
  /login                  → OTP verification (6 chars, A-Z2-9, 4hr timeout, 10 attempts)
  /wizard/wallet          → Admin wallet connect + signature (template provided by engine via get_wallet_template())

Wizard steps (WIZARD_STEPS in app.py, dynamically built):
  Core:
  1. /wizard/network        → DHCP or static IP
  2. /wizard/storage         → Disk selection for LVM
  Engine (from engine manifest.setup.wizard_module → Flask Blueprint):
  3. /wizard/<engine>        → chain-specific config (chain_id, rpc_url, wallet, contracts, plan, revenue_share)
  Provisioner (from provisioner manifest.setup.wizard_module → Flask Blueprint):
  4. /wizard/<provisioner>   → provisioner-specific config (ip_pool, gc_grace_days, ...)
  Post:
  5. /wizard/ipv6            → broker allocation or manual prefix
  6. /wizard/admin_commands  → port knocking config
  7. /wizard/summary         → review → POST confirm=yes → /wizard/install

All state stored in Flask session (see SESSION SCHEMA below).
```

### Phase 5: Finalization (background thread)

```
POST /api/finalize → run_finalization_with_state() in thread (finalize.py)
  State file: /var/lib/blockhost/setup-state.json (SetupState class, app.py)
  Poll: GET /api/finalize/status
  Retry: POST /api/finalize/retry {step_id?}
  Reset: POST /api/finalize/reset

Step dispatch (get_finalization_steps() in finalize.py, dynamically built, 5 phases):
  Engine pre-steps (from engine module get_finalization_steps()):
    (varies by engine — e.g. EVM: keypair, wallet, contracts, chain_config)
  Provisioner steps (from provisioner module get_finalization_steps()):
    (varies by provisioner — e.g. Proxmox: token, terraform, template)
  Installer post-steps (hardcoded):
        ipv6        _finalize_ipv6              → broker-client or manual prefix, WireGuard
        https       _finalize_https             → dns_zone hostname (preferred) or sslip.io fallback, Let's Encrypt cert
        signup      _finalize_signup            → blockhost-generate-signup → /var/www/blockhost/signup.html (static)
        nginx       _finalize_nginx             → install nginx, write reverse proxy config, enable (not start)
  Engine post-steps (from engine module get_post_finalization_steps()):
    (varies by engine — e.g. EVM: mint_nft, plan, revenue_share)
  Final steps (hardcoded):
        finalize    _finalize_complete          → .setup-complete marker, enable services, permissions
        validate    _finalize_validate          → System validation (testing mode only)

Each step: skip if completed, mark running → completed|failed, supports retry.
```

### Phase 6: Runtime (post-setup)

```
Services enabled by finalization (all run as User=blockhost except root-agent and nginx):
  blockhost-root-agent.service → Privileged ops daemon (root, installed + enabled by blockhost-common .deb)
  blockhost-monitor.service    → TypeScript event watcher (blockhost-engine)
  blockhost-admin.service      → Admin panel Flask app (127.0.0.1:8443, behind nginx)
  nginx.service                → TLS terminator: signup page (static) + admin panel reverse proxy (:443)
  blockhost-gc.timer           → Daily garbage collection (2 AM)

Subscription purchase flow:
  1. User visits signup page → connects wallet → signs message
  2. Signup page calls BlockhostSubscriptions.buySubscription(planId, days, paymentMethodId, userEncrypted)
     - userEncrypted = ECIES-encrypted data blob (wallet-derived key)
  3. Contract emits SubscriptionCreated event with encrypted user data
  4. blockhost-monitor detects event → enqueues to subscription pipeline (pipeline.json):
     Pipeline stages (each persisted, resumable on crash):
     a. received     — event parsed, entry created
     b. decrypted    — userEncrypted decrypted to user signature via server.key
     c. token_reserved — local next_token_id counter incremented, reserved in vms.json
     d. vm_created   — provisioner create called, JSON summary parsed (ip, vmid, username)
     e. encrypted    — connection details encrypted with user's signature (symmetric AES-GCM)
     f. nft_minted   — blockhost-mint-nft called, actual token ID verified against reserved
     g. db_updated   — markNftMinted() awaited; if token ID mismatch: reservation fixed + GECOS updated
     h. complete     — moved to history, queue drained
     Concurrency: one active pipeline at a time. Additional events queued. Reconciler, fund manager,
     and gas check are blocked (isPipelineBusy) and awaited (not fire-and-forget).
     Retry: exponential backoff (5s base, max 3 retries per stage). Per-stage timeouts.
  5. User retrieves NFT → re-signs publicSecret → derives key → decrypts connection details
  6. VM named: blockhost-XXX (3-digit zero-padded subscription ID)

VM authentication flow (on each SSH login):
  1. SSH connect → PAM module (pam_web3.so) generates OTP
     OTP = HMAC-SHA3(machine_id + timestamp + secret_key), 6 chars
  2. PAM writes session file to /run/libpam-web3/pending/<session_id>.json
     (callback mode detected by directory existence — auth-svc creates the dir via tmpfiles.d)
  3. User sees signing page URL with ?session=<id> (https://{ip}:8443, self-signed TLS)
     Prompt shows "Press Enter after signing in browser (or paste signature):"
  4. Two input paths (first one wins):
     Path A (callback): User opens URL → signing page auto-fills OTP+machine → user signs →
       page POSTs signature to /auth/callback/<session_id> → PAM detects .sig file → authenticates
     Path B (manual): User copies OTP, signs offline, pastes raw hex signature in terminal
  5. PAM verifies identity: EVM = secp256k1 ecrecover, OPNet = Schnorr sig + OTP validation via .sig file
  6. PAM checks wallet=ADDRESS in Linux user GECOS field (no blockchain query)
  7. Match → access granted as that Linux user
  8. PAM cleans up session files
  Note: PAM is scoped to provisioned user only via pam_succeed_if.so guard. Other users get pam_deny.

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

## ADMIN PANEL

Post-install web dashboard for system management. Wallet-based auth (same flow as libpam-web3 SSH login). Runs as standalone Flask app.

```
Entry: python3 -m admin.app --port 8443
Bind: 127.0.0.1:8443 (localhost only — accessed via nginx reverse proxy at configurable prefix, default /admin)
Service: blockhost-admin.service (systemd)
```

Full interface specification: `facts/ADMIN_INTERFACE.md`

### Structure

```
admin/
├── app.py         → create_app() factory, session config, CLI (argparse --port/--host/--debug)
├── auth.py        → Challenge generation, signature verification (bw who + engine constraints), session management, login_required decorator
├── routes.py      → Blueprint "admin", auth routes + protected API + page routes
├── system.py      → Data collection (reads host files/commands), action wrappers
├── root-agent-actions/
│   └── admin_panel.py → Root agent plugin: admin-path-update (nginx + service restart)
├── templates/
│   ├── base.html      → Dark theme, sidebar nav, topbar status, shared JS (apiGet/apiPost/showAlert/formatUptime/formatBytes)
│   ├── system.html    → System & Storage page (hostname, uptime, disk usage, block devices)
│   ├── network.html   → Network & Security page (IPv4, broker, knock settings, admin path)
│   ├── wallet.html    → Wallet & Addressbook page (balances, transfer, withdraw, addressbook CRUD)
│   ├── vms.html       → VMs & Accounts page (VM table with actions, accounts placeholder)
│   └── login.html     → Standalone login page: challenge code, wallet signing + paste-signature paths
└── static/css/    → Style overrides
```

### Authentication

Wallet-signing flow identical to libpam-web3 SSH login. Access is NFT-gated: only the current holder of the admin credential NFT can authenticate.

```
1. Visit any page → redirected to /login (login_required decorator)
2. Login page generates random 6-char OTP (A-Z2-9, no ambiguous chars), shows:
   "Code: A3B7K2  |  Machine: blockhost  |  Sign at: /sign"
3. Two signing paths:
   Path A: Open /sign (serves engine signing page), sign, paste signature
   Path B: Engine-specific inline signing (e.g. MetaMask for EVM), auto-submits
4. POST /api/auth/verify {code, signature}
5. Backend: bw who admin → queries chain for NFT owner → 0x...
6. Backend: bw who "<message>" <signature> → recovers signer address
7. Compare recovered address with NFT owner (case-insensitive)
8. Match → session cookie → redirect to dashboard
```

Message format: `"Authenticate to {hostname} with code: {code}"` — same as PAM module.

Auth state (module-level dicts in auth.py):
- `_challenges`: code → expiry (TTL 300s, one-time use)
- `_sessions`: token → (address, expiry) (TTL 3600s)
- Admin wallet resolved via `bw who admin` → queries `ownerOf(credential_nft_id)` on-chain (cached 60s)
- Signature verification: `bw who <message> <signature>` subprocess (blockhost-engine)
- Format constraints (address/signature patterns): loaded from engine manifest `constraints` key at startup
- If NFT #0 is transferred, the new holder becomes admin — no config changes needed

Session config: `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE=Lax`, `SESSION_COOKIE_SECURE=True`, `PERMANENT_SESSION_LIFETIME=1h`.

### Pages & Cards

| Page | Cards | Read Source | Writable |
|------|-------|-----------|----------|
| System & Storage | System, Storage | `/proc/uptime`, `/etc/os-release`, `lsblk -J`, `shutil.disk_usage()` | Hostname (`hostnamectl`) |
| Network & Security | Network, Security, Admin Path | `ip -j addr/route`, `/etc/resolv.conf`, `broker-allocation.json`, `admin-commands.json`, `admin.json` | Broker lease (root agent), knock settings, admin path (root agent) |
| Wallet | Wallet, Addressbook | `addressbook.json`, `bw balance`, `/opt/blockhost/.env` | Transfer (`bw send`), withdraw (`bw withdraw`), addressbook CRUD (`ab` CLI) |
| VMs & Accounts | VMs, Accounts (placeholder) | `blockhost-vm-list --format json` | Start/stop/kill/destroy via provisioner CLI |

### API Endpoints

```
GET  /login                      → login page (standalone, no auth)
GET  /sign                       → serve signing page HTML
POST /api/auth/verify            → {code, signature} → verify → set session → {"ok": true}
GET  /logout                     → invalidate session → redirect /login

GET  /                           → System & Storage page (@login_required)
GET  /network                    → Network & Security page
GET  /wallet                     → Wallet Management page
GET  /vms                        → VMs & Accounts page

GET  /api/system                 → {hostname, uptime_seconds, os, kernel}
POST /api/system/hostname        → set hostname
GET  /api/network                → {ipv4, gateway, dns, ipv6_broker}
POST /api/network/broker/renew   → root agent broker-renew
GET  /api/security               → admin-commands.json contents
POST /api/security               → update knock settings
GET  /api/admin/path             → {path_prefix}
POST /api/admin/path             → update path prefix (writes admin.json, root agent updates nginx)
GET  /api/storage                → {devices, usage, boot_device}
GET  /api/wallet                 → addressbook.json wallet list [{role, address, can_sign}]
GET  /api/wallet/balance/<role>  → bw balance <role>
POST /api/wallet/send            → bw send (amount, token, from, to)
POST /api/wallet/withdraw        → bw withdraw [token] <to>
POST /api/addressbook/add        → ab add <name> <address>
POST /api/addressbook/remove     → ab del <name>
POST /api/addressbook/generate   → ab new <name>
GET  /api/vms                    → blockhost-vm-list --format json
POST /api/vms/<name>/{start,stop,kill,destroy}
```

All data/action endpoints protected by `@login_required`. All POST actions return `{"ok": bool, "error": "..."}`. VM names validated against `^[a-z0-9-]{1,64}$`.

## ENGINE CONTRACT

Full interface specification: `facts/ENGINE_INTERFACE.md`

One active engine per host. Package installs manifest at well-known path.

### Manifest (`/usr/share/blockhost/engine.json`)

Example (EVM). OPNet uses `name: "opnet"`, `wizard_module: "blockhost.engine_opnet.wizard"`,
32-byte addresses (`^0x[0-9a-fA-F]{64}$`), `native_token: "btc"`. Structure identical.

```json
{
  "name": "evm",
  "version": "0.2.0",
  "display_name": "EVM (Ethereum/Polygon)",
  "setup": {
    "wizard_module": "blockhost.engine_evm.wizard",
    "finalization_steps": ["keypair", "wallet", "contracts", "chain_config"],
    "post_finalization_steps": ["mint_nft", "plan", "revenue_share"]
  },
  "config_keys": { "session_key": "blockchain" },
  "constraints": {
    "address_pattern": "^0x[0-9a-fA-F]{40}$",
    "signature_pattern": "^0x[0-9a-fA-F]{130}$",
    "native_token": "eth",
    "native_token_label": "ETH",
    "token_pattern": "^0x[0-9a-fA-F]{40}$",
    "address_placeholder": "0x..."
  }
}
```

### Discovery (`_discover_engine()` in app.py)

Same pattern as provisioner discovery. Loads manifest JSON, imports wizard module, extracts Flask blueprint.

### Plugin Points

| Extension | Mechanism | Provider |
|-----------|-----------|----------|
| Wizard step | Flask Blueprint via `wizard_module` | Engine .deb |
| Pre-finalization | `get_finalization_steps()` from wizard module | Engine .deb |
| Post-finalization | `get_post_finalization_steps()` from wizard module | Engine .deb |
| Summary section | `get_summary_data()` + `get_summary_template()` | Engine .deb |
| UI parameters | `get_ui_params(session)` → `eng_ui` context variable (optional) | Engine .deb |
| Address validation | `validate_address(address)` → bool | Engine .deb |
| Format constraints | `constraints` in manifest (address/signature/token patterns, native token) | Engine .deb |
| Keypair generation | `generate_keypair()` → (private_key, address) | Engine .deb |
| Progress step metadata | `get_progress_steps_meta()` → list[dict] | Engine .deb |

### Wizard Module Exports

The module at `blockhost.engine_<name>.wizard` must export:

| Export | Type | Description |
|--------|------|-------------|
| `blueprint` | `flask.Blueprint` | Routes for wizard page + API endpoints |
| `get_finalization_steps()` | `-> list[tuple]` | Pre-provisioner steps (keypair, wallet, contracts, config) |
| `get_post_finalization_steps()` | `-> list[tuple]` | Post-nginx steps (mint, plan, revenue_share) |
| `get_summary_data(session_data)` | `-> dict` | Summary values for summary page |
| `get_summary_template()` | `-> str` | Path to custom summary template partial |
| `get_ui_params(session_data)` | `-> dict` | Chain-specific template variables |
| `get_progress_steps_meta()` | `-> list[dict]` | Step metadata for progress UI (id, label, hint) |
| `validate_address(address)` | `-> bool` | Chain-specific address validation |
| `get_wallet_template()` | `-> Optional[str]` | Custom wallet connect template path |
| `validate_signature(sig)` | `-> bool` | Signature format validation |
| `decrypt_config(sig, ciphertext)` | `-> dict` | Decrypt config backup (chain-specific key derivation) |
| `encrypt_config(sig, plaintext)` | `-> str` | Encrypt config backup (chain-specific key derivation) |

## PROVISIONER CONTRACT

Full interface specification: `facts/PROVISIONER_INTERFACE.md`

One active provisioner per host. Package installs manifest at well-known path.

### Manifest (`/usr/share/blockhost/provisioner.json`)

Example (Proxmox). Commands section is identical across provisioners; setup, root_agent_actions,
and config_keys vary. See `facts/PROVISIONER_INTERFACE.md` for the full schema.

```json
{
  "name": "proxmox",
  "version": "0.2.0",
  "display_name": "Proxmox VE + Terraform",
  "commands": { "create": "blockhost-vm-create", "destroy": "blockhost-vm-destroy", "..." : "..." },
  "setup": {
    "first_boot_hook": "/usr/share/blockhost/provisioner-hooks/first-boot.sh",
    "detect": "blockhost-provisioner-detect",
    "wizard_module": "blockhost.provisioner_<name>.wizard",
    "finalization_steps": ["..."]
  },
  "root_agent_actions": "/usr/share/blockhost/root-agent-actions/<name>.py",
  "config_keys": { "session_key": "<name>", "provisioner_config": ["..."] }
}
```

| | Proxmox | libvirt |
|---|---------|---------|
| `finalization_steps` | `["token", "terraform", "bridge", "template"]` | `["storage", "network", "template"]` |
| `root_agent_actions` | `qm.py` | `virsh.py` |
| `config_keys.provisioner_config` | `["terraform_dir", "vmid_range"]` | `["storage_pool"]` |

### Dispatcher (`blockhost.provisioner.ProvisionerDispatcher` in blockhost-common)

Loads manifest, dispatches CLI commands by verb → binary name. Falls back to legacy
hardcoded paths when no manifest exists (transition period).

### Plugin Points

| Extension | Mechanism | Provider |
|-----------|-----------|----------|
| Wizard step | Flask Blueprint via `wizard_module` | Provisioner .deb |
| Finalization | `get_finalization_steps()` from wizard module (3- or 4-tuples) | Provisioner .deb |
| Summary section | `get_summary_data()` + `get_summary_template()` | Provisioner .deb |
| UI parameters | `get_ui_params(session)` → `prov_ui` context variable (optional) | Provisioner .deb |
| First-boot hook | `setup.first_boot_hook` script | Provisioner .deb |
| Root agent actions | `.py` modules in `/usr/share/blockhost/root-agent-actions/` | Provisioner .deb |
| CLI commands | Binaries named in `commands` dict | Provisioner .deb |

### CLI Command Contract

All provisioner commands use `vm_name` (string) as the VM identifier:
- `create <name> --owner-wallet <addr> --nft-token-id <int> [--expiry-days N] [--cpu N] [--memory N] [--disk N] [--apply] [--cloud-init-content <path>]`
- `destroy <name>`, `start <name>`, `stop <name>`, `kill <name>`
- `status <name>` → stdout: `active`, `suspended`, `destroyed`, `unknown`
- `list [--format json]` → stdout: list of VMs

## SESSION SCHEMA

Flask session populated across wizard steps:

```python
session = {
    'authenticated': bool,
    'admin_wallet': str,                # from /wizard/wallet (format: engine-specific)
    'admin_signature': str,             # wallet signature
    'admin_public_secret': str,        # signing message (e.g. 'blockhost-access')
    'selected_disk': '/dev/sda',       # from /wizard/storage

    '<engine_session_key>': {             # from /wizard/<engine> (key from engine manifest config_keys.session_key)
        # Engine-specific keys (e.g. EVM: chain_id, rpc_url, deployer_key, contracts, plan, revenue_share)
        # Structure defined by engine wizard module, not hardcoded in installer
    },

    '<prov_session_key>': {             # from /wizard/<provisioner> (key from provisioner manifest config_keys.session_key)
        'ip_network': '192.168.122.0/24',
        'ip_start': '200',
        'ip_end': '250',
        'gateway': '192.168.122.1',
        'gc_grace_days': 7,
        # ... plus provisioner-specific keys (vmid_range, storage, etc.)
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
        'knock_ports': [22],
        'knock_timeout': 300,
    },
}
```

## CONFIG FILES (written by finalization)

Directory: `/etc/blockhost/`

| File | Format | Owner:Group | Permissions | Written by step | Read by |
|------|--------|-------------|-------------|-----------------|---------|
| server.key | hex 64 chars | root:blockhost | 0640 | engine:keypair | blockhost-engine, provisioner |
| server.pubkey | hex 0x04+... | root:blockhost | 0644 | engine:keypair | signup page, NFT mint |
| deployer.key | hex / mnemonic (engine-specific) | root:blockhost | 0640 | engine:wallet | engine contract calls |
| db.yaml | YAML | root:blockhost | 0644 | provisioner:db_config, installer:ipv6 appends ipv6_pool | blockhost-provisioner, blockhost-gc |
| web3-defaults.yaml | YAML | root:blockhost | 0644 | engine:chain_config | blockhost-engine, blockhost-provisioner-proxmox |
| blockhost.yaml | YAML | root:blockhost | 0644 | engine:chain_config | blockhost-engine, signup generator |
| https.json | JSON | root:blockhost | 0644 | https | nginx config generation |
| pve-token | text | root:blockhost | 0640 | token | blockhost-provisioner-proxmox (Terraform) |
| terraform_ssh_key | PEM | root:blockhost | 0640 | token | Terraform SSH provisioner |
| terraform_ssh_key.pub | PEM | root:blockhost | 0644 | token | VM authorized_keys |
| admin-signature.key | hex | root:blockhost | 0640 | finalize | admin command verification |
| admin-commands.json | JSON | root:blockhost | 0644 | finalize | blockhost-engine src/admin/ |
| broker-allocation.json | JSON | root:blockhost | 0644 | ipv6 | blockhost-broker-client |
| addressbook.json | JSON | root:blockhost | 0640 | engine:revenue_share/root-agent | blockhost-engine fund-manager, bw, ab CLIs |
| revenue-share.json | JSON | root:blockhost | 0644 | engine:revenue_share | blockhost-engine fund-manager |
| hot.key | hex 64 chars | root:blockhost | 0640 | root-agent (auto) | blockhost-engine fund-manager (hot wallet signing) |

### db.yaml structure
```yaml
db_file: /var/lib/blockhost/vms.json
bridge: br0                                        # from first-boot bridge discovery
terraform_dir: /var/lib/blockhost/terraform         # Proxmox only
vmid_range: {start: 100, end: 999}                  # Proxmox only
ip_pool: {network: '192.168.122.0/24', start: 200, end: 250, gateway: '192.168.122.1'}
ipv6_pool: {start: 2, end: 254}
default_expiry_days: 30
gc_grace_days: 7
```

### web3-defaults.yaml structure
```yaml
blockchain: {chain_id: 11155111, rpc_url: str, nft_contract: str, subscription_contract: str, usdc_address: str}
auth: {otp_length: 6, otp_ttl_seconds: 300, public_secret: 'blockhost-access'}
signing_page: {html_path: '/usr/share/blockhost/signing-page/index.html', port: 8443}
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
admin: {wallet_address: '0x...', credential_nft_id: 0, max_command_age: 300, destination_mode: 'self'}
```
`credential_nft_id`: Written by engine's `mint_nft` post-step after minting. Maps the `admin` alias in `bw who admin` to an NFT token ID. Default 0 (first mint).

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
| vms.json.lock | empty | Lockfile for atomic DB updates (separate from data file) |
| pipeline.json | JSON | Subscription pipeline state: active entry, queue, token counter, history (see §11 in ENGINE_INTERFACE.md) |
| terraform/ | dir | Terraform state, provider config, .tfvars, per-VM .tf.json |
| template-packages/ | dir | .debs for VM template builds: libpam-web3_*.deb, blockhost-auth-svc_*.deb (OPNet) |
| validation-output.txt | text | Validation report (testing mode only) |
| fund-manager-state.json | JSON | Fund manager last-run timestamps (auto-created by engine) |

OTP state: `/run/blockhost/otp.json` (tmpfs, cleared on reboot)
Bridge name: `/run/blockhost/bridge` (tmpfs, written by first-boot Step 3a, re-populated on resume)

## SUBMODULE INTERFACES

Each submodule is a separate git repo. This project consumes their .deb outputs only.

### libpam-web3

| Package | Build | Install target | Contents |
|---------|-------|----------------|----------|
| libpam-web3 | packaging/build-deb.sh | VM template-packages/ | PAM module (`pam_web3.so`) |

**PAM module** (Rust, installed in VMs):
- Config: `/etc/pam_web3/config.toml` (machine.id, machine.secret_key, auth settings)
- Auth: verify identity → check `wallet=ADDRESS` in GECOS field (no blockchain query)
- Input detection: raw hex = EVM (ecrecover), JSON `.sig` file = OPNet (OTP + wallet assertion)
- OTP: HMAC-SHA3(machine_id + timestamp + secret_key), 6 chars, 5min TTL
- Callback: detects auth-svc via `/run/libpam-web3/pending/` directory presence (no config flag)
- Security: JSON path only accepted from `.sig` files (callback mode), never from terminal paste
- PAM scope: guarded by `pam_succeed_if.so user = <provisioned_user>`, others get `pam_deny`

**nft_tool** CLI and **auth-svc** are shipped by blockhost-engine (see engine components table).

**Encryption schemes** (ecies.rs): secp256k1 ECIES, x25519, AES-256-GCM

### blockhost-common

| Package | Build | Install target |
|---------|-------|----------------|
| blockhost-common | build.sh | Host |

**Python module** (`blockhost.*`, installed to `/usr/lib/python3/dist-packages/`):

```python
from blockhost.config import load_db_config, load_web3_config, load_blockhost_config
from blockhost.vm_db import VMDatabase, MockVMDatabase, get_database

db = get_database()          # Returns VMDatabase (prod) or MockVMDatabase (--mock)
vmid = db.allocate_vmid()    # Next available VMID from pool
db.reserve_nft_token_id()    # Sequential NFT token ID
db.mark_nft_minted(token_id) # After successful mint
db.mark_nft_failed(token_id) # If VM creation fails (never reuse failed IDs)
```

Reads: `/etc/blockhost/db.yaml`, `/etc/blockhost/web3-defaults.yaml`
Dev mode: `BLOCKHOST_DEV=1` falls back to `./config/` directory

**Dependency**: Required by all provisioner packages and blockhost-engine.

### blockhost-provisioner-proxmox

| Package | Build | Install target |
|---------|-------|----------------|
| blockhost-provisioner-proxmox | build-deb.sh | Proxmox host |

**Scripts**:

| Script | Purpose | Key args |
|--------|---------|----------|
| `vm-generator.py` | Create VM | `<name> --owner-wallet <addr> --nft-token-id <int> [--expiry-days N] [--apply] [--cpu N --memory N --disk N]` |
| `vm-gc.py` | Garbage collect expired VMs | `[--execute] [--suspend-only] [--grace-days N]` |
| `build-template.sh` | Build Debian 12 VM template | `[PROXMOX_HOST=root@ix TEMPLATE_VMID=9001]` |

**vm-generator.py workflow**:
1. Allocate VMID + IPv4 from pool + IPv6 /128 from prefix
2. Derive FQDN from `dns_zone` if available: `f"{offset:x}.{dns_zone}"` (hex offset of IPv6 within prefix)
3. Render cloud-init from `nft-auth.yaml` template (GECOS: `wallet=ADDR,nft=TOKEN_ID`, SIGNING_DOMAIN for HTTPS)
4. Generate `.tf.json` in terraform_dir
5. `terraform apply` (if --apply)
6. Return JSON summary with connection details (ip, vmid, nft_token_id)
Note: NFT token reservation, encryption, and minting are engine responsibilities (see subscription flow).

**Cloud-init templates** (`cloud-init/templates/`):
- `nft-auth.yaml` — Default: web3 NFT auth, GECOS nft=TOKEN_ID
- `webserver.yaml` — Basic webserver
- `devbox.yaml` — Dev environment

**VM naming**: `blockhost-XXX` (3-digit zero-padded subscription ID)

**Dependencies**: blockhost-common, blockhost-engine (nft_tool), Terraform (bpg/proxmox provider), libguestfs-tools

### blockhost-engine

| Package | Build | Install target |
|---------|-------|----------------|
| blockhost-engine | packaging/build.sh | Host |

**Components** (TypeScript, language-specific contracts):

Two engine packages exist: `blockhost-engine` (EVM) and `blockhost-engine-opnet` (OPNet/Bitcoin L1).
Only one is installed per host. Both implement the same ENGINE_INTERFACE.md contract.

| Directory | Language | Purpose |
|-----------|----------|---------|
| `contracts/` | Solidity / OPNet TS | Chain-specific smart contracts |
| `src/monitor/` | TypeScript | Blockchain event polling (watches for subscription events) |
| `src/handlers/` | TypeScript | Event handlers (reserves token ID, calls provisioner, encrypts, mints) |
| `src/admin/` | TypeScript | On-chain admin commands (ECIES-encrypted, anti-replay nonce) |
| `src/reconcile/` | TypeScript | Periodic NFT ownership reconciliation → GECOS sync via provisioner `update-gecos` |
| `src/fund-manager/` | TypeScript | Automated fund withdrawal, revenue sharing, gas management |
| `src/bw/` | TypeScript | blockwallet CLI (`bw send`, `bw balance`, `bw withdraw`, `bw swap`, `bw split`, `bw who`, `bw plan create`, `bw config stable`, `bw set encrypt`) |
| `src/ab/` | TypeScript | addressbook CLI (`ab add`, `ab del`, `ab up`, `ab new`, `ab list`, `ab --init`) |
| `src/is/` | TypeScript | identity predicate CLI (`is <wallet> <nft_id>`, `is contract <address>`) |
| `src/auth-svc/` | TypeScript | Signing page HTTPS server + callback API (installed on VMs via blockhost-auth-svc template pkg, port 8443) |
| `src/nft-tool.ts` | TypeScript | Crypto CLI (keypair gen, encrypt/decrypt-symmetric) — replaces former `pam_web3_tool` |
| `scripts/generate-signup-page` | Python | Generates signup.html from template (extensionless) |
| `scripts/mint_nft` | Python/TS | Mint access credential NFT (extensionless, `--owner-wallet`, `--user-encrypted`) |
| `scripts/deploy-contracts` | Bash/TS | Deploy smart contracts (extensionless) |

**Smart contracts**:

AccessCredentialNFT (ERC721, stripped):
```
mint(address to, bytes userEncrypted)              — owner-only, 2 params
updateUserEncrypted(uint256 tokenId, bytes data)   — owner-only
getUserEncrypted(uint256 tokenId) → bytes           — view
Standard ERC721/Enumerable/Ownable                 — transfer, burn, ownerOf, totalSupply
```
Full spec: `facts/NFT_CONTRACT_INTERFACE.md`

BlockhostSubscriptions:
```
Events (monitored by blockhost-monitor):
  SubscriptionCreated, SubscriptionExtended, SubscriptionCancelled
  PlanCreated, PlanUpdated, PaymentMethodAdded, PaymentMethodUpdated
```
Full spec: chain-specific (EVM: Solidity, OPNet: TypeScript contracts)

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
| blockhost-broker-client | scripts/build-deb.sh | Host (client only) |

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

## KEY FUNCTIONS

### app.py — Flask wizard, routes, state
| Symbol | Purpose |
|--------|---------|
| WIZARD_STEPS | Ordered wizard step list (core + engine + provisioner + post) |
| SETUP_STATE_FILE | Path to setup-state.json |
| class SetupState | Persistent finalization state management |
| _discover_engine() | Load engine manifest + import wizard module |
| _discover_provisioner() | Load provisioner manifest + import wizard module |
| create_app() | Flask app factory with all routes |
| _build_vm_template() | Background template build (uses _jobs) |

### finalize.py — Finalization pipeline
| Function | Purpose |
|----------|---------|
| get_finalization_steps(provisioner, engine) | Build step list (engine pre + provisioner + post + engine post + final) |
| run_finalization_with_state(state, config, prov, engine) | Step dispatcher loop |
| run_finalization(job_id, config, jobs, prov, engine) | Legacy wrapper |
| _finalize_ipv6 | Broker allocation or manual prefix |
| _finalize_https | dns_zone / sslip.io hostname + Let's Encrypt |
| _finalize_signup | blockhost-generate-signup (static file only) |
| _finalize_nginx | Install + configure nginx reverse proxy |
| _finalize_complete | Permissions, markers, enable services |
| _finalize_validate | System validation (testing only) |

### utils.py — Pure utilities (no Flask dependency)
| Function | Purpose |
|----------|---------|
| detect_disks | List available disks (lsblk) |
| is_valid_address | Basic address validation (fallback when no engine loaded) |
| is_valid_ipv6_prefix | Validate prefix/length format |
| get_broker_registry | Look up broker registry by chain_id |
| get_wallet_balance | eth_getBalance via JSON-RPC |
| fetch_broker_registry_from_github | Fetch registry address from GitHub |
| request_broker_allocation | Call blockhost-broker-client CLI |
| write_yaml | Write YAML file (pyyaml or fallback) |
| set_blockhost_ownership | Set file to root:blockhost |
| generate_self_signed_cert | Self-signed cert for run_server |
| generate_self_signed_cert_for_finalization | Self-signed cert for HTTPS step |

## BLOCKCHAIN INTERACTIONS

On-chain calls from the installer (chain-agnostic):

| Action | Tool | Contract | Function | Called by |
|--------|------|----------|----------|-----------|
| Broker allocation | broker-client | BrokerRequests | submitRequest(address,bytes) | _finalize_ipv6 |

On-chain calls from the engine wizard plugin (chain-specific, e.g. EVM):

| Action | Tool | Contract | Function | Called by |
|--------|------|----------|----------|-----------|
| Deploy contracts | blockhost-deploy-contracts CLI | — | — | engine:contracts step |
| Create plan | bw plan create CLI | BlockhostSubscriptions | createPlan(string,uint256) | engine:plan step |
| Set stablecoin | bw config stable CLI | BlockhostSubscriptions | setPrimaryStablecoin(address) | engine:plan step |
| Mint NFT | blockhost-mint-nft CLI | AccessCredentialNFT | mint(address, bytes) | engine:mint_nft step |
| Init addressbook | ab --init CLI | — | — | engine:revenue_share step |

Runtime on-chain interactions (by submodule services, not this repo):

| Action | Service | Contract | Events/Functions |
|--------|---------|----------|-----------------|
| Watch subscriptions | blockhost-monitor (TypeScript) | BlockhostSubscriptions | SubscriptionCreated, SubscriptionExtended, SubscriptionCancelled |
| Query expired | blockhost-gc (Python) | BlockhostSubscriptions | Off-chain expiry check via getSubscription() |
| Admin commands | blockhost-engine src/admin/ | — | ECIES-encrypted on-chain commands |
| NFT reconciliation | blockhost-engine src/reconcile/ | AccessCredentialNFT | Periodic ownership check → GECOS sync via provisioner `update-gecos` |

## NETWORK TOPOLOGY

```
Internet
  │
  ├─ nginx :443 (TLS terminator, Let's Encrypt cert)
  │   ├─ /           → static: /var/www/blockhost/signup.html
  │   └─ {path_prefix}/* → proxy: 127.0.0.1:8443 (Flask admin panel, strips prefix; default /admin, configurable via admin.json)
  │
  ├─ eth0/ens* (physical NIC, bridge port after first-boot Step 3a)
  │
  ├─ br0 (Linux bridge, created by first-boot Step 3a)
  │   │   Proxmox: may be vmbr0 (pre-existing or created by PVE installer)
  │   ├─ Host bridge IP (migrated from NIC; same subnet as VMs)
  │   └─ VM NICs (tap devices)
  │       ├─ VMs get IPv4 from ip_pool range
  │       └─ Each VM serves signing page on port 8443 (HTTPS, self-signed TLS via engine auth-svc)
  │
  └─ wg-broker (WireGuard, if broker mode)
      └─ IPv6 prefix from broker allocation
          ├─ VMs get /128 from ipv6_pool range (host routes added per VM)
          └─ DNS: {hex_offset}.{dns_zone} → prefix::{hex_offset} (broker authoritative DNS)
              └─ Enables Let's Encrypt on VM signing pages (replaces self-signed cert)
```

## PRIVILEGE SEPARATION

### User Model

| User | UID type | Purpose |
|------|----------|---------|
| root | system | Runs root-agent daemon only |
| blockhost | system (nologin) | Runs all other runtime services |

Created by first-boot Step 2b. Group `blockhost` grants read access to config files in `/etc/blockhost/`.

### Root Agent Daemon

`blockhost-root-agent.service` — Python asyncio daemon running as root.

- Socket: `/run/blockhost/root-agent.sock` (root:blockhost 0660, auto-created via `RuntimeDirectory=blockhost`)
- Protocol: 4-byte big-endian length prefix + JSON payload (both directions)
- Response: `{"ok": true, ...}` or `{"ok": false, "error": "reason"}`
- Install path: `/usr/share/blockhost/root-agent/blockhost_root_agent.py` (shipped by blockhost-common .deb)

### Root Agent Action Catalog

Common actions (from blockhost-common):

| Action | Params | Caller |
|--------|--------|--------|
| `ip6-route-add` | address:str(/128), dev:str | provisioner (vm-create) |
| `ip6-route-del` | address:str(/128), dev:str | provisioner (vm-gc, vm-destroy) |
| `iptables-open` | port:int, proto:str, comment:str | engine (admin knock) |
| `iptables-close` | port:int, proto:str, comment:str | engine (admin knock) |
| `virt-customize` | image_path:str, commands:list | provisioner (template build) |
| `generate-wallet` | name:str | engine (fund-manager, ab CLI) |
| `addressbook-save` | entries:dict | engine (fund-manager, ab CLI) |

Proxmox provisioner actions (from `qm.py`):

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

libvirt provisioner actions (from `virsh.py`):

| Action | Params | Caller |
|--------|--------|--------|
| `virsh-start` | name:str | provisioner (vm-resume) |
| `virsh-shutdown` | name:str | provisioner (vm-gc) |
| `virsh-destroy` | name:str | provisioner (vm-gc, vm-destroy) |
| `virsh-reboot` | name:str | provisioner |
| `virsh-define` | xml:str | provisioner (vm-create) |
| `virsh-undefine` | name:str, flags:list | provisioner (vm-destroy) |

### What Runs Without Root

| Operation | Why unprivileged | Service |
|-----------|-----------------|---------|
| `terraform init/apply/destroy` | HTTP API auth, working dir owned by blockhost | provisioner |
| `bw who`, `is contract` | HTTP RPC, reads config via group perm | admin panel, installer validation |
| `nft_tool decrypt/encrypt` | User-space binary, reads keys via group | provisioner, engine |
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
| blockhost-gc | blockhost | Yes (provisioner actions, ip6-route) |
| blockhost-admin | blockhost | Yes (via bw, ab CLIs) |
| nginx | root (master) / www-data (workers) | No |

## ENCRYPTION MODEL

Three distinct encryption contexts:

| Context | Scheme | Key source | Purpose |
|---------|--------|------------|---------|
| NFT user data (userEncrypted) | AES-256-GCM | Chain-specific key derivation from wallet signature of publicSecret | Connection details (hostname, port, username) only decryptable by NFT holder |
| Broker allocation | secp256k1 ECIES | Broker's published public key / client's ephemeral key | Request/response payloads between client and broker |
| Admin commands | ECIES | Admin wallet | On-chain admin commands with anti-replay nonce |

**NFT userEncrypted format**: IV[12 bytes] || ciphertext || authTag[16 bytes] (hex-encoded)
**publicSecret**: Host config value (e.g. `"blockhost-access"`), stored in `blockhost.yaml` → `auth.public_secret`. Not an NFT field.

## TEMPLATE VARIABLES REFERENCE

### Summary template (summary.html) receives:
```python
summary.network.{ip, gateway}
summary.ipv6.{mode, prefix, broker_node, broker_registry}
summary.admin.{wallet, enabled, destination_mode, command_count}

engine_summary           # dict from engine module's get_summary_data(session), or None
engine_summary_template  # template path from engine module's get_summary_template(), or None
provisioner_summary      # dict from provisioner module's get_summary_data(session), or None
provisioner_summary_template  # template path from provisioner module's get_summary_template(), or None

all_finalization_steps   # list[dict] — all steps in pipeline order: {id, label, hint?}
                         # Rendered as dynamic <li> elements in progress list
                         # Source: engine pre + provisioner + installer post + engine post + final
```

### All templates receive (via context_processor):
```python
wizard_steps  # WIZARD_STEPS list for step bar rendering
prov_ui       # dict from provisioner module's get_ui_params(session), or {} if no provisioner
              # Keys: management_url, management_label, knock_ports_default, knock_description,
              #        storage_hint, storage_extra_hint (all optional, templates use | default())
eng_ui        # dict from engine module's get_ui_params(session), or {} if no engine
```

## CI/CD

### Workflows

| Workflow | Trigger | Runner | Jobs |
|----------|---------|--------|------|
| `ci.yml` | Push develop, PR master | ubuntu-latest | rust-tests, engine-tests, forge-tests, build-packages |
| `iso-build.yml` | workflow_dispatch, tag v* | self-hosted (blockhost-iso) | Build ISO, upload artifact |
| `integration.yml` | workflow_dispatch only | self-hosted (blockhost-{proxmox,libvirt}, blockhost-phone) | provision → integration-test → ipv6-login-test → cleanup |

### Test Setup API (`/api/setup-test`)

Testing-only endpoint (legacy). Accepts all wizard config in a single JSON POST.
Not used by CI anymore — CI steps through the wizard pages like a real user.

- **Guard**: Returns 404 unless `/etc/blockhost/.testing-mode` exists (created by `build-iso.sh --testing`)
- **Auth**: Verifies OTP from request body (same as `/login`)
- **Flow**: Populates Flask session → triggers finalization
- **Poll**: Returns `poll_url: /api/finalize/status` (use cookie jar for session)

### CI Provision Script (`testing/ci-provision.sh`)

VM lifecycle automation for integration tests. Steps through the wizard like a real user
(form POSTs to each wizard page, server-side wallet generation, then finalization).

```
Phase 1:    virt-install (ISO boot, virbr0 NAT network)
Phase 2:    Wait for preseed install (VM shuts off)
Phase 3:    Eject ISO, boot from HDD (first-boot begins)
Phase 4:    Poll SSH + /run/blockhost/otp.json (first-boot complete)
Phase 5:    Read OTP via SSH
Phase 5.5:  Step through wizard (login → wallet → network → storage →
            generate-wallet → fund → engine → provisioner → ipv6 → admin)
Phase 6:    POST /api/finalize, poll /api/finalize/status until completed
Phase 7-9:  Read contracts, reboot, verify services
Output:     VM_NAME, VM_IP, NFT_CONTRACT, REQUESTS_CONTRACT (to GITHUB_OUTPUT)
```

Backend is auto-detected from the config file's provisioner section key (e.g., `proxmox` or `libvirt`).

### GitHub Secrets (for integration workflow)

| Secret | Purpose |
|--------|---------|
| `DEPLOYER_KEY` | Deployer private key (owns contracts, funds test wallets) |
| `NFT_CONTRACT` | AccessCredentialNFT address on Sepolia |
| `SUBSCRIPTION_CONTRACT` | BlockhostSubscriptions address on Sepolia |

### Self-Hosted Runner Labels

Single runner on dev machine with four labels:
- `blockhost-iso` — has xorriso, isolinux, build toolchains
- `blockhost-proxmox` — has virsh, virt-install, sshpass, sudo
- `blockhost-libvirt` — same runner, same tools (libvirt and proxmox CI both use virt-install)
- `blockhost-phone` — has adb-connected Android phone with carrier IPv6
