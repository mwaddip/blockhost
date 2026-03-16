# Infrastructure Reference

This document covers how BlockHost components connect, what they read and write, and how to extend the system.

For build instructions, see [BUILD_GUIDE.md](BUILD_GUIDE.md). For coding conventions, see [STANDARDS.md](STANDARDS.md).

---

## System Overview

BlockHost runs on a dedicated host with a pluggable provisioner backend (e.g., Proxmox, libvirt). After installation, the system has two user contexts:

| User | Runs | Purpose |
|------|------|---------|
| `root` | `blockhost-root-agent` | Privileged operations daemon (only component needing root) |
| `blockhost` | Everything else | Engine, provisioner, GC, signup server |

### Directory layout

```
/etc/blockhost/           # Configuration (root:blockhost 750)
    *.yaml                #   Structured config files
    *.key                 #   Private keys (0640, group-readable)
    addressbook.json      #   Wallet directory (0640)
    ssl/                  #   TLS certificate + key

/var/lib/blockhost/       # Runtime state (blockhost:blockhost 750)
    vms.json              #   VM database
    terraform/            #   Terraform state + per-VM configs
    setup-state.json      #   Finalization progress
    template-packages/    #   .debs for VM template builds

/run/blockhost/           # Ephemeral (tmpfs, cleared on reboot)
    root-agent.sock       #   Root agent Unix socket (root:blockhost 660)
    otp.json              #   OTP state during installation

/opt/blockhost/           # Application files (from ISO)
    installer/            #   Flask wizard
    scripts/              #   First-boot script
    .env                  #   Environment for blockhost-monitor
```

---

## Component Interfaces

### Engine → Provisioner

The engine spawns provisioner scripts as subprocesses:

```
blockhost-vm-create <name> --owner-wallet <0x> [--nft-token-id <int>] [--expiry-days N] [--apply]
blockhost-vm-start <name>
blockhost-vm-stop <name>
blockhost-vm-destroy <name>
blockhost-vm-status <name>
blockhost-vm-list [--format json]
```

Both run as the `blockhost` user. The provisioner reads config from `/etc/blockhost/` and writes state to `/var/lib/blockhost/`.

### Services → Root Agent

Any service needing a privileged operation connects to `/run/blockhost/root-agent.sock` using a length-prefixed JSON protocol:

```
[4-byte big-endian length][JSON request]  →  [4-byte big-endian length][JSON response]
```

Request: `{"action": "qm-start", "params": {"vmid": 100}}`
Response: `{"ok": true, "output": "..."}` or `{"ok": false, "error": "reason"}`

Client libraries:
- Python: `from blockhost.root_agent import qm_start, ip6_route_add, ...` (in blockhost-common)
- TypeScript: `import { iptablesOpen, generateWallet, ... } from "./root-agent/client"` (in blockhost-engine)

### Root Agent Action Catalog

Common actions (from blockhost-common):

| Action | Parameters | Used by |
|--------|-----------|---------|
| `ip6-route-add/del` | `address` (/128), `dev` | Provisioner (generator, GC) |
| `iptables-open/close` | `port`, `proto`, `comment` | Engine (admin knock) |
| `virt-customize` | `image_path`, `commands` | Provisioner (template build) |
| `generate-wallet` | `name` | Engine (fund-manager, `ab new`) |
| `addressbook-save` | `entries` | Engine (fund-manager, `ab` CLI) |

Proxmox provisioner actions:

| Action | Parameters | Used by |
|--------|-----------|---------|
| `qm-start/stop/shutdown/destroy` | `vmid` | Provisioner (GC, resume) |
| `qm-create` | `vmid`, `name`, `args` | Provisioner (generator) |
| `qm-set` | `vmid`, `options` | Provisioner |
| `qm-importdisk` | `vmid`, `disk_path`, `storage` | Provisioner |
| `qm-template` | `vmid` | Provisioner |

libvirt provisioner actions:

| Action | Parameters | Used by |
|--------|-----------|---------|
| `virsh-start` | `name` | Provisioner (resume) |
| `virsh-shutdown/destroy` | `name` | Provisioner (GC, destroy) |
| `virsh-reboot` | `name` | Provisioner |
| `virsh-define` | `xml` | Provisioner (vm-create) |
| `virsh-undefine` | `name`, `flags` | Provisioner (destroy) |

### blockhost-common (shared library)

Installed to `/usr/lib/python3/dist-packages/blockhost/`. Provides:

- `blockhost.config` — `load_db_config()`, `load_web3_config()`, `get_terraform_dir()`
- `blockhost.vm_db` — `VMDatabase`, `MockVMDatabase`, `get_database()` (allocate VMIDs, reserve NFT token IDs, track VM state)
- `blockhost.root_agent` — client library for the root agent daemon

### bhcrypt (shipped by blockhost-engine)

Installed on the host via the engine package. Provides:
- `bhcrypt` CLI — `decrypt`, `encrypt-symmetric`, `decrypt-symmetric`, `generate-keypair`, `derive-pubkey`
- Contract artifacts — `AccessCredentialNFT.json`, `BlockhostSubscriptions.json`

Key derivation for symmetric operations is engine-specific (EVM: keccak256, OPNet: SHAKE256). Wire format is identical: IV(12) + ciphertext + tag(16). ECIES is identical across engines.

---

## Configuration Files

### `/etc/blockhost/` — written during finalization, read at runtime

| File | Format | Mode | Written by | Read by |
|------|--------|------|-----------|---------|
| `server.key` | hex (64 chars) | 0640 | Finalization (keypair) | Engine, provisioner |
| `server.pubkey` | hex (0x04...) | 0644 | Finalization (keypair) | Signup page |
| `deployer.key` | hex (64 chars) | 0640 | Finalization (wallet) | Cast (contract calls) |
| `db.yaml` | YAML | 0644 | Finalization (config) | Provisioner, GC |
| `web3-defaults.yaml` | YAML | 0644 | Finalization (config) | Engine, provisioner |
| `blockhost.yaml` | YAML | 0644 | Finalization (config) | Engine, signup generator |
| `https.json` | JSON | 0644 | Finalization (https) | Signup service |
| `terraform_ssh_key` | PEM | 0640 | Finalization (terraform) | Terraform SSH |
| `terraform_ssh_key.pub` | PEM | 0644 | Finalization (terraform) | VM authorized_keys |
| `admin-signature.key` | hex | 0640 | Finalization (config) | Admin command verification |
| `admin-commands.json` | JSON | 0644 | Finalization (config) | Engine admin handler |
| `broker-allocation.json` | JSON | 0644 | Finalization (ipv6) | Broker client |
| `addressbook.json` | JSON | 0640 | Finalization / root agent | Engine fund-manager, `bw`, `ab` |
| `revenue-share.json` | JSON | 0644 | Finalization | Engine fund-manager |
| `hot.key` | hex (64 chars) | 0640 | Root agent (auto) | Engine fund-manager |

All files are owned `root:blockhost`. The `blockhost` user reads them via group permission.

### `/var/lib/blockhost/` — runtime state

| File | Format | Purpose |
|------|--------|---------|
| `.setup-complete` | empty | Marker: setup finished (prevents re-run) |
| `setup-state.json` | JSON | Finalization progress tracking |
| `vms.json` | JSON | VM database (VMID, IP, NFT token, subscription, expiry) |
| `vms.json.lock` | empty | Lockfile for atomic DB updates (separate from data file) |
| `pipeline.json` | JSON | Reserved for future use |
| `terraform/` | directory | Terraform state, provider config, per-VM `.tf.json` |
| `template-packages/` | directory | `.deb` files for VM template builds |
| `fund-manager-state.json` | JSON | Fund manager last-run timestamps (auto-created by engine) |
| `validation-output.txt` | text | Post-install validation report (testing mode) |

All owned `blockhost:blockhost`.

### Key config structures

**db.yaml:**
```yaml
db_file: /var/lib/blockhost/vms.json
terraform_dir: /var/lib/blockhost/terraform
vmid_range: {start: 100, end: 999}
ip_pool: {network: '192.168.122.0/24', start: 200, end: 250, gateway: '192.168.122.1'}
ipv6_pool: {start: 2, end: 254}
gc_grace_days: 7
```

**web3-defaults.yaml:**
```yaml
blockchain: {chain_id: 11155111, rpc_url: 'https://...', nft_contract: '0x...', subscription_contract: '0x...'}
deployer: {private_key_file: '/etc/blockhost/deployer.key'}
server: {public_key: '0x04...'}
```

**blockhost.yaml:**
```yaml
server: {address: '0x...', key_file: '/etc/blockhost/server.key'}
deployer: {key_file: '/etc/blockhost/deployer.key'}
admin: {wallet_address: '0x...', destination_mode: 'self'}
# Proxmox provisioner adds: proxmox: {node, storage, bridge}
```

**addressbook.json:**
```json
{
  "admin":  {"address": "0x..."},
  "server": {"address": "0x...", "keyfile": "/etc/blockhost/deployer.key"},
  "dev":    {"address": "0x..."},
  "hot":    {"address": "0x...", "keyfile": "/etc/blockhost/hot.key"}
}
```

---

## Encryption Model

Three distinct encryption contexts are used:

**NFT user data** — connection details encrypted so only the NFT holder can decrypt them.
- Scheme: AES-256-GCM
- Key derivation: engine-specific (EVM: `keccak256(signature)`, OPNet: `SHAKE256(signature)`)
- The server encrypts at VM creation time; the user re-signs the same message to derive the decryption key.

**Broker allocation** — request/response payloads between broker client and broker daemon.
- Scheme: secp256k1 ECIES
- Keys: broker's published public key + client's ephemeral key

**Admin commands** — on-chain admin commands with anti-replay protection.
- Scheme: ECIES with admin wallet key
- Includes nonce for replay prevention

---

## Network Topology

```
Internet
  |
  +-- eth0/ens* (physical NIC, bridge port after first-boot)
  |
  +-- br0 (Linux bridge, created by first-boot Step 3a)
  |     Proxmox: may be vmbr0 (pre-existing or created by PVE installer)
  |     +-- Host bridge IP (migrated from NIC; same subnet as VMs)
  |     +-- VM NICs (tap devices, IPv4 from ip_pool)
  |
  +-- wg-broker (WireGuard, if broker mode)
        +-- IPv6 prefix from broker allocation
        +-- VMs get /128 host routes via bridge
```

Each VM gets an IPv4 address from the configured pool and optionally an IPv6 `/128` from the broker-allocated prefix. IPv6 host routes (`ip -6 route replace <addr>/128 dev <bridge>`) are added by the provisioner via the root agent when a VM is created, and removed by GC when a VM is destroyed. The bridge name is stored in `db.yaml` under the `bridge` key.

---

## Installer Flow

### Phase 1: First boot (`scripts/first-boot.sh`)

Runs once after Debian auto-install. Each step writes a marker file so it can resume if interrupted.

| Step | Marker | Action |
|------|--------|--------|
| 1 | `.step-network-wait` | Wait for network (DHCP) |
| 2 | `.step-packages` | Install host `.deb` packages, copy template `.deb`s |
| 2b | — | Verify `blockhost` user exists (from blockhost-common .deb) |
| 2c | — | Verify root agent running, wait for socket |
| 3 | `.step-provisioner-hook` | Run provisioner first-boot hook (hypervisor install, etc.) |
| 3a | `.step-bridge` | Create Linux bridge (br0), migrate IP, verify connectivity |
| 3b-pre | `.step-nodejs` | Install Node.js 22 LTS via NodeSource (required by engine) |
| 3b | `.step-foundry` | Install Foundry (`cast`, `forge`, `anvil`) — EVM engine only |
| 4 | `.step-network` | Verify network connectivity (DHCP fallback) |
| 5 | `.step-otp` | Generate OTP code, display on console |
| 6 | — | Start Flask web wizard on port 80/443 |

### Phase 2: Web wizard (`installer/web/app.py`)

The wizard collects configuration through 7 steps. All state is stored in the Flask session.

| Step | URL | Configures |
|------|-----|-----------|
| Pre | `/wizard/wallet` | Admin wallet connection (wallet signing, template from engine) |
| 1 | `/wizard/network` | DHCP or static IP |
| 2 | `/wizard/storage` | Disk selection for LVM |
| 3 | `/wizard/<engine>` | Chain-specific config (chain_id, RPC, deployer wallet, contracts, plan, revenue sharing) |
| 4 | `/wizard/<provisioner>` | Provisioner-specific config (IP pool, storage, VMID range, etc.) |
| 5 | `/wizard/ipv6` | Broker allocation or manual prefix |
| 6 | `/wizard/admin_commands` | Port knocking configuration |
| 7 | `/wizard/summary` | Review all settings, confirm |

### Phase 3: Finalization (background thread)

After confirmation, `POST /api/finalize` starts a background thread that runs 14 steps sequentially. Progress is tracked in `setup-state.json` and polled by the frontend via `GET /api/finalize/status`.

| Phase | Step IDs | Source | Action |
|-------|----------|--------|--------|
| Engine pre | e.g. `keypair`, `wallet`, `contracts`, `chain_config` | `engine.get_finalization_steps()` | Engine-specific setup (keys, wallet, deploy, config) |
| Provisioner | e.g. `token`, `terraform`, `template` (Proxmox) or `storage`, `network`, `template` (libvirt) | `provisioner.get_finalization_steps()` | Provisioner-specific setup |
| Installer post | `ipv6`, `https`, `signup`, `nginx` | Hardcoded in `finalize.py` | Broker/manual prefix, TLS cert, signup page, nginx reverse proxy |
| Engine post | e.g. `mint_nft`, `plan`, `revenue_share` | `engine.get_post_finalization_steps()` | NFT #0 mint, subscription plan, revenue sharing |
| Final | `finalize`, `validate` | Hardcoded in `finalize.py` | Enable services, permissions, marker; validation (testing only) |

Each step: checks if already completed, marks running, executes, marks completed or failed. Failed steps can be retried via `POST /api/finalize/retry`.

---

## Extending the Installer

### Adding a wizard step

1. **Add to `WIZARD_STEPS`** in `app.py` (line ~53) — this controls the step bar rendering.
2. **Create a template** in `installer/web/templates/wizard/<step_id>.html`.
3. **Add a route** in `create_app()`: `@app.route('/wizard/<step_id>', methods=['GET', 'POST'])`.
4. **Store data in session** — all wizard state lives in `session[<key>]`.
5. **Update `summary.html`** to display the new step's data for review.
6. **Update ARCHITECTURE.md** — add the route to the routes table and session schema.

### Adding a finalization step

1. **Write the function**: `def _finalize_<name>(config: dict) -> tuple[bool, Optional[str]]` — return `(True, None)` on success, `(False, error_message)` on failure.
2. **Add to `_default_state()`** in `SetupState` — add `'<name>': {'status': 'pending', 'error': None, 'completed_at': None}`.
3. **Add to `step_order`** in `get_next_step()` — controls execution order.
4. **Add to the dispatch dict** in `_run_finalization_with_state()`.
5. **Make it idempotent** — the function may be called again on retry. Check if the work is already done before repeating it.

### Adding a first-boot step

1. **Define a marker**: `STEP_NAME="${STATE_DIR}/.step-name"`.
2. **Guard with marker check**: `if [ ! -f "$STEP_NAME" ]; then ... touch "$STEP_NAME"; fi`.
3. **Insert in order** — steps run sequentially, each guarded by its own marker.

---

## Extending the Root Agent

### Adding a new command

1. **Write handler** in `blockhost-common: usr/share/blockhost/root-agent/blockhost_root_agent.py`:
   ```python
   def handle_my_action(params):
       # Validate params strictly
       # Execute the privileged operation
       # Return {"ok": True, ...} or {"ok": False, "error": "..."}
   ```

2. **Add to `ACTIONS` dict**:
   ```python
   ACTIONS = {
       ...
       'my-action': handle_my_action,
   }
   ```

3. **Update Python client** (`blockhost-common: blockhost/root_agent.py`):
   ```python
   def my_action(**kwargs) -> dict:
       return call("my-action", **kwargs)
   ```

4. **Update TypeScript client** (`blockhost-engine: src/root-agent/client.ts`):
   ```typescript
   export async function myAction(params: ...): Promise<void> {
     await callRootAgent("my-action", params);
   }
   ```

5. **Update `ARCHITECTURE.md`** — add the action to the root agent action catalog.

### Validation requirements

Every handler must validate all parameters before executing:
- Integer ranges (e.g., VMID 100–999999, port 1–65535)
- String patterns (regex allowlists, not denylists)
- Path confinement (must be under expected directories)
- Allowlisted option keys for open-ended dicts
