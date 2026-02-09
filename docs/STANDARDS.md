# Development Standards

Best practices and conventions for the BlockHost project. For build instructions, see [BUILD_GUIDE.md](BUILD_GUIDE.md). For infrastructure details, see [INFRASTRUCTURE.md](INFRASTRUCTURE.md).

---

## Privilege Separation

BlockHost uses a two-user model:

| User | Runs | Why |
|------|------|----|
| `root` | `blockhost-root-agent` only | Single, auditable surface for privileged operations |
| `blockhost` | Everything else | Engine, provisioner, GC, signup, broker client |

### What MUST go through the root agent

Any operation that requires root privileges:

- **Proxmox VM management** — `qm start`, `qm stop`, `qm create`, `qm destroy`, `qm set`, `qm importdisk`, `qm template`
- **Network routing** — `ip -6 route add/del`
- **Firewall rules** — `iptables -A/-D`
- **Disk image customization** — `virt-customize`
- **Key generation** — writing private keys to `/etc/blockhost/` (root-owned)
- **Addressbook writes** — updating `/etc/blockhost/addressbook.json` (root-owned)

### What runs directly as `blockhost`

These do NOT need the root agent:

- **Terraform** — runs in `/var/lib/blockhost/terraform/` (blockhost-owned)
- **Foundry `cast`** — blockchain transactions, contract calls
- **`pam_web3_tool`** — encryption/decryption (reads keys via group permission)
- **Config reads** — all `/etc/blockhost/` configs are group-readable
- **Database operations** — `/var/lib/blockhost/vms.json` is blockhost-owned

### Rule

Never add root privileges to runtime services. If a new feature needs root, add a root agent action instead. See [INFRASTRUCTURE.md](INFRASTRUCTURE.md#extending-the-root-agent) for how.

---

## Use the CLI Tools

BlockHost provides purpose-built CLIs for common operations. Always use them instead of crafting direct calls.

### `bw` — wallet and fund operations

```bash
bw send <amount> <token> <from> <to>       # Transfer tokens
bw balance <role> [token]                   # Check balances
bw withdraw [token] <to>                    # Withdraw from contract
bw swap <amount> <from-token> eth <wallet>  # Swap via Uniswap V2
bw split <amount> <token> <ratios> <from> <to1> <to2> ...
```

The fund-manager imports `executeSend()`, `executeWithdraw()`, and `executeSwap()` from the bw modules directly — all wallet operations share the same code paths. New features that move funds should do the same, not duplicate logic with raw ethers calls or `cast send`.

### `ab` — addressbook management

```bash
ab add <name> <0xaddress>    # Add entry
ab del <name>                # Remove entry
ab up <name> <0xaddress>     # Update address
ab new <name>                # Generate wallet + save key
ab list                      # Show all entries
```

Addressbook writes go through the root agent (the file is root-owned). The `ab` CLI handles this automatically. Never write `addressbook.json` directly with `fs.writeFileSync` or `json.dump`.

### Root agent client libraries

For privileged operations in code:

**Python** (blockhost-common):
```python
from blockhost.root_agent import qm_start, qm_stop, ip6_route_add, generate_wallet
```

**TypeScript** (blockhost-engine):
```typescript
import { iptablesOpen, generateWallet, addressbookSave } from "./root-agent/client";
```

Never shell out to `qm`, `iptables`, or `ip route` directly from application code. The root agent validates all parameters before execution.

---

## Submodule Boundaries

Each submodule has a defined scope. Keep functionality in the right place.

| Submodule | Scope | Contains |
|-----------|-------|----------|
| **blockhost-common** | Shared libraries | Config loading, VM database, root agent Python client |
| **blockhost-provisioner-proxmox** | VM lifecycle | Create, suspend, destroy, resume, template build, NFT mint |
| **blockhost-engine** | Blockchain interaction | Event monitor, admin commands, fund manager, `bw`/`ab` CLIs, root agent TS client |
| **libpam-web3** | Authentication + crypto | PAM module (in VMs), `pam_web3_tool` CLI, signing page, ECIES encryption |
| **blockhost-broker** | IPv6 allocation | Broker client, on-chain registry interaction, WireGuard config |
| **Main repo** (installer) | Setup-time only | First boot, web wizard, finalization, root agent daemon |

### Guidelines

- **If multiple submodules need it** → put it in `blockhost-common`.
- **If it touches Proxmox/Terraform/VMs** → `blockhost-provisioner-proxmox`.
- **If it watches the chain or manages wallets** → `blockhost-engine`.
- **If it involves PAM, ECIES, or runs inside VMs** → `libpam-web3`.
- **If it only runs during installation** → main repo.

### Submodule modification rule

Never modify submodule files from the main repo. When a submodule change is needed:

1. Write a complete, self-contained prompt describing the change.
2. Hand it to the user to run in that submodule's Claude session.
3. After the submodule is updated and pushed, pull the changes with `git submodule update --remote <name>`.

---

## File Ownership and Permissions

### Private keys (`/etc/blockhost/*.key`)

```
-rw-r-----  root:blockhost  0640
```

Root-owned, group-readable. The `blockhost` user reads them via group membership. Never chmod to 0600 — that breaks the unprivileged services.

### Configuration files (`/etc/blockhost/*.yaml`, `*.json`)

```
-rw-r--r--  root:blockhost  0644    # Non-sensitive configs
-rw-r-----  root:blockhost  0640    # addressbook.json (contains key paths)
```

### State directory (`/var/lib/blockhost/`)

```
drwxr-x---  blockhost:blockhost  0750
```

Owned by `blockhost`. The engine, provisioner, and GC write here freely.

### Config directory (`/etc/blockhost/`)

```
drwxr-x---  root:blockhost  0750
```

Root-owned. The `blockhost` user reads via group permission. Writes go through the root agent or the installer (which runs as root during finalization).

### Root agent socket (`/run/blockhost/root-agent.sock`)

```
srw-rw----  root:blockhost  0660
```

Both root and `blockhost` group members can connect.

### TLS certificates (`/etc/blockhost/ssl/`)

```
-rw-r--r--  root:blockhost  0644    # cert.pem
-rw-r-----  root:blockhost  0640    # key.pem
```

---

## Service Conventions

All runtime services follow the same pattern:

```ini
[Service]
User=blockhost
Group=blockhost
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/blockhost
```

### Dependencies

Services that need the root agent:

```ini
Requires=blockhost-root-agent.service
After=blockhost-root-agent.service
```

The root agent itself is the only service running as root, with `RuntimeDirectory=blockhost` to create `/run/blockhost/` on boot.

### Logging

All services use journal logging:

```ini
StandardOutput=journal
StandardError=journal
```

No custom log files. Use `journalctl -u blockhost-monitor` to view logs.

---

## Code Conventions

### Idempotent operations

Every operation that can be interrupted and retried must be idempotent:

- **First-boot steps**: Guarded by marker files (`.step-hostname`, `.step-proxmox`, etc.). Check `[ ! -f "$MARKER" ]` before running, `touch "$MARKER"` after success.
- **Finalization steps**: Tracked by `SetupState` in `setup-state.json`. Each step checks its status before executing. Failed steps can be retried via `POST /api/finalize/retry`.

### Error handling

Distinguish between fatal and non-fatal errors:

- **Fatal**: Return `(False, "error message")` from finalization steps. The step is marked failed and can be retried.
- **Non-fatal**: Log a warning and continue. Example: a missing optional config value that has a sensible default.

### Config access

Always use the shared config module:

```python
from blockhost.config import load_db_config, load_web3_config, get_terraform_dir
```

Never parse `/etc/blockhost/*.yaml` with raw `yaml.safe_load()` in application code. The config module handles file paths, defaults, and validation.

### Database access

Always use the database abstraction:

```python
from blockhost.vm_db import get_database

db = get_database()
vmid = db.allocate_vmid()
```

Never manipulate `/var/lib/blockhost/vms.json` directly. The `VMDatabase` class handles locking, validation, and atomic writes.

### Documentation sync

After any code change, check whether these files need updating:

- `ARCHITECTURE.md` — component interfaces, config files, execution phases
- Submodule `CLAUDE.md` files — CLI commands, API surfaces, configuration options
- Submodule `PROJECT.yaml` (provisioner) — entry points, Python API, workflow
