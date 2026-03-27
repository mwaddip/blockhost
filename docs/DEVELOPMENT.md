---
name: blockhost-development
description: Use when working on the BlockHost project or any of its submodules — covers architecture philosophy, interface contracts, multi-session workflow, build pipeline, S.P.E.C.I.A.L. system, and development principles
---

# BlockHost Development

## Overview

BlockHost is a pluggable VM hosting platform driven by blockchain. One operator boots an ISO, walks through a wizard, and the system runs itself — users pay on-chain, receive NFT access credentials, and authenticate with their wallet at the OS level.

The codebase is split across 10+ repositories connected by interface contracts. Every component is agnostic of every other component's internals. The architecture is maintained by multiple coding agent sessions coordinated through a single main session.

## Core Philosophy

### Agnosticism as religion

Every component is agnostic of whatever engine, provisioner, or chain is installed. No chain-specific exceptions in shared code — not in build scripts, not in validation, not in config templates. If you catch yourself writing `if engine == 'cardano'` in the installer, you're violating the architecture. The engine declares what it needs through its manifest and interface exports. The installer discovers and calls — it never assumes.

### Presence as state

NFT existence = access credential. Directory contents = configuration. Plugin exists = chain supported. Port number = function of chain name. UTXO exists = subscription active. File present = feature enabled. Prefer state you can observe over state you must configure.

### Interface integrity

When interfaces don't match, fix the interface — never wrap the mismatch. No adapters, no shims, no glue code. Trace the mismatch to whichever side is wrong and fix it at the source. Duct tape hides the bug and breeds more duct tape.

### Design by Contract

The `facts/` submodule contains the interface contracts — the single source of truth for how components connect. Every cross-boundary interaction is specified there. Read the contract before modifying code that touches a boundary. If the contract needs changing, change it first, then update the implementations.

### Dependency minimalism

If a library does 300 things and you need 3, write the 3. The Cardano engine went from 200MB of dependencies to 237KB by replacing framework libraries with purpose-built ones (`noble-bip32ed25519`, `cmttk`). Ship self-contained bundles, not `node_modules` trees.

## Architecture

### Repository structure

```
blockhost/                          # Main repo — installer, admin panel, scripts, ISO builder
  facts/                            # Interface contracts (submodule, editable by main session)
  blockhost-common/                 # Shared library: config, VM database, root agent
  blockhost-engine-evm/             # EVM blockchain engine
  blockhost-engine-opnet/           # OPNet blockchain engine
  blockhost-engine-cardano/         # Cardano blockchain engine
  blockhost-provisioner-proxmox/    # Proxmox hypervisor backend
  blockhost-provisioner-libvirt/    # libvirt/KVM hypervisor backend
  blockhost-broker/                 # IPv6 broker (server + client + chain adapters)
  blockhost-monitor/                # Host resource watchdog (Go)
  libpam-web3/                      # PAM module + chain auth plugins
  installer/web/                    # Flask wizard + finalization pipeline
  admin/                            # NFT-gated admin panel
  scripts/                          # Build, ISO, testing scripts
  packages/                         # Built .deb files (host/ and template/)
```

### Plugin model

Two plugin axes — engines and provisioners:

| Axis | Discovery | Manifest | Examples |
|------|-----------|----------|----------|
| Engine | `engine.json` at `/usr/share/blockhost/` | Wizard module, finalization steps, constraints, accent color | evm, opnet, cardano |
| Provisioner | `provisioner.json` at `/usr/share/blockhost/` | CLI commands, wizard plugin, first-boot hook | proxmox, libvirt |

The installer discovers both at runtime via manifests. No hardcoded engine or provisioner names anywhere in shared code. A new engine is a new submodule with the right manifest and interface exports — zero changes to the installer, common, or provisioner.

### Interface contracts (facts/)

| Contract | Covers |
|----------|--------|
| `ENGINE_INTERFACE.md` | CLIs (bw, ab, is, bhcrypt), monitor, fund manager, wizard plugin, config files, systemd units |
| `PROVISIONER_INTERFACE.md` | VM lifecycle CLIs, manifest, wizard plugin, root agent actions, first-boot hook |
| `COMMON_INTERFACE.md` | Config API, VM database, root agent protocol, cloud-init, dispatcher |
| `WIZARD_UI.md` | HTML patterns, CSS classes, components for wizard templates |

**The contract change pipeline:**
1. Update the contract in `facts/`
2. Push facts
3. Each submodule pulls new facts into their nested `facts/` submodule
4. Submodule implements against the updated contract
5. Main session pulls submodule, updates pointer

### Virtual package conflicts

Engines declare `Provides: blockhost-engine` + `Conflicts: blockhost-engine`. Provisioners declare `Provides: blockhost-provisioner` + `Conflicts: blockhost-provisioner`. A package never conflicts with itself through a virtual package — this prevents coinstallation without enumerating names. Scales to N engines/provisioners without editing existing control files.

## S.P.E.C.I.A.L. System

Analytical bias weights per component. Not instructions — attention allocation. Scale 1-10, where 5 = standard professional competence (always maintained). Stats above 5 indicate where to invest extra scrutiny.

```
S  Strength      Robustness, error handling, input validation
P  Perception    Security awareness, privilege scrutiny, trust boundaries
E  Endurance     Reliability, idempotency, crash recovery
C  Charisma      Clarity, API design, naming, readability
I  Intelligence  Architecture, separation of concerns, correct scope
A  Agility       Performance, lean code, minimal dependencies
L  Luck          Edge cases, race conditions, timing failures
```

Each submodule has a `SPECIAL.md` defining profiles per component. The main repo's `SETTINGS.md` lists active profiles. When working on a file, apply the stats of its component.

Example: The root agent daemon is P10 (authentication boundary — if this gets fooled, everything's gone). The addressbook CLI is S6 P6 E5 C7 (simple CRUD — don't overthink it).

## Multi-Session Workflow

### Session roles

**Main session** (this repo):
- Owns `facts/` — the interface contracts
- Knows the full infrastructure through defined interfaces
- Writes prompts for submodule sessions
- Pulls submodule updates, commits pointer changes
- Builds packages and ISOs
- **Never edits submodule source code**

**Submodule sessions** (one per repo):
- Receive prompts as markdown files
- Work within their interface contract
- Push to their own repo

### Prompt workflow

1. Main session identifies what needs to change in a submodule
2. Writes a prompt to `prompts/<submodule-change>.md`
3. User copies to clipboard, pastes into the submodule's session
4. Submodule session implements and pushes
5. Main session pulls, updates pointer, rebuilds

Prompts are disposable — delete after the submodule applies them.

### Making interface changes

1. Update `facts/` interface contract first — push to facts repo
2. Each affected submodule pulls new facts
3. Submodule sessions implement against the updated contract
4. Main session pulls all submodules, verifies integration

Never change code first and contract after. The contract leads.

## Build Pipeline

```bash
# Build all packages for a backend/engine combo
./scripts/build-packages.sh --backend libvirt --engine cardano

# Build the ISO (requires packages already built)
./scripts/build-iso.sh --backend libvirt --engine cardano --testing \
  --apt-proxy http://192.168.122.1:3142

# Boot a VM from the ISO
virt-install --connect qemu:///system --name blockhost-test \
  --ram 8192 --vcpus 4 --disk size=64,format=qcow2 \
  --cdrom build/blockhost_0.3.0.iso --os-variant debian12 \
  --network network=default --graphics vnc,listen=127.0.0.1 \
  --noautoconsole --check disk_size=off --boot cdrom,hd
```

**Key rules:**
- `build-packages.sh` cleans and rebuilds everything — always run before ISO build
- The ISO copies pre-built .debs from `packages/` — it does NOT rebuild them
- **Never `sudo` the build.** Neither `build-packages.sh` nor `build-iso.sh` need root. `sudo` drops nvm/cargo/go from PATH and breaks builds. The only thing that may need `sudo rm` is a stale ISO owned by `libvirt-qemu` after `virt-install`.
- Go must be in PATH: `export PATH="/usr/local/go/bin:$PATH"`
- Engine `packaging/build.sh` may need `chmod +x` locally if git doesn't preserve it

## Testing Workflow (revert/resume)

Testing ISOs use btrfs with snapshots at each first-boot stage. The `revert` command rolls back to a named snapshot; `resume` releases the hold and continues first-boot.

```bash
# On VM: revert to before engine install
revert pre-engine

# On host: copy new .deb to packages dir (first-boot will install it)
scp -i testing/blockhost-test-key -o StrictHostKeyChecking=no \
  engine.deb root@<IP>:/opt/blockhost/packages/host/

# On VM: continue first-boot from engine install step
resume
```

**Important:** Packages installed BEFORE the revert snapshot are already installed. Dropping a new .deb in `packages/host/` doesn't retroactively reinstall. For pre-snapshot packages (broker, common), also `dpkg -i` directly.

**Inline patching** (engine already installed, wizard running): `dpkg -i /tmp/package.deb` then retry the finalization step. Python files may be cached by Flask — on testing ISOs, Flask auto-reloads. On production ISOs, restart the process.

## Shared Environment (Local Testing)

Secrets for local testing (deployer keys, RPC URLs, contract addresses) live in `~/projects/sharedenv/`:

```bash
source ~/projects/sharedenv/blockhost.env
```

This directory is outside all repos deliberately. Never commit secrets. An agent session that needs these should ask the user where shared environment files are stored.

## Config Ownership

| File | Owner | Notes |
|------|-------|-------|
| `web3-defaults.yaml` | Engine finalization | Common ships empty `blockchain: {}` skeleton |
| `.env` | Engine finalization | Engine writes chain-specific vars |
| `blockhost.yaml` | Installer finalization | Server keys, admin config, fund manager settings |
| `addressbook.json` | Engine finalization + fund manager | Role-to-wallet mapping |
| `engine.json` | Engine .deb | Static manifest, read-only after install |
| `provisioner.json` | Provisioner .deb | Static manifest, read-only after install |

**Rule:** Common and the installer ship empty skeletons. The engine fills them during finalization. Never hardcode chain-specific defaults in shared config templates.

## Validation

`installer/web/validate_system.py` runs after finalization on testing ISOs. It reads `engine.json` to determine which keys to validate — no hardcoded EVM assumptions. Each engine declares what it writes; validation checks what was declared.

## Design Patterns (from hard experience)

### Interfaces write themselves

Good documentation in `facts/` produces correct implementations even when prompts don't explicitly specify details. If the contract is precise, the submodule session builds the right thing. Invest in the contract; save on the prompt.

### The wallet IS the config

PAM derives chain from wallet format, port from chain name (`crc32(name) % 64511 + 1024`), FQDN from hostname, signing URL from all of the above. Zero config files in the entire auth pipeline. If both sides can compute a value, don't configure it — derive it.

### Deterministic derivation over configuration

Port numbers, DNS addresses, signing URLs, broker offsets — computed, not configured. `{offset:x}.{dns_zone}` → AAAA → prefix + offset. Both sides derive the same result from the same input. No coordination, no database, no config sync.

### Self-healing over monitoring

The system already has: fund cycle (24h), gas check (30min), GC timer (daily), reconciliation (5min). These don't monitor and alert — they detect and fix. Report facts, not judgments. Submodules expose raw metrics; a central system (future) derives health.

### Shim over patch over unbundle

When a transitive dependency uses a problematic native library, write a drop-in shim implementing the same API with pure JS. Use esbuild `--alias` to redirect at bundle time. No runtime patches, no `node_modules` shipping, no `patch-package` fragility.

## Git Practices

- **Sensitive filenames go in `.git/info/exclude`, not `.gitignore`.** The `.gitignore` is committed and visible on GitHub — any filename listed there leaks its existence. Use `.git/info/exclude` for session files, feature design docs, and anything whose name alone is revealing.
- **`git submodule update --remote` is a footgun.** It checks out whatever the remote's default branch is, not the branch the main repo expects. Always verify which branch each submodule lands on.
- **Clean build artifacts before rebuilding.** `build-packages.sh` does this automatically. Manual builds in submodules may leave stale `.deb` files that `find` picks up instead of fresh ones.
- **`git-filter-repo` removes the origin remote.** Must `git remote add origin <url>` after rewriting history.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Hardcoding `0x` address format in shared code | Read `engine.json` constraints or accept any non-empty string |
| Adding `--external` in esbuild without shipping the package | Either bundle it or ship `node_modules` — don't externalize and hope |
| Editing submodule files from the main session | Write a prompt, send to the submodule's session |
| Running `build-iso.sh` without `build-packages.sh` first | ISO copies pre-built .debs — always rebuild packages first |
| Writing engine-specific logic in the installer | Use manifest discovery and optional engine exports |
| Treating `web3-defaults.yaml` as having a fixed schema | Schema is engine-defined — common ships an empty skeleton |
| Using `--graphics none` in virt-install | Kills the Debian preseed installer — some debconf prompt needs a TTY. Always use `--graphics vnc` |
| First-boot step ordering assumptions | Hooks depend on packages being installed first. Marker files must be unique per step — collisions cause silent skips |
| `sudo` on any build script | Never needed. `sudo` drops nvm/cargo/go from PATH. Only `sudo rm` for stale ISOs owned by libvirt-qemu |
