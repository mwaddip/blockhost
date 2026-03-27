# Architecture

BlockHost is a pluggable system with three independent axes: **installer** (one-time setup), **engine** (blockchain), and **provisioner** (hypervisor). Any engine works with any provisioner.

## System Overview

```
┌─────────────────────────────────────────────────┐
│                  BlockHost Host                   │
│                                                   │
│  ┌─────────┐  ┌──────────┐  ┌───────────────┐   │
│  │ Engine  │  │Provisioner│  │   Monitor     │   │
│  │(EVM/    │  │(Proxmox/ │  │  (metrics,    │   │
│  │ OPNet/  │  │ libvirt) │  │   enforce,    │   │
│  │ Cardano)│  │          │  │   health)     │   │
│  └────┬────┘  └─────┬────┘  └───────┬───────┘   │
│       │             │               │             │
│  ┌────┴─────────────┴───────────────┴────────┐   │
│  │            blockhost-common                │   │
│  │  config · vm_db · root_agent · cloud_init  │   │
│  └────────────────────┬──────────────────────┘   │
│                       │                           │
│  ┌────────────────────┴──────────────────────┐   │
│  │         root-agent daemon (root)           │   │
│  │  iptables · cgroups · key writes · virsh   │   │
│  └───────────────────────────────────────────┘   │
│                                                   │
│  VMs: ┌──────┐ ┌──────┐ ┌──────┐                │
│       │ VM 1 │ │ VM 2 │ │ VM 3 │ ...            │
│       │pam+  │ │pam+  │ │pam+  │                │
│       │authsvc│ │authsvc│ │authsvc│               │
│       └──────┘ └──────┘ └──────┘                │
└─────────────────────────────────────────────────┘
```

## User Model

| User | Runs | Purpose |
|------|------|---------|
| `root` | `blockhost-root-agent` only | Single auditable surface for privileged operations |
| `blockhost` | Everything else | Engine, provisioner, monitor, GC, signup, broker |

## Discovery Model

Components discover each other through **manifests** — JSON files installed to `/usr/share/blockhost/`:

| Manifest | Installed by | Discovered by |
|----------|-------------|---------------|
| `provisioner.json` | Provisioner .deb | Installer, engine, common |
| `engine.json` | Engine .deb | Installer |
| `broker.json` | Broker .deb | Installer |

If a manifest exists, the component is active. If not, it's not installed. No config file lists which components are present — presence is discovery.

## Data Flow: Subscription → VM

```
User purchases subscription on-chain
    │
    ▼
Engine monitor detects on-chain event
    │
    ▼
Engine calls provisioner CLI: blockhost-vm-create <name> --owner-wallet <addr>
    │
    ▼
Provisioner creates VM (cloud-init, network, disk)
    │
    ▼
Engine mints NFT with encrypted credentials (userEncrypted field)
    │
    ▼
Engine calls: blockhost-vm-update-gecos <name> <wallet> --nft-id <id>
    │
    ▼
VM GECOS updated → PAM module can authenticate this wallet
    │
    ▼
User decrypts NFT with their wallet → gets SSH credentials
    │
    ▼
User connects: SSH → PAM verifies wallet signature → access granted
```

## Key Directories

```
/etc/blockhost/           # Configuration (root:blockhost 750)
    *.yaml                #   Structured config
    *.key                 #   Private keys (0640)
    addressbook.json      #   Wallet directory
    ssl/                  #   TLS cert + key

/var/lib/blockhost/       # Runtime state (blockhost:blockhost 750)
    vms.json              #   VM database
    setup-state.json      #   Finalization progress
    metrics/              #   Per-VM metric samples

/usr/share/blockhost/     # Package-installed files
    provisioner.json      #   Provisioner manifest
    engine.json           #   Engine manifest
    root-agent-actions/   #   Root agent plugins
```

## Plugin System

### Engines

An engine is a .deb package that provides:
- `engine.json` manifest with identity, wizard module, finalization steps, and chain constraints
- A Flask blueprint for the installer wizard (blockchain config page)
- Finalization step functions (wallet, contracts, chain config, mint, plan)
- CLI tools: `bw` (wallet), `ab` (addressbook), `is` (identity), `blockhost-mint-nft`
- A blockchain event monitor (systemd service)
- Signing and signup page templates

See [Building an Engine](/developer/building-an-engine) for the full guide.

### Provisioners

A provisioner is a .deb package that provides:
- `provisioner.json` manifest with commands, wizard module, finalization steps
- VM lifecycle CLIs: create, destroy, start, stop, kill, status, list, metrics, throttle, gc
- A Flask blueprint for the installer wizard (hypervisor config page)
- Root agent action plugins for privileged operations
- A first-boot hook for installing hypervisor dependencies

See [Building a Provisioner](/developer/building-a-provisioner) for the full guide.

### How they connect

The installer imports wizard blueprints dynamically from manifests. The engine resolves provisioner CLI commands via `getCommand("create")` → manifest lookup → subprocess. No component hardcodes another's executable names or internal structure.
