# BlockHost

> **WARNING: THE BLOCKHOST ISO WILL IMMEDIATELY AND IRREVERSIBLY ERASE ALL DATA ON THE DEVICE IT IS BOOTED ON.** The installer runs a fully automated Debian preseed that partitions and formats disks without any confirmation prompt. ANY EXISTING DATA ON ALL CONNECTED DRIVES WILL BE DESTROYED. DO NOT BOOT THIS ISO ON A PRODUCTION MACHINE OR ANY DEVICE CONTAINING DATA YOU WANT TO KEEP UNLESS YOU FULLY UNDERSTAND WHAT YOU ARE DOING. Always boot in a dedicated machine or virtual machine with no important data present.

**Autonomous VM hosting, driven by blockchain.** — [Telegram](https://t.me/BlockHostOS)

> **Status:** Currently only operational on **Sepolia testnet**. Full multichain support is not yet implemented, and the IPv6 broker registry contract is only deployed on testnet. Do not use in production.
>
> **Security:** This project is built with security as a core design principle — OS-level authentication, on-chain identity, encrypted credentials, zero standing admin access. However, the code has not been formally audited. Review before deploying with real assets.

BlockHost eliminates traditional hosting accounts entirely. Users purchase a subscription on-chain, receive an NFT containing their encrypted connection details, and authenticate to their VM by signing a message with their wallet. No usernames, no passwords, no control panels — just a wallet and a signature.

The entire lifecycle — from payment to VM provisioning to access credential delivery — happens without human intervention. The host operator installs from an ISO, walks through a wizard, and the system runs itself.

### What's different

- **Identity is a wallet.** No registration, no email, no 2FA. Your Ethereum wallet *is* your identity.
- **Access credentials live on-chain.** Connection details are encrypted into an NFT that only the owner's wallet can decrypt.
- **VMs provision themselves.** A blockchain event monitor detects purchases and triggers Terraform — no admin dashboard, no ticket system.
- **Authentication happens at the OS level.** A custom PAM module verifies wallet signatures at SSH login. No application-layer auth to bypass.
- **Admin access via on-chain commands.** Port knocking through blockchain transactions — no management ports exposed by default.

---

## Quick Start

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/mwaddip/blockhost.git
cd blockhost

# Check and install build dependencies
./scripts/check-build-deps.sh --install

# Build packages and ISO
./scripts/build-iso.sh --build-deb

# Boot the ISO on bare metal or in a VM, then:
# 1. Wait for Debian auto-install + first boot (installs Proxmox VE)
# 2. Note the OTP code displayed on the console
# 3. Open the web wizard at the displayed URL
# 4. Connect your admin wallet, walk through the 7 wizard steps
# 5. Finalization deploys contracts, configures IPv6, builds VM template
# 6. System is live — send a subscription transaction to test
```

See [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) for the full build and installation reference.

---

## How It Works

### Admin installs once, system runs itself

```
Boot ISO → Debian auto-install → Proxmox VE
    → First boot: install packages, generate OTP
    → Web wizard: network, storage, blockchain, Proxmox, IPv6, admin
    → Finalization: deploy contracts, configure tunnel, build template
    → System live: engine monitors the chain
```

### Users interact with the blockchain, not the server

```
User wallet                    Blockchain              BlockHost server
     |                              |                        |
     |-- purchase subscription ---->|                        |
     |                              |-- event detected ----->|
     |                              |                        |-- create VM
     |                              |<-- mint NFT -----------|
     |                              |   (encrypted access)   |
     |                              |                        |
     |-- decrypt NFT, get details ->|                        |
     |-- SSH to VM (wallet auth) ---|----------------------->|
```

### VM lifecycle

```
Subscription purchased → VM provisioned (active)
    → subscription expires → VM suspended (data preserved)
        → renewed → VM resumed
        → grace period expires → VM destroyed
```

Default grace period: 7 days (configurable).

---

## Architecture

```
+------------------------------------------------------------------+
|                        Proxmox VE Host                           |
|                                                                  |
|  +-------------------+     +-------------------+                 |
|  | blockhost-engine  |     | blockhost-        |                 |
|  | (Node.js)         |     | provisioner       |                 |
|  |                   |     | (Python)          |                 |
|  | - monitors chain  |---->| - vm-generator.py |                 |
|  | - detects events  |     | - mint_nft.py     |                 |
|  | - triggers        |     | - vm-gc.py        |                 |
|  |   provisioning    |     | - Terraform       |                 |
|  +-------------------+     +--------+----------+                 |
|           |                         |                            |
|           |  +------------------+   |   +--------------------+   |
|           |  | blockhost-common |   |   | libpam-web3-tools  |   |
|           |  | (Python)         |   |   | (Rust)             |   |
|           +->| - config loading |<--+   | - pam_web3_tool    |   |
|              | - VM database    |       | - encrypt/decrypt  |   |
|              | - root agent     |       | - signing page gen |   |
|              +------------------+       +--------------------+   |
|                                                                  |
|  +---------------------------+    +---------------------------+  |
|  | blockhost-root-agent      |    | blockhost-signup          |  |
|  | (Python, runs as root)    |    | (static HTML)             |  |
|  | - privileged ops daemon   |    | - served on port 443      |  |
|  | - Unix socket IPC         |    | - NFT decrypt UI          |  |
|  +---------------------------+    +---------------------------+  |
|                                                                  |
|  +---------------------------+                                   |
|  | blockhost-broker-client   |                                   |
|  | (Python)                  |                                   |
|  | - requests IPv6 prefix    |                                   |
|  | - configures WireGuard    |                                   |
|  +---------------------------+                                   |
+------------------------------------------------------------------+
                |                          ^
        WireGuard tunnel            User wallet
                |                  (MetaMask etc.)
     +----------v-----------+
     |   IPv6 Broker         |
     |   (NDP proxy)         |
     +----------------------+
```

For detailed component interfaces, configuration files, network topology, and the installer flow, see [docs/INFRASTRUCTURE.md](docs/INFRASTRUCTURE.md).

---

## Components

| Component | Language | Role |
|-----------|----------|------|
| **blockhost-engine** | TypeScript | Monitors blockchain events, triggers provisioning, admin commands, fund management, `bw`/`ab` CLIs |
| **blockhost-provisioner-proxmox** | Python | VM lifecycle: create, suspend, destroy, resume, template build, NFT minting |
| **blockhost-common** | Python | Shared library: config loading, VM database, root agent client |
| **libpam-web3** | Rust | PAM module (in VMs) + host tools: wallet auth at SSH, ECIES encryption |
| **blockhost-broker-client** | Python | IPv6 prefix allocation via on-chain broker registry + WireGuard tunnel |
| **blockhost-root-agent** | Python | Privileged operations daemon (qm, iptables, key writes) — only component running as root |
| **installer** (this repo) | Python/Flask | First boot wizard, finalization, system configuration |

---

## Documentation

| Document | Audience | Content |
|----------|----------|---------|
| [docs/INFRASTRUCTURE.md](docs/INFRASTRUCTURE.md) | Developers | Component interfaces, config files, installer flow, how to extend |
| [docs/STANDARDS.md](docs/STANDARDS.md) | Contributors | Privilege separation, CLI usage, submodule boundaries, conventions |
| [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) | Operators | Build dependencies, ISO creation, test cycle |
| [ARCHITECTURE.md](ARCHITECTURE.md) | LLM sessions | Dense, structured reference for AI-assisted development |

---

## License

TBD
