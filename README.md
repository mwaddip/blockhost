# BlockHost

> **WARNING: THE BLOCKHOST ISO WILL IMMEDIATELY AND IRREVERSIBLY ERASE ALL DATA ON THE DEVICE IT IS BOOTED ON.** The installer runs a fully automated Debian preseed that partitions and formats disks without any confirmation prompt. ANY EXISTING DATA ON ALL CONNECTED DRIVES WILL BE DESTROYED. DO NOT BOOT THIS ISO ON A PRODUCTION MACHINE OR ANY DEVICE CONTAINING DATA YOU WANT TO KEEP UNLESS YOU FULLY UNDERSTAND WHAT YOU ARE DOING. Always boot in a dedicated machine or virtual machine with no important data present.

**Autonomous VM hosting, driven by blockchain.** — [Telegram](https://t.me/BlockHostOS)

> **Status:** Currently operational on **Sepolia testnet** only. Not ready for production use.

BlockHost turns a bare-metal server into a fully autonomous VM hosting platform. Users pay on-chain, receive an NFT with their encrypted access credentials, and authenticate with their wallet — no accounts, no passwords, no admin intervention.

The operator boots an ISO, walks through a setup wizard, and the system runs itself from that point on.

---

## What makes it different

**No accounts.** Your Ethereum wallet is your identity. No registration, no email, no 2FA.

**No control panels.** Subscriptions, access credentials, and admin commands all live on-chain. The server watches the blockchain and acts on what it sees.

**No manual provisioning.** A blockchain event monitor detects new purchases and provisions automatically. VMs spin up, suspend on expiry, resume on renewal, and clean up after a grace period.

**No exposed management ports.** Admin operations happen through on-chain commands. Port knocking via blockchain transactions — nothing to scan, nothing to brute-force.

**OS-level auth.** A custom PAM module verifies wallet signatures at SSH login. Not an application-layer wrapper — it's in the authentication stack itself.

---

## How it works

### For the operator

Boot the ISO on dedicated hardware (or a VM). Debian auto-installs, packages deploy on first boot, and a web wizard walks through network, storage, blockchain, and hypervisor configuration. Finalization deploys smart contracts, configures IPv6 tunneling, builds a VM template, and enables all services. After a reboot, the system is live.

An admin panel (NFT-gated, wallet-authenticated) provides system monitoring, network management, certificate renewal, and VM oversight — but day-to-day operation requires zero intervention.

### For the user

```
Purchase subscription on-chain
    → VM provisions automatically
    → NFT minted with encrypted SSH credentials
    → Decrypt with your wallet, connect via SSH
    → Wallet signature replaces password at the OS level
```

VM lifecycle follows the subscription: active while paid, suspended on expiry (data preserved), resumed on renewal, destroyed after a configurable grace period.

---

## Quick start

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/mwaddip/blockhost.git
cd blockhost

# Check and install build dependencies
./scripts/check-build-deps.sh --install

# Build packages for your chosen backend
./scripts/build-packages.sh --backend proxmox    # or: libvirt

# Build the ISO
sudo ./scripts/build-iso.sh --backend proxmox

# Boot the ISO, follow the wizard, done.
```

See [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) for the full build reference and test cycle.

---

## Components

| Component | Role |
|-----------|------|
| **Installer** (this repo) | First-boot wizard, finalization, system configuration |
| **Admin panel** (this repo) | NFT-gated web interface for system management post-install |
| **blockhost-engine** | Blockchain event monitor, provisioning trigger, fund management, `bw`/`ab` CLIs |
| **blockhost-provisioner** | VM lifecycle (pluggable: Proxmox, libvirt), template builds, NFT minting |
| **blockhost-common** | Shared library: config, VM database, root agent |
| **libpam-web3** | PAM module for wallet auth + ECIES encryption tools |
| **blockhost-broker-client** | IPv6 prefix allocation via on-chain broker registry + WireGuard tunnel |

---

## Documentation

| Document | Content |
|----------|---------|
| [docs/BUILD_GUIDE.md](docs/BUILD_GUIDE.md) | Build dependencies, ISO creation, test cycle |
| [docs/INFRASTRUCTURE.md](docs/INFRASTRUCTURE.md) | Architecture, component interfaces, config files, how to extend |
| [docs/STANDARDS.md](docs/STANDARDS.md) | Privilege separation, CLI conventions, submodule boundaries |

---

## Security

BlockHost is built with security as a core design principle: OS-level authentication, on-chain identity, encrypted credentials, zero standing admin access. That said, the code has not been formally audited. Review before deploying with real assets.

---

## License

TBD
