# What is BlockHost?

BlockHost turns a bare-metal server into a fully autonomous VM hosting platform. Users pay on-chain, receive an NFT with their encrypted access credentials, and authenticate with their wallet — no accounts, no passwords, no admin intervention.

## How it works

### For the operator

Boot the ISO on dedicated hardware (or a VM for testing). Debian auto-installs, packages deploy on first boot, and a web wizard walks through network, storage, blockchain, and hypervisor configuration. Finalization deploys smart contracts, configures IPv6 tunneling, builds a VM template, and enables all services. After a reboot, the system is live.

An admin panel (NFT-gated, wallet-authenticated) provides system monitoring, network management, certificate renewal, and VM oversight — but day-to-day operation requires zero intervention.

### For the user

1. Purchase a subscription on-chain via the signup page
2. VM provisions automatically
3. NFT minted with encrypted SSH credentials
4. Decrypt with your wallet, connect via SSH
5. Wallet signature replaces password at the OS level

VM lifecycle follows the subscription: active while paid, suspended on expiry (data preserved), resumed on renewal, destroyed after a configurable grace period.

## Design principles

**Presence as state.** NFT existence = access credential. Manifest existence = provisioner registration. Subscription UTXO = active service. The system derives its state from what's present, not from config files.

**Pluggable, not monolithic.** The blockchain engine and the hypervisor provisioner are independent plugins. Adding a new chain means writing an engine — the provisioner, installer, and common library don't change.

**Privacy by default.** Wallet signatures for auth, encrypted credentials in NFTs, no email or personal data collected. The operator can't see your SSH password — it's encrypted to your wallet.

**Interface over implementation.** Components communicate through documented contracts. If two components miscommunicate, the contract is wrong — never write a wrapper.

## Components

| Component | Role |
|-----------|------|
| **Installer** | First-boot wizard, finalization, system configuration |
| **Admin panel** | NFT-gated web interface for post-install management |
| **blockhost-engine-evm** | EVM engine (Ethereum, Polygon, Base, Arbitrum) |
| **blockhost-engine-opnet** | OPNet engine (Bitcoin L1 smart contracts) |
| **blockhost-engine-cardano** | Cardano engine (UTXO-native subscriptions) — in development |
| **blockhost-provisioner-proxmox** | VM lifecycle on Proxmox VE |
| **blockhost-provisioner-libvirt** | VM lifecycle on libvirt/KVM |
| **blockhost-common** | Shared library: config, VM database, root agent, cloud-init |
| **blockhost-monitor** | Host resource monitoring and enforcement — in development |
| **libpam-web3** | PAM module for wallet-based SSH authentication |
| **blockhost-broker** | IPv6 prefix allocation via on-chain broker registry |
