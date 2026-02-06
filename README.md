# BlockHost

Custom Proxmox VE image with blockchain-based VM provisioning. Users pay for VMs via on-chain subscriptions and authenticate using their web3 wallets.

## What It Does

1. **Subscription-based VMs**: Users create subscriptions on-chain, system automatically provisions VMs
2. **Web3 Authentication**: VMs use PAM module that authenticates via wallet signatures (no passwords)
3. **Automatic Lifecycle**: Expired subscriptions suspend VMs; grace period allows renewal before deletion
4. **IPv6 Tunneling**: Optional broker network for IPv6 allocation to VMs

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Proxmox Host                            │
├─────────────────────────────────────────────────────────────────┤
│  blockhost-monitor          Watches blockchain for events       │
│  blockhost-provisioner      Creates/destroys VMs via Terraform  │
│  blockhost-gc.timer         Daily cleanup of expired VMs        │
│  broker-client              IPv6 tunnel management              │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Provisioned VMs                            │
├─────────────────────────────────────────────────────────────────┤
│  libpam-web3                PAM module for wallet auth          │
│  Cloned from template       Base Debian with web3 PAM           │
└─────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Purpose |
|-----------|---------|
| `installer/web/` | Flask wizard for initial setup |
| `blockhost-common` | Shared config and database modules |
| `blockhost-provisioner` | VM provisioning, GC, NFT minting |
| `blockhost-engine` | Blockchain event monitor |
| `blockhost-broker` | IPv6 tunnel broker client |
| `libpam-web3` | PAM authentication via wallet signatures |

## VM Lifecycle

```
SubscriptionCreated → VM Provisioned (active)
                            │
                     subscription expires
                            ▼
                     VM Suspended (data preserved)
                            │
              ┌─────────────┴─────────────┐
              │                           │
      grace period expires         subscription renewed
              │                           │
              ▼                           ▼
        VM Destroyed               VM Resumed (active)
```

Default grace period: 7 days (configurable in wizard)

## Building

```bash
# Build ISO (testing mode enables SSH + root password)
./scripts/build-iso.sh --testing

# Output: build/blockhost_0.1.0.iso
```

## Installation

1. Boot from ISO (installs Proxmox VE automatically)
2. After reboot, access web wizard at `http://<ip>/`
3. Enter OTP shown on console
4. Configure: Network, Storage, Blockchain, Proxmox, IPv6
5. Wizard deploys contracts, creates API tokens, builds VM template
6. System reboots, monitor service starts watching blockchain

## Testing

```bash
# SSH to test VM (requires testing/blockhost-test-key)
./scripts/ssh-test.sh 192.168.122.x "command"

# Check services
systemctl status blockhost-monitor
systemctl status blockhost-gc.timer
```

## Configuration Files

After wizard completion:

| File | Contents |
|------|----------|
| `/etc/blockhost/db.yaml` | VM pools, IP ranges, grace period |
| `/etc/blockhost/web3-defaults.yaml` | Chain ID, RPC URL, contracts |
| `/etc/blockhost/blockhost.yaml` | Server keys, Proxmox settings |
| `/opt/blockhost/.env` | Monitor service environment |

## Submodules

This repo coordinates several submodules, each with their own repos:

- `libpam-web3/` - PAM authentication module
- `blockhost-common/` - Shared Python modules
- `blockhost-provisioner/` - VM provisioning scripts
- `blockhost-engine/` - TypeScript blockchain monitor
- `blockhost-broker/` - IPv6 broker client

## License

[TBD]
