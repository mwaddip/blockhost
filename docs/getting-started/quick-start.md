# Quick Start

## Prerequisites

- A dedicated machine or VM (minimum: 2 vCPU, 4GB RAM, 32GB disk)
- Build host with: git, node.js 22+, cargo (Rust), dpkg-dev
- Choose your stack: `--backend` (proxmox or libvirt) + `--engine` (evm or opnet)

## Build

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/mwaddip/blockhost.git
cd blockhost

# Check and install build dependencies
./scripts/check-build-deps.sh --install

# Build packages and ISO
./scripts/build-iso.sh --backend libvirt --engine evm --build-deb

# For testing (enables SSH root login, btrfs snapshots, apt proxy):
./scripts/build-iso.sh --backend libvirt --engine evm --build-deb --testing \
    --apt-proxy http://192.168.122.1:3142
```

::: tip
Do not use `sudo` for `build-iso.sh` — it drops nvm/cargo from PATH. The ISO only becomes root-owned after libvirt boots it.
:::

## Boot

Write the ISO to a USB drive or boot it in a VM:

```bash
# Example: libvirt test VM
sudo virt-install \
    --name blockhost-test \
    --ram 4096 \
    --vcpus 2 \
    --disk size=32 \
    --cdrom build/blockhost_0.3.0.iso \
    --network network=default \
    --graphics vnc \
    --os-variant debian12 \
    --boot cdrom,hd
```

Debian auto-installs (no interaction needed), reboots, runs first-boot, and launches the setup wizard on port 80.

## Setup Wizard

1. **OTP** — displayed on the console, enter it in the browser to authenticate
2. **Admin Wallet** — connect your crypto wallet and sign a message
3. **Network** — DHCP (auto) or static configuration
4. **Storage** — select the root disk
5. **Blockchain** — generate or import a deployer wallet, choose contract deployment
6. **Provisioner** — hypervisor-specific settings
7. **IPv6** — broker allocation or manual prefix
8. **Admin Commands** — on-chain admin management, port knocking
9. **Summary** — review and finalize

Finalization deploys contracts, configures services, builds the VM template, and validates the system. After reboot, the host is live and waiting for subscribers.

## Next Steps

- [Build Guide](/operator/build-guide) — full build reference, ISO options, test cycle
- [Wizard Walkthrough](/operator/wizard-walkthrough) — detailed explanation of each step
- [Supported Chains](/getting-started/supported-chains) — choose your blockchain engine
