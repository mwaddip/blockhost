# Build Guide

For the quick version, see [Quick Start](/getting-started/quick-start). This page covers the full build reference.

## Prerequisites

### Build host

- Linux (tested on Ubuntu 22.04+, Debian 12+, Mint 22)
- git, dpkg-dev
- Node.js 22+ (via nvm)
- Rust toolchain (via rustup) — for libpam-web3
- Foundry (forge, cast) — for EVM contract compilation

```bash
./scripts/check-build-deps.sh --install
```

### Target

- Dedicated machine or VM: 2+ vCPU, 4+ GB RAM, 32+ GB disk
- Network access (DHCP or static)
- For testing: libvirt/KVM on the build host works fine

## Build Commands

```bash
# Build all .deb packages for a backend + engine combo
./scripts/build-packages.sh --backend libvirt --engine evm

# Verify packages were built correctly
./scripts/ci-verify-packages.sh --backend libvirt --engine evm

# Build the ISO
./scripts/build-iso.sh --backend libvirt --engine evm

# Build with testing mode (recommended for development)
./scripts/build-iso.sh --backend libvirt --engine evm --build-deb --testing \
    --apt-proxy http://192.168.122.1:3142
```

::: warning
Do not use `sudo` for `build-iso.sh`. The build tools (npm, cargo) are user-installed and `sudo` drops them from PATH.
:::

### Backend + engine combinations

| Backend | Engine | Description |
|---------|--------|-------------|
| `libvirt` | `evm` | libvirt/KVM + Ethereum |
| `libvirt` | `opnet` | libvirt/KVM + OPNet (Bitcoin L1) |
| `proxmox` | `evm` | Proxmox VE + Ethereum |
| `proxmox` | `opnet` | Proxmox VE + OPNet (Bitcoin L1) |

### Testing mode flags

`--testing` enables:
- SSH root login (password: `blockhost`)
- Btrfs root with snapshots (enables `revert`/`resume` commands)
- Testing mode marker at `/etc/blockhost/.testing-mode`

`--apt-proxy <url>` uses a local apt-cacher-ng for faster installs (e.g., `http://192.168.122.1:3142`).

## ISO build cycle

1. **Rebuild .deb packages** if a submodule changed: `./scripts/build-packages.sh --backend <name> --engine <name>`. The ISO build copies pre-built .debs, it does NOT rebuild them.
2. **Remove the old ISO**: `sudo rm build/blockhost_0.3.0.iso` — the ISO may be root-owned after a VM boots it.
3. **Build**: `./scripts/build-iso.sh --backend <name> --engine <name> --build-deb --testing`
4. **Boot**: `virt-install` or write to USB.

## Test VM workflow

```bash
# Destroy old test VM
sudo virsh destroy blockhost-test 2>/dev/null
sudo virsh undefine blockhost-test --remove-all-storage

# Launch new VM
sudo virt-install \
    --name blockhost-test \
    --ram 4096 --vcpus 2 --disk size=32 \
    --cdrom build/blockhost_0.3.0.iso \
    --network network=default \
    --graphics vnc --noautoconsole \
    --os-variant debian12 --boot cdrom,hd

# Get IP
virsh domifaddr blockhost-test

# SSH in (testing mode)
./scripts/ssh-test.sh <IP>
```

### Revert/resume cycle

For rapid iteration without rebuilding the ISO:

```bash
# On VM: revert to a snapshot
./scripts/ssh-test.sh <IP> "revert pre-engine"

# Upload new packages
scp -i testing/blockhost-test-key -o StrictHostKeyChecking=no \
    blockhost-engine-evm/packaging/blockhost-engine-evm_*.deb \
    root@<IP>:/opt/blockhost/packages/host/

# Resume first-boot
./scripts/ssh-test.sh <IP> "resume"

# Generate fresh OTP if needed
./scripts/ssh-test.sh <IP> "otp"
```
