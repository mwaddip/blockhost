# Post-Install

After the wizard completes and the system reboots, BlockHost is operational. Day-to-day operation is autonomous — the system monitors the blockchain and manages VMs without intervention.

## What's running

| Service | Purpose |
|---------|---------|
| `blockhost-monitor` | Blockchain event watcher, subscription processing |
| `blockhost-root-agent` | Privileged operations daemon |
| `blockhost-gc.timer` | Daily garbage collection of expired VMs |
| `nginx` | Reverse proxy for signup page (HTTPS) |
| `web3-auth-svc` | Signing server on each VM (port 8443) |

## Admin Panel

The admin panel is accessible via the host's HTTPS address. Authentication requires:
1. Holding the admin credential NFT (token ID 0)
2. Wallet signature verification with a one-time challenge

Features:
- System status overview
- VM listing and management
- Network configuration
- Certificate renewal
- Log viewing

## Monitoring

Current monitoring is handled by the engine's blockchain monitor service. A dedicated host monitor (`blockhost-monitor`) is in development for resource enforcement, health checks, and abuse detection.

## Logs

| Log | Location |
|-----|----------|
| First-boot | `/var/log/blockhost-firstboot.log` |
| Installer | `/var/log/blockhost-installer.log` |
| Engine monitor | `journalctl -u blockhost-monitor` |
| Root agent | `journalctl -u blockhost-root-agent` |

## Config Backup

During finalization, you can download an encrypted config backup (`.enc` file). This is encrypted with your wallet signature — only you can decrypt it. Use it to restore settings if you need to re-run the wizard on the same or different hardware.

## Updating Packages

To update a submodule package on a running system:

```bash
# Build the new .deb on your build host
cd blockhost-engine-evm && git pull && bash packaging/build.sh

# Copy to the running host
scp packaging/blockhost-engine-evm_*.deb root@<host-ip>:/tmp/

# Install on the host
ssh root@<host-ip> "dpkg -i /tmp/blockhost-engine-evm_*.deb && systemctl restart blockhost-monitor"
```
