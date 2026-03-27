# Threat Model

## Trust Boundaries

### Untrusted

- **VMs**: Tenant VMs are fully untrusted. They may run malicious software, attempt to escape the hypervisor, scan the network, or abuse resources.
- **Network**: The local network during wizard setup and the public internet post-install are both untrusted.
- **Blockchain data**: On-chain data is trustworthy for *what happened* (transactions, ownership) but not for *intent*. A valid subscription purchase from a known-bad actor is still a valid purchase.

### Trusted

- **The operator** (during setup): The person running the wizard has physical access and root. The OTP mechanism prevents unauthorized wizard access on the local network.
- **The host OS**: The ISO installs Debian from known packages. If the host OS is compromised, everything is compromised.
- **The root agent daemon**: Runs as root, auditable, single process. If this is compromised, the attacker has root.

### Semi-trusted

- **The `blockhost` user**: Has access to private keys (deployer, server) via group permissions. Compromise of this user means access to chain funds and the ability to mint NFTs. However, it does NOT mean root access — the root agent validates all requests.
- **The broker**: Allocates IPv6 prefixes. A malicious broker could assign conflicting prefixes or refuse service. It cannot compromise VMs or access credentials.

## Attack Surfaces

### Installer wizard (port 80, during setup only)

- OTP-authenticated, but the OTP is displayed on the physical console
- Runs on `0.0.0.0` — accessible to anyone on the local network
- Engine API endpoints (RPC proxying) have SSRF protections
- Wizard is only active during first-boot; disabled after finalization

### VM SSH authentication (port 22, ongoing)

- PAM module verifies wallet signatures — no brute-forceable passwords
- Signing page served over HTTPS (self-signed) on port 8443
- Guest agent communication between host and VM

### Admin panel (ongoing)

- NFT-gated access — must hold admin credential NFT
- Wallet signature authentication with one-time challenge codes
- On-chain admin commands via port knocking

### Blockchain interaction

- Deployer key stored at `/etc/blockhost/deployer.key` (0640 root:blockhost)
- Private keys passed as CLI arguments to `cast` (visible in `/proc` during execution — brief window, single-user system)
- ECIES encryption for credential storage in NFTs

## Mitigations

| Threat | Mitigation |
|--------|------------|
| VM escape | Standard hypervisor isolation (KVM/QEMU). Bridge port isolation planned. |
| Network scanning from VMs | Monitor detects connection count anomalies. Throttle/suspend. |
| Cryptomining | Monitor detects sustained 100% CPU. Throttle/suspend. |
| Deployer key theft | File permissions (0640), single-user host, no remote access to key files. |
| SSRF via installer | RPC URL validation, private IP blocking, generic error messages. |
| Symlink traversal | `os.path.realpath()` before path prefix checks in root agent actions. |
| Setup state secrets | Redacted from `setup-state.json` on finalization completion. File chmod 0640. |
