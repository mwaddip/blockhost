# Wizard Walkthrough

After the ISO boots and first-boot completes, a web wizard launches on port 80. An OTP code is displayed on the console for authentication.

## Steps

### 1. OTP Authentication

Enter the one-time password shown on the console. This prevents unauthorized access from the local network during setup. The OTP expires after use or timeout.

### 2. Admin Wallet

Connect your crypto wallet and sign a message. This establishes your admin identity:
- The wallet address becomes the admin credential
- The signature is used for encrypting the config backup
- The signed message ("public secret") is needed to decrypt your NFT later

### 3. Network

DHCP (auto) or static IP configuration. For most setups, DHCP is detected automatically.

### 4. Storage

Select the root disk. The wizard detects available disks and their sizes.

### 5. Blockchain Configuration

Engine-specific. This page is provided by the engine plugin:
- **EVM**: Network selection (Sepolia, etc.), RPC URL, contract deployment or existing contracts, deployer wallet (generate or import)
- **OPNet**: Network selection, RPC URL, contract deployment, deployer wallet (mnemonic-based)

### 6. Provisioner Configuration

Hypervisor-specific. This page is provided by the provisioner plugin:
- **Proxmox**: API URL, node name, storage, bridge, IP pool, VMID range
- **libvirt**: Storage pool selection (auto-detected)

### 7. IPv6

Choose IPv6 allocation method:
- **Broker**: Automated allocation via on-chain broker registry + WireGuard tunnel
- **Manual**: Enter your own IPv6 prefix

### 8. Admin Commands

Configure on-chain admin management:
- Enable/disable admin commands
- Port knocking configuration (ports, timeout, command name)
- Destination mode (self or remote)

### 9. Summary

Review all configuration. Click "Finalize" to begin the automated setup:

1. Server keypair generation
2. Deployer wallet setup
3. Smart contract deployment
4. Chain configuration files
5. Provisioner-specific setup (API tokens, storage, network)
6. VM template build
7. IPv6 tunnel configuration
8. HTTPS certificate generation
9. Signup page deployment
10. Revenue sharing configuration
11. Admin NFT minting
12. Subscription plan creation
13. Service enablement
14. System validation

After validation passes, download the encrypted config backup and reboot.
