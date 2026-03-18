# FAQ

## General

### What chains does BlockHost support?
EVM-compatible chains (Ethereum, Polygon, Base, Arbitrum), OPNet (Bitcoin L1), and Cardano (in development). The system is chain-agnostic — adding a new chain is a matter of building an engine plugin.

### Do I need to know anything about blockchain?
You need a crypto wallet and enough tokens to pay for a subscription. The purchase flow is a standard DApp interaction — connect wallet, approve transaction. SSH login uses your wallet signature instead of a password.

### Is my data private?
Your SSH credentials are encrypted to your wallet — the operator cannot read them. The VM itself is a standard Linux machine. What you run on it is your business.

### What happens if the operator disappears?
Your VM continues running as long as the host hardware is up. Your NFT persists on-chain regardless. However, without the operator, there's no one to maintain the host, renew certificates, or deploy updates. The system is autonomous, not immortal.

## Subscriptions

### What payment tokens are accepted?
This is operator-configured. Typically a stablecoin (USDC on EVM, a designated OP_20 token on OPNet, ADA on Cardano).

### Can I extend my subscription?
Yes. Purchase an extension before or after expiry. If the VM was suspended, it resumes automatically.

### What happens when my subscription expires?
The VM is suspended (stopped, data preserved). After a grace period (set by the operator, typically 7 days), the VM is destroyed. Renew before the grace period ends to keep your data.

### Can I get a refund?
Depends on the operator's contract configuration and the chain. Cardano subscriptions use a UTXO model where you can cancel and reclaim remaining funds (minus any policy-defined fee). EVM/OPNet refund policies are encoded in the subscription contract.

## Access

### I lost my password / credentials
You don't have a password. Your wallet is your credential. Visit the signup page, connect your wallet, sign the same message you used at purchase, and decrypt your NFT to see your SSH details.

### Can I use a regular SSH key?
Once you're logged in via wallet auth, you can add your SSH public key to `~/.ssh/authorized_keys` like any Linux machine. The wallet auth is for initial and fallback access.

### I transferred my NFT but the new owner can't log in
The system reconciles ownership periodically (every few minutes). If the transfer just happened, wait for the next reconciliation cycle. The VM's GECOS field will update automatically.

## Technical

### What hypervisors are supported?
Proxmox VE and libvirt/KVM. The provisioner is pluggable — both implement the same interface.

### Can I run BlockHost in a VM for testing?
Yes. Build with `--testing` flag for SSH access and btrfs snapshots. Use `virt-install` or import the ISO into your preferred hypervisor.

### How does the wallet authentication actually work?
A custom PAM module (`libpam-web3`) is installed on each VM. During SSH login, it presents a signing page via a local HTTPS service. You sign a challenge with your wallet, the PAM module verifies the signature matches the wallet address in the GECOS field. It's OS-level authentication, not an application wrapper.
