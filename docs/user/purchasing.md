# Purchasing a Subscription

## What you need

- A crypto wallet (MetaMask for EVM, OPWallet for OPNet, Nami/Eternl/Lace for Cardano)
- Enough funds to cover the subscription (payment token varies by operator)
- The operator's signup page URL

## How it works

1. **Visit the signup page** — the operator provides the URL (typically `https://signup.<domain>`)
2. **Connect your wallet** — click "Connect Wallet" and approve the connection in your wallet extension
3. **Sign a message** — this creates your admin credential. The signature is used to encrypt your SSH access details into the NFT. **Remember what message you signed** — you'll need to sign the same message to decrypt your credentials later.
4. **Choose a plan** — select the subscription tier and duration
5. **Purchase** — confirm the on-chain transaction in your wallet. This sends payment to the subscription contract.
6. **Wait for provisioning** — the operator's system detects your purchase and automatically:
   - Provisions a VM
   - Mints an NFT to your wallet with encrypted SSH credentials
   - Configures IPv6 access
7. **View your servers** — the signup page shows your active subscriptions. Click to decrypt your connection details.

## What you receive

An **NFT** in your wallet containing:
- Your encrypted SSH credentials (only you can decrypt them)
- Your subscription ID
- Proof of ownership

The NFT is your access key. As long as you hold it, you can access your VM. Transfer the NFT, transfer the access.

## Renewing

Subscriptions have an expiry. When it approaches:
- Purchase an extension on the same subscription
- Your VM continues running without interruption

If you let it expire:
- VM is **suspended** (stopped, data preserved)
- A grace period allows you to renew and resume
- After the grace period, the VM is destroyed

## Cancelling

Cancellation policy depends on the chain:
- **EVM/OPNet**: Cancel through the subscription contract. Refund policy is set by the operator.
- **Cardano**: Your funds sit in your own UTXO. Cancel by spending it back to yourself (validator enforces refund rules).
