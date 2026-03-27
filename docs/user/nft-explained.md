# Your NFT Explained

## It's a key, not a JPEG

BlockHost NFTs are access credentials, not collectibles. Your NFT proves you own a VM subscription and contains the encrypted data needed to connect.

## What's in it

| Field | Purpose |
|-------|---------|
| Token ID | Unique identifier for your subscription |
| Owner | Your wallet address — determines who can access the VM |
| userEncrypted | Your SSH credentials, encrypted so only you can read them |

The `userEncrypted` field is encrypted with a key derived from your wallet signature. Only someone who can sign with your wallet can decrypt it. The operator can't read it. Other users can't read it. It's between you and your private key.

## How decryption works

1. You sign a message with your wallet (the same message from signup)
2. A decryption key is derived from your signature
3. The `userEncrypted` field is decrypted locally in your browser
4. Your SSH credentials are revealed

This happens entirely client-side. The decryption key never leaves your device.

## Transferability

NFTs can be transferred like any other token on the chain. When you transfer:

- The new owner's wallet becomes the authorized login
- The VM's GECOS field is automatically updated
- The old credentials become inaccessible (encrypted to the original signer)
- The new owner can re-encrypt credentials to their own wallet via the admin panel (future)

This makes VM access tradeable, inheritable, and delegatable — all without the operator doing anything.

## One NFT per subscription

Each subscription gets exactly one NFT (token ID 0 is reserved for the operator's admin credential). The NFT persists as long as the VM exists. Destroying the VM doesn't burn the NFT — the chain record survives.

## Chain differences

| Chain | NFT type | Storage |
|-------|----------|---------|
| EVM | ERC-721 smart contract | Contract storage |
| OPNet | OP-721 smart contract | OPNet contract state |
| Cardano | Native asset + reference datum | UTXO with datum |

The interface is the same regardless of chain. Your wallet holds the NFT, the NFT holds your credentials, your signature unlocks them.
