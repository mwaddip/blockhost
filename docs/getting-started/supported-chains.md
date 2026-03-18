# Supported Chains

BlockHost is chain-agnostic. The blockchain engine is a pluggable component — each engine implements the same interface, and the rest of the system doesn't know or care which chain is running.

## Production-Ready

### EVM (Ethereum, Polygon, Base, Arbitrum)

- **Engine:** `blockhost-engine-evm`
- **Wallet:** MetaMask or any injected Ethereum provider
- **Contracts:** Solidity (ERC-721 NFT + subscription manager)
- **Signing:** secp256k1 (ECDSA)
- **Testnets tested:** Sepolia

The original engine. EVM-compatible chains share the same contract bytecode — deploy once, works on any EVM chain.

### OPNet (Bitcoin L1)

- **Engine:** `blockhost-engine-opnet`
- **Wallet:** OPWallet browser extension
- **Contracts:** AssemblyScript (OPNet smart contracts via Tapscript)
- **Signing:** Schnorr / ML-DSA
- **Testnets tested:** OPNet Signet

Smart contracts on Bitcoin L1 without sidechains or bridges. Subscriptions and NFTs live directly on Bitcoin. Uses OPNet's Tapscript-encoded calldata — valid Bitcoin transactions paying valid fees.

## In Development

### Cardano

- **Engine:** `blockhost-engine-cardano`
- **Wallet:** Nami, Eternl, Lace (CIP-30 compatible)
- **Contracts:** Aiken validators
- **Signing:** Ed25519
- **Testnets tested:** Preprod

Uses a UTXO-native subscription model inspired by [cardano-swaps](https://github.com/fallen-icarus/cardano-swaps). Instead of locking funds in a shared contract, each subscriber creates their own UTXO at a validator address. No custody transfer, no UTXO contention. The validator enforces payment collection and cancellation rules through pure math.

NFTs are Cardano native assets — no smart contract needed for the token itself, just a minting policy tied to the subscription validator.

## Adding a New Chain

Building an engine requires implementing:

1. **Engine manifest** (`engine.json`) — identity, wizard module, finalization steps, constraints
2. **Wizard plugin** — Flask blueprint for the installer's blockchain configuration page
3. **Finalization steps** — wallet generation, contract deployment, chain config
4. **Monitor** — blockchain event watcher that detects new subscriptions
5. **CLI tools** — `bw` (wallet ops), `ab` (addressbook), `is` (identity predicates), `mint_nft`
6. **Signing page** — wallet connect + signature capture for SSH authentication
7. **Signup page** — subscription purchase flow

See the [Building an Engine](/developer/building-an-engine) guide for the full walkthrough.
