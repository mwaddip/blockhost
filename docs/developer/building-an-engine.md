# Building an Engine

An engine connects BlockHost to a blockchain. It handles wallet operations, smart contract interaction, subscription monitoring, and NFT minting. The provisioner and installer don't know what chain is running — they interact with the engine through a standardized interface.

## What you need to implement

### 1. Engine manifest (`engine.json`)

Installed to `/usr/share/blockhost/engine.json`. This is how the installer discovers your engine.

```json
{
  "name": "mychain",
  "version": "0.1.0",
  "display_name": "MyChain (Testnet)",
  "accent_color": "#FF5500",
  "setup": {
    "first_boot_hook": "/usr/share/blockhost/engine-hooks/first-boot.sh",
    "wizard_module": "blockhost.engine_mychain.wizard",
    "finalization_steps": ["wallet", "contracts", "chain_config"],
    "post_finalization_steps": ["mint_nft", "plan", "revenue_share"]
  },
  "config_keys": {
    "session_key": "blockchain"
  },
  "constraints": {
    "address_pattern": "^0x[0-9a-fA-F]{40}$",
    "native_token": "eth",
    "native_token_label": "ETH",
    "token_pattern": "^0x[0-9a-fA-F]{40}$",
    "address_placeholder": "0x..."
  }
}
```

The `constraints` object tells the installer how to validate chain-specific input (address formats, token patterns). The `accent_color` tints the installer UI.

### 2. Wizard plugin (Python)

A Flask blueprint that provides the blockchain configuration page in the setup wizard.

Required exports:

| Export | Type | Purpose |
|--------|------|---------|
| `blueprint` | `flask.Blueprint` | Registers wizard route(s) |
| `get_finalization_steps()` | function | Returns `list[tuple[str, str, callable]]` |
| `get_summary_data(session)` | function | Returns `dict` for summary page |
| `get_summary_template()` | function | Returns template path string |
| `validate_address(address)` | function | Chain-specific address validation |

### 3. CLI tools

| Command | Purpose |
|---------|---------|
| `bw` | Wallet operations: send, balance, withdraw, swap, split, who, config, plan, set |
| `ab` | Addressbook management: add, del, up, new, list, --init |
| `is` | Identity predicates: `is <wallet> <nft_id>`, `is contract <address>` |
| `blockhost-mint-nft` | Mint access credential NFT: `--owner-wallet`, `--user-encrypted` |
| `blockhost-deploy-contracts` | Deploy smart contracts from compiled artifacts |

All CLIs read config from `/etc/blockhost/web3-defaults.yaml` and the addressbook from `/etc/blockhost/addressbook.json`.

### 4. Blockchain monitor

A long-running service that watches the chain for events:
- New subscription → trigger VM provisioning
- Subscription extended → update expiry
- Subscription cancelled → suspend VM
- NFT ownership transfer → update GECOS

### 5. Signing and signup pages

Separated into **template** (HTML/CSS, replaceable) and **engine bundle** (JS, chain-specific). See [Page Templates](/developer/page-templates) for the contract.

### 6. .deb package

Install locations follow the convention:

| Content | Destination |
|---------|-------------|
| CLI commands | `/usr/bin/blockhost-*` |
| Manifest | `/usr/share/blockhost/engine.json` |
| Monitor | `/usr/bin/blockhost-monitor` (the chain monitor, not the host monitor) |
| Wizard plugin | `/usr/lib/python3/dist-packages/blockhost/engine_<name>/` |
| Systemd units | `/usr/lib/systemd/system/blockhost-monitor.service` |
| Signing page | Template package for VMs |

## Reference implementations

- **EVM**: [`blockhost-engine-evm`](https://github.com/mwaddip/blockhost-engine-evm) — Solidity contracts, ethers.js, MetaMask
- **OPNet**: [`blockhost-engine-opnet`](https://github.com/mwaddip/blockhost-engine-opnet) — AssemblyScript contracts, OPNet SDK, OPWallet

Study the EVM engine first — it's the most straightforward. The OPNet engine shows how to handle a very different chain model (Bitcoin L1, Schnorr signatures, ML-DSA) within the same interface.

## Contract reference

Read [`facts/ENGINE_INTERFACE.md`](https://github.com/mwaddip/blockhost-facts/blob/main/ENGINE_INTERFACE.md) for the full specification.
