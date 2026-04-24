# blockhost-common: Make web3-defaults.yaml chain-agnostic

The default `etc/blockhost/web3-defaults.yaml` ships EVM-specific values (`chain_id: 11155111`, `rpc_url` pointing to Sepolia) and stale sections (`signing_page`, `deployer`). On non-EVM engines, these defaults persist after installation and confuse downstream readers.

The engine's finalization step owns the entire `blockchain:` section — common should ship a minimal skeleton with no chain-specific assumptions.

## Replace `etc/blockhost/web3-defaults.yaml` with:

```yaml
# Blockhost Web3/Blockchain Configuration
#
# This file is populated by the engine's finalization step.
# The engine writes chain-specific keys under the blockchain: section.
# Do not add chain-specific defaults here — common is chain-agnostic.
#
# Used by: engine monitor, engine CLIs, validate_system.py

blockchain: {}

# Deployer wallet configuration
# The key file path is set by the engine's wallet finalization step
deployer:
  private_key_file: "/etc/blockhost/deployer.key"

# OTP authentication settings
auth:
  otp_length: 6
  otp_ttl_seconds: 300
```

## What was removed

- `blockchain.chain_id` — EVM-specific, set by EVM engine finalization
- `blockchain.rpc_url` — EVM-specific, set by EVM engine finalization
- `blockchain.nft_contract` — set by engine finalization (all engines)
- `signing_page` section — now owned by libpam-web3 chain plugins, not common
- All EVM-specific comments

## What stays

- `deployer.private_key_file` — path convention used by all engines
- `auth` section — OTP settings used by libpam-web3 core (chain-agnostic)
- `blockchain: {}` — empty section so the file is valid YAML; engine fills it

## Also update

Update `DESIGN.md` if it references the old `web3-defaults.yaml` schema.
