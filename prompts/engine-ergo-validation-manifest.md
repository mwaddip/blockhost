# Add `validation` section to engine.json manifest

## Context

`validate_system.py` in the installer now reads engine-declared validation requirements from `engine.json`. Without a `validation` section, it falls back to EVM defaults — which fail on Ergo because Ergo uses different config keys, .env variable names, and contract formats.

## Change

Add a `validation` section to `engine.json`:

```json
{
  "validation": {
    "web3_required_keys": [
      "blockchain.node_url",
      "blockchain.network",
      "blockchain.nft_contract",
      "blockchain.subscription_ergo_tree",
      "blockchain.server_public_key"
    ],
    "env_required_vars": [
      "NODE_URL",
      "DEPLOYER_KEY_FILE"
    ],
    "env_rpc_var": "NODE_URL",
    "contract_pattern": "^[0-9a-fA-F]+$",
    "signup_markers": ["ergo", "nautilus"]
  }
}
```

### Field descriptions

- `web3_required_keys`: Keys that must exist in `/etc/blockhost/web3-defaults.yaml`. Use dot notation for nested keys.
- `env_required_vars`: Variables that must be set in `/opt/blockhost/.env`.
- `env_rpc_var`: The name of the RPC/node URL variable in `.env` (checked separately for presence).
- `contract_pattern`: Regex for validating `nft_contract` and `subscription_contract` values. Ergo contracts are hex ErgoTree strings, not addresses.
- `signup_markers`: Strings that should appear in `signup.html` to verify the signup page has the right chain integration. Case-insensitive.

### Notes

- Adjust the `web3_required_keys` to match exactly what your finalization writes to `web3-defaults.yaml`
- Adjust `env_required_vars` to match what your `.env` template writes
- The `contract_pattern` should match both the `nft_contract` (64-char hex token ID) and `subscription_ergo_tree` (variable-length hex). `^[0-9a-fA-F]+$` covers both.
