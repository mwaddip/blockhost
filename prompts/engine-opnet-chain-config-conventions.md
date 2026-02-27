# OPNet Engine: Align chain_config with EVM conventions

## Context

`validate_system.py` checks the post-finalization system state. Several checks fail because the OPNet engine's `finalize_chain_config()` uses different config key names and omits files that the EVM engine writes. The validator is chain-agnostic — the OPNet engine must use the same conventions as EVM.

Reference: EVM engine's chain_config step in `blockhost-engine/blockhost/engine_evm/wizard.py` lines 1060-1174.

## Changes needed in `blockhost/engine_opnet/wizard.py`, function `finalize_chain_config()`

### 1. Rename `subscriptions_contract` → `subscription_contract` in web3-defaults.yaml

Line 1015: `"subscriptions_contract": sub_contract,` → `"subscription_contract": sub_contract,`

Also update any other code that reads this key (check the whole codebase — monitor, bw, is, deploy scripts, etc. — anything reading `subscriptions_contract` from web3-defaults.yaml must be updated to `subscription_contract`).

### 2. Add missing keys to web3-defaults.yaml

The `blockchain` section needs two additional keys:
- `chain_id` (from `blockchain.get("chain_id")` — already in the session config)
- `server_public_key` (read from `/etc/blockhost/server.pubkey`, same as it's already done for blockhost.yaml)

### 3. Rename `server.mnemonic_file` → `server.key_file` in blockhost.yaml

Line 1044: `"mnemonic_file": "/etc/blockhost/deployer.key",` → `"key_file": "/etc/blockhost/deployer.key",`

Also update any code that reads `server.mnemonic_file` from blockhost.yaml — it should read `server.key_file` instead.

### 4. Add `destination_mode` to blockhost.yaml admin section

After line 1065, add (matching EVM exactly):
```python
if admin_commands.get("enabled"):
    bh_config["admin"]["destination_mode"] = admin_commands.get(
        "destination_mode", "self"
    )
```

### 5. Write `/opt/blockhost/.env` file

After the admin-signature.key block (after line 1096), add the .env file write (matching EVM exactly):

```python
# --- .env ---
opt_dir = Path("/opt/blockhost")
opt_dir.mkdir(parents=True, exist_ok=True)
env_lines = [
    f"RPC_URL={rpc_url}",
    f"BLOCKHOST_CONTRACT={sub_contract}",
    f"NFT_CONTRACT={nft_contract}",
    f"DEPLOYER_KEY_FILE=/etc/blockhost/deployer.key",
]
env_path = opt_dir / ".env"
env_path.write_text("\n".join(env_lines) + "\n")
_set_blockhost_ownership(env_path, 0o640)
```

### 6. Fix key file permissions in `finalize_wallet()` (or wherever deployer.key is written)

Both `server.key` and `deployer.key` must be `0o640` (root:blockhost, group-readable), not `0o600`. The blockhost user needs to read these files. Search for where these files are written and ensure `_set_blockhost_ownership(path, 0o640)` is called.

## Summary of convention alignment

| Item | OPNet (current) | EVM (correct) |
|------|-----------------|---------------|
| Subscription contract key | `subscriptions_contract` | `subscription_contract` |
| Server key path key | `server.mnemonic_file` | `server.key_file` |
| `chain_id` in web3-defaults | missing | present |
| `server_public_key` in web3-defaults | missing | present |
| `admin.destination_mode` in blockhost.yaml | missing | present when admin enabled |
| `/opt/blockhost/.env` | missing | written |
| Key file permissions | 0o600 | 0o640 |

## Important

After making these changes, search the entire OPNet codebase for any code reading the OLD key names (`subscriptions_contract`, `mnemonic_file`) and update those references too. This includes TypeScript source (monitor, bw, is, fund-manager) and any bash scripts.
