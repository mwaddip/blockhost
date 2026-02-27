# OPNet Engine: Ship generate-wallet root agent action

## Context

The root agent (blockhost-common) loads action plugins from `/usr/share/blockhost/root-agent-actions/`. Each `.py` file that exports an `ACTIONS` dict gets its handlers registered. Common is removing its `generate-wallet` handler (which used `cast`, an EVM tool). Each engine must now provide its own.

## What to create

A new file installed to `/usr/share/blockhost/root-agent-actions/wallet.py` (or similar — any name that doesn't start with `_`).

It must export:
```python
ACTIONS = {
    'generate-wallet': handle_generate_wallet,
}
```

## Handler contract

The handler receives `params` dict with:
- `name` (string) — wallet name (e.g. `hot`)

It must:
1. Validate `name` (short alphanumeric, not a reserved name like `admin`, `server`)
2. Check `/etc/blockhost/<name>.key` doesn't already exist
3. Generate a new private key (secp256k1, 32 bytes hex)
4. Write the private key to `/etc/blockhost/<name>.key`
5. Set ownership to `root:blockhost`, mode `0o640`
6. Derive the public address from the private key
7. Add the entry to `/etc/blockhost/addressbook.json` with `{"address": "0x...", "keyfile": "/etc/blockhost/<name>.key"}`
8. Return `{'ok': True, 'address': '0x...', 'keyfile': str(keyfile)}`

For OPNet, the address derivation should use the same method as the rest of the engine (secp256k1 public key). The fund manager and `ab` CLI will use this address.

You can import shared utilities from `_common.py` (same directory):
```python
from _common import CONFIG_DIR, SHORT_NAME_RE, WALLET_DENY_NAMES, run, log
```

## Packaging

Add the file to `packaging/build.sh` so it gets installed to `/usr/share/blockhost/root-agent-actions/` in the .deb package.
