# EVM Engine: Ship generate-wallet root agent action

## Context

The root agent (blockhost-common) loads action plugins from `/usr/share/blockhost/root-agent-actions/`. Each `.py` file that exports an `ACTIONS` dict gets its handlers registered. Common has removed its `generate-wallet` handler (which used `cast`). Each engine must now provide its own.

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
6. Derive the EVM address from the private key (keccak256 of uncompressed public key, last 20 bytes, `0x`-prefixed)
7. Add the entry to `/etc/blockhost/addressbook.json` with `{"address": "0x...", "keyfile": "/etc/blockhost/<name>.key"}`
8. Return `{'ok': True, 'address': '0x...', 'keyfile': str(keyfile)}`

For EVM address derivation, use the `cryptography` library (already available):
```python
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import hashlib

raw_key = secrets.token_hex(32)
priv_int = int(raw_key, 16)
priv_key = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())
pub_bytes = priv_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
# EVM address: keccak256 of uncompressed pubkey (minus 0x04 prefix), last 20 bytes
from Crypto.Hash import keccak  # or use pysha3 / hashlib if available
k = keccak.new(digest_bits=256)
k.update(pub_bytes[1:])  # skip 0x04 prefix
address = '0x' + k.hexdigest()[-40:]
```

If `pycryptodome` isn't available, `pysha3` or Python 3.11+ `hashlib` with `sha3_256` would also work — but keccak256 is NOT the same as SHA3-256. Use whichever keccak256 implementation is already available in the engine's dependencies.

You can import shared utilities from `_common.py` (same directory):
```python
from _common import CONFIG_DIR, SHORT_NAME_RE, WALLET_DENY_NAMES, run, log
```

## Packaging

Add the file to `packaging/build.sh` so it gets installed to `/usr/share/blockhost/root-agent-actions/` in the .deb package.
