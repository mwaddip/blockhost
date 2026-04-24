# libpam-web3 Ergo plugin: address_pattern off-by-one

## Observable problem

The Ergo PAM plugin's `address_pattern` rejects valid Ergo P2PK addresses, causing libpam-web3 to fall through to the `evm` default chain. The symptom on a provisioned VM: the signing URL shown at SSH login advertises **port 63108** (`chain_port("evm")`) instead of **22898** (`chain_port("ergo")`), and that port isn't listening — so the user can't reach the signing page.

## Root cause

In `plugins/ergo/src/main.rs`, the plugin's info response reports:

```rust
address_pattern: "^[39][1-9A-HJ-NP-Za-km-z]{50}$",
```

The `{50}` quantifier expects a total of **51 characters** (1 prefix + 50), but real Ergo P2PK addresses are **52 characters** (1 prefix + 51). Example failing address from a real provisioned VM:

```
3Wy6H5zue2YARihJKk4ccYF239cDWZYSj43qfVmzearpoy1jTPa8
```

Length 52 → fails the pattern → `find_plugin_for_address` returns `None` → PAM module logs `"No plugin matched wallet — using EVM default"` and derives port from `"evm"`.

## Verified via

Syslog from a running test VM:

```
pam_web3: GECOS wallet: 3Wy6H5zue2YARihJKk4ccYF239cDWZYSj43qfVmzearpoy1jTPa8
pam_web3: Discovered plugin: ergo (^[39][1-9A-HJ-NP-Za-km-z]{50}$)
pam_web3: No plugin matched wallet — using EVM default
```

Python regex check confirms:

```
Wallet length: 52
Match {50}: False
Match {51}: True
```

## Size reference (for correctness check)

Ergo P2PK addresses encode: 1-byte network prefix + 33-byte compressed pubkey + 4-byte Blake2b256 checksum = 38 bytes. Base58 encoding of 38 bytes is 52 characters for typical (non-zero-leading) prefix bytes. Both testnet (`0x10` → starts with `3`) and mainnet (`0x00`/`0x01` → starts with `9`) produce 52-char addresses.

## Requested fix

Update the address_pattern in `plugins/ergo/src/main.rs` to require 52 characters total. Verify against sigma-rust's canonical address format if ambiguous — do not guess.

## Verification

After rebuild + redeploy:
- `echo '{"command":"info"}' | /usr/lib/libpam-web3/plugins/ergo` should report the corrected pattern
- The pattern must match a real testnet P2PK address (e.g., the one above)
- A fresh SSH auth to a provisioned VM should produce a signing URL ending in `:22898` (ergo port), not `:63108` (evm fallback)

## Contract reference

Plugin info response format is specified in the libpam-web3 internal plugin discovery contract (`plugins/` layout, `{"command":"info"}` → `{"chain": str, "address_pattern": str}`). No contract change needed — this is a correctness fix within the existing contract.
