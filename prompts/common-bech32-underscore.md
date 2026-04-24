# blockhost-common: Fix bech32 address validation for Cardano testnet

In `usr/share/blockhost/root-agent-actions/_common.py` line 27, the bech32 regex rejects Cardano testnet addresses (`addr_test1...`) because the human-readable part (HRP) contains an underscore:

```python
_BECH32_ADDRESS_RE = re.compile(r'^[a-z][a-z0-9]{0,9}1[02-9ac-hj-np-z]{39,90}$')
```

`addr_test` has 9 chars with an underscore — the regex only allows `[a-z0-9]` in the HRP.

Fix: allow underscores in the HRP and extend the max length to accommodate `addr_test` (9 chars before the `1` separator):

```python
_BECH32_ADDRESS_RE = re.compile(r'^[a-z][a-z0-9_]{0,14}1[02-9ac-hj-np-z]{39,90}$')
```

This matches both mainnet (`addr1...`) and testnet (`addr_test1...`) Cardano addresses, as well as any other bech32 scheme.
