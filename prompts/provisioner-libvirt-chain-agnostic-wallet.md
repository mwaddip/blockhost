# Libvirt Provisioner: Remove EVM-specific wallet address validation

`scripts/vm-create.py` line 54 hardcodes an EVM address regex:

```python
WALLET_RE = re.compile(r'^0x[0-9a-fA-F]{40}$')
```

This rejects Cardano bech32 addresses (`addr_test1...`), OPNet addresses, and any non-EVM format. The provisioner interface contract (`facts/PROVISIONER_INTERFACE.md` line 121) explicitly says `--owner-wallet` accepts "chain-agnostic format."

## Fix

Replace the hardcoded regex with a validation that reads the engine manifest's `constraints.address_pattern`:

```python
def _load_wallet_pattern():
    """Load address format from engine manifest, or accept any non-empty string."""
    try:
        manifest = json.loads(Path('/usr/share/blockhost/engine.json').read_text())
        pattern = manifest.get('constraints', {}).get('address_pattern')
        if pattern:
            return re.compile(pattern)
    except (OSError, json.JSONDecodeError, re.error):
        pass
    return None

WALLET_RE = _load_wallet_pattern()
```

Then at line 286-287, change:

```python
if not WALLET_RE.match(args.owner_wallet):
    fail(f"Invalid wallet address: {args.owner_wallet!r} (expected 0x + 40 hex chars)")
```

To:

```python
if not args.owner_wallet or not args.owner_wallet.strip():
    fail("Empty wallet address")
if WALLET_RE and not WALLET_RE.match(args.owner_wallet):
    fail(f"Invalid wallet address format: {args.owner_wallet!r}")
```

If no engine manifest exists or no pattern is defined, any non-empty address is accepted.

Also update the `--help` text at line 269 from `"Owner wallet address (0x...)"` to `"Owner wallet address"`.

## Also check

`scripts/vm-update-gecos.py` — verify it doesn't have the same hardcoded validation on the wallet address argument.
