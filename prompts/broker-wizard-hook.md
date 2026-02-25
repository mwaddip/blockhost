# Broker Wizard Hook — Implementation Prompt

The blockhost installer wizard now supports a pluggable connectivity options page.
The broker package must provide two files so the wizard can discover and configure it:

1. A manifest file at `/usr/share/blockhost/broker.json`
2. An optional Python module with a `fetch_registry()` function

Pull the updated facts before starting:
```
cd facts && git pull origin feature/opnet
```

Read `facts/BROKER_INTERFACE.md` section 13 ("Wizard Integration Hook") for the full contract.

## What to build

### 1. Manifest: `/usr/share/blockhost/broker.json`

Drop this file via the `.deb` package. The `chains` section must define patterns for each supported chain.

**Required fields:**
- `name`: `"broker"`
- `display_name`: human-readable name shown in wizard
- `description`: one-line description shown below label
- `excludes`: `["manual"]`
- `setup.wizard_module`: Python import path to your wizard hook module
- `chains.*.wallet_pattern`: regex matching wallet address format for that chain
- `chains.*.contract_validation`: regex validating contract address input
- `chains.*.fields`: array of field definitions (see interface doc for schema)

**Chain patterns to implement:**
- EVM: `wallet_pattern: "^0x[0-9a-fA-F]{40}$"`, `contract_validation: "^0x[0-9a-fA-F]{40}$"`
- OPNet: `wallet_pattern: "^bc1p[a-z0-9]{58}$"`, `contract_validation: "^0x[0-9a-fA-F]{64}$"`

Both chains use a single field: `broker_registry` (text input, with `has_auto_fetch: true`).

### 2. Python module: `wizard_hook.py`

Importable as the path in `setup.wizard_module`. Must export:

```python
def fetch_registry(wallet_address: str, testing: bool = False) -> Optional[str]:
    """Return the registry contract address for the given wallet's chain.

    - Derive chain from wallet_address format (same patterns as chains[] in manifest)
    - If testing=True, fetch from registry-testnet.json; else registry.json
    - Fetch the appropriate registry.json from GitHub
    - Return the contract address string, or None if not found
    """
```

The GitHub URLs for registry files come from the same broker repo where registry.json lives.

**For OPNet** (wallet starts with `bc1p`):
- testing: fetch `registry-testnet.json` from the broker repo
- production: fetch `registry.json` from the broker repo

**For EVM** (wallet starts with `0x` and is 42 chars):
- Same pattern, same files

The function must handle network errors gracefully (return None, do not raise).

### 3. Package the files

- `broker.json` → installs to `/usr/share/blockhost/broker.json`
- `wizard_hook.py` → installs as an importable Python module matching `setup.wizard_module`
- Update `build-deb.sh` to include both files

### Testing

After implementing, verify manually:
1. `broker.json` is valid JSON
2. `fetch_registry('0x1234...', testing=True)` returns a string or None (no exception)
3. `fetch_registry('bc1p...', testing=True)` returns a string or None (no exception)
4. Import the module: `python3 -c "from blockhost.broker import wizard_hook; print(wizard_hook.fetch_registry.__doc__)"`
