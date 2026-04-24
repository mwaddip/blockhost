# Cardano Engine: Interface Compliance Fixes

Three issues found during engine interface audit. All are small, isolated changes.

## 1. Export `validate_address` from wizard module

The installer (`app.py`) discovers the engine's address validator via:
```python
fn = getattr(_engine['module'], 'validate_address', None)
```

The wizard currently exports `validate_cardano_address` — the installer won't find it. Add an alias at module level in `blockhost/engine_cardano/wizard.py`:

```python
# After the validate_cardano_address definition (around line 73):
# Alias for installer discovery (app.py calls getattr(module, 'validate_address'))
validate_address = validate_cardano_address
```

That's it. One line.

## 2. Add `signature_pattern` to `engine.json` constraints

The admin panel uses `constraints.signature_pattern` to pre-validate user-submitted signatures. Currently missing from `engine.json`.

Cardano signatures are COSE_Sign1 encoded — the raw hex is variable-length but always hex. Add to the `constraints` object in `engine.json`:

```json
"signature_pattern": "^[0-9a-fA-F]{2,}$"
```

This is deliberately loose (any even-length hex) because COSE_Sign1 payloads vary in size. The actual cryptographic validation happens in the libpam-web3 Cardano plugin — this is just a format pre-check to reject obvious garbage before it hits the chain.

## 3. Add virtual package conflict to DEBIAN/control

Only one engine can be active per host. Instead of listing every engine by name, use the Debian virtual package pattern.

In `packaging/build.sh`, update the `DEBIAN/control` heredoc. Change:

```
Provides: bhcrypt
```

To:

```
Provides: bhcrypt, blockhost-engine
Conflicts: blockhost-engine
```

A package never conflicts with itself through a virtual package, so this won't block its own install — but will prevent any other `blockhost-engine-*` (that also declares `Provides: blockhost-engine`) from coexisting.

## 4. Update facts submodule

The `ENGINE_INTERFACE.md` has been updated to document the virtual package pattern.

```bash
cd facts && git fetch origin main && git checkout origin/main && cd ..
git add facts
```

Include the facts update in your commit.
