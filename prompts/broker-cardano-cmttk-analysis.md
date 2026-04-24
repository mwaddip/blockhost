# Analyze: Migration from TyphonJS to cmttk

## Context

The Cardano engine went from 200MB of dependencies (Lucid + MeshJS + WASM + libsodium) down to 184KB by replacing framework libraries with purpose-built ones:

- `@stricahq/bip32ed25519` → `noble-bip32ed25519` (pure TS, 4.5KB, GitHub: `mwaddip/noble-bip32ed25519`)
- `bip39` → `@scure/bip39` (English-only wordlist, ~80KB smaller)
- Lucid/MeshJS → `cmttk` (Cardano Minimal Transaction Toolkit, GitHub: `mwaddip/cmttk`)
- libsodium → noble-bip32ed25519 ships a sodium shim at `noble-bip32ed25519/sodium`

The broker's Cardano adapter currently uses `@stricahq/typhonjs` for transaction building, `@stricahq/bip32ed25519` for key derivation, and `bip39` for mnemonics. The `@noble/*` packages stay as-is.

## Task

**This is an analysis only — do not implement changes.** Produce a detailed assessment of what it would take to replace TyphonJS + stricahq/bip32ed25519 + bip39 with cmttk + noble-bip32ed25519 + @scure/bip39 in the Cardano adapter (both adapter/ and client/).

### What to analyze

1. **Inventory all TyphonJS usage** across both adapter and client:
   - Transaction building (inputs, outputs, minting, redeemers)
   - Plutus Data / datum construction (constructors, fields)
   - CBOR encoding
   - Fee calculation (`calculateMinUtxoAmountBabbage` + Conway margin)
   - Address handling (BaseAddress with staking key, bech32)
   - Protocol parameter handling
   - Transaction signing (Ed25519)
   - Transaction submission (if TyphonJS handles this)

2. **Map each usage to cmttk** — check what cmttk already provides by reading its source (install with `npm i github:mwaddip/cmttk` and look at the exports). Specifically check:
   - Does cmttk support minting with redeemers?
   - Does cmttk support Plutus Data constructors (for RequestDatum/ResponseDatum)?
   - Does cmttk support collateral inputs?
   - Does cmttk have fee calculation or min-UTXO calculation?
   - Does cmttk handle BaseAddress derivation (payment + staking)?

3. **Identify gaps** — what does TyphonJS provide that cmttk doesn't? For each gap:
   - How complex would it be to add to cmttk?
   - Could it be done inline in the adapter instead?
   - Is it a blocker or nice-to-have?

4. **bip32ed25519 migration** — the noble-bip32ed25519 API may differ from stricahq's. Map the key derivation calls (derive path, get public/private key, sign) and note any differences.

5. **Bundle size impact** — estimate the size reduction. Current TyphonJS brings its own CBOR and crypto. Removing it in favor of cmttk (which is much smaller) + noble libs should shrink the bundle.

6. **Risk assessment** — what could go wrong? Transaction building is money-critical. Identify the highest-risk areas of the migration.

### Output format

Produce a structured report with:
- A table mapping each TyphonJS API call → cmttk equivalent (or "MISSING")
- A list of cmttk gaps with complexity estimates
- A summary recommendation: migrate now, migrate after cmttk adds X, or don't migrate
