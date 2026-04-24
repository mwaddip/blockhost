# Cardano Engine: Wallet Template for Installer Wizard

The installer wizard hits `TemplateNotFound: wizard/wallet.html` because the Cardano engine doesn't export `get_wallet_template()`. The fallback template (`wizard/wallet.html`) was moved to engines per the interface spec — each engine provides its own wallet connection page.

## What to implement

### 1. Add wallet template

Create `blockhost/engine_cardano/templates/engine_cardano/wallet.html` — a Jinja2 template that:

- Extends `base.html`
- Uses `{{ step_bar('wallet') }}` from `macros/wizard_steps.html`
- Implements a 3-step flow: Connect → Sign → Continue
- Uses CIP-30 wallet API (`window.cardano`) for wallet detection
- Supports common Cardano wallets: Nami, Eternl, Lace, Flint, Typhon
- Calls `api.signData()` on the wallet to sign the public secret message
- POSTs to `{{ url_for('wizard_wallet') }}` with three hidden form fields:
  - `admin_wallet` — bech32 address
  - `admin_signature` — hex COSE_Sign1 signature
  - `public_secret` — the message that was signed
- Includes a config restore section (upload `.enc` file, POST to `/api/restore-config`)

Reference the OPNet wallet template for the exact HTML structure and UI patterns — it's at `blockhost-engine-opnet/blockhost/engine_opnet/templates/engine_opnet/wallet.html` but you can't read it. Here's the key structure:

```
Section 1: Connect (wallet detection + connect button)
Section 2: Sign (public_secret input + sign button, shown after connect)
Section 3: Confirmed (address display, shown after sign)
Section 4: Restore (file upload for .enc config restore, shown after sign)
Hidden form: admin_wallet, admin_signature, public_secret → POST to wizard_wallet
Continue button: enabled after signature captured
```

### CIP-30 wallet interaction

```javascript
// Detect available wallets
var wallets = Object.keys(window.cardano || {}).filter(function(k) {
    return window.cardano[k] && window.cardano[k].enable;
});

// Connect (returns API object)
var api = await window.cardano[walletName].enable();

// Get address (returns array of hex-encoded addresses)
var addresses = await api.getUsedAddresses();
// or: var addresses = await api.getUnusedAddresses();
// Convert first hex address to bech32 for display

// Sign data (CIP-30 signData)
var hexAddress = addresses[0];
var hexPayload = Buffer.from(publicSecret).toString('hex');
// or: Array.from(new TextEncoder().encode(publicSecret)).map(b => b.toString(16).padStart(2,'0')).join('')
var result = await api.signData(hexAddress, hexPayload);
// result = { signature: "<hex COSE_Sign1>", key: "<hex COSE_Key>" }
```

The `admin_signature` field should contain the hex COSE_Sign1 signature. The COSE_Key (public key) is also needed for verification — the Cardano libpam plugin `.sig` format includes both. For the wizard wallet page, concatenating them or JSON-encoding them as the signature value is fine — the engine's `validate_signature()` and `finalize_mint_nft()` will parse it.

Simplest approach: JSON-encode both as the signature value:
```javascript
adminSignature = JSON.stringify({ signature: result.signature, key: result.key });
```

### 2. Export `get_wallet_template()` from wizard.py

Add to `blockhost/engine_cardano/wizard.py`:

```python
def get_wallet_template() -> str:
    """Return the template name for the engine wallet connection page."""
    return "engine_cardano/wallet.html"
```

### 3. Verify template is packaged

In `packaging/build.sh`, the template copy section already handles `templates/engine_cardano/*.html` — verify the new `wallet.html` gets included.
