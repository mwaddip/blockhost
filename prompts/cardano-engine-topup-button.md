# Cardano Engine: Add wallet topup button to blockchain wizard

The blockchain wizard page needs a "Fund via Wallet" button that opens the admin's CIP-30 wallet and sends ADA to the deployer address. The OPNet engine has this for OPWallet — the Cardano version uses CIP-30.

## Pattern

The signup page (`scripts/signup-engine.js`) already has a complete inline CBOR transaction builder with CIP-30 wallet integration — UTXO parsing, coin selection, transaction body construction, signTx/submitTx. No external libraries. The topup transaction is much simpler than a subscription transaction: just a basic ADA transfer (inputs → output + change).

## What to add to `templates/engine_cardano/blockchain.html`

### 1. Balance display + topup UI

After the "Fund this address with ADA" message (around line 118 in the generate section), replace the static funding hint with an interactive section:

```html
<div style="margin-top: 1rem; padding: 1rem; background: var(--bg-secondary); border-radius: 4px;">
    <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 0.75rem;">
        <label style="margin: 0;">Balance:</label>
        <span id="wallet-balance" style="font-size: 1.25rem; font-weight: 500;">—</span>
        <button type="button" class="btn btn-small btn-secondary" onclick="checkBalance('generate')">
            Refresh
        </button>
    </div>
    <p style="font-size: 0.875rem; margin: 0 0 0.75rem;">
        Fund this wallet with ADA to continue. At least <strong>10 ADA</strong> recommended.
    </p>
    <div style="display: flex; gap: 0.5rem; align-items: center;">
        <input type="number" id="topup-amount" step="1" min="2" value="10" style="width: 6rem;">
        <span style="font-size: 0.875rem;">ADA</span>
        <button type="button" class="btn btn-small btn-primary"
                onclick="topUpWallet('generate')" id="topup-btn">
            Fund via Wallet
        </button>
    </div>
    <div id="topup-status" class="text-muted mt-1" style="font-size: 0.75rem;"></div>
</div>
```

Add the same for the import section (with `import-` prefixed IDs).

### 2. Balance check via Koios (browser-side)

```javascript
function checkBalance(mode) {
    var addr = mode === 'generate'
        ? document.getElementById('deployer-address').textContent.trim()
        : document.getElementById('import-deployer-address').textContent.trim();
    var balanceEl = document.getElementById(mode === 'generate' ? 'wallet-balance' : 'import-wallet-balance');
    if (!addr || addr === '-') { balanceEl.textContent = '—'; return; }

    var network = document.getElementById('network').value;
    var koiosUrl = network === 'mainnet' ? 'https://api.koios.rest/api/v1'
        : network === 'preview' ? 'https://preview.koios.rest/api/v1'
        : 'https://preprod.koios.rest/api/v1';

    fetch(koiosUrl + '/address_info', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ _addresses: [addr] })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data && data[0] && data[0].balance) {
            var ada = (parseInt(data[0].balance) / 1000000).toFixed(2);
            balanceEl.textContent = ada + ' ADA';
        } else {
            balanceEl.textContent = '0 ADA';
        }
    })
    .catch(function() { balanceEl.textContent = 'Error'; });
}
```

Call `checkBalance('generate')` automatically after wallet generation succeeds (in the `generateWallet` success handler).

### 3. Topup transaction via CIP-30

Use the same CBOR encoding pattern as `signup-engine.js`. The topup transaction is minimal — no scripts, no datums, no minting. Just:
- Parse wallet UTXOs from CIP-30 (`api.getUtxos()`)
- Select inputs that cover amount + fee
- Build transaction body: inputs, outputs (deployer + change), fee, TTL
- Sign via `api.signTx(txHex, true)` (partial=true since we assemble witnesses)
- Submit via `api.submitTx(signedTxHex)`

Copy the CBOR helpers from `signup-engine.js` (or extract them into a shared snippet). The ones you need:
- `cborHeader`, `cborUint`, `cborBytes`, `cborArray`, `cborMap`, `cborTag`
- `hexToBytes`, `bytesToHex`, `concatBytes`
- `decodeCbor` (for parsing CIP-30 UTXOs)
- `parseCip30Utxo` (extract txHash, index, lovelace from CBOR)

The topup function:

```javascript
async function topUpWallet(mode) {
    var deployerAddr = mode === 'generate'
        ? document.getElementById('deployer-address').textContent.trim()
        : document.getElementById('import-deployer-address').textContent.trim();
    var amountInput = document.getElementById(mode === 'generate' ? 'topup-amount' : 'import-topup-amount');
    var statusEl = document.getElementById(mode === 'generate' ? 'topup-status' : 'import-topup-status');
    var btn = document.getElementById(mode === 'generate' ? 'topup-btn' : 'import-topup-btn');

    var lovelace = BigInt(Math.floor(parseFloat(amountInput.value) * 1000000));
    if (!deployerAddr || deployerAddr === '-') { statusEl.textContent = 'Generate wallet first'; return; }
    if (lovelace < 2000000n) { statusEl.textContent = 'Minimum 2 ADA'; return; }

    // Find CIP-30 wallet
    if (!window.cardano) { statusEl.textContent = 'No Cardano wallet detected'; return; }
    var walletName = Object.keys(window.cardano).find(function(k) {
        return window.cardano[k] && typeof window.cardano[k].enable === 'function'
            && !['ccvault'].includes(k); // skip known non-wallet entries
    });
    if (!walletName) { statusEl.textContent = 'No CIP-30 wallet found'; return; }

    btn.disabled = true;
    statusEl.textContent = 'Connecting to ' + walletName + '...';

    try {
        var api = await window.cardano[walletName].enable();

        // Get wallet UTXOs and change address
        var utxoHexList = await api.getUtxos();
        var changeAddrHex = (await api.getChangeAddress());
        if (!utxoHexList || !utxoHexList.length) throw new Error('No UTXOs in wallet');

        // Parse UTXOs
        var utxos = utxoHexList.map(parseCip30Utxo).filter(Boolean);

        // Simple coin selection: pick UTXOs until we cover amount + estimated fee
        var estimatedFee = 200000n; // 0.2 ADA — generous for a simple tx
        var target = lovelace + estimatedFee;
        var selected = [];
        var inputTotal = 0n;
        for (var i = 0; i < utxos.length && inputTotal < target; i++) {
            if (utxos[i].lovelace > 0n) {
                selected.push(utxos[i]);
                inputTotal += utxos[i].lovelace;
            }
        }
        if (inputTotal < target) throw new Error('Insufficient ADA in wallet');

        var changeLovelace = inputTotal - lovelace - estimatedFee;

        // Build transaction body
        // Convert deployer bech32 address to hex for CBOR
        var deployerAddrHex = bech32ToHex(deployerAddr);

        var inputsCbor = cborTag(258, cborArray(selected.map(function(u) {
            return cborArray([cborBytes(u.txHash), cborUint(BigInt(u.index))]);
        })));

        var outputs = [
            // Output to deployer
            cborMap([
                [cborUint(0), cborBytes(hexToBytes(deployerAddrHex))],
                [cborUint(1), cborUint(lovelace)],
            ]),
        ];
        // Change output (only if change > min UTXO)
        if (changeLovelace >= 1000000n) {
            outputs.push(cborMap([
                [cborUint(0), cborBytes(hexToBytes(changeAddrHex))],
                [cborUint(1), cborUint(changeLovelace)],
            ]));
        }

        // TTL: current slot + 900 (15 minutes)
        // Get current slot from Koios
        var tipResp = await fetch(koiosUrl() + '/tip');
        var tip = await tipResp.json();
        var ttl = parseInt(tip[0].abs_slot) + 900;

        var txBody = cborMap([
            [cborUint(0), inputsCbor],
            [cborUint(1), cborArray(outputs)],
            [cborUint(2), cborUint(estimatedFee)],
            [cborUint(3), cborUint(BigInt(ttl))],
        ]);

        // Unsigned transaction: [body, witness_set{}, true, null]
        var unsignedTx = cborArray([txBody, cborMap([]), new Uint8Array([0xf5]), new Uint8Array([0xf6])]);
        var txHex = bytesToHex(unsignedTx);

        statusEl.textContent = 'Confirm in wallet...';
        var witnessHex = await api.signTx(txHex, true);

        // Merge witness into tx
        var signedTx = cborArray([txBody, hexToBytes(witnessHex), new Uint8Array([0xf5]), new Uint8Array([0xf6])]);
        var signedTxHex = bytesToHex(signedTx);

        statusEl.textContent = 'Submitting...';
        var txHash = await api.submitTx(signedTxHex);

        statusEl.innerHTML = 'Sent! tx: <code style="font-size: 0.7rem;">' + txHash.slice(0, 16) + '...</code> — click Refresh after ~20s';
        btn.disabled = false;
    } catch (e) {
        btn.disabled = false;
        if (e.code === 2 || (e.info && e.info.includes('User'))) {
            statusEl.textContent = 'Transaction cancelled by user.';
        } else {
            statusEl.textContent = 'Error: ' + (e.message || e.info || e);
        }
    }
}

// Convert bech32 address to raw hex (for CBOR encoding)
function bech32ToHex(addr) {
    // bech32 decode — reuse the bech32 lib or inline a minimal decoder
    // The simplest approach: use the Koios address_info endpoint which returns hex
    // But for synchronous use, inline bech32 decode is better.
    // This is a minimal bech32 decoder:
    var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    var sep = addr.lastIndexOf('1');
    var data = [];
    for (var i = sep + 1; i < addr.length; i++) {
        var v = CHARSET.indexOf(addr.charAt(i));
        if (v === -1) throw new Error('Invalid bech32 character');
        data.push(v);
    }
    // Remove checksum (last 6 values)
    data = data.slice(0, -6);
    // Convert 5-bit groups to 8-bit bytes
    var acc = 0, bits = 0, result = [];
    for (var j = 0; j < data.length; j++) {
        acc = (acc << 5) | data[j];
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            result.push((acc >> bits) & 0xff);
        }
    }
    return result.map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join('');
}
```

### 4. Koios URL helper

Add a helper that reads the network dropdown (reused by both balance check and topup):

```javascript
function koiosUrl() {
    var network = document.getElementById('network').value;
    if (network === 'mainnet') return 'https://api.koios.rest/api/v1';
    if (network === 'preview') return 'https://preview.koios.rest/api/v1';
    return 'https://preprod.koios.rest/api/v1';
}
```

### Key points

- Copy CBOR helpers from `signup-engine.js` — they're self-contained, no imports
- The topup tx is trivial compared to the subscription tx: no scripts, no datums, no minting
- CIP-30 `signTx(hex, true)` with partial=true, then `submitTx` — wallet handles signing
- Koios for slot tip (TTL) and balance checks — free, no API key
- The inline bech32 decoder is ~15 lines — avoids importing any library
