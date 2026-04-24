# Cardano Engine: Consolidated Fixes

Issues found during ISO build and wizard testing.

## 1. Wallet template: public_secret default value

In `blockhost/engine_cardano/templates/engine_cardano/wallet.html`, the public secret input has no default:

```html
value="{{ public_secret }}"
```

Should be:

```html
value="{{ public_secret | default('blockhost-access') }}"
```

The variable isn't passed in the template context — the Jinja2 `default()` filter is how the other engines handle this.

## 2. Accent color too dark for dark theme

`engine.json` has `"accent_color": "#0033AD"` — Cardano's brand navy. This is invisible on the dark wizard background (`#0f172a`). It's used for the logo text, buttons, input borders, links.

EVM uses `#627EEA`, OPNet uses `#F97900` — both readable on dark. Change to a lighter Cardano blue:

```json
"accent_color": "#2E6AE6"
```

Or `#3B82F6` if you want more pop. Still recognizably Cardano, but actually visible.

## 3. Blockfrost Project ID: auto-prepend network prefix

The blockchain wizard page asks the user to enter a Blockfrost project ID with a network prefix (`preprodXXX...`), but the network is already selected in the dropdown above. The user shouldn't have to type the prefix manually.

Either:
- Accept just the 32 alphanumeric chars and prepend the selected network automatically
- Or pre-fill the prefix from the network dropdown and let the user paste the 32-char part

## 4. `packaging/build.sh` executable bit

The file still needs `git update-index --chmod=+x packaging/build.sh` — the previous push fixed the CJS/keygen issue but the file permissions in git weren't updated. `build-packages.sh` calls `./packaging/build.sh` which fails without the executable bit.

## 5. Ship WASM blobs alongside bundled JS

esbuild bundles the JS but can't inline WASM files. At runtime, `@anastasia-labs/cardano-multiplatform-lib-nodejs` (pulled in by Lucid/MeshJS) tries to `readFileSync` the file `cardano_multiplatform_lib_bg.wasm` from the same directory — but it's not in the .deb.

The WASM file lives at:
```
node_modules/@anastasia-labs/cardano-multiplatform-lib-nodejs/cardano_multiplatform_lib_bg.wasm
```

The build script needs to copy it next to each bundle that depends on it. Every bundle that imports Lucid will trigger this at runtime. The affected bundles are: `bhcrypt.js`, `bw.js`, `ab.js`, `is.js`, `keygen.js`, `mint_nft.js`, `monitor.js`.

Since they all install to `/usr/share/blockhost/`, a single copy should suffice:

```bash
# After all esbuild bundling, copy the WASM blob
WASM_SRC="$PROJECT_DIR/node_modules/@anastasia-labs/cardano-multiplatform-lib-nodejs/cardano_multiplatform_lib_bg.wasm"
if [ -f "$WASM_SRC" ]; then
    cp "$WASM_SRC" "$PKG_DIR/usr/share/blockhost/"
    echo "  Copied: cardano_multiplatform_lib_bg.wasm ($(du -h "$WASM_SRC" | cut -f1))"
fi
```

Verify at runtime that Node.js resolves the WASM relative to the JS bundle (it should, since they're in the same directory). If not, you may need to also check whether `@meshsdk/core` has a similar WASM dependency — `pubKeyAddress` and `serializeAddressObj` in `src/cardano/wallet.ts` come from MeshJS.
