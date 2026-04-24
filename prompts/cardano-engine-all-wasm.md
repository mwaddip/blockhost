# Cardano Engine: Ship all WASM dependencies

The build script only copies `cardano_multiplatform_lib_bg.wasm` but the bundles reference three WASM files at runtime:

1. `cardano_multiplatform_lib_bg.wasm` — from `@anastasia-labs/cardano-multiplatform-lib-nodejs`
2. `uplc_tx_bg.wasm` — from `@lucid-evolution/uplc/dist/node/`
3. `cardano_message_signing_bg.wasm` — from `@emurgo/cardano-message-signing-nodejs`

In `packaging/build.sh`, replace the single WASM copy with a loop that finds and copies all three. They all need to land in `/usr/share/blockhost/` alongside the JS bundles:

```bash
# Copy all WASM runtime dependencies
echo ""
echo "Copying WASM dependencies..."
WASM_FILES=(
    "node_modules/@anastasia-labs/cardano-multiplatform-lib-nodejs/cardano_multiplatform_lib_bg.wasm"
    "node_modules/@lucid-evolution/uplc/dist/node/uplc_tx_bg.wasm"
    "node_modules/@emurgo/cardano-message-signing-nodejs/cardano_message_signing_bg.wasm"
)
for wasm in "${WASM_FILES[@]}"; do
    SRC="$PROJECT_DIR/$wasm"
    if [ -f "$SRC" ]; then
        cp "$SRC" "$PKG_DIR/usr/share/blockhost/"
        echo "  Copied: $(basename "$SRC") ($(du -h "$SRC" | cut -f1))"
    else
        echo "  WARNING: Not found: $SRC"
    fi
done
```

Also update `node_modules/@lucid-evolution/core-utils/` path — it may have its own nested copy of the CML WASM under `node_modules/@lucid-evolution/core-utils/node_modules/@anastasia-labs/`. Check which path the bundle actually resolves to.
