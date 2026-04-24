# Cardano Engine: Stop bundling — ship source + node_modules

esbuild can't handle the Lucid dependency tree — multiple WASM blobs loaded at runtime via `readFileSync`, ESM/CJS conflicts, 10MB bundles with triplicated libsodium. Every fix reveals another WASM file.

Replace the entire esbuild approach: ship TypeScript source + production node_modules in the .deb, run with `tsx` (already a devDependency). This is how the engine runs in dev mode today.

## Build script changes

Replace all esbuild invocations in `packaging/build.sh` with:

```bash
# ============================================
# Install production dependencies
# ============================================
echo ""
echo "Installing production dependencies..."
MODULES_DIR="$PKG_DIR/usr/share/blockhost/node_modules"
cp "$PROJECT_DIR/package.json" "$PKG_DIR/usr/share/blockhost/"
cp "$PROJECT_DIR/package-lock.json" "$PKG_DIR/usr/share/blockhost/" 2>/dev/null || true

# Install production deps + tsx (needed as runtime)
(cd "$PKG_DIR/usr/share/blockhost" && npm install --production --ignore-scripts --no-optional --silent)
# tsx is a devDependency but needed at runtime for .ts execution
(cd "$PKG_DIR/usr/share/blockhost" && npm install tsx --no-save --silent)

echo "  node_modules: $(du -sh "$MODULES_DIR" | cut -f1)"

# ============================================
# Copy TypeScript source
# ============================================
echo ""
echo "Copying TypeScript source..."
cp -r "$PROJECT_DIR/src" "$PKG_DIR/usr/share/blockhost/src"
cp "$PROJECT_DIR/tsconfig.json" "$PKG_DIR/usr/share/blockhost/"

# Scripts (keygen, mint_nft, etc.)
mkdir -p "$PKG_DIR/usr/share/blockhost/scripts"
cp "$PROJECT_DIR/scripts/keygen.ts" "$PKG_DIR/usr/share/blockhost/scripts/"
cp "$PROJECT_DIR/scripts/mint_nft.ts" "$PKG_DIR/usr/share/blockhost/scripts/"
```

## Wrapper scripts

Update all `/usr/bin/` wrappers to use `tsx` instead of `node`:

```bash
# bw wrapper
cat > "$PKG_DIR/usr/bin/bw" << 'EOF'
#!/bin/sh
exec /usr/share/blockhost/node_modules/.bin/tsx /usr/share/blockhost/src/bw/index.ts "$@"
EOF

# ab wrapper
cat > "$PKG_DIR/usr/bin/ab" << 'EOF'
#!/bin/sh
exec /usr/share/blockhost/node_modules/.bin/tsx /usr/share/blockhost/src/ab/index.ts "$@"
EOF

# is wrapper
cat > "$PKG_DIR/usr/bin/is" << 'EOF'
#!/bin/sh
exec /usr/share/blockhost/node_modules/.bin/tsx /usr/share/blockhost/src/is/index.ts "$@"
EOF

# bhcrypt wrapper
cat > "$PKG_DIR/usr/bin/bhcrypt" << 'EOF'
#!/bin/sh
exec /usr/share/blockhost/node_modules/.bin/tsx /usr/share/blockhost/src/bhcrypt.ts "$@"
EOF

# mint_nft wrapper
cat > "$PKG_DIR/usr/bin/blockhost-mint-nft" << 'EOF'
#!/bin/sh
exec /usr/share/blockhost/node_modules/.bin/tsx /usr/share/blockhost/scripts/mint_nft.ts "$@"
EOF
```

## Monitor systemd unit

Update `examples/blockhost-monitor.service` ExecStart:

```
ExecStart=/usr/share/blockhost/node_modules/.bin/tsx /usr/share/blockhost/src/monitor/index.ts
```

## tsconfig.json

The current config uses `moduleResolution: "bundler"` which is esbuild-specific. Change to `"nodenext"` so tsx can resolve modules correctly:

```json
"moduleResolution": "nodenext",
"module": "nodenext",
```

Also remove `"verbatimModuleSyntax": true` — it conflicts with `nodenext` module resolution for some import patterns.

## What to remove

- All esbuild invocations from `packaging/build.sh`
- The WASM copy section
- `esbuild` from devDependencies (if listed)
- Move `tsx` from devDependencies to dependencies (it's now a runtime requirement)

## What stays the same

- `signup-engine.js` and `signup-template.html` — these are browser JS, not Node.js, keep as-is
- `deploy-contracts` and `generate-signup-page` — these are Python/bash scripts, unaffected
- Engine wizard plugin (Python) — unaffected
- Engine manifest, plutus.json, systemd unit, root-agent actions — all copied the same way
