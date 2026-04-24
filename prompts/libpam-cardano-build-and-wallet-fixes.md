# libpam-web3-cardano: Build fixes and wallet detection

Two issues found during testing.

## 1. esbuild can't resolve `@noble/curves/ed25519`

The `@noble/curves` package uses `.js` suffixed subpath exports (`./ed25519.js`, not `./ed25519`). esbuild doesn't resolve the bare import `@noble/curves/ed25519` to the `.js` export.

### Fix in `packaging/build-deb.sh`

Add an alias to the esbuild call:

```bash
npx esbuild auth-svc-src/index.ts \
    --bundle --platform=node --target=node22 --minify \
    --alias:@noble/curves/ed25519=@noble/curves/ed25519.js \
    --outfile=auth-svc.js
```

### Add package.json with dependencies

The plugin directory needs a `package.json` so `npm install` can fetch `@noble/curves`:

```json
{
  "name": "libpam-web3-cardano-auth-svc",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "@noble/curves": "^1.8.0",
    "@noble/hashes": "^1.7.0"
  }
}
```

The build script should run `npm install` before the esbuild step:

```bash
# Before esbuild:
(cd "$PROJECT_DIR" && npm install --silent)
```

## 2. Wallet detection race condition — use setTimeout

The previous retry-loop fix doesn't survive esbuild minification reliably. The simplest fix that works in all cases:

In `signing-page/engine.js`, replace:

```javascript
detectWallets();
```

With:

```javascript
setTimeout(detectWallets, 500);
```

500ms is enough for any CIP-30 extension to inject `window.cardano`. No retry loop, no conditional, no minification issues. One function call.
