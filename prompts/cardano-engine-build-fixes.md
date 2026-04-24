# Cardano Engine: Build Script Fixes

Three issues found during ISO build.

## 1. `packaging/build.sh` not executable

The file has 644 permissions — `build-packages.sh` calls it as `./packaging/build.sh` which fails with "Permission denied".

```bash
git update-index --chmod=+x packaging/build.sh
```

## 2. keygen.js ESM bundling fails with libsodium

The keygen helper bundles with `--format=esm` and `--external:libsodium-wrappers-sumo`, but the ESM entry point of libsodium-wrappers-sumo uses a relative import (`./libsodium-sumo.mjs`) that esbuild can't resolve against the external marker.

The `--external` flag works for CJS (matches the package name in `require()`) but not for ESM (which resolves to a relative `.mjs` file path).

Two options:

**Option A** — Bundle libsodium into keygen instead of externalizing it:
Remove `--external:libsodium-wrappers-sumo` from the keygen esbuild call. This increases bundle size but eliminates the resolution issue.

**Option B** — Switch keygen to CJS format with the createRequire banner (same approach as broker-client):
```bash
npx esbuild "$PROJECT_DIR/scripts/keygen.ts" \
    --bundle \
    --platform=node \
    --target=node22 \
    --format=cjs \
    --minify \
    --external:@stricahq/bip32ed25519 \
    --external:libsodium-wrappers-sumo \
    --outfile="$PKG_DIR/usr/share/blockhost/keygen.js"
```

The CJS format needs the root-agent wallet action to call it with `node` instead of `node --experimental-modules`, but since the wrapper uses `require()` via the createRequire banner pattern, CJS should work.

Either way, the current `|| true` workaround makes the failure silent — keygen.js won't be in the .deb and wallet generation via root agent will fail at runtime.

## 3. Missing `plutus.json`

The build script looks for `plutus.json` at the project root but it's been removed from the repo (per the git log: "remove build artifacts and lock files from repo"). The validators need to be compiled with Aiken first:

```bash
aiken build
```

This generates `plutus.json` which the build script copies to `/usr/share/blockhost/contracts/`. Without it, contract deployment (`blockhost-deploy-contracts`) will fail.

Either:
- Add `aiken build` to the build script (requires Aiken toolchain on the build host)
- Or commit `plutus.json` back as a checked-in artifact (it's the compiled output of deterministic Aiken compilation, safe to track)
