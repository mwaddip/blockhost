# blockhost-engine-opnet — bhcrypt + Runner Integration

> Paste this into the blockhost-engine-opnet Claude session.

---

## Pre-flight

1. Read and internalize `CLAUDE.md` and `facts/SPECIAL.md`.
2. Read `facts/ENGINE_INTERFACE.md` — especially §1 (bhcrypt contract) and §11 (Subscription Pipeline / Runner).
3. This is a multi-part change: new bhcrypt CLI, runner integration, nft_tool removal, Node 18 polyfill removal, Node 22 target.

## Part A — bhcrypt CLI

### What

Replace `src/nft-tool.ts` with `src/bhcrypt/index.ts`. Same crypto operations from `src/crypto.ts`, new CLI interface matching the `bhcrypt` contract in ENGINE_INTERFACE.md §1.

### Create: `src/bhcrypt/index.ts`

A CLI entry point with subcommands. Uses functions from `src/crypto.ts` (eciesDecrypt, symmetricEncrypt, symmetricDecrypt) plus keypair generation from `@noble/curves/secp256k1`.

**Subcommands — all output is raw values, no labels, no decoration. Errors go to stderr.**

| Subcommand | Args | stdout | exit |
|------------|------|--------|------|
| `decrypt` | `--private-key-file <path> --ciphertext <hex>` | raw plaintext (UTF-8, no newline) | 0/1 |
| `encrypt-symmetric` | `--signature <hex> --plaintext <text>` | `0x` + hex (no label, no newline) | 0/1 |
| `decrypt-symmetric` | `--signature <hex> --ciphertext <hex>` | raw plaintext (UTF-8, no newline) | 0/1 |
| `generate-keypair` | `[--show-pubkey]` | line 1: private key hex. line 2 (if --show-pubkey): public key hex. No labels. | 0/1 |
| `derive-pubkey` | `--private-key <hex>` | public key hex (no label) | 0/1 |

**stdout format is critical.** The runner parses stdout directly. Any labels, prefixes, or decoration will break the pipeline.

Implementation notes:
- `decrypt`: Read private key from file (hex), parse ciphertext from hex, call `eciesDecrypt()`. Write plaintext to stdout via `process.stdout.write()` (NOT console.log, which adds a newline).
- `encrypt-symmetric`: Call `symmetricEncrypt(signatureBytes, plaintext)`. Prefix with `0x`, write hex to stdout.
- `decrypt-symmetric`: Strip `0x` prefix from ciphertext if present, call `symmetricDecrypt(signatureBytes, ciphertextBuffer)`. Write plaintext to stdout.
- `generate-keypair`: Generate random 32 bytes, derive public key via `secp256k1.getPublicKey()`. Write private key hex to stdout. If `--show-pubkey`, write newline then public key hex.
- `derive-pubkey`: Parse private key from hex, derive public key, write hex to stdout.

**Error handling:** Catch all errors, write to stderr, exit 1. Never write error messages to stdout.

**Arg parsing:** Simple manual parsing (process.argv). No arg-parsing libraries. The CLI is machine-to-machine, not user-facing.

### Remove: `src/nft-tool.ts`

Delete this file entirely. Its functionality is superseded by `src/bhcrypt/index.ts`.

### Update: `src/ab/index.ts`

The `ab new` command currently calls `nft_tool generate-keypair`. Update it to call `bhcrypt generate-keypair --show-pubkey` instead. Same stdout parsing — line 1 is private key hex, line 2 is public key hex.

### Update: any other references to `nft_tool`

Search the entire codebase for `nft_tool` and `nft-tool` references. Update them all to `bhcrypt`.

## Part B — Runner Integration

### What

Add `blockhost-runner` as a dependency. Import `createPipeline` from it. Wire it into the monitor and handlers.

### Add dependency

In `package.json`, add:
```json
"blockhost-runner": "file:../blockhost-runner"
```

(Local file reference for development. The build script will resolve this — esbuild bundles it into the monitor.js.)

### Update: `src/monitor/index.ts`

The monitor needs to:

1. **On startup:**
   - Import `createPipeline` from `blockhost-runner`
   - Create the pipeline with a config object:
     ```typescript
     const pipeline = createPipeline({
       stateFile: '/var/lib/blockhost/pipeline.json',
       commands: {
         bhcrypt: 'bhcrypt',
         create: getCommand('create'),     // from provisioner manifest
         mint: 'blockhost-mint-nft',
         updateGecos: getCommand('update-gecos'),
       },
       serverKeyPath: '/etc/blockhost/server.key',
       timeouts: {
         crypto: 10_000,
         vmCreate: 600_000,
         mint: 900_000,    // OPNet: 15min (block time ~10min)
         db: 10_000,
       },
       retry: { baseMs: 5_000, maxRetries: 3 },
       workingDir: '/var/lib/blockhost',
     });
     ```
   - Initialize token counter: if `pipeline.getNextTokenId() === -1`, query `totalSupply()` on the NFT contract and call `pipeline.setNextTokenId(supply)`.
   - If pipeline has an active entry (crash recovery): call `pipeline.resumeOrDrain()`.

2. **In the polling loop (after processing block events):**
   - Call `pipeline.resumeOrDrain()` (drains queue if items were enqueued during event processing).
   - Guard background tasks:
     ```typescript
     if (!pipeline.isPipelineBusy()) {
       await runReconciliation();   // NOT .catch() — await it
       await runFundCycle();        // NOT .catch() — await it
       await runGasCheck();         // NOT .catch() — await it
     }
     ```
   - All three background tasks must be `await`ed, not fire-and-forget.

3. **`handleSubscriptionCreated` dispatch:**
   - Format VM name: `blockhost-${String(subscriptionId).padStart(3, '0')}`
   - Calculate expiry days from `expiresAt`
   - Call `pipeline.enqueue({ subscriptionId, vmName, ownerWallet, expiryDays, userEncrypted })`
   - That's it. The runner handles everything else.

### Update: `src/handlers/index.ts`

The handler file becomes thin. The `handleSubscriptionCreated` function:
1. Extracts event fields (subscriptionId, subscriber, expiresAt, userEncrypted)
2. Formats VM name
3. Calculates expiry days
4. Calls `pipeline.enqueue(event)`

**Remove from handlers:** All the following logic is now in the runner (executed via subprocess calls):
- `decryptUserSignature()` — runner calls `bhcrypt decrypt`
- `encryptConnectionDetails()` — runner calls `bhcrypt encrypt-symmetric`
- `reserveNftTokenId()` — runner calls Python DB subprocess
- `markNftMinted()` / `markNftFailed()` — runner calls Python DB subprocess
- `parseVmSummary()` / `VmCreateSummary` type — runner parses VM create JSON output
- Any direct subprocess calls to provisioner create, mint, etc.

**Keep in handlers:** `handleSubscriptionExtended`, `handleSubscriptionCancelled` — these are simple inline operations (DB update + provisioner call), not pipelined.

### Update: `src/reconcile/index.ts`

Two changes:
1. Replace `isProvisioningInProgress()` (which uses `pgrep`) with `pipeline.isPipelineBusy()`.
2. Add drift correction: query `totalSupply()` from the NFT contract, compare with `pipeline.getNextTokenId()`. If chain has more tokens, call `pipeline.setNextTokenId(chainSupply)`.

The `pipeline` instance needs to be accessible — either passed as a parameter or stored in a shared module-level variable.

## Part C — Remove nft_tool from build

### Update: `packaging/build.sh`

1. **Remove** the nft_tool esbuild invocation and wrapper script creation.
2. **Add** bhcrypt esbuild invocation:
   ```bash
   echo "Bundling bhcrypt CLI with esbuild..."
   npx esbuild "$PROJECT_DIR/src/bhcrypt/index.ts" \
       --bundle \
       --platform=node \
       --target=node22 \
       --minify \
       --outfile="$PKG_DIR/usr/share/blockhost/bhcrypt.js"
   ```
3. **Add** bhcrypt wrapper script:
   ```bash
   cat > "$PKG_DIR/usr/bin/bhcrypt" << 'BHEOF'
   #!/bin/sh
   export NODE_OPTIONS="--dns-result-order=ipv4first${NODE_OPTIONS:+ $NODE_OPTIONS}"
   exec /usr/bin/node /usr/share/blockhost/bhcrypt.js "$@"
   BHEOF
   chmod 755 "$PKG_DIR/usr/bin/bhcrypt"
   ```
4. Update the "Package contents" echo section at the bottom: replace `nft_tool` references with `bhcrypt`.
5. Update the DEBIAN/control Description to list `bhcrypt` instead of `nft_tool`.

## Part D — Drop Node 18 polyfills

### Remove: `packaging/polyfill-node18.js`

Delete this file entirely.

### Update: `packaging/build.sh`

1. Remove the `NODE18_POLYFILL` variable declaration.
2. Remove ALL `--inject:"$NODE18_POLYFILL"` flags from esbuild invocations.
3. Change ALL `--target=node18` to `--target=node22` in esbuild invocations.
4. Update `DEBIAN/control`: change `nodejs (>= 18)` to `nodejs (>= 22)` in both the engine package and the auth-svc template package.

### What esbuild invocations need updating

Search the build script for `--target=node18` and `--inject:"$NODE18_POLYFILL"`. Every one of them needs updating:
- monitor.js bundle
- bw.js bundle
- ab.js bundle
- is.js bundle
- nft_tool.js → bhcrypt.js (already handled in Part C)
- auth-svc.js bundle
- mint_nft.js bundle

## Part E — Node version in package.json

Update `package.json`:
```json
"engines": {
  "node": ">=22"
}
```

## Summary of file changes

| Action | File |
|--------|------|
| Create | `src/bhcrypt/index.ts` |
| Delete | `src/nft-tool.ts` |
| Delete | `packaging/polyfill-node18.js` |
| Modify | `src/monitor/index.ts` (runner integration) |
| Modify | `src/handlers/index.ts` (thin dispatch to pipeline) |
| Modify | `src/reconcile/index.ts` (isPipelineBusy, drift correction) |
| Modify | `src/ab/index.ts` (nft_tool → bhcrypt reference) |
| Modify | `packaging/build.sh` (bhcrypt, drop polyfills, node22 target) |
| Modify | `package.json` (add blockhost-runner dep, node >=22) |

## Verification

After implementation:
1. `npm run typecheck` — types compile with no errors
2. `npx esbuild src/bhcrypt/index.ts --bundle --platform=node --target=node22 --outfile=/tmp/bhcrypt.js` — bhcrypt bundles
3. `node /tmp/bhcrypt.js generate-keypair --show-pubkey` — prints two lines of hex
4. `./packaging/build.sh` — full package builds without errors
5. Verify `packaging/polyfill-node18.js` is deleted
6. Verify no references to `nft_tool` or `nft-tool` remain (except in git history)

## What NOT to do

- Do NOT keep nft_tool as a backwards-compatibility shim — it's gone, bhcrypt replaces it entirely
- Do NOT add `blockhost-runner` as a bundled dependency in the .deb — esbuild bundles it into monitor.js
- Do NOT add any polyfills — Node 22 has everything we need
- Do NOT change the crypto implementation in `src/crypto.ts` — bhcrypt is a thin CLI wrapper around it
- Do NOT change `handleSubscriptionExtended` or `handleSubscriptionCancelled` — they stay inline
