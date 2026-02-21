# blockhost-engine (EVM) — bhcrypt + Runner Integration

> Paste this into the blockhost-engine Claude session.

---

## Pre-flight

1. Read and internalize `CLAUDE.md` and `facts/SPECIAL.md`.
2. Read `facts/ENGINE_INTERFACE.md` — especially §1 (bhcrypt contract) and §11 (Subscription Pipeline / Runner).
3. This is a multi-part change: nft_tool → bhcrypt rename (Python), runner integration, Node 22 target.

## Part A — bhcrypt (Python rename + stdout standardization)

### What

Rename `scripts/nft_tool.py` to `scripts/bhcrypt.py`. Standardize stdout to match the bhcrypt contract in ENGINE_INTERFACE.md §1.

### Rename: `scripts/nft_tool.py` → `scripts/bhcrypt.py`

Use `git mv scripts/nft_tool.py scripts/bhcrypt.py`.

### Update: `scripts/bhcrypt.py`

The file needs these changes to match the bhcrypt contract:

1. **Program name:** Change `prog="nft_tool"` to `prog="bhcrypt"`, update description to `"Crypto CLI for Blockhost engine"`.

2. **`generate-keypair` stdout — remove labels:**
   - Current: `print(f"Private key (hex): {priv_hex}")`
   - Required: `sys.stdout.write(priv_hex)` (no label, no newline)
   - For `--show-pubkey`: write newline then pubkey hex, no label: `sys.stdout.write(f"\n{pub_hex}")`

3. **`derive-pubkey` stdout — remove label:**
   - Current: `print(f"Public key (hex): {pub_hex}")`
   - Required: `sys.stdout.write(pub_hex)` (no label, no newline)

4. **`encrypt-symmetric` stdout — remove label:**
   - Current: `print(f"Ciphertext (hex): 0x{output.hex()}")`
   - Required: `sys.stdout.write(f"0x{output.hex()}")` (no label, no newline)

5. **`decrypt` — remove `--scheme` arg:**
   - Delete the `--scheme` argument from the argparse definition
   - Delete the `if args.scheme:` error check at the top of `cmd_decrypt`
   - The bhcrypt contract has no `--scheme` flag

6. **`decrypt` stdout — already correct** (`sys.stdout.write` with no prefix). But remove the `"Decrypted: "` prefix that the handler was stripping — verify it's not there (it isn't in the current code, the handler strips it defensively).

7. **`decrypt-symmetric` stdout — already correct** (`sys.stdout.write` with no prefix).

8. **`key-to-address` — keep as-is.** This subcommand isn't in the bhcrypt contract but it's EVM-specific and useful. Keep it.

9. **Remove deprecated subcommands:** Delete `wallet-encryption-key` parser and `cmd_not_implemented`.

10. **Error messages:** Update any remaining references to `nft_tool` in error messages to `bhcrypt`.

### CLAUDE.md — update nft_tool references

Update the CLAUDE.md in blockhost-engine:
- S.P.E.C.I.A.L. profile table: `scripts/nft_tool.py` → `scripts/bhcrypt.py`
- Architecture section: rename nft_tool references to bhcrypt
- "What does NOT go through the root agent" section: `nft_tool` → `bhcrypt`
- Any other references throughout the file

## Part B — Runner Integration

### What

Add `blockhost-runner` as a dependency. Import `createPipeline` from it. Wire it into the monitor and handlers.

### Add dependency

In `package.json`, add:
```json
"blockhost-runner": "file:../blockhost-runner"
```

Also update engines:
```json
"engines": {
  "node": ">=22"
}
```

### Update: `src/monitor/index.ts`

The monitor needs to:

1. **On startup:**
   - Import `createPipeline` from `blockhost-runner`
   - Import `ethers` (already imported) for `totalSupply` query
   - Load NFT contract address from `web3-defaults.yaml` (same as reconciler does)
   - Create the pipeline with a config object:
     ```typescript
     const pipeline = createPipeline({
       stateFile: '/var/lib/blockhost/pipeline.json',
       commands: {
         bhcrypt: 'bhcrypt',
         create: getCommand('create'),
         mint: 'blockhost-mint-nft',
         updateGecos: getCommand('update-gecos'),
       },
       serverKeyPath: '/etc/blockhost/server.key',
       timeouts: {
         crypto: 10_000,
         vmCreate: 600_000,
         mint: 120_000,     // EVM: ~2min (block time ~12s)
         db: 10_000,
       },
       retry: { baseMs: 5_000, maxRetries: 3 },
       workingDir: '/var/lib/blockhost',
     });
     ```
   - Initialize token counter: query `totalSupply()` on the NFT contract, call `pipeline.setNextTokenId(Number(supply))`
   - If pipeline has an active entry (crash recovery): call `await pipeline.resumeOrDrain()`

2. **In the polling loop (after processing block events):**
   - Call `await pipeline.resumeOrDrain()` (drains queue if items were enqueued during event processing)
   - Guard background tasks:
     ```typescript
     if (!pipeline.isPipelineBusy()) {
       await runReconciliation(provider);
       await runFundCycle(provider);
       await runGasCheck(provider);
     }
     ```
   - **Critical:** All three background tasks must be `await`ed, not `.catch()` fire-and-forget. The current code uses `.catch()` — change this.

3. **`handleSubscriptionCreated` dispatch:**
   - The handler signature changes — it now needs the pipeline instance. Either:
     - Pass pipeline as a parameter, or
     - Store pipeline in a module-level variable that handlers import
   - The handler calls `pipeline.enqueue({ subscriptionId, vmName, ownerWallet, expiryDays, userEncrypted })`
   - That's it. The runner handles everything else.

4. **Remove `shouldRunReconciliation()` / `shouldRunFundCycle()` / `shouldRunGasCheck()` gating from the polling loop.** These timer checks stay, but they must be inside the `!pipeline.isPipelineBusy()` guard to prevent running during pipeline execution.

### Update: `src/handlers/index.ts`

The handler file becomes thin. The `handleSubscriptionCreated` function:
1. Extracts event fields (subscriptionId, subscriber, expiresAt, userEncrypted)
2. Formats VM name
3. Calculates expiry days
4. Calls `pipeline.enqueue(event)`

**Remove from handlers — all now handled by the runner via subprocess calls:**
- `decryptUserSignature()` function
- `encryptConnectionDetails()` function
- `markNftMinted()` function
- `parseVmSummary()` function and `VmCreateSummary` interface
- `runCommand()` function (for create/mint — keep if used by other handlers)
- `getPublicSecret()` function
- The inline VM create + mint + encrypt logic in `handleSubscriptionCreated`
- The `execFileSync` import (if no longer used)

**Keep in handlers:**
- `handleSubscriptionExtended` — stays as-is (simple DB update + provisioner call)
- `handleSubscriptionCancelled` — stays as-is (provisioner destroy call)
- `handlePlanCreated` / `handlePlanUpdated` — stays as-is (just logging)
- `formatVmName()` — still used by all handlers
- `calculateExpiryDays()` — still used
- `destroyVm()` — still used by cancellation handler
- `runCommand()` — still used by extend/cancel handlers

### Update: `src/reconcile/index.ts`

Two changes:

1. **Replace `isProvisioningInProgress()` (which uses `pgrep`) with `pipeline.isPipelineBusy()`.**
   The pipeline instance needs to be accessible — either passed as a parameter or imported from a shared module. Remove the `pgrep`-based function entirely.

2. **Add drift correction:** After querying `totalSupply()` from the NFT contract (already done on line ~268), compare with `pipeline.getNextTokenId()`. If chain has more tokens, call `pipeline.setNextTokenId(onChainCount)`.

## Part C — bhcrypt in build script

### Update: `packaging/build.sh`

1. **Rename nft_tool installation:**
   - Change: `cp "$PROJECT_DIR/scripts/nft_tool.py" "$PKG_DIR/usr/bin/nft_tool"`
   - To: `cp "$PROJECT_DIR/scripts/bhcrypt.py" "$PKG_DIR/usr/bin/bhcrypt"`

2. **Update DEBIAN/control:**
   - Change `Provides: nft-tool` → `Provides: bhcrypt`
   - Remove `Conflicts: libpam-web3-tools` (the conflicting package no longer exists)
   - Change `nodejs (>= 18)` → `nodejs (>= 22)` in Depends

3. **Update esbuild targets:** Change ALL `--target=node18` to `--target=node22` (monitor, bw, ab, is bundles).

4. **Update package contents echo section:** Change `/usr/bin/nft_tool` → `/usr/bin/bhcrypt` and update the description.

5. **Update comment:** Change "nft_tool (Python crypto CLI, replaces deprecated pam_web3_tool Rust binary)" to "bhcrypt (Python crypto CLI)"

## Part D — Remaining nft_tool references

Search the entire codebase for `nft_tool` and `nft-tool` references. Update them all to `bhcrypt`. Places to check:

- `src/handlers/index.ts` — `execFileSync("nft_tool", ...)` calls (these should be GONE after Part B, but verify)
- `CLAUDE.md` — profile table and descriptions
- `README.md` — if it mentions nft_tool
- `engine.json` — shouldn't have references but check
- `INSTALL.md` — if it mentions nft_tool
- Error messages in any file

## Summary of file changes

| Action | File |
|--------|------|
| Rename | `scripts/nft_tool.py` → `scripts/bhcrypt.py` |
| Modify | `scripts/bhcrypt.py` (stdout standardization, remove labels) |
| Modify | `src/monitor/index.ts` (runner integration) |
| Modify | `src/handlers/index.ts` (thin dispatch to pipeline) |
| Modify | `src/reconcile/index.ts` (isPipelineBusy, drift correction) |
| Modify | `packaging/build.sh` (bhcrypt, node22 target) |
| Modify | `package.json` (add blockhost-runner dep, node >=22) |
| Modify | `CLAUDE.md` (nft_tool → bhcrypt references) |

## Verification

After implementation:
1. `python3 scripts/bhcrypt.py generate-keypair --show-pubkey` — prints two lines of raw hex, no labels
2. `python3 scripts/bhcrypt.py encrypt-symmetric --signature aabbccdd --plaintext hello` — prints `0x` + hex, no labels
3. `npm run compile` — Solidity compiles (unchanged)
4. Verify no references to `nft_tool` or `nft-tool` remain in source (except git history)
5. `./packaging/build.sh` — full package builds without errors (if deps available)

## What NOT to do

- Do NOT convert bhcrypt from Python to TypeScript — it stays Python for the EVM engine
- Do NOT change the crypto implementation (keccak256 key derivation, ECIES, AES-256-GCM) — only change stdout format
- Do NOT change `handleSubscriptionExtended` or `handleSubscriptionCancelled` — they stay inline
- Do NOT keep nft_tool as a backwards-compatibility shim — it's gone, bhcrypt replaces it entirely
- Do NOT add blockhost-runner as a bundled dependency in the .deb — esbuild bundles it into monitor.js
