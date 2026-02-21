# blockhost-runner — Implementation Prompt

> Paste this into the blockhost-runner Claude session.

---

## Pre-flight

1. Read and internalize `CLAUDE.md` and `facts/SPECIAL.md`.
2. Read `facts/ENGINE_INTERFACE.md` §11 (Subscription Pipeline) — that's the contract.

## CLAUDE.md Corrections

Before starting, fix two things in CLAUDE.md:

1. **Node version:** Change `Node >= 24.0.0` → `Node >= 22` (we're targeting Node 22 LTS via NodeSource).
2. **Strategy interface → subprocess config:** The CLAUDE.md mentions a "strategy interface" with callbacks. That design was superseded. The runner does NOT use a strategy/callback pattern. Instead, the engine provides a `PipelineConfig` with command strings and paths, and the runner executes everything via `child_process.execFile()` subprocesses. This is simpler and enforces the abstraction boundary: runner depends only on CLI contracts, not TypeScript types from engines. Update the "What This Module Is" and "What This Module Is NOT" sections accordingly.

## Architecture

The runner is a zero-dependency npm package (Node built-ins only). It's consumed via `import { createPipeline } from 'blockhost-runner'` by each engine and bundled into the engine's `.js` via esbuild.

**Core idea:** The runner is a state machine that executes pipeline stages by shelling out to CLIs. It persists state to `pipeline.json` via atomic temp+rename writes. If the process dies, the next startup resumes from the last completed stage.

**The runner has zero chain awareness.** It doesn't know about OPNet, Ethereum, UTXO, nonces, or providers. It knows about commands, timeouts, and exit codes.

## Files to Create

| File | Purpose |
|------|---------|
| `src/types.ts` | All TypeScript types |
| `src/state.ts` | Load/save pipeline.json, isPipelineBusy, get/setNextTokenId, invalidateCache |
| `src/executor.ts` | Stage execution via subprocess, retry loop, queue drain, crash recovery |
| `src/index.ts` | Public API: createPipeline factory, re-exports |
| `package.json` | ESM, Node >= 22, zero runtime deps |
| `tsconfig.json` | Strict, ESNext, NodeNext module resolution |

## Types (`src/types.ts`)

```typescript
/** Pipeline stage names — each represents a COMPLETED action */
export type PipelineStage =
  | 'received'
  | 'decrypted'
  | 'token_reserved'
  | 'vm_created'
  | 'encrypted'
  | 'nft_minted'
  | 'db_updated'
  | 'complete';

/** Ordered stage progression */
export const STAGE_ORDER: readonly PipelineStage[] = [
  'received',
  'decrypted',
  'token_reserved',
  'vm_created',
  'encrypted',
  'nft_minted',
  'db_updated',
  'complete',
] as const;

/** Event data from SubscriptionCreated — everything the pipeline needs */
export interface QueuedEvent {
  subscriptionId: number;
  vmName: string;               // "blockhost-001"
  ownerWallet: string;          // subscriber address
  expiryDays: number;           // calculated from expiresAt
  userEncrypted: string;        // hex — ECIES-encrypted user data
}

/** Active pipeline entry — persisted to pipeline.json */
export interface PipelineEntry {
  event: QueuedEvent;
  stage: PipelineStage;
  retryCount: number;
  startedAt: number;            // Unix ms
  /** Populated after 'decrypted' stage */
  userSignature?: string;
  /** Populated after 'token_reserved' stage */
  reservedTokenId?: number;
  /** Populated after 'vm_created' stage */
  vmSummary?: {
    ip: string;
    vmid?: string | number;
    username: string;
    [key: string]: unknown;     // provisioner may add more fields
  };
  /** Populated after 'encrypted' stage */
  encryptedConnectionDetails?: string;
  /** Populated after 'nft_minted' stage */
  actualMintedTokenId?: number;
}

/** Completed pipeline for history */
export interface CompletedPipeline {
  event: QueuedEvent;
  tokenId: number;
  completedAt: number;          // Unix ms
  stages: PipelineStage[];      // stages that were executed
}

/** The pipeline.json state file schema */
export interface PipelineState {
  next_token_id: number;        // -1 = needs initialization from chain
  active: PipelineEntry | null;
  queue: QueuedEvent[];
  pipeline_busy: boolean;
  history: CompletedPipeline[];  // last 50
}

/** Engine provides this when creating the pipeline */
export interface PipelineConfig {
  stateFile: string;
  commands: {
    bhcrypt: string;
    create: string;
    mint: string;
    updateGecos: string;
  };
  serverKeyPath: string;
  timeouts: {
    crypto: number;
    vmCreate: number;
    mint: number;
    db: number;
  };
  retry: {
    baseMs: number;
    maxRetries: number;
  };
  workingDir: string;
}

/** Public pipeline interface */
export interface Pipeline {
  enqueue(event: QueuedEvent): boolean;
  resumeOrDrain(): Promise<void>;
  isPipelineBusy(): boolean;
  getNextTokenId(): number;
  setNextTokenId(n: number): void;
  invalidateCache(): void;
}
```

## State Management (`src/state.ts`)

Atomic persistence via temp file + rename:

```
save: write to pipeline.json.tmp → fsync → rename to pipeline.json
load: read pipeline.json, JSON.parse, validate shape
```

Key behaviors:
- `isPipelineBusy()`: returns `state.pipeline_busy` (reads from memory cache, not disk)
- `getNextTokenId()`: returns `state.next_token_id`
- `setNextTokenId(n)`: only sets if `n > state.next_token_id` (upward drift correction only)
- `invalidateCache()`: forces next read to go to disk (for when external tools modify pipeline.json)
- State is loaded once into memory on `createPipeline()` and updated in-memory + persisted on every mutation
- If the state file doesn't exist, create it with defaults: `{ next_token_id: -1, active: null, queue: [], pipeline_busy: false, history: [] }`

**Important:** Every state mutation must be persisted BEFORE the next stage executes. The invariant is: if the process dies at any point, pipeline.json reflects the last successfully completed stage.

## Executor (`src/executor.ts`)

This is the core. It runs stages by shelling out to CLIs via `child_process.execFile()`.

### Stage Execution

Each stage has a function that:
1. Runs a subprocess
2. Parses stdout
3. Updates the pipeline entry with results
4. Advances the stage
5. Persists state

**Stage → CLI mapping:**

| Stage | Command | stdout parsing |
|-------|---------|---------------|
| `decrypted` | `bhcrypt decrypt --private-key-file <serverKeyPath> --ciphertext <event.userEncrypted>` | Full stdout = plaintext (user signature) |
| `token_reserved` | `python3 -c "import sys; sys.path.insert(0, '/opt/blockhost'); from blockhost.vm_db import get_database; db = get_database(); db.reserve_nft_token_id('<vmName>', <tokenId>)"` | None — success = exit 0 |
| `vm_created` | `<commands.create> <vmName> --owner-wallet <ownerWallet> --nft-token-id <tokenId> --expiry-days <expiryDays> --apply` | Find last line starting with `{` → JSON.parse → vmSummary |
| `encrypted` | `bhcrypt encrypt-symmetric --signature <userSignature> --plaintext <connDetailsJson>` | Full stdout = `0x`-prefixed hex ciphertext |
| `nft_minted` | `<commands.mint> --owner-wallet <ownerWallet> --user-encrypted <encryptedHex>` | stdout trimmed = integer token ID |
| `db_updated` | Python subprocess: `mark_nft_minted(tokenId, wallet)`. If `actualMintedTokenId !== reservedTokenId`: mark old as failed, re-reserve with actual, update GECOS. | None — success = exit 0 |

**Connection details JSON** (constructed for `encrypted` stage):
```json
{
  "hostname": "<vmSummary.ip>",
  "port": 22,
  "username": "<vmSummary.username>"
}
```

### Retry Logic

Exponential backoff: `baseMs * 2^retryCount`. Max retries per stage from config.

On failure:
- Increment `retryCount` on the active entry, persist
- Wait for backoff delay
- Retry same stage
- After exhausting retries: set `pipeline_busy = false`, leave `active` entry in place (manual intervention required). Do NOT clear the entry — it preserves state for debugging.
- Special case: if `vm_created` fails on final retry AND `token_reserved` was already completed, call `python3 -c "...mark_nft_failed(tokenId)"` to release the reservation.

### Queue Drain

After `complete` stage:
1. Move entry to `history` (keep last 50, drop oldest)
2. Set `active = null`
3. If `queue` is non-empty: shift first event, create new entry at `received` stage, start execution
4. If queue is empty: set `pipeline_busy = false`, persist

### `resumeOrDrain()`

Called on engine startup:
1. Load state
2. If `active !== null`: determine next stage (stage after `active.stage` in STAGE_ORDER), execute from there
3. If `active === null` and `queue.length > 0`: drain next event
4. If both null/empty: no-op

### `enqueue(event)`

1. Load current state
2. If `active === null`: create entry at `received`, set `pipeline_busy = true`, persist, start execution async. Return `true`.
3. If `active !== null`: push to `queue`, persist. Return `false`.

### Subprocess execution

Use `child_process.execFile` with:
- `timeout` from config (per-stage)
- `maxBuffer: 10 * 1024 * 1024` (10 MB — VM create can be verbose)
- `encoding: 'utf-8'`
- Capture `stdout` and `stderr`
- On non-zero exit: throw with stderr content
- On timeout: throw with timeout message

Wrap in a helper: `async function exec(cmd: string, args: string[], timeoutMs: number): Promise<string>`

### Token ID in `token_reserved` stage

The `token_reserved` stage does two things:
1. Read `next_token_id` from state, use it as the reserved token ID
2. Increment `next_token_id` and persist
3. Call `reserve_nft_token_id(vmName, tokenId)` via Python subprocess

The token ID increment and persist happen BEFORE the Python call, so even if the process dies after increment but before the Python call, the counter has advanced and won't reuse the ID.

## Public API (`src/index.ts`)

```typescript
export { createPipeline } from './executor.js';
export type { Pipeline, PipelineConfig, QueuedEvent, PipelineEntry, PipelineState, CompletedPipeline } from './types.js';
```

`createPipeline(config: PipelineConfig): Pipeline` — loads state (or creates default), returns the pipeline interface. Does NOT auto-resume — the engine must call `resumeOrDrain()` explicitly after initializing the token counter.

## package.json

```json
{
  "name": "blockhost-runner",
  "version": "0.1.0",
  "type": "module",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    }
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsc",
    "typecheck": "tsc --noEmit"
  },
  "engines": {
    "node": ">=22"
  },
  "devDependencies": {
    "typescript": "^5.7.0"
  }
}
```

Zero runtime dependencies. Only `typescript` as devDependency.

## tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ESNext",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "rootDir": "src",
    "declaration": true,
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noUncheckedIndexedAccess": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "exactOptionalPropertyTypes": false
  },
  "include": ["src"],
  "exclude": ["node_modules", "dist"]
}
```

## Critical Invariants

1. **State before action:** Every stage persists its RESULT to pipeline.json before the NEXT stage starts. If the process dies between persist and next stage, resume picks up cleanly.

2. **Token ID monotonicity:** `next_token_id` only ever increases. `setNextTokenId(n)` is a no-op if `n <= current`. This prevents double-minting.

3. **Single active:** Only one `active` entry at a time. Queue is FIFO. No parallel execution.

4. **Retry isolation:** Retry count resets to 0 when moving to a new stage. Only the current stage retries.

5. **Busy flag:** `pipeline_busy` is `true` from the moment an entry becomes active until the moment the queue is fully drained and no active entry remains.

## After Implementation

1. `npm run typecheck` — verify types compile
2. `npm run build` — verify output in `dist/`
3. Verify `dist/index.js` exports `createPipeline`
4. Verify `dist/index.d.ts` has all type exports
5. Push to GitHub so the engine can reference it as a dependency

## What NOT To Do

- Do NOT add any blockchain imports (ethers, opnet, web3)
- Do NOT add any provisioner-specific logic
- Do NOT add runtime dependencies (lodash, winston, etc.)
- Do NOT use `console.log` for logging — use `process.stderr.write` for debug output (the engine captures stdout from CLIs; runner should not pollute stdout)
- Do NOT use `JSON.stringify` without proper error handling on circular references
- Do NOT use `fs.writeFileSync` — always use the atomic temp+rename pattern
