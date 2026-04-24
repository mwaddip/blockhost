# libpam-web3-cardano: Replace crypto.subtle with @noble/ed25519

The auth-svc uses `crypto.subtle` for Ed25519 COSE_Sign1 verification. Node.js 22's `crypto.subtle` doesn't support Ed25519 (or requires experimental flags). The error:

```
COSE verification error: crypto.subtle must be defined, consider polyfill
```

No `.sig` file gets written — the signature is rejected before reaching the file write step. SSH auth hangs waiting for a file that never appears.

## Fix

In `auth-svc-src/crypto.ts` (or wherever COSE_Sign1 verification happens), replace `crypto.subtle.verify` with `ed25519.verify` from `@noble/curves`:

```typescript
import { ed25519 } from '@noble/curves/ed25519';

// Replace:
//   const valid = await crypto.subtle.verify('Ed25519', key, signature, message);
// With:
const valid = ed25519.verify(signature, message, publicKey);
```

`ed25519.verify` is synchronous, takes raw byte arrays (Uint8Array), and works in any Node.js version without flags.

## Dependencies

`@noble/curves` should already be in the plugin's dependencies (or add it — it's the same package the engine uses). Check `package.json` and add if missing:

```json
"@noble/curves": "^1.8.0"
```

## Also check

The COSE_Sign1 decoding extracts the public key from the COSE_Key structure and the signature + payload from the COSE_Sign1 envelope. Make sure those raw bytes are passed correctly to `ed25519.verify(signature, message, publicKey)` — the parameter order is different from `crypto.subtle.verify`.

The auth-svc bundles with esbuild — `@noble/curves` bundles cleanly with no WASM or ESM issues.
