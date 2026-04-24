# Cardano Engine: Replace libsodium with noble shim + return to esbuild

Instead of patching `@cardano-sdk/crypto` or shipping 200MB of node_modules, create a drop-in `libsodium-wrappers-sumo` shim that implements the 12 functions Lucid's dependency tree actually uses — backed by `@noble/curves` and `@noble/hashes` which are already in the dependency tree. Then switch back to esbuild bundling.

## The shim

Create `src/shims/libsodium-wrappers-sumo.ts`:

```typescript
/**
 * Drop-in shim for libsodium-wrappers-sumo using @noble/curves and @noble/hashes.
 * Implements only the 12 functions that @cardano-sdk/crypto actually calls.
 * Eliminates the 40MB WASM dependency.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { hmac } from '@noble/hashes/hmac';
import { blake2b } from '@noble/hashes/blake2b';

// Ed25519 curve order
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]!);  // little-endian
  }
  return result;
}

function bigIntToBytes(n: bigint, len: number): Uint8Array {
  const result = new Uint8Array(len);
  let val = n;
  for (let i = 0; i < len; i++) {
    result[i] = Number(val & 0xFFn);
    val >>= 8n;
  }
  return result;
}

const sodium = {
  ready: Promise.resolve(),

  // HMAC-SHA512
  crypto_auth_hmacsha512(message: Uint8Array, key: Uint8Array): Uint8Array {
    return hmac(sha512, key, message);
  },

  // SHA-512
  crypto_hash_sha512(message: Uint8Array): Uint8Array {
    return sha512(message);
  },

  // BLAKE2b (generichash)
  crypto_generichash(hashLength: number, message: Uint8Array, _key?: Uint8Array): Uint8Array {
    return blake2b(message, { dkLen: hashLength });
  },

  // Ed25519 base point multiplication (no clamping — caller handles it)
  crypto_scalarmult_ed25519_base_noclamp(scalar: Uint8Array): Uint8Array {
    const s = bytesToBigInt(scalar) % L;
    const point = ed25519.ExtendedPoint.BASE.multiply(s);
    return point.toRawBytes();
  },

  // Ed25519 point addition
  crypto_core_ed25519_add(p: Uint8Array, q: Uint8Array): Uint8Array {
    const P = ed25519.ExtendedPoint.fromHex(p);
    const Q = ed25519.ExtendedPoint.fromHex(q);
    return P.add(Q).toRawBytes();
  },

  // Scalar addition mod L
  crypto_core_ed25519_scalar_add(x: Uint8Array, y: Uint8Array): Uint8Array {
    const result = (bytesToBigInt(x) + bytesToBigInt(y)) % L;
    return bigIntToBytes(result, 32);
  },

  // Scalar multiplication mod L
  crypto_core_ed25519_scalar_mul(x: Uint8Array, y: Uint8Array): Uint8Array {
    const result = (bytesToBigInt(x) * bytesToBigInt(y)) % L;
    return bigIntToBytes(result, 32);
  },

  // Scalar reduction mod L (64-byte input → 32-byte output)
  crypto_core_ed25519_scalar_reduce(scalar: Uint8Array): Uint8Array {
    const result = bytesToBigInt(scalar) % L;
    return bigIntToBytes(result, 32);
  },

  // Ed25519 sign (normal key — 32-byte seed)
  crypto_sign_detached(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    // secretKey is 64 bytes: [seed(32) | pubkey(32)]
    const seed = secretKey.slice(0, 32);
    return ed25519.sign(message, seed);
  },

  // Derive keypair from 32-byte seed
  crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array } {
    const publicKey = ed25519.getPublicKey(seed);
    const privateKey = new Uint8Array(64);
    privateKey.set(seed);
    privateKey.set(publicKey, 32);
    return { publicKey, privateKey };
  },

  // Verify Ed25519 signature
  crypto_sign_verify_detached(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
    return ed25519.verify(signature, message, publicKey);
  },
};

export default sodium;
```

**Important**: The extended key signing in `Ed25519PrivateKey.signExtendedDetached` is a custom Ed25519 variant (not standard `crypto_sign_detached`). It manually constructs the signature from scalar operations. This shim handles it because those scalar operations (`scalar_reduce`, `scalar_mul`, `scalar_add`, `scalarmult_base_noclamp`) are shimmed individually — `@cardano-sdk/crypto` calls them directly, not through a high-level sign function.

## esbuild alias

In `packaging/build.sh`, add an alias flag to every esbuild invocation that redirects the libsodium import to the shim:

```bash
--alias:libsodium-wrappers-sumo=./src/shims/libsodium-wrappers-sumo.ts
```

esbuild resolves the alias at bundle time — `@cardano-sdk/crypto`'s `import sodium from 'libsodium-wrappers-sumo'` gets redirected to the shim. No patches, no runtime overhead.

## Build script changes

1. Revert from tsx/node_modules approach back to esbuild bundling (restore the esbuild invocations from before the unbundling — check git history)
2. Add `--alias:libsodium-wrappers-sumo=./src/shims/libsodium-wrappers-sumo.ts` to each esbuild call
3. Remove `--external:@stricahq/bip32ed25519` and `--external:libsodium-wrappers-sumo` (they no longer exist / are shimmed)
4. Keep `--conditions=require` if any other dependency has ESM/CJS issues
5. Remove the npm install / node_modules copy / tsx runtime sections
6. Remove the libsodium package.json patch section

## What this achieves

- Back to self-contained bundled JS files (no node_modules on disk)
- Monitor: ~600KB instead of ~11MB (no inlined libsodium)
- Zero WASM files
- .deb drops from 18MB to ~2-3MB
- Cold start is instant (no tsx compilation, no WASM loading)

## Wrapper scripts

Revert wrappers from tsx back to node:

```bash
#!/bin/sh
exec node /usr/share/blockhost/bw.js "$@"
```

## Systemd unit

Revert `ExecStart` from tsx back to node:

```
ExecStart=/usr/bin/node /usr/share/blockhost/monitor.js
```

## Verification

After building, test on the VM:
- `bhcrypt keygen` — derives a wallet (uses BIP32-Ed25519 from noble-bip32ed25519, now shimmed in @cardano-sdk/crypto too)
- `bw balance server` — queries chain (uses Lucid which uses @cardano-sdk/crypto)
- `blockhost-mint-nft --dry-run` — transaction building (exercises the full Lucid stack)

If any of these fail with a sodium-related error, the shim is missing a function — check which one and add it.
