# libpam-web3 Ergo auth-svc: Schnorr verification always fails

## Observable problem

On a fully provisioned VM running Ergo auth, a successful Nautilus `sign_data` call produces a valid Schnorr signature — sigma-rust accepts it — but the auth-svc rejects it with:

```
[AUTH] Callback rejected for session <id>: Schnorr signature verification failed
```

PAM therefore never receives a valid `.sig` file and login is impossible. Every signing attempt by every Ergo wallet fails.

## Constraint (non-negotiable)

**No WASM.** No `ergo-lib-wasm-nodejs`, no `ergo-lib-wasm-browser`, no wrapping of sigma-rust via WebAssembly. The auth-svc must stay pure TypeScript, using `@noble/curves` + `@noble/hashes` only. This matches the established pattern (Cardano engine dependency liberation, `frots`, `cmttk`, `noble-bip32ed25519`). If a cryptographic primitive needs to be ported from sigma-rust, port the algorithm — do not link the WASM.

## Root cause

The custom Schnorr verification in `plugins/ergo/auth-svc-src/index.ts::verifySchnorrProof` is a hand-rolled reimplementation of Ergo's sigma-protocol ProveDlog verification, and it's wrong on two points.

### 1. Wrong sign convention

```ts
// current (wrong):
aPoint = G.multiply(z).add(P.multiply(e));   // a = z*G + e*P
```

Ergo uses `z = r + xe`, so verification is `g^z = a · h^e` → `a = g^z / h^e` → in additive EC: **`a = z*G − e*P`**. sigma-rust's implementation (`ergotree-interpreter/src/sigma_protocol/dlog_protocol.rs::compute_commitment`):

```rust
// g^z = a*h^e => a = g^z/h^e
let g_z = exponentiate_gen(second_message.z.as_scalar_ref());
let h_e = exponentiate(&h, &e);
g_z * &inverse(&h_e)
```

In noble terms:

```ts
const aPoint = G.multiply(z).add(P.multiply(e).negate());
```

### 2. Wrong Fiat-Shamir pre-image

```ts
// current (wrong):
const hashInput = new Uint8Array([...aCompressed, ...signedMsg]);
```

Ergo's Fiat-Shamir hash takes the **serialized sigma tree** (not just the commitment bytes) concatenated with the message. sigma-rust's `fiat_shamir_tree_to_bytes` (`ergotree-interpreter/src/sigma_protocol/fiat_shamir.rs::fiat_shamir_write_bytes`) for a single ProveDlog leaf produces:

```
LEAF_PREFIX                  (1 byte,  = 0x01)
prop_bytes_len               (2 bytes, big-endian i16)
prop_bytes                   (ErgoTree v0 with constants-segregated flag, encoding SigmaProp(ProveDlog(pk)))
commitment_bytes_len         (2 bytes, big-endian i16, always 0x0021 = 33)
commitment_bytes             (33-byte compressed EC point `a`)
```

Then the verifier computes `blake2b256(tree_bytes || message)[0..24]` and compares it against the challenge (first 24 bytes of the signature).

The EIP-44 message format the auth-svc uses (`[0x00, network, blake2b256(utf8_msg)]`, 34 bytes) is **correct** — keep that. Also keep trying mainnet first (`[0x00, 0x00]`) then testnet (`[0x00, 0x10]`); Fleet SDK's `ErgoMessage.fromData(data)` defaults to mainnet even for testnet addresses, so mainnet is what real Nautilus signatures use today.

## The P2PK ErgoTree template

For a P2PK address with compressed pubkey `pk` (33 bytes), `prop_bytes` is always **exactly 39 bytes**:

```
0x10                            ErgoTree header: v0 + constants-segregated flag
0x01                            numConstants (VLQ) = 1
0x08                            type tag: SigmaProp
0xcd                            ProveDlog opcode
<33 bytes of pubkey>            the compressed secp256k1 point
0x73                            opcode: ConstantPlaceholder
0x00                            placeholder index 0
```

Assembled: `10 01 08 cd <33 bytes pk> 73 00`. No VLQ edge cases, no variable lengths — it's a fixed 5-byte prefix + 33 bytes pk + 2-byte suffix.

Verified by extracting from sigma-rust directly against the test address `3Wy6H5zue2YARihJKk4ccYF239cDWZYSj43qfVmzearpoy1jTPa8` with pubkey `0347203530f6977e33b0465a0da69428f2497f90ce32434fc16fb17c93e3e8300e`:

```
prop_bytes = 100108cd0347203530f6977e33b0465a0da69428f2497f90ce32434fc16fb17c93e3e8300e7300
             ^^ ^^ ^^ ^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^ ^^
             10 01 08 cd <---------------- 33-byte pubkey ---------------------------> 73 00
```

## Assembled verification flow (pure TS, target behavior)

```ts
function verifySchnorrProof(proofHex: string, publicKeyHex: string, message: string): string | null {
  const sig = hexToBytes(proofHex);
  const pk  = hexToBytes(publicKeyHex);

  if (sig.length !== 56) return `proof must be 56 bytes, got ${sig.length}`;
  if (pk.length !== 33)  return `pubkey must be 33 bytes, got ${pk.length}`;

  const challenge = sig.slice(0, 24);
  const zBytes    = sig.slice(24, 56);

  // EIP-44 ADH message: [0x00, network, blake2b256(utf8_message)]
  const msgHash = blake2b(utf8.encode(message), { dkLen: 32 });
  const msgMainnet = concat([0x00, 0x00], msgHash);   // 34 bytes
  const msgTestnet = concat([0x00, 0x10], msgHash);

  // Reconstruct commitment: a = z*G - e*P (NOT +)
  const P = secp256k1.Point.fromBytes(pk);
  const z = bytesToBigInt(zBytes);
  const e = bytesToBigInt(challenge);
  const a = secp256k1.Point.BASE.multiply(z).add(P.multiply(e).negate());
  const aCompressed = a.toBytes(true);   // 33 bytes

  // Build fiat-shamir tree bytes for a single ProveDlog leaf
  const propBytes = new Uint8Array([
    0x10, 0x01, 0x08, 0xcd,       // header, numConstants=1, SigmaProp type, ProveDlog opcode
    ...pk,                         // 33-byte pubkey
    0x73, 0x00,                    // ConstantPlaceholder(0) body
  ]);                              // length always 39

  const treeBytes = new Uint8Array([
    0x01,                          // LEAF_PREFIX
    0x00, propBytes.length,        // prop_len i16 BE (= 0x00 0x27 for 39)
    ...propBytes,
    0x00, aCompressed.length,      // commit_len i16 BE (= 0x00 0x21 for 33)
    ...aCompressed,
  ]);

  // Try mainnet first, then testnet
  for (const signedMsg of [msgMainnet, msgTestnet]) {
    const hashInput = concat(treeBytes, signedMsg);
    const ePrime = blake2b(hashInput, { dkLen: 32 }).slice(0, 24);
    if (timingSafeEqual(Buffer.from(challenge), Buffer.from(ePrime))) return null;
  }
  return "Schnorr signature verification failed";
}
```

(Pseudocode — adapt to the existing noble imports and codec helpers already in use.)

## Captured test vector

Embed this in the auth-svc unit tests so this class of regression cannot recur:

```
signature:  2f007062d92faea2c77ae85758999262e856ce737495f9eb74ab33e26903c9d084a5544209d31500917c390452d56d889fae680a408d4a96
public_key: 0347203530f6977e33b0465a0da69428f2497f90ce32434fc16fb17c93e3e8300e
address:    3Wy6H5zue2YARihJKk4ccYF239cDWZYSj43qfVmzearpoy1jTPa8
message:    "Authenticate to blockhost-001 with code: 145553"
expected:   valid (returns null / no error)
```

Any passing implementation must accept this vector. sigma-rust's `verify_signature` has been confirmed to accept it with the EIP-44 mainnet-prefixed 34-byte message format.

## Verification

After rebuild + redeploy:
- The captured test vector above returns `null` (valid) from `verifySchnorrProof`.
- A fresh SSH auth with Nautilus signing results in login success (`.sig` file written, PAM accepts).
- Syslog shows `[AUTH] Verified Schnorr proof for session <id>`.
- No WASM in the dependency tree or bundled output.

## Contract reference

No facts/ contract change. Pure implementation fix to `plugins/ergo/auth-svc-src/index.ts` (and its bundled output at `/usr/share/blockhost/auth-svc/ergo/auth-svc.js`).

## Out-of-scope note

The Fleet SDK `ErgoMessage.fromData()` default-network choice (mainnet regardless of address network) is a Fleet SDK behavior, not an auth-svc concern. Handle both prefixes defensively as above; do not try to "fix" this upstream.
