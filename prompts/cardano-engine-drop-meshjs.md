# Cardano Engine: Remove @meshsdk/core dependency

The only MeshJS usage in the entire engine is two functions in `src/cardano/wallet.ts`:

```typescript
import { pubKeyAddress, serializeAddressObj } from "@meshsdk/core";
```

These construct a bech32 Cardano base address from payment and stake key hashes. MeshJS pulls in `@cardano-sdk/crypto` which ships ESM-only files that import `libsodium-wrappers-sumo` via the ESM export path — esbuild can't resolve this regardless of `--conditions` or `--main-fields` flags. This breaks the keygen bundle.

Replace with manual address construction using the `bech32` package (already a transitive dependency, or add it — it's 4KB):

```typescript
import { bech32 } from "bech32";

function buildBaseAddress(paymentKeyHash: string, stakeKeyHash: string, networkId: number): string {
  // Cardano base address (type 0): header byte + 28-byte payment hash + 28-byte stake hash
  // Header: 0b0000_xxxx where xxxx = network_id (0 = testnet, 1 = mainnet)
  const header = networkId & 0x0f;
  const payload = Buffer.concat([
    Buffer.from([header]),
    Buffer.from(paymentKeyHash, "hex"),
    Buffer.from(stakeKeyHash, "hex"),
  ]);
  const words = bech32.toWords(payload);
  const prefix = networkId === 1 ? "addr" : "addr_test";
  return bech32.encode(prefix, words, 1023);
}
```

Then in `deriveWallet()`, replace lines 65-67:

```typescript
const networkId = network === "mainnet" ? 1 : 0;
const address = buildBaseAddress(paymentKeyHash, stakeKeyHash, networkId);
```

After this change, remove `@meshsdk/core` from `package.json` dependencies and run `npm install` to clean up node_modules. Add `bech32` to dependencies if it's not already there.

This eliminates the entire MeshJS/cardano-sdk/libsodium-wrappers-sumo dependency chain from the keygen bundle.
