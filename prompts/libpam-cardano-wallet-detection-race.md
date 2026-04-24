# libpam-web3-cardano: Fix wallet detection race condition

`signing-page/engine.js` line 179 calls `detectWallets()` immediately at script load. CIP-30 wallet extensions (Eternl, Nami, etc.) inject `window.cardano` asynchronously — the script runs before the extension has populated it. Result: "No CIP-30 compatible wallets detected" even when the extension is installed.

## Fix

Replace line 179:

```javascript
detectWallets();
```

With:

```javascript
// Wallet extensions inject window.cardano asynchronously — retry until found
if (window.cardano) {
  detectWallets();
} else {
  let retries = 0;
  const timer = setInterval(() => {
    if (window.cardano || ++retries > 10) {
      clearInterval(timer);
      detectWallets();
    }
  }, 200);
}
```

This gives extensions up to 2 seconds to inject, checking every 200ms. If `window.cardano` is already present (fast extension), it runs immediately.
