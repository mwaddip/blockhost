# Known Issues

## ~~Finalization not idempotent with reused contracts~~ (RESOLVED)

**Resolved.** Three changes make finalization safe to re-run against existing contracts:

1. **UI guard:** "Use existing contracts" is hidden when wallet_mode is "generate" — a fresh wallet can't own pre-deployed contracts.
2. **Plan creation:** `_create_default_plan()` queries `nextPlanId()` and `primaryStablecoin()` before writing. Skips if plans/stablecoin already exist.
3. **NFT minting:** `_finalize_mint_nft()` checks admin's `balanceOf()`. If > 0, calls `updateUserEncrypted()` + `updateAnimationUrl()` on the existing token instead of minting a new one. Reads immutable `publicSecret` from on-chain via `getAccessData()`.
