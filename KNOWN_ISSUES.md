# Known Issues

## Finalization not idempotent with reused contracts

**Affected steps:** `contracts`, `finalize` (createPlan), `mint_nft`

**Trigger:** Admin chooses "import wallet" + "use existing contracts" — i.e., rerunning the wizard against contracts that were already finalized once (same deployer, same NFT + subscription contracts).

**Current behavior:** Finalization blindly executes every on-chain call regardless of existing state:
- `createPlan()` creates a duplicate plan (plan #2, #3, ...) every run
- `setPrimaryStablecoin()` re-sets the same address (harmless but wasteful)
- `mint()` mints a new NFT (#1, #2, ...) to the admin wallet instead of updating #0

Nothing reverts — it all succeeds — but it leaves junk on-chain and the integration test hardcodes `PLAN_ID=1`, so duplicate plans don't break tests but will confuse anyone looking at the contract state.

**Expected behavior:** When `contract_mode == "existing"` and `wallet_mode == "import"`, finalization should query on-chain state before acting:

| Step | Check | Action if exists |
|------|-------|-----------------|
| `_create_default_plan` | `nextPlanId > 1` (plans already exist) | Skip plan creation |
| `setPrimaryStablecoin` | Query current stablecoin address | Skip if already set to correct address |
| `_finalize_mint_nft` | `totalSupply() > 0` and admin wallet `balanceOf() > 0` | Update NFT #0's `userEncrypted` and `publicSecret` via contract update call instead of minting new token |

**NFT update path:** The AccessCredentialNFT contract has separate update functions (all owner-only):
- `updateUserEncrypted(uint256 tokenId, bytes newUserEncrypted)`
- `updateAnimationUrl(uint256 tokenId, string newAnimationUrlBase64)`
- `updateExpiration(uint256 tokenId, uint256 newExpiration)`

No single call updates `publicSecret` — that field is immutable after mint. When an admin NFT already exists, finalization should:
1. Find the admin's token: `tokenOfOwnerByIndex(adminWallet, 0)`
2. Call `updateUserEncrypted(tokenId, newEncryptedData)` with fresh ciphertext
3. Call `updateAnimationUrl(tokenId, newBase64)` to refresh the signing page
4. Use the same `publicSecret` that was set at original mint time (or accept that the admin re-signs with the existing one)

**Scope:** Installer wizard finalization (`installer/web/app.py`), not CI-specific. Surfaced by CI reuse of persistent test contracts but affects any re-finalization scenario.
