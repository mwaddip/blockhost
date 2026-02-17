# blockhost-engine: Reconciler NFT Ownership Transfer Detection

**Branch:** `feature/opnet` (create from current master)

**Start by reading:** `SPECIAL.md`, `CLAUDE.md` — in that order, before doing anything else.

**Pull updated facts submodule:** The interface contracts have already been updated on `feature/opnet`. Before starting work:
```bash
cd facts && git fetch origin && git checkout feature/opnet && cd ..
```

---

## Context

libpam-web3 has been refactored. The PAM module no longer queries any blockchain for NFT ownership. Instead, it verifies signatures locally and checks wallet addresses against the VM's GECOS field (`wallet=ADDRESS,nft=TOKEN_ID`). The GECOS field is populated at VM creation time by cloud-init.

This creates a new responsibility for the reconciler: when an NFT is transferred to a new wallet, the reconciler must detect the ownership change and update the VM's GECOS field so the new owner can authenticate. This is the sole mechanism by which VMs learn about ownership changes — there is no other path.

---

## What Changes

### 1. Detect NFT ownership transfers in `src/reconcile/index.ts`

The reconciler currently checks:
- Tokens that exist on-chain but aren't marked minted locally
- Reserved tokens that haven't been minted yet

**Add:** For every active VM with a minted NFT, compare the on-chain `ownerOf(tokenId)` result with the locally stored `owner_wallet`. If they differ, the NFT has been transferred.

**When a transfer is detected:**

1. Log the ownership change: `[RECONCILE] NFT #${tokenId} transferred: ${oldOwner} → ${newOwner}`
2. Update `owner_wallet` in vms.json to the new owner address
3. Call the provisioner's `update-gecos` command to update the VM's GECOS field:
   ```
   getCommand("update-gecos") <vm-name> <new-wallet-address>
   ```
4. If the provisioner command fails (VM stopped, guest agent unresponsive), log a warning but keep the updated `owner_wallet` in vms.json. The GECOS update will be retried on the next reconciliation cycle because the local `owner_wallet` now matches on-chain, but the VM hasn't been updated — track this with a flag like `gecos_synced: false` on the VM entry.

**Integration point:** This check should run as part of the existing reconciliation cycle (every 5 minutes). Add it after the existing minting reconciliation logic.

### 2. Track GECOS sync state

Add a `gecos_synced` field to the VM entry tracking. When an ownership transfer is detected:
- Set `gecos_synced = false` when the transfer is first detected
- Set `gecos_synced = true` when the provisioner `update-gecos` command succeeds
- On each reconciliation cycle, retry any VMs where `gecos_synced === false`

This handles the case where the VM is temporarily unreachable (stopped, rebooting, guest agent not responding).

### 3. No changes to event handlers

The `SubscriptionCreated` handler and other event handlers are unchanged. The wallet address at VM creation time is still passed via `--owner-wallet` to the provisioner. The GECOS field is initially set correctly by cloud-init. The reconciler only needs to handle post-creation ownership changes.

### 4. No changes to existing reconciliation logic

The existing minting reconciliation (checking if tokens are marked as minted) stays exactly as is. The ownership transfer detection is additive — a new check that runs alongside the existing checks.

---

## Provisioner Command Contract

The `update-gecos` verb is being added to both provisioner manifests (`provisioner.json`). Each provisioner implements it using the QEMU guest agent to execute `usermod` on the running VM. The engine doesn't need to know the implementation details — just call:

```
getCommand("update-gecos") <vm-name> <wallet-address> --nft-id <token_id>
```

The engine has both the wallet address (from `ownerOf`) and the token ID readily available. Pass both — the provisioner constructs the GECOS string from the args without any database lookup for the token.

**Exit 0** = GECOS updated successfully.
**Exit 1** = Failed (VM stopped, guest agent unresponsive, etc.).

---

## Verification

After implementation:
1. Reconciler detects when `ownerOf(tokenId)` returns a different address than `owner_wallet`
2. On transfer detection: vms.json `owner_wallet` updated, provisioner `update-gecos` called
3. Failed GECOS updates are retried on subsequent reconciliation cycles
4. Existing minting reconciliation logic is unchanged
5. No new blockchain queries beyond what already exists (just `ownerOf` which is already called)

---

## Documentation

Update `CLAUDE.md` and `README.md` to document the new ownership transfer detection and GECOS sync mechanism.
