# OPNet Engine: Fix mark_nft_minted → set_nft_minted

The monitor calls `mark_nft_minted()` on the VMDatabase after minting an NFT, but common's VMDatabase exposes `set_nft_minted()`. The method was renamed in common but the engine wasn't updated.

Error in monitor log:
```
AttributeError: 'VMDatabase' object has no attribute 'mark_nft_minted'. Did you mean: 'set_nft_minted'?
```

Non-critical — the VM provisions and GECOS updates correctly — but the database flag `nft_minted` never gets set, which breaks the reconciler's ability to track NFT state.

Find all occurrences of `mark_nft_minted` in the engine source and replace with `set_nft_minted`.
