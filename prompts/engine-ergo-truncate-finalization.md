# Truncate contract outputs in finalization step

## Problem

The "Deploying contracts" finalization step displays full ErgoTree hex strings untruncated. These overflow the card width. Compare with the deployer address line above it, which correctly uses truncation + copy button.

Screenshot shows:
```
Reference Ergo Tree:   0008cd03cde805c3809edda31f89aa574698e7507863c1cc65334d5811d8a7ce5cbc0a7d
Subscription Ergo Tree: 100a04080040004000400040005026e2103cde805c3809edda31f89aa574698e7507863c1cc65334...
```

These should look like:
```
Reference Ergo Tree:   0008cd03...bc0a7d  📋
Subscription Ergo Tree: 100a0408...c65334  📋
```

## Fix

In the finalization step that deploys contracts (the Python function that returns the status dict with these values), truncate the ErgoTree hex strings the same way the deployer address is truncated. Use the same pattern the installer uses everywhere else:

```html
<span class="truncated-value" title="FULL_HEX" data-copy="FULL_HEX">
    FIRST_8...LAST_6
    <button class="copy-btn" onclick="copyToClipboard('FULL_HEX', this)">📋</button>
</span>
```

The existing CSS class `truncated-value` and `copyToClipboard()` JS function are already available from the installer framework — no need to define them.

## Where to look

The finalization step returns a dict with keys like `reference_ergo_tree` and `subscription_ergo_tree` (or similar). The template that renders these values in the finalization progress page needs to wrap them in the truncation pattern. Check how the deployer address line does it on the same page — match that pattern exactly.
