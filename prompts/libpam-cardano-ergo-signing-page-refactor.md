Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.

---

# Refactor Cardano and Ergo signing pages to the PAGE_TEMPLATE contract

`facts/PAGE_TEMPLATE_INTERFACE.md` specifies that each chain plugin's signing page is split into three pieces:

```
plugins/<chain>/signing-page/
  template.html   ← replaceable (HTML/CSS only)
  engine.js       ← plugin-owned (wallet + signing logic)
  index.html      ← generated (template + bundle + CONFIG injection)
```

EVM and OPNet honor this contract: they ship separate `template.html` and `engine.js`, and a generator produces `index.html` by substituting `{{VARIABLE}}` placeholders and inlining the bundle.

Cardano and Ergo currently ship a hand-written `index.html` with no template/bundle split, divergent DOM IDs, divergent or absent CONFIG object, and no callback POST to `/auth/callback/{sessionId}`. Bring them into the contract.

## What to produce, per plugin

For `plugins/cardano/signing-page/` and `plugins/ergo/signing-page/` — each gets:

1. **`template.html`** — pure HTML/CSS, no chain logic. Lift the visual structure from the current `index.html`. Must contain all required DOM elements below.
2. **`engine.js`** — wallet connection, signing, callback POST. No layout code, no styling.
3. **Generator script** or build rule that produces `index.html` from the template with `{{VARIABLE}}` substitutions and the bundle inlined.
4. Delete the hand-written `index.html` (it becomes generator output, not source).

## Required DOM element IDs (from the contract)

Both pages must expose these IDs (rename your existing elements to match):

| Element ID | Purpose |
|------------|---------|
| `btn-connect` | Wallet connect button |
| `btn-sign` | Sign message button |
| `wallet-address` | Displays connected wallet address |
| `status-message` | Shows status/error messages |
| `step-connect` | Connect wallet step container |
| `step-sign` | Sign message step container |

Your current Cardano page uses `#wallet`, `#connect-section`, `#main-section`, `#sign` — rename to the canonical set above.

## CONFIG object

The template must embed a `CONFIG` `<script>` block populated by the generator:

```html
<script>
  const CONFIG = {
    publicSecret: "{{PUBLIC_SECRET}}",
    serverPublicKey: "{{SERVER_PUBLIC_KEY}}",
    rpcUrl: "{{RPC_URL}}",
    nftContract: "{{NFT_CONTRACT}}",
    subscriptionContract: "{{SUBSCRIPTION_CONTRACT}}"
    // Add chain-specific fields as needed for Cardano/Ergo — document them
    // in the plugin's README and update facts/PAGE_TEMPLATE_INTERFACE.md
    // (send a patch up; don't edit facts/ directly — that's main-session work).
  };
</script>
<script src="engine.js"></script>
```

Cardano needs: Koios URL, NFT policy ID, subscription validator address (at minimum).
Ergo needs: node/explorer URL, registry NFT ID, subscription ergo-tree hash (at minimum).

Pick names that parallel the EVM/OPNet style (camelCase in JS, UPPER_SNAKE in template placeholders).

## CSS classes the bundle toggles

The bundle must only add/remove these on elements — never inject inline styles:

- `hidden` on step containers (not-yet-active)
- `active` on step containers (current)
- `completed` on step containers (done)
- `disabled` on buttons
- `loading` on buttons
- `error` / `success` on `#status-message`

The template owns what those classes look like.

## Callback flow

Cardano and Ergo already POST to `/auth/callback/{sessionId}` — full end-to-end auth works today. Keep it working. The refactor is purely structural: the existing callback payload (`{signature, key, otp, machineId}`) stays as-is. Verify it survives the template/engine split.

## What NOT to change

- Don't touch EVM or OPNet signing pages — they're already compliant.
- Don't move signing pages out of `plugins/<chain>/signing-page/` — directory layout is canonical.
- Don't bundle a framework (React, Vue, etc.). Plain JS, matches EVM/OPNet.

## Verification

For each of Cardano and Ergo, before pushing:

1. `template.html` has no chain logic — grep for `fetch(`, `Nautilus`, `Lace`, `cardano`, `ergo` in template: should be zero matches.
2. `engine.js` has no `<style>`, no `innerHTML = '<div ...'`, etc.
3. `index.html` is regenerated from template + bundle + live config.
4. DOM IDs match the canonical list.
5. Manually test: load page, connect wallet, sign, check browser devtools Network tab for the POST to `/auth/callback/...`.

Single commit per plugin (so two commits if you do both). Push when done; main session pulls the pointer.

## Scope boundary

This is libpam-web3 work. Do NOT edit files in `blockhost/`, `facts/`, or the engine submodules. If `facts/PAGE_TEMPLATE_INTERFACE.md` needs updating to document Cardano/Ergo-specific CONFIG fields, add notes to the commit message and flag it — main session will update facts.
