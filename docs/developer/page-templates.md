# Page Templates

The signing and signup pages use a template/engine split: HTML/CSS is replaceable, JavaScript wallet logic stays with the engine.

## Separation

```
template (HTML/CSS)     — layout, branding, copy, styles
engine bundle (JS)      — wallet connection, signing, chain interaction
generator (script)      — injects config variables, combines template + bundle → output
```

The template never contains wallet or chain logic. The bundle never contains layout or styling.

## Customizing

To create a custom template:

1. Copy the default `template.html` or `signup-template.html` from an engine
2. Modify HTML structure, CSS, copy, images — anything visual
3. Keep all required DOM element IDs intact
4. Keep the `CONFIG` script block and `engine.js` include
5. Rebuild with the generator script

## Required DOM Elements

### Signing page

| Element ID | Type | Purpose |
|------------|------|---------|
| `btn-connect` | button | Triggers wallet connection |
| `btn-sign` | button | Triggers message signing |
| `wallet-address` | span/div | Displays connected wallet address |
| `status-message` | div | Shows status/error messages |
| `step-connect` | div | Connect wallet step container |
| `step-sign` | div | Sign message step container |

### Signup page

| Element ID | Type | Purpose |
|------------|------|---------|
| `btn-connect` | button | Wallet connection |
| `btn-sign` | button | Message signing |
| `btn-purchase` | button | Subscription purchase |
| `wallet-address` | span/div | Wallet address display |
| `plan-select` | select | Plan selection |
| `days-input` | input | Subscription duration |
| `total-cost` | span/div | Computed cost |
| `status-message` | div | Status/error display |
| `step-connect` | div | Connect step container |
| `step-sign` | div | Sign step container |
| `step-purchase` | div | Purchase step container |
| `step-servers` | div | View servers container |
| `server-list` | div | Decrypted server details |

## CSS Classes

The engine bundle toggles these classes — the template defines what they look like:

| Class | Applied to | Meaning |
|-------|-----------|---------|
| `hidden` | step container | Not yet active |
| `active` | step container | Currently active |
| `completed` | step container | Finished |
| `disabled` | button | Not clickable |
| `loading` | button | Operation in progress |
| `error` | status-message | Error state |
| `success` | status-message | Success state |

## CONFIG Object

The generator injects configuration as a global object:

```html
<script>
  const CONFIG = {
    publicSecret: "{{PUBLIC_SECRET}}",
    serverPublicKey: "{{SERVER_PUBLIC_KEY}}",
    rpcUrl: "{{RPC_URL}}",
    nftContract: "{{NFT_CONTRACT}}",
    subscriptionContract: "{{SUBSCRIPTION_CONTRACT}}",
    // Engine-specific (present or absent):
    chainId: {{CHAIN_ID}},             // EVM only
    usdcAddress: "{{USDC_ADDRESS}}",   // EVM only
    paymentToken: "{{PAYMENT_TOKEN}}"  // OPNet only
  };
</script>
<script src="engine.js"></script>
```

## Full Contract

See [`facts/PAGE_TEMPLATE_INTERFACE.md`](https://github.com/mwaddip/blockhost-facts/blob/main/PAGE_TEMPLATE_INTERFACE.md) for the complete specification.
