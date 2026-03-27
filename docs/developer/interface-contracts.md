# Interface Contracts

Every component boundary in BlockHost has a documented contract. Contracts live in the `facts/` submodule and define the exact signatures, output formats, and integration points that consumers depend on.

## Available Contracts

| Contract | Covers |
|----------|--------|
| [`PROVISIONER_INTERFACE.md`](https://github.com/mwaddip/blockhost-facts/blob/main/PROVISIONER_INTERFACE.md) | Manifest schema, CLI commands (create, destroy, start, stop, metrics, throttle, etc.), wizard plugin exports, root agent actions, first-boot hook, .deb packaging |
| [`ENGINE_INTERFACE.md`](https://github.com/mwaddip/blockhost-facts/blob/main/ENGINE_INTERFACE.md) | Engine CLIs (bw, ab, is, mint_nft, deploy-contracts), smart contract ABIs, monitor, fund manager, wizard plugin, .env files |
| [`COMMON_INTERFACE.md`](https://github.com/mwaddip/blockhost-facts/blob/main/COMMON_INTERFACE.md) | Config API, VM database, root agent protocol, cloud-init rendering, dispatcher |
| [`WIZARD_UI.md`](https://github.com/mwaddip/blockhost-facts/blob/main/WIZARD_UI.md) | HTML patterns, CSS classes, components, anti-patterns for wizard templates |
| [`PAGE_TEMPLATE_INTERFACE.md`](https://github.com/mwaddip/blockhost-facts/blob/main/PAGE_TEMPLATE_INTERFACE.md) | Signing/signup page template contract — DOM element IDs, CSS classes, CONFIG object, engine bundle API |
| [`BROKER_INTERFACE.md`](https://github.com/mwaddip/blockhost-facts/blob/main/BROKER_INTERFACE.md) | Broker registry, allocation protocol, WireGuard tunnel setup |
| [`ADMIN_INTERFACE.md`](https://github.com/mwaddip/blockhost-facts/blob/main/ADMIN_INTERFACE.md) | Admin panel authentication, API endpoints, management operations |
| [`NFT_CONTRACT_INTERFACE.md`](https://github.com/mwaddip/blockhost-facts/blob/main/NFT_CONTRACT_INTERFACE.md) | Access credential NFT spec — minting, ownership, userEncrypted field |

## The Rule

**When interfaces don't match, fix the interface — never wrap the mismatch.** If two components miscommunicate, the problem is in the contract definition, not in missing glue code. Do not write adapters, shims, or wrappers to paper over interface disagreements. Trace the mismatch to whichever side is wrong and fix it at the source.

## Reading Contracts

Before modifying any code that touches a component boundary, read the relevant contract. Don't rely on memory or assumptions about how a component interfaces — read the contract. The facts/ submodule is checked out in every repo that needs it.

```bash
# In any repo with facts/ as a submodule
cat facts/PROVISIONER_INTERFACE.md
```
