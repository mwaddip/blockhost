# Common: Remove generate-wallet from root agent

## Context

`/usr/share/blockhost/root-agent-actions/system.py` contains `handle_generate_wallet` which uses `cast wallet new` (EVM-only). Wallet generation is chain-specific and should be provided by each engine, not by common.

The root agent already supports this — it's a plugin system that loads all `.py` files from `/usr/share/blockhost/root-agent-actions/` (except `_`-prefixed). Each engine can ship its own action file.

## Changes needed in `system.py`

1. Remove the `handle_generate_wallet` function entirely (lines ~83-120 approximately — the function that calls `cast wallet new`)
2. Remove the `'generate-wallet': handle_generate_wallet` entry from the `ACTIONS` dict

That's it. Do NOT replace it with anything — each engine will provide its own implementation.

## Do NOT remove

- `handle_addressbook_save` — this is chain-agnostic (just writes JSON), keep it
- Anything else in `system.py` — only remove `generate-wallet`
