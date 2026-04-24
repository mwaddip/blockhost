Before starting, load CLAUDE.md, `~/projects/OVERRIDES.md`, and the `blockhost-development` skill.
Read `facts/ENGINE_INTERFACE.md` §13 (Network Hook Integration) before making changes.

---

# Engine-Cardano: Network Hook Integration

## Observable problem
The engine handler currently reads IPv6 from the provisioner's `create` result and uses it directly for connection details. There's no network-mode awareness — the engine assumes broker/manual IPv6.

## Target state
After `provisioner.create()`, call `network_hook.get_connection_endpoint()` to get the subscriber-facing host. Use `guest-exec` instead of `update-gecos` for GECOS updates. The engine is network-mode-agnostic.

## Changes needed

Same as the EVM/OPNet engines:

1. Read `/etc/blockhost/network-mode` at handler startup (default `broker`)
2. After `provisioner.create()`, call the network hook to get the connection endpoint
3. Replace `update-gecos` with `guest-exec`
4. Call `network_hook.cleanup()` on VM destroy

The engine handler is TypeScript — call the Python network hook via `child_process.execSync` or equivalent:

```typescript
import { execSync } from "child_process";
const host = execSync(
  `python3 -c "from blockhost.network_hook import get_connection_endpoint; print(get_connection_endpoint('${vmName}', '${bridgeIp}', '${networkMode}'))"`,
  { encoding: "utf8" }
).trim();
```

## Deliverables
1. Modify: VM creation handler — add network hook call after create
2. Modify: VM destroy handler — add cleanup call after destroy
3. Modify: GECOS update — use `guest-exec`
4. Modify: connection details — use host from network hook

## Verification
- Broker mode: connection details still contain IPv6 (no regression)
