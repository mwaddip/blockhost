# Onion Routing — Host-Level Network Mode

> Design spec for adding Tor hidden services as a third network mode in the BlockHost wizard.
> ONION.md (2026-02-25) established the concept; this is the implementation spec.

## Scope

Host-level onion routing only. The entire BlockHost machine is reachable via `.onion` addresses. Plan-level onion (per-plan "onion-only VM" toggle) is future work.

## Summary

The wizard gains a "Network Mode" choice: Broker (IPv6 tunnel), Manual (static IPs), or Onion (Tor hidden services). Choosing Onion skips broker registration, IPv6 allocation, and Let's Encrypt. The host runs a single Tor daemon. Each VM gets its own hidden service and `.onion` address. Provisioners, engines, and VM templates are unchanged — the network stack is a layer between the engine handler and the root agent.

## Architecture

```
Wizard (network mode choice → session['network_mode'])
  │
First-boot (install tor, generate host hidden service, write config)
  │
Engine handler (agnostic — calls network_hook for connection endpoint)
  ├─ provisioner.create()        → {ip, ipv6, vmid, ...}
  ├─ network_hook.setup()        → ".onion" or IPv6 or static IP
  ├─ provisioner.guest-exec()    → update GECOS, update signing URL
  └─ encrypt connection details  → subscriber
```

## Key Principle: Provisioners and Engines Stay Agnostic

The provisioner creates VMs with internal bridge IPs — always the same regardless of network mode. The engine handler calls `network_hook.get_connection_endpoint()` and gets back a host string. It doesn't know which mode is active. `.onion`, IPv6, static IP — all the same opaque string to the engine.

## Submodule Boundary

Changes span multiple repos. The main session owns the wizard and facts. All submodule changes (common, provisioners, engines, libpam-web3) are dispatched as prompts.

---

## 1. Wizard — Network Mode Choice

The connectivity page currently offers Broker and Manual as radio options. Onion becomes a third.

**Onion path through the wizard:**
- User picks Onion on the connectivity page
- Broker registry field is hidden
- Certbot/SSL step is skipped (Tor encrypts end-to-end)
- IPv6 allocation step is skipped
- Wizard saves `session['network_mode'] = 'onion'`
- If the user picks a host-level onion, the wizard generates a host hidden service for the signup page (so users can reach the wizard itself)

**Session data written:**
```python
session['network'] = {
    'mode': 'onion',       # 'broker', 'manual', 'onion'
}
```

---

## 2. First-Boot — Tor Installation

When `network_mode == 'onion'`:
- Install `tor` package
- Generate host hidden service (for admin/signup access to the host itself)
- Write network mode to `/etc/blockhost/network-mode` (or equivalent config)
- No broker-client call, no certbot, no IPv6 config

---

## 3. Provisioner — New `guest-exec` Command

Add a generic guest-exec primitive to the provisioner CLI. Both provisioners implement it using their hypervisor's native mechanism (qemu-guest-agent for libvirt, `qm guest exec` for Proxmox).

```
blockhost-vm-guest-exec <name> <command...>
```

This replaces the domain-specific `update-gecos` command. `update-gecos` becomes `guest-exec name "sed ... /etc/passwd"`.

**Manifest addition:** Add `"guest-exec"` to the `commands` dict in `provisioner.json`.

---

## 4. Root Agent — Tor Actions

Two new actions in the root agent:

### `tor-hidden-service-add`
- Params: `vm_name`, `bridge_ip`, `port=22`
- Creates `/var/lib/tor/blockhost-{name}/`
- Appends to `/etc/tor/torrc`:
  ```
  HiddenServiceDir /var/lib/tor/blockhost-{name}/
  HiddenServicePort {port} {bridge_ip}:{port}
  ```
- Reloads tor (`systemctl reload tor`)
- Returns the `.onion` address from `hostname` file

### `tor-hidden-service-remove`
- Params: `vm_name`
- Removes entries from `/etc/tor/torrc`
- Reloads tor
- Removes `/var/lib/tor/blockhost-{name}/`

---

## 5. Network Hook — Common Module

New module: `blockhost/network_hook.py` in blockhost-common.

### `get_connection_endpoint(vm_name, bridge_ip, mode) -> str`

| Mode | Behavior | Returns |
|------|----------|---------|
| `broker` | Pass-through (IPv6 allocated by broker-client, stored in broker-allocation.json, consumed by provisioner) | IPv6 address |
| `manual` | Pass-through (static IP from config) | Static IP |
| `onion` | Calls root agent `tor-hidden-service-add`, then `guest-exec` to push `.onion` into VM, updates signing URL | `.onion` address |

### `cleanup(vm_name, mode) -> None`

| Mode | Behavior |
|------|----------|
| `broker` | No-op (broker release handled by broker-client) |
| `manual` | No-op |
| `onion` | Calls root agent `tor-hidden-service-remove` |

### Onion mode detail:

```
1. Call root_agent.tor-hidden-service-add(vm_name, bridge_ip, port=22)
2. Read /var/lib/tor/blockhost-{vm_name}/hostname → get .onion address
3. Push .onion into VM:
   a. provisioner.guest-exec(vm_name, "echo '{bridge_ip} {onion} {vm_name}' >> /etc/hosts")
   b. provisioner.guest-exec(vm_name, "sed -i 's|signing_url = .*|signing_url = \"http://{onion}:8443\"|' /etc/pam_web3/config.toml")
4. Return .onion address
```

---

## 6. Engine Handler — Agnostic Flow

The engine's VM creation handler (fund manager / subscription handler) follows the same flow for all network modes:

```
1. If broker mode: broker-client allocation (existing, unchanged)
2. result = provisioner.create(name, wallet, ...)
   → {ip, ipv6, vmid, username}
   Note: ipv6 is "" in onion/manual modes (already handled by provisioner)
3. host = network_hook.get_connection_endpoint(name, result.ip, mode)
   → broker: result.ipv6
   → manual: static_ip
   → onion: creates hidden service, pushes to VM, returns .onion
4. Mint NFT (existing, unchanged)
5. provisioner.guest_exec(name, "sed GECOS with NFT ID")
6. encrypt_connection_details({host, port: 22}) → subscriber
```

Destroy flow adds `network_hook.cleanup(name, mode)` after `provisioner.destroy(name)`.

---

## 7. VM / Cloud-init — No Changes

The `nft-auth.yaml` template is unchanged:
- `SIGNING_HOST` starts as a placeholder (e.g., the internal bridge IP)
- `SIGNING_DOMAIN` is empty in onion mode → Let's Encrypt block is skipped (already gated on `[ -n "${SIGNING_DOMAIN}" ]`)
- Self-signed cert is generated as the fallback
- The network hook fixes the signing URL post-boot via `guest-exec`

---

## 8. libpam-web3 — No Changes

libpam-web3 reads `signing_url` from `/etc/pam_web3/config.toml` as-is — it doesn't hardcode the scheme. The cloud-init template writes `https://` as the default. In onion mode, the network hook sed-replaces the full URL to `http://{onion}:8443`. libpam-web3 just reads whatever is in the config file. No code change needed.

---

## 9. Destroy Flow

```
1. provisioner.destroy(name)          // existing, unchanged
2. network_hook.cleanup(name, mode)   // removes hidden service if onion
3. Broker release if applicable       // existing, unchanged
```

---

## 10. What Doesn't Change

| Component | Impact |
|-----------|--------|
| Provisioner create/destroy | Same args, same output. Empty ipv6 already handled. |
| VM template (nft-auth.yaml) | No changes. |
| Smart contracts | Plan ID determines behavior. No contract changes. |
| Broker | Unchanged. Onion mode simply doesn't call it. |
| VM internals | No tor in VMs. No awareness of network mode. |

## Files Changed (by repo)

### blockhost (main) — owned by this session
- `installer/web/templates/connectivity.html` — add Onion radio option
- `installer/web/app.py` — handle network_mode in session
- `installer/web/finalize.py` — pass network mode to engine config
- `scripts/first-boot.sh` — install tor, generate host hidden service
- `facts/PROVISIONER_INTERFACE.md` — add guest-exec to commands
- `facts/COMMON_INTERFACE.md` — add network_hook, tor actions
- `facts/ENGINE_INTERFACE.md` — document network_hook call in handler flow

### Submodule repos — dispatched as prompts
- `blockhost-common` — network_hook.py, root agent tor actions, guest-exec in dispatcher
- `blockhost-provisioner-libvirt` — guest-exec CLI, update-gecos refactored
- `blockhost-provisioner-proxmox` — guest-exec CLI
- `blockhost-engine-evm` — call network_hook in handler, use guest-exec for GECOS
- `blockhost-engine-opnet` — same
- `blockhost-engine-cardano` — same
- `blockhost-engine-ergo` — same
