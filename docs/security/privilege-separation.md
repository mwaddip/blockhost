# Privilege Separation

BlockHost uses a strict two-user model. Only one component runs as root.

## User Model

| User | Runs | Why |
|------|------|----|
| `root` | `blockhost-root-agent` only | Single, auditable surface for privileged operations |
| `blockhost` | Everything else | Engine, provisioner, monitor, GC, signup, broker |

## Root Agent

The root agent daemon is a Unix socket server that accepts JSON requests from the `blockhost` user and executes privileged operations. Socket permissions are `0660 root:blockhost`.

### What goes through the root agent

- VM management (Proxmox: `qm` commands; libvirt: `virsh` on systems without group access)
- Network routing (`ip -6 route add/del`)
- Firewall rules (`iptables -A/-D`)
- Disk image customization (`virt-customize`)
- Key generation (writing to `/etc/blockhost/`)
- Addressbook writes (updating `/etc/blockhost/addressbook.json`)
- Resource throttling (cgroup adjustments, tc commands)

### What runs directly as `blockhost`

- Blockchain interactions (RPC calls, signing, contract reads)
- Config file reads (`/etc/blockhost/*.yaml` — group-readable)
- Key file reads (`/etc/blockhost/*.key` — 0640, group-readable)
- VM database reads/writes (`/var/lib/blockhost/vms.json`)
- Provisioner CLI commands (most operations)
- Network queries, DNS, health checks

## Protocol

Length-prefixed JSON over Unix socket:
- 4-byte big-endian length + JSON payload (both directions)
- Request: `{"action": "action-name", "params": {...}}`
- Response: `{"ok": true, ...}` or `{"ok": false, "error": "reason"}`

## Security Properties

- **No shell access**: The root agent never executes shell strings. Commands are constructed from validated, whitelisted parameters.
- **Path validation**: File paths are restricted to allowed directories. Symlinks are resolved with `os.path.realpath()` before prefix checks.
- **Argument whitelisting**: Command arguments are validated against allowlists. Unknown arguments are rejected.
- **No `shell=True`**: All subprocess calls use argument lists, never shell interpolation.
- **Timeout on all operations**: Every subprocess has a timeout. Hanging operations are killed.
