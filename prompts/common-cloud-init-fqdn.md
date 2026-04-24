# blockhost-common: Set FQDN in cloud-init templates

VMs need their FQDN set so `hostname -f` returns the full domain (e.g. `f03.vm.blockhost.io`) instead of just the VM name (`blockhost-001`). libpam-web3 derives the signing page URL from `hostname -f` — without FQDN, the URL shows `https://blockhost-001:34206` which is unreachable from the user's browser.

## What to change

In `usr/share/blockhost/cloud-init/templates/nft-auth.yaml`, add FQDN and hostname management. The VM creation script passes these as template variables:

```yaml
# Add near the top of the cloud-init template:
fqdn: ${VM_FQDN}
manage_etc_hosts: true
```

`manage_etc_hosts: true` tells cloud-init to update `/etc/hosts` with the FQDN → `127.0.1.1` mapping, so `hostname -f` resolves correctly.

## Template variables

The provisioner's `vm-create` script needs to pass these variables when rendering the cloud-init template:

| Variable | Source | Example |
|----------|--------|---------|
| `VM_FQDN` | Computed from broker allocation: `{offset_hex}.{dns_zone}` | `f03.vm.blockhost.io` |

If no broker allocation exists (no IPv6, no DNS zone), fall back to `{vm_name}.local`.

## Where FQDN is computed

The provisioner already has the broker allocation data (`/etc/blockhost/broker-allocation.json`) with `dns_zone` and the allocated IPv6. The FQDN offset is derived from the IPv6 address: lower bits of the allocated address in hex + the `dns_zone`.

The provisioner passes this to `render_cloud_init()` from common. Common's template just needs the `fqdn:` and `manage_etc_hosts:` directives to use it.
