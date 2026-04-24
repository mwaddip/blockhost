# Libvirt Provisioner: Pass VM_FQDN to cloud-init template

The common cloud-init template (`nft-auth.yaml`) already has `fqdn: ${VM_FQDN}` and `manage_etc_hosts: true`. But `scripts/vm-create.py` doesn't pass `VM_FQDN` when rendering cloud-init. The variable is empty, so `hostname -f` returns just the VM name instead of the full domain.

## Fix

In `scripts/vm-create.py`, around where the cloud-init variables are assembled (near the `signing_domain` computation around line 430), add `VM_FQDN` to the template variables dict:

```python
# Already computed:
# signing_domain = f"{offset:x}.{broker['dns_zone']}"

# Add to the cloud-init template variables:
"VM_FQDN": signing_domain if signing_domain else f"{vm_name}.local",
```

The `signing_domain` is already computed from the broker allocation (`{offset_hex}.{dns_zone}`). Just pass it through as `VM_FQDN`. Fall back to `{vm_name}.local` when no broker allocation exists.
