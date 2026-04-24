# Proxmox Provisioner: Pass VM_FQDN to cloud-init template

Same issue as the libvirt provisioner. The common cloud-init template has `fqdn: ${VM_FQDN}` and `manage_etc_hosts: true`, but `scripts/vm-generator.py` doesn't pass `VM_FQDN` when rendering cloud-init.

## Fix

In `scripts/vm-generator.py`, around the `signing_domain` computation (line ~414), add `VM_FQDN` to the cloud-init template variables:

```python
"VM_FQDN": signing_domain if signing_domain else f"{vm_name}.local",
```

The `signing_domain` is already computed from the broker allocation. Just pass it through.
