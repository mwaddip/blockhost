# Proxmox Provisioner: Install all template packages in VM template

Same issue as the libvirt provisioner. `scripts/build-template.sh` only looks for `libpam-web3_*.deb` (line 23) and the dead `blockhost-auth-svc_*.deb` (line 35). Chain-specific PAM plugins (`libpam-web3-cardano_*.deb`, `libpam-web3-opnet_*.deb`, etc.) are in `/var/lib/blockhost/template-packages/` but never get installed into the Proxmox VM template.

## Fix

Replace the individual package lookups with a glob that installs ALL `.deb` files from the template packages directory:

```bash
# --- Locate ALL template packages ---
TEMPLATE_DEBS=()
for deb in /var/lib/blockhost/template-packages/*.deb; do
    [ -f "$deb" ] || continue
    TEMPLATE_DEBS+=("$deb")
    echo "Found template package: $(basename "$deb")"
done

if [ ${#TEMPLATE_DEBS[@]} -eq 0 ]; then
    echo "Error: No template packages found in /var/lib/blockhost/template-packages/"
    exit 1
fi
```

Then in the `virt-customize` call, copy all of them and install together:

```bash
# Copy all debs into the VM
for deb in "${TEMPLATE_DEBS[@]}"; do
    CUSTOMIZE_ARGS+=(--copy-in "$deb:/tmp/")
done

# Install all at once
DEB_NAMES=$(printf "/tmp/%s " "${TEMPLATE_DEBS[@]##*/}")
CUSTOMIZE_ARGS+=(--run-command "dpkg -i $DEB_NAMES || apt-get install -f -y")
```

## Also remove

- The `blockhost-auth-svc_*.deb` lookup (line 35) — dead code, package moved to libpam plugins
- The `$HOME/projects/libpam-web3/packaging/libpam-web3_0.2.0_amd64.deb` fallback (line 26) — development path, not for production
