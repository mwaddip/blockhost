# Libvirt Provisioner: Install all template packages in VM template

`scripts/build-template.sh` only looks for `libpam-web3_*.deb` and the dead `blockhost-auth-svc_*.deb`. Chain-specific PAM plugins (`libpam-web3-cardano_*.deb`, `libpam-web3-opnet_*.deb`, etc.) are in `/var/lib/blockhost/template-packages/` but never get installed into the VM template. Without the plugin, the PAM module can't verify signatures for that chain — SSH login gets permission denied.

## Fix

Replace the individual package lookups with a glob that installs ALL `.deb` files from the template packages directory. In `scripts/build-template.sh`:

Replace the `libpam-web3_*.deb` and `blockhost-auth-svc_*.deb` lookup logic (lines ~90-96 in your version) with:

```bash
# --- Locate ALL template packages ---
TEMPLATE_DEBS=()
for deb in "$LIBPAM_DEB_DIR"/*.deb; do
    [ -f "$deb" ] || continue
    TEMPLATE_DEBS+=("$deb")
    log "Found template package: $(basename "$deb")"
done

if [ ${#TEMPLATE_DEBS[@]} -eq 0 ]; then
    die "No template packages found in $LIBPAM_DEB_DIR"
fi
```

Then in the `virt-customize` call, copy all of them into the VM and install them together:

```bash
# Copy all debs into the VM
for deb in "${TEMPLATE_DEBS[@]}"; do
    CUSTOMIZE_ARGS+=(--copy-in "$deb:/tmp/")
done

# Install all at once (dpkg handles dependency order)
DEB_NAMES=$(printf "/tmp/%s " "${TEMPLATE_DEBS[@]##*/}")
CUSTOMIZE_ARGS+=(--run-command "dpkg -i $DEB_NAMES || apt-get install -f -y")
```

## Also remove

- The `blockhost-auth-svc_*.deb` lookup — dead code, that package moved to libpam plugins
- The hardcoded `libpam-web3_*.deb` fallback to `$HOME/projects/...` — development path that doesn't belong in production
