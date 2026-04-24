# Libvirt Provisioner: Virtual Package Conflict + Facts Update

## 1. Virtual package conflict

Only one provisioner can be active per host. Instead of listing every provisioner by name in `Conflicts:`, use the Debian virtual package pattern.

In `build-deb.sh`, find the `DEBIAN/control` section. Change:

```
Conflicts: blockhost-provisioner-proxmox
```

To:

```
Provides: blockhost-provisioner
Conflicts: blockhost-provisioner
```

A package never conflicts with itself through a virtual package — this won't block its own install, but prevents any other `blockhost-provisioner-*` package that also `Provides: blockhost-provisioner` from coexisting. Scales to any number of provisioners without updating each control file.

## 2. Update facts submodule

The `PROVISIONER_INTERFACE.md` has been updated to document the virtual package pattern (replaces the old explicit `Conflicts:` example).

```bash
cd facts && git fetch origin main && git checkout origin/main && cd ..
git add facts
```

Include the facts update in your commit.
