# EVM Engine: Virtual Package Conflict + Facts Update

## 1. Virtual package conflict

Only one engine can be active per host. Instead of listing every engine by name in `Conflicts:`, use the Debian virtual package pattern.

In `packaging/build.sh`, find the `DEBIAN/control` heredoc. Change:

```
Provides: bhcrypt
```

To:

```
Provides: bhcrypt, blockhost-engine
Conflicts: blockhost-engine
```

A package never conflicts with itself through a virtual package — this won't block its own install, but prevents any other `blockhost-engine-*` package that also `Provides: blockhost-engine` from coexisting. No need to enumerate engine names.

## 2. Update facts submodule

The `ENGINE_INTERFACE.md` and `PROVISIONER_INTERFACE.md` have been updated to document the virtual package pattern.

```bash
cd facts && git fetch origin main && git checkout origin/main && cd ..
git add facts
```

Include the facts update in your commit.
