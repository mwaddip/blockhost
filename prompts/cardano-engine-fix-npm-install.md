# Cardano Engine: Remove --no-optional from npm install

In `packaging/build.sh` line 32, the `--no-optional` flag skips esbuild's platform-specific binary (`@esbuild/linux-x64`). tsx depends on esbuild for TypeScript transpilation at runtime.

Change:
```bash
(cd "$PKG_DIR/usr/share/blockhost" && npm install --production --ignore-scripts --no-optional --silent)
```

To:
```bash
(cd "$PKG_DIR/usr/share/blockhost" && npm install --production --ignore-scripts --silent)
```
