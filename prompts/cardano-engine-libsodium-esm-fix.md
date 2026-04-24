# Cardano Engine: Fix libsodium-wrappers-sumo ESM resolution

The `libsodium-wrappers-sumo` package has a broken ESM distribution — `dist/modules-sumo-esm/libsodium-wrappers.mjs` imports `./libsodium-sumo.mjs` but that file doesn't exist in the package. The CJS entry (`dist/modules-sumo/libsodium-wrappers.js`) works fine.

Since the engine runs as ESM (`"type": "module"` in package.json), Node.js/tsx picks the `import` export condition and hits the broken path.

Fix: after `npm install` in the build script, patch the `libsodium-wrappers-sumo` package.json to remove the ESM export, forcing Node.js to use CJS:

Add this after the npm install lines in `packaging/build.sh`:

```bash
# Patch libsodium-wrappers-sumo: remove broken ESM export
# The ESM dist is missing libsodium-sumo.mjs — force CJS fallback
LIBSODIUM_PKG="$PKG_DIR/usr/share/blockhost/node_modules/libsodium-wrappers-sumo/package.json"
if [ -f "$LIBSODIUM_PKG" ]; then
    python3 -c "
import json, sys
p = json.load(open(sys.argv[1]))
if 'exports' in p and '.' in p['exports']:
    p['exports']['.'].pop('import', None)
    p['exports']['.'].pop('module', None)
json.dump(p, open(sys.argv[1], 'w'), indent=2)
print('  Patched libsodium-wrappers-sumo: removed ESM export')
" "$LIBSODIUM_PKG"
fi
```

This removes the `import` and `module` conditions from the exports map, leaving only `require` and `default` — both point to the working CJS entry.

Also check for nested copies (hoisted differently):
```bash
# Same patch for any nested copies
find "$PKG_DIR/usr/share/blockhost/node_modules" -path "*/libsodium-wrappers-sumo/package.json" | while read pkg; do
    python3 -c "
import json, sys
p = json.load(open(sys.argv[1]))
if 'exports' in p and '.' in p['exports']:
    p['exports']['.'].pop('import', None)
    p['exports']['.'].pop('module', None)
json.dump(p, open(sys.argv[1], 'w'), indent=2)
" "$pkg"
done
```
