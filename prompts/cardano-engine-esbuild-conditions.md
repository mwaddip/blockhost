# Cardano Engine: Fix libsodium — use --conditions=require

`--main-fields=main,module` isn't enough — esbuild checks the `exports` field in package.json first, which maps `import` to the broken ESM entry. The `exports` field takes precedence over `main`/`module`.

Replace `--main-fields=main,module` with `--conditions=require` in all 7 esbuild calls in `packaging/build.sh`. This tells esbuild to use the `require` condition from the `exports` map, which resolves to the working CJS entry point.

Tested locally — builds clean with this flag.
