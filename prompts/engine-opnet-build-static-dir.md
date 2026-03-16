# OPNet Engine: Fix build.sh after static/ directory removal

## Context

Commit 0071e9d deleted `blockhost/engine_opnet/static/topup.js`, which was the only file in the `static/` directory. Git doesn't track empty directories, so the `static/` dir no longer exists. The build script (`packaging/build.sh`) unconditionally copies from it and fails:

```
cp: cannot stat '.../blockhost/engine_opnet/static/*': No such file or directory
```

## Fix in `packaging/build.sh`

Lines 348 and 352 unconditionally create and copy the static directory. Guard both with an existence check:

**Before:**
```bash
mkdir -p "$WIZARD_DST/static"
cp "$WIZARD_SRC/__init__.py" "$WIZARD_DST/"
cp "$WIZARD_SRC/wizard.py" "$WIZARD_DST/"
cp "$WIZARD_SRC/templates/engine_opnet/"*.html "$WIZARD_DST/templates/engine_opnet/"
cp "$WIZARD_SRC/static/"* "$WIZARD_DST/static/"
```

**After:**
```bash
cp "$WIZARD_SRC/__init__.py" "$WIZARD_DST/"
cp "$WIZARD_SRC/wizard.py" "$WIZARD_DST/"
cp "$WIZARD_SRC/templates/engine_opnet/"*.html "$WIZARD_DST/templates/engine_opnet/"
if [ -d "$WIZARD_SRC/static" ] && ls "$WIZARD_SRC/static/"* &>/dev/null; then
    mkdir -p "$WIZARD_DST/static"
    cp "$WIZARD_SRC/static/"* "$WIZARD_DST/static/"
fi
```

This way the build succeeds whether or not the static directory exists or has files in it.
