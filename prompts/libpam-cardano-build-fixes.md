# libpam-web3-cardano: Build Script Permission Fix

In `plugins/cardano/packaging/build-deb.sh`, the blanket permission reset on line 151 clobbers the `DEBIAN/prerm` script permissions:

```bash
find "$PKG_DIR" -type f -exec chmod 644 {} \;
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 755 "$PKG_DIR/usr/lib/libpam-web3/plugins/cardano"
chmod 755 "$PKG_DIR/usr/bin/web3-auth-svc-cardano"
```

`prerm` is missing from the restore list. dpkg requires maintainer scripts to be `>=0555`. Add it after the postinst line:

```bash
chmod 755 "$PKG_DIR/DEBIAN/prerm"
```
