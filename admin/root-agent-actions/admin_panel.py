"""Root agent actions for admin panel management.

Handles operations that require root: nginx config updates, service restarts.
"""

import re
import subprocess
from pathlib import Path

NGINX_CONF = Path("/etc/nginx/sites-available/blockhost")


def update_admin_path(params):
    """Update nginx reverse proxy location for the admin panel, then restart."""
    new_path = params.get("path_prefix", "").strip()
    if not new_path:
        return {"ok": False, "error": "path_prefix required"}

    # Normalize
    new_path = "/" + new_path.strip("/")

    if not re.match(r"^/[a-z0-9][a-z0-9/-]{0,62}[a-z0-9]$", new_path):
        return {"ok": False, "error": "invalid path"}

    if "//" in new_path:
        return {"ok": False, "error": "consecutive slashes not allowed"}

    # Read current nginx config
    try:
        original = NGINX_CONF.read_text()
    except OSError as e:
        return {"ok": False, "error": f"cannot read nginx config: {e}"}

    # Replace the admin location block path.
    # Match: "location /something {" followed by "proxy_pass http://127.0.0.1:8443/;"
    # This uniquely identifies the admin block (signup page uses "location / {" with try_files).
    updated, count = re.subn(
        r"(location\s+)/[a-zA-Z0-9/_-]+(\s*\{\s*\n\s*proxy_pass\s+http://127\.0\.0\.1:8443/;)",
        rf"\g<1>{new_path}\2",
        original,
    )

    if count == 0:
        return {"ok": False, "error": "admin location block not found in nginx config"}

    # Write and test
    try:
        NGINX_CONF.write_text(updated)
    except OSError as e:
        return {"ok": False, "error": f"cannot write nginx config: {e}"}

    r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if r.returncode != 0:
        NGINX_CONF.write_text(original)
        return {"ok": False, "error": f"nginx test failed, rolled back: {r.stderr}"}

    # Reload nginx (picks up new location immediately)
    r = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
    if r.returncode != 0:
        NGINX_CONF.write_text(original)
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)
        return {"ok": False, "error": f"nginx reload failed, rolled back: {r.stderr}"}

    # Schedule admin restart in 3s (service reads admin.json on start for new prefix)
    subprocess.Popen(
        ["systemd-run", "--on-active=3s", "--unit=blockhost-admin-path-restart",
         "systemctl", "restart", "blockhost-admin"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    return {"ok": True}


ACTIONS = {
    "admin-path-update": update_admin_path,
}
