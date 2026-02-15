"""BlockHost Admin Panel — Flask application."""

import argparse
import importlib
import json
import logging
import os
from datetime import timedelta
from pathlib import Path

from flask import Flask, redirect, session

ADMIN_CONFIG_PATH = "/etc/blockhost/admin.json"
PROVISIONER_MANIFEST_PATH = "/usr/share/blockhost/provisioner.json"
ENGINE_MANIFEST_PATH = "/usr/share/blockhost/engine.json"
DEFAULT_PATH_PREFIX = "/admin"

log = logging.getLogger(__name__)

BUILTIN_PAGES = [
    {"id": "system",  "path": "/",        "label": "System & Storage",    "icon": "&#9881;"},
    {"id": "network", "path": "/network",  "label": "Network & Security",  "icon": "&#9919;"},
    {"id": "wallet",  "path": "/wallet",   "label": "Wallet",              "icon": "&#9710;"},
    {"id": "vms",     "path": "/vms",      "label": "VMs & Accounts",      "icon": "&#128421;"},
]


def _load_path_prefix():
    """Read panel path prefix from /etc/blockhost/admin.json."""
    try:
        cfg = json.loads(Path(ADMIN_CONFIG_PATH).read_text())
        prefix = cfg.get("path_prefix", DEFAULT_PATH_PREFIX)
        # Normalize: must start with /, must not end with /
        prefix = "/" + prefix.strip("/")
        return prefix
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return DEFAULT_PATH_PREFIX


def _load_engine_ui():
    """Load engine display hints from manifest for templates."""
    try:
        manifest = json.loads(Path(ENGINE_MANIFEST_PATH).read_text())
        constraints = manifest.get('constraints', {})
        return {
            'native_token': constraints.get('native_token', ''),
            'native_token_label': constraints.get('native_token_label', 'Native'),
            'address_placeholder': constraints.get('address_placeholder', ''),
        }
    except (OSError, json.JSONDecodeError):
        return {'native_token': '', 'native_token_label': 'Native', 'address_placeholder': ''}


def _load_provisioner_admin():
    """Discover provisioner admin plugin from manifest. Returns (blueprint, pages) or (None, [])."""
    try:
        manifest = json.loads(Path(PROVISIONER_MANIFEST_PATH).read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None, []

    module_path = manifest.get("admin", {}).get("module")
    if not module_path:
        return None, []

    try:
        module = importlib.import_module(module_path)
        blueprint = getattr(module, "blueprint", None)
        pages = getattr(module, "PAGES", [])
        if blueprint is None:
            log.warning("Admin plugin %s has no blueprint export", module_path)
            return None, []
        log.info("Loaded admin plugin: %s (%d pages)", module_path, len(pages))
        return blueprint, pages
    except Exception as e:
        log.warning("Failed to load admin plugin %s: %s", module_path, e)
        return None, []


def create_app():
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.secret_key = os.urandom(32)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)
    app.config["PATH_PREFIX"] = _load_path_prefix()

    from .routes import bp
    app.register_blueprint(bp)

    # Discover provisioner admin plugin
    nav_pages = list(BUILTIN_PAGES)
    prov_bp, prov_pages = _load_provisioner_admin()
    if prov_bp is not None:
        # Auth enforcement — plugin routes don't need @login_required
        from .auth import validate_session

        @prov_bp.before_request
        def _require_login():
            token = session.get("auth_token")
            if not validate_session(token):
                return redirect(app.config["PATH_PREFIX"] + "/login")

        app.register_blueprint(prov_bp)
        nav_pages.extend(prov_pages)

    engine_ui = _load_engine_ui()

    @app.context_processor
    def inject_globals():
        return {
            "admin_prefix": app.config["PATH_PREFIX"],
            "nav_pages": nav_pages,
            "engine_ui": engine_ui,
        }

    return app


def main():
    parser = argparse.ArgumentParser(description="BlockHost Admin Panel")
    parser.add_argument("--port", type=int, default=8443, help="Port to listen on")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    app = create_app()
    if args.debug:
        app.config["SESSION_COOKIE_SECURE"] = False
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
