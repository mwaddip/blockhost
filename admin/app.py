"""BlockHost Admin Panel — Flask application."""

import argparse
import os
from datetime import timedelta

from flask import Flask


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

    from .routes import bp
    app.register_blueprint(bp)

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
