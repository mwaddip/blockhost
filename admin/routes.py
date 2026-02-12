"""Admin panel routes — API endpoints and page routes."""

from flask import (
    Blueprint, abort, jsonify, render_template, redirect, request,
    send_file, session, url_for,
)

from . import system
from .auth import (
    create_session, generate_challenge, get_admin_wallet, get_hostname,
    invalidate_session, login_required, validate_session, verify_signature,
)

bp = Blueprint("admin", __name__)

SIGNING_PAGE_PATH = "/usr/share/libpam-web3-tools/signing-page/index.html"


# --- Auth routes ---

@bp.route("/login")
def login():
    # Already authenticated? Go to dashboard.
    token = session.get("auth_token")
    if validate_session(token):
        return redirect(url_for("admin.dashboard"))
    code = generate_challenge()
    return render_template("login.html", code=code, hostname=get_hostname())


@bp.route("/sign")
def sign():
    try:
        return send_file(SIGNING_PAGE_PATH)
    except FileNotFoundError:
        abort(404, "Signing page not installed")


@bp.route("/api/auth/verify", methods=["POST"])
def api_auth_verify():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "missing JSON body"}), 400

    code = data.get("code", "").strip()
    signature = data.get("signature", "").strip()

    if not code or not signature:
        return jsonify({"ok": False, "error": "code and signature required"}), 400

    ok, result = verify_signature(code, signature)
    if not ok:
        return jsonify({"ok": False, "error": result}), 401

    token = create_session(result)
    session["auth_token"] = token
    session.permanent = True
    return jsonify({"ok": True})


@bp.route("/logout")
def logout():
    token = session.pop("auth_token", None)
    if token:
        invalidate_session(token)
    return redirect(url_for("admin.login"))


# --- Dashboard page ---

@bp.route("/")
@login_required
def dashboard():
    wallet = get_admin_wallet() or ""
    short_wallet = wallet[:6] + "..." + wallet[-4:] if len(wallet) > 10 else wallet
    return render_template("dashboard.html", wallet=short_wallet)


# --- System API ---

@bp.route("/api/system")
@login_required
def api_system():
    return jsonify(system.get_system_info())


@bp.route("/api/system/hostname", methods=["POST"])
@login_required
def api_set_hostname():
    data = request.get_json(silent=True)
    if not data or "hostname" not in data:
        return jsonify({"ok": False, "error": "missing hostname"}), 400
    ok, err = system.set_hostname(data["hostname"])
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify({"ok": True})


# --- Network API ---

@bp.route("/api/network")
@login_required
def api_network():
    return jsonify(system.get_network_info())


@bp.route("/api/network/broker/renew", methods=["POST"])
@login_required
def api_broker_renew():
    ok, err = system.renew_broker_lease()
    if not ok:
        return jsonify({"ok": False, "error": err}), 500
    return jsonify({"ok": True})


# --- Security API ---

@bp.route("/api/security")
@login_required
def api_security():
    data = system.get_security_info()
    if data is None:
        return jsonify({"ok": False, "error": "cannot read admin-commands.json"}), 500
    return jsonify(data)


@bp.route("/api/security", methods=["POST"])
@login_required
def api_update_security():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "missing JSON body"}), 400
    ok, err = system.update_security_settings(data)
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify({"ok": True})


# --- Storage API ---

@bp.route("/api/storage")
@login_required
def api_storage():
    return jsonify(system.get_storage_info())


# --- VM API ---

@bp.route("/api/vms")
@login_required
def api_vms():
    return jsonify(system.get_vms())


@bp.route("/api/vms/<name>/start", methods=["POST"])
@login_required
def api_vm_start(name):
    ok, err = system.vm_action(name, "start")
    if not ok:
        return jsonify({"ok": False, "error": err}), 500
    return jsonify({"ok": True})


@bp.route("/api/vms/<name>/stop", methods=["POST"])
@login_required
def api_vm_stop(name):
    ok, err = system.vm_action(name, "stop")
    if not ok:
        return jsonify({"ok": False, "error": err}), 500
    return jsonify({"ok": True})


@bp.route("/api/vms/<name>/kill", methods=["POST"])
@login_required
def api_vm_kill(name):
    ok, err = system.vm_action(name, "kill")
    if not ok:
        return jsonify({"ok": False, "error": err}), 500
    return jsonify({"ok": True})


@bp.route("/api/vms/<name>/destroy", methods=["POST"])
@login_required
def api_vm_destroy(name):
    ok, err = system.vm_action(name, "destroy")
    if not ok:
        return jsonify({"ok": False, "error": err}), 500
    return jsonify({"ok": True})


# --- Wallet API ---

@bp.route("/api/wallet")
@login_required
def api_wallet():
    data = system.get_wallet_info()
    if data is None:
        return jsonify({"ok": False, "error": "cannot read addressbook"}), 500
    return jsonify(data)


@bp.route("/api/wallet/balance/<role>")
@login_required
def api_wallet_balance(role):
    out, err = system.get_wallet_balances(role)
    if err:
        return jsonify({"ok": False, "error": err}), 500
    return jsonify({"ok": True, "output": out})


@bp.route("/api/wallet/send", methods=["POST"])
@login_required
def api_wallet_send():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "missing JSON body"}), 400
    ok, out, err = system.wallet_send(
        data.get("amount"), data.get("token"),
        data.get("from"), data.get("to"),
    )
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify({"ok": True, "output": out})


@bp.route("/api/wallet/withdraw", methods=["POST"])
@login_required
def api_wallet_withdraw():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "missing JSON body"}), 400
    ok, out, err = system.wallet_withdraw(
        data.get("to"), data.get("token"),
    )
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify({"ok": True, "output": out})


# --- Addressbook API ---

@bp.route("/api/addressbook/add", methods=["POST"])
@login_required
def api_addressbook_add():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "missing JSON body"}), 400
    ok, out, err = system.addressbook_add(
        data.get("name"), data.get("address"),
    )
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify({"ok": True, "output": out})


@bp.route("/api/addressbook/remove", methods=["POST"])
@login_required
def api_addressbook_remove():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "missing JSON body"}), 400
    ok, out, err = system.addressbook_remove(data.get("name"))
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify({"ok": True, "output": out})


@bp.route("/api/addressbook/generate", methods=["POST"])
@login_required
def api_addressbook_generate():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "missing JSON body"}), 400
    ok, out, err = system.addressbook_generate(data.get("name"))
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify({"ok": True, "output": out})
