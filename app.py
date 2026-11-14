import json
import os
import re
import secrets
import sqlite3
import subprocess
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path

import psutil
from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

from xray_profiles import build_vless_uri, build_vmess_uri

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,30}\$?$")
HELPER = "/usr/local/sbin/iyke-vps-helper"


class Admin(UserMixin):
    def __init__(self, row):
        self.id = str(row["id"])
        self.username = row["username"]


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("IYKE_SECRET_KEY", ""),
        DATABASE=os.environ.get("IYKE_DATABASE", "/var/lib/iyke-vps-manager/manager.sqlite3"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("IYKE_COOKIE_SECURE", "0") == "1",
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SECURE=os.environ.get("IYKE_COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=16 * 1024,
        HELPER=HELPER,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("IYKE_SECRET_KEY must be set to a long random secret")

    csrf = CSRFProtect(app)
    login_manager = LoginManager(app)
    login_manager.login_view = "login"
    limiter = Limiter(get_remote_address, app=app, default_limits=["300 per day", "60 per hour"],
                      storage_uri="memory://")

    def connect_db():
        Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(app.config["DATABASE"], timeout=10)
        db.row_factory = sqlite3.Row
        return db

    @contextmanager
    def db_session():
        db = connect_db()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def init_db():
        with db_session() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            bootstrap_user = os.environ.get("IYKE_BOOTSTRAP_ADMIN", "").strip()
            bootstrap_password = os.environ.get("IYKE_BOOTSTRAP_PASSWORD", "")
            if bootstrap_user and bootstrap_password and db.execute(
                "SELECT 1 FROM admins WHERE username=?", (bootstrap_user,)
            ).fetchone() is None:
                if len(bootstrap_password) < 16:
                    raise RuntimeError("Bootstrap password must be at least 16 characters")
                db.execute("INSERT OR IGNORE INTO admins(username,password_hash,created_at) VALUES(?,?,?)",
                           (bootstrap_user, generate_password_hash(bootstrap_password),
                            datetime.utcnow().isoformat(timespec="seconds")))

    init_db()

    @login_manager.user_loader
    def load_user(admin_id):
        with db_session() as db:
            row = db.execute("SELECT id,username FROM admins WHERE id=?", (admin_id,)).fetchone()
        return Admin(row) if row else None

    def audit(action, detail):
        with db_session() as db:
            db.execute("INSERT INTO audit(admin,action,detail,created_at) VALUES(?,?,?,?)",
                       (current_user.username if current_user.is_authenticated else "system",
                        action, detail[:240], datetime.utcnow().isoformat(timespec="seconds")))

    def run_helper(action, timeout=30, **payload):
        # The privileged executable receives a single strict JSON request on stdin.
        # No user-controlled arguments are ever passed through sudo's command line.
        request_data = {"action": action, **payload}
        try:
            result = subprocess.run(
                ["sudo", "-n", app.config["HELPER"]],
                input=json.dumps(request_data, separators=(",", ":")),
                text=True, capture_output=True, timeout=timeout, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("Privileged helper unavailable or timed out") from exc
        if result.returncode != 0:
            message = result.stderr.strip() or "The server operation failed"
            raise RuntimeError(message[:200])
        return result.stdout.strip()

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        )
        return response

    @app.get("/health")
    def health():
        return jsonify(status="ok", service="iyke-vps-manager")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute")
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            with db_session() as db:
                row = db.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
            if row and check_password_hash(row["password_hash"], password):
                login_user(Admin(row), remember=False, fresh=True)
                audit("login", "Successful administrator login")
                return redirect(url_for("dashboard"))
            flash("Incorrect username or password.", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        audit("logout", "Administrator logged out")
        logout_user()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def dashboard():
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        try:
            uptime = int(datetime.now().timestamp() - psutil.boot_time())
        except (OSError, ValueError):
            uptime = 0
        return render_template("dashboard.html", cpu=psutil.cpu_percent(interval=0.15),
            memory=vm.percent, memory_used=vm.used, memory_total=vm.total,
            disk=disk.percent, disk_used=disk.used, disk_total=disk.total,
            uptime=uptime, audit_rows=recent_audit())

    def recent_audit():
        with db_session() as db:
            return db.execute("SELECT admin,action,detail,created_at FROM audit "
                              "ORDER BY id DESC LIMIT 8").fetchall()

    @app.route("/settings/password", methods=["GET", "POST"])
    @login_required
    def password_settings():
        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            with db_session() as db:
                row = db.execute("SELECT password_hash FROM admins WHERE id=?",
                                 (current_user.id,)).fetchone()
                if not row or not check_password_hash(row["password_hash"], current_password):
                    flash("Current password is incorrect.", "error")
                elif len(new_password) < 16:
                    flash("New password must be at least 16 characters.", "error")
                elif new_password != confirm_password:
                    flash("New passwords do not match.", "error")
                else:
                    db.execute("UPDATE admins SET password_hash=? WHERE id=?",
                               (generate_password_hash(new_password), current_user.id))
                    db.execute("INSERT INTO audit(admin,action,detail,created_at) VALUES(?,?,?,?)",
                               (current_user.username, "password_changed",
                                "Administrator password changed",
                                datetime.utcnow().isoformat(timespec="seconds")))
                    flash("Administrator password updated.", "success")
                    return redirect(url_for("password_settings"))
        return render_template("password.html")

    @app.get("/users")
    @login_required
    def users():
        try:
            rows = json.loads(run_helper("list") or "[]")
        except (RuntimeError, json.JSONDecodeError) as exc:
            rows = []
            flash(str(exc), "error")
        return render_template("users.html", users=rows, today=date.today().isoformat())

    @app.post("/users/create")
    @login_required
    def create_user():
        username = request.form.get("username", "").strip().lower()
        expiry = request.form.get("expiry", "")
        if not USERNAME_RE.fullmatch(username) or username in {"root", "nobody"}:
            flash("Choose a valid, non-system Linux username.", "error")
            return redirect(url_for("users"))
        try:
            expiry_date = date.fromisoformat(expiry)
            if expiry_date <= date.today():
                raise ValueError
        except ValueError:
            flash("Expiry must be a future date.", "error")
            return redirect(url_for("users"))
        temporary_password = secrets.token_urlsafe(18)
        try:
            run_helper("create", username=username, expiry=expiry, password=temporary_password)
            audit("ssh_user_created", f"Created Linux account {username}; expiry {expiry}")
            return render_template("created.html", username=username, password=temporary_password,
                                   expiry=expiry)
        except RuntimeError as exc:
            flash(str(exc), "error")
            return redirect(url_for("users"))

    @app.post("/users/<username>/expiry")
    @login_required
    def update_expiry(username):
        if not USERNAME_RE.fullmatch(username) or username in {"root", "nobody"}:
            abort(400)
        expiry = request.form.get("expiry", "")
        try:
            expiry_date = date.fromisoformat(expiry)
            if expiry_date <= date.today():
                raise ValueError
            run_helper("expire", username=username, expiry=expiry)
            audit("ssh_user_expiry_changed", f"Changed expiry for {username} to {expiry}")
            flash(f"Expiry updated for {username}.", "success")
        except (ValueError, RuntimeError) as exc:
            flash(str(exc) or "Expiry must be a future date.", "error")
        return redirect(url_for("users"))

    @app.post("/users/<username>/delete")
    @login_required
    def delete_user(username):
        if not USERNAME_RE.fullmatch(username) or username in {"root", "nobody"}:
            abort(400)
        try:
            run_helper("delete", username=username)
            audit("ssh_user_deleted", f"Deleted Linux account {username}")
            flash(f"Account {username} deleted.", "success")
        except RuntimeError as exc:
            flash(str(exc), "error")
        return redirect(url_for("users"))

    @app.get("/vpn")
    @login_required
    def vpn_services():
        try:
            status = json.loads(run_helper("vpn_status") or "{}")
        except (RuntimeError, json.JSONDecodeError) as exc:
            status = {"wireguard": {"installed": False, "interfaces": []},
                      "openvpn": {"installed": False, "instances": []},
                      "xray": {"installed": False, "service": "not-installed"},
                      "hysteria": {"installed": False, "service": "not-installed"}}
            flash(str(exc), "error")
        # Older helper responses and test doubles may omit newer Xray metadata.
        xray_status = status.setdefault(
            "xray", {"installed": False, "service": "not-installed"}
        )
        xray_status.setdefault("config_status", "unavailable")
        xray_status.setdefault("inbounds", [])
        status.setdefault("hysteria", {"installed": False, "service": "not-installed"})
        status["hysteria"].setdefault("config_status", "missing")
        peers = []
        xray_clients = []
        if status.get("xray", {}).get("installed"):
            try:
                xray_clients = json.loads(run_helper("xray_clients") or "[]")
                if not isinstance(xray_clients, list):
                    xray_clients = []
            except (RuntimeError, json.JSONDecodeError) as exc:
                flash(str(exc), "error")
        public_endpoint = ""
        try:
            endpoint_info = json.loads(run_helper("wireguard_public_endpoint") or "{}")
            public_endpoint = endpoint_info.get("endpoint", "")
            if not isinstance(public_endpoint, str):
                public_endpoint = ""
        except (RuntimeError, json.JSONDecodeError):
            # Manual endpoint entry remains available if public-IP discovery is unavailable.
            pass
        if status.get("wireguard", {}).get("installed"):
            try:
                peers = json.loads(run_helper("wireguard_peers") or "[]")
                if not isinstance(peers, list):
                    peers = []
            except (RuntimeError, json.JSONDecodeError) as exc:
                flash(str(exc), "error")
        openvpn_inventory = {"available": False, "reason": "OpenVPN is not installed", "clients": []}
        if status.get("openvpn", {}).get("installed"):
            try:
                openvpn_inventory = json.loads(run_helper("openvpn_clients") or "{}")
                if not isinstance(openvpn_inventory, dict):
                    openvpn_inventory = {"available": False, "reason": "Invalid inventory response", "clients": []}
            except (RuntimeError, json.JSONDecodeError) as exc:
                openvpn_inventory = {"available": False, "reason": str(exc), "clients": []}
        return render_template("vpn.html", vpn=status, peers=peers,
                               xray_clients=xray_clients,
                               public_endpoint=public_endpoint,
                               openvpn_inventory=openvpn_inventory)



    @app.post("/vpn/xray/install")
    @login_required
    def install_xray():
        try:
            result = json.loads(run_helper("xray_install", timeout=330) or "{}")
            audit("xray_installed", "Installed Xray-core using the pinned official installer")
            flash("Xray-core is installed. No VLESS/VMess listeners or firewall rules were configured.", "success")
            flash(f"Xray service state: {result.get('service', 'unknown')}", "success")
        except (RuntimeError, json.JSONDecodeError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("vpn_services"))

    @app.post("/vpn/hysteria/validate")
    @login_required
    def validate_hysteria():
        domain = request.form.get("domain", "")
        ports = request.form.get("ports", "")
        try:
            result = json.loads(run_helper(
                "hysteria_validate", domain=domain, ports=ports
            ) or "{}")
            if result.get("valid") is not True or result.get("service_changed") is not False:
                raise RuntimeError("Hysteria configuration validation could not be verified")
            audit(
                "hysteria_config_validated",
                f"Validated domain {result['domain']} and UDP ports "
                + ", ".join(str(port) for port in result["udp_ports"]),
            )
            flash(
                "Input check passed for " + result["domain"] + " on UDP "
                + ", ".join(str(port) for port in result["udp_ports"])
                + ". DNS, port availability and TLS have not been checked; "
                  "nothing was applied.",
                "success",
            )
        except (RuntimeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("vpn_services"))

    @app.post("/vpn/hysteria/install")
    @login_required
    def install_hysteria():
        try:
            result = json.loads(run_helper("hysteria_install", timeout=330) or "{}")
            if result.get("installed") is not True or result.get("service_started") is not False:
                raise RuntimeError("Hysteria 2 installation could not be verified")
            audit("hysteria_installed", "Installed Hysteria 2 using the pinned official installer")
            flash(
                "Hysteria 2 is installed. Its example configuration is not ready for client connections; "
                "configure a domain, TLS certificate and authentication before starting the service. "
                "No firewall rules or listeners were changed.",
                "success",
            )
        except (RuntimeError, json.JSONDecodeError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("vpn_services"))

    @app.post("/vpn/xray/clients")
    @login_required
    def create_xray_client():
        name = request.form.get("name", "").strip().lower()
        protocol = request.form.get("protocol", "").strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) or name in {"root", "server", "ca"}:
            flash("Use a client name with lowercase letters, numbers, hyphens or underscores.", "error")
            return redirect(url_for("vpn_services"))
        if protocol not in {"vmess", "vless"}:
            abort(400)
        try:
            result = json.loads(run_helper("xray_create_client", timeout=150, name=name, protocol=protocol) or "{}")
            if result.get("created") is not True or result.get("name") != name or result.get("protocol") != protocol:
                raise RuntimeError("Xray client creation could not be verified")
            audit("xray_client_created", f"Created Xray {protocol.upper()} client {name}")
            flash(f"Xray {protocol.upper()} client {name} created and activated. Download its profile or open its QR code from the Xray client list.", "success")
        except (RuntimeError, json.JSONDecodeError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("vpn_services"))

    def xray_profile_uris(name):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) or name in {"root", "server", "ca"}:
            abort(404)
        try:
            data = json.loads(run_helper("xray_get_profile", name=name) or "{}")
            if (data.get("name") != name or data.get("protocol") not in {"vmess", "vless"}
                    or not isinstance(data.get("id"), str)
                    or not isinstance(data.get("hostname"), str)
                    or not isinstance(data.get("path"), str) or data.get("port") != 443):
                raise RuntimeError("Xray profile data could not be verified")
            builder = build_vmess_uri if data["protocol"] == "vmess" else build_vless_uri
            return [
                (443, builder(data["id"], data["hostname"], data["path"], name, port=443)),
                (80, builder(data["id"], data["hostname"], data["path"], name, port=80)),
            ], data["protocol"]
        except (RuntimeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            abort(404, description="Xray client profile is unavailable")

    def xray_profile_uri(name):
        profiles, protocol = xray_profile_uris(name)
        return profiles[0][1], protocol

    @app.get("/vpn/xray/clients/<name>/profile")
    @login_required
    def download_xray_profile(name):
        profiles, protocol = xray_profile_uris(name)
        content = "\n".join(
            f"# {protocol.upper()} WebSocket port {port} ({'TLS' if port == 443 else 'plain HTTP'})\n{uri}"
            for port, uri in profiles
        ) + "\n"
        response = Response(content, mimetype="text/plain; charset=utf-8")
        response.headers["Content-Disposition"] = f'attachment; filename="{name}-{protocol}-80-443.txt"'
        response.headers["Cache-Control"] = "no-store, private, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    @app.get("/vpn/xray/clients/<name>/qr")
    @login_required
    def xray_profile_qr(name):
        try:
            import io
            import qrcode
            from qrcode.image.svg import SvgPathImage
            profile, _ = xray_profile_uri(name)
            image = qrcode.make(profile, image_factory=SvgPathImage, border=4)
            output = io.BytesIO()
            image.save(output)
            response = Response(output.getvalue(), mimetype="image/svg+xml")
            response.headers["Cache-Control"] = "no-store, private, max-age=0"
            response.headers["Pragma"] = "no-cache"
            return response
        except (ImportError, RuntimeError):
            abort(404, description="Xray client QR code is unavailable")

    @app.post("/vpn/xray/clients/<name>/revoke")
    @login_required
    def revoke_xray_client(name):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) or name in {"root", "server", "ca"}:
            abort(404)
        try:
            result = json.loads(run_helper("xray_revoke_client", timeout=150, name=name) or "{}")
            if result.get("revoked") is not True or result.get("name") != name:
                raise RuntimeError("Xray client revocation could not be verified")
            audit("xray_client_revoked", f"Revoked Xray client {name}")
            flash(f"Xray client {name} revoked from the live configuration.", "success")
        except (RuntimeError, json.JSONDecodeError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("vpn_services"))


    @app.get("/vpn/openvpn/clients/<name>/profile")
    @login_required
    def download_openvpn_profile(name):
        name = name.strip().lower()
        endpoint = request.args.get("endpoint", "").strip()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) or name in {"root", "server", "ca"}:
            abort(404)
        if not endpoint or len(endpoint) > 253:
            abort(400, "Provide this VPS public DNS name or IP address")
        try:
            result = json.loads(run_helper(
                "openvpn_get_profile", timeout=30, name=name, endpoint=endpoint
            ) or "{}")
            profile = result.get("profile")
            if result.get("name") != name or not isinstance(profile, str) or len(profile) > 4 * 1024 * 1024:
                raise RuntimeError("OpenVPN profile could not be verified")
            if not profile.startswith("client\ndev tun\n") or "<key>" not in profile:
                raise RuntimeError("OpenVPN profile format could not be verified")
            audit("openvpn_profile_downloaded", f"Downloaded OpenVPN profile for {name}")
            response = Response(profile, mimetype="application/x-openvpn-profile")
            response.headers["Content-Disposition"] = f'attachment; filename="{name}.ovpn"'
            response.headers["Cache-Control"] = "no-store, private, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response
        except (RuntimeError, json.JSONDecodeError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("vpn_services"))

    @app.post("/vpn/openvpn/clients")
    @login_required
    def create_openvpn_client():
        name = request.form.get("name", "").strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) or name in {"root", "server", "ca"}:
            flash("Use a client name with lowercase letters, numbers, hyphens or underscores.", "error")
            return redirect(url_for("vpn_services"))
        try:
            result = json.loads(run_helper("openvpn_create_client", timeout=360, name=name) or "{}")
            if result.get("created") is not True or result.get("name") != name:
                raise RuntimeError("OpenVPN client issuance could not be verified")
            audit("openvpn_client_created", f"Issued OpenVPN client certificate {name}")
            flash(f"OpenVPN client certificate {name} was issued. Profile delivery is the next step.", "success")
        except (RuntimeError, json.JSONDecodeError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("vpn_services"))

    @app.post("/vpn/openvpn/clients/<name>/revoke")
    @login_required
    def revoke_openvpn_client(name):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) or name in {"root", "server", "ca"}:
            abort(404)
        try:
            result = json.loads(run_helper(
                "openvpn_revoke_client", timeout=240, name=name
            ) or "{}")
            if (result.get("name") != name or result.get("revoked") is not True
                    or result.get("crl_regenerated") is not True
                    or result.get("server_reload_performed") is not False):
                raise RuntimeError("OpenVPN revocation could not be verified")
            audit("openvpn_client_revoked", f"Revoked OpenVPN client certificate {name} and regenerated CRL")
            flash(
                f"OpenVPN client {name} revoked and CRL regenerated. The server was not restarted; "
                "restart/reload may be required for immediate enforcement.",
                "success"
            )
        except (RuntimeError, json.JSONDecodeError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("vpn_services"))

    @app.post("/vpn/wireguard/install")
    @login_required
    def install_wireguard():
        try:
            result = json.loads(run_helper("wireguard_install", timeout=360) or "{}")
            audit("wireguard_installed", "Installed WireGuard and created wg0 server configuration")
            flash("WireGuard is installed. The server interface has not been started, and firewall rules were not changed.", "success")
            flash(f"Server public key: {result.get('public_key', '')}", "success")
        except (RuntimeError, json.JSONDecodeError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("vpn_services"))

    @app.post("/vpn/wireguard/service")
    @login_required
    def control_wireguard():
        state = request.form.get("state", "")
        if state not in {"start", "stop"}:
            abort(400)
        try:
            run_helper("wireguard_service", state=state)
            audit(f"wireguard_{state}", f"Requested WireGuard interface {state}")
            flash(f"WireGuard interface {state} requested.", "success")
        except RuntimeError as exc:
            flash(str(exc), "error")
        return redirect(url_for("vpn_services"))


    @app.post("/vpn/wireguard/peers")
    @login_required
    def create_wireguard_peer():
        name = request.form.get("name", "").strip().lower()
        endpoint = request.form.get("endpoint", "").strip()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) or name in {"root", "server"}:
            flash("Use a client name with lowercase letters, numbers, hyphens or underscores.", "error")
            return redirect(url_for("vpn_services"))
        try:
            result = json.loads(run_helper("wireguard_create_peer", name=name, endpoint=endpoint) or "{}")
            audit("wireguard_peer_created", f"Created WireGuard client {name} ({result.get('address', '')})")
            flash(f"WireGuard client {name} created. Download its profile or scan its QR code now.", "success")
        except (RuntimeError, json.JSONDecodeError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("vpn_services"))

    @app.get("/vpn/wireguard/peers/<name>/profile")
    @login_required
    def download_wireguard_profile(name):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) or name in {"root", "server"}:
            abort(404)
        try:
            result = json.loads(run_helper("wireguard_get_profile", name=name))
            profile = result["profile"]
        except (RuntimeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            abort(404, description=str(exc))
        response = Response(profile, mimetype="application/octet-stream")
        response.headers["Content-Disposition"] = f'attachment; filename="{name}.conf"'
        response.headers["Cache-Control"] = "no-store, private, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    @app.get("/vpn/wireguard/peers/<name>/qr")
    @login_required
    def wireguard_profile_qr(name):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) or name in {"root", "server"}:
            abort(404)
        try:
            import io
            import qrcode
            from qrcode.image.svg import SvgPathImage
            result = json.loads(run_helper("wireguard_get_profile", name=name))
            profile = result["profile"]
            image = qrcode.make(profile, image_factory=SvgPathImage, border=4)
            output = io.BytesIO()
            image.save(output)
            response = Response(output.getvalue(), mimetype="image/svg+xml")
            response.headers["Cache-Control"] = "no-store, private, max-age=0"
            response.headers["Pragma"] = "no-cache"
            return response
        except (RuntimeError, json.JSONDecodeError, ImportError, KeyError, TypeError):
            abort(404)

    @app.post("/vpn/wireguard/peers/<name>/revoke")
    @login_required
    def revoke_wireguard_peer(name):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) or name in {"root", "server"}:
            abort(404)
        try:
            run_helper("wireguard_revoke_peer", name=name)
            audit("wireguard_peer_revoked", f"Revoked WireGuard client {name}")
            flash(f"WireGuard client {name} revoked and its saved profile removed.", "success")
        except RuntimeError as exc:
            flash(str(exc), "error")
        return redirect(url_for("vpn_services"))

    @app.get("/api/metrics")
    @login_required
    def metrics():
        vm = psutil.virtual_memory()
        return jsonify(cpu=psutil.cpu_percent(), memory=vm.percent,
                       disk=psutil.disk_usage("/").percent)

    return app
