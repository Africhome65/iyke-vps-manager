import json
import os
import re
import secrets
import sqlite3
import subprocess
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path

import psutil
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

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
    Limiter(get_remote_address, app=app, default_limits=["300 per day", "60 per hour"],
            storage_uri="memory://")

    def connect_db():
        Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(app.config["DATABASE"], timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def init_db():
        with connect_db() as db:
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
                db.execute("INSERT INTO admins(username,password_hash,created_at) VALUES(?,?,?)",
                           (bootstrap_user, generate_password_hash(bootstrap_password),
                            datetime.utcnow().isoformat(timespec="seconds")))

    init_db()

    @login_manager.user_loader
    def load_user(admin_id):
        with connect_db() as db:
            row = db.execute("SELECT id,username FROM admins WHERE id=?", (admin_id,)).fetchone()
        return Admin(row) if row else None

    def audit(action, detail):
        with connect_db() as db:
            db.execute("INSERT INTO audit(admin,action,detail,created_at) VALUES(?,?,?,?)",
                       (current_user.username if current_user.is_authenticated else "system",
                        action, detail[:240], datetime.utcnow().isoformat(timespec="seconds")))

    def run_helper(*args, input_text=None):
        try:
            result = subprocess.run(
                ["sudo", "-n", app.config["HELPER"], *args],
                input=input_text, text=True, capture_output=True, timeout=20, check=False
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
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        )
        return response

    @app.get("/health")
    def health():
        return jsonify(status="ok", service="iyke-vps-manager")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            with connect_db() as db:
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
        with connect_db() as db:
            return db.execute("SELECT admin,action,detail,created_at FROM audit "
                              "ORDER BY id DESC LIMIT 8").fetchall()

    @app.get("/users")
    @login_required
    def users():
        try:
            rows = json.loads(run_helper("list") or "[]")
        except (RuntimeError, json.JSONDecodeError) as exc:
            rows = []
            flash(str(exc), "error")
        return render_template("users.html", users=rows)

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
            run_helper("create", username, expiry, input_text=temporary_password + "\n")
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
            run_helper("expire", username, expiry)
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
            run_helper("delete", username)
            audit("ssh_user_deleted", f"Deleted Linux account {username}")
            flash(f"Account {username} deleted.", "success")
        except RuntimeError as exc:
            flash(str(exc), "error")
        return redirect(url_for("users"))

    @app.get("/api/metrics")
    @login_required
    def metrics():
        vm = psutil.virtual_memory()
        return jsonify(cpu=psutil.cpu_percent(), memory=vm.percent,
                       disk=psutil.disk_usage("/").percent)

    return app
