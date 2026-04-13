"""
GhostTrace v6.0 — OSINT Intelligence Platform
by Alsartawi

Professional Edition with modular architecture
"""
import sys, os, json, argparse, getpass
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, session, redirect, jsonify
from config import Config
from database.manager import Database
from tools.registry import ToolRegistry
from api.routes import scans_bp, history_bp, exports_bp, system_bp
from api.recon_routes import recon_bp
from utils.logger import log

# ── Login page HTML ──
_LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>GhostTrace — Login</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0e1117;color:#e8edf5;
     font-family:'Inter',sans-serif;
     display:flex;align-items:center;
     justify-content:center;height:100vh}}
.box{{background:#141820;border:1px solid #252d3d;
     border-radius:12px;padding:40px;width:340px}}
h1{{font-size:18px;font-weight:700;
    margin-bottom:6px;color:#e8edf5}}
.sub{{font-size:11px;color:#4f8ef7;
      font-family:'JetBrains Mono',monospace;
      margin-bottom:28px}}
input{{width:100%;background:#0e1117;
       border:1px solid #252d3d;border-radius:6px;
       padding:10px 14px;color:#e8edf5;
       font-size:13px;margin-bottom:14px;outline:none}}
input:focus{{border-color:#4f8ef7}}
button{{width:100%;background:#4f8ef7;
        border:none;border-radius:6px;
        padding:11px;color:#fff;
        font-size:13px;font-weight:600;cursor:pointer}}
button:hover{{background:#3a7de8}}
.err{{color:#f16060;font-size:12px;
      margin-bottom:12px;text-align:center}}
</style></head>
<body><div class="box">
<h1>GhostTrace</h1>
<div class="sub">v{version} by Alsartawi</div>
{error}
<form method="POST" action="/login">
<input type="password" name="password"
       placeholder="Password" autofocus>
<button type="submit">Enter</button>
</form></div></body></html>"""


def _setup_password():
    """Run with --setup to configure password"""
    Config.init()
    print("\n GhostTrace — Password Setup")
    print("─" * 40)
    pw = getpass.getpass("Set password: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw != pw2:
        print("[!] Passwords don't match.")
        sys.exit(1)
    if len(pw) < 6:
        print("[!] Password too short (min 6 chars).")
        sys.exit(1)
    import bcrypt
    hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    Config.save_auth_hash(hashed)
    print("[✓] Password set. Run: python app.py")
    sys.exit(0)


def create_app():
    Config.init()

    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request
    app.secret_key = Config.SECRET_KEY

    # Initialize components
    Database.init()
    ToolRegistry.init()

    # Check PDF engine
    try:
        import weasyprint
        log.info("PDF engine: weasyprint available")
    except ImportError:
        log.warning("weasyprint not installed — PDF reports disabled. Fix: pip install weasyprint")

    # Register blueprints
    app.register_blueprint(scans_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(exports_bp)
    app.register_blueprint(system_bp)
    app.register_blueprint(recon_bp)

    # ── Auth routes ──
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            import bcrypt
            pw = request.form.get("password", "")
            stored = Config.load_auth_hash()
            if stored and bcrypt.checkpw(pw.encode(), stored.encode()):
                session["auth"] = True
                session.permanent = True
                return redirect("/")
            error = '<div class="err">Wrong password</div>'
            return _LOGIN_HTML.format(
                version=Config.VERSION, error=error), 401
        return _LOGIN_HTML.format(version=Config.VERSION, error="")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/login")

    @app.before_request
    def require_auth():
        # Always allow login page
        if request.path == "/login":
            return
        # Allow static files
        if request.path.startswith("/static"):
            return
        # CSRF protection on mutation requests (always, regardless of auth)
        if request.method in ("POST", "DELETE"):
            token = request.headers.get("X-CSRF-Token")
            expected = session.get("csrf_token")
            if not token or not expected or token != expected:
                return jsonify({"error": "CSRF token invalid"}), 403
        stored = Config.load_auth_hash()
        # No password set — allow localhost only
        if not stored:
            if request.remote_addr == "127.0.0.1":
                return
            return "Access denied — no password configured", 403
        # Password set — require session
        if not session.get("auth"):
            return redirect("/login")

    @app.after_request
    def inject_csrf(response):
        if "csrf_token" not in session:
            import secrets as _secrets
            session["csrf_token"] = _secrets.token_hex(32)
        return response

    # ── Main routes ──
    @app.route("/")
    def index():
        import secrets as _secrets
        if "csrf_token" not in session:
            session["csrf_token"] = _secrets.token_hex(32)
        return render_template("index.html", csrf_token=session["csrf_token"])

    @app.teardown_appcontext
    def close_db(e=None):
        Database.close()

    @app.errorhandler(404)
    def not_found(e):
        return {"error": "Not found"}, 404

    @app.errorhandler(500)
    def server_error(e):
        log.error(f"Server error: {e}")
        return {"error": "Internal server error"}, 500

    log.info(f"GhostTrace v{Config.VERSION} initialized")
    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GhostTrace OSINT Platform")
    parser.add_argument("--setup", action="store_true",
                        help="Set GhostTrace password")
    args = parser.parse_args()

    if args.setup:
        _setup_password()

    print(f"""
    ╔══════════════════════════════════════════╗
    ║       GhostTrace v{Config.VERSION}                    ║
    ║       by Alsartawi                       ║
    ║    OSINT Intelligence Platform           ║
    ║                                          ║
    ║    http://127.0.0.1:5000                 ║
    ╚══════════════════════════════════════════╝
    """)
    app = create_app()
    # Debug mode via env var only — never default ON (leaks stack traces)
    debug = os.environ.get("GT_DEBUG", "0") == "1"
    app.run(debug=debug, host="127.0.0.1", port=5000, threaded=True)
