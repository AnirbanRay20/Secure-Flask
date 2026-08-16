"""
app.py

Remediated Flask REST API for the technology company's user
registration/login service.

Fixes applied vs. the original insecure implementation:
  1. SQL Injection -> parameterised queries (sqlite3 placeholders)
  2. Broken Access Control -> API-key auth middleware on /admin
  3. Unsalted MD5 password storage -> Bcrypt via crypto_utils.py
  4. Hardcoded credentials -> loaded from environment variables (.env)
"""

import os
import sqlite3
from functools import wraps

from flask import Flask, request, jsonify, g
from dotenv import load_dotenv

from crypto_utils import hash_password, verify_password

load_dotenv()  # loads variables from a local .env file (never committed)

app = Flask(__name__)

DATABASE = os.environ.get("DATABASE_PATH", "app.db")

# --- Secret management -----------------------------------------------
# BEFORE (insecure — do not do this):
#   API_KEY = "sk_live_9f2a7c3e1b6d4f80"
#   ADMIN_TOKEN = "admin123"
#
# AFTER (secure — read from environment, populated via .env / a real
# secrets manager in production; .env is never committed, see .gitignore):
API_KEY = os.environ.get("API_KEY")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")

if not API_KEY or not ADMIN_TOKEN:
    raise RuntimeError(
        "API_KEY and ADMIN_TOKEN must be set via environment variables "
        "(see .env.example). Refusing to start with missing secrets."
    )


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    db.commit()


# --- Broken Access Control fix: authentication middleware ------------
def require_admin_auth(f):
    """
    Decorator enforcing that a valid API key is presented before the
    wrapped route executes. Compares against the server-side ADMIN_TOKEN
    loaded from the environment, never a value the client can influence.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        provided_token = request.headers.get("X-Admin-Token")
        if not provided_token or provided_token != ADMIN_TOKEN:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    password_hash = hash_password(password)

    db = get_db()
    try:
        # --- SQL Injection fix: parameterised query -------------------
        # BEFORE (insecure):
        #   query = f"INSERT INTO users (username, password_hash) "
        #           f"VALUES ('{username}', '{password_hash}')"
        #   db.execute(query)
        #
        # AFTER (secure — placeholders, driver escapes values):
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409

    return jsonify({"status": "registered"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    db = get_db()
    # Parameterised lookup — same fix as /register.
    cursor = db.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    )
    row = cursor.fetchone()

    if row is None or not verify_password(password, row[0]):
        return jsonify({"error": "invalid credentials"}), 401

    return jsonify({"status": "login successful"}), 200


# --- Broken Access Control fix applied here ---------------------------
# BEFORE (insecure):
#   @app.route("/admin", methods=["GET"])
#   def admin():
#       return jsonify({"users": get_all_users()})
#
# AFTER (secure — requires a valid admin token on every request):
@app.route("/admin", methods=["GET"])
@require_admin_auth
def admin():
    db = get_db()
    cursor = db.execute("SELECT id, username FROM users")
    users = [{"id": r[0], "username": r[1]} for r in cursor.fetchall()]
    return jsonify({"users": users}), 200


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=False, host="127.0.0.1", port=5000)
