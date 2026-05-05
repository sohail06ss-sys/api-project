from flask import Flask, request, jsonify, send_file, redirect, url_for
from flask_cors import CORS
import sqlite3
import os
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

# 🔐 Google OAuth
from flask_dance.contrib.google import make_google_blueprint, google

app = Flask(__name__)
CORS(app)

# 🔥 Required for Render (HTTPS cookies)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["PREFERRED_URL_SCHEME"] = "https"

# 🔐 JWT
app.config["JWT_SECRET_KEY"] = "secret123"
jwt = JWTManager(app)

# 🔐 Flask secret
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

# 🔐 Load Google creds from env
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise Exception("Missing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET")

# 👉 IMPORTANT: redirect_to ensures we land on /google_login after auth
google_bp = make_google_blueprint(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    scope=["openid", "email", "profile"],
    redirect_to="google_login",
)

app.register_blueprint(google_bp, url_prefix="/login")

# ---------- DB ----------
def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, email TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS auth (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, password TEXT)""")
    conn.commit()
    conn.close()

init_db()

# ---------- FRONTEND ----------
@app.route("/")
def home():
    return send_file("index.html")

# ---------- AUTH ----------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("INSERT INTO auth (username, password) VALUES (?, ?)",
              (data["username"], data["password"]))
    conn.commit()
    conn.close()
    return jsonify({"message": "Registered"})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT * FROM auth WHERE username=? AND password=?",
              (data["username"], data["password"]))
    user = c.fetchone()
    conn.close()
    if user:
        token = create_access_token(identity=data["username"])
        return jsonify({"token": token})
    return jsonify({"msg": "Invalid login"}), 401

# ---------- GOOGLE FLOW ----------
@app.route("/google_login")
def google_login():
    try:
        # Step 1: go to Google if not authorized
        if not google.authorized:
            return redirect(url_for("google.login"))

        # Step 2: fetch user info
        resp = google.get("https://www.googleapis.com/oauth2/v2/userinfo")
        if not resp or not resp.ok:
            return f"Google API error: {resp.text if resp else 'no response'}"

        data = resp.json()
        email = data.get("email")
        if not email:
            return f"No email in response: {data}"

        # Step 3: issue JWT
        token = create_access_token(identity=email)

        # Step 4: send back to frontend
        return redirect(f"/?token={token}")

    except Exception as e:
        import traceback
        return f"ERROR: {str(e)}\n{traceback.format_exc()}"

# ---------- USERS ----------
@app.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    rows = c.fetchall()
    conn.close()
    return jsonify([{"id": r[0], "name": r[1], "email": r[2]} for r in rows])

@app.route("/users", methods=["POST"])
@jwt_required()
def add_user():
    data = request.get_json()
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("INSERT INTO users (name, email) VALUES (?, ?)",
              (data["name"], data["email"]))
    conn.commit()
    conn.close()
    return jsonify({"message": "User added"})

@app.route("/users/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_user(id):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "User deleted"})

@app.route("/users/<int:id>", methods=["PUT"])
@jwt_required()
def update_user(id):
    data = request.get_json()
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("UPDATE users SET name=?, email=? WHERE id=?",
              (data["name"], data["email"], id))
    conn.commit()
    conn.close()
    return jsonify({"message": "User updated"})