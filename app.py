from flask import Flask, request, jsonify, send_file, redirect, url_for
from flask_cors import CORS
import sqlite3
import os
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

# Google OAuth
from flask_dance.contrib.google import make_google_blueprint, google

app = Flask(__name__)
CORS(app)

# 🔐 REQUIRED FOR RENDER
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['PREFERRED_URL_SCHEME'] = "https"

# 🔐 SECRET KEY
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")

# 🔐 JWT
app.config["JWT_SECRET_KEY"] = "secret123"
jwt = JWTManager(app)

# 🔐 GOOGLE ENV
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise Exception("❌ Google credentials missing")

# 🔐 GOOGLE SETUP
google_bp = make_google_blueprint(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_to="google_login"
)

app.register_blueprint(google_bp, url_prefix="/login")

# ---------- DATABASE ----------
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE
        )
    """)

    conn.commit()
    conn.close()

# 🔥 ALWAYS RUN ON START
init_db()

# ---------- FRONTEND ----------
@app.route('/')
def home():
    return send_file("index.html")

# ---------- GOOGLE LOGIN ----------
@app.route("/google_login")
def google_login():
    try:
        if not google.authorized:
            return redirect(url_for("google.login"))

        resp = google.get("https://www.googleapis.com/oauth2/v2/userinfo")

        if not resp or not resp.ok:
            return f"❌ Google API error: {resp.text if resp else 'No response'}"

        user_info = resp.json()

        name = user_info.get("name", "Google User")
        email = user_info.get("email")

        if not email:
            return f"❌ Email missing → {user_info}"

        # 🔥 SAVE USER INTO DATABASE
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        existing = cursor.fetchone()

        if not existing:
            cursor.execute(
                "INSERT INTO users (name, email) VALUES (?, ?)",
                (name, email)
            )
            conn.commit()

        conn.close()

        # 🔐 CREATE TOKEN
        token = create_access_token(identity=email)

        return redirect(f"/?token={token}")

    except Exception as e:
        import traceback
        return f"ERROR: {str(e)}\n{traceback.format_exc()}"

# ---------- USERS ----------
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    conn.close()

    return jsonify([
        {"id": r[0], "name": r[1], "email": r[2]}
        for r in rows
    ])

# ✅ FIXED ADD USER
@app.route('/users', methods=['POST'])
@jwt_required()
def add_user():
    data = request.get_json()

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (name, email) VALUES (?, ?)",
            (data['name'], data['email'])
        )
        conn.commit()

        return jsonify({"message": "User added"})

    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 400

    finally:
        conn.close()

# DELETE
@app.route('/users/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM users WHERE id=?", (id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "User deleted"})

# UPDATE
@app.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    data = request.get_json()

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE users SET name=?, email=? WHERE id=?",
        (data['name'], data['email'], id)
    )

    conn.commit()
    conn.close()

    return jsonify({"message": "User updated"})

# ---------- RUN ----------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))