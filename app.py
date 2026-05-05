from flask import Flask, request, jsonify, send_file, redirect
from flask_cors import CORS
import sqlite3
import os
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

# 🔐 Google OAuth
from flask_dance.contrib.google import make_google_blueprint, google

app = Flask(__name__)
CORS(app)

# 🔐 JWT CONFIG
app.config["JWT_SECRET_KEY"] = "secret123"
jwt = JWTManager(app)

# 🔐 GOOGLE CONFIG
app.secret_key = "supersecretkey"

google_bp = make_google_blueprint(
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    scope=["profile", "email"]
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
            email TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ---------- FRONTEND ----------
@app.route('/')
def home():
    return send_file("index.html")

# ---------- REGISTER ----------
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO auth (username, password) VALUES (?, ?)",
        (data['username'], data['password'])
    )

    conn.commit()
    conn.close()

    return jsonify({"message": "Registered successfully"})

# ---------- LOGIN ----------
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM auth WHERE username=? AND password=?",
        (data['username'], data['password'])
    )

    user = cursor.fetchone()
    conn.close()

    if user:
        token = create_access_token(identity=data['username'])
        return jsonify({"token": token})

    return jsonify({"msg": "Invalid login"}), 401

# ---------- GOOGLE LOGIN ----------
@app.route("/google_login")
def google_login():
    try:
        # Step 1: Redirect to Google if not authorized
        if not google.authorized:
            return redirect("/login/google")

        # ✅ Step 2: Get user info (UPDATED ENDPOINT)
        resp = google.get("/userinfo")

        if not resp.ok:
            return f"Google API error: {resp.text}"

        user_info = resp.json()
        print("USER INFO:", user_info)

        email = user_info.get("email")

        if not email:
            return "No email returned from Google"

        # Step 3: Create JWT token
        token = create_access_token(identity=email)

        # Step 4: Redirect to frontend with token
        return redirect(f"/?token={token}")

    except Exception as e:
        return f"ERROR: {str(e)}"

# ---------- USERS ----------
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    conn.close()

    users = []
    for row in rows:
        users.append({
            "id": row[0],
            "name": row[1],
            "email": row[2]
        })

    return jsonify(users)

@app.route('/users', methods=['POST'])
@jwt_required()
def add_user():
    data = request.get_json()

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        (data['name'], data['email'])
    )

    conn.commit()
    conn.close()

    return jsonify({"message": "User added"})

@app.route('/users/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM users WHERE id=?", (id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "User deleted"})

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