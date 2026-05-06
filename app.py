from flask import Flask, request, jsonify, send_file, redirect, url_for
from flask_cors import CORS
import sqlite3
import os

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from flask_dance.contrib.google import make_google_blueprint, google

app = Flask(__name__)
CORS(app)

# ---------------- CONFIG ----------------

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "secret")

app.config["JWT_SECRET_KEY"] = "jwt-secret-key"

jwt = JWTManager(app)

# ---------------- GOOGLE CONFIG ----------------

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

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

# ---------------- DATABASE ----------------

def init_db():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        picture TEXT,
        mobile TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ---------------- FRONTEND ----------------

@app.route('/')
def home():
    return send_file("index.html")

# ---------------- REGISTER ----------------

@app.route('/register', methods=['POST'])
def register():

    data = request.get_json()

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    mobile = data.get("mobile", "")

    if not name or not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    hashed_password = generate_password_hash(password)

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO users
            (name,email,password,picture,mobile)
            VALUES(?,?,?,?,?)
            """,
            (
                name,
                email,
                hashed_password,
                "",
                mobile
            )
        )

        conn.commit()

        return jsonify({
            "message": "Registration successful"
        })

    except sqlite3.IntegrityError:

        return jsonify({
            "error": "User already exists"
        }), 400

    finally:
        conn.close()

# ---------------- LOGIN ----------------

@app.route('/login', methods=['POST'])
def login():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE email=?",
        (email,)
    )

    user = cursor.fetchone()

    conn.close()

    if not user:
        return jsonify({
            "error": "User not found"
        }), 401

    # GOOGLE LOGIN ACCOUNT
    if user[3] is None:

        return jsonify({
            "error": "Use Google Login"
        }), 401

    if not check_password_hash(user[3], password):

        return jsonify({
            "error": "Wrong password"
        }), 401

    token = create_access_token(
        identity={
            "email": user[2],
            "name": user[1],
            "picture": user[4] if user[4] else "",
            "mobile": user[5] if user[5] else ""
        }
    )

    return jsonify({
        "token": token,
        "name": user[1],
        "picture": user[4],
        "mobile": user[5]
    })

# ---------------- GOOGLE LOGIN ----------------

@app.route('/me')
@jwt_required()
def me():

    current_email = get_jwt_identity()

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            name,
            email,
            picture,
            mobile
        FROM users
        WHERE email=?
        """,
        (current_email,)
    )

    user = cursor.fetchone()

    conn.close()

    if not user:

        return jsonify({
            "name": "User",
            "email": "",
            "picture": "",
            "mobile": ""
        })

    return jsonify({
        "name": user[0],
        "email": user[1],
        "picture": user[2] if user[2] else "",
        "mobile": user[3] if user[3] else "Not Added"
    })
# ---------------- CURRENT USER ----------------

@app.route('/me')
@jwt_required()
def me():

    current_user = get_jwt_identity()

    # JWT stores dictionary
    if isinstance(current_user, dict):

        return jsonify({
            "name": current_user.get("name", "User"),
            "email": current_user.get("email", ""),
            "picture": current_user.get("picture", ""),
            "mobile": current_user.get("mobile", "")
        })

    # fallback if only email stored
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT name,email,picture,mobile
        FROM users
        WHERE email=?
        """,
        (current_user,)
    )

    user = cursor.fetchone()

    conn.close()

    if not user:

        return jsonify({
            "name": "User",
            "email": "",
            "picture": "",
            "mobile": ""
        })

    return jsonify({
        "name": user[0],
        "email": user[1],
        "picture": user[2] if user[2] else "",
        "mobile": user[3] if user[3] else ""
    })

# ---------------- USERS ----------------

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id,name,email,picture,mobile
        FROM users
        """
    )

    rows = cursor.fetchall()

    conn.close()

    return jsonify([

        {
            "id": r[0],
            "name": r[1],
            "email": r[2],
            "picture": r[3],
            "mobile": r[4]
        }

        for r in rows
    ])

# ---------------- ADD USER ----------------

@app.route('/users', methods=['POST'])
@jwt_required()
def add_user():

    data = request.get_json()

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO users
            (name,email,password,picture,mobile)
            VALUES(?,?,?,?,?)
            """,
            (
                data['name'],
                data['email'],
                None,
                "",
                data.get("mobile", "")
            )
        )

        conn.commit()

        return jsonify({
            "message": "User added"
        })

    except sqlite3.IntegrityError:

        return jsonify({
            "error": "User already exists"
        }), 400

    finally:
        conn.close()

# ---------------- DELETE USER ----------------

@app.route('/users/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM users WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Deleted"
    })

# ---------------- UPDATE USER ----------------

@app.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):

    data = request.get_json()

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET name=?, email=?, mobile=?
        WHERE id=?
        """,
        (
            data['name'],
            data['email'],
            data.get("mobile", ""),
            id
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Updated"
    })

# ---------------- RUN ----------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )