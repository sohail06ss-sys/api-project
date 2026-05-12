from flask import Flask, request, jsonify, redirect, url_for, render_template, session
from flask_cors import CORS
import sqlite3
import os
import requests

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

# ---------------- ADMIN EMAIL ----------------

ADMIN_EMAIL = "sohail06.ss@gmail.com"

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
        mobile TEXT,
        role TEXT DEFAULT 'User'
    )
    """)

    try:

        cursor.execute(
            """
            ALTER TABLE users
            ADD COLUMN role TEXT DEFAULT 'User'
            """
        )

    except:
        pass

    conn.commit()
    conn.close()

init_db()

# ---------------- FRONTEND ----------------

@app.route('/')
def home():
    return render_template("index.html")

# ---------------- REGISTER ----------------

@app.route('/register', methods=['POST'])
def register():

    data = request.get_json()

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    mobile = data.get("mobile", "")

    if not name or not email or not password:

        return jsonify({
            "error": "Missing fields"
        }), 400

    hashed_password = generate_password_hash(password)

    role = "Admin" if email == ADMIN_EMAIL else "User"

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO users
            (name,email,password,picture,mobile,role)
            VALUES(?,?,?,?,?,?)
            """,
            (
                name,
                email,
                hashed_password,
                "",
                mobile,
                role
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

    if user[3] is None:

        return jsonify({
            "error": "Use Google Login"
        }), 401

    if not check_password_hash(user[3], password):

        return jsonify({
            "error": "Wrong password"
        }), 401

    token = create_access_token(
        identity=email
    )

    return jsonify({
        "token": token,
        "name": user[1],
        "picture": user[4],
        "mobile": user[5],
        "role": user[6]
    })

# ---------------- GOOGLE LOGIN ----------------

@app.route('/google_login')
def google_login():

    try:

        if not google.authorized:
            return redirect(url_for("google.login"))

        resp = google.get(
            "https://www.googleapis.com/oauth2/v2/userinfo"
        )

        if not resp.ok:
            return "Google API Error"

        user_info = resp.json()

        name = user_info.get("name", "Google User")
        email = user_info.get("email", "")
        picture = user_info.get("picture", "")

        role = "Admin" if email == ADMIN_EMAIL else "User"

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM users
            WHERE email=?
            """,
            (email,)
        )

        existing = cursor.fetchone()

        if not existing:

            cursor.execute(
                """
                INSERT INTO users
                (name,email,password,picture,mobile,role)
                VALUES(?,?,?,?,?,?)
                """,
                (
                    name,
                    email,
                    None,
                    picture,
                    "",
                    role
                )
            )

        else:

            cursor.execute(
                """
                UPDATE users
                SET name=?, picture=?, role=?
                WHERE email=?
                """,
                (
                    name,
                    picture,
                    role,
                    email
                )
            )

        conn.commit()
        conn.close()

        token = create_access_token(
            identity=email
        )

        frontend_url = url_for(
            "home",
            _external=True
        )

        return redirect(
            f"{frontend_url}?token={token}"
        )

    except Exception as e:

        return f"Google Login Error: {str(e)}"

# ---------------- GOOGLE LOGOUT ----------------

@app.route('/google_logout')
def google_logout():

    try:

        session.clear()

        if "google_oauth_token" in session:

            del session["google_oauth_token"]

        return redirect("/")

    except Exception as e:

        return f"Logout Error: {str(e)}"

# ---------------- CURRENT USER ----------------

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
            mobile,
            role
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
            "mobile": "",
            "role": "User"
        })

    return jsonify({
        "name": user[0],
        "email": user[1],
        "picture": user[2] if user[2] else "",
        "mobile": user[3] if user[3] else "Not Added",
        "role": user[4]
    })

# ---------------- USERS ----------------

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id,name,email,picture,mobile,role
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
            "mobile": r[4],
            "role": r[5]
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

        name = data.get("name")
        email = data.get("email")
        mobile = data.get("mobile", "")

        password = data.get("password", "123456")

        hashed_password = generate_password_hash(password)

        role = data.get("role", "User")

        if not name or not email:

            return jsonify({
                "error": "Missing required fields"
            }), 400

        cursor.execute(
            """
            INSERT INTO users
            (name,email,password,picture,mobile,role)
            VALUES(?,?,?,?,?,?)
            """,
            (
                name,
                email,
                hashed_password,
                "",
                mobile,
                role
            )
        )

        conn.commit()

        return jsonify({
            "message": "User added successfully",
            "default_password": password
        })

    except sqlite3.IntegrityError:

        return jsonify({
            "error": "User already exists"
        }), 400

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500

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

    role = data.get("role", "User")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET name=?, email=?, mobile=?, role=?
        WHERE id=?
        """,
        (
            data['name'],
            data['email'],
            data.get("mobile", ""),
            role,
            id
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Updated"
    })

# ---------------- UPDATE MOBILE ----------------

@app.route('/update_mobile', methods=['POST'])
@jwt_required()
def update_mobile():

    current_email = get_jwt_identity()

    data = request.get_json()

    mobile = data.get("mobile")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET mobile=?
        WHERE email=?
        """,
        (mobile, current_email)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Mobile updated successfully"
    })

# ---------------- AI ASSISTANT ----------------

@app.route('/ai', methods=['POST'])
@jwt_required()
def ai_assistant():

    try:

        data = request.get_json()

        prompt = data.get("prompt")

        api_key = os.environ.get(
            "OPENROUTER_API_KEY"
        )

        response = requests.post(

            url="https://openrouter.ai/api/v1/chat/completions",

            headers={

                "Authorization":
                f"Bearer {api_key}",

                "Content-Type":
                "application/json"
            },

            json={

                "model":
                "openrouter/free",

                "messages":[

                    {
                        "role":"system",
                        "content":
                        "You are an advanced AI SaaS assistant that gives detailed, professional, accurate, and useful answers."
                    },

                    {
                        "role":"user",
                        "content":prompt
                    }
                ],

                "max_tokens":1000,

                "temperature":0.7
            }
        )

        result = response.json()

        print(result)

        if "choices" not in result:

            return jsonify({

                "error":
                result.get(
                    "error",
                    {}).get(
                        "message",
                        "AI response failed"
                    )
            }), 500

        message = result["choices"][0]["message"]["content"]

        return jsonify({

            "reply": message
        })

    except Exception as e:

        return jsonify({

            "error": str(e)
        }), 500
# ---------------- RUN ----------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )