from flask import Flask, render_template, request, redirect, session, url_for
import os
import sqlite3
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change for production

# File Upload Configuration
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# Database Initialization
DB_NAME = "database.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db_connection() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )""")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            content TEXT,
            filename TEXT
        )""")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT
        )""")
    print("Database initialized successfully.")


init_db()


# Helper function to check file type
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
def home():
    return redirect("/dashboard") if "user_id" in session else redirect("/login")


# Route: Signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]  # No hashing (Security flaw)

        with get_db_connection() as conn:
            try:
                conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                             (username, email, password))
                conn.commit()
                return redirect("/login")
            except sqlite3.IntegrityError:
                return "Username or email already exists!"

    return render_template("signup.html")


# Route: Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        with get_db_connection() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password)).fetchone()

            if user:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect("/dashboard")
            else:
                return "Invalid credentials!"

    return render_template("login.html")


# Route: Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# Route: Dashboard
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("dashboard.html", username=session.get("username"))


# Route: Profile (Editable, with HTML Injection Vulnerability)
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect("/login")

    with get_db_connection() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if request.method == "POST":
        new_username = request.form["username"]
        new_email = request.form["email"]

        with get_db_connection() as conn:
            conn.execute("UPDATE users SET username = ?, email = ? WHERE id = ?", (new_username, new_email, session["user_id"]))
            conn.commit()

        session["username"] = new_username
        return redirect("/profile")

    return render_template("profile.html", user=user)


# Route: Change Password (Does not verify current password)
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        new_password = request.form["new_password"]

        with get_db_connection() as conn:
            conn.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, session["user_id"]))
            conn.commit()

        return redirect("/profile")

    return render_template("change_password.html")


# Route: Create Post (Includes file upload)
@app.route("/create-post", methods=["GET", "POST"])
def create_post():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        content = request.form["post_content"]
        filename = None

        if "file" in request.files:
            file = request.files["file"]
            if file.filename != "" and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        with get_db_connection() as conn:
            conn.execute("INSERT INTO posts (user_id, username, content, filename) VALUES (?, ?, ?, ?)",
                         (session["user_id"], session["username"], content, filename))
            conn.commit()

        return redirect("/feed")

    return render_template("create_post.html")


# Route: Feed (All Posts & Images)
@app.route("/feed")
def feed():
    with get_db_connection() as conn:
        posts = conn.execute("SELECT username, content, filename FROM posts").fetchall()

    return render_template("feed.html", posts=posts)


if __name__ == "__main__":
    app.run(debug=True)