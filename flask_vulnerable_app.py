from flask import Flask, render_template, request, redirect, session, url_for
import os
import sqlite3
from werkzeug.utils import secure_filename
from flask import send_from_directory



# Initialize Flask App
app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change in production

# File Upload Config
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# Database Config
DB_NAME = "database.db"

def get_db_connection():
    """Connect to the database and return connection."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables if they don't exist."""
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
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            image TEXT
        )""")
        
        conn.execute("""
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL
        )""")
    print("Database initialized successfully.")

# Run database initialization
init_db()

# Helper Function: Check file type
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ROUTES

@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route("/")
def home():
    return redirect("/dashboard") if "user_id" in session else redirect("/login")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]  # No hashing (Security Flaw)

        with get_db_connection() as conn:
            try:
                conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                             (username, email, password))
                return redirect("/login")
            except sqlite3.IntegrityError:
                return "Username or email already exists!"

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]  # Fetch username instead of email
        password = request.form["password"]

        with get_db_connection() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
                                (username, password)).fetchone()

            if user:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect("/dashboard")
            else:
                return "Invalid credentials!"

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))

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
            conn.execute("UPDATE users SET username = ?, email = ? WHERE id = ?", 
                         (new_username, new_email, session["user_id"]))
        session["username"] = new_username
        return redirect("/profile")

    return render_template("profile.html", user=user)

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        new_password = request.form["new_password"]

        with get_db_connection() as conn:
            conn.execute("UPDATE users SET password = ? WHERE id = ?", 
                         (new_password, session["user_id"]))
        return redirect("/profile")

    return render_template("change_password.html")

from datetime import datetime  # Import datetime at the top

#Create Post Route
@app.route("/create-post", methods=["GET", "POST"])
def create_post():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        content = request.form["post_content"]
        file = request.files["file"]
        
        filename = ""
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current timestamp

        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO posts (user_id, username, content, image, timestamp) VALUES (?, ?, ?, ?, ?)",
                (session["user_id"], session["username"], content, filename, timestamp),
            )

        return redirect("/feed")

    return render_template("create_post.html")



#Feed Route
@app.route("/feed")
def feed():
    with get_db_connection() as conn:
        posts = conn.execute("SELECT username, content, image, timestamp FROM posts ORDER BY timestamp DESC").fetchall()
    
    return render_template("feed.html", posts=posts)

@app.route("/gallery")
def gallery():
    if "user_id" not in session:
        return redirect("/login")

    with get_db_connection() as conn:
        posts = conn.execute("SELECT id, content, image, timestamp FROM posts WHERE user_id = ?", 
                             (session["user_id"],)).fetchall()

    return render_template("gallery.html", posts=posts)


#Edit Post Route
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    if "user_id" not in session:
        return redirect("/login")

    with get_db_connection() as conn:
        post = conn.execute("SELECT * FROM posts WHERE id = ? AND user_id = ?", 
                            (post_id, session["user_id"])).fetchone()

        if not post:
            return "Post not found or unauthorized!"

        if request.method == "POST":
            new_content = request.form["post_content"]
            remove_image = request.form.get("remove_image")
            new_image = request.files["new_image"]
            filename = post["image"]  # Keep old image unless replaced

            if remove_image:  
                if post["image"]:
                    os.remove(os.path.join(app.config["UPLOAD_FOLDER"], post["image"]))
                filename = None  # Remove image

            if new_image and allowed_file(new_image.filename):
                filename = secure_filename(new_image.filename)
                new_image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

            conn.execute("UPDATE posts SET content = ?, image = ? WHERE id = ?", 
                         (new_content, filename, post_id))

            return redirect("/gallery")

    return render_template("edit_post.html", post=post)

#Delete Post Route
@app.route("/delete-post/<int:post_id>")
def delete_post(post_id):
    if "user_id" not in session:
        return redirect("/login")

    with get_db_connection() as conn:
        post = conn.execute("SELECT * FROM posts WHERE id = ? AND user_id = ?", (post_id, session["user_id"])).fetchone()
        if not post:
            return "Unauthorized", 403
        
        conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))

    return redirect("/gallery")




if __name__ == "__main__":
    app.run(debug=True)
