from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
import os
import sqlite3
from werkzeug.utils import secure_filename
from flask import send_from_directory
from urllib.parse import urlparse, unquote
import re
import sys
import platform
from datetime import datetime  # Import datetime at the top
try:
    import pkg_resources
except Exception:
    pkg_resources = None



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

# Progress Tracking Functions
def award_achievement(user_id, achievement_name, achievement_description, points):
    """Award an achievement to a user"""
    with get_db_connection() as conn:
        # Check if user already has this achievement
        existing = conn.execute(
            "SELECT id FROM achievements WHERE user_id = ? AND achievement_name = ?",
            (user_id, achievement_name)
        ).fetchone()
        
        if not existing:
            # Award the achievement
            conn.execute("""
                INSERT INTO achievements (user_id, achievement_name, achievement_description, points)
                VALUES (?, ?, ?, ?)
            """, (user_id, achievement_name, achievement_description, points))
            
            # Update user stats
            conn.execute("""
                UPDATE user_stats 
                SET total_points = total_points + ?, achievements_earned = achievements_earned + 1
                WHERE user_id = ?
            """, (points, user_id))
            
            return True
    return False

def record_vulnerability_found(user_id, vulnerability_type, points):
    """Record when a user finds a vulnerability"""
    with get_db_connection() as conn:
        # Record the vulnerability
        conn.execute("""
            INSERT INTO user_progress (user_id, vulnerability_type, points)
            VALUES (?, ?, ?)
        """, (user_id, vulnerability_type, points))
        
        # Update user stats
        conn.execute("""
            UPDATE user_stats 
            SET total_points = total_points + ?, vulnerabilities_found = vulnerabilities_found + 1,
                level = CAST(((total_points + ?) / 100) AS INTEGER) + 1, last_updated = CURRENT_TIMESTAMP
            WHERE user_id = ?
        """, (points, points, user_id))

def get_user_progress(user_id):
    """Get user's progress and achievements"""
    with get_db_connection() as conn:
        # Get user stats
        stats = conn.execute("""
            SELECT total_points, vulnerabilities_found, achievements_earned, level
            FROM user_stats WHERE user_id = ?
        """, (user_id,)).fetchone()
        
        # Get recent achievements
        achievements = conn.execute("""
            SELECT achievement_name, achievement_description, points, earned_at
            FROM achievements WHERE user_id = ?
            ORDER BY earned_at DESC LIMIT 5
        """, (user_id,)).fetchall()
        
        # Get vulnerability progress
        vulnerabilities = conn.execute("""
            SELECT vulnerability_type, COUNT(*) as count, SUM(points) as total_points
            FROM user_progress WHERE user_id = ?
            GROUP BY vulnerability_type
        """, (user_id,)).fetchall()
        
        return {
            'stats': stats,
            'achievements': achievements,
            'vulnerabilities': vulnerabilities
        }

def detect_vulnerability_attempts(user_id, request_data):
    """Detect if user is attempting vulnerability exploits"""
    achievements = []
    
    # SQL Injection detection
    if 'username' in request_data:
        username = request_data['username']
        sql_patterns = ["'", "OR", "AND", "UNION", "SELECT", "DROP", "INSERT", "UPDATE", "DELETE", "--", "/*", "*/"]
        if any(pattern.upper() in username.upper() for pattern in sql_patterns):
            if award_achievement(user_id, "SQL_INJECTION_ATTEMPT", "Attempted SQL Injection Attack", 50):
                achievements.append("SQL Injection Attempt Detected! +50 points")
    
    # XSS detection
    if 'post_content' in request_data:
        content = request_data['post_content']
        xss_patterns = ["<script>", "javascript:", "onload=", "onerror=", "onclick=", "alert(", "document.cookie"]
        if any(pattern.lower() in content.lower() for pattern in xss_patterns):
            if award_achievement(user_id, "XSS_ATTEMPT", "Attempted XSS Attack", 50):
                achievements.append("XSS Attack Attempt Detected! +50 points")
    
    # File upload vulnerability detection
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename:
            # Check for suspicious file extensions
            suspicious_extensions = ['.php', '.jsp', '.asp', '.exe', '.bat', '.sh', '.py', '.rb']
            if any(file.filename.lower().endswith(ext) for ext in suspicious_extensions):
                if award_achievement(user_id, "MALICIOUS_FILE_UPLOAD", "Attempted Malicious File Upload", 75):
                    achievements.append("Malicious File Upload Attempt! +75 points")
    
    return achievements

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
        
        # Detect vulnerability attempts
        achievements = []
        if "user_id" in session:
            achievements = detect_vulnerability_attempts(session["user_id"], request.form)

        with get_db_connection() as conn:
            # Intentionally vulnerable to SQL Injection for lab demonstration
            query = (
                "SELECT * FROM users WHERE username = '" + username + "' "
                "AND password = '" + password + "'"
            )
            try:
                user = conn.execute(query).fetchone()
            except sqlite3.OperationalError as e:
                app.logger.error(f"SQL error: {e}. Query: {query}")
                return f"SQL syntax error. Query was:<br><pre>{query}</pre><br>Error: {str(e)}"

            if user:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                
                # Award login achievement
                award_achievement(user["id"], "FIRST_LOGIN", "Successfully logged into the lab", 10)
                
                # Check for SQL injection success
                sql_patterns = ["'", "OR", "AND", "UNION", "SELECT", "DROP", "INSERT", "UPDATE", "DELETE", "--", "/*", "*/"]
                if any(pattern.upper() in username.upper() for pattern in sql_patterns):
                    record_vulnerability_found(user["id"], "SQL_INJECTION", 100)
                    achievements.append("🎉 SQL Injection Success! +100 points")
                
                if achievements:
                    flash(achievements, "achievements")
                else:
                    flash("Welcome back! Ready to learn?", "success")
                
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
    if "user_id" not in session:
        return redirect("/login")
    
    progress = get_user_progress(session["user_id"])
    return render_template("dashboard.html", 
                         username=session.get("username"), 
                         progress=progress)

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


#Create Post Route
@app.route("/create-post", methods=["GET", "POST"])
def create_post():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        content = request.form["post_content"]
        file = request.files["file"]
        
        # Detect vulnerability attempts
        achievements = detect_vulnerability_attempts(session["user_id"], request.form)
        
        # Check for XSS in content
        xss_patterns = ["<script>", "javascript:", "onload=", "onerror=", "onclick=", "alert(", "document.cookie"]
        if any(pattern.lower() in content.lower() for pattern in xss_patterns):
            record_vulnerability_found(session["user_id"], "XSS", 100)
            achievements.append("🎉 XSS Attack Successful! +100 points")
        
        filename = ""
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        elif file and file.filename:
            # Malicious file upload attempt
            record_vulnerability_found(session["user_id"], "FILE_UPLOAD", 75)
            achievements.append("🎉 File Upload Vulnerability Found! +75 points")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current timestamp

        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO posts (user_id, username, content, image, timestamp) VALUES (?, ?, ?, ?, ?)",
                (session["user_id"], session["username"], content, filename, timestamp),
            )

        if achievements:
            flash(achievements, "achievements")
        else:
            flash("Post created successfully!", "success")

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
        # Ownership check removed intentionally for IDOR demonstration
        post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()

        if not post:
            return "Post not found!"

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

# Intentionally insecure edit endpoint for IDOR demonstration
@app.route("/edit-post-insecure/<int:post_id>", methods=["GET", "POST"])
def edit_post_insecure(post_id):
    if "user_id" not in session:
        return redirect("/login")

    with get_db_connection() as conn:
        # No ownership check – vulnerable to IDOR
        post = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()

        if not post:
            return "Post not found!"

        if request.method == "POST":
            new_content = request.form["post_content"]
            remove_image = request.form.get("remove_image")
            new_image = request.files["new_image"]
            filename = post["image"]

            if remove_image:
                if post["image"]:
                    os.remove(os.path.join(app.config["UPLOAD_FOLDER"], post["image"]))
                filename = None

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

@app.route("/scoreboard")
def scoreboard():
    with get_db_connection() as conn:
        # Get top users by points
        top_users = conn.execute("""
            SELECT u.username, us.total_points, us.vulnerabilities_found, 
                   us.achievements_earned, us.level
            FROM users u
            JOIN user_stats us ON u.id = us.user_id
            ORDER BY us.total_points DESC
            LIMIT 10
        """).fetchall()
        
        # Get vulnerability statistics
        vuln_stats = conn.execute("""
            SELECT vulnerability_type, COUNT(*) as total_attempts, 
                   COUNT(DISTINCT user_id) as unique_users
            FROM user_progress
            GROUP BY vulnerability_type
            ORDER BY total_attempts DESC
        """).fetchall()
    
    # Get current user's progress if logged in
    current_user_progress = None
    if "user_id" in session:
        current_user_progress = get_user_progress(session["user_id"])
    
    return render_template("scoreboard.html", 
                         top_users=top_users, 
                         vuln_stats=vuln_stats,
                         current_user_progress=current_user_progress)

# Additional Vulnerability Routes

@app.route("/csrf-demo", methods=["GET", "POST"])
def csrf_demo():
    if "user_id" not in session:
        return redirect("/login")
    
    if request.method == "POST":
        # CSRF vulnerability - no token validation
        new_email = request.form.get("email")
        if new_email:
            with get_db_connection() as conn:
                conn.execute("UPDATE users SET email = ? WHERE id = ?", 
                           (new_email, session["user_id"]))
            record_vulnerability_found(session["user_id"], "CSRF", 80)
            flash("🎉 CSRF Attack Successful! Email updated without proper validation. +80 points", "achievements")
            return redirect("/profile")
    
    return render_template("csrf_demo.html")

# CSRF GET variant to make PoC easy via top-level navigation (SameSite=Lax friendly)
@app.route("/csrf-change-email")
def csrf_change_email():
    if "user_id" not in session:
        return redirect("/login")
    new_email = request.args.get("email")
    if new_email:
        with get_db_connection() as conn:
            conn.execute("UPDATE users SET email = ? WHERE id = ?",
                         (new_email, session["user_id"]))
        record_vulnerability_found(session["user_id"], "CSRF", 80)
        flash("🎉 CSRF via GET Successful! Email updated without validation. +80 points", "achievements")
        return redirect("/profile")
    return "Provide email query param, e.g., /csrf-change-email?email=hacked@evil.com"

@app.route("/brute-force-demo", methods=["GET", "POST"])
def brute_force_demo():
    # Feature removed: guide users to the AI chatbot instead
    return redirect(url_for('dashboard'))

@app.route("/clickjacking-demo")
def clickjacking_demo():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("clickjacking_demo.html")

@app.route("/ssrf-demo", methods=["GET", "POST"])
def ssrf_demo():
    if "user_id" not in session:
        return redirect("/login")
    
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            # SSRF vulnerability - intentionally supports file:// and http(s) without validation
            try:
                parsed = urlparse(url)
                if parsed.scheme == 'file':
                    # Handle file scheme for both Unix and Windows
                    # Example: file:///etc/hosts or file:///C:/Windows/System32/drivers/etc/hosts
                    local_path = unquote(parsed.path)
                    if platform.system().lower().startswith('win') and local_path.startswith('/') and len(local_path) > 3 and local_path[2] == ':':
                        # Strip leading slash for Windows drive letters
                        local_path = local_path.lstrip('/')
                    with open(local_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    record_vulnerability_found(session["user_id"], "SSRF", 90)
                    flash(f"🎉 SSRF File Read Successful! Fetched: {local_path} +90 points", "achievements")
                    return f"<h2>SSRF File Response:</h2><pre>{content[:2000]}</pre>"
                else:
                    import requests
                    response = requests.get(url, timeout=5)
                    record_vulnerability_found(session["user_id"], "SSRF", 90)
                    flash(f"🎉 SSRF Attack Successful! Fetched: {url} +90 points", "achievements")
                    return f"<h2>SSRF Response:</h2><pre>{response.text[:2000]}</pre>"
            except Exception as e:
                return f"Error: {str(e)}"
    
    return render_template("ssrf_demo.html")

@app.route("/xxe-demo", methods=["GET", "POST"])
def xxe_demo():
    if "user_id" not in session:
        return redirect("/login")
    
    if request.method == "POST":
        xml_data = request.form.get("xml_data")
        if xml_data:
            # XXE vulnerability - no XML validation
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(xml_data)
                record_vulnerability_found(session["user_id"], "XXE", 85)
                flash("🎉 XXE Attack Successful! XML parsed without validation. +85 points", "achievements")
                return f"<h2>XXE Response:</h2><pre>{ET.tostring(root, encoding='unicode')}</pre>"
            except Exception as e:
                return f"Error: {str(e)}"
    
    return render_template("xxe_demo.html")

@app.route("/deserialization-demo", methods=["GET", "POST"])
def deserialization_demo():
    if "user_id" not in session:
        return redirect("/login")
    
    if request.method == "POST":
        data = request.form.get("serialized_data")
        if data:
            # Insecure deserialization vulnerability
            try:
                import pickle
                import base64
                decoded_data = base64.b64decode(data)
                obj = pickle.loads(decoded_data)
                record_vulnerability_found(session["user_id"], "DESERIALIZATION", 95)
                flash("🎉 Deserialization Attack Successful! +95 points", "achievements")
                return f"<h2>Deserialized Object:</h2><pre>{str(obj)}</pre>"
            except Exception as e:
                return f"Error: {str(e)}"
    
    return render_template("deserialization_demo.html")

@app.route("/race-condition-demo", methods=["GET", "POST"])
def race_condition_demo():
    if "user_id" not in session:
        return redirect("/login")
    
    if request.method == "POST":
        # Race condition vulnerability - no proper locking
        import time
        import random
        time.sleep(random.uniform(0.05, 0.2))  # Simulate variable processing delay
        
        try:
            with get_db_connection() as conn:
                # Simulate a race condition in account balance update
                # This demonstrates the vulnerability without causing database locks
                current_balance = conn.execute("SELECT balance FROM user_stats WHERE user_id = ?", 
                                            (session["user_id"],)).fetchone()
                
                if not current_balance:
                    # Initialize balance if not exists
                    conn.execute("INSERT INTO user_stats (user_id, balance) VALUES (?, 100)", 
                               (session["user_id"],))
                    balance = 100
                else:
                    # Simulate race condition by reading, processing, then writing
                    balance = current_balance[0] + 10  # Add 10 points
                    conn.execute("UPDATE user_stats SET balance = ? WHERE user_id = ?", 
                               (balance, session["user_id"]))
                
                # Record the race condition attempt
                record_vulnerability_found(session["user_id"], "RACE_CONDITION", 70)
                flash(f"🎉 Race Condition Exploited! Balance updated to {balance}. +70 points", "achievements")
                return f"<h2>Race Condition Demo:</h2><p>Balance: {balance}</p><p><em>Try clicking rapidly to see race conditions!</em></p>"
                
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                # This is actually demonstrating a race condition!
                record_vulnerability_found(session["user_id"], "RACE_CONDITION", 70)
                flash("🎉 Race Condition Detected! Database locked due to concurrent access. +70 points", "achievements")
                return f"<h2>Race Condition Demo:</h2><p>Database locked! This demonstrates a race condition where multiple requests tried to access the database simultaneously.</p><p><strong>This is exactly what race conditions look like in real applications!</strong></p>"
            else:
                raise e
    
    return render_template("race_condition_demo.html")


# Information Disclosure Routes (Intentionally Vulnerable)
@app.route("/admin")
def admin_info():
    # No authentication/authorization – exposes critical data
    info_sections = []
    info_sections.append(("App Secrets", {
        "secret_key": app.secret_key,
        "database": DB_NAME,
        "upload_folder": app.config.get("UPLOAD_FOLDER"),
    }))

    info_sections.append(("System", {
        "cwd": os.getcwd(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "executable": sys.executable,
        "env_sample": {k: os.environ.get(k) for k in list(os.environ.keys())[:20]},
    }))

    # Dump users and stats (plaintext passwords!)
    with get_db_connection() as conn:
        users = conn.execute("SELECT id, username, email, password FROM users").fetchall()
        posts_count = conn.execute("SELECT COUNT(*) as c FROM posts").fetchone()[0]
        stats = conn.execute("SELECT user_id, total_points, level FROM user_stats").fetchall()

    user_lines = [f"{u['id']}: {u['username']} | {u['email']} | password={u['password']}" for u in users]
    stat_lines = [f"user_id={s['user_id']} total_points={s['total_points']} level={s['level']}" for s in stats]
    info_sections.append(("Database Dump", {
        "users": "\n".join(user_lines) if users else "<no users>",
        "posts_count": posts_count,
        "user_stats": "\n".join(stat_lines) if stats else "<no stats>",
    }))

    # Render as simple HTML
    html_parts = ["<h2>/admin - Sensitive Information (DO NOT EXPOSE)</h2>"]
    for title, data in info_sections:
        html_parts.append(f"<h3>{title}</h3>")
        html_parts.append("<pre>" + str(data) + "</pre>")
    return "\n".join(html_parts)


@app.route("/debug")
def debug_info():
    # Dump request, headers, session, and app config
    details = {
        "request": {
            "method": request.method,
            "url": request.url,
            "remote_addr": request.remote_addr,
            "args": request.args.to_dict(flat=False),
            "form": request.form.to_dict(flat=False),
            "headers": {k: v for k, v in request.headers.items()},
            "cookies": request.cookies,
        },
        "session": dict(session),
        "app_config_sample": {k: str(v) for k, v in list(app.config.items())[:25]},
        "sys_path_head": sys.path[:10],
    }
    return """
    <h2>/debug - Request & Runtime Context</h2>
    <h3>Details</h3>
    <pre>{}</pre>
    """.format(details)


@app.route("/test")
def test_info():
    # Show versions, installed packages, files, and sample source
    packages = []
    if pkg_resources:
        try:
            packages = sorted([f"{d.project_name}=={d.version}" for d in pkg_resources.working_set])
        except Exception:
            packages = []

    requirements_txt = None
    try:
        with open("requirements.txt", "r", encoding="utf-8") as f:
            requirements_txt = f.read()
    except Exception:
        requirements_txt = "<requirements.txt not readable>"

    files_root = []
    try:
        files_root = os.listdir('.')[:100]
    except Exception:
        files_root = []

    snippet = None
    try:
        with open(__file__, "r", encoding="utf-8") as f:
            snippet = "\n".join(f.read().splitlines()[:80])
    except Exception:
        snippet = "<source not readable>"

    html = [
        "<h2>/test - Environment & Sources</h2>",
        "<h3>Versions</h3>",
        f"<pre>Flask: {Flask.__version__ if hasattr(Flask, '__version__') else 'N/A'}\nPython: {platform.python_version()}\nSQLite: {sqlite3.sqlite_version}</pre>",
        "<h3>Installed Packages</h3>",
        "<pre>" + ("\n".join(packages) if packages else "<unknown>") + "</pre>",
        "<h3>requirements.txt</h3>",
        "<pre>" + requirements_txt + "</pre>",
        "<h3>Project Files (root)</h3>",
        "<pre>" + "\n".join(files_root) + "</pre>",
        "<h3>Application Source (head)</h3>",
        "<pre>" + snippet + "</pre>",
    ]
    return "\n".join(html)

if __name__ == "__main__":
    app.run(debug=True)
