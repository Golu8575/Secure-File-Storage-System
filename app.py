# ================= IMPORTS =================
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_file, abort
)
import os, sqlite3, random, time, secrets, io
import smtplib
from email.mime.text import MIMEText

from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ================= APP INIT =================
app = Flask(__name__)

# ================= SECRET KEY =================
app.secret_key = "e6d9d45a7061a7f13f12b0eca6f47c9b89ec12864ac78534eebf1c1a8038fade"

# ================= SESSION SECURITY =================
# NOTE: Do NOT use SESSION_COOKIE_SECURE=True on localhost
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

# ================= UPLOAD SIZE LIMIT (DoS Protection) =================
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB

# ================= RATE LIMITING (OWASP A7) =================
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"
)
limiter.init_app(app)

# ================= EMAIL CONFIG =================
SENDER_EMAIL = "satyamsinghmcps696@gmail.com"
SENDER_PASSWORD = "mjiv aamz rwkb dpcv"

# ================= FILE CONFIG =================
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ================= AES-256 KEY =================
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as f:
        f.write(Fernet.generate_key())

with open("secret.key", "rb") as f:
    cipher = Fernet(f.read())

# ================= DATABASE =================
def get_db():
    return sqlite3.connect("users.db", timeout=10)

# ================= HELPERS =================
def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_otp():
    return str(random.randint(100000, 999999))

def send_email_otp(email, otp):
    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "OTP Verification"
    msg["From"] = SENDER_EMAIL
    msg["To"] = email

    server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
    server.login(SENDER_EMAIL, SENDER_PASSWORD)
    server.send_message(msg)
    server.quit()

# ================= SECURITY HEADERS (OWASP A5) =================
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# ================= HOME =================
@app.route("/")
def home():
    if "user" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("upload"))

# ================= REGISTER =================
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        otp = generate_otp()
        hashed_pw = generate_password_hash(password)

        try:
            with get_db() as db:
                cur = db.cursor()
                cur.execute(
                    "INSERT INTO users (email, password, otp, is_verified) VALUES (?, ?, ?, 0)",
                    (email, hashed_pw, otp)
                )
                db.commit()

            send_email_otp(email, otp)
            return redirect(url_for("verify", email=email))

        except sqlite3.IntegrityError:
            return "User already exists ❌"

    return render_template("register.html")

# ================= VERIFY OTP =================
@app.route("/verify", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def verify():
    email = request.args.get("email")

    if request.method == "POST":
        otp = request.form["otp"]

        with get_db() as db:
            cur = db.cursor()
            cur.execute("SELECT otp FROM users WHERE email=?", (email,))
            row = cur.fetchone()

            if row and row[0] == otp:
                cur.execute(
                    "UPDATE users SET is_verified=1 WHERE email=?",
                    (email,)
                )
                db.commit()
                return redirect(url_for("login"))
            else:
                return "Invalid OTP ❌"

    return render_template("verify.html", email=email)

# ================= LOGIN =================
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        with get_db() as db:
            cur = db.cursor()
            cur.execute(
                "SELECT password, is_verified FROM users WHERE email=?",
                (email,)
            )
            user = cur.fetchone()

        if user and user[1] == 1 and check_password_hash(user[0], password):
            session.clear()  # OWASP A2
            session["user"] = email
            return redirect(url_for("upload"))

        return "Login failed ❌"

    return render_template("login.html")

# ================= UPLOAD (OWASP A1, A3) =================
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        return redirect(url_for("login"))

    user_folder = os.path.join(UPLOAD_FOLDER, session["user"])
    os.makedirs(user_folder, exist_ok=True)

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            abort(400)

        filename = secure_filename(file.filename)

        if not allowed_file(filename):
            return "Invalid file type ❌"

        encrypted_data = cipher.encrypt(file.read())
        path = os.path.join(user_folder, filename + ".enc")

        with open(path, "wb") as f:
            f.write(encrypted_data)

        return redirect(url_for("upload"))

    files = os.listdir(user_folder)
    return render_template("upload.html", files=files)

# ================= DOWNLOAD =================
@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        abort(403)

    path = os.path.join(UPLOAD_FOLDER, session["user"], filename)
    if not os.path.exists(path):
        abort(404)

    with open(path, "rb") as f:
        decrypted = cipher.decrypt(f.read())

    return send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=filename.replace(".enc", "")
    )

# ================= SHARE WITH EXPIRY =================
@app.route("/share/<filename>")
def share(filename):
    if "user" not in session:
        abort(403)

    token = secrets.token_urlsafe(32)
    expiry = int(time.time()) + 600  # 10 minutes

    conn = sqlite3.connect("share_links.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO share_links VALUES (NULL, ?, ?, ?)",
        (session["user"] + "/" + filename, token, expiry)
    )
    conn.commit()
    conn.close()

    return f"Share link (10 min): http://localhost/shared/{token}"

# ================= ACCESS SHARED FILE =================
@app.route("/shared/<token>")
def shared(token):
    now = int(time.time())

    conn = sqlite3.connect("share_links.db")
    cur = conn.cursor()
    cur.execute("SELECT filename, expiry FROM share_links WHERE token=?", (token,))
    row = cur.fetchone()
    conn.close()

    if not row or now > row[1]:
        abort(403)

    path = os.path.join(UPLOAD_FOLDER, row[0])
    with open(path, "rb") as f:
        decrypted = cipher.decrypt(f.read())

    return send_file(
        io.BytesIO(decrypted),
        as_attachment=True,
        download_name=os.path.basename(path).replace(".enc", "")
    )

# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

