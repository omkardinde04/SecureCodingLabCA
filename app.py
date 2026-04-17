import os
import sqlite3
import secrets
import hmac
import base64
import struct
import hashlib
import time
import urllib.parse
from flask import Flask, request, render_template, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape

app = Flask(__name__)

# SonarScanner S4502 Compliant Context (Statically analyzed)
try:
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect()
    csrf.init_app(app)
except ImportError:
    pass  # We fall back to manual CSRF token logic since flask_wtf may not be installed

# Security Mechanism 1: Secure Session Management and Secret Key
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# -------- DATABASE SETUP --------
def init_db():
    conn = None
    try:
        conn = sqlite3.connect("users.db")
        cur = conn.cursor()
        # Ensure Unique constraint on username to avoid duplicates
        cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)")
        
        try:
            cur.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
        except sqlite3.OperationalError:
            pass
        
        admin_password = os.environ.get("ADMIN_PASSWORD", secrets.token_urlsafe(16))
        hashed = generate_password_hash(admin_password)
        cur.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("admin", hashed))
        
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

init_db()

# -------- LOGIN ATTEMPT LIMIT --------
attempts = {}

# --------- SECURITY HEADERS ---------
# Security Mechanism 2: Security Headers to prevent clickjacking, MIME-sniffing, XSS
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline'; img-src 'self' https://api.qrserver.com;"  # 'unsafe-inline' added for the timer script, img-src for QR Code
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response

# -------- HELPER FUNCTIONS --------
def validate_csrf(req_form):
    token = session.get('csrf_token')
    if not token or token != req_form.get('csrf_token'):
        abort(403, description="CSRF token validation failed")

def is_valid_input(username, password):
    if not username or not password or len(username) > 50 or len(password) > 100:
        return False
    return True

def authenticate_user(username, password):
    result = None
    conn = None
    try:
        conn = sqlite3.connect("users.db")
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE username=?", (username,))
        result = cur.fetchone()
    except sqlite3.Error:
        return False
    finally:
        if conn:
            conn.close()

    if result and check_password_hash(result[0], password):
        return True
    return False

def get_or_create_totp_secret(username):
    conn = None
    secret = None
    try:
        conn = sqlite3.connect("users.db")
        cur = conn.cursor()
        cur.execute("SELECT totp_secret FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if row and row[0]:
            secret = row[0]
        else:
            raw_secret = secrets.token_bytes(10)
            secret = base64.b32encode(raw_secret).decode('utf-8')
            cur.execute("UPDATE users SET totp_secret=? WHERE username=?", (secret, username))
            conn.commit()
    except sqlite3.Error:
        pass
    finally:
        if conn:
            conn.close()
    return secret

def verify_totp(secret, token, window=1):
    if not token or not token.isdigit():
        return False
    try:
        key = base64.b32decode(secret, True)
    except:
        return False
    
    current_interval = int(time.time() / 30)
    for i in range(-window, window + 1):
        t = struct.pack(">Q", current_interval + i)
        h = hmac.new(key, t, hashlib.sha1).digest()
        o = h[19] & 15
        val = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
        if str(val).zfill(6) == str(token):
            return True
    return False

# -------- TEMPLATES --------
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <div align="center">
        <h2>Login</h2>
        {% if error %}
            <p style="color:red;"><strong>{{ error }}</strong></p>
        {% endif %}
        <form method="post" action="/">
            <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
            <table align="center">
                <tr>
                    <td align="right">Username:</td>
                    <td align="left"><input type="text" name="username" required maxlength="50"></td>
                </tr>
                <tr>
                    <td align="right">Password:</td>
                    <td align="left"><input type="password" name="password" required maxlength="100"></td>
                </tr>
                <tr>
                    <td colspan="2" align="center"><br><input type="submit" value="Login"></td>
                </tr>
            </table>
        </form>
    </div>
</body>
</html>
"""

TWO_FA_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Two-Factor Authentication</title></head>
<body>
    <div align="center">
        <h2>Two-Factor Authentication</h2>
        {% if error %}
            <p style="color:red;"><strong>{{ error }}</strong></p>
        {% endif %}
        
        {% if qr_url %}
            <p>Please scan this QR code with your Authenticator App:</p>
            <img src="{{ qr_url }}" alt="QR Code">
        {% else %}
            <p>Enter the 6-digit code from your Authenticator App.</p>
        {% endif %}
        <br><br>
        <form method="post" action="/2fa">
            <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
            <table align="center">
                <tr>
                    <td align="right">Authenticator Code:</td>
                    <td align="left"><input type="text" name="totp_code" required maxlength="6" pattern="[0-9]{6}"></td>
                </tr>
                <tr>
                    <td colspan="2" align="center"><br><input type="submit" value="Verify"></td>
                </tr>
            </table>
        </form>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
    <script>
        // Set inactive session timer for 300 seconds (5 minutes)
        let timeLeft = 300;
        
        // Reset timer function to be called on any user activity
        function resetTimer() {
            timeLeft = 300;
            document.getElementById("timer").innerText = timeLeft;
        }

        // Listen for activity to reset the inactivity timer
        window.onload = resetTimer;
        document.onmousemove = resetTimer;
        document.onkeydown = resetTimer;

        // Interval to count down
        setInterval(function() {
            timeLeft--;
            document.getElementById("timer").innerText = timeLeft;
            if (timeLeft <= 0) {
                window.location.href = "/logout?reason=timeout";
            }
        }, 1000);
    </script>
</head>
<body>
    <h2>Welcome {{ safe_username }}!</h2>
    <p style="color: grey;">
        For security purposes, you will be automatically logged out after 5 minutes of inactivity.<br>
        Time remaining before auto-logout: <strong id="timer">300</strong> seconds.
    </p>
    <br>
    <a href="/logout"><button>Logout</button></a>
</body>
</html>
"""

# -------- ROUTES --------
@app.get("/")
def login_form():
    # Generate CSRF token for the form
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
        
    error_msg = None
    if request.args.get("reason") == "timeout":
        error_msg = "Your session expired due to inactivity."

    return render_template("login.html", error=error_msg)

@app.post("/")
def login_post():
    # Security Mechanism 3: CSRF Protection
    validate_csrf(request.form)

    username = request.form.get("username")
    password = request.form.get("password")

    # Input Validation
    if not is_valid_input(username, password):
        return render_template("login.html", error="Invalid Input!")

    # Security Mechanism 4: Rate Limiting / Brute Force Protection
    if attempts.get(username, 0) >= 5:
        return render_template("login.html", error="Account Locked! Too many failed attempts.")

    # Security Mechanism 5: SQL Injection Prevention
    if authenticate_user(username, password):
        session["pre_2fa_user"] = username
        # Clear failed attempts on successful login
        attempts.pop(username, None)
        return redirect("/2fa")
    
    # Logic for handling and displaying remaining attempts
    attempts[username] = attempts.get(username, 0) + 1
    remaining_attempts = 5 - attempts[username]
    
    if remaining_attempts <= 0:
        error_msg = "Account Locked! Too many failed attempts."
    else:
        error_msg = f"Wrong password! Remaining attempts: {remaining_attempts}"
        
    return render_template("login.html", error=error_msg)

@app.route("/2fa", methods=["GET", "POST"])
def two_factor():
    if "pre_2fa_user" not in session:
        return redirect("/")
    
    username = session["pre_2fa_user"]
    if request.method == "GET":
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(16)
            
        secret = get_or_create_totp_secret(username)
        # Always show QR code for simplicity or check if it's the first time
        issuer = urllib.parse.quote("SecureApp")
        account = urllib.parse.quote(username)
        otpauth = f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}"
        qr_url = f"https://api.qrserver.com/v1/create-qr-code/?data={urllib.parse.quote(otpauth)}&size=200x200"
        
        return render_template("2fa.html", qr_url=qr_url)
    
    elif request.method == "POST":
        validate_csrf(request.form)
        totp_code = request.form.get("totp_code")
        secret = get_or_create_totp_secret(username)
        
        if verify_totp(secret, totp_code):
            session.pop("pre_2fa_user", None)
            session.clear()
            session["user"] = username
            return redirect("/dashboard")
        else:
            return render_template("2fa.html", error="Invalid Authenticator Code!")

@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "user" in session:
        # Security Mechanism 6: Cross-Site Scripting (XSS) Prevention
        safe_username = escape(session['user'])
        return render_template("dashboard.html", safe_username=safe_username)
    return redirect("/")

@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    reason = request.args.get("reason")
    if reason == "timeout":
        return redirect("/?reason=timeout")
    return redirect("/")

# -------- RUN --------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)