# Security Mechanisms - Lab Application

This application has been fortified with core security mechanisms to resolve standard Quality Gate checks (Vulnerabilities, Bugs, Security Hotspots). 

Below are the 5 core Security Mechanisms cleanly documented alongside their exact code implementation snippets natively from `app.py`.

## Mechanism 1: Secure Session Management
* **Objective:** Ensure the Flask application generates unpredictable session cookies and implements secure flags (HttpOnly, SameSite) to prevent unauthorized extraction or tracking.
* **Code Snippet:**
```python
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)
```

## Mechanism 2: Defensive Security Headers
* **Objective:** Protect against Clickjacking, MIME-Type Sniffing, and Cross-Site Injections utilizing structured HTTP Headers across all application responses.
* **Code Snippet:**
```python
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline'; img-src 'self' https://api.qrserver.com;"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response
```

## Mechanism 3: CSRF (Cross-Site Request Forgery) Prevention
* **Objective:** Ensure that state-changing `POST` requests cannot be implicitly performed by malicious third-party websites leveraging the ambient browser session.
* **Code Snippet:**
```python
def validate_csrf(req_form):
    token = session.get('csrf_token')
    if not token or token != req_form.get('csrf_token'):
        abort(403, description="CSRF token validation failed")

# Usage inside GET routes to append token to DOM
if 'csrf_token' not in session:
    session['csrf_token'] = secrets.token_hex(16)
```

## Mechanism 4: SQL Injection (SQLi) Prevention
* **Objective:** Prevent malicious input arguments from altering arbitrary backend SQLite database queries logic by strictly parameterizing database structures.
* **Code Snippet:**
```python
def authenticate_user(username, password):
    # Parameterized query strictly forces data to evaluate without mutating DB commands
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE username=?", (username,))
    result = cur.fetchone()
    
    if result and check_password_hash(result[0], password):
        return True
    return False
```

## Mechanism 5: Two-Factor Authentication (2FA) Implementation
* **Objective:** Add a secondary layer of authentication using Time-Based One-Time Passwords (TOTP) to protect user accounts dynamically even if base passwords are compromised.
* **Code Snippet:**
```python
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
```
