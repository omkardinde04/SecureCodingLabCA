# Security Mechanisms & Test Cases - Lab Application

This application has been fortified with core security mechanisms to resolve standard Quality Gate checks (Vulnerabilities, Bugs, Security Hotspots). 

Below are the 5 core Security Mechanisms cleanly documented alongside their exact code implementation snippets natively from `app.py`, along with their individual test case verification steps.

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
* **Verification Steps (Test Case 1):**
  1. Login to the application.
  2. Inspect the browser's developer tools (Application -> Cookies).
  3. Verify that the `HttpOnly` flag is checked and `SameSite` is set to `Lax`.
  4. Verify you cannot access `document.cookie` via the developer console.

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
* **Verification Steps (Test Case 2):**
  1. Intercept the network response using a tool like Burp Suite or browser DevTools.
  2. Read the HTTP Response Headers.
  3. Ensure `X-Frame-Options: DENY` is present (meaning it cannot be embedded in an `<iframe>`).
  4. Ensure `Content-Security-Policy` and `Cache-Control` are correctly outputted.

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
* **Verification Steps (Test Case 3):**
  1. Open the login page.
  2. Modify the `csrf_token` value in the HTML DOM to an invalid string via Inspect Element.
  3. Submit the form.
  4. Verify that the server responds with a `403 Forbidden` corresponding to "CSRF token validation failed."

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
* **Verification Steps (Test Case 4):**
  1. Attempt to log in with the username parameter: `admin' OR '1'='1`.
  2. Submit any password.
  3. Verify that the login fails with "Invalid Credentials" because the inputs are parameterized as strings and do not alter the logic.

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
* **Verification Steps (Test Case 5):**
  1. Complete the initial login step with valid credentials.
  2. The application redirects you to `/2fa` and correctly displays an Authenticator App QR Code.
  3. Enter an invalid or expired code and confirm you get "Invalid Authenticator Code!".
  4. Enter the matching active code and confirm you are securely advanced to the `/dashboard`.
