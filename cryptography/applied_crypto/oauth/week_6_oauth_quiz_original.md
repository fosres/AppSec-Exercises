Question 1:

Vulnerable Code Snippet:

```
# OAuth Client - Callback Endpoint
from flask import Flask, request, session, redirect
import requests
import os

app = Flask(__name__)

# Using os.urandom() is not best. Keep in mind `os.urandom()`

# It is wiser to use the secrets module directly
app.secret_key = os.urandom(24)

CLIENT_ID = "my-app-12345"
CLIENT_SECRET = "super-secret-key-abc123"
REDIRECT_URI = "https://myapp.com/oauth/callback"
TOKEN_URL = "https://accounts.google.com/o/oauth2/token"

@app.route('/oauth/callback')
def oauth_callback():
	# Get authorization code from Google
	code = request.args.get('code')
	
	# Exchange code for access token
	response = requests.post(TOKEN_URL, data={
		'grant_type': 'authorization_code',
		'code': code,
		'client_id': CLIENT_ID,
		'client_secret': CLIENT_SECRET,
		'redirect_uri': REDIRECT_URI
	})
	
	# Parse token response
	token_data = response.json()
	access_token = token_data['access_token']
	
	# Store token in session
	session['oauth_token'] = access_token
	session['logged_in'] = True
	
	return redirect('/dashboard')

if __name__ == '__main__':
	app.run()
```

Vulnerabilities:

1. Not wise to use `os.urandom()` since it returns raw bytes. Coders

can forget or fail to properly convert these to proper data types

that the application needs to execute their tasks. So this is a

potential misuse of secret data issue. Use `secrets` module instead.

2. Do NOT hardcode `CLIENT_SECRET`. An attacker than can access the

file will steal the secret!

3. No Redirect URI Validation before receiving authorization code

nor before receiving access token.

4. No CSRF Protection for Callback Endpoint.

5. The client does not exercise Proof Key for Code Exchange. This

leaves OAuth vulnerable to authorization interception attack. 

Question 2:

```
# OAuth Authorization Server - Authorization & Token Endpoints
from flask import Flask, request, render_template, redirect
import secrets
import time

app = Flask(__name__)

# In-memory storage (production would use database)
codes = {}  # {code: {client_id, redirect_uri, expires_at, user_id}}
clients = {
	'oauth-client-1': {
		'client_secret': 'secret123',
		'redirect_uris': ['https://client.com/callback']
	}
}

@app.route('/authorize')
def authorize():
	client_id = request.args.get('client_id')
	redirect_uri = request.args.get('redirect_uri')
	scope = request.args.get('scope')
	state = request.args.get('state')
	
	# Validate client exists
	client = clients.get(client_id)
	if not client:
		return "Unknown client", 400
	
	# Show approval page to user
	# (Skipping user authentication for brevity)
	return render_template('approve.html',
		client_id=client_id,
		redirect_uri=redirect_uri,
		scope=scope,
		state=state)

@app.route('/approve', methods=['POST'])
def approve():
	client_id = request.form.get('client_id')
	redirect_uri = request.form.get('redirect_uri')
	state = request.form.get('state')
	approved = request.form.get('approved')
	
	if approved != 'yes':
		return redirect(f"{redirect_uri}?error=access_denied")
	
	# Generate authorization code
	code = secrets.token_urlsafe(32)
	codes[code] = {
		'client_id': client_id,
		'redirect_uri': redirect_uri,
		'expires_at': time.time() + 600,  # 10 minutes
		'user_id': 'user123'  # Hardcoded for example
	}
	
	# Redirect back to client
	redirect_url = f"{redirect_uri}?code={code}"
	if state:
		redirect_url += f"&state={state}"
	
	return redirect(redirect_url)

@app.route('/token', methods=['POST'])
def token():
	grant_type = request.form.get('grant_type')
	code = request.form.get('code')
	client_id = request.form.get('client_id')
	client_secret = request.form.get('client_secret')
	redirect_uri = request.form.get('redirect_uri')
	
	# Validate client credentials
	client = clients.get(client_id)
	if not client or client['client_secret'] != client_secret:
		return {'error': 'invalid_client'}, 401
	
	# Get code data
	code_data = codes.get(code)
	if not code_data:
		return {'error': 'invalid_grant'}, 400
	
	# Generate access token
	access_token = secrets.token_urlsafe(32)
	
	return {
		'access_token': access_token,
		'token_type': 'Bearer',
		'expires_in': 3600
	}

if __name__ == '__main__':
	app.run()
```

Question 3:

```
# Mobile App OAuth Client with PKCE
from flask import Flask, request, session, redirect, jsonify
import requests
import hashlib
import base64
import secrets
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

CLIENT_ID = "mobile-app-xyz"
# Note: Mobile apps are public clients - no client_secret
AUTH_URL = "https://oauth.provider.com/authorize"
TOKEN_URL = "https://oauth.provider.com/token"
REDIRECT_URI = "myapp://oauth/callback"

@app.route('/login')
def login():
	# Generate PKCE code verifier
	code_verifier = secrets.token_urlsafe(32)
	
	# Create code challenge (SHA256 hash)
	challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
	code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode().rstrip('=')
	
	# Store verifier in session
	session['code_verifier'] = code_verifier
	
	# Build authorization URL
	auth_params = {
		'client_id': CLIENT_ID,
		'redirect_uri': REDIRECT_URI,
		'response_type': 'code',
		'scope': 'read_profile read_email',
		'code_challenge': code_challenge,
		'code_challenge_method': 'S256'
	}
	
	auth_url = f"{AUTH_URL}?{'&'.join(f'{k}={v}' for k, v in auth_params.items())}"
	return redirect(auth_url)

@app.route('/oauth/callback')
def oauth_callback():
	# Get authorization code
	code = request.args.get('code')
	error = request.args.get('error')
	
	if error:
		return f"OAuth error: {error}", 400
	
	# Get code verifier from session
	code_verifier = session.get('code_verifier')
	
	# Exchange code for token
	token_response = requests.post(TOKEN_URL, data={
		'grant_type': 'authorization_code',
		'code': code,
		'client_id': CLIENT_ID,
		'redirect_uri': REDIRECT_URI,
		'code_verifier': code_verifier
	})
	
	if token_response.status_code != 200:
		return "Token exchange failed", 400
	
	token_data = token_response.json()
	
	# Store tokens
	session['access_token'] = token_data.get('access_token')
	session['refresh_token'] = token_data.get('refresh_token')
	
	# Get user info
	user_response = requests.get(
		'https://oauth.provider.com/userinfo',
		headers={'Authorization': f"Bearer {session['access_token']}"}
	)
	
	user_data = user_response.json()
	session['user_id'] = user_data['sub']
	session['email'] = user_data['email']
	
	return redirect('/dashboard')

@app.route('/api/user')
def api_user():
	# API endpoint to get current user
	access_token = session.get('access_token')
	
	if not access_token:
		return {'error': 'Not authenticated'}, 401
	
	return {
		'user_id': session.get('user_id'),
		'email': session.get('email')
	}

if __name__ == '__main__':
	app.run(debug=True)
```

**YOUR TASK:** Find at least 7 vulnerabilities. For each:
- Name the vulnerability
- Rate severity (Critical/High/Medium/Low)
- Explain exploitation scenario
- Provide detailed fix with code example

---

<details>
<summary>💡 HINT (click if you need help after 10 minutes)</summary>

Think about:
- What CSRF protection exists?
- What validation is missing on the code?
- What happens if code_verifier is missing?
- Session security issues?
- Error handling problems?
- API security concerns?
- Debug mode implications?

</details>

---

## 📝 **HOW TO SUBMIT YOUR ANSWERS**

**For each exercise, write your findings like this:**
```
EXERCISE 1 FINDINGS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VULNERABILITY 1: [Name]
Severity: [Critical/High/Medium/Low]
Location: [Line number or function]
Issue: [What's wrong]
Attack: [How to exploit]
Fix: [How to fix with code]

VULNERABILITY 2: [Name]
...
```
