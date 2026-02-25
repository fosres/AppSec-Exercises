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


3. No CSRF Protection for Callback Endpoint.

4. The client does not exercise Proof Key for Code Exchange. This

leaves OAuth vulnerable to authorization interception attack. 

5. No HTTP Strict Transport Layer Security
