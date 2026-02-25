# OAuth Client - Callback Endpoint
from flask import Flask, request, session, redirect
import requests
import os

app = Flask(__name__)

# Using os.urandom() is not best. 

# It is wiser to use the secrets module directly
app.secret_key = os.urandom(24)

CLIENT_ID = "my-app-12345"

# Do NOT hardcode CLIENT SECRETS
CLIENT_SECRET = "super-secret-key-abc123"
REDIRECT_URI = "https://myapp.com/oauth/callback"
TOKEN_URL = "https://accounts.google.com/o/oauth2/token"

# No CSRF protection at Callback endpoint.

# To mitigate this the `oauth_callback` should

# check if a `state` parameter matches what

# was expected.

# For a great example of a secure callback see

# Appendix B: Extended Code Listings: page 311

@app.route('/oauth/callback')
def oauth_callback():
	
	# No Redirect URI Validation before receiving authorization code

	# No attempt at Proof Key of Code Exchange. This makes

	# OAuth vulnerable to authorization code interception

	# attack.

	# Get authorization code from Google
	code = request.args.get('code')
	

	# Not a security bug but headers must be present

	# to tell the server this is an HTTP form-encoded

	# request ( OAuth2 in Action page 49).

	headers = {
			'Content-Type': 'application/x-www-form-urlencoded',
			'Authorization': 'Basic ' + encodeClientCredentials(client.client_id,client.client_secret)
	}
		
	# Exchange code for access token
	response = requests.post(TOKEN_URL,

		data={
			'grant_type': 'authorization_code',
			'code': code,
			'client_id': CLIENT_ID,
			'client_secret': CLIENT_SECRET,
			'redirect_uri': REDIRECT_URI
		},

		headers

	)

	# Parse token response
	
	# Best practice to have a refresh

	# token in case original access
		
	# token expires.
	
	token_data = response.json()

	access_token = token_data['access_token']
	
	# Store token in session
	session['oauth_token'] = access_token
	session['logged_in'] = True
	
	return redirect('/dashboard')

if __name__ == '__main__':
	app.run()

