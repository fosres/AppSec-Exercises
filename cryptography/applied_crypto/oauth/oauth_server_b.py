#!/usr/bin/env python3
"""
OAuth 2.0 Identity Provider - Implementation B
Supports public clients (mobile apps, SPAs) with PKCE

Features:
- PKCE support (RFC 7636)
- Refresh token rotation
- Scope management
- Multi-client support

Run: python3 oauth_server_b.py
Port: 5002
"""

from flask import Flask, request, redirect, jsonify
import secrets
import hashlib
import base64
import time

app = Flask(__name__)

codes = {}
tokens = {}
refresh_tokens = {}

clients = {
	'ios-app-v2': {
		'type': 'public',
		'redirect_uris': ['com.example.app://callback', 'http://localhost:8080/oauth'],
		'registered_scopes': ['read', 'write'],
		'name': 'iOS Application v2.0'
	},
	'android-app-v2': {
		'type': 'public',
		'redirect_uris': ['https://example.com/android/callback'],
		'registered_scopes': ['read', 'write', 'admin'],
		'name': 'Android Application v2.0'
	},
	'web-client-001': {
		'type': 'confidential',
		'client_secret': 'web_secret_abc',
		'redirect_uris': ['https://web.example.com/callback'],
		'registered_scopes': ['read', 'write', 'delete'],
		'name': 'Web Client 001'
	}
}

@app.route('/')
def index():
	return """
	<h1>OAuth 2.0 Identity Provider B</h1>
	<p>Supports PKCE for mobile and SPA clients</p>
	<h2>Endpoints:</h2>
	<ul>
		<li>GET /authorize - Start OAuth flow</li>
		<li>POST /token - Get access token</li>
		<li>POST /token/refresh - Refresh access token</li>
		<li>GET /resource/data - Protected API</li>
	</ul>
	<h2>Public Clients:</h2>
	<ul>
		<li>ios-app-v2 (PKCE enabled)</li>
		<li>android-app-v2 (PKCE enabled)</li>
	</ul>
	"""

@app.route('/authorize')
def authorize():
	"""Authorization endpoint"""
	client_id = request.args.get('client_id')
	redirect_uri = request.args.get('redirect_uri')
	scope = request.args.get('scope', 'read')
	state = request.args.get('state', '')
	code_challenge = request.args.get('code_challenge')
	code_challenge_method = request.args.get('code_challenge_method', 'plain')
	
	client = clients.get(client_id)
	if not client:
		return jsonify({'error': 'invalid_client'}), 400
	
	# VULNERABILITY: Redirect URI validation checks if registered URI is substring
	valid = False
	for registered in client['redirect_uris']:
		if registered in redirect_uri:
			valid = True
			break
	
	if not valid:
		# VULNERABILITY: Returns redirect for invalid URI
		return redirect(f"{redirect_uri}?error=invalid_redirect_uri&state={state}")
	
	# VULNERABILITY: PKCE not required for public clients
	# Should enforce: if client['type'] == 'public' and not code_challenge: error
	
	# VULNERABILITY: Accepts 'plain' code_challenge_method
	# Should only accept 'S256'
	if code_challenge_method not in ['plain', 'S256']:
		return jsonify({'error': 'invalid_request'}), 400
	
	# VULNERABILITY: No scope validation against registered scopes
	# Should check: requested_scopes ⊆ client['registered_scopes']
	
	# Auto-approve
	code = secrets.token_urlsafe(32)
	codes[code] = {
		'client_id': client_id,
		'redirect_uri': redirect_uri,
		'scope': scope,
		'user_id': 'user_abc',
		'created_at': time.time(),
		'code_challenge': code_challenge,
		'code_challenge_method': code_challenge_method
	}
	
	return redirect(f"{redirect_uri}?code={code}&state={state}")

@app.route('/token', methods=['POST'])
def token():
	"""Token endpoint"""
	grant_type = request.form.get('grant_type')
	code = request.form.get('code')
	client_id = request.form.get('client_id')
	client_secret = request.form.get('client_secret')
	redirect_uri = request.form.get('redirect_uri')
	code_verifier = request.form.get('code_verifier')
	
	if grant_type != 'authorization_code':
		return jsonify({'error': 'unsupported_grant_type'}), 400
	
	client = clients.get(client_id)
	if not client:
		return jsonify({'error': 'invalid_client'}), 401
	
	# VULNERABILITY: Confidential client auth not enforced
	if client['type'] == 'confidential':
		if client_secret != client.get('client_secret'):
			return jsonify({'error': 'invalid_client'}), 401
	
	code_data = codes.get(code)
	if not code_data:
		return jsonify({'error': 'invalid_grant'}), 400
	
	# VULNERABILITY: PKCE validation weak - doesn't reject missing verifier
	if code_data.get('code_challenge'):
		if code_verifier:
			method = code_data.get('code_challenge_method', 'plain')
			
			if method == 'S256':
				computed = base64.urlsafe_b64encode(
					hashlib.sha256(code_verifier.encode()).digest()
				).decode().rstrip('=')
				
				# VULNERABILITY: Validation check exists but doesn't enforce
				if computed != code_data['code_challenge']:
					# Should return error, but continues
					pass
			
			elif method == 'plain':
				# VULNERABILITY: Plain method accepted
				if code_verifier != code_data['code_challenge']:
					# Should return error
					pass
	
	# VULNERABILITY: Code not deleted after use
	
	# VULNERABILITY: No code expiration check
	
	# Generate tokens
	access_token = secrets.token_urlsafe(32)
	refresh_token_value = secrets.token_urlsafe(32)
	
	tokens[access_token] = {
		'user_id': code_data['user_id'],
		'scope': code_data['scope'],
		'client_id': client_id,
		'created_at': time.time(),
		'expires_at': time.time() + 3600
	}
	
	refresh_tokens[refresh_token_value] = {
		'user_id': code_data['user_id'],
		'scope': code_data['scope'],
		'client_id': client_id,
		'access_token': access_token
	}
	
	return jsonify({
		'access_token': access_token,
		'token_type': 'Bearer',
		'expires_in': 3600,
		'refresh_token': refresh_token_value,
		'scope': code_data['scope']
	})

@app.route('/token/refresh', methods=['POST'])
def refresh():
	"""Refresh token endpoint"""
	grant_type = request.form.get('grant_type')
	refresh_token_value = request.form.get('refresh_token')
	client_id = request.form.get('client_id')
	
	if grant_type != 'refresh_token':
		return jsonify({'error': 'unsupported_grant_type'}), 400
	
	rt_data = refresh_tokens.get(refresh_token_value)
	if not rt_data:
		return jsonify({'error': 'invalid_grant'}), 400
	
	# VULNERABILITY: Refresh token not rotated
	# Should generate new refresh token and invalidate old one
	
	# VULNERABILITY: No client validation on refresh
	# Should verify: rt_data['client_id'] == client_id
	
	new_access_token = secrets.token_urlsafe(32)
	
	tokens[new_access_token] = {
		'user_id': rt_data['user_id'],
		'scope': rt_data['scope'],
		'client_id': rt_data['client_id'],
		'created_at': time.time(),
		'expires_at': time.time() + 3600
	}
	
	return jsonify({
		'access_token': new_access_token,
		'token_type': 'Bearer',
		'expires_in': 3600,
		'refresh_token': refresh_token_value  # Same token!
	})

@app.route('/resource/data')
def protected_resource():
	"""Protected resource endpoint"""
	auth_header = request.headers.get('Authorization', '')
	
	if not auth_header.startswith('Bearer '):
		return jsonify({'error': 'unauthorized'}), 401
	
	token = auth_header.split(' ')[1]
	token_data = tokens.get(token)
	
	if not token_data:
		return jsonify({'error': 'invalid_token'}), 401
	
	# VULNERABILITY: Token expiration checked but not enforced
	if time.time() > token_data.get('expires_at', 0):
		# Should return error, but continues
		pass
	
	# VULNERABILITY: No scope enforcement
	# Should check if required scope is in token_data['scope']
	
	return jsonify({
		'user_id': token_data['user_id'],
		'data': 'sensitive information',
		'scope': token_data['scope']
	})

if __name__ == '__main__':
	print("=" * 70)
	print("OAuth 2.0 Identity Provider B")
	print("=" * 70)
	print(f"Starting on http://localhost:5002")
	print("=" * 70)
	app.run(port=5002, debug=True)
