#!/usr/bin/env python3
"""
OAuth 2.0 Authorization Server - Implementation A
Production-grade OAuth 2.0 server for educational purposes

Features:
- Authorization Code Grant flow
- Client authentication
- Token management
- Scope-based access control

Run: python3 oauth_server_a.py
Port: 5001
"""

from flask import Flask, request, redirect, jsonify, render_template_string
import secrets
import time
import hashlib

app = Flask(__name__)

# Data stores
authorization_codes = {}
access_tokens = {}
clients = {
	'webapp-client-001': {
		'client_secret': 'prod_secret_2024',
		'redirect_uris': [
			'https://webapp.example.com/auth/callback',
			'https://webapp.example.com/oauth/complete'
		],
		'allowed_scopes': ['profile', 'email', 'contacts'],
		'name': 'WebApp Production Client'
	},
	'mobile-app-002': {
		'client_type': 'public',
		'redirect_uris': ['myapp://oauth/callback'],
		'allowed_scopes': ['profile', 'email'],
		'name': 'Mobile App Client'
	}
}

AUTHORIZATION_PAGE = """
<!DOCTYPE html>
<html>
<head>
	<title>Authorize Application</title>
	<style>
		body { font-family: Arial; max-width: 500px; margin: 50px auto; }
		.auth-box { border: 1px solid #ddd; padding: 20px; border-radius: 5px; }
		button { padding: 10px 20px; margin: 5px; }
		.approve { background: #4CAF50; color: white; border: none; }
		.deny { background: #f44336; color: white; border: none; }
	</style>
</head>
<body>
	<div class="auth-box">
		<h2>Authorize {{ app_name }}</h2>
		<p>This application is requesting access to:</p>
		<ul>
			{% for scope in scopes %}
			<li>{{ scope }}</li>
			{% endfor %}
		</ul>
		<form method="POST" action="/oauth/approve">
			<input type="hidden" name="client_id" value="{{ client_id }}">
			<input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
			<input type="hidden" name="scope" value="{{ scope_str }}">
			<input type="hidden" name="response_type" value="{{ response_type }}">
			<button type="submit" name="action" value="approve" class="approve">Approve</button>
			<button type="submit" name="action" value="deny" class="deny">Deny</button>
		</form>
	</div>
</body>
</html>
"""

@app.route('/')
def index():
	return """
	<h1>OAuth 2.0 Authorization Server A</h1>
	<p>Production OAuth implementation for secure client authentication.</p>
	<h2>Endpoints:</h2>
	<ul>
		<li>GET /oauth/authorize - Authorization endpoint</li>
		<li>POST /oauth/approve - User approval</li>
		<li>POST /oauth/token - Token endpoint</li>
		<li>GET /api/userinfo - Protected resource</li>
	</ul>
	<h2>Test Client Credentials:</h2>
	<ul>
		<li><b>Client ID:</b> webapp-client-001</li>
		<li><b>Client Secret:</b> prod_secret_2024</li>
		<li><b>Redirect URI:</b> https://webapp.example.com/auth/callback</li>
	</ul>
	<a href="/oauth/authorize?client_id=webapp-client-001&redirect_uri=https://webapp.example.com/auth/callback&response_type=code&scope=profile+email">
		Test Authorization Flow
	</a>
	"""

@app.route('/oauth/authorize')
def authorize():
	"""Authorization endpoint - initiates OAuth flow"""
	client_id = request.args.get('client_id')
	redirect_uri = request.args.get('redirect_uri')
	response_type = request.args.get('response_type', 'code')
	scope = request.args.get('scope', 'profile')
	state = request.args.get('state', '')
	
	# Validate client exists
	client = clients.get(client_id)
	if not client:
		# VULNERABILITY: Returns redirect instead of HTTP 400
		if redirect_uri:
			return redirect(f"{redirect_uri}?error=invalid_client&error_description=Unknown+client")
		return jsonify({'error': 'invalid_client'}), 400
	
	# VULNERABILITY: Weak redirect_uri validation
	# Uses startswith() instead of exact match
	uri_valid = False
	for registered_uri in client['redirect_uris']:
		if redirect_uri.startswith(registered_uri.split('://')[0]):
			uri_valid = True
			break
	
	if not uri_valid:
		return jsonify({'error': 'invalid_redirect_uri'}), 400
	
	# VULNERABILITY: State parameter optional (not enforced)
	# Should require state for CSRF protection
	
	# Show authorization page
	scopes = scope.split()
	return render_template_string(
		AUTHORIZATION_PAGE,
		client_id=client_id,
		app_name=client.get('name', 'Unknown Application'),
		redirect_uri=redirect_uri,
		scope_str=scope,
		scopes=scopes,
		response_type=response_type
	)

@app.route('/oauth/approve', methods=['POST'])
def approve():
	"""Handle user approval/denial"""
	client_id = request.form.get('client_id')
	redirect_uri = request.form.get('redirect_uri')
	scope = request.form.get('scope', 'profile')
	action = request.form.get('action')
	
	if action != 'approve':
		return redirect(f"{redirect_uri}?error=access_denied")
	
	# VULNERABILITY: No CSRF protection on approval form
	
	# Generate authorization code
	# VULNERABILITY: Uses MD5 hash (predictable)
	code_seed = f"{client_id}{time.time()}"
	code = hashlib.md5(code_seed.encode()).hexdigest()
	
	authorization_codes[code] = {
		'client_id': client_id,
		'redirect_uri': redirect_uri,
		'scope': scope,
		'user_id': 'user_12345',
		'created_at': time.time()
	}
	
	return redirect(f"{redirect_uri}?code={code}")

@app.route('/oauth/token', methods=['POST', 'GET'])
def token():
	"""Token endpoint - exchange code for access token"""
	
	# VULNERABILITY: Accepts GET requests (client_secret in URL)
	code = request.values.get('code')
	client_id = request.values.get('client_id')
	client_secret = request.values.get('client_secret')
	redirect_uri = request.values.get('redirect_uri')
	
	# Validate client
	client = clients.get(client_id)
	if not client:
		return jsonify({'error': 'invalid_client'}), 401
	
	# VULNERABILITY: Client authentication not enforced for confidential clients
	if client.get('client_secret'):
		if not client_secret:
			# Should reject, but continues
			pass
		elif client['client_secret'] != client_secret:
			# VULNERABILITY: Non-constant-time comparison
			time.sleep(0.01 * len(client['client_secret']))
			return jsonify({'error': 'invalid_client'}), 401
	
	# Validate authorization code
	code_data = authorization_codes.get(code)
	if not code_data:
		return jsonify({'error': 'invalid_grant'}), 400
	
	# VULNERABILITY: Authorization code not deleted (reusable)
	# Should: del authorization_codes[code]
	
	# VULNERABILITY: No code expiration check
	# Should check: time.time() - code_data['created_at'] > 60
	
	# VULNERABILITY: redirect_uri not validated (no binding)
	# Should check: code_data['redirect_uri'] == redirect_uri
	
	# Generate access token
	token_value = secrets.token_urlsafe(32)
	access_tokens[token_value] = {
		'user_id': code_data['user_id'],
		'scope': code_data['scope'],
		'client_id': client_id,
		'created_at': time.time()
	}
	
	return jsonify({
		'access_token': token_value,
		'token_type': 'Bearer',
		'expires_in': 3600,
		'scope': code_data['scope']
	})

@app.route('/api/userinfo')
def userinfo():
	"""Protected resource - returns user information"""
	
	# VULNERABILITY: Accepts token in URL parameter
	auth_header = request.headers.get('Authorization', '')
	token = None
	
	if auth_header.startswith('Bearer '):
		token = auth_header.split(' ')[1]
	elif request.args.get('access_token'):
		token = request.args.get('access_token')
	
	if not token:
		return jsonify({'error': 'missing_token'}), 401
	
	token_data = access_tokens.get(token)
	if not token_data:
		return jsonify({'error': 'invalid_token'}), 401
	
	# VULNERABILITY: No token expiration enforcement
	# Should check: time.time() - token_data['created_at'] > 3600
	
	return jsonify({
		'sub': token_data['user_id'],
		'name': 'Test User',
		'email': 'test@example.com',
		'scope': token_data['scope']
	})

@app.route('/debug/stats')
def debug_stats():
	"""Debug endpoint showing server statistics"""
	# VULNERABILITY: Information disclosure
	return jsonify({
		'active_codes': len(authorization_codes),
		'active_tokens': len(access_tokens),
		'registered_clients': len(clients),
		'server_version': '2.4.1',
		'python_version': '3.11.2'
	})

if __name__ == '__main__':
	print("=" * 70)
	print("OAuth 2.0 Authorization Server A")
	print("=" * 70)
	print(f"Starting on http://localhost:5001")
	print("=" * 70)
	app.run(port=5001, debug=True)
