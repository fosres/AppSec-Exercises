#!/usr/bin/env python3
"""
OAuth 2.0 Authentication Service - Implementation D
Enterprise OAuth provider with enhanced security features

Features:
- Client credential validation
- Token lifecycle management
- Security event logging
- Multi-tenant support

Run: python3 oauth_server_d.py
Port: 5004
"""

from flask import Flask, request, redirect, jsonify
import secrets
import time
import hmac
import hashlib

app = Flask(__name__)

codes = {}
tokens_storage = {}  # In-memory token storage
failed_auth_attempts = {}

clients = {
	'enterprise-app-001': {
		'client_secret': 'ent_prod_secret_2024',
		'redirect_uris': ['https://enterprise.example.com/oauth/callback'],
		'scopes': ['admin', 'read', 'write'],
		'name': 'Enterprise Application 001'
	},
	'partner-integration-002': {
		'client_secret': 'partner_key_abc123',
		'redirect_uris': ['https://partner.example.com/auth/complete'],
		'scopes': ['read', 'write'],
		'name': 'Partner Integration 002'
	}
}

@app.route('/')
def index():
	return """
	<h1>OAuth 2.0 Authentication Service D</h1>
	<p>Enterprise-grade OAuth provider</p>
	<h2>Endpoints:</h2>
	<ul>
		<li>GET /auth/authorize</li>
		<li>POST /auth/token</li>
		<li>GET /api/resource</li>
		<li>GET /introspect (token validation)</li>
	</ul>
	"""

@app.route('/auth/authorize')
def authorize():
	"""Authorization endpoint"""
	client_id = request.args.get('client_id')
	redirect_uri = request.args.get('redirect_uri')
	scope = request.args.get('scope', 'read')
	state = request.args.get('state')
	
	client = clients.get(client_id)
	if not client:
		return jsonify({'error': 'invalid_client'}), 400
	
	# Redirect URI validation
	if redirect_uri not in client['redirect_uris']:
		return jsonify({'error': 'invalid_redirect_uri'}), 400
	
	# Auto-approve
	code = secrets.token_urlsafe(32)
	codes[code] = {
		'client_id': client_id,
		'redirect_uri': redirect_uri,
		'scope': scope,
		'user_id': 'ent_user_001',
		'created_at': time.time()
	}
	
	return redirect(f"{redirect_uri}?code={code}&state={state}")

@app.route('/auth/token', methods=['POST'])
def token():
	"""Token endpoint with client authentication"""
	code = request.form.get('code')
	client_id = request.form.get('client_id')
	client_secret = request.form.get('client_secret')
	
	client = clients.get(client_id)
	if not client:
		return jsonify({'error': 'invalid_client'}), 401
	
	# VULNERABILITY: Timing attack in client_secret comparison
	# Uses standard == comparison instead of constant-time
	if client_secret:
		# Add deliberate timing difference based on secret length
		correct_secret = client['client_secret']
		
		# Check character by character (timing attack vulnerable)
		for i in range(min(len(client_secret), len(correct_secret))):
			if i < len(client_secret) and i < len(correct_secret):
				if client_secret[i] != correct_secret[i]:
					time.sleep(0.001)  # Timing leak
					# Track failed attempt
					failed_auth_attempts.setdefault(client_id, []).append({
						'timestamp': time.time(),
						'secret_attempt': client_secret
					})
					
					# VULNERABILITY: No rate limiting on failed attempts
					return jsonify({'error': 'invalid_client'}), 401
		
		if client_secret != correct_secret:
			return jsonify({'error': 'invalid_client'}), 401
	
	code_data = codes.get(code)
	if not code_data:
		return jsonify({'error': 'invalid_grant'}), 400
	
	# VULNERABILITY: Code not deleted after use
	
	# Generate access token
	access_token = secrets.token_urlsafe(32)
	
	# VULNERABILITY: Token stored in plain text
	# Should store hash: hashlib.sha256(access_token.encode()).hexdigest()
	tokens_storage[access_token] = {
		'user_id': code_data['user_id'],
		'scope': code_data['scope'],
		'client_id': client_id,
		'created_at': time.time()
	}
	
	return jsonify({
		'access_token': access_token,
		'token_type': 'Bearer',
		'expires_in': 3600,
		'scope': code_data['scope']
	})

@app.route('/api/resource')
def resource():
	"""Protected resource"""
	auth_header = request.headers.get('Authorization', '')
	
	if not auth_header.startswith('Bearer '):
		return jsonify({'error': 'unauthorized'}), 401
	
	token = auth_header.split(' ')[1]
	
	# VULNERABILITY: Token lookup in plain text storage
	# Should compare against hashed tokens
	token_data = tokens_storage.get(token)
	
	if not token_data:
		return jsonify({'error': 'invalid_token'}), 401
	
	# VULNERABILITY: No token expiration enforcement
	
	return jsonify({
		'user_id': token_data['user_id'],
		'data': 'protected resource',
		'scope': token_data['scope']
	})

@app.route('/introspect', methods=['POST'])
def introspect():
	"""Token introspection endpoint"""
	token = request.form.get('token')
	
	if not token:
		return jsonify({'active': False})
	
	# VULNERABILITY: Token introspection doesn't use hashing
	# Searches plain text tokens
	token_data = tokens_storage.get(token)
	
	if not token_data:
		return jsonify({'active': False})
	
	# VULNERABILITY: Returns sensitive information
	return jsonify({
		'active': True,
		'user_id': token_data['user_id'],
		'scope': token_data['scope'],
		'client_id': token_data['client_id'],
		'created_at': token_data['created_at'],
		'_internal_token': token  # VULNERABILITY: Leaks actual token
	})

@app.route('/debug/auth-failures')
def debug_failures():
	"""View failed authentication attempts"""
	# VULNERABILITY: Exposes authentication failure data
	return jsonify({
		'failed_attempts': failed_auth_attempts,
		'total_failures': sum(len(attempts) for attempts in failed_auth_attempts.values()),
		'warning': 'No rate limiting active'
	})

if __name__ == '__main__':
	print("=" * 70)
	print("OAuth 2.0 Authentication Service D")
	print("=" * 70)
	print(f"Starting on http://localhost:5004")
	print("=" * 70)
	app.run(port=5004, debug=True)
