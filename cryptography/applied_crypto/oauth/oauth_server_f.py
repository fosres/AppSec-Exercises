#!/usr/bin/env python3
"""
OAuth 2.0 Authorization Platform - Implementation F
Advanced OAuth service with dynamic client registration

Features:
- Dynamic client registration (RFC 7591)
- Client metadata management
- Advanced error handling
- Multi-protocol support

Run: python3 oauth_server_f.py
Port: 5006
"""

from flask import Flask, request, redirect, jsonify
import secrets
import time
import re

app = Flask(__name__)

codes = {}
tokens = {}
registered_clients = {
	'static-client-001': {
		'client_secret': 'static_secret_2024',
		'redirect_uris': ['https://static.example.com/callback'],
		'scopes': ['read', 'write'],
		'name': 'Static Registered Client',
		'registration_type': 'static'
	}
}

registration_tokens = {}  # For managing client registration

@app.route('/')
def index():
	return """
	<h1>OAuth 2.0 Authorization Platform F</h1>
	<p>Advanced OAuth service with dynamic client registration</p>
	<h2>Endpoints:</h2>
	<ul>
		<li>POST /register - Dynamic client registration</li>
		<li>GET /oauth/authorize - Authorization</li>
		<li>POST /oauth/token - Token exchange</li>
		<li>GET /api/data - Protected resource</li>
	</ul>
	<h2>Features:</h2>
	<ul>
		<li>RFC 7591 Dynamic Client Registration</li>
		<li>Client metadata management</li>
		<li>Scope-based authorization</li>
	</ul>
	"""

@app.route('/register', methods=['POST'])
def register_client():
	"""Dynamic client registration endpoint (RFC 7591)"""
	
	# VULNERABILITY: No authentication required for registration
	# Should require: registration access token or admin credentials
	
	# VULNERABILITY: No rate limiting on registration
	# Attackers can register unlimited clients
	
	client_metadata = request.get_json()
	if not client_metadata:
		return jsonify({'error': 'invalid_request'}), 400
	
	# Extract registration details
	redirect_uris = client_metadata.get('redirect_uris', [])
	client_name = client_metadata.get('client_name', 'Unnamed Client')
	scopes = client_metadata.get('scope', 'read').split()
	
	# VULNERABILITY: No validation of redirect_uri format
	# Should validate: must be HTTPS, no wildcards, etc.
	# Accepts: javascript:, data:, file:, etc.
	
	# VULNERABILITY: No sanitization of client metadata
	# Accepts any client_name (could be XSS payload)
	
	# Generate client credentials
	client_id = f"dynamic-{secrets.token_hex(8)}"
	client_secret = secrets.token_urlsafe(32)
	
	registered_clients[client_id] = {
		'client_secret': client_secret,
		'redirect_uris': redirect_uris,  # Stored without validation
		'scopes': scopes,
		'name': client_name,  # Not sanitized
		'registration_type': 'dynamic',
		'registered_at': time.time()
	}
	
	# VULNERABILITY: Returns client_secret in response
	# Should use client_secret_expires_at
	return jsonify({
		'client_id': client_id,
		'client_secret': client_secret,  # Exposed!
		'client_secret_expires_at': 0,  # Never expires!
		'redirect_uris': redirect_uris,
		'client_name': client_name,
		'scope': ' '.join(scopes)
	}), 201

@app.route('/oauth/authorize')
def authorize():
	"""Authorization endpoint"""
	client_id = request.args.get('client_id')
	redirect_uri = request.args.get('redirect_uri')
	scope = request.args.get('scope', 'read')
	state = request.args.get('state')
	response_type = request.args.get('response_type', 'code')
	
	client = registered_clients.get(client_id)
	
	# VULNERABILITY: Error handling exposes whether client_id exists
	if not client:
		error_msg = f"Client '{client_id}' is not registered"
		return jsonify({
			'error': 'invalid_client',
			'error_description': error_msg,
			'_hint': 'Register at /register endpoint'
		}), 400
	
	# VULNERABILITY: Redirect URI validation against unsanitized list
	# Dynamically registered URIs could be malicious
	if redirect_uri not in client['redirect_uris']:
		# VULNERABILITY: Redirects anyway with error
		return redirect(f"{redirect_uri}?error=invalid_redirect_uri&state={state}")
	
	# VULNERABILITY: No scope validation
	# Accepts scopes not in client['scopes']
	
	# Auto-approve
	code = secrets.token_urlsafe(32)
	codes[code] = {
		'client_id': client_id,
		'redirect_uri': redirect_uri,
		'scope': scope,
		'user_id': 'platform_user_001',
		'created_at': time.time()
	}
	
	# VULNERABILITY: Fragment leakage with debug info
	return redirect(f"{redirect_uri}?code={code}&state={state}#registration_type={client['registration_type']}")

@app.route('/oauth/token', methods=['POST'])
def token():
	"""Token endpoint"""
	code = request.form.get('code')
	client_id = request.form.get('client_id')
	client_secret = request.form.get('client_secret')
	redirect_uri = request.form.get('redirect_uri')
	
	client = registered_clients.get(client_id)
	if not client:
		return jsonify({'error': 'invalid_client'}), 401
	
	# Client authentication
	if client['client_secret'] != client_secret:
		return jsonify({'error': 'invalid_client'}), 401
	
	code_data = codes.get(code)
	if not code_data:
		return jsonify({'error': 'invalid_grant'}), 400
	
	# VULNERABILITY: No redirect_uri binding check
	
	# VULNERABILITY: Code not deleted
	
	# VULNERABILITY: No expiration check on code
	age = time.time() - code_data['created_at']
	if age > 600:  # 10 minutes
		# Check exists but doesn't enforce
		pass
	
	# Generate token
	access_token = secrets.token_urlsafe(32)
	tokens[access_token] = {
		'user_id': code_data['user_id'],
		'scope': code_data['scope'],
		'client_id': client_id,
		'created_at': time.time(),
		'client_type': client['registration_type']
	}
	
	return jsonify({
		'access_token': access_token,
		'token_type': 'Bearer',
		'expires_in': 3600,
		'scope': code_data['scope']
	})

@app.route('/api/data')
def protected_data():
	"""Protected API endpoint"""
	auth_header = request.headers.get('Authorization', '')
	
	if not auth_header.startswith('Bearer '):
		return jsonify({'error': 'unauthorized'}), 401
	
	token = auth_header.split(' ')[1]
	token_data = tokens.get(token)
	
	if not token_data:
		return jsonify({'error': 'invalid_token'}), 401
	
	# VULNERABILITY: No scope enforcement
	
	# VULNERABILITY: No token expiration check
	
	# VULNERABILITY: Tokens from dynamically registered clients treated same as static
	# Should have different trust levels
	
	return jsonify({
		'user_id': token_data['user_id'],
		'data': 'protected information',
		'client_type': token_data.get('client_type'),
		'scope': token_data['scope']
	})

@app.route('/clients')
def list_clients():
	"""List all registered clients"""
	# VULNERABILITY: Exposes all client information
	# Should require authentication
	
	return jsonify({
		'total_clients': len(registered_clients),
		'clients': [
			{
				'client_id': cid,
				'name': data['name'],
				'redirect_uris': data['redirect_uris'],
				'scopes': data.get('scopes', []),
				'registration_type': data.get('registration_type'),
				'_client_secret_preview': data['client_secret'][:8] + '...'  # Partial leak
			}
			for cid, data in registered_clients.items()
		]
	})

if __name__ == '__main__':
	print("=" * 70)
	print("OAuth 2.0 Authorization Platform F")
	print("=" * 70)
	print(f"Starting on http://localhost:5006")
	print("Dynamic Client Registration: POST /register")
	print("=" * 70)
	app.run(port=5006, debug=True)
