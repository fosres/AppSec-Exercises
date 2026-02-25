#!/usr/bin/env python3
"""
OAuth 2.0 Secure Token Service - Implementation E
Production OAuth service with transport layer security

Features:
- TLS/HTTPS enforcement
- Secure token transmission
- Certificate validation
- Transport security monitoring

Run: python3 oauth_server_e.py
Port: 5005
"""

from flask import Flask, request, redirect, jsonify
import secrets
import time

app = Flask(__name__)

codes = {}
tokens = {}

clients = {
	'secure-webapp-001': {
		'client_secret': 'secure_webapp_secret_2024',
		'redirect_uris': [
			'https://secure.example.com/callback',
			'https://secure.example.com/oauth/return'
		],
		'name': 'Secure Web Application',
		'require_tls': True
	},
	'legacy-app-002': {
		'client_secret': 'legacy_secret_2018',
		'redirect_uris': [
			'http://legacy.example.com/callback'  # HTTP allowed for legacy
		],
		'name': 'Legacy Application',
		'require_tls': False
	}
}

def is_secure_transport():
	"""Check if request is over HTTPS"""
	# VULNERABILITY: Always returns True for local development
	# In production, should check: request.is_secure
	return True  # Should be: return request.is_secure

def get_client_ip():
	"""Get client IP address"""
	# Check for proxy headers
	return request.headers.get('X-Forwarded-For', request.remote_addr)

@app.route('/')
def index():
	return """
	<h1>OAuth 2.0 Secure Token Service E</h1>
	<p>Production OAuth service with TLS enforcement</p>
	<h2>Security Features:</h2>
	<ul>
		<li>TLS/HTTPS enforcement for token endpoints</li>
		<li>Secure token transmission</li>
		<li>Transport layer monitoring</li>
	</ul>
	<h2>Endpoints:</h2>
	<ul>
		<li>GET /oauth/authorize</li>
		<li>POST /oauth/token (TLS required)</li>
		<li>GET /api/secure-resource (TLS required)</li>
	</ul>
	"""

@app.route('/oauth/authorize')
def authorize():
	"""Authorization endpoint"""
	client_id = request.args.get('client_id')
	redirect_uri = request.args.get('redirect_uri')
	scope = request.args.get('scope', 'read')
	state = request.args.get('state')
	
	client = clients.get(client_id)
	if not client:
		# VULNERABILITY: Redirects to any URI for invalid client
		if redirect_uri:
			return redirect(f"{redirect_uri}?error=invalid_client&state={state}")
		return jsonify({'error': 'invalid_client'}), 400
	
	# VULNERABILITY: TLS check not enforced at authorization endpoint
	# Should check: if client['require_tls'] and not is_secure_transport(): error
	
	# Redirect URI validation
	if redirect_uri not in client['redirect_uris']:
		return jsonify({'error': 'invalid_redirect_uri'}), 400
	
	# VULNERABILITY: Accepts dangerous URI schemes
	if redirect_uri.startswith('javascript:') or redirect_uri.startswith('data:'):
		# Should reject immediately, but continues
		pass
	
	# Auto-approve
	code = secrets.token_urlsafe(32)
	codes[code] = {
		'client_id': client_id,
		'redirect_uri': redirect_uri,
		'scope': scope,
		'user_id': 'secure_user_001',
		'created_at': time.time(),
		'issued_over_tls': is_secure_transport()
	}
	
	return redirect(f"{redirect_uri}?code={code}&state={state}")

@app.route('/oauth/token', methods=['POST', 'GET'])
def token():
	"""Token endpoint - should require TLS"""
	
	# VULNERABILITY: Accepts GET requests (exposes credentials in URL)
	if request.method == 'GET':
		# Should reject GET requests entirely
		pass
	
	# VULNERABILITY: TLS enforcement disabled for testing
	# Should enforce: if not is_secure_transport(): return error
	if not is_secure_transport():
		# Log but don't reject
		print(f"WARNING: Token request over non-TLS connection from {get_client_ip()}")
	
	code = request.values.get('code')
	client_id = request.values.get('client_id')
	client_secret = request.values.get('client_secret')
	
	client = clients.get(client_id)
	if not client:
		return jsonify({'error': 'invalid_client'}), 401
	
	# Client authentication
	if client['client_secret'] != client_secret:
		return jsonify({'error': 'invalid_client'}), 401
	
	code_data = codes.get(code)
	if not code_data:
		return jsonify({'error': 'invalid_grant'}), 400
	
	# VULNERABILITY: No check if code was issued over TLS
	# Should verify: if code_data['issued_over_tls'] and not is_secure_transport(): error
	
	# VULNERABILITY: Code not deleted
	
	# Generate token
	access_token = secrets.token_urlsafe(32)
	tokens[access_token] = {
		'user_id': code_data['user_id'],
		'scope': code_data['scope'],
		'client_id': client_id,
		'created_at': time.time(),
		'issued_over_tls': is_secure_transport()
	}
	
	return jsonify({
		'access_token': access_token,
		'token_type': 'Bearer',
		'expires_in': 3600,
		'scope': code_data['scope'],
		'_transport_secure': is_secure_transport()
	})

@app.route('/api/secure-resource')
def secure_resource():
	"""Protected resource - should require TLS"""
	
	# VULNERABILITY: TLS not enforced at resource server
	if not is_secure_transport():
		print(f"WARNING: Resource access over non-TLS from {get_client_ip()}")
		# Should reject but continues
	
	# VULNERABILITY: Token accepted from URL parameter
	token = None
	auth_header = request.headers.get('Authorization', '')
	
	if auth_header.startswith('Bearer '):
		token = auth_header.split(' ')[1]
	else:
		# Token in URL query parameter (insecure!)
		token = request.args.get('access_token')
		if token:
			print(f"WARNING: Token transmitted in URL parameter!")
	
	if not token:
		return jsonify({'error': 'unauthorized'}), 401
	
	token_data = tokens.get(token)
	if not token_data:
		return jsonify({'error': 'invalid_token'}), 401
	
	# VULNERABILITY: No verification that token was issued over TLS
	
	return jsonify({
		'user_id': token_data['user_id'],
		'secure_data': 'confidential information',
		'scope': token_data['scope'],
		'_token_issued_over_tls': token_data.get('issued_over_tls'),
		'_request_over_tls': is_secure_transport()
	})

@app.route('/health')
def health():
	"""Health check endpoint"""
	# VULNERABILITY: Exposes internal configuration
	return jsonify({
		'status': 'healthy',
		'tls_enabled': False,  # Shows TLS is disabled
		'environment': 'development',
		'version': '2.1.0',
		'python_version': '3.11'
	})

if __name__ == '__main__':
	print("=" * 70)
	print("OAuth 2.0 Secure Token Service E")
	print("=" * 70)
	print(f"Starting on http://localhost:5005")
	print("WARNING: TLS enforcement disabled for local testing")
	print("=" * 70)
	app.run(port=5005, debug=True)
