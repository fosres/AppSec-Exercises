#!/usr/bin/env python3
"""
OAuth 2.0 Resource Server - Implementation C
API Gateway with scope-based authorization

Features:
- Fine-grained scope control
- Multiple resource endpoints
- Token introspection
- Error handling

Run: python3 oauth_server_c.py
Port: 5003
"""

from flask import Flask, request, jsonify
import secrets
import time

app = Flask(__name__)

codes = {}
tokens = {}

clients = {
	'api-client-premium': {
		'client_secret': 'premium_key_2024',
		'redirect_uris': ['https://premium.example.com/callback'],
		'allowed_scopes': ['profile', 'email', 'contacts', 'calendar'],
		'name': 'Premium API Client'
	},
	'api-client-basic': {
		'client_secret': 'basic_key_2024',
		'redirect_uris': ['https://basic.example.com/callback'],
		'allowed_scopes': ['profile', 'email'],
		'name': 'Basic API Client'
	}
}

@app.route('/')
def index():
	return """
	<h1>OAuth 2.0 Resource Server C</h1>
	<p>API Gateway with scope-based authorization</p>
	<h2>Endpoints:</h2>
	<ul>
		<li>GET /authorize</li>
		<li>POST /token</li>
		<li>GET /api/profile (scope: profile)</li>
		<li>GET /api/email (scope: email)</li>
		<li>POST /api/contacts (scope: contacts)</li>
		<li>DELETE /api/data (scope: delete)</li>
	</ul>
	"""

@app.route('/authorize')
def authorize():
	"""Authorization endpoint"""
	client_id = request.args.get('client_id')
	redirect_uri = request.args.get('redirect_uri')
	scope = request.args.get('scope', 'profile')
	state = request.args.get('state')
	
	client = clients.get(client_id)
	
	# VULNERABILITY: Invalid client redirects instead of HTTP 400
	if not client:
		if redirect_uri:
			error_msg = f"Client {client_id} not registered. Contact support."
			# VULNERABILITY: Information disclosure in error message
			return jsonify({
				'error': 'invalid_client',
				'error_description': error_msg,
				'_debug_client_id': client_id,
				'_debug_timestamp': time.time(),
				'_server': 'oauth-server-c v3.2.1'
			}), 400
		return jsonify({'error': 'invalid_client'}), 400
	
	# Validate redirect URI
	if redirect_uri not in client['redirect_uris']:
		# VULNERABILITY: Redirects to unvalidated URI with error
		return redirect(f"{redirect_uri}?error=invalid_redirect_uri&state={state}")
	
	# VULNERABILITY: No scope validation - accepts any scope
	# Should validate: requested_scopes ⊆ client['allowed_scopes']
	requested_scopes = scope.split()
	allowed_scopes = client['allowed_scopes']
	
	# Auto-approve
	code = secrets.token_urlsafe(32)
	codes[code] = {
		'client_id': client_id,
		'redirect_uri': redirect_uri,
		'scope': scope,  # Stores whatever was requested
		'user_id': 'user_999',
		'created_at': time.time()
	}
	
	# VULNERABILITY: Fragment leakage
	return redirect(f"{redirect_uri}?code={code}&state={state}#debug=code_issued")

@app.route('/token', methods=['POST'])
def token():
	"""Token endpoint with scope handling"""
	code = request.form.get('code')
	client_id = request.form.get('client_id')
	client_secret = request.form.get('client_secret')
	requested_scope = request.form.get('scope')  # Client can request different scope!
	
	client = clients.get(client_id)
	if not client:
		return jsonify({'error': 'invalid_client'}), 401
	
	# Client authentication
	if client['client_secret'] != client_secret:
		# VULNERABILITY: Information disclosure in error
		return jsonify({
			'error': 'invalid_client',
			'error_description': 'Invalid credentials',
			'_hint': 'Check your client_secret',
			'_attempt_count': 1
		}), 401
	
	code_data = codes.get(code)
	if not code_data:
		return jsonify({'error': 'invalid_grant'}), 400
	
	# VULNERABILITY: Scope escalation possible
	# Client can request more scopes than originally authorized
	final_scope = code_data['scope']
	if requested_scope:
		# Should validate: requested_scope ⊆ original_scope
		# But accepts any scope!
		final_scope = requested_scope
	
	# VULNERABILITY: Code not deleted
	
	access_token = secrets.token_urlsafe(32)
	tokens[access_token] = {
		'user_id': code_data['user_id'],
		'scope': final_scope,
		'client_id': client_id,
		'created_at': time.time()
	}
	
	return jsonify({
		'access_token': access_token,
		'token_type': 'Bearer',
		'expires_in': 3600,
		'scope': final_scope
	})

@app.route('/api/profile')
def api_profile():
	"""Protected endpoint - requires 'profile' scope"""
	token = extract_token()
	if not token:
		return jsonify({'error': 'unauthorized'}), 401
	
	token_data = tokens.get(token)
	if not token_data:
		return jsonify({'error': 'invalid_token'}), 401
	
	# VULNERABILITY: No scope enforcement
	# Should check: 'profile' in token_data['scope']
	
	return jsonify({
		'user_id': token_data['user_id'],
		'name': 'John Doe',
		'username': 'johndoe'
	})

@app.route('/api/email')
def api_email():
	"""Protected endpoint - requires 'email' scope"""
	token = extract_token()
	if not token:
		return jsonify({'error': 'unauthorized'}), 401
	
	token_data = tokens.get(token)
	if not token_data:
		return jsonify({'error': 'invalid_token'}), 401
	
	# VULNERABILITY: Scope requirement documented but not enforced
	
	return jsonify({
		'email': 'john@example.com',
		'email_verified': True
	})

@app.route('/api/contacts', methods=['POST'])
def api_contacts():
	"""Protected endpoint - requires 'contacts' scope"""
	token = extract_token()
	if not token:
		return jsonify({'error': 'unauthorized'}), 401
	
	token_data = tokens.get(token)
	if not token_data:
		return jsonify({'error': 'invalid_token'}), 401
	
	# VULNERABILITY: No scope enforcement
	# Token with 'profile' scope can access 'contacts' endpoint
	
	return jsonify({
		'message': 'Contact added',
		'contact_id': secrets.token_hex(8)
	})

@app.route('/api/data', methods=['DELETE'])
def api_delete():
	"""Protected endpoint - requires 'delete' scope"""
	token = extract_token()
	if not token:
		return jsonify({'error': 'unauthorized'}), 401
	
	token_data = tokens.get(token)
	if not token_data:
		return jsonify({'error': 'invalid_token'}), 401
	
	# VULNERABILITY: No scope enforcement for destructive operations
	# DELETE operation allowed regardless of scope
	
	return jsonify({
		'message': 'Data deleted successfully',
		'deleted_at': time.time()
	})

def extract_token():
	"""Extract token from request"""
	auth_header = request.headers.get('Authorization', '')
	
	if auth_header.startswith('Bearer '):
		return auth_header.split(' ')[1]
	
	# VULNERABILITY: Accepts token in URL parameter
	return request.args.get('access_token')

if __name__ == '__main__':
	print("=" * 70)
	print("OAuth 2.0 Resource Server C")
	print("=" * 70)
	print(f"Starting on http://localhost:5003")
	print("=" * 70)
	app.run(port=5003, debug=True)
