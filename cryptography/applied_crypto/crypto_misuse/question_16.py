
from __future__ import annotations
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import hashlib
import random
import secrets
import string
import os
# Missing import below
# from dotenv import load_dotenv
from datetime import datetime, timedelta
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from passlib.hash import argon2


app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"],
    storage_uri="memory://",
)

DATABASE = 'users.db'

SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', 'SG.test_key_12345')

DATABASE_KEY = os.getenv('DATABASE_KEY')

def get_db():
	"""Get database connection"""
	conn = sqlite3.connect(DATABASE)
	conn.row_factory = sqlite3.Row
	return conn

def init_db():
	"""Initialize database schema"""
	conn = get_db()
	conn.execute('''
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			name TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	''')
	
	conn.execute('''
		CREATE TABLE IF NOT EXISTS reset_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token TEXT UNIQUE NOT NULL,
			user_id INTEGER NOT NULL,
			created_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	''')
	
	conn.commit()
	conn.close()

def generate_reset_token():
	"""Generate password reset token"""

	chars = string.ascii_letters + string.digits
	
	# `random` module is unsuitable for CSPRNG

	# Use `secrets` module instead

	token = ''.join(secrets.choice(chars) for i in range(32))

	return token

def send_reset_email(email, token):
	"""Send password reset email via SendGrid"""
	reset_url = f"https://example.com/reset?token={token}"
	
	message = Mail(
		from_email='noreply@example.com',
		to_emails=email,
		subject='Password Reset Request',
		html_content=f'''
		<p>Hello,</p>
		<p>Click the link below to reset your password:</p>
		<p><a href="{reset_url}">Reset Password</a></p>
		<p>This link will expire in 1 hour.</p>
		<p>If you didn't request this, please ignore this email.</p>
		'''
	)
	
	try:
		sg = SendGridAPIClient(SENDGRID_API_KEY)
		response = sg.send(message)
		return response.status_code == 202
	except Exception as e:
		print(f"Error sending email: {e}")
		return False

@app.route('/register', methods=['POST'])
@limiter.limit("5/minute")
def register():
	"""Register new user"""
	data = request.json
	email = data.get('email')
	password = data.get('password')
	name = data.get('name')

	
	if not email or not password or not name:
		return jsonify({"error": "Missing required fields"}), 400

	# SHA256 is NOT a password-based key derivation function!	
	# Hash password with SHA256
	
	password_hash = argon2.using(
		type='ID',
		memory_cost=19456,
		time_cost=2,
		parallelism=1,
	).hash(password)
	
	conn = get_db()
	
	try:
		conn.execute('''
			INSERT INTO users (email, password_hash, name)
			VALUES (?, ?, ?)
		''', (email, password_hash, name))
		conn.commit()
		conn.close()
		
		return jsonify({"message": "User registered successfully"}), 201
		
	except sqlite3.IntegrityError:
		conn.close()
		return jsonify({"error": "Email already exists"}), 400

@app.route('/login', methods=['POST'])
@limiter.limit("5/minute")
def login():
	"""Login user"""
	data = request.json
	email = data.get('email')
	password = data.get('password')

	# SHA256 is NOT a password-based key derivation function	
	
	conn = get_db()
	user = conn.execute('''
		SELECT name,email,password_hash FROM users WHERE email = ?
	''', (email,)).fetchone()
	conn.close()

	
	if user and argon2.verify(password,user['password_hash']):
		return jsonify({"message": "Login successful", "name": user['name']}), 200
	else:
		return jsonify({"error": "Invalid credentials"}), 401

@app.route('/forgot-password', methods=['POST'])
@limiter.limit("5/minute")
def forgot_password():
	"""Request password reset"""
	email = request.json.get('email')
	
	conn = get_db()
	
	# Check if user exists
	user = conn.execute('SELECT id,email FROM users WHERE email = ?', (email,)).fetchone()
	
	if not user:
		conn.close()
		# Don't reveal if email exists
		return jsonify({"message": "If that email exists, a reset link has been sent"}), 200
	
	# Generate reset token
	token = generate_reset_token()

	# Store cryptographic message digest of token

	# in database NOT the raw token. If the database

	# is stolen the token is stolen as well without

	# doing so.	
	# Store token in database
	
	token_hash = hashlib.sha512(token.encode()).hexdigest()

	conn.execute('''
		INSERT INTO reset_tokens (token, user_id, created_at)
		VALUES (?, ?, ?)
	''', (token_hash, user['id'], datetime.utcnow()))
	
	conn.commit()
	conn.close()
	
	# Send email
	send_reset_email(email, token)
	
	return jsonify({"message": "If that email exists, a reset link has been sent"}), 200

@app.route('/reset-password', methods=['POST'])
@limiter.limit("5/minute")
def reset_password():
	"""Reset password with token"""
	token = request.json.get('token')
	
	new_password = request.json.get('new_password')
	
	token_hash = hashlib.sha512(token.encode()).hexdigest()

	conn = get_db()
	
	# Validate token
	token_data = conn.execute('''
		SELECT rt.*, u.email 
		FROM reset_tokens rt
		JOIN users u ON rt.user_id = u.id
		WHERE rt.token = ?
	''', (token_hash,)).fetchone()
	
	if not token_data:
		conn.close()
		return jsonify({"error": "Invalid token"}), 400
	
	user_id = token_data['user_id']
	created_at = datetime.fromisoformat(token_data['created_at'])
	
	# Check expiration (1 hour)
	if datetime.utcnow() - created_at > timedelta(hours=1):

		conn.execute('''

			DELETE FROM reset_tokens where token = ?
		''',(token_hash,))	

		conn.commit()

		conn.close()

		return jsonify({"error": "Token expired"}), 400
	
	# Hash new password

	# SHA256 is NOT a cryptographically secure message digest

	password_hash = argon2.using(
		type='ID',
		memory_cost=19456,
		time_cost=2,
		parallelism=1,
	).hash(new_password) 

	# Update password in database
	conn.execute('''
		UPDATE users
		SET password_hash = ?
		WHERE id = ?
	''', (password_hash, user_id))
	

	conn.commit()

	conn.execute('''

		DELETE FROM reset_tokens where token = ?
	''',(token_hash,))	

	conn.commit()
	
	conn.close()
	
	return jsonify({"message": "Password reset successful"}), 200

@app.route('/check-token', methods=['GET'])
@limiter.limit("5/minute")
def check_token():
	"""Check if reset token is valid"""
	token = request.args.get('token')

	token_hash = hashlib.sha512(token.encode()).hexdigest()

	# Check with the hash of the token against database	
	conn = get_db()
	
	token_data = conn.execute('''
		SELECT rt.*, u.email
		FROM reset_tokens rt
		JOIN users u ON rt.user_id = u.id
		WHERE rt.token = ?
	''', (token_hash,)).fetchone()
	
	if token_data:
		created_at = datetime.fromisoformat(token_data['created_at'])
		
		if datetime.utcnow() - created_at <= timedelta(hours=1):
			
			conn.close()

			return jsonify({
				"valid": True,
				"email": token_data['email'],
				"created_at": token_data['created_at']
			}), 200

	# Invalid token must be deleted from database
	conn.execute('''

		DELETE FROM reset_tokens where token = ?
	''',(token_hash,))	

	conn.commit()
	
	conn.close()
	
	return jsonify({"valid": False}), 200

if __name__ == '__main__':
	init_db()
	app.run(debug=False)
