#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║              XSS EXERCISE 3: MULTI-MODULE SECURITY AUDIT                  ║
║                     VULNERABLE IMPLEMENTATION                             ║
║                   FOR EDUCATIONAL PURPOSES ONLY                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

A comprehensive security application with FOUR modules:
  1. User Authentication
  2. Session Management
  3. Rate Limiting Dashboard
  4. API Key Management

All modules use SQL databases for data persistence.

🎯 YOUR MISSION: Find and fix ALL XSS vulnerabilities!

SETUP:
======
pip install fastapi uvicorn bcrypt --break-system-packages

RUN:
====
python3 xss_ex3_multi_module_vulnerable.py

Then open: http://127.0.0.1:8000

YOUR TASK:
==========
Find ALL XSS vulnerabilities in this application.
Fix each using textContent (not innerHTML)!

SOURCES:
========
- "Full Stack Python Security" by Dennis Byrne, Chapter 14, pp. 208-226
- "Hacking APIs" by Corey Ball, Chapter 7
- "Secure by Design" (Johnsson, Deogun, Sawano)
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import sqlite3
import secrets
import hashlib
import bcrypt
import uvicorn
import os

app = FastAPI()

# Database file
DB_FILE = 'security_app.db'


# ═════════════════════════════════════════════════════════════════════════
# DATABASE SCHEMA - 5 TABLES
# ═════════════════════════════════════════════════════════════════════════

def init_db():
	"""Initialize all database tables"""
	conn = sqlite3.connect(DB_FILE)
	cursor = conn.cursor()
	
	# TABLE 1: Users (for authentication module)
	cursor.execute('''
		CREATE TABLE IF NOT EXISTS users (
			user_id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			bio TEXT,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	''')
	
	# TABLE 2: Sessions (for session management module)
	cursor.execute('''
		CREATE TABLE IF NOT EXISTS sessions (
			session_id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			user_agent TEXT,
			metadata TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(user_id)
		)
	''')
	
	# TABLE 3: Rate Limits (for rate limiting module)
	cursor.execute('''
		CREATE TABLE IF NOT EXISTS rate_limits (
			identifier TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			request_count INTEGER DEFAULT 0,
			window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (identifier, endpoint)
		)
	''')
	
	# TABLE 4: Rate Violations (for rate limiting module)
	cursor.execute('''
		CREATE TABLE IF NOT EXISTS rate_violations (
			violation_id INTEGER PRIMARY KEY AUTOINCREMENT,
			identifier TEXT NOT NULL,
			endpoint TEXT NOT NULL,
			reason TEXT,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	''')
	
	# TABLE 5: API Keys (for API key management module)
	cursor.execute('''
		CREATE TABLE IF NOT EXISTS api_keys (
			key_id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			key_hash TEXT NOT NULL,
			key_name TEXT,
			description TEXT,
			last_used_ip TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(user_id)
		)
	''')
	
	# Create indexes for performance
	cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)')
	cursor.execute('CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier)')
	cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)')
	
	conn.commit()
	conn.close()


def get_db():
	"""Get database connection with row factory"""
	conn = sqlite3.connect(DB_FILE)
	conn.row_factory = sqlite3.Row
	return conn


# ═════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS
# ═════════════════════════════════════════════════════════════════════════

class UserRegister(BaseModel):
	username: str
	password: str
	bio: Optional[str] = ""

class UserLogin(BaseModel):
	username: str
	password: str

class SessionCreate(BaseModel):
	user_id: int
	metadata: Optional[str] = ""

class APIKeyCreate(BaseModel):
	user_id: int
	key_name: str
	description: Optional[str] = ""


# ═════════════════════════════════════════════════════════════════════════
# MODULE 1: USER AUTHENTICATION
# ═════════════════════════════════════════════════════════════════════════

@app.post("/auth/register")
async def register_user(user: UserRegister):
	"""Register a new user"""
	conn = get_db()
	cursor = conn.cursor()
	
	try:
		# Hash password
		password_hash = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt()).decode()
		
		# Insert user (store bio as-is)
		cursor.execute(
			"INSERT INTO users (username, bio, password_hash) VALUES (?, ?, ?)",
			(user.username, user.bio, password_hash)
		)
		conn.commit()
		
		user_id = cursor.lastrowid
		
		return {
			"status": "success",
			"user_id": user_id,
			"username": user.username
		}
	
	except sqlite3.IntegrityError:
		raise HTTPException(status_code=400, detail="Username already exists")
	finally:
		conn.close()


@app.post("/auth/login")
async def login_user(credentials: UserLogin):
	"""Login user"""
	conn = get_db()
	cursor = conn.cursor()
	
	cursor.execute(
		"SELECT user_id, username, password_hash FROM users WHERE username = ?",
		(credentials.username,)
	)
	user = cursor.fetchone()
	conn.close()
	
	if user and bcrypt.checkpw(credentials.password.encode(), user['password_hash'].encode()):
		return {
			"status": "success",
			"user_id": user['user_id'],
			"username": user['username']
		}
	else:
		return JSONResponse(
			status_code=401,
			content={
				"status": "error",
				"message": f"Login failed for user: {credentials.username}"
			}
		)


@app.get("/auth/profile/{user_id}")
async def get_profile(user_id: int):
	"""Get user profile"""
	conn = get_db()
	cursor = conn.cursor()
	
	cursor.execute(
		"SELECT user_id, username, bio, created_at FROM users WHERE user_id = ?",
		(user_id,)
	)
	user = cursor.fetchone()
	conn.close()
	
	if user:
		return {
			"user_id": user['user_id'],
			"username": user['username'],
			"bio": user['bio'],
			"created_at": user['created_at']
		}
	
	raise HTTPException(status_code=404, detail="User not found")


# ═════════════════════════════════════════════════════════════════════════
# MODULE 2: SESSION MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════

@app.post("/session/create")
async def create_session(request: Request, session: SessionCreate):
	"""Create a new session"""
	conn = get_db()
	cursor = conn.cursor()
	
	# Generate session ID
	session_id = secrets.token_urlsafe(32)
	
	# Get user agent from request
	user_agent = request.headers.get('User-Agent', 'Unknown')
	
	# Create session
	expires_at = datetime.now() + timedelta(hours=24)
	
	cursor.execute(
		"INSERT INTO sessions (session_id, user_id, user_agent, metadata, expires_at) VALUES (?, ?, ?, ?, ?)",
		(session_id, session.user_id, user_agent, session.metadata, expires_at)
	)
	conn.commit()
	conn.close()
	
	return {
		"status": "success",
		"session_id": session_id,
		"expires_at": expires_at.isoformat()
	}


@app.get("/session/info/{session_id}")
async def get_session_info(session_id: str):
	"""Get session information"""
	conn = get_db()
	cursor = conn.cursor()
	
	cursor.execute(
		"SELECT session_id, user_id, user_agent, metadata, created_at, expires_at FROM sessions WHERE session_id = ?",
		(session_id,)
	)
	session = cursor.fetchone()
	conn.close()
	
	if session:
		return {
			"session_id": session['session_id'],
			"user_id": session['user_id'],
			"user_agent": session['user_agent'],
			"metadata": session['metadata'],
			"created_at": session['created_at'],
			"expires_at": session['expires_at']
		}
	
	return JSONResponse(
		status_code=404,
		content={
			"status": "error",
			"message": f"Session not found: {session_id}"
		}
	)


@app.delete("/session/logout/{session_id}")
async def logout_session(session_id: str):
	"""Delete a session"""
	conn = get_db()
	cursor = conn.cursor()
	
	cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
	conn.commit()
	affected = cursor.rowcount
	conn.close()
	
	if affected > 0:
		return {"status": "success", "message": "Session deleted"}
	
	raise HTTPException(status_code=404, detail="Session not found")


# ═════════════════════════════════════════════════════════════════════════
# MODULE 3: RATE LIMITING DASHBOARD
# ═════════════════════════════════════════════════════════════════════════

@app.post("/api/action")
async def rate_limited_action(request: Request):
	"""Rate-limited API endpoint"""
	# Get identifier (IP address or username)
	identifier = request.client.host if request.client else "unknown"
	endpoint = "/api/action"
	
	conn = get_db()
	cursor = conn.cursor()
	
	# Check rate limit
	cursor.execute(
		"SELECT request_count, window_start FROM rate_limits WHERE identifier = ? AND endpoint = ?",
		(identifier, endpoint)
	)
	limit = cursor.fetchone()
	
	current_time = datetime.now()
	window_duration = timedelta(minutes=1)
	max_requests = 5
	
	if limit:
		window_start = datetime.fromisoformat(limit['window_start'])
		
		if current_time - window_start < window_duration:
			# Within window
			if limit['request_count'] >= max_requests:
				reason = f"Too many requests from {identifier}"
				
				cursor.execute(
					"INSERT INTO rate_violations (identifier, endpoint, reason) VALUES (?, ?, ?)",
					(identifier, endpoint, reason)
				)
				conn.commit()
				conn.close()
				
				return JSONResponse(
					status_code=429,
					content={
						"status": "error",
						"message": f"Rate limit exceeded for {identifier}"
					}
				)
			else:
				# Increment count
				cursor.execute(
					"UPDATE rate_limits SET request_count = request_count + 1 WHERE identifier = ? AND endpoint = ?",
					(identifier, endpoint)
				)
		else:
			# Reset window
			cursor.execute(
				"UPDATE rate_limits SET request_count = 1, window_start = ? WHERE identifier = ? AND endpoint = ?",
				(current_time, identifier, endpoint)
			)
	else:
		# Create new limit
		cursor.execute(
			"INSERT INTO rate_limits (identifier, endpoint, request_count, window_start) VALUES (?, ?, 1, ?)",
			(identifier, endpoint, current_time)
		)
	
	conn.commit()
	conn.close()
	
	return {"status": "success", "message": "Action performed"}


@app.get("/ratelimit/status/{identifier}")
async def get_rate_limit_status(identifier: str):
	"""Get rate limit status for identifier"""
	conn = get_db()
	cursor = conn.cursor()
	
	cursor.execute(
		"SELECT identifier, endpoint, request_count, window_start FROM rate_limits WHERE identifier = ?",
		(identifier,)
	)
	limits = cursor.fetchall()
	conn.close()
	
	return {
		"identifier": identifier,
		"limits": [dict(limit) for limit in limits]
	}


@app.get("/ratelimit/violations")
async def get_violations():
	"""Get all rate limit violations"""
	conn = get_db()
	cursor = conn.cursor()
	
	cursor.execute(
		"SELECT violation_id, identifier, endpoint, reason, timestamp FROM rate_violations ORDER BY timestamp DESC LIMIT 50"
	)
	violations = cursor.fetchall()
	conn.close()
	
	return {
		"violations": [dict(v) for v in violations]
	}


# ═════════════════════════════════════════════════════════════════════════
# MODULE 4: API KEY MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════

@app.post("/apikey/generate")
async def generate_api_key(request: Request, key_data: APIKeyCreate):
	"""Generate a new API key"""
	conn = get_db()
	cursor = conn.cursor()
	
	# Generate API key
	api_key = secrets.token_urlsafe(32)
	key_hash = hashlib.sha256(api_key.encode()).hexdigest()
	
	# Get IP address
	ip_address = request.client.host if request.client else "unknown"
	
	# Store key
	cursor.execute(
		"INSERT INTO api_keys (user_id, key_hash, key_name, description, last_used_ip) VALUES (?, ?, ?, ?, ?)",
		(key_data.user_id, key_hash, key_data.key_name, key_data.description, ip_address)
	)
	conn.commit()
	key_id = cursor.lastrowid
	conn.close()
	
	return {
		"status": "success",
		"key_id": key_id,
		"api_key": api_key,  # Only shown once!
		"key_name": key_data.key_name
	}


@app.get("/apikey/list/{user_id}")
async def list_api_keys(user_id: int):
	"""List all API keys for a user"""
	conn = get_db()
	cursor = conn.cursor()
	
	cursor.execute(
		"SELECT key_id, key_name, description, last_used_ip, created_at FROM api_keys WHERE user_id = ?",
		(user_id,)
	)
	keys = cursor.fetchall()
	conn.close()
	
	return {
		"user_id": user_id,
		"keys": [dict(key) for key in keys]
	}


@app.put("/apikey/update/{key_id}")
async def update_api_key(key_id: int, key_name: Optional[str] = None, description: Optional[str] = None):
	"""Update API key metadata"""
	conn = get_db()
	cursor = conn.cursor()
	
	if key_name:
		cursor.execute("UPDATE api_keys SET key_name = ? WHERE key_id = ?", (key_name, key_id))
	
	if description:
		cursor.execute("UPDATE api_keys SET description = ? WHERE key_id = ?", (description, key_id))
	
	conn.commit()
	affected = cursor.rowcount
	conn.close()
	
	if affected > 0:
		return {"status": "success", "message": "API key updated"}
	
	raise HTTPException(status_code=404, detail="API key not found")


# ═════════════════════════════════════════════════════════════════════════
# FRONTEND - SINGLE PAGE WITH TABS
# ═════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def home():
	"""Main application page"""
	return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Security Application - Multi-Module XSS Exercise</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			min-height: 100vh;
			padding: 20px;
		}
		.container {
			max-width: 1200px;
			margin: 0 auto;
			background: white;
			border-radius: 16px;
			box-shadow: 0 20px 60px rgba(0,0,0,0.3);
			overflow: hidden;
		}
		.header {
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			color: white;
			padding: 30px;
			text-align: center;
		}
		.header h1 { font-size: 32px; margin-bottom: 10px; }
		.header p { opacity: 0.9; }
		.tabs {
			display: flex;
			background: #f7f7f7;
			border-bottom: 2px solid #e0e0e0;
		}
		.tab {
			flex: 1;
			padding: 15px;
			text-align: center;
			cursor: pointer;
			transition: all 0.3s;
			border: none;
			background: none;
			font-size: 16px;
		}
		.tab:hover { background: #e8e8e8; }
		.tab.active {
			background: white;
			border-bottom: 3px solid #667eea;
			font-weight: 600;
		}
		.tab-content {
			display: none;
			padding: 30px;
		}
		.tab-content.active { display: block; }
		.module {
			background: #f9f9f9;
			padding: 20px;
			border-radius: 8px;
			margin-bottom: 20px;
		}
		.module h3 {
			color: #667eea;
			margin-bottom: 15px;
		}
		.form-group {
			margin-bottom: 15px;
		}
		label {
			display: block;
			margin-bottom: 5px;
			font-weight: 500;
		}
		input, textarea {
			width: 100%;
			padding: 10px;
			border: 2px solid #e0e0e0;
			border-radius: 4px;
			font-size: 14px;
		}
		textarea { min-height: 80px; resize: vertical; }
		button {
			background: #667eea;
			color: white;
			padding: 12px 24px;
			border: none;
			border-radius: 4px;
			cursor: pointer;
			font-size: 16px;
			transition: all 0.3s;
		}
		button:hover { background: #5568d3; }
		.result {
			margin-top: 20px;
			padding: 15px;
			border-radius: 4px;
			border-left: 4px solid #667eea;
			background: #f0f0f0;
		}
		.error {
			border-left-color: #e74c3c;
			background: #fee;
			color: #c0392b;
		}
		.list-item {
			background: white;
			padding: 15px;
			margin-bottom: 10px;
			border-radius: 4px;
			border: 1px solid #e0e0e0;
		}
		.warning {
			background: #fff3cd;
			border: 2px solid #ffc107;
			padding: 15px;
			border-radius: 8px;
			margin-bottom: 20px;
		}
		.warning h4 {
			color: #856404;
			margin-bottom: 10px;
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>🔐 Security Application</h1>
			<p>Multi-Module XSS Security Audit Challenge</p>
		</div>
		
		<div class="warning">
			<h4>⚠️ SECURITY AUDIT CHALLENGE</h4>
			<p><strong>Your Mission:</strong> Find and fix ALL XSS vulnerabilities hidden in this application!</p>
			<p>Hint: Look for places where user input is displayed without proper escaping.</p>
		</div>
		
		<div class="tabs">
			<button class="tab active" onclick="showTab('auth')">🔐 Authentication</button>
			<button class="tab" onclick="showTab('session')">🎫 Sessions</button>
			<button class="tab" onclick="showTab('ratelimit')">⏱️ Rate Limits</button>
			<button class="tab" onclick="showTab('apikey')">🔑 API Keys</button>
		</div>
		
		<!-- MODULE 1: AUTHENTICATION -->
		<div id="auth" class="tab-content active">
			<div class="module">
				<h3>Register New User</h3>
				<div class="form-group">
					<label>Username:</label>
					<input type="text" id="reg_username" placeholder="Enter username">
				</div>
				<div class="form-group">
					<label>Password:</label>
					<input type="password" id="reg_password" placeholder="Enter password">
				</div>
				<div class="form-group">
					<label>Bio (optional):</label>
					<textarea id="reg_bio" placeholder="Tell us about yourself..."></textarea>
				</div>
				<button onclick="registerUser()">Register</button>
				<div id="register_result"></div>
			</div>
			
			<div class="module">
				<h3>Login</h3>
				<div class="form-group">
					<label>Username:</label>
					<input type="text" id="login_username" placeholder="Enter username">
				</div>
				<div class="form-group">
					<label>Password:</label>
					<input type="password" id="login_password" placeholder="Enter password">
				</div>
				<button onclick="loginUser()">Login</button>
				<div id="login_result"></div>
			</div>
			
			<div class="module">
				<h3>View Profile</h3>
				<div class="form-group">
					<label>User ID:</label>
					<input type="number" id="profile_user_id" placeholder="Enter user ID">
				</div>
				<button onclick="getProfile()">Get Profile</button>
				<div id="profile_result"></div>
			</div>
		</div>
		
		<!-- MODULE 2: SESSIONS -->
		<div id="session" class="tab-content">
			<div class="module">
				<h3>Create Session</h3>
				<div class="form-group">
					<label>User ID:</label>
					<input type="number" id="session_user_id" placeholder="Enter user ID">
				</div>
				<div class="form-group">
					<label>Metadata (optional):</label>
					<input type="text" id="session_metadata" placeholder="Custom metadata">
				</div>
				<button onclick="createSession()">Create Session</button>
				<div id="session_create_result"></div>
			</div>
			
			<div class="module">
				<h3>View Session Info</h3>
				<div class="form-group">
					<label>Session ID:</label>
					<input type="text" id="session_id_view" placeholder="Enter session ID">
				</div>
				<button onclick="getSessionInfo()">Get Session Info</button>
				<div id="session_info_result"></div>
			</div>
		</div>
		
		<!-- MODULE 3: RATE LIMITING -->
		<div id="ratelimit" class="tab-content">
			<div class="module">
				<h3>Test Rate Limit</h3>
				<p>Try making multiple requests (limit: 5 per minute)</p>
				<button onclick="testRateLimit()">Make Request</button>
				<div id="ratelimit_test_result"></div>
			</div>
			
			<div class="module">
				<h3>Check Rate Limit Status</h3>
				<div class="form-group">
					<label>Identifier (IP or username):</label>
					<input type="text" id="rate_identifier" placeholder="Enter identifier">
				</div>
				<button onclick="getRateLimitStatus()">Check Status</button>
				<div id="rate_status_result"></div>
			</div>
			
			<div class="module">
				<h3>View Violations</h3>
				<button onclick="getViolations()">Get Violations</button>
				<div id="violations_result"></div>
			</div>
		</div>
		
		<!-- MODULE 4: API KEYS -->
		<div id="apikey" class="tab-content">
			<div class="module">
				<h3>Generate API Key</h3>
				<div class="form-group">
					<label>User ID:</label>
					<input type="number" id="apikey_user_id" placeholder="Enter user ID">
				</div>
				<div class="form-group">
					<label>Key Name:</label>
					<input type="text" id="apikey_name" placeholder="My API Key">
				</div>
				<div class="form-group">
					<label>Description (optional):</label>
					<textarea id="apikey_description" placeholder="What is this key for?"></textarea>
				</div>
				<button onclick="generateAPIKey()">Generate Key</button>
				<div id="apikey_generate_result"></div>
			</div>
			
			<div class="module">
				<h3>List API Keys</h3>
				<div class="form-group">
					<label>User ID:</label>
					<input type="number" id="apikey_list_user_id" placeholder="Enter user ID">
				</div>
				<button onclick="listAPIKeys()">List Keys</button>
				<div id="apikey_list_result"></div>
			</div>
		</div>
	</div>
	
	<script>
		// Tab switching
		function showTab(tabName) {
			const tabs = document.querySelectorAll('.tab');
			const contents = document.querySelectorAll('.tab-content');
			
			tabs.forEach(tab => tab.classList.remove('active'));
			contents.forEach(content => content.classList.remove('active'));
			
			event.target.classList.add('active');
			document.getElementById(tabName).classList.add('active');
		}
		
		// ═════════════════════════════════════════════════════════════════
		// MODULE 1: AUTHENTICATION
		// ═════════════════════════════════════════════════════════════════
		
		async function registerUser() {
			const username = document.getElementById('reg_username').value;
			const password = document.getElementById('reg_password').value;
			const bio = document.getElementById('reg_bio').value;
			
			const response = await fetch('/auth/register', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({username, password, bio})
			});
			
			const data = await response.json();
			const result = document.getElementById('register_result');
			
			if (response.ok) {
				result.innerHTML = `<div class="result">✓ Registered! User ID: ${data.user_id}, Username: ${data.username}</div>`;
			} else {
				result.innerHTML = `<div class="result error">✗ ${data.detail}</div>`;
			}
		}
		
		async function loginUser() {
			const username = document.getElementById('login_username').value;
			const password = document.getElementById('login_password').value;
			
			const response = await fetch('/auth/login', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({username, password})
			});
			
			const data = await response.json();
			const result = document.getElementById('login_result');
			
			if (response.ok) {
				result.innerHTML = `<div class="result">✓ Login successful! User ID: ${data.user_id}</div>`;
			} else {
				result.innerHTML = `<div class="result error">✗ ${data.message}</div>`;
			}
		}
		
		async function getProfile() {
			const userId = document.getElementById('profile_user_id').value;
			
			const response = await fetch(`/auth/profile/${userId}`);
			const data = await response.json();
			const result = document.getElementById('profile_result');
			
			if (response.ok) {
				result.innerHTML = `
					<div class="result">
						<h4>Profile Information</h4>
						<p><strong>Username:</strong> ${data.username}</p>
						<p><strong>Bio:</strong> ${data.bio}</p>
						<p><strong>Created:</strong> ${data.created_at}</p>
					</div>
				`;
			} else {
				result.innerHTML = `<div class="result error">✗ ${data.detail}</div>`;
			}
		}
		
		// ═════════════════════════════════════════════════════════════════
		// MODULE 2: SESSIONS
		// ═════════════════════════════════════════════════════════════════
		
		async function createSession() {
			const userId = document.getElementById('session_user_id').value;
			const metadata = document.getElementById('session_metadata').value;
			
			const response = await fetch('/session/create', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({user_id: parseInt(userId), metadata})
			});
			
			const data = await response.json();
			const result = document.getElementById('session_create_result');
			
			if (response.ok) {
				result.innerHTML = `<div class="result">✓ Session created! ID: ${data.session_id}</div>`;
			} else {
				result.innerHTML = `<div class="result error">✗ ${data.detail}</div>`;
			}
		}
		
		async function getSessionInfo() {
			const sessionId = document.getElementById('session_id_view').value;
			
			const response = await fetch(`/session/info/${sessionId}`);
			const data = await response.json();
			const result = document.getElementById('session_info_result');
			
			if (response.ok) {
				result.innerHTML = `
					<div class="result">
						<h4>Session Information</h4>
						<p><strong>Session ID:</strong> ${data.session_id}</p>
						<p><strong>User ID:</strong> ${data.user_id}</p>
						<p><strong>User Agent:</strong> ${data.user_agent}</p>
						<p><strong>Metadata:</strong> ${data.metadata}</p>
						<p><strong>Expires:</strong> ${data.expires_at}</p>
					</div>
				`;
			} else {
				result.innerHTML = `<div class="result error">✗ ${data.message}</div>`;
			}
		}
		
		// ═════════════════════════════════════════════════════════════════
		// MODULE 3: RATE LIMITING
		// ═════════════════════════════════════════════════════════════════
		
		async function testRateLimit() {
			const response = await fetch('/api/action', {
				method: 'POST'
			});
			
			const data = await response.json();
			const result = document.getElementById('ratelimit_test_result');
			
			if (response.ok) {
				result.innerHTML = `<div class="result">✓ ${data.message}</div>`;
			} else {
				result.innerHTML = `<div class="result error">✗ ${data.message}</div>`;
			}
		}
		
		async function getRateLimitStatus() {
			const identifier = document.getElementById('rate_identifier').value;
			
			const response = await fetch(`/ratelimit/status/${identifier}`);
			const data = await response.json();
			const result = document.getElementById('rate_status_result');
			
			let html = `<div class="result"><h4>Rate Limit Status for: ${data.identifier}</h4>`;
			
			if (data.limits.length > 0) {
				data.limits.forEach(limit => {
					html += `
						<div class="list-item">
							<p><strong>Endpoint:</strong> ${limit.endpoint}</p>
							<p><strong>Requests:</strong> ${limit.request_count}/5</p>
							<p><strong>Window Start:</strong> ${limit.window_start}</p>
						</div>
					`;
				});
			} else {
				html += '<p>No rate limits found</p>';
			}
			
			html += '</div>';
			result.innerHTML = html;
		}
		
		async function getViolations() {
			const response = await fetch('/ratelimit/violations');
			const data = await response.json();
			const result = document.getElementById('violations_result');
			
			let html = '<div class="result"><h4>Rate Limit Violations</h4>';
			
			if (data.violations.length > 0) {
				data.violations.forEach(v => {
					html += `
						<div class="list-item">
							<p><strong>Identifier:</strong> ${v.identifier}</p>
							<p><strong>Endpoint:</strong> ${v.endpoint}</p>
							<p><strong>Reason:</strong> ${v.reason}</p>
							<p><strong>Time:</strong> ${v.timestamp}</p>
						</div>
					`;
				});
			} else {
				html += '<p>No violations found</p>';
			}
			
			html += '</div>';
			result.innerHTML = html;
		}
		
		// ═════════════════════════════════════════════════════════════════
		// MODULE 4: API KEYS
		// ═════════════════════════════════════════════════════════════════
		
		async function generateAPIKey() {
			const userId = document.getElementById('apikey_user_id').value;
			const keyName = document.getElementById('apikey_name').value;
			const description = document.getElementById('apikey_description').value;
			
			const response = await fetch('/apikey/generate', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({
					user_id: parseInt(userId),
					key_name: keyName,
					description: description
				})
			});
			
			const data = await response.json();
			const result = document.getElementById('apikey_generate_result');
			
			if (response.ok) {
				result.innerHTML = `
					<div class="result">
						<h4>✓ API Key Generated!</h4>
						<p><strong>Key ID:</strong> ${data.key_id}</p>
						<p><strong>API Key:</strong> <code>${data.api_key}</code></p>
						<p style="color: #e74c3c;"><strong>Save this key! It won't be shown again.</strong></p>
					</div>
				`;
			} else {
				result.innerHTML = `<div class="result error">✗ ${data.detail}</div>`;
			}
		}
		
		async function listAPIKeys() {
			const userId = document.getElementById('apikey_list_user_id').value;
			
			const response = await fetch(`/apikey/list/${userId}`);
			const data = await response.json();
			const result = document.getElementById('apikey_list_result');
			
			let html = '<div class="result"><h4>API Keys</h4>';
			
			if (data.keys.length > 0) {
				data.keys.forEach(key => {
					html += `
						<div class="list-item">
							<p><strong>Name:</strong> ${key.key_name}</p>
							<p><strong>Description:</strong> ${key.description}</p>
							<p><strong>Last Used IP:</strong> ${key.last_used_ip}</p>
							<p><strong>Created:</strong> ${key.created_at}</p>
						</div>
					`;
				});
			} else {
				html += '<p>No API keys found</p>';
			}
			
			html += '</div>';
			result.innerHTML = html;
		}
	</script>
</body>
</html>
	""")


# ═════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
	# Initialize database
	if not os.path.exists(DB_FILE):
		print("Initializing database...")
		init_db()
		print("Database initialized!")
	
	print("\n" + "="*80)
	print("🔐 SECURITY APPLICATION - MULTI-MODULE XSS EXERCISE")
	print("="*80)
	print("\n📋 YOUR MISSION:")
	print("   Find and fix ALL XSS vulnerabilities in this application!")
	print("\n🛠️  DATABASE:")
	print("   • 5 SQL tables (users, sessions, rate_limits, rate_violations, api_keys)")
	print("   • All data persisted in SQLite database")
	print("\n🚀 STARTING SERVER...")
	print("   Open: http://127.0.0.1:8000")
	print("="*80 + "\n")
	
	uvicorn.run(app, host="127.0.0.1", port=8000)
