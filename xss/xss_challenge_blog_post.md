---
title: "Week 6 Challenge Audit XSS Vulnerabilities"
published: true
description: "Learn XSS prevention through real-world code challenges from a 48-week Security Engineering curriculum. Free exercises with 60+ test cases each. ⭐ Open source!"
tags: security, python, webdev, appsec
series: Security Engineering Interview Prep
canonical_url: https://github.com/fosres/SecEng-Exercises
---

> **📚 Part of Week 6** in the [SecEng-Exercises](https://github.com/fosres/SecEng-Exercises) curriculum - a free, open-source path to becoming a Security Engineer. **Star the repo** to follow along with weekly challenges!

## The $5 Million XSS Disaster

It was 3 AM when the security team at TechFinance Corporation received the alert. Their customer portal—processing millions of dollars in transactions daily—had been compromised. The attack vector? A simple Cross-Site Scripting (XSS) vulnerability in their search functionality.

The attacker had crafted a malicious URL containing JavaScript that stole session cookies. They shared it on social media disguised as a "special promotion." Within hours, thousands of customers clicked the link. The malicious script silently harvested authentication tokens, granting the attacker access to customer accounts.

By morning, the damage was catastrophic:
- **15,000+ customer accounts compromised**
- **$5.2 million in unauthorized transfers**
- **Complete database exfiltration** including social security numbers
- **Stock price plummeted 40%** after disclosure
- **Class action lawsuit** filed within 72 hours

The company's Chief Security Officer resigned. The engineering team worked 72-hour shifts to contain the breach. Regulatory fines exceeded $12 million. All because of a single XSS vulnerability that should have been caught in code review.

**Don't let this happen to your application.**

---

> ### 🎓 Learning Security Engineering?
> 
> This challenge is from my **free, open-source Security Engineering curriculum** with:
> - ✅ LeetCode-style exercises with 60+ test cases
> - ✅ Real CVEs and production-incident inspired scenarios  
> - ✅ Complete solutions with best practices
> - ✅ New challenges added weekly
> 
> **⭐ [Star SecEng-Exercises on GitHub](https://github.com/fosres/SecEng-Exercises)** - Join developers mastering AppSec fundamentals!

---

## 🎯 Part of the SecEng-Exercises Collection

This XSS challenge is **Week 6** of my comprehensive Security Engineering curriculum. I'm building a public collection of **LeetCode-style security exercises** with:
- ✅ **60+ test cases per exercise** for thorough validation
- ✅ **Real-world vulnerability patterns** from production systems
- ✅ **Hands-on pentesting practice** against intentionally vulnerable code
- ✅ **Complete solutions** with security best practices

**⭐ [Star the repo on GitHub](https://github.com/fosres/SecEng-Exercises)** to follow along as I add new exercises weekly covering AppSec, cryptography, API security, and more.

> 💡 **Why star the repo?** You'll get notified when I publish new challenges covering SQL injection, authentication bypasses, cryptographic vulnerabilities, and advanced API attacks. All exercises include comprehensive test suites and are production-incident inspired.

### 📋 What You'll Learn in This Post

1. **Real XSS attack scenario** and its $5M+ impact
2. **Three vulnerable code challenges** to test your skills
3. **Complete vulnerability analysis** with fix implementations  
4. **Prevention patterns** used by security teams at top tech companies

**Estimated completion time:** 30-45 minutes | **Difficulty:** Intermediate | **Prerequisites:** Basic Python, HTML/JavaScript

---

## Your Challenge: Find the XSS Vulnerabilities

Below are **three real-world code snippets**, each containing multiple XSS vulnerabilities. Your task is to:

1. **Identify** all security vulnerabilities in each snippet
2. **Understand** how an attacker could exploit them
3. **Fix** the code to prevent XSS attacks

These exercises are based on patterns from production systems and real security incidents. Study each carefully—the vulnerabilities range from obvious to subtle.

**Sources for these exercises:**
- *Full Stack Python Security* by Dennis Byrne, Chapter 14, pp. 208-226<sup>[1](#ref1)</sup>
- *API Security in Action* by Neil Madden, Chapter 2, pp. 54-55<sup>[2](#ref2)</sup>
- *Secure by Design* by Johnsson et al., Chapter 9, pp. 247-249<sup>[3](#ref3)</sup>
- *Hacking APIs* by Corey Ball<sup>[4](#ref4)</sup>

> **📖 Following the curriculum?** I'm documenting my journey through these books in the [SecEng-Exercises repository](https://github.com/fosres/SecEng-Exercises), creating exercises for each chapter. Week 7 covers *Full Stack Python Security* Chapter 15 (CSRF) and *Hacking APIs* Chapter 3 (API Authentication Bypasses). **Star the repo** for weekly updates!

---

## Vulnerable Code Snippet #1: Flask Search Application

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
	"""Search endpoint - handles user queries"""
	query = request.args.get('q', '')
	
	# Simulate database search
	results = []
	if query:
		query_lower = query.lower()
		if 'laptop' in query_lower:
			results = [
				{'name': 'Gaming Laptop Pro', 'price': 1299.99, 'stock': 12},
				{'name': 'Business Laptop Elite', 'price': 899.99, 'stock': 8},
			]
	
	# Generate HTML response
	html = f"""
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Search Results</title>
</head>
<body>
	<h1>Search Results for: <span>{query}</span></h1>
	<div class="results">
	"""
	
	if results:
		for product in results:
			html += f"""
			<div class="product">
				<h3>{product['name']}</h3>
				<div class="price">${product['price']}</div>
				<div class="stock">In stock: {product['stock']} units</div>
			</div>
			"""
	else:
		html += f"""
		<div class="no-results">
			<h2>No Results Found</h2>
			<p>Your search for '<strong>{query}</strong>' did not match any products.</p>
		</div>
		"""
	
	html += """
	</div>
</body>
</html>
	"""
	
	return html

if __name__ == '__main__':
	app.run(debug=True, port=5000, host='127.0.0.1')
```

---

## Vulnerable Code Snippet #2: FastAPI Comment Board

```python
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import sqlite3
import html

app = FastAPI()

class Comment(BaseModel):
	author: str
	content: str

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
	"""Main page with comment form"""
	return """
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Comment Board</title>
</head>
<body>
	<h1>Community Comment Board</h1>
	<form id="commentForm">
		<input type="text" id="author" placeholder="Your name" required>
		<textarea id="content" placeholder="Your comment" required></textarea>
		<button type="submit">Post Comment</button>
	</form>
	<div id="commentsContainer"></div>
	
	<script>
		// Load comments when page loads
		loadComments();
		
		// Handle form submission
		document.getElementById('commentForm').addEventListener('submit', async (e) => {
			e.preventDefault();
			
			const author = document.getElementById('author').value;
			const content = document.getElementById('content').value;
			
			const response = await fetch('/api/comments', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({ author, content })
			});
			
			if (response.ok) {
				document.getElementById('author').value = '';
				document.getElementById('content').value = '';
				loadComments();
			}
		});
		
		// Load and display comments
		async function loadComments() {
			const response = await fetch('/api/comments');
			const comments = await response.json();
			
			const container = document.getElementById('commentsContainer');
			container.innerHTML = '';
			
			comments.forEach(comment => {
				const div = document.createElement('div');
				div.className = 'comment';
				
				div.innerHTML = `
					<div class="comment-author">${comment.author}</div>
					<div class="comment-time">${comment.timestamp}</div>
					<div class="comment-content">${comment.content}</div>
				`;
				container.appendChild(div);
			});
		}
	</script>
</body>
</html>
	"""

@app.post("/api/comments")
async def create_comment(comment: Comment):
	"""Create a new comment"""
	conn = sqlite3.connect('comments.db')
	cursor = conn.cursor()
	
	# Escape HTML to prevent XSS
	author = html.escape(comment.author, quote=True)
	content = html.escape(comment.content, quote=True)
	
	# SQL Injection vulnerable query
	query = f"INSERT INTO comments (author, content, timestamp) VALUES ('{author}', '{content}', datetime('now'))"
	cursor.execute(query)
	
	conn.commit()
	conn.close()
	
	return {"status": "success"}

@app.get("/api/comments")
async def get_comments():
	"""Get all comments"""
	conn = sqlite3.connect('comments.db')
	cursor = conn.cursor()
	
	# SQL Injection vulnerable query
	query = "SELECT author, content, timestamp FROM comments ORDER BY id DESC"
	cursor.execute(query)
	
	comments = []
	for row in cursor.fetchall():
		comments.append({
			"author": row[0],
			"content": row[1],
			"timestamp": row[2]
		})
	
	conn.close()
	return comments
```

---

## Vulnerable Code Snippet #3: Session Management API

```python
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import sqlite3

app = FastAPI()

@app.post("/auth/register")
async def register(username: str, password: str):
	"""Register a new user"""
	conn = sqlite3.connect('security_app.db')
	cursor = conn.cursor()
	
	# Store user in database
	cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
				   (username, password))
	
	user_id = cursor.lastrowid
	conn.commit()
	conn.close()
	
	return {"user_id": user_id, "username": username}

@app.post("/sessions/create")
async def create_session(user_id: int, metadata: str):
	"""Create a new session"""
	conn = sqlite3.connect('security_app.db')
	cursor = conn.cursor()
	
	import secrets
	session_id = secrets.token_urlsafe(32)
	
	# Store raw session ID in database
	cursor.execute(
		"INSERT INTO sessions (session_id, user_id, metadata) VALUES (?, ?, ?)",
		(session_id, user_id, metadata)
	)
	
	conn.commit()
	conn.close()
	
	return {"session_id": session_id}

@app.get("/", response_class=HTMLResponse)
async def home():
	"""Frontend with session management"""
	return """
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Session Manager</title>
</head>
<body>
	<h1>Session Management System</h1>
	
	<div id="register_section">
		<h2>Register</h2>
		<input type="text" id="register_username" placeholder="Username">
		<input type="password" id="register_password" placeholder="Password">
		<button onclick="registerUser()">Register</button>
		<div id="register_result"></div>
	</div>
	
	<div id="login_section">
		<h2>Login</h2>
		<input type="text" id="login_username" placeholder="Username">
		<input type="password" id="login_password" placeholder="Password">
		<button onclick="loginUser()">Login</button>
		<div id="login_result"></div>
	</div>
	
	<div id="profile_section">
		<h2>Get Profile</h2>
		<input type="text" id="profile_user_id" placeholder="User ID">
		<button onclick="getProfile()">Get Profile</button>
		<div id="profile_result"></div>
	</div>
	
	<script>
		async function registerUser() {
			const username = document.getElementById('register_username').value;
			const password = document.getElementById('register_password').value;
			
			const response = await fetch('/auth/register', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({username, password})
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
	</script>
</body>
</html>
	"""
```

---

## 🔒 Test Yourself First

Before scrolling to the answers, try identifying the vulnerabilities yourself! Each exercise in the [SecEng-Exercises repository](https://github.com/fosres/SecEng-Exercises) includes:

- **Automated test suites** with 60+ test cases
- **Vulnerable and fixed versions** for comparison
- **Step-by-step exploitation guides**
- **Production-ready security patterns**

**⭐ Star the repo** to get the full test suites and run the exploits yourself. The hands-on practice is 10x more valuable than just reading solutions.

---

## Answer Key: Vulnerabilities & Fixes

### Exercise 1: Flask Search Application

**Identified Vulnerabilities:**

1. **Reflected XSS Vulnerability** (Critical)
   - **Location:** Lines where `{query}` is directly embedded in HTML
   - **Impact:** Attacker can inject malicious JavaScript via the search parameter
   - **Example Attack:** `?q=<script>alert(document.cookie)</script>`
   - **Reference:** *Full Stack Python Security*, Chapter 14, pp. 208-212<sup>[1](#ref1)</sup>

2. **Missing Security Headers**
   - No `X-XSS-Protection` header
   - No `X-Content-Type-Options: nosniff` header
   - No `Content-Security-Policy` header
   - **Reference:** *Secure by Design*, Chapter 9, pp. 247-249<sup>[3](#ref3)</sup>

3. **Missing Rate Limiting**
   - Attacker can overwhelm server with excessive requests
   - No protection against brute-force attacks

4. **Debug Mode Enabled in Production**
   - `debug=True` exposes sensitive stack traces and system information
   - Should always be `False` in production environments

**Fixed Code:**

```python
from flask import Flask, request
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import html

app = Flask(__name__)

# Configure security headers with Talisman
talisman = Talisman(
	app,
	content_security_policy={
		'default-src': ["'self'"]
	}
)

# Add rate limiting
limiter = Limiter(
	key_func=get_remote_address,
	app=app,
	default_limits=["100/hour"],
	storage_uri="memory://",
)

# Enable security headers
talisman.x_xss_protection = True
talisman.x_content_type_options = True

@app.route('/search')
@limiter.limit("30/minute")
def search():
	"""Search endpoint - handles user queries"""
	query = request.args.get('q', '')
	
	# ✅ FIX: HTML escape user input to prevent XSS
	query_escaped = html.escape(query, quote=True)
	
	# Simulate database search
	results = []
	if query:
		query_lower = query.lower()
		if 'laptop' in query_lower:
			results = [
				{'name': 'Gaming Laptop Pro', 'price': 1299.99, 'stock': 12},
				{'name': 'Business Laptop Elite', 'price': 899.99, 'stock': 8},
			]
	
	# Generate HTML response with escaped query
	html_content = f"""
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Search Results</title>
</head>
<body>
	<h1>Search Results for: <span>{query_escaped}</span></h1>
	<div class="results">
	"""
	
	if results:
		for product in results:
			html_content += f"""
			<div class="product">
				<h3>{html.escape(product['name'])}</h3>
				<div class="price">${product['price']}</div>
				<div class="stock">In stock: {product['stock']} units</div>
			</div>
			"""
	else:
		html_content += f"""
		<div class="no-results">
			<h2>No Results Found</h2>
			<p>Your search for '<strong>{query_escaped}</strong>' did not match any products.</p>
		</div>
		"""
	
	html_content += """
	</div>
</body>
</html>
	"""
	
	return html_content

if __name__ == '__main__':
	# ✅ FIX: Disable debug mode in production
	app.run(debug=False, port=5000, host='127.0.0.1')
```

**Key Security Improvements:**
- Used `html.escape()` to sanitize all user input<sup>[1](#ref1)</sup>
- Added Flask-Talisman for Content Security Policy
- Implemented rate limiting with Flask-Limiter
- Disabled debug mode
- Added `X-XSS-Protection` and `X-Content-Type-Options` headers

> **💡 Want the complete test suite?** The [GitHub repository](https://github.com/fosres/SecEng-Exercises) includes 60+ pytest test cases for this exercise, including edge cases like double-encoded attacks, null byte injection, and DOM clobbering attempts. **Star the repo** to access all test files!

---

### Exercise 2: FastAPI Comment Board

**Identified Vulnerabilities:**

1. **Stored/DOM XSS Vulnerability** (Critical)
   - **Location:** Line where `div.innerHTML` is set with unescaped comment data
   - **Impact:** Malicious JavaScript stored in database executes when loaded
   - **Attack Flow:** 
     1. Attacker posts comment with XSS payload
     2. Payload stored in database (even though it's HTML-escaped on server)
     3. Server returns escaped HTML entities to client
     4. Client-side JavaScript inserts into DOM via `innerHTML`
     5. Browser unescapes HTML entities and executes script
   - **Reference:** *Full Stack Python Security*, Chapter 14, pp. 213-220<sup>[1](#ref1)</sup>

2. **SQL Injection Vulnerability** (Critical)
   - **Location:** String interpolation in SQL queries
   - Despite HTML escaping, the query uses f-string formatting which is vulnerable
   - **Reference:** *API Security in Action*, Chapter 2, pp. 54-55<sup>[2](#ref2)</sup>

3. **Missing Rate Limiting**
   - No protection against comment spam or DoS attacks

4. **Inline Scripts Without CSP Nonces**
   - Inline `<script>` tags violate Content Security Policy best practices
   - Should use nonces or move scripts to external files
   - **Reference:** https://www.johal.in/fastapi-content-security-csp-policies-nonce-hashes-strict-dynamic-2026/

**Fixed Code:**

```python
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
import sqlite3
import html

app = FastAPI()

# Add rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

class Comment(BaseModel):
	author: str
	content: str

@app.get("/", response_class=HTMLResponse)
@limiter.limit("10/minute")
async def home(request: Request):
	"""Main page with comment form"""
	return """
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'">
	<title>Comment Board</title>
</head>
<body>
	<h1>Community Comment Board</h1>
	<form id="commentForm">
		<input type="text" id="author" placeholder="Your name" required>
		<textarea id="content" placeholder="Your comment" required></textarea>
		<button type="submit">Post Comment</button>
	</form>
	<div id="commentsContainer"></div>
	
	<script>
		loadComments();
		
		document.getElementById('commentForm').addEventListener('submit', async (e) => {
			e.preventDefault();
			
			const author = document.getElementById('author').value;
			const content = document.getElementById('content').value;
			
			const response = await fetch('/api/comments', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({ author, content })
			});
			
			if (response.ok) {
				document.getElementById('author').value = '';
				document.getElementById('content').value = '';
				loadComments();
			}
		});
		
		// ✅ FIX: Use textContent instead of innerHTML to prevent XSS
		async function loadComments() {
			const response = await fetch('/api/comments');
			const comments = await response.json();
			
			const container = document.getElementById('commentsContainer');
			container.innerHTML = '';
			
			comments.forEach(comment => {
				const div = document.createElement('div');
				div.className = 'comment';
				
				// Create separate elements and use textContent
				const authorDiv = document.createElement('div');
				authorDiv.className = 'comment-author';
				authorDiv.textContent = comment.author;  // ✅ Safe: Uses textContent
				
				const timeDiv = document.createElement('div');
				timeDiv.className = 'comment-time';
				timeDiv.textContent = comment.timestamp;  // ✅ Safe: Uses textContent
				
				const contentDiv = document.createElement('div');
				contentDiv.className = 'comment-content';
				contentDiv.textContent = comment.content;  // ✅ Safe: Uses textContent
				
				div.appendChild(authorDiv);
				div.appendChild(timeDiv);
				div.appendChild(contentDiv);
				
				container.appendChild(div);
			});
		}
	</script>
</body>
</html>
	"""

@app.post("/api/comments")
@limiter.limit("5/minute")
async def create_comment(request: Request, comment: Comment):
	"""Create a new comment"""
	conn = sqlite3.connect('comments.db')
	cursor = conn.cursor()
	
	# ✅ FIX: Use parameterized queries to prevent SQL injection
	query = "INSERT INTO comments (author, content, timestamp) VALUES (?, ?, datetime('now'))"
	cursor.execute(query, (comment.author, comment.content))
	
	conn.commit()
	conn.close()
	
	return {"status": "success"}

@app.get("/api/comments")
@limiter.limit("10/minute")
async def get_comments(request: Request):
	"""Get all comments"""
	conn = sqlite3.connect('comments.db')
	cursor = conn.cursor()
	
	# ✅ FIX: Use parameterized query
	query = "SELECT author, content, timestamp FROM comments ORDER BY id DESC"
	cursor.execute(query)
	
	comments = []
	for row in cursor.fetchall():
		comments.append({
			"author": row[0],
			"content": row[1],
			"timestamp": row[2]
		})
	
	conn.close()
	return comments
```

**Key Security Improvements:**
- **Critical:** Changed from `innerHTML` to `textContent` for DOM manipulation<sup>[1](#ref1)</sup>
- Used parameterized SQL queries to prevent SQL injection<sup>[2](#ref2)</sup>
- Added Content-Security-Policy header
- Implemented rate limiting on all endpoints
- Removed HTML escaping on server since client now uses textContent (defense in depth still valuable)

**Why innerHTML is Dangerous:**
Even though the server HTML-escapes the data, when the client retrieves it and uses `innerHTML`, the browser automatically unescapes HTML entities, converting `&lt;script&gt;` back to `<script>`, which then executes. Using `textContent` prevents this by treating everything as plain text.<sup>[1](#ref1)</sup>

> **🔥 Pro Tip:** Exercise 2 in the [SecEng-Exercises repo](https://github.com/fosres/SecEng-Exercises) includes a bonus challenge on CSP nonces and hash-based script whitelisting—an advanced defense technique used by Google and Facebook. **Star to unlock!**

---

### Exercise 3: Session Management API

**Identified Vulnerabilities:**

1. **Multiple DOM-Based XSS Vulnerabilities** (Critical)
   - **Locations:** Every use of `.innerHTML` in JavaScript functions
   - Lines with `result.innerHTML = ...${data.user_id}...` and similar
   - **Impact:** API responses containing malicious data execute as JavaScript
   - **Reference:** *Full Stack Python Security*, Chapter 14, pp. 220-226<sup>[1](#ref1)</sup>

2. **Session ID Storage Vulnerability** (High)
   - **Location:** `create_session()` stores raw session ID in database
   - **Impact:** If database is compromised, all session IDs are exposed
   - **Best Practice:** Store only hashed session IDs<sup>[2](#ref2)</sup>

3. **Missing Rate Limiting** (Medium)
   - No protection against brute-force login attempts
   - No limits on session creation

4. **Password Storage Issue** (Critical, implied)
   - Password likely stored in plaintext (not shown hashing in register)
   - Should use bcrypt or similar

**Fixed Code:**

```python
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import sqlite3
import secrets
import hashlib

app = FastAPI()

# Add rate limiting (import statements omitted for brevity)

@app.post("/auth/register")
async def register(username: str, password: str):
	"""Register a new user"""
	conn = sqlite3.connect('security_app.db')
	cursor = conn.cursor()
	
	# ✅ FIX: Hash password before storing
	import bcrypt
	password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
	
	cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
				   (username, password_hash))
	
	user_id = cursor.lastrowid
	conn.commit()
	conn.close()
	
	return {"user_id": user_id, "username": username}

@app.post("/sessions/create")
async def create_session(user_id: int, metadata: str):
	"""Create a new session"""
	conn = sqlite3.connect('security_app.db')
	cursor = conn.cursor()
	
	session_id = secrets.token_urlsafe(32)
	
	# ✅ FIX: Store hashed session ID, not raw value
	session_hash = hashlib.sha256(session_id.encode()).hexdigest()
	
	cursor.execute(
		"INSERT INTO sessions (session_hash, user_id, metadata) VALUES (?, ?, ?)",
		(session_hash, user_id, metadata)
	)
	
	conn.commit()
	conn.close()
	
	# Return raw session ID to client (only once)
	return {"session_id": session_id}

@app.get("/", response_class=HTMLResponse)
async def home():
	"""Frontend with session management"""
	return """
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'">
	<title>Session Manager</title>
</head>
<body>
	<h1>Session Management System</h1>
	
	<div id="register_section">
		<h2>Register</h2>
		<input type="text" id="register_username" placeholder="Username">
		<input type="password" id="register_password" placeholder="Password">
		<button onclick="registerUser()">Register</button>
		<div id="register_result"></div>
	</div>
	
	<div id="login_section">
		<h2>Login</h2>
		<input type="text" id="login_username" placeholder="Username">
		<input type="password" id="login_password" placeholder="Password">
		<button onclick="loginUser()">Login</button>
		<div id="login_result"></div>
	</div>
	
	<div id="profile_section">
		<h2>Get Profile</h2>
		<input type="text" id="profile_user_id" placeholder="User ID">
		<button onclick="getProfile()">Get Profile</button>
		<div id="profile_result"></div>
	</div>
	
	<script>
		// ✅ FIX: Helper function to safely display text
		function createTextElement(tag, className, text) {
			const element = document.createElement(tag);
			element.className = className;
			element.textContent = text;  // Safe: textContent prevents XSS
			return element;
		}
		
		async function registerUser() {
			const username = document.getElementById('register_username').value;
			const password = document.getElementById('register_password').value;
			
			const response = await fetch('/auth/register', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({username, password})
			});
			
			const data = await response.json();
			const result = document.getElementById('register_result');
			result.innerHTML = '';  // Clear previous content
			
			if (response.ok) {
				const div = document.createElement('div');
				div.className = 'result';
				// ✅ FIX: Use textContent instead of innerHTML
				div.textContent = `✓ Registered! User ID: ${data.user_id}, Username: ${data.username}`;
				result.appendChild(div);
			} else {
				const div = document.createElement('div');
				div.className = 'result error';
				div.textContent = `✗ ${data.detail}`;
				result.appendChild(div);
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
			result.innerHTML = '';
			
			if (response.ok) {
				const div = document.createElement('div');
				div.className = 'result';
				// ✅ FIX: Use textContent
				div.textContent = `✓ Login successful! User ID: ${data.user_id}`;
				result.appendChild(div);
			} else {
				const div = document.createElement('div');
				div.className = 'result error';
				div.textContent = `✗ ${data.message}`;
				result.appendChild(div);
			}
		}
		
		async function getProfile() {
			const userId = document.getElementById('profile_user_id').value;
			
			const response = await fetch(`/auth/profile/${userId}`);
			const data = await response.json();
			const result = document.getElementById('profile_result');
			result.innerHTML = '';
			
			if (response.ok) {
				// ✅ FIX: Build DOM safely without innerHTML
				const div = document.createElement('div');
				div.className = 'result';
				
				const h4 = document.createElement('h4');
				h4.textContent = 'Profile Information';
				div.appendChild(h4);
				
				const usernamePara = document.createElement('p');
				const usernameStrong = document.createElement('strong');
				usernameStrong.textContent = 'Username: ';
				usernamePara.appendChild(usernameStrong);
				usernamePara.appendChild(document.createTextNode(data.username));
				div.appendChild(usernamePara);
				
				const bioPara = document.createElement('p');
				const bioStrong = document.createElement('strong');
				bioStrong.textContent = 'Bio: ';
				bioPara.appendChild(bioStrong);
				bioPara.appendChild(document.createTextNode(data.bio));
				div.appendChild(bioPara);
				
				const createdPara = document.createElement('p');
				const createdStrong = document.createElement('strong');
				createdStrong.textContent = 'Created: ';
				createdPara.appendChild(createdStrong);
				createdPara.appendChild(document.createTextNode(data.created_at));
				div.appendChild(createdPara);
				
				result.appendChild(div);
			} else {
				const div = document.createElement('div');
				div.className = 'result error';
				div.textContent = `✗ ${data.detail}`;
				result.appendChild(div);
			}
		}
	</script>
</body>
</html>
	"""
```

**Key Security Improvements:**
- **Replaced ALL `innerHTML` assignments with safe DOM manipulation**<sup>[1](#ref1)</sup>
- Used `textContent` to prevent XSS when displaying user data
- Added password hashing with bcrypt
- Implemented session ID hashing before database storage<sup>[2](#ref2)</sup>
- Added Content-Security-Policy header
- Should add rate limiting (not shown for brevity)

**Pattern to Remember:**
```javascript
// ❌ DANGEROUS
element.innerHTML = `<p>${untrustedData}</p>`;

// ✅ SAFE
const p = document.createElement('p');
p.textContent = untrustedData;
element.appendChild(p);
```

---

## Key Takeaways

### The Three Types of XSS

1. **Reflected XSS** (Exercise 1): User input immediately reflected in response
2. **Stored XSS** (Exercise 2): Malicious payload stored in database
3. **DOM-Based XSS** (Exercise 3): Vulnerability in client-side JavaScript

### Universal Prevention Rules

1. **Never trust user input** - Always assume it's malicious
2. **Escape output** - Use `html.escape()` in Python, `textContent` in JavaScript
3. **Use parameterized queries** - Prevent SQL injection
4. **Implement CSP** - Content Security Policy headers
5. **Rate limit everything** - Prevent abuse and DoS
6. **Hash sensitive data** - Session IDs, passwords, tokens
7. **Disable debug mode** - Never run production with `debug=True`

These exercises are inspired by real vulnerabilities and industry-standard security books. I invest significant time ensuring each exercise is:
- **Technically accurate** - Based on actual CVEs and production incidents
- **Properly cited** - All patterns sourced from authoritative security literature  
- **Interview-relevant** - Covers topics asked in Security Engineer interviews at FAANG+ companies

**All 48 weeks of exercises available in the [SecEng-Exercises repository](https://github.com/fosres/SecEng-Exercises).** Star it to stay updated!

### References

<a name="ref1"></a>
1. Byrne, Dennis. *Full Stack Python Security*. Manning Publications, 2021. Chapter 14: "Cross-Site Scripting", pp. 208-226.

<a name="ref2"></a>
2. Madden, Neil. *API Security in Action*. Manning Publications, 2020. Chapter 2: "Secure API development", pp. 54-55.

<a name="ref3"></a>
3. Johnsson, Dan, et al. *Secure by Design*. Manning Publications, 2019. Chapter 9: "Handling output safely", pp. 247-249.

<a name="ref4"></a>
4. Ball, Corey. *Hacking APIs*. No Starch Press, 2022.

---

## 🚀 What's Next? Continue Your Security Training

This XSS challenge is just **one exercise** from a complete Security Engineering curriculum. The [SecEng-Exercises repository](https://github.com/fosres/SecEng-Exercises) includes:

### Current Exercises (Updated Weekly)
- ✅ Week 1-5: TCP/IP fundamentals, SQL injection, Python security patterns
- ✅ **Week 6: XSS vulnerabilities** (you just completed this!)
- 🔄 Week 7-10: SAST/DAST tools, authentication bypasses, API security
- 📅 Coming soon: Cryptographic attacks, race conditions, SSRF, and more

### What Makes These Exercises Different?
1. **Battle-tested patterns** - Every vulnerability is based on real CVEs and production incidents
2. **Comprehensive testing** - 60+ test cases per exercise ensure you truly understand the exploits
3. **Career-focused** - Designed to prepare you for Security Engineer interviews at top companies
4. **Open source** - Free forever, community-driven, continuously improving

### 📊 Exercise Difficulty Progression
- Weeks 1-8: Foundation (beginner-friendly)
- Weeks 9-16: Intermediate (interview-ready)  
- Weeks 17-24: Advanced (senior-level concepts)

## Practice Challenge

Can you identify which vulnerability would cause the most damage in each scenario?

1. **Exercise 1**: Which attack vector is most dangerous—the search query or the "no results" message?
2. **Exercise 2**: Why doesn't HTML escaping on the server prevent the XSS?
3. **Exercise 3**: If you could only fix ONE vulnerability, which would have the biggest security impact?

**⭐ [Star the GitHub repo](https://github.com/fosres/SecEng-Exercises)** and share your answers in the Issues tab—I respond to every submission!

---

## 🎯 Ready to Level Up Your Security Skills?

If this exercise helped you understand XSS better, imagine mastering:
- SQL injection with 15 different attack vectors
- JWT authentication bypasses
- Race condition exploits
- Cryptographic timing attacks
- API rate limit bypasses
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE) attacks

**All available for free in the repository.**

### Take Action Now:
1. **⭐ [Star the SecEng-Exercises repo](https://github.com/fosres/SecEng-Exercises)** - Get notified of new challenges
2. **🔀 Fork it** - Customize exercises for your learning style
3. **💬 Join discussions** - Ask questions, share solutions, help others
4. **📢 Share** - Help other aspiring Security Engineers discover these resources

### My Goal
I'm creating the **most comprehensive, free, open-source Security Engineering curriculum** available. Every week I add new exercises based on real vulnerabilities I've encountered in my career at Intel and from analyzing thousands of CVEs.

**Your ⭐ star helps more developers discover these resources and motivates me to create even better content.**

---

**Remember:** The TechFinance disaster started with a single XSS vulnerability. Don't let it happen to your application. 

**Master these patterns. Review code carefully. Always assume user input is malicious.**

### 🎓 Continue Your Journey
This is just Week 6 of a 48-week curriculum. **[Star the SecEng-Exercises repository](https://github.com/fosres/SecEng-Exercises)** to follow the complete path from beginner to senior Security Engineer.

**Next up:** Week 7 covers SAST/DAST tool implementation and code review automation—exercises drop this Friday!

---

*Built by a Security Engineer, for Security Engineers. All exercises are free and open source forever. Star the repo to support the project! ⭐*

**Repository:** https://github.com/fosres/SecEng-Exercises

Stay secure! 🔒
