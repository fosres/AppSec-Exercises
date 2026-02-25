#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║             XSS EXERCISE 1: SEARCH FUNCTIONALITY                          ║
║                    VULNERABLE IMPLEMENTATION                              ║
║                   FOR EDUCATIONAL PURPOSES ONLY                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

WHAT IS CROSS-SITE SCRIPTING (XSS)?
====================================
XSS allows attackers to inject malicious scripts into web applications.
When these scripts execute in victims' browsers, attackers can:
- Steal session cookies and authentication tokens
- Perform actions on behalf of the victim
- Redirect users to malicious sites
- Modify page content
- Log keystrokes

Your task: Figure out what type of XSS vulnerability exists in this application.

SETUP:
======
pip install flask --break-system-packages

RUN:
====
python3 xss_ex1_reflected_vulnerable.py

TEST (in another terminal):
============================
pytest xss_ex1_reflected_tests.py -v

SOURCES:
========
- "Full Stack Python Security" by Dennis Byrne, Chapter 14, pp. 208-226
- "API Security in Action" by Neil Madden, Chapter 2, pp. 54-55
- "Secure by Design" by Johnsson et al., Chapter 9, pp. 247-249
"""
from __future__ import annotations
from flask import Flask, request
from flask_talisman import Talisman

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import html

app = Flask(__name__)
talisman = Talisman(
			app,
			csp = {
			    'default-src': [
				'\'self\'',
			    ]
			}

)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5/minute"],
    storage_uri="memory://",
)

# Enforce HTTPS and other headers
talisman.x_xss_protection = True
talisman.x_content_type_options = True

# Add the headers to Talisman
talisman.content_security_policy = csp


@app.route('/')
@limiter.limit("5/minute")
def home():
	"""Home page with search form and educational content"""
	return """
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>XSS Exercise 1: Search Functionality</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body { 
			font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
			line-height: 1.6;
			background: #f5f5f5;
		}
		.container { max-width: 900px; margin: 0 auto; padding: 20px; }
		.warning {
			background: linear-gradient(135deg, #ff4444, #cc0000);
			color: white;
			padding: 20px;
			margin: 20px 0;
			border-radius: 8px;
			box-shadow: 0 4px 6px rgba(0,0,0,0.1);
		}
		.warning h2 { margin-bottom: 10px; }
		.card {
			background: white;
			padding: 30px;
			margin: 20px 0;
			border-radius: 8px;
			box-shadow: 0 2px 4px rgba(0,0,0,0.1);
		}
		h1 { color: #333; margin-bottom: 20px; }
		.search-box { margin: 30px 0; }
		input[type="text"] { 
			width: 100%; 
			padding: 15px;
			font-size: 16px;
			border: 2px solid #ddd;
			border-radius: 5px;
			margin-bottom: 10px;
		}
		input[type="text"]:focus {
			outline: none;
			border-color: #007bff;
		}
		button { 
			width: 100%;
			padding: 15px; 
			background: #007bff; 
			color: white; 
			border: none; 
			cursor: pointer;
			font-size: 16px;
			border-radius: 5px;
			transition: background 0.3s;
		}
		button:hover { background: #0056b3; }
		.payloads {
			background: #f8f9fa;
			padding: 20px;
			margin: 20px 0;
			border-left: 4px solid #ff4444;
			border-radius: 4px;
		}
		.payloads h3 { margin-bottom: 15px; color: #333; }
		.payload-item {
			background: white;
			padding: 10px;
			margin: 10px 0;
			border-radius: 4px;
			font-family: 'Courier New', monospace;
			font-size: 14px;
			word-break: break-all;
		}
		.payload-label {
			font-weight: bold;
			color: #666;
			margin-bottom: 5px;
		}
		.info-box {
			background: #e7f3ff;
			border-left: 4px solid #007bff;
			padding: 15px;
			margin: 20px 0;
			border-radius: 4px;
		}
		.test-command {
			background: #2d2d2d;
			color: #00ff00;
			padding: 15px;
			border-radius: 5px;
			font-family: 'Courier New', monospace;
			margin: 10px 0;
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="warning">
			<h2>⚠️ SECURITY WARNING</h2>
			<p>This is an <strong>INTENTIONALLY VULNERABLE</strong> application created for educational purposes.</p>
			<p><strong>DO NOT DEPLOY TO PRODUCTION!</strong></p>
		</div>
		
		<div class="card">
			<h1>🔍 Product Search</h1>
			
			<div class="search-box">
				<form action="/search" method="GET">
					<input type="text" name="q" placeholder="Search for products (try an XSS payload)..." autofocus>
					<button type="submit">Search</button>
				</form>
			</div>
			
			<div class="info-box">
				<strong>📚 Educational Context:</strong>
				<p>This search functionality contains an <strong>XSS vulnerability</strong>. 
				Study the code and run the tests to determine what type of XSS it is.</p>
			</div>
			
			<div class="info-box" style="background: #fff3cd; border-left-color: #ffc107;">
				<strong>🎯 Your Challenge:</strong>
				<p>Analyze the code, run the test suite, and discover:</p>
				<ul style="margin: 10px 0; padding-left: 20px;">
					<li>What type of XSS vulnerability exists?</li>
					<li>Where in the code is the vulnerability?</li>
					<li>Which attack payloads work and why?</li>
					<li>How would you defend against this?</li>
				</ul>
			</div>
		</div>
		
		<div class="card">
			<h2>🧪 Run Automated Tests</h2>
			<p>Execute 60 comprehensive XSS tests:</p>
			<div class="test-command">pytest xss_ex1_reflected_tests.py -v</div>
		</div>
	</div>
</body>
</html>
	"""


@app.route('/search')
@limiter.limit("5/minute")
def search():
	"""
	🔴 VULNERABLE ENDPOINT: Search with XSS
	
	VULNERABILITY DESCRIPTION:
	==========================
	User input from the 'q' query parameter is directly embedded into the
	HTML response using Python f-strings.
	
	This allows an attacker to inject arbitrary HTML and JavaScript that
	executes in the victim's browser context.
	
	ATTACK SCENARIO:
	================
	1. Attacker crafts malicious URL with payload in query parameter
	2. Victim clicks link (via email, social media, etc.)
	3. Malicious payload executes in victim's browser
	4. Attacker steals cookies, session tokens, or performs actions as victim
	
	YOUR TASK:
	==========
	Analyze this code and the test results to determine:
	- What type of XSS vulnerability is this?
	- Where exactly does the vulnerability occur?
	- How does the attack flow work?
	- What security controls are missing?
	"""
	query = request.args.get('q', '')

	query = html.escape(query,quote=True)

	print(f"request.headers: {request.headers}")
	
	# Simulate database search (mock implementation)
	results = []

	if query:
		query_lower = query.lower()
		if 'laptop' in query_lower:
			results = [
				{'name': 'Gaming Laptop Pro', 'price': 1299.99, 'stock': 12},
				{'name': 'Business Laptop Elite', 'price': 899.99, 'stock': 8},
				{'name': 'Student Laptop Budget', 'price': 499.99, 'stock': 25},
			]
		elif 'phone' in query_lower:
			results = [
				{'name': 'Smartphone X Pro', 'price': 999.99, 'stock': 15},
				{'name': 'Smartphone Y Lite', 'price': 599.99, 'stock': 30},
			]
		elif 'tablet' in query_lower:
			results = [
				{'name': 'Tablet Pro 12"', 'price': 799.99, 'stock': 10},
			]
	
	# 🔴 VULNERABILITY: Direct string interpolation
	html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Search Results</title>
	<style>
		* {{ margin: 0; padding: 0; box-sizing: border-box; }}
		body {{ 
			font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
			background: #f5f5f5;
			padding: 20px;
		}}
		.container {{ max-width: 900px; margin: 0 auto; }}
		.header {{
			background: white;
			padding: 20px;
			border-radius: 8px;
			margin-bottom: 20px;
			box-shadow: 0 2px 4px rgba(0,0,0,0.1);
		}}
		h1 {{ color: #333; }}
		.query {{ 
			color: #007bff; 
			font-weight: bold;
			word-break: break-all;
		}}
		.results {{ margin-top: 20px; }}
		.product {{ 
			background: white;
			border: 1px solid #ddd; 
			padding: 20px; 
			margin: 15px 0;
			border-radius: 8px;
			box-shadow: 0 2px 4px rgba(0,0,0,0.05);
			transition: box-shadow 0.3s;
		}}
		.product:hover {{ box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
		.product h3 {{ color: #333; margin-bottom: 10px; }}
		.price {{ 
			color: #28a745; 
			font-weight: bold; 
			font-size: 1.2em;
			margin: 10px 0;
		}}
		.stock {{ color: #666; font-size: 0.9em; }}
		.no-results {{
			background: white;
			padding: 30px;
			text-align: center;
			border-radius: 8px;
			color: #666;
		}}
		.back {{
			display: inline-block;
			margin: 20px 0;
			padding: 12px 24px;
			background: #6c757d;
			color: white;
			text-decoration: none;
			border-radius: 5px;
			transition: background 0.3s;
		}}
		.back:hover {{ background: #5a6268; }}
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>Search Results for: <span class="query">{query}</span></h1>
		</div>
		
		<div class="results">
	"""
	
	if results:
		for product in results:
			# 🔴 VULNERABILITY: Product data also rendered directly
			html += f"""
			<div class="product">
				<h3>{product['name']}</h3>
				<div class="price">${product['price']}</div>
				<div class="stock">In stock: {product['stock']} units</div>
			</div>
			"""
	else:
		# 🔴 VULNERABILITY: User input echoed in "no results" message
		html += f"""
		<div class="no-results">
			<h2>No Results Found</h2>
			<p>Your search for '<strong>{query}</strong>' did not match any products.</p>
		</div>
		"""
	
	html += """
		</div>
		<a href="/" class="back">← Back to Search</a>
	</div>
</body>
</html>
	"""
	
	return html


if __name__ == '__main__':
	print("╔" + "═" * 78 + "╗")
	print("║" + " " * 22 + "XSS EXERCISE 1: SEARCH APP" + " " * 30 + "║")
	print("║" + " " * 24 + "VULNERABLE VERSION" + " " * 33 + "║")
	print("╚" + "═" * 78 + "╝")
	print()
	print("⚠️  WARNING: This application contains INTENTIONAL security vulnerabilities!")
	print("   DO NOT deploy to production!")
	print()
	print("🌐 Server: http://127.0.0.1:5000")
	print()
	print("📍 Endpoints:")
	print("   /              - Home page with search form")
	print("   /search?q=X    - Search endpoint (VULNERABLE to XSS)")
	print()
	print("🧪 To test exploits:")
	print("   pytest xss_ex1_reflected_tests.py -v")
	print()
	print("🎯 Your Task:")
	print("   1. Run the tests to see which attacks work")
	print("   2. Analyze the code to find the vulnerability")
	print("   3. Determine what TYPE of XSS this is")
	print("   4. Figure out how to defend against it")
	print()
	print("=" * 80)
	
	app.run(debug=False, port=50000, host='127.0.0.1')
