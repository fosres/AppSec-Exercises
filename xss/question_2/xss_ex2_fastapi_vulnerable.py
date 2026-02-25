#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                    XSS EXERCISE 2: COMMENT BOARD                          ║
║                    VULNERABLE IMPLEMENTATION                              ║
║                   FOR EDUCATIONAL PURPOSES ONLY                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

A modern API-based comment board built with FastAPI.
Users can post comments and view all comments.
Comments are stored in a SQLite database for persistence.

SETUP:
======
pip install fastapi uvicorn --break-system-packages

RUN:
====
python3 xss_ex2_fastapi_vulnerable.py

TEST:
=====
pytest xss_ex2_fastapi_tests.py -v

SOURCES:
========
- "Full Stack Python Security" by Dennis Byrne, Chapter 14, pp. 208-226
- "API Security in Action" by Neil Madden
- "Hacking APIs" by Corey Ball

YOUR TASK:
==========
Find ALL security vulnerabilities in this application.
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from typing import List
from datetime import datetime
import html
import uvicorn
import sqlite3
import os

app = FastAPI()

# Database file
DB_FILE = 'comments.db'

limiter = Limiter(key_func=get_remote_address)

def init_db():
	"""Initialize SQLite database"""
	conn = sqlite3.connect(DB_FILE)
	cursor = conn.cursor()
	
	cursor.execute('''
		CREATE TABLE IF NOT EXISTS comments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			author TEXT NOT NULL,
			content TEXT NOT NULL,
			timestamp TEXT NOT NULL
		)
	''')
	
	conn.commit()
	conn.close()


def get_db():
	"""Get database connection"""
	conn = sqlite3.connect(DB_FILE)
	conn.row_factory = sqlite3.Row
	return conn


class Comment(BaseModel):
	author: str
	content: str


@app.get("/", response_class=HTMLResponse)
@limiter.limit("5/minute")
async def home(request: Request):
	"""Main page with comment form"""
	return """
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Comment Board</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: Arial, sans-serif;
			max-width: 800px;
			margin: 50px auto;
			padding: 20px;
			background: #f5f5f5;
		}
		.warning {
			background: #ff4444;
			color: white;
			padding: 15px;
			border-radius: 5px;
			margin-bottom: 20px;
		}
		.container {
			background: white;
			padding: 30px;
			border-radius: 8px;
			box-shadow: 0 2px 4px rgba(0,0,0,0.1);
		}
		h1 { color: #333; margin-bottom: 20px; }
		.form-group {
			margin-bottom: 15px;
		}
		label {
			display: block;
			margin-bottom: 5px;
			font-weight: bold;
			color: #555;
		}
		input, textarea {
			width: 100%;
			padding: 10px;
			border: 2px solid #ddd;
			border-radius: 4px;
			font-size: 14px;
		}
		textarea {
			min-height: 100px;
			resize: vertical;
		}
		button {
			background: #007bff;
			color: white;
			padding: 12px 30px;
			border: none;
			border-radius: 4px;
			cursor: pointer;
			font-size: 16px;
		}
		button:hover {
			background: #0056b3;
		}
		.comments {
			margin-top: 40px;
		}
		.comment {
			background: #f9f9f9;
			padding: 15px;
			margin-bottom: 15px;
			border-left: 4px solid #007bff;
			border-radius: 4px;
		}
		.comment-author {
			font-weight: bold;
			color: #333;
			margin-bottom: 5px;
		}
		.comment-time {
			font-size: 12px;
			color: #999;
			margin-bottom: 10px;
		}
		.comment-content {
			color: #555;
			line-height: 1.6;
		}
	</style>
</head>
<body>
	<div class="warning">
		⚠️ WARNING: VULNERABLE APPLICATION - FOR EDUCATIONAL PURPOSES ONLY
	</div>
	
	<div class="container">
		<h1>💬 Comment Board</h1>
		
		<form id="commentForm">
			<div class="form-group">
				<label>Your Name:</label>
				<input type="text" id="author" required>
			</div>
			
			<div class="form-group">
				<label>Comment:</label>
				<textarea id="content" required></textarea>
			</div>
			
			<button type="submit">Post Comment</button>
		</form>
		
		<div class="comments">
			<h2>All Comments</h2>
			<div id="commentsContainer"></div>
		</div>
	</div>
	
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
				headers: {
					'Content-Type': 'application/json',
	
				},
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

				# Stored XSS Vulnerabilities Below
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
@limiter.limit("5/minute")
async def create_comment(request: Request,comment: Comment):
	"""Create a new comment"""
	conn = get_db()
	cursor = conn.cursor()
	
	timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	# SQL Injection Vulnerability Below

	# Stored XSS Vulnerability possible


	author = html.escape(comment.author,quote=True)
	
	content = html.escape(comment.content,quote=True)
	
	# Insert into database
	query = f"INSERT INTO comments (author, content, timestamp) VALUES (?,?,?)"
	
	cursor.execute(query,(author,content,timestamp))
	
	comment_id = cursor.lastrowid
	conn.commit()
	conn.close()
	
	comment_data = {
		"id": comment_id,
		"author": comment.author,
		"content": comment.content,
		"timestamp": timestamp
	}
	
	return {"status": "success", "comment": comment_data}


@app.get("/api/comments")
@limiter.limit("5/minute")
async def get_comments(request: Request):
	"""Get all comments"""
	conn = get_db()
	cursor = conn.cursor()
	
	cursor.execute("SELECT * FROM comments ORDER BY id DESC")
	rows = cursor.fetchall()
	
	comments = []
	for row in rows:
		comments.append({
			"id": row["id"],
			"author": row["author"],
			"content": row["content"],
			"timestamp": row["timestamp"]
		})
	
	conn.close()
	return comments


@app.delete("/api/comments")
@limiter.limit("5/minute")
async def delete_all_comments(request: Request):
	"""Delete all comments (for testing)"""
	conn = get_db()
	cursor = conn.cursor()
	
	cursor.execute("DELETE FROM comments")
	conn.commit()
	conn.close()
	
	return {"status": "success", "message": "All comments deleted"}


@app.get("/api/comment/{comment_id}")
@limiter.limit("5/minute")
async def get_comment(request: Request,comment_id: int):
	"""Get a specific comment"""
	conn = get_db()
	cursor = conn.cursor()

	# SQL Injection Vulnerability Below
	
	# Vulnerable SQL query
	query = f"SELECT * FROM comments WHERE id = ?"
	cursor.execute(query,(comment_id,))
	row = cursor.fetchone()
	
	conn.close()
	
	if row:
		return {
			"id": row["id"],
			"author": row["author"],
			"content": row["content"],
			"timestamp": row["timestamp"]
		}
	
	return {"error": "Comment not found"}


if __name__ == "__main__":
	print("╔" + "═" * 78 + "╗")
	print("║" + " " * 25 + "XSS EXERCISE 2: COMMENT BOARD" + " " * 25 + "║")
	print("║" + " " * 28 + "VULNERABLE VERSION" + " " * 29 + "║")
	print("╚" + "═" * 78 + "╝")
	print()
	print("⚠️  WARNING: This application contains INTENTIONAL security vulnerabilities!")
	print("   DO NOT deploy to production!")
	print()
	print("🌐 Server: http://127.0.0.1:8000")
	print()
	print("📍 Endpoints:")
	print("   GET  /                  - Main page")
	print("   POST /api/comments      - Create comment")
	print("   GET  /api/comments      - Get all comments")
	print("   GET  /api/comment/{id}  - Get specific comment")
	print()
	print("🧪 To test:")
	print("   pytest xss_ex2_fastapi_tests.py -v")
	print()
	print("🎯 Your Task:")
	print("   Find ALL security vulnerabilities")
	print("   Determine the XSS type(s)")
	print("   Implement proper defenses")
	print()
	print("=" * 80)
	
	# Initialize database
	if os.path.exists(DB_FILE):
		os.remove(DB_FILE)
	init_db()
	print(f"✓ Database initialized: {DB_FILE}\n")
	
	# Run development server
	uvicorn.run(app, host="127.0.0.1", port=50000, log_level="info")
