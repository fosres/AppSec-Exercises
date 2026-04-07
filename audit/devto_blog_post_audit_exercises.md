---
title: "7 Full-Stack Security Audit Challenges: Can You Find All the Bugs?"
published: false
description: "Real full-stack Python + JavaScript code riddled with SQL Injection, XSS, IDOR, Path Traversal, SSRF, OS Command Injection, and Broken Auth. Audit it. Fix it. Ship secure code."
tags: security, python, webdev, appsec
---

# 7 Full-Stack Security Audit Challenges: Can You Find All the Bugs?

**Time:** Self-paced  
**Difficulty:** Intermediate to Advanced  
**Skills:** Web AppSec, Secure Code Review, Python, JavaScript

---

## The Breach That Changed Everything

In July 2019, a lone attacker compromised over 100 million Capital One customer records — credit card applications, Social Security numbers, bank account data — all from a single misconfigured AWS WAF. The root cause? A Server-Side Request Forgery vulnerability. The WAF's URL-fetching feature made an outbound HTTP request to the AWS metadata endpoint at `http://169.254.169.254/`, handed back temporary IAM credentials, and the attacker walked straight into an S3 bucket containing a decade of customer data.

Capital One paid $190 million in settlements. The attacker was a former AWS engineer who understood exactly which endpoint to hit.

The vulnerability wasn't exotic. It wasn't a zero-day. It was a feature — a URL fetcher — that trusted user input without validation. A developer built it. A code reviewer missed it. A security team didn't catch it in production until it was too late.

This pattern repeats constantly. The 2017 Equifax breach? Apache Struts with a known CVE sitting unpatched for months. The 2020 Twitter hack? Social engineering into an internal admin panel with no IDOR protection. The 2022 Optus breach? An unauthenticated API endpoint returning customer records with sequential IDs.

The vulnerabilities in these stories are the same ones you are about to audit.

---

## Bug Classes Under the Microscope

These seven exercises cover the following vulnerability classes:

```
1.  Broken Authentication / Authorization
    a. Session Cookie Authentication + CSRF
    b. Password Authentication
    c. JWT Token Authentication

2.  SQL Injection

3.  XSS (Cross-Site Scripting)

4.  Server-Side Request Forgery (SSRF)

5.  IDOR (Insecure Direct Object Reference)

6.  Missing Rate Limiting

7.  OS Path Traversal

8.  OS Command Injection

9.  Malicious File Uploads

10. Security Misconfigurations

11. API Key Management & Authentication

12. Security Logging and Monitoring Failures
```

Each exercise embeds 3–6 of these classes into a realistic multi-file full-stack application. No labels. No hints. Audit it like a real codebase.

---

## The Rules

For each exercise:

1. **Find every bug** — identify the file, the vulnerable line, and the bug class
2. **Write a sample payload** — demonstrate how an attacker would exploit it
3. **Fix it** — write corrected code that defends at the right layer

Ready? Let's go.

---

## Exercise 1 — FastAPI + React

**App:** User search portal

**`main.py`**
```python
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from sqlalchemy import text

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/user")
async def get_user(request: Request):
	user = request.query_params.get("username")
	query = f"SELECT * FROM users WHERE username = '{user}'"
	result = db.session.execute(text(query)).fetchall()
	return templates.TemplateResponse("results.html", {"request": request, "results": result})
```

**`UserSearch.jsx`**
```jsx
import { useState } from 'react';

export default function UserSearch() {
	const [username, setUsername] = useState('');

	const searchUser = async () => {
		const response = await fetch(`/user?username=${username}`);
		const html = await response.text();
		document.getElementById('results').innerHTML = html;
	};

	return (
		<div>
			<input
				type="text"
				value={username}
				onChange={(e) => setUsername(e.target.value)}
				placeholder="Enter username"
			/>
			<button onClick={searchUser}>Search</button>
			<div id="results"></div>
		</div>
	);
}
```

**`templates/results.html`**
```html
<h1>Results</h1>
<ul>
	{% for row in results %}
		<li>{{ row }}</li>
	{% endfor %}
</ul>
```

---

## Exercise 2 — Flask + React

**App:** Blog platform with file uploads and profile management

**Database Schema:**
```sql
CREATE TABLE users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT UNIQUE NOT NULL,
	password TEXT NOT NULL,
	email TEXT NOT NULL,
	role TEXT DEFAULT 'user'
);

CREATE TABLE posts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	title TEXT NOT NULL,
	content TEXT,
	author_id INTEGER NOT NULL,
	FOREIGN KEY (author_id) REFERENCES users(id)
);
```

**`app.py`**
```python
from flask import Flask, request, render_template, redirect, url_for, session, flash
import sqlite3
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/upload', methods=['POST'])
def upload_file():
	if 'file' not in request.files:
		return "No file uploaded", 400
	file = request.files['file']
	if file.filename == '':
		return "No file selected", 400
	file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
	return "File uploaded successfully!"

@app.route('/search')
def search_posts():
	query = request.args.get('q')
	conn = sqlite3.connect('database.db')
	cursor = conn.cursor()
	cursor.execute(f"SELECT * FROM posts WHERE title LIKE '%{query}%'")
	results = cursor.fetchall()
	conn.close()
	return render_template('results.html', results=results)

@app.route('/profile', methods=['POST'])
def update_profile():
	username = session.get('username')
	new_email = request.form['email']
	conn = sqlite3.connect('database.db')
	cursor = conn.cursor()
	cursor.execute(f"UPDATE users SET email = '{new_email}' WHERE username = '{username}'")
	conn.commit()
	conn.close()
	flash('Profile updated!')
	return redirect(url_for('profile'))

if __name__ == '__main__':
	app.run(debug=True)
```

**`Search.jsx`**
```jsx
import { useState } from 'react';

export default function Search() {
	if (query) {
		const handleSearch = async () => {
			const response = await fetch(`/search?q=${query}`);
			const html = await response.text();
			document.getElementById('results').innerHTML = html;
		};
	}
	return (
		<div>
			<input
				type="text"
				value={query}
				onChange={(e) => setQuery(e.target.value)}
				placeholder="Search posts..."
			/>
			<button onClick={handleSearch}>Search</button>
			<div id="results"></div>
		</div>
	);
}
```

---

## Exercise 3 — FastAPI + React

**App:** Admin panel with JWT authentication

**`app.py`**
```python
from fastapi import FastAPI, Request, Form, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
import sqlite3
import os
import subprocess
import requests
from jose import JWTError, jwt
from datetime import datetime, timedelta

app = FastAPI()
app.secret_key = "supersecretkey"
templates = Jinja2Templates(directory="templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
	to_encode = data.copy()
	expire = datetime.utcnow() + timedelta(days=365)
	to_encode.update({"exp": expire})
	return jwt.encode(to_encode, "supersecretkey", algorithm="HS256")

@app.get("/fetch")
async def fetch_url(url: str):
	response = requests.get(url)
	return {"content": response.text}

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
	conn = sqlite3.connect("database.db")
	cursor = conn.cursor()
	cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
	user = cursor.fetchone()
	conn.close()
	if not user:
		raise HTTPException(status_code=401, detail="Invalid credentials")
	token = create_access_token({"sub": username})
	return {"access_token": token}

@app.get("/admin")
async def admin_panel(token: str = Depends(oauth2_scheme)):
	payload = jwt.decode(token, "supersecretkey", algorithms=["HS256"])
	username = payload.get("sub")
	conn = sqlite3.connect("database.db")
	cursor = conn.cursor()
	cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
	user = cursor.fetchone()
	conn.close()
	if user[3] != "admin":
		raise HTTPException(status_code=403, detail="Unauthorized")
	return {"message": "Admin Panel"}

@app.get("/ping")
async def ping_server(host: str):
	result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True, text=True)
	return {"output": result.stdout}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
	file.save(os.path.join("uploads", file.filename))
	return {"message": "File uploaded!"}
```

**`Search.jsx`**
```jsx
import { useState } from "react";

export default function Search() {
	const [url, setUrl] = useState("");

	const handleFetch = async () => {
		const response = await fetch(`/fetch?url=${url}`);
		const data = await response.json();
		document.getElementById("results").innerHTML = data.content;
	};

	return (
		<div>
			<input
				type="text"
				value={url}
				onChange={(e) => setUrl(e.target.value)}
				placeholder="Enter URL..."
			/>
			<button onClick={handleFetch}>Fetch</button>
			<div id="results"></div>
		</div>
	);
}
```

---

## Exercise 4 — Django + Alpine.js (DevDash)

**App:** Developer dashboard with avatar uploads, report search, and DNS diagnostics

**`devdash/settings.py`**
```python
SECRET_KEY = 'django-insecure-abc123xyz'
DEBUG = True
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
	'django.contrib.admin',
	'django.contrib.auth',
	'django.contrib.contenttypes',
	'django.contrib.sessions',
	'django.contrib.messages',
	'django.contrib.staticfiles',
	'dashboard',
]

MIDDLEWARE = [
	'django.middleware.security.SecurityMiddleware',
	'django.contrib.sessions.middleware.SessionMiddleware',
	'django.middleware.common.CommonMiddleware',
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'django.contrib.messages.middleware.MessageMiddleware',
]
```

**`dashboard/views.py`**
```python
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.db import connection
import requests
import os
import subprocess
from .models import Report, UserProfile

def set_avatar(request):
	if request.method == 'POST':
		avatar_url = request.POST.get('avatar_url', '')
		user_id = request.POST.get('user_id')
		response = requests.get(avatar_url, timeout=5)
		upload_path = os.path.join('media/avatars', f'{user_id}_avatar.png')
		with open(upload_path, 'wb') as f:
			f.write(response.content)
		profile = UserProfile.objects.get(user_id=user_id)
		profile.avatar_url = upload_path
		profile.save()
		return JsonResponse({'status': 'avatar updated'})
	return JsonResponse({'error': 'invalid method'}, status=405)

def search_reports(request):
	q = request.GET.get('q', '')
	with connection.cursor() as cursor:
		cursor.execute(
			f"SELECT id, title, content FROM dashboard_report WHERE title LIKE '%{q}%'"
		)
		rows = cursor.fetchall()
	return JsonResponse({'results': rows})

def get_report(request, report_id):
	report = get_object_or_404(Report, id=report_id)
	return JsonResponse({
		'id': report.id,
		'title': report.title,
		'content': report.content,
		'owner': report.owner.username
	})

def run_diagnostic(request):
	if request.method == 'POST':
		target = request.POST.get('target', '')
		result = subprocess.run(
			f'dig +short {target}',
			shell=True,
			capture_output=True,
			text=True
		)
		return JsonResponse({'output': result.stdout})
	return JsonResponse({'error': 'invalid method'}, status=405)

def admin_users(request):
	users = User.objects.values('id', 'username', 'email', 'is_staff')
	return JsonResponse({'users': list(users)})
```

**`templates/dashboard.html`**
```html
<!DOCTYPE html>
<html>
<head><title>DevDash</title></head>
<body>
<div x-data="dashboard()" x-init="init()">
	<div>
		<input type="text" x-model="avatarUrl" placeholder="Paste image URL..." />
		<input type="text" x-model="userId" placeholder="User ID..." />
		<button @click="setAvatar()">Update</button>
	</div>
	<div>
		<input type="text" x-model="searchQuery" placeholder="Search..." />
		<button @click="searchReports()">Search</button>
		<div x-html="searchResults"></div>
	</div>
	<div>
		<input type="text" x-model="diagTarget" placeholder="Enter hostname..." />
		<button @click="runDiagnostic()">Run</button>
		<pre x-text="diagOutput"></pre>
	</div>
</div>
<script src="//cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</body>
</html>
```

---

## Exercise 5 — Django + Next.js (InvoiceHub)

**App:** Billing platform with invoice management and file downloads

**`billing/views.py`**
```python
from django.http import JsonResponse, FileResponse
from django.contrib.auth.models import User
from django.db import connection
import subprocess
import os
import requests
from .models import Invoice, APIKey

def get_invoices(request):
	api_key = request.headers.get('X-API-Key', '')
	key_obj = APIKey.objects.filter(key=api_key).first()
	owner_id = key_obj.owner_id if key_obj else None
	with connection.cursor() as cursor:
		cursor.execute(
			f"SELECT id, title, amount, pdf_filename FROM billing_invoice WHERE owner_id = {owner_id}"
		)
		rows = cursor.fetchall()
	return JsonResponse({'invoices': rows})

def download_invoice(request):
	filename = request.GET.get('file', '')
	filepath = os.path.join('/var/invoices', filename)
	return FileResponse(open(filepath, 'rb'))

def health_check(request):
	host = request.GET.get('host', 'localhost')
	result = subprocess.run(
		f'curl -s --max-time 3 {host}',
		shell=True,
		capture_output=True,
		text=True
	)
	return JsonResponse({'status': result.stdout})

def get_invoice(request, invoice_id):
	with connection.cursor() as cursor:
		cursor.execute(
			f"SELECT id, title, amount, pdf_filename, owner_id FROM billing_invoice WHERE id = {invoice_id}"
		)
		row = cursor.fetchone()
	if not row:
		return JsonResponse({'error': 'not found'}, status=404)
	return JsonResponse({'id': row[0], 'title': row[1], 'amount': str(row[2]), 'pdf_filename': row[3]})

def create_api_key(request):
	if request.method == 'POST':
		import secrets
		user_id = request.POST.get('user_id')
		key = secrets.token_hex(32)
		APIKey.objects.create(key=key, owner_id=user_id)
		return JsonResponse({'api_key': key})
	return JsonResponse({'error': 'invalid method'}, status=405)
```

**`components/InvoiceDashboard.tsx`**
```tsx
'use client';
import { useState } from 'react';

export default function InvoiceDashboard() {
	const [invoices, setInvoices] = useState([]);
	const [searchHtml, setSearchHtml] = useState('');
	const [host, setHost] = useState('');

	const loadInvoices = async () => {
		const apiKey = localStorage.getItem('api_key');
		const res = await fetch('/api/invoices/', {
			headers: { 'X-API-Key': apiKey || '' }
		});
		const data = await res.json();
		setInvoices(data.invoices);
	};

	const searchInvoices = async (query: string) => {
		const res = await fetch(`/api/invoices/?search=${query}`);
		const html = await res.text();
		setSearchHtml(html);
	};

	const checkHealth = async () => {
		const res = await fetch(`/api/admin/health/?host=${host}`);
		const data = await res.json();
	};

	const downloadInvoice = (filename: string) => {
		window.location.href = `/api/invoices/download/?file=${filename}`;
	};

	return (
		<div>
			<button onClick={loadInvoices}>Load Invoices</button>
			<ul>
				{invoices.map((inv: any) => (
					<li key={inv[0]}>
						{inv[1]} - ${inv[2]}
						<button onClick={() => downloadInvoice(inv[3])}>Download PDF</button>
					</li>
				))}
			</ul>
			<div>
				<input placeholder="Search invoices..." onChange={(e) => searchInvoices(e.target.value)} />
				<div dangerouslySetInnerHTML={{ __html: searchHtml }} />
			</div>
			<div>
				<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="Health check host..." />
				<button onClick={checkHealth}>Check</button>
			</div>
		</div>
	);
}
```

---

## Exercise 6 — FastAPI + Nuxt.js (TeamCollab)

**App:** Team collaboration platform with documents, webhooks, and file uploads

**`app/main.py`**
```python
from fastapi import FastAPI, Request, Header, UploadFile, File, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
import subprocess
import httpx
import os
import sqlite3

app = FastAPI()
SECRET_KEY = "teamcollab-secret-hardcoded-2024"
UPLOAD_DIR = "uploads"

def get_db():
	conn = sqlite3.connect("teamcollab.db")
	try:
		yield conn
	finally:
		conn.close()

@app.get("/documents/search")
async def search_documents(q: str, db: sqlite3.Connection = Depends(get_db)):
	cursor = db.cursor()
	cursor.execute(
		f"SELECT id, title, content, owner_id FROM documents WHERE title LIKE '%{q}%' OR content LIKE '%{q}%'"
	)
	return {"results": cursor.fetchall()}

@app.get("/documents/{doc_id}")
async def get_document(doc_id: int, x_api_token: str = Header(None), db: sqlite3.Connection = Depends(get_db)):
	cursor = db.cursor()
	cursor.execute(f"SELECT id, title, content, owner_id, is_public FROM documents WHERE id = {doc_id}")
	doc = cursor.fetchone()
	if not doc:
		return {"error": "not found"}, 404
	return {"id": doc[0], "title": doc[1], "content": doc[2]}

@app.post("/workspaces/{workspace_id}/notify")
async def notify_workspace(workspace_id: int, payload: dict, db: sqlite3.Connection = Depends(get_db)):
	cursor = db.cursor()
	cursor.execute(f"SELECT webhook_url FROM workspaces WHERE id = {workspace_id}")
	row = cursor.fetchone()
	if not row:
		return {"error": "not found"}
	webhook_url = row[0]
	async with httpx.AsyncClient() as client:
		await client.post(webhook_url, json=payload)
	return {"status": "notified"}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), x_api_token: str = Header(None)):
	dest = os.path.join(UPLOAD_DIR, file.filename)
	with open(dest, "wb") as f:
		content = await file.read()
		f.write(content)
	return {"path": dest}

@app.get("/admin/run")
async def run_command(cmd: str, x_api_token: str = Header(None)):
	result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
	return {"output": result.stdout}

@app.post("/auth/login")
async def login(username: str, password: str, db: sqlite3.Connection = Depends(get_db)):
	cursor = db.cursor()
	cursor.execute(
		f"SELECT id, username, role, api_token FROM users WHERE username = '{username}' AND password_hash = '{password}'"
	)
	user = cursor.fetchone()
	if not user:
		return {"error": "invalid credentials"}
	return {"api_token": user[3], "role": user[2]}
```

**`pages/documents.vue`**
```vue
<template>
	<div>
		<input v-model="searchQuery" @input="search" placeholder="Search documents..." />
		<div v-html="searchResults"></div>
		<div v-for="doc in documents" :key="doc.id">
			<h3>{{ doc.title }}</h3>
			<div v-html="doc.content"></div>
			<button @click="downloadDoc(doc.id)">Download</button>
		</div>
		<div>
			<input v-model="webhookPayload" placeholder="Webhook payload..." />
			<button @click="triggerWebhook">Send Webhook</button>
		</div>
	</div>
</template>

<script setup>
import { ref } from 'vue'
const searchQuery = ref('')
const searchResults = ref('')
const documents = ref([])
const webhookPayload = ref('')
const apiToken = localStorage.getItem('api_token')

const search = async () => {
	const res = await fetch(`/api/documents/search?q=${searchQuery.value}`)
	const html = await res.text()
	searchResults.value = html
}

const downloadDoc = (id) => {
	window.location.href = `/api/documents/${id}/download?token=${apiToken}`
}

const triggerWebhook = async () => {
	await fetch('/api/workspaces/1/notify', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: webhookPayload.value
	})
}
</script>
```

---

## Exercise 7 — Django + Angular (MedPortal)

**App:** Medical records portal for clinic staff, doctors, and administrators

**`medportal/settings.py`**
```python
SECRET_KEY = 'medportal-django-insecure-key-xyz987'
DEBUG = True
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
	'django.contrib.admin',
	'django.contrib.auth',
	'django.contrib.contenttypes',
	'django.contrib.sessions',
	'django.contrib.messages',
	'django.contrib.staticfiles',
	'portal',
]

MIDDLEWARE = [
	'django.middleware.security.SecurityMiddleware',
	'django.contrib.sessions.middleware.SessionMiddleware',
	'django.middleware.common.CommonMiddleware',
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'django.contrib.messages.middleware.MessageMiddleware',
]

DATABASES = {
	'default': {
		'ENGINE': 'django.db.backends.sqlite3',
		'NAME': 'medportal.db',
	}
}
```

**`portal/views.py`**
```python
from django.http import JsonResponse, FileResponse, HttpResponse
from django.contrib.auth import authenticate
from django.db import connection
import subprocess
import os
import requests
from .models import Patient, LabResult, AuditLog

def login(request):
	if request.method == 'POST':
		import json
		data = json.loads(request.body)
		username = data.get('username', '')
		password = data.get('password', '')
		user = authenticate(username=username, password=password)
		if user:
			return JsonResponse({'token': user.auth_token.key, 'role': user.profile.role})
		return JsonResponse({'error': 'invalid credentials'}, status=401)

def search_patients(request):
	q = request.GET.get('q', '')
	with connection.cursor() as cursor:
		cursor.execute(
			f"SELECT id, full_name, diagnosis FROM portal_patient WHERE full_name LIKE '%{q}%'"
		)
		rows = cursor.fetchall()
	return JsonResponse({'patients': rows})

def get_patient(request, patient_id):
	with connection.cursor() as cursor:
		cursor.execute(
			f"SELECT id, full_name, date_of_birth, diagnosis FROM portal_patient WHERE id = {patient_id}"
		)
		row = cursor.fetchone()
		if not row:
			return JsonResponse({'error': 'not found'}, status=404)
	return JsonResponse({'id': row[0], 'name': row[1], 'dob': str(row[2]), 'diagnosis': row[3]})

def download_lab_result(request):
	filename = request.GET.get('file', '')
	filepath = os.path.join('/var/lab_results', filename)
	return FileResponse(open(filepath, 'rb'))

def run_export(request):
	report_type = request.GET.get('type', 'daily')
	result = subprocess.run(
		f'python manage.py export_report --type={report_type}',
		shell=True,
		capture_output=True,
		text=True
	)
	return JsonResponse({'output': result.stdout})

def fetch_external_guidelines(request):
	url = request.GET.get('url', '')
	response = requests.get(url, timeout=5)
	return JsonResponse({'content': response.text})

def upload_lab_result(request):
	if request.method == 'POST':
		f = request.FILES.get('file')
		patient_id = request.POST.get('patient_id')
		if f:
			dest = os.path.join('/var/lab_results', f.name)
			with open(dest, 'wb+') as dest_file:
				for chunk in f.chunks():
					dest_file.write(chunk)
			LabResult.objects.create(patient_id=patient_id, filename=f.name, uploaded_by=request.user)
			return JsonResponse({'status': 'uploaded'})
	return JsonResponse({'error': 'invalid request'}, status=400)
```

**`src/app/patient-search.component.ts`**
```typescript
import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
	selector: 'app-patient-search',
	template: `
		<div>
			<input [(ngModel)]="query" (input)="search()" placeholder="Search patients..." />
			<div [innerHTML]="searchResults"></div>
			<div *ngFor="let p of patients">
				<h3>{{ p.name }}</h3>
				<p [innerHTML]="p.diagnosis"></p>
				<button (click)="downloadLab(p.id)">Download Lab Result</button>
			</div>
			<div>
				<input [(ngModel)]="guidelinesUrl" placeholder="Guidelines URL..." />
				<button (click)="fetchGuidelines()">Fetch</button>
				<div [innerHTML]="guidelinesContent"></div>
			</div>
			<div>
				<input [(ngModel)]="exportType" placeholder="Export type..." />
				<button (click)="runExport()">Run Export</button>
				<pre>{{ exportOutput }}</pre>
			</div>
		</div>
	`
})
export class PatientSearchComponent {
	query = '';
	searchResults: SafeHtml = '';
	patients: any[] = [];
	guidelinesUrl = '';
	guidelinesContent: SafeHtml = '';
	exportType = '';
	exportOutput = '';

	constructor(private http: HttpClient, private sanitizer: DomSanitizer) {}

	search() {
		this.http.get(`/api/patients/search/?q=${this.query}`, { responseType: 'text' })
			.subscribe(html => {
				this.searchResults = this.sanitizer.bypassSecurityTrustHtml(html);
			});
	}

	fetchGuidelines() {
		this.http.get(`/api/guidelines/fetch/?url=${this.guidelinesUrl}`)
			.subscribe((res: any) => {
				this.guidelinesContent = this.sanitizer.bypassSecurityTrustHtml(res.content);
			});
	}

	downloadLab(patientId: number) {
		const token = localStorage.getItem('auth_token');
		window.location.href = `/api/lab-results/download/?file=${patientId}_result.pdf&token=${token}`;
	}

	runExport() {
		this.http.get(`/api/reports/export/?type=${this.exportType}`)
			.subscribe((res: any) => {
				this.exportOutput = res.output;
			});
	}
}
```

---

## My Solutions

> ⚠️ **Stop scrolling if you haven't attempted the exercises.** Solutions below.

---

### Solution — Exercise 1

**Bugs found:** SQL Injection, DOM XSS, IDOR (missing auth)

**`main.py` — Fixed**
```python
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from pydantic import BaseModel

class LoginRequest(BaseModel):
	username: str
	password: str

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.post("/user")
async def get_user(request: Request, body: LoginRequest):
	user = body.username
	passwd = body.password
	if not authenticate_user(user, passwd):
		raise Exception("Invalid Credentials")
	query = "SELECT * FROM users WHERE username = :user"
	result = db.session.execute(text(query), {"user": user}).fetchall()
	return templates.TemplateResponse("results.html", {"request": request, "results": result})
```

**`UserSearch.jsx` — Fixed**
```jsx
import { useState } from 'react';

export default function UserSearch() {
	const [username, setUsername] = useState('');
	const [password, setPassword] = useState('');

	const searchUser = async () => {
		const user_regex = /^[a-zA-Z0-9-_.]+$/;
		if (!user_regex.test(username)) throw new Error("Invalid credentials");

		const response = await fetch('/api/users', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username, password })
		});

		if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

		const resp = await response.text();
		document.getElementById('results').textContent = resp;
	};

	return (
		<div>
			<input type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Enter username" />
			<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Enter password" />
			<button onClick={searchUser}>Search</button>
			<div id="results"></div>
		</div>
	);
}
```

---

### Solution — Exercise 2

**Bugs found:** Hardcoded secret, Path Traversal, SQLi (×2), Missing Auth, DOM XSS, No Rate Limiting, `debug=True`

**`app.py` — Fixed**
```python
from flask_wtf.csrf import CSRFProtect
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"], storage_uri="memory://")
app.secret_key = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/upload', methods=['POST'])
@limiter.limit("5 per minute")
def upload_file():
	if 'file' not in request.files:
		return "No file uploaded", 400
	file = request.files['file']
	if file.filename == '':
		return "No file selected", 400
	cookie_value = request.cookies.get('session')
	session_data = verify_session_cookie(cookie_value)
	if not session_data:
		return jsonify({"error": "Unauthorized"}), 401
	base_dir = os.path.abspath('uploads')
	pwd_file = os.path.abspath(os.path.join(base_dir, file.filename))
	if not pwd_file.startswith(base_dir + os.sep):
		raise Exception("Invalid filepath")
	file.save(pwd_file)
	return "File uploaded successfully!"

@app.route('/search')
@limiter.limit("5 per minute")
def search_posts():
	query = request.args.get('q')
	conn = sqlite3.connect('database.db')
	cursor = conn.cursor()
	cursor.execute("SELECT * FROM posts WHERE title LIKE ?", ('%' + query + '%',))
	results = cursor.fetchall()
	conn.close()
	return render_template('results.html', results=results)

@app.route('/profile', methods=['POST'])
@limiter.limit("5 per minute")
def update_profile():
	username = session.get('username')
	password = request.form['password']
	cookie_value = request.cookies.get('session')
	session_data = verify_session_cookie(cookie_value)
	new_email = request.form['email']
	conn = sqlite3.connect('database.db')
	cursor = conn.cursor()
	if not authenticate_user(username, password):
		raise Exception("Invalid Credentials")
	cursor.execute("UPDATE users SET email = ? WHERE username = ?", (new_email, username))
	conn.commit()
	conn.close()
	flash('Profile updated!')
	return redirect(url_for('profile'))

if __name__ == '__main__':
	app.run(debug=False)
```

**`Search.jsx` — Fixed**
```jsx
import { useState } from 'react';

export default function Search() {
	const [query, setQuery] = useState('');

	const handleSearch = async () => {
		if (!query) return;
		const response = await fetch(`/search?q=${query}`);
		const resp = await response.text();
		document.getElementById('results').textContent = resp;
	};

	return (
		<div>
			<input type="text" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search posts..." />
			<button onClick={handleSearch}>Search</button>
			<div id="results"></div>
		</div>
	);
}
```

---

### Solution — Exercise 3

**Bugs found:** Hardcoded secrets (×2), SSRF, SQLi + plaintext password in login, JWT no failure handling, JWT 365-day expiry, OS Command Injection, Path Traversal, No Rate Limiting, DOM XSS

**`app.py` — Fixed**
```python
from fastapi import FastAPI, Request, Form, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi import File, UploadFile
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from passlib.hash import argon2
from jose import jwt
import sqlite3
import os
import subprocess
import shlex
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
	to_encode = data.copy()
	expire = datetime.utcnow() + timedelta(minutes=30)
	to_encode.update({"exp": expire})
	token = ''
	try:
		token = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
	except Exception:
		raise HTTPException(status_code=401, detail="Invalid credentials")
	return token

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
	conn = sqlite3.connect("database.db")
	cursor = conn.cursor()
	cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
	pwhash = cursor.fetchone()
	if not pwhash or not argon2.verify(password, pwhash[0]):
		conn.close()
		raise HTTPException(status_code=401, detail="Invalid credentials")
	conn.close()
	token = create_access_token({"sub": username})
	return {"access_token": token}

@app.get("/admin")
@limiter.limit("5/minute")
async def admin_panel(request: Request, token: str = Depends(oauth2_scheme)):
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
	except Exception:
		raise HTTPException(status_code=403, detail="Unauthorized")
	username = payload.get("sub")
	conn = sqlite3.connect("database.db")
	cursor = conn.cursor()
	cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
	user = cursor.fetchone()
	conn.close()
	if not user or user[3] != "admin":
		raise HTTPException(status_code=403, detail="Unauthorized")
	return {"message": "Admin Panel"}

@app.get("/ping")
@limiter.limit("5/minute")
async def ping_server(request: Request, host: str):
	raw_arg_list = "ping -c 4 " + shlex.quote(host)
	cmd_list = shlex.split(raw_arg_list)
	result = subprocess.run(cmd_list, capture_output=True, text=True, shell=False)
	return {"output": result.stdout}

@app.post("/upload")
@limiter.limit("5/minute")
async def upload_file(request: Request, file: UploadFile = File(...)):
	base_dir = os.path.abspath('uploads')
	pwd_file = os.path.abspath(os.path.join(base_dir, file.filename))
	if not pwd_file.startswith(base_dir + os.sep):
		raise HTTPException(status_code=403, detail="Unauthorized")
	with open(pwd_file, "wb") as f:
		content = await file.read()
		f.write(content)
	return {"message": "File uploaded!"}
```

---

### Solution — Exercise 4

**Bugs found:** Hardcoded secret, `DEBUG=True`, `ALLOWED_HOSTS=['*']`, SSRF (Capital One pattern), Path Traversal, SQLi, OS Command Injection, IDOR (get_report + admin_users), XSS via `x-html`, No Rate Limiting, No TLS

**`devdash/settings.py` — Fixed**
```python
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
COOKIE_KEY = os.getenv('COOKIE_KEY')
DEBUG = False
ALLOWED_HOSTS = ['first_allow.com', 'second_allow.com']

INSTALLED_APPS = [
	'django.contrib.admin',
	'django.contrib.auth',
	'django.contrib.contenttypes',
	'django.contrib.sessions',
	'django.contrib.messages',
	'django.contrib.staticfiles',
	'dashboard',
]

MIDDLEWARE = [
	'django.middleware.security.SecurityMiddleware',
	'django.contrib.sessions.middleware.SessionMiddleware',
	'django.middleware.common.CommonMiddleware',
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'django.contrib.messages.middleware.MessageMiddleware',
]

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

**`dashboard/views.py` — Fixed (key excerpts)**
```python
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.db import connection
from django_ratelimit.decorators import ratelimit
from django.views.decorators.csrf import csrf_protect
from urllib.parse import urlparse
from dotenv import load_dotenv
import jwt, requests, os, shlex, subprocess
from .models import Report, UserProfile

load_dotenv()
COOKIE_KEY = os.getenv('COOKIE_KEY')

def is_valid_url(url: str, allow_list: list[str]) -> bool:
	parsed = urlparse(url)
	hostname = parsed.netloc.split(':')[0]
	return hostname in allow_list

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def set_avatar(request):
	if request.method == 'POST':
		token = request.COOKIES.get('report_token')
		if not token:
			return JsonResponse({'error': 'not authenticated'}, status=401)
		try:
			payload = jwt.decode(token, COOKIE_KEY, algorithms=['HS256'],
				issuer="issuer_here", audience="audience_here")
		except Exception:
			return JsonResponse({'error': 'not authenticated'}, status=401)
		avatar_url = request.POST.get('avatar_url', '')
		user_id = request.POST.get('user_id')
		if str(payload['user_id']) != str(user_id):
			return JsonResponse({'error': 'not authorized'}, status=403)
		allowlist_urls = ['first_allow.com', 'second_allow.com']
		if not is_valid_url(avatar_url, allowlist_urls):
			return JsonResponse({'error': 'avatar NOT updated'}, status=405)
		response = requests.get(avatar_url, allow_redirects=False, timeout=5)
		base_dir = os.path.abspath('media/avatars')
		pwd_file = os.path.abspath(os.path.join(base_dir, f'{user_id}_avatar.png'))
		if not pwd_file.startswith(base_dir + os.sep):
			return JsonResponse({'error': 'avatar NOT updated'}, status=405)
		with open(pwd_file, 'wb') as f:
			f.write(response.content)
		profile = UserProfile.objects.get(user_id=user_id)
		profile.avatar_url = pwd_file
		profile.save()
		return JsonResponse({'status': 'avatar updated'})
	return JsonResponse({'error': 'invalid method'}, status=405)

@ratelimit(key='ip', rate='5/m')
def search_reports(request):
	q = request.GET.get('q', '')
	with connection.cursor() as cursor:
		cursor.execute(
			"SELECT id, title, content FROM dashboard_report WHERE title LIKE %s",
			('%' + q + '%',)
		)
		rows = cursor.fetchall()
	return JsonResponse({'results': rows})

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def get_report(request, report_id):
	token = request.COOKIES.get('report_token')
	if not token:
		return JsonResponse({'error': 'not authenticated'}, status=401)
	try:
		payload = jwt.decode(token, COOKIE_KEY, algorithms=['HS256'],
			issuer="issuer_here", audience="audience_here")
	except Exception:
		return JsonResponse({'error': 'not authenticated'}, status=401)
	report = get_object_or_404(Report, id=report_id)
	if payload['username'] != report.owner.username:
		return JsonResponse({'error': 'not authorized'}, status=403)
	return JsonResponse({'id': report.id, 'title': report.title,
		'content': report.content, 'owner': report.owner.username})

@ratelimit(key='ip', rate='5/m')
def run_diagnostic(request):
	if request.method == 'POST':
		target = request.POST.get('target', '')
		target_sanitize = shlex.quote(target)
		cmd = 'dig +short ' + target_sanitize
		cmd_list = shlex.split(cmd)
		result = subprocess.run(cmd_list, shell=False, capture_output=True, text=True)
		return JsonResponse({'output': result.stdout})
	return JsonResponse({'error': 'invalid method'}, status=405)

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def admin_users(request):
	token = request.COOKIES.get('report_token')
	if not token:
		return JsonResponse({'error': 'not authenticated'}, status=401)
	try:
		payload = jwt.decode(token, COOKIE_KEY, algorithms=['HS256'],
			issuer="issuer_here", audience="audience_here")
	except Exception:
		return JsonResponse({'error': 'not authenticated'}, status=401)
	if payload['role'] != 'admin':
		return JsonResponse({'error': 'not authorized'}, status=403)
	users = User.objects.values('id', 'username', 'email', 'is_staff')
	return JsonResponse({'users': list(users)})
```

**`templates/dashboard.html` — Fixed (XSS sink)**
```html
<!-- x-html replaced with x-text throughout -->
<div x-text="searchResults"></div>
```

---

### Solution — Exercise 5

**Bugs found:** Hardcoded secret, `DEBUG=True`, `ALLOWED_HOSTS=['*']`, SQLi (×2), Path Traversal, OS Command Injection + SSRF in health_check, IDOR (get_invoice + create_api_key), DOM XSS, No Rate Limiting, No TLS

**`invoicehub/settings.py` — Fixed**
```python
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = False
ALLOWED_HOSTS = ['first_domain.com', 'second_domain.com']

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

**`billing/views.py` — Fixed (key excerpts)**
```python
from django.http import JsonResponse, FileResponse
from django.contrib.auth.models import User
from django.db import connection
from django_ratelimit.decorators import ratelimit
from django.views.decorators.csrf import csrf_protect
from urllib.parse import urlparse
from dotenv import load_dotenv
import shlex, subprocess, jwt, os, requests, secrets

load_dotenv()
COOKIE_KEY = os.getenv('COOKIE_KEY')

def is_valid_url(url: str, allow_list: list[str]) -> bool:
	parsed = urlparse(url)
	hostname = parsed.netloc.split(':')[0]
	return hostname in allow_list

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def get_invoice(request, invoice_id):
	token = request.COOKIES.get('report_token')
	if not token:
		return JsonResponse({'error': 'not authenticated'}, status=401)
	try:
		payload = jwt.decode(token, COOKIE_KEY, algorithms=['HS256'],
			issuer="issuer_here", audience="audience_here")
	except Exception:
		return JsonResponse({'error': 'not authenticated'}, status=401)
	api_key = request.headers.get('X-API-Key', '')
	key_obj = APIKey.objects.filter(key=api_key).first()
	owner_id = key_obj.owner_id if key_obj else None
	if not owner_id or payload['owner_id'] != owner_id:
		return JsonResponse({'error': 'not authorized'}, status=403)
	with connection.cursor() as cursor:
		cursor.execute(
			"SELECT id, title, amount, pdf_filename, owner_id FROM billing_invoice WHERE id = %s",
			(invoice_id,)
		)
		row = cursor.fetchone()
	if not row or row[4] != owner_id:
		return JsonResponse({'error': 'not found'}, status=404)
	return JsonResponse({'id': row[0], 'title': row[1], 'amount': str(row[2]), 'pdf_filename': row[3]})

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def health_check(request):
	token = request.COOKIES.get('report_token')
	if not token:
		return JsonResponse({'error': 'not authenticated'}, status=401)
	try:
		payload = jwt.decode(token, COOKIE_KEY, algorithms=['HS256'],
			issuer="issuer_here", audience="audience_here")
	except Exception:
		return JsonResponse({'error': 'not authenticated'}, status=401)
	if payload['role'] != 'admin':
		return JsonResponse({'error': 'not authorized'}, status=403)
	host = request.GET.get('host', 'localhost')
	allowlist = ['first.com', 'second.com']
	if not is_valid_url(host, allowlist):
		return JsonResponse({'error': 'not authorized'}, status=403)
	host_sanitize = shlex.quote(host)
	argument = 'curl -s --max-time 3 ' + host_sanitize
	cmd_list = shlex.split(argument)
	result = subprocess.run(cmd_list, shell=False, capture_output=True, text=True)
	return JsonResponse({'status': result.stdout})
```

**`components/InvoiceDashboard.tsx` — Fixed**
```tsx
{/* DOM XSS fixed — dangerouslySetInnerHTML removed */}
<div>{searchHtml}</div>

const downloadInvoice = (filename: string) => {
	window.location.href = `/api/invoices/download/?file=${encodeURIComponent(filename)}`;
};
```

---

### Solution — Exercise 6

**Bugs found:** Hardcoded secret, SQLi (×4), IDOR (×2), Path Traversal, OS Command Injection, SSRF (webhook), Missing Auth on all endpoints, XSS via `v-html`, No Rate Limiting

**`app/main.py` — Fixed imports**
```python
from fastapi import FastAPI, Request, Header, UploadFile, File, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette_csrf import CSRFMiddleware
from urllib.parse import urlparse
from dotenv import load_dotenv
from passlib.hash import argon2
import subprocess, httpx, shlex, jwt, os, sqlite3, secrets
```

**Key fixed views (excerpts)**
```python
@app.post("/workspaces/{workspace_id}/notify")
@limiter.limit("5/minute")
async def notify_workspace(request: Request, workspace_id: int, payload: dict,
		db: sqlite3.Connection = Depends(get_db)):
	token = request.cookies.get('session')
	if not token:
		return JSONResponse({'error': 'not authenticated'}, status_code=401)
	try:
		jwt_payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
	except Exception:
		return JSONResponse({'error': 'invalid token'}, status_code=401)
	cursor = db.cursor()
	cursor.execute("SELECT webhook_url, owner_id FROM workspaces WHERE id = :workspace_id",
		{"workspace_id": workspace_id})
	row = cursor.fetchone()
	if not row or jwt_payload['owner_id'] != int(row[1]):
		return JSONResponse({'error': 'not authorized'}, status_code=403)
	webhook_url = row[0]
	allowlist_domains = ['first.com', 'second.com']
	if not is_valid_url(webhook_url, allowlist_domains):
		return JSONResponse({'error': 'not authorized'}, status_code=403)
	async with httpx.AsyncClient() as client:
		await client.post(webhook_url, json=payload)
	return {"status": "notified"}
```

**`pages/documents.vue` — Fixed**
```vue
<!-- v-html replaced with v-text throughout -->
<div v-text="searchResults"></div>
<div v-text="doc.content"></div>
```

---

### Solution — Exercise 7

**Bugs found:** Hardcoded secret, `DEBUG=True`, `ALLOWED_HOSTS=['*']`, Missing CSRF + Clickjacking middleware, No TLS, SQLi (×2), IDOR (×2), Path Traversal (×2), OS Command Injection, SSRF, Missing Auth on all endpoints, XSS via `[innerHTML]` + `bypassSecurityTrustHtml`, No Rate Limiting, Missing AuditLog calls

**`portal/models.py` — Fixed (Profile + authorization matrix)**
```python
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class Profile(models.Model):
	"""
	Role-based access control for MedPortal.

	Authorization matrix:
	┌─────────────┬──────────────────────────────────────────────────────────┐
	│ Role        │ Permissions                                              │
	├─────────────┼──────────────────────────────────────────────────────────┤
	│ staff       │ - Upload lab results                                     │
	│             │ - Search patients by name                                │
	│             │ - View patient basic info (name, DOB)                    │
	│             │ - Cannot view diagnosis                                  │
	│             │ - Cannot download lab results                            │
	│             │ - Cannot run exports                                     │
	│             │ - Cannot fetch external guidelines                       │
	├─────────────┼──────────────────────────────────────────────────────────┤
	│ doctor      │ - All staff permissions                                  │
	│             │ - View full patient record including diagnosis            │
	│             │ - Download lab results for assigned patients only        │
	│             │ - Fetch external clinical guidelines                     │
	│             │ - Cannot run report exports                              │
	│             │ - Cannot access other doctors' patients                  │
	├─────────────┼──────────────────────────────────────────────────────────┤
	│ admin       │ - Full access to all endpoints                           │
	│             │ - Run report exports                                     │
	│             │ - View all patients regardless of assigned doctor        │
	│             │ - View all lab results                                   │
	│             │ - Cannot be assigned as a doctor to a patient            │
	└─────────────┴──────────────────────────────────────────────────────────┘
	"""

	class Role(models.TextChoices):
		STAFF = 'staff', 'Staff'
		DOCTOR = 'doctor', 'Doctor'
		ADMIN = 'admin', 'Admin'

	user = models.OneToOneField(User, on_delete=models.CASCADE)
	role = models.CharField(max_length=50, choices=Role.choices, default=Role.STAFF)

@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
	if created:
		Profile.objects.create(user=instance)
```

**`medportal/settings.py` — Fixed**
```python
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = False
ALLOWED_HOSTS = ['medportal.com', 'secondportal.com']

MIDDLEWARE = [
	'django.middleware.security.SecurityMiddleware',
	'django.contrib.sessions.middleware.SessionMiddleware',
	'django.middleware.common.CommonMiddleware',
	'django.middleware.clickjacking.XFrameOptionsMiddleware',
	'django.middleware.csrf.CsrfViewMiddleware',
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'django.contrib.messages.middleware.MessageMiddleware',
]

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

**`portal/views.py` — Fixed (key excerpts)**
```python
@csrf_protect
@ratelimit(key='ip', rate='5/m')
def get_patient(request, patient_id):
	cookie_value = request.COOKIES.get('session')
	session_data = verify_session_cookie(cookie_value)
	if not session_data:
		return JsonResponse({'error': 'Invalid Credentials'}, status=401)
	if session_data['role'].lower() not in ['doctor', 'admin']:
		return JsonResponse({'error': 'Not Authorized'}, status=403)
	with connection.cursor() as cursor:
		cursor.execute(
			"SELECT id, full_name, date_of_birth, diagnosis, assigned_doctor_id FROM portal_patient WHERE id = %s",
			(patient_id,)
		)
		row = cursor.fetchone()
		if not row:
			return JsonResponse({'error': 'not found'}, status=404)
		assigned_doctor = row[4]
		if session_data['role'].lower() == 'doctor' and assigned_doctor != session_data['id']:
			return JsonResponse({'error': 'Not Authorized'}, status=403)
	return JsonResponse({'id': row[0], 'name': row[1], 'dob': str(row[2]), 'diagnosis': row[3]})

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def download_lab_result(request):
	cookie_value = request.COOKIES.get('session')
	session_data = verify_session_cookie(cookie_value)
	if not session_data:
		return JsonResponse({'error': 'Invalid Credentials'}, status=401)
	if session_data['role'].lower() not in ['doctor', 'admin']:
		return JsonResponse({'error': 'Not Authorized'}, status=403)
	with connection.cursor() as cursor:
		filename = request.GET.get('file', '')
		base_dir = os.path.abspath('/var/lab_results')
		pwd_file = os.path.abspath(os.path.join(base_dir, filename))
		if not pwd_file.startswith(base_dir + os.sep):
			return JsonResponse({'error': 'Invalid filepath.'}, status=404)
		cursor.execute(
			"SELECT patient_id, filename FROM portal_labresult WHERE filename = %s",
			(filename,)
		)
		row = cursor.fetchone()
		if not row:
			return JsonResponse({'error': 'not found'}, status=404)
		patient_id = row[0]
		cursor.execute(
			"SELECT assigned_doctor_id FROM portal_patient WHERE id = %s",
			(patient_id,)
		)
		doctor_row = cursor.fetchone()
		if not doctor_row:
			return JsonResponse({'error': 'not found'}, status=404)
		assigned_doctor = doctor_row[0]
		if session_data['role'].lower() == 'doctor' and assigned_doctor != session_data['id']:
			return JsonResponse({'error': 'Not Authorized'}, status=403)
	return FileResponse(open(pwd_file, 'rb'))
```

**`src/app/patient-search.component.ts` — Fixed**
```typescript
// [innerHTML] replaced with {{ }} interpolation throughout
// bypassSecurityTrustHtml removed entirely
// SafeHtml type replaced with plain string

export class PatientSearchComponent {
	query = '';
	searchResults = '';
	patients: any[] = [];
	guidelinesContent = '';
	exportOutput = '';

	search() {
		this.http.get(`/api/patients/search/?q=${this.query}`, { responseType: 'text' })
			.subscribe(resp => {
				this.searchResults = resp;
			});
	}
}
```

---

## What You Learned

After seven exercises across FastAPI, Flask, and Django backends paired with React, Vue.js, Alpine.js, Next.js, Nuxt.js, and Angular frontends — here is the pattern that runs through every single vulnerability:

**Every bug is a trust boundary violation.** SQL injection trusts user input in a query. IDOR trusts a client-supplied ID without verifying ownership. SSRF trusts a URL without validating the destination. Path traversal trusts a filename without verifying the path stays inside its directory. The fix is always the same question: *at which layer does the server establish trust, and is that layer actually enforced?*

The XSS sink table is worth memorizing:

| Framework | Unsafe | Safe |
|---|---|---|
| React | `dangerouslySetInnerHTML` | `{variable}` |
| Vue.js | `v-html` | `v-text` / `{{ }}` |
| Alpine.js | `x-html` | `x-text` |
| Next.js | `dangerouslySetInnerHTML` | `{variable}` |
| Nuxt.js | `v-html` | `v-text` / `{{ }}` |
| Angular | `[innerHTML]` / `bypassSecurityTrustHtml()` | `{{ }}` |

Every frontend framework has exactly one escape hatch that bypasses auto-escaping. That escape hatch is always the XSS sink.

---

## Take the Challenge

All exercises are available in the open source repository:

⭐ **[github.com/fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)**

Found a bug I missed? Disagree with a fix? Drop it in the comments. The best security engineers argue about this stuff.

*What vulnerability class trips you up most often?* → [Vote here](https://strawpoll.com/wby5QoKAkyA)

---

*Written by Tanveer Salim — Security Engineer in training, Intel IPAS alumni, 553+ threat models documented. Follow on Dev.to: [@fosres](https://dev.to/fosres)*
