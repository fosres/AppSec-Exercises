---
title: "Master SQL Injection Detection: 15 Real-World Exercises for AppSec Engineers"
published: false
description: "Learn to spot and fix SQL injection vulnerabilities with hands-on exercises covering SELECT, INSERT, UPDATE, DELETE, and second-order attacks. Essential practice for Security Engineering interviews."
tags: appsec, security, sql, python
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/placeholder.jpg
---

# Master SQL Injection Detection: 15 Real-World Exercises for AppSec Engineers

## The $1.5 Billion Wake-Up Call

In 2015, hackers exploited a SQL injection vulnerability in the UK telecommunications company TalkTalk, stealing personal data of 157,000 customers—including names, addresses, dates of birth, and 15,600 bank account numbers. The company paid £400,000 in fines and lost an estimated £60 million in direct costs and customer compensation [^1]. The attacker? A 17-year-old who used one of the oldest and most preventable vulnerabilities in web security.

This isn't an isolated incident. According to the OWASP Top 10 2025 (released November 6, 2025), injection attacks rank as **A05:2025 – Injection**, affecting **100% of applications tested for some form of injection** [^2]. While SQL injection has decreased in frequency due to better frameworks and awareness, the **impact remains catastrophically high**:

- **SQL injection: Low frequency, high impact** with **14,000+ CVEs** [^2]
- **Average impact:** Injection vulnerabilities can lead to complete data compromise
- **Testing coverage:** 100% of applications tested for injection vulnerabilities [^2]
- **37 CWEs in the injection category** - the greatest number of CVEs for any OWASP Top 10 2025 category [^2]

Translation: SQL injection is less common than it used to be, but when it appears, it's devastating. OWASP explicitly characterizes SQL injection as "**low frequency/high impact**"—meaning fewer applications are vulnerable, but those that are face complete compromise.

## Why Security Engineers Must Master SQL Injection

If you're interviewing for Security Engineering or Application Security roles at companies like **GitLab, Stripe, Coinbase, Trail of Bits, or NCC Group**, you'll face SQL injection questions. Not theory—**live code review scenarios** where you must:

1. **Identify vulnerable code** in unfamiliar frameworks
2. **Craft working exploit payloads** demonstrating impact
3. **Provide secure fixes** using parameterized queries
4. **Explain why validation alone fails** as a defense

These skills separate candidates who've read about SQL injection from those who can **actually find and fix it in production code**.

## About This Exercise Set

I created these 15 exercises while building my AppSec engineering skills, drawing from:

- **PortSwigger Web Security Academy** SQL Injection labs [^3]
- **OWASP SQL Injection Prevention Cheat Sheet** [^4]
- **Secure by Design** (Manning, 2017) - Chapters 1-3
- **API Security in Action** (Manning, 2020) - Chapter 2

Each exercise presents **real-world vulnerable code** you might encounter during security reviews or penetration tests. All exercises include:

✅ Vulnerability identification  
✅ Exploit payload construction  
✅ Secure parameterized query fixes  
✅ Explanations of why defenses fail

**⭐ Want more exercises like this?** Star my repository: **[AppSec-Exercises on GitHub](https://github.com/fosres/AppSec-Exercises)** for LeetCode-style secure coding challenges.

---

## Exercise 1: Authentication Bypass - The Classic Attack

**Difficulty:** Beginner  
**Vulnerability Type:** WHERE Clause Injection

### The Vulnerable Code

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
	username = request.form.get('username')
	password = request.form.get('password')
	
	conn = sqlite3.connect('users.db')
	cursor = conn.cursor()
	
	query = "SELECT id, username FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
	
	cursor.execute(query)
	user = cursor.fetchone()
	conn.close()
	
	if user:
		return jsonify({"message": "Login successful", "user_id": user[0]})
	else:
		return jsonify({"message": "Invalid credentials"}), 401
```

### Your Challenge

1. **Is this vulnerable to SQL injection?** (Yes/No)
2. **Craft a payload** for the `username` field that bypasses authentication without knowing any passwords
3. **Provide the secure fix** using SQLite parameterized queries

**💡 Solution at the end of this post**

---

## Exercise 2: Partial Parameterization - Why Half-Secure Fails

**Difficulty:** Beginner  
**Vulnerability Type:** Mixed Parameterization Anti-Pattern

### The Vulnerable Code

```python
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search_products():
	search_term = request.args.get('q', '')
	category = request.args.get('category', 'all')
	
	search_term = search_term.replace("'", "''")
	
	conn = psycopg2.connect(database="store", user="app", password="secret")
	cursor = conn.cursor()
	
	if category == 'all':
		query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
		cursor.execute(query)
	else:
		query = "SELECT * FROM products WHERE name LIKE %s AND category = %s"
		cursor.execute(query, ('%' + search_term + '%', category))
	
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"products": results})
```

### Your Challenge

1. **Is the `category == 'all'` branch vulnerable?** (Yes/No)
2. **Why does the string escaping** (`replace("'", "''")`) **fail to prevent SQL injection?**
3. **Provide the correct parameterized query fix** for the vulnerable branch

**💡 Solution at the end of this post**

---

## Exercise 3: LIKE Clause Injection - Wildcards Don't Protect You

**Difficulty:** Beginner  
**Vulnerability Type:** LIKE Clause Injection

### Database Schema

```sql
CREATE TABLE products (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	price DECIMAL(10,2),
	category TEXT
);

CREATE TABLE admin_notes (
	id INTEGER PRIMARY KEY,
	product_id INTEGER,
	note TEXT,
	created_by TEXT
);
```

### The Vulnerable Code

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search_products():
	search_term = request.args.get('q', '')
	
	conn = sqlite3.connect('shop.db')
	cursor = conn.cursor()
	
	query = f"SELECT id, name, price FROM products WHERE name LIKE '%{search_term}%'"
	
	cursor.execute(query)
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"products": results})
```

### Your Challenge

1. **Is this vulnerable?** The search term is wrapped in `%` wildcards—does this prevent injection?
2. **Craft a payload** that extracts sensitive data from the `admin_notes` table
3. **Provide the secure fix** with proper wildcard handling

**💡 Solution at the end of this post**

---

## Exercise 4: Second-Order SQL Injection - The Delayed Attack

**Difficulty:** Intermediate  
**Vulnerability Type:** Second-Order Injection

### Database Schema

```sql
CREATE TABLE users (
	id INTEGER PRIMARY KEY,
	username TEXT UNIQUE NOT NULL,
	email TEXT,
	password_hash TEXT
);

CREATE TABLE posts (
	id INTEGER PRIMARY KEY,
	author TEXT,
	content TEXT,
	created_at DATETIME
);
```

### The Vulnerable Code (Two Endpoints)

```python
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

# Endpoint 1: Update profile (SAFE)
@app.route('/update-profile', methods=['POST'])
def update_profile():
	user_id = request.form.get('user_id')
	bio = request.form.get('bio')
	
	conn = psycopg2.connect(host='localhost', user='app', password='pass', database='social')
	cursor = conn.cursor()
	
	query = "UPDATE users SET bio = %s WHERE id = %s"
	cursor.execute(query, (bio, user_id))
	conn.commit()
	conn.close()
	
	return jsonify({"message": "Profile updated successfully"})

# Endpoint 2: Get user posts (VULNERABLE)
@app.route('/get-user-posts', methods=['GET'])
def get_user_posts():
	user_id = request.args.get('user_id')
	
	conn = psycopg2.connect(host='localhost', user='app', password='pass', database='social')
	cursor = conn.cursor()
	
	cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
	user = cursor.fetchone()
	
	if not user:
		return jsonify({"error": "User not found"}), 404
	
	username = user[0]
	
	query = "SELECT post_id, content, created_at FROM posts WHERE author = '" + username + "' ORDER BY created_at DESC"
	cursor.execute(query)
	posts = cursor.fetchall()
	
	conn.close()
	
	return jsonify({"username": username, "posts": posts})
```

### Your Challenge

1. **Which endpoint is vulnerable?** (update-profile, get-user-posts, or both?)
2. **Explain the attack flow:** Which endpoint stores malicious data and which triggers the injection?
3. **Craft a malicious username** that would extract password hashes when viewing posts
4. **Provide the secure fix** for the vulnerable endpoint

**💡 Solution at the end of this post**

---

## Exercise 5: ORDER BY Injection - When Parameterization Isn't Enough

**Difficulty:** Intermediate  
**Vulnerability Type:** ORDER BY Clause Injection

### Database Schema

```sql
CREATE TABLE products (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	price DECIMAL(10,2),
	category TEXT,
	stock_quantity INTEGER
);
```

### The Vulnerable Code

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/products', methods=['GET'])
def list_products():
	sort_by = request.args.get('sort', 'name')
	order = request.args.get('order', 'ASC')
	
	conn = sqlite3.connect('shop.db')
	cursor = conn.cursor()
	
	if order.upper() not in ['ASC', 'DESC']:
		return jsonify({"error": "Invalid order"}), 400
	
	query = f"SELECT id, name, price FROM products ORDER BY {sort_by} {order}"
	
	cursor.execute(query)
	products = cursor.fetchall()
	conn.close()
	
	return jsonify({"products": products})
```

### Your Challenge

1. **Is this vulnerable?** The developer validated `order` but not `sort_by`.
2. **Why can't you use parameterized queries for ORDER BY column names?**
3. **Provide the secure fix** using whitelist validation

**💡 Solution at the end of this post**

---

## Exercise 6: Numeric Context Injection - Quotes Aren't Always Required

**Difficulty:** Beginner  
**Vulnerability Type:** Numeric Parameter Injection

### Database Schema

```sql
CREATE TABLE products (
	id INTEGER PRIMARY KEY,
	name TEXT,
	price DECIMAL(10,2),
	category TEXT
);

CREATE TABLE users (
	id INTEGER PRIMARY KEY,
	username TEXT,
	password_hash TEXT,
	email TEXT
);
```

### The Vulnerable Code

```python
import pymysql
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/product/<int:product_id>', methods=['GET'])
def get_product_details(product_id):
	limit = request.args.get('limit', '10')
	
	conn = pymysql.connect(host='localhost', user='app', password='secret', database='store')
	cursor = conn.cursor()
	
	query = f"SELECT * FROM products WHERE id = {product_id} LIMIT {limit}"
	
	cursor.execute(query)
	result = cursor.fetchone()
	conn.close()
	
	return jsonify({"product": result})
```

### Your Challenge

1. **Is `product_id` vulnerable?** Flask validates it as an integer in the route.
2. **Is `limit` vulnerable?** It's expected to be numeric.
3. **Craft a UNION attack payload** for the vulnerable parameter to extract user passwords
4. **Provide the secure fix**

**💡 Solution at the end of this post**

---

## Exercise 7: INSERT Statement Privilege Escalation

**Difficulty:** Intermediate  
**Vulnerability Type:** INSERT Injection with Role Escalation

### Database Schema

```sql
CREATE TABLE users (
	id INTEGER PRIMARY KEY,
	username TEXT UNIQUE,
	email TEXT,
	password_hash TEXT,
	country TEXT,
	role TEXT DEFAULT 'user'
);
```

### The Vulnerable Code

```python
import psycopg2
from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
	username = request.form.get('username')
	email = request.form.get('email')
	password = request.form.get('password')
	country = request.form.get('country', 'US')
	
	# Hash the password
	password_hash = hashlib.sha256(password.encode()).hexdigest()
	
	conn = psycopg2.connect(database="users", user="app", password="secret")
	cursor = conn.cursor()
	
	query = """
		INSERT INTO users (username, email, password_hash, country, role) 
		VALUES (%s, %s, %s, '""" + country + """', 'user')
	"""
	
	cursor.execute(query, (username, email, password_hash))
	conn.commit()
	conn.close()
	
	return jsonify({"message": "Registration successful"})
```

### Your Challenge

1. **Which parameter is vulnerable?**
2. **Why doesn't partial parameterization work?**
3. **Craft a payload** for `country` that creates an admin account
4. **Provide the secure fix**

**💡 Solution at the end of this post**

---

## Exercise 8: UPDATE Statement Column Injection

**Difficulty:** Intermediate  
**Vulnerability Type:** UPDATE with Additional Column Injection

### Database Schema

```sql
CREATE TABLE users (
	id INTEGER PRIMARY KEY,
	username TEXT,
	email TEXT,
	bio TEXT,
	role TEXT DEFAULT 'user',
	account_balance DECIMAL(10,2) DEFAULT 0
);
```

### The Vulnerable Code

```python
import psycopg2
from flask import Flask, request, jsonify, session

app = Flask(__name__)

@app.route('/update-bio', methods=['POST'])
def update_bio():
	user_id = session.get('user_id')
	new_bio = request.form.get('bio')
	
	conn = psycopg2.connect(database="users", user="app", password="secret")
	cursor = conn.cursor()
	
	query = f"UPDATE users SET bio = '{new_bio}' WHERE id = %s"
	
	cursor.execute(query, (user_id,))
	conn.commit()
	conn.close()
	
	return jsonify({"message": "Bio updated successfully"})
```

### Your Challenge

1. **Is the `bio` parameter vulnerable?**
2. **Is the `user_id` parameter safe?** (Consider where it comes from)
3. **Craft a payload** that sets role='admin' and account_balance=1000000 while keeping a legitimate bio
4. **Provide the secure fix**

**💡 Solution at the end of this post**

---

## Exercise 9: DELETE Statement - Bypassing Authorization

**Difficulty:** Beginner  
**Vulnerability Type:** DELETE with WHERE Bypass

### Database Schema

```sql
CREATE TABLE posts (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL,
	title TEXT,
	content TEXT,
	created_at DATETIME
);
```

### The Vulnerable Code

```python
import sqlite3
from flask import Flask, request, jsonify, session

app = Flask(__name__)

@app.route('/delete-post', methods=['POST'])
def delete_post():
	post_id = request.form.get('post_id')
	user_id = session.get('user_id')
	
	conn = sqlite3.connect('blog.db')
	cursor = conn.cursor()
	
	query = f"DELETE FROM posts WHERE id = {post_id} AND user_id = {user_id}"
	
	cursor.execute(query)
	conn.commit()
	
	deleted = cursor.rowcount
	conn.close()
	
	if deleted > 0:
		return jsonify({"message": "Post deleted"})
	else:
		return jsonify({"error": "Post not found or unauthorized"}), 403
```

### Your Challenge

1. **Is `post_id` vulnerable?**
2. **Is `user_id` vulnerable?** (Consider its source)
3. **Craft a payload** that deletes ALL posts in the database
4. **Provide the secure fix**

**💡 Solution at the end of this post**

---

## Exercise 10: Multiple Injection Points - Dynamic Query Building

**Difficulty:** Intermediate  
**Vulnerability Type:** Multiple Parameter Injection

### Database Schema

```sql
CREATE TABLE transactions (
	id INTEGER PRIMARY KEY,
	amount DECIMAL(10,2),
	category TEXT,
	transaction_date DATE,
	user_id INTEGER
);
```

### The Vulnerable Code

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/report', methods=['GET'])
def generate_report():
	start_date = request.args.get('start', '2024-01-01')
	end_date = request.args.get('end', '2024-12-31')
	category = request.args.get('category', 'all')
	
	conn = sqlite3.connect('finance.db')
	cursor = conn.cursor()
	
	if category == 'all':
		query = f"""
			SELECT * FROM transactions 
			WHERE transaction_date >= '{start_date}' 
			AND transaction_date <= '{end_date}'
		"""
	else:
		query = f"""
			SELECT * FROM transactions 
			WHERE transaction_date >= '{start_date}' 
			AND transaction_date <= '{end_date}'
			AND category = '{category}'
		"""
	
	cursor.execute(query)
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"transactions": results})
```

### Your Challenge

1. **Which parameters are vulnerable?** (start_date, end_date, category, or multiple?)
2. **Do the single quotes around dates make them safe?**
3. **Craft a payload** for `start_date` that returns all transactions ignoring filters
4. **Provide the secure fix**

**💡 Solution at the end of this post**

---

## Exercise 11: Batch Operations - Loop-Based Injection

**Difficulty:** Advanced  
**Vulnerability Type:** Injection in Loop Context

### Database Schema

```sql
CREATE TABLE products (
	id INTEGER PRIMARY KEY,
	name TEXT,
	base_price DECIMAL(10,2),
	current_price DECIMAL(10,2),
	discount_percent INTEGER DEFAULT 0
);
```

### The Vulnerable Code

```python
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/admin/bulk-discount', methods=['POST'])
def bulk_discount():
	product_ids = request.form.get('product_ids', '')  # "1,2,3,4,5"
	discount = request.form.get('discount', '0')
	
	# Validate discount is 0-100
	try:
		discount_value = int(discount)
		if discount_value < 0 or discount_value > 100:
			return jsonify({"error": "Discount must be 0-100"}), 400
	except ValueError:
		return jsonify({"error": "Invalid discount"}), 400
	
	id_list = product_ids.split(',')
	
	conn = psycopg2.connect(database="store", user="admin", password="secret")
	cursor = conn.cursor()
	
	updated_count = 0
	
	for product_id in id_list:
		product_id = product_id.strip()
		
		query = f"""
			UPDATE products 
			SET current_price = base_price * (1 - {discount_value} / 100.0),
			    discount_percent = {discount_value}
			WHERE id = {product_id}
		"""
		
		cursor.execute(query)
		updated_count += cursor.rowcount
	
	conn.commit()
	conn.close()
	
	return jsonify({"message": f"Updated {updated_count} products"})
```

### Your Challenge

1. **Which parameter is vulnerable?** (`product_ids`, `discount`, or both?)
2. **Is `discount` safe?** It's validated as an integer 0-100.
3. **Craft a payload** in `product_ids` that sets all products to $0.00
4. **Provide the secure fix**

**💡 Solution at the end of this post**

---

## Exercise 12: WHERE IN Clause with Multiple Values

**Difficulty:** Intermediate  
**Vulnerability Type:** IN Clause Injection

### Database Schema

```sql
CREATE TABLE products (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	category_id INTEGER,
	price DECIMAL(10,2),
	stock INTEGER
);

CREATE TABLE admin_users (
	id INTEGER PRIMARY KEY,
	username TEXT,
	password_hash TEXT
);
```

### The Vulnerable Code

```python
import pymysql
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/products/filter', methods=['GET'])
def filter_products():
	category_ids = request.args.get('categories', '1')
	
	conn = pymysql.connect(host='localhost', user='app', password='pass', database='shop')
	cursor = conn.cursor()
	
	query = f"SELECT id, name, price FROM products WHERE category_id IN ({category_ids})"
	
	cursor.execute(query)
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"products": results})
```

### Your Challenge

1. **Is the `category_ids` parameter vulnerable to SQL injection?** (Yes/No)
2. **The developer expects numeric IDs like "1,2,3". Does this make it safe?** Explain why or why not.
3. **Provide a payload** that would extract usernames and passwords from the `admin_users` table
4. **Provide the secure fix.** (Hint: Parameterizing IN clauses requires generating the right number of `%s` placeholders)

**💡 Solution at the end of this post**

---

## Exercise 13: Second-Order SQL Injection in Comments

**Difficulty:** Intermediate  
**Vulnerability Type:** Second-Order Injection

### Database Schema

```sql
CREATE TABLE comments (
	id INTEGER PRIMARY KEY,
	post_id INTEGER,
	author_name TEXT,
	comment_text TEXT,
	created_at DATETIME
);

CREATE TABLE posts (
	id INTEGER PRIMARY KEY,
	title TEXT,
	author TEXT
);
```

### The Vulnerable Code (Two Endpoints)

```python
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

# Endpoint 1: Store comment (SAFE)
@app.route('/add-comment', methods=['POST'])
def add_comment():
	post_id = request.form.get('post_id')
	author_name = request.form.get('author_name')
	comment_text = request.form.get('comment_text')
	
	conn = psycopg2.connect(database="blog", user="app", password="secret")
	cursor = conn.cursor()
	
	query = "INSERT INTO comments (post_id, author_name, comment_text) VALUES (%s, %s, %s)"
	cursor.execute(query, (post_id, author_name, comment_text))
	conn.commit()
	conn.close()
	
	return jsonify({"message": "Comment added"})

# Endpoint 2: Get all comments by a specific author
@app.route('/comments/by-author', methods=['GET'])
def get_author_comments():
	author_name = request.args.get('author')
	
	conn = psycopg2.connect(database="blog", user="app", password="secret")
	cursor = conn.cursor()
	
	cursor.execute("SELECT author_name FROM comments WHERE author_name = %s LIMIT 1", (author_name,))
	author = cursor.fetchone()
	
	if not author:
		return jsonify({"error": "Author not found"}), 404
	
	author_name_from_db = author[0]
	
	query = f"SELECT comment_text, created_at FROM comments WHERE author_name = '{author_name_from_db}' ORDER BY created_at DESC"
	cursor.execute(query)
	comments = cursor.fetchall()
	conn.close()
	
	return jsonify({"author": author_name_from_db, "comments": comments})
```

### Your Challenge

1. **Which endpoint is vulnerable to SQL injection?** (add-comment, get_author_comments, or both?)
2. **Explain the second-order attack flow:** which endpoint stores malicious data and which endpoint triggers the injection?
3. **Provide a malicious `author_name`** that would extract all post titles from the `posts` table
4. **Provide the secure fix** for the vulnerable endpoint

**💡 Solution at the end of this post**

---

## Exercise 14: Status Filtering with Boolean Logic

**Difficulty:** Beginner  
**Vulnerability Type:** WHERE Clause Injection with Multiple Parameters

### Database Schema

```sql
CREATE TABLE orders (
	id INTEGER PRIMARY KEY,
	customer_id INTEGER,
	total_amount DECIMAL(10,2),
	status TEXT,
	created_date DATE,
	payment_method TEXT
);

CREATE TABLE customers (
	id INTEGER PRIMARY KEY,
	name TEXT,
	email TEXT,
	credit_card_last4 TEXT
);
```

### The Vulnerable Code

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/orders', methods=['GET'])
def get_orders():
	status_filter = request.args.get('status', 'pending')
	date_from = request.args.get('date_from', '2024-01-01')
	
	conn = sqlite3.connect('orders.db')
	cursor = conn.cursor()
	
	query = f"SELECT id, customer_id, total_amount, status FROM orders WHERE status = '{status_filter}' AND created_date >= '{date_from}'"
	
	cursor.execute(query)
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"orders": results})
```

### Your Challenge

1. **Are the `status_filter` or `date_from` parameters vulnerable to SQL injection?** (Yes/No for each)
2. **The developer expects simple status values like 'pending' or 'shipped'. Does this expectation make the parameters safe?** Explain why or why not.
3. **Provide a payload** for the `status_filter` parameter that extracts credit card information from the `customers` table
4. **Provide the secure fix** using proper parameterization with SQLite syntax

**💡 Solution at the end of this post**

---

## Exercise 15: Complex Search with Multiple AND Conditions

**Difficulty:** Intermediate  
**Vulnerability Type:** Dynamic WHERE Clause Building

### Database Schema

```sql
CREATE TABLE items (
	id INTEGER PRIMARY KEY,
	name TEXT,
	category TEXT,
	price DECIMAL(10,2),
	seller_id INTEGER,
	status TEXT
);

CREATE TABLE sellers (
	id INTEGER PRIMARY KEY,
	username TEXT,
	email TEXT,
	api_key TEXT
);
```

### The Vulnerable Code

```python
import pymysql
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search_items():
	name = request.args.get('name', '')
	category = request.args.get('category', '')
	max_price = request.args.get('max_price', '')
	
	conn = pymysql.connect(host='localhost', user='app', password='pass', database='marketplace')
	cursor = conn.cursor()
	
	conditions = []
	
	if name:
		conditions.append(f"name LIKE '%{name}%'")
	
	if category:
		conditions.append(f"category = '{category}'")
	
	if max_price:
		conditions.append(f"price <= {max_price}")
	
	where_clause = " AND ".join(conditions) if conditions else "1=1"
	
	query = f"SELECT id, name, price, category FROM items WHERE {where_clause} AND status = 'active'"
	
	cursor.execute(query)
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"items": results})
```

### Your Challenge

1. **Which parameter(s) are vulnerable to SQL injection?** (name, category, max_price, or multiple?)
2. **The conditions are joined with AND. Can you still inject SQL even though your payload is in the middle of the query?** Explain.
3. **Provide a payload** for the `category` parameter that extracts seller API keys from the `sellers` table
4. **Provide the secure fix** for all vulnerable parameters

**💡 Solution at the end of this post**

---

## Key Takeaways: The SQL Injection Defense Hierarchy

After completing these 15 exercises, you should understand the **defense hierarchy** as outlined by OWASP Top 10 2025:

### ❌ What Doesn't Work

1. **String escaping/sanitization** - Can be bypassed with encoding tricks
2. **Blacklist filtering** - Attackers find new bypass techniques
3. **HTML escaping** - Wrong layer (HTML ≠ SQL)
4. **Client-side validation** - Easily bypassed
5. **"Expected values"** - Attackers don't care what you expect

### ⚠️ What Sometimes Works (But Shouldn't Be Your Primary Defense)

6. **Whitelist validation** - Works for ORDER BY columns, table names (when parameterization impossible)
7. **Type casting** - Works only if applied correctly AND parameters aren't concatenated
8. **Stored procedures** - Only if they use parameterized queries internally

### ✅ What Actually Works

9. **Parameterized queries (prepared statements)** - The gold standard [^2]
10. **ORM frameworks with proper usage** - If configured to use parameterized queries

**The OWASP Top 10 2025 Rule:** "The preferred option is to use a safe API, which avoids using the interpreter entirely, provides a parameterized interface, or migrates to use Object Relational Mapping Tools (ORMs)." [^2]

This is Defense Option #1 - there is no substitute.

---

## Database-Specific Placeholder Syntax

Different database drivers use different placeholder syntax:

| Database | Python Library | Placeholder | Example |
|----------|---------------|-------------|---------|
| SQLite | `sqlite3` | `?` | `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))` |
| PostgreSQL | `psycopg2` | `%s` | `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))` |
| MySQL | `pymysql` | `%s` | `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))` |
| MySQL | `mysql.connector` | `?` or `%s` | Supports both syntaxes |
| Oracle | `cx_Oracle` | `:name` | `cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})` |

**Critical rule:** Always pass parameters as a **tuple** or **dict**, never format strings with f-strings or `.format()` before passing to `execute()`.

---

## Real-World Impact: Why This Matters

SQL injection isn't just a theoretical problem:

- **Equifax (2017):** Attackers exploited SQL injection to steal personal data of 147 million people [^5]
- **TalkTalk (2015):** £400,000 fine + £60 million in losses from SQL injection attack [^1]
- **LinkedIn (2012):** 6.5 million password hashes stolen via SQL injection [^6]

According to the Verizon 2023 Data Breach Investigations Report, **injection attacks are involved in 22% of web application breaches** [^7].

**For AppSec engineers:** Your ability to spot these vulnerabilities in code review prevents these disasters.

---

## SQL Injection in OWASP Top 10 2025: Where Does It Stand?

The OWASP Top 10 2025 (released November 6, 2025) provides critical context for understanding SQL injection's current threat landscape [^8]:

### The Rankings Shift

**A05:2025 - Injection** (dropped from #3 in 2021 to #5 in 2025)

While injection dropped two positions, this doesn't mean it's less dangerous—it reflects that:
- Security Misconfiguration (#2) and Software Supply Chain Failures (#3) have emerged as more prevalent
- Organizations have improved at preventing traditional injection attacks
- **However:** 100% of tested applications still show some form of injection vulnerability [^2]

### The "Low Frequency, High Impact" Classification

OWASP 2025 explicitly categorizes SQL injection as "low frequency/high impact" with more than 14,000 CVEs, compared to Cross-site Scripting (XSS) which is "high frequency/low impact" with 30,000+ CVEs [^2].

**What this means for AppSec engineers:**
- Fewer applications have SQL injection vulnerabilities than before
- But those that do face **complete database compromise**
- Your role is to ensure your organization is NOT in that vulnerable minority

### Why SQL Injection Remains Critical

Injection had the greatest number of CVEs for any category in the OWASP Top 10 2025, with 37 CWEs mapped [^2]. The category includes:

- **SQL Injection** (CWE-89) - Database query manipulation
- **NoSQL Injection** - Document database attacks
- **OS Command Injection** - System command execution
- **LDAP Injection** - Directory service attacks
- **ORM Injection** - Object-relational mapping exploits

### OWASP 2025's Primary Defense Recommendation

The preferred option is to use a safe API, which avoids using the interpreter entirely, provides a parameterized interface, or migrates to use Object Relational Mapping Tools (ORMs) [^2].

**This aligns exactly with what you're learning in these exercises:** Parameterized queries are the gold standard, not a secondary defense.

### The Complete OWASP Top 10 2025 List

For context, here's where SQL injection fits in the modern threat landscape [^8]:

1. **A01:2025 - Broken Access Control** (3.73% of apps affected, 40 CWEs)
2. **A02:2025 - Security Misconfiguration** (moved up from #5 in 2021)
3. **A03:2025 - Software Supply Chain Failures** (NEW - replaces "Vulnerable Components")
4. **A04:2025 - Cryptographic Failures**
5. **A05:2025 - Injection** ← **SQL injection lives here**
6. **A06:2025 - Insecure Design**
7. **A07:2025 - Authentication Failures**
8. **A08:2025 - Software or Data Integrity Failures**
9. **A09:2025 - Logging and Alerting Failures**
10. **A10:2025 - Mishandling of Exceptional Conditions** (NEW)

**Key changes from 2021:**
- SSRF merged into Broken Access Control (#1)
- Two new categories addressing modern threats: Supply Chain and Error Handling
- Shift from symptoms to root causes in categorization

**The bottom line:** Even though injection dropped to #5, mastering SQL injection detection remains **essential** for AppSec roles. Companies still expect you to spot these vulnerabilities instantly during code review.

---

## Next Steps: Continue Your AppSec Journey

Want more exercises like these? **⭐ Star the repository: [AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)**

### What You'll Find There:

- **LeetCode-style secure coding challenges** with comprehensive test suites
- **XSS, CSRF, SSRF exercises** (coming soon)
- **OAuth 2.0 and JWT security exercises** (coming soon)
- **SAST/DAST automation practice** (coming soon)
- **Real interview questions** from AppSec engineering roles

### Additional Resources:

1. **PortSwigger Web Security Academy** - Free hands-on labs: https://portswigger.net/web-security
2. **OWASP Testing Guide** - Comprehensive methodology: https://owasp.org/www-project-web-security-testing-guide/
3. **API Security in Action** (Neil Madden, Manning 2020)
4. **Secure by Design** (Dan Bergh Johnsson et al., Manning 2017)

---

## About the Author

I'm Tanveer Salim, transitioning from Intel Security Engineering to Application Security roles. At Intel's Product Assurance and Security (IPAS) division, I documented 553+ threats using STRIDE methodology and created reusable threat model templates used by 100+ engineers.

Currently completing a comprehensive 28-week AppSec curriculum covering:
- OWASP Top 10 exploitation and defense
- Python security tool development
- Burp Suite and penetration testing
- DevSecOps and CI/CD security gates

**Connect with me:**
- GitHub: [@fosres](https://github.com/fosres)
- Dev.to: [@fosres](https://dev.to/fosres)

---

## References

[^1]: BBC News. (2015). "TalkTalk fined £400,000 for theft of customer details." https://www.bbc.com/news/business-37564326

[^2]: OWASP. (2025). "OWASP Top 10 2025 - A05:2025 – Injection." https://owasp.org/Top10/2025/A05_2025-Injection/

[^3]: PortSwigger. (2024). "SQL Injection." https://portswigger.net/web-security/sql-injection

[^4]: OWASP. (2024). "SQL Injection Prevention Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

[^5]: U.S. Government Accountability Office. (2018). "Equifax Data Breach: Cybersecurity Practices." https://www.gao.gov/products/gao-18-559

[^6]: Krebs on Security. (2016). "LinkedIn Breach Exposed 6.5M Passwords." https://krebsonsecurity.com/2016/05/linkedin-hack-exposed-light-passwords/

[^7]: Verizon. (2023). "2023 Data Breach Investigations Report." https://www.verizon.com/business/resources/reports/dbir/

[^8]: OWASP. (2025). "OWASP Top 10:2025 - Introduction." https://owasp.org/Top10/2025/0x00_2025-Introduction/

---

---

## Solutions to All Exercises

Ready to check your work? Here are detailed solutions to all 15 exercises:

### Solution 1: Authentication Bypass

**1. Vulnerable:** Yes - both `username` and `password` are concatenated directly into the SQL query.

**2. Attack Payload:**

```python
username = "admin'--"
password = "anything"
```

**What happens:**
```sql
-- Original template:
SELECT id, username FROM users WHERE username = 'admin'--' AND password = 'anything'

-- After the payload:
SELECT id, username FROM users WHERE username = 'admin'
                                                       ↑
                                               Quote closes username
                                                     ↑↑
                                            Comment operator starts
```

Everything after `--` is commented out, so the password check never happens.

**3. Secure Fix:**

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
	username = request.form.get('username')
	password = request.form.get('password')
	
	conn = sqlite3.connect('users.db')
	cursor = conn.cursor()
	
	# Secure: Parameterized query with ? placeholders
	query = "SELECT id, username FROM users WHERE username = ? AND password = ?"
	cursor.execute(query, (username, password))
	
	user = cursor.fetchone()
	conn.close()
	
	if user:
		return jsonify({"message": "Login successful", "user_id": user[0]})
	else:
		return jsonify({"message": "Invalid credentials"}), 401
```

**Why this works:** The database driver treats the entire username value (including quotes and SQL syntax) as literal data, not SQL commands.

**Note:** Production code should also hash passwords using bcrypt or Argon2!

---

### Solution 2: Partial Parameterization

**1. Vulnerable:** Yes - the `category == 'all'` branch concatenates `search_term` directly into SQL.

**2. Why string escaping fails:** 

The `replace("'", "''")` attempts to escape single quotes by doubling them (SQL's escaping method), but this approach has multiple problems:

- It only handles single quotes, not other SQL injection vectors
- The escaping happens in Python, but the database doesn't know about it
- You're still concatenating user input into SQL structure
- According to OWASP: "Escaping user input is not a reliable defense against SQL injection"

Even with escaping, the attacker can use techniques like:
- Encoding attacks (hex, unicode)
- Second-order injection
- Comment-based attacks that don't require quotes

**3. Secure Fix:**

```python
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search_products():
	search_term = request.args.get('q', '')
	category = request.args.get('category', 'all')
	
	conn = psycopg2.connect(database="store", user="app", password="secret")
	cursor = conn.cursor()
	
	# Parameterize both branches
	if category == 'all':
		query = "SELECT * FROM products WHERE name LIKE %s"
		cursor.execute(query, ('%' + search_term + '%',))
	else:
		query = "SELECT * FROM products WHERE name LIKE %s AND category = %s"
		cursor.execute(query, ('%' + search_term + '%', category))
	
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"products": results})
```

**Key lesson:** You can't mix escaping with parameterization. Use parameterized queries for ALL user input.

---

### Solution 3: LIKE Clause Injection

**1. Vulnerable:** Yes - both `username` and `password` are concatenated directly into the SQL query.

**2. Attack Payload:**

```python
username = "admin'--"
password = "anything"
```

**What happens:**
```sql
-- Original template:
SELECT id, username FROM users WHERE username = 'admin'--' AND password = 'anything'

-- After the payload:
SELECT id, username FROM users WHERE username = 'admin'
                                                       ↑
                                               Quote closes username
                                                     ↑↑
                                            Comment operator starts
```

Everything after `--` is commented out, so the password check never happens.

**3. Secure Fix:**

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
	username = request.form.get('username')
	password = request.form.get('password')
	
	conn = sqlite3.connect('users.db')
	cursor = conn.cursor()
	
	# Secure: Parameterized query with ? placeholders
	query = "SELECT id, username FROM users WHERE username = ? AND password = ?"
	cursor.execute(query, (username, password))
	
	user = cursor.fetchone()
	conn.close()
	
	if user:
		return jsonify({"message": "Login successful", "user_id": user[0]})
	else:
		return jsonify({"message": "Invalid credentials"}), 401
```

**Why this works:** The database driver treats the entire username value (including quotes and SQL syntax) as literal data, not SQL commands.

**Note:** Production code should also hash passwords using bcrypt or Argon2!

---

### Solution 3: LIKE Clause Injection

**1. Vulnerable:** Yes! The `%` wildcards are part of the LIKE pattern syntax, NOT SQL string delimiters.

**2. Attack Payload:**

```python
search_term = "Widget%' UNION SELECT id, note, created_by FROM admin_notes--"
```

**What happens:**
```sql
SELECT id, name, price FROM products WHERE name LIKE '%Widget%' UNION SELECT id, note, created_by FROM admin_notes--%'
                                                              ↑                                                      ↑↑
                                                      Closes LIKE string                                 Comments out trailing %'
```

**3. Secure Fix:**

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search_products():
	search_term = request.args.get('q', '')
	
	conn = sqlite3.connect('shop.db')
	cursor = conn.cursor()
	
	# Secure: Wildcards in the PARAMETER VALUE, not the SQL string
	query = "SELECT id, name, price FROM products WHERE name LIKE ?"
	cursor.execute(query, ('%' + search_term + '%',))
	
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"products": results})
```

**Key insight:** The `%` wildcards are added to the *parameter value*, not embedded in the SQL string.

---

### Solution 4: Second-Order SQL Injection

**1. Vulnerable endpoint:** `get-user-posts` is vulnerable to second-order SQL injection.

**2. Attack Flow:**

**Second-order injection** means the malicious payload is stored safely in one operation, then executed when retrieved and used unsafely in another.

**Step 1:** User sets their username to:
```python
username = "alice' UNION SELECT id, username, password_hash FROM users--"
```

**Step 2:** This gets stored safely via parameterized query in `update-profile`.

**Step 3:** Later, `get-user-posts` retrieves this username and concatenates it:

```sql
SELECT post_id, content, created_at FROM posts WHERE author = 'alice' UNION SELECT id, username, password_hash FROM users--' ORDER BY created_at DESC
```

**Now the injection executes!**

**3. Malicious Username:**

```python
username = "alice' UNION SELECT id, username, password_hash FROM users--"
```

**4. Secure Fix:**

```python
@app.route('/get-user-posts', methods=['GET'])
def get_user_posts():
	user_id = request.args.get('user_id')
	
	conn = psycopg2.connect(host='localhost', user='app', password='pass', database='social')
	cursor = conn.cursor()
	
	cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
	user = cursor.fetchone()
	
	if not user:
		return jsonify({"error": "User not found"}), 404
	
	username = user[0]
	
	# Parameterize the retrieved username too!
	query = "SELECT post_id, content, created_at FROM posts WHERE author = %s ORDER BY created_at DESC"
	cursor.execute(query, (username,))
	posts = cursor.fetchall()
	
	conn.close()
	
	return jsonify({"username": username, "posts": posts})
```

**Key lesson:** Even data from your own database must be parameterized if it originated from user input!

---

### Solution 5: ORDER BY Injection

**1. Vulnerable:** Yes - `sort_by` accepts arbitrary user input.

**2. Why parameterization doesn't work:**

```python
# This doesn't work - sorts by literal string "name"
query = "SELECT * FROM products ORDER BY ?"
cursor.execute(query, (sort_by,))  # ❌ Wrong!
```

SQL databases need column names at query planning time. Parameterized queries bind **values**, not column names.

**3. Secure Fix - Whitelist Validation:**

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/products', methods=['GET'])
def list_products():
	sort_by = request.args.get('sort', 'name')
	order = request.args.get('order', 'ASC')
	
	# Define allowed columns (whitelist)
	ALLOWED_COLUMNS = ['id', 'name', 'price', 'category', 'stock_quantity']
	
	# Validate against whitelist
	if sort_by not in ALLOWED_COLUMNS:
		return jsonify({"error": "Invalid sort column"}), 400
	
	if order.upper() not in ['ASC', 'DESC']:
		return jsonify({"error": "Invalid order"}), 400
	
	conn = sqlite3.connect('shop.db')
	cursor = conn.cursor()
	
	# Now safe - sort_by is constrained
	query = f"SELECT id, name, price FROM products ORDER BY {sort_by} {order}"
	
	cursor.execute(query)
	products = cursor.fetchall()
	conn.close()
	
	return jsonify({"products": products})
```

---

### Solution 6: Numeric Context Injection

**1. `product_id` is NOT vulnerable:** Flask's `<int:product_id>` validates it as integer before function executes.

**2. `limit` IS vulnerable:** Query parameters from `request.args.get()` are NOT validated by Flask.

**3. UNION Attack Payload:**

```python
limit = "1 UNION SELECT id, username, password_hash, email, null FROM users--"
```

**Column count must match!** `SELECT * FROM products` returns 5 columns, so UNION needs 5 columns (we use `null` as placeholder).

**4. Secure Fix:**

```python
import pymysql
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/product/<int:product_id>', methods=['GET'])
def get_product_details(product_id):
	limit = request.args.get('limit', '10')
	
	conn = pymysql.connect(host='localhost', user='app', password='secret', database='store')
	cursor = conn.cursor()
	
	# Parameterize both (use %s for pymysql)
	query = "SELECT * FROM products WHERE id = %s LIMIT %s"
	cursor.execute(query, (product_id, limit))
	
	result = cursor.fetchone()
	conn.close()
	
	return jsonify({"product": result})
```

---

### Solution 7: INSERT Privilege Escalation

**1. Vulnerable parameter:** `country` is concatenated directly.

**2. Why partial parameterization fails:** SQL injection requires **ALL** user input use parameterized queries. One concatenated parameter = vulnerable application.

**3. Attack Payload:**

```python
country = "US','admin')--"
```

**What happens:**
```sql
INSERT INTO users (username, email, password_hash, country, role) 
VALUES ('alice', 'alice@test.com', 'hash', 'US', 'admin')
                                            ↑    ↑
                                        country  role (injected!)
```

**Breaking it down:**
- `'US'` - closes country string
- `,'admin'` - injects role = 'admin'
- `)` - closes VALUES clause  
- `--` - comments out `', 'user')`

**4. Secure Fix:**

```python
import psycopg2
from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
	username = request.form.get('username')
	email = request.form.get('email')
	password = request.form.get('password')
	country = request.form.get('country', 'US')
	
	password_hash = hashlib.sha256(password.encode()).hexdigest()
	
	conn = psycopg2.connect(database="users", user="app", password="secret")
	cursor = conn.cursor()
	
	# Parameterize ALL values
	query = """
		INSERT INTO users (username, email, password_hash, country, role) 
		VALUES (%s, %s, %s, %s, 'user')
	"""
	
	cursor.execute(query, (username, email, password_hash, country))
	conn.commit()
	conn.close()
	
	return jsonify({"message": "Registration successful"})
```

---

### Solution 8: UPDATE Column Injection

**1. `bio` is vulnerable:** Concatenated directly into SQL.

**2. `user_id` is safe:** Comes from server-side `session.get()`, not user input.

**3. Attack Payload:**

```python
new_bio = "I love coding', role = 'admin', account_balance = 1000000--"
```

**What happens:**
```sql
UPDATE users SET bio = 'I love coding', role = 'admin', account_balance = 1000000--' WHERE id = %s
                      ↑              ↑                                         ↑↑
              Closes bio         Injected columns                       Comment starts
```

**Result:** User gets admin + $1M balance!

**4. Secure Fix:**

```python
import psycopg2
from flask import Flask, request, jsonify, session

app = Flask(__name__)

@app.route('/update-bio', methods=['POST'])
def update_bio():
	user_id = session.get('user_id')
	new_bio = request.form.get('bio')
	
	conn = psycopg2.connect(database="users", user="app", password="secret")
	cursor = conn.cursor()
	
	# Parameterize both
	query = "UPDATE users SET bio = %s WHERE id = %s"
	cursor.execute(query, (new_bio, user_id))
	
	conn.commit()
	conn.close()
	
	return jsonify({"message": "Bio updated successfully"})
```

---

### Solution 9: DELETE Bypass

**1. `post_id` is vulnerable:** User input concatenated directly.

**2. `user_id` is NOT vulnerable:** Comes from server-side session.

**3. Attack Payload:**

```python
post_id = "1 OR 1=1--"
```

**What happens:**
```sql
DELETE FROM posts WHERE id = 1 OR 1=1-- AND user_id = 5
                           ↑       ↑↑
                    Always true  Comment
```

**Result:** ALL posts deleted because `1=1` is always true!

**4. Secure Fix:**

```python
import sqlite3
from flask import Flask, request, jsonify, session

app = Flask(__name__)

@app.route('/delete-post', methods=['POST'])
def delete_post():
	post_id = request.form.get('post_id')
	user_id = session.get('user_id')
	
	conn = sqlite3.connect('blog.db')
	cursor = conn.cursor()
	
	# Parameterize both
	query = "DELETE FROM posts WHERE id = ? AND user_id = ?"
	cursor.execute(query, (post_id, user_id))
	
	conn.commit()
	deleted = cursor.rowcount
	conn.close()
	
	if deleted > 0:
		return jsonify({"message": "Post deleted"})
	else:
		return jsonify({"error": "Post not found or unauthorized"}), 403
```

---

### Solution 10: Multiple Injection Points

**1. All three vulnerable:** `start_date`, `end_date`, and `category` all concatenated.

**2. Single quotes don't make safe:** Attacker closes quotes and injects SQL.

**3. Attack Payload:**

```python
start_date = "2024-01-01' OR 1=1--"
```

**Result:** Returns ALL transactions (OR 1=1 always true, -- comments out filters).

**4. Secure Fix:**

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/report', methods=['GET'])
def generate_report():
	start_date = request.args.get('start', '2024-01-01')
	end_date = request.args.get('end', '2024-12-31')
	category = request.args.get('category', 'all')
	
	conn = sqlite3.connect('finance.db')
	cursor = conn.cursor()
	
	# Parameterize ALL
	if category == 'all':
		query = """
			SELECT * FROM transactions 
			WHERE transaction_date >= ? AND transaction_date <= ?
		"""
		cursor.execute(query, (start_date, end_date))
	else:
		query = """
			SELECT * FROM transactions 
			WHERE transaction_date >= ? AND transaction_date <= ? AND category = ?
		"""
		cursor.execute(query, (start_date, end_date, category))
	
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"transactions": results})
```

---

### Solution 11: Batch Operations

**1. `product_ids` is vulnerable:** Each ID concatenated in loop.

**2. `discount` is safe:** Validated as integer 0-100, converted with `int()`.

**3. Attack Payload:**

```python
product_ids = "1 OR 1=1,2,3"
```

**First loop iteration:**
```sql
UPDATE products ... WHERE id = 1 OR 1=1
                              ↑
                       Always true - updates ALL!
```

**4. Secure Fix:**

```python
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/admin/bulk-discount', methods=['POST'])
def bulk_discount():
	product_ids = request.form.get('product_ids', '')
	discount = request.form.get('discount', '0')
	
	try:
		discount_value = int(discount)
		if discount_value < 0 or discount_value > 100:
			return jsonify({"error": "Discount must be 0-100"}), 400
	except ValueError:
		return jsonify({"error": "Invalid discount"}), 400
	
	id_list = product_ids.split(',')
	
	conn = psycopg2.connect(database="store", user="admin", password="secret")
	cursor = conn.cursor()
	
	updated_count = 0
	
	# Parameterize in loop
	for product_id in id_list:
		product_id = product_id.strip()
		
		query = """
			UPDATE products 
			SET current_price = base_price * (1 - %s / 100.0),
			    discount_percent = %s
			WHERE id = %s
		"""
		
		cursor.execute(query, (discount_value, discount_value, product_id))
		updated_count += cursor.rowcount
	
	conn.commit()
	conn.close()
	
	return jsonify({"message": f"Updated {updated_count} products"})
```

---

### Solution 12: WHERE IN Clause

**1. `category_ids` is vulnerable:** Yes - the comma-separated values are concatenated directly into the IN clause.

**2. Numeric expectation doesn't make it safe:** The developer expects "1,2,3" but attackers can inject:
```
1) UNION SELECT ...--
```
Breaking out of the IN clause with `)` then injecting SQL.

**3. Attack Payload:**

```python
category_ids = "1) UNION SELECT id, username, password_hash FROM admin_users--"
```

**What happens:**
```sql
SELECT id, name, price FROM products WHERE category_id IN (1) UNION SELECT id, username, password_hash FROM admin_users--
                                                              ↑                                                        ↑↑
                                                      Closes IN                                            Comments out )
```

**4. Secure Fix:**

This is advanced, but here's the proper approach for dynamic IN clauses:

```python
import pymysql
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/products/filter', methods=['GET'])
def filter_products():
	category_ids = request.args.get('categories', '1')
	
	# Split and validate
	id_list = category_ids.split(',')
	
	# Validate all are integers
	try:
		id_list = [int(x.strip()) for x in id_list]
	except ValueError:
		return jsonify({"error": "Invalid category IDs"}), 400
	
	# Generate the right number of placeholders
	placeholders = ','.join(['%s'] * len(id_list))
	
	conn = pymysql.connect(host='localhost', user='app', password='pass', database='shop')
	cursor = conn.cursor()
	
	query = f"SELECT id, name, price FROM products WHERE category_id IN ({placeholders})"
	cursor.execute(query, tuple(id_list))
	
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"products": results})
```

**Key insight:** Dynamic IN clauses require generating the correct number of placeholders AND validating input types.

---

### Solution 13: Second-Order in Comments

**1. Vulnerable endpoint:** `get_author_comments` is vulnerable to second-order SQL injection.

**2. Attack Flow:**

The `add_comment` endpoint stores the malicious `author_name` safely using parameterized queries. Later, the `get_author_comments` endpoint retrieves that stored name from the database and concatenates it directly into a SQL query, triggering the injection.

**Step-by-step:**
1. Attacker posts comment with malicious author name
2. Name is stored safely via parameterized INSERT
3. Later, when retrieving comments by that author, the name is concatenated unsafely
4. Injection executes

**3. Malicious Author Name:**

```python
author_name = "Alice' UNION SELECT id, title FROM posts--"
```

When this is retrieved and used:
```sql
SELECT comment_text, created_at FROM comments WHERE author_name = 'Alice' UNION SELECT id, title FROM posts--' ORDER BY created_at DESC
```

**4. Secure Fix:**

```python
@app.route('/comments/by-author', methods=['GET'])
def get_author_comments():
	author_name = request.args.get('author')
	
	conn = psycopg2.connect(database="blog", user="app", password="secret")
	cursor = conn.cursor()
	
	cursor.execute("SELECT author_name FROM comments WHERE author_name = %s LIMIT 1", (author_name,))
	author = cursor.fetchone()
	
	if not author:
		return jsonify({"error": "Author not found"}), 404
	
	author_name_from_db = author[0]
	
	# Parameterize the retrieved value too!
	query = "SELECT comment_text, created_at FROM comments WHERE author_name = %s ORDER BY created_at DESC"
	cursor.execute(query, (author_name_from_db,))
	comments = cursor.fetchall()
	
	conn.close()
	
	return jsonify({"author": author_name_from_db, "comments": comments})
```

---

### Solution 14: Status Filtering

**1. Both vulnerable:** Yes - both `status_filter` and `date_from` are concatenated directly.

**2. Expected values don't make parameters safe:** Just because the developer expects "pending" or "shipped" doesn't prevent an attacker from sending malicious SQL. Expectations ≠ enforcement.

**3. Attack Payload:**

```python
status_filter = "pending' UNION SELECT id, name, email, credit_card_last4 FROM customers--"
```

**What happens:**
```sql
SELECT id, customer_id, total_amount, status FROM orders WHERE status = 'pending' UNION SELECT id, name, email, credit_card_last4 FROM customers--' AND created_date >= '2024-01-01'
```

Extracts customer credit card data!

**4. Secure Fix:**

```python
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/orders', methods=['GET'])
def get_orders():
	status_filter = request.args.get('status', 'pending')
	date_from = request.args.get('date_from', '2024-01-01')
	
	conn = sqlite3.connect('orders.db')
	cursor = conn.cursor()
	
	# Parameterize both values (use ? for SQLite)
	query = "SELECT id, customer_id, total_amount, status FROM orders WHERE status = ? AND created_date >= ?"
	cursor.execute(query, (status_filter, date_from))
	
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"orders": results})
```

---

### Solution 15: Complex Search

**1. All three vulnerable:** `name`, `category`, and `max_price` - all are concatenated into the WHERE clause.

**2. Yes, UNION works in AND chains:** You can inject UNION attacks or use OR to bypass conditions:

```python
category = "electronics' UNION SELECT id, username, email, api_key FROM sellers--"
```

The UNION executes regardless of the AND conditions that follow.

**3. Attack Payload:**

```python
category = "electronics' UNION SELECT id, username, email, api_key FROM sellers--"
```

**What happens:**
```sql
SELECT id, name, price, category FROM items WHERE name LIKE '%..%' AND category = 'electronics' UNION SELECT id, username, email, api_key FROM sellers--' AND status = 'active'
```

**4. Secure Fix:**

This requires building conditions and parameters together:

```python
import pymysql
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search_items():
	name = request.args.get('name', '')
	category = request.args.get('category', '')
	max_price = request.args.get('max_price', '')
	
	conn = pymysql.connect(host='localhost', user='app', password='pass', database='marketplace')
	cursor = conn.cursor()
	
	# Build conditions AND parameters together
	conditions = []
	params = []
	
	if name:
		conditions.append("name LIKE %s")
		params.append('%' + name + '%')
	
	if category:
		conditions.append("category = %s")
		params.append(category)
	
	if max_price:
		conditions.append("price <= %s")
		params.append(max_price)
	
	# Add status condition
	conditions.append("status = %s")
	params.append('active')
	
	where_clause = " AND ".join(conditions)
	
	query = f"SELECT id, name, price, category FROM items WHERE {where_clause}"
	
	cursor.execute(query, tuple(params))
	results = cursor.fetchall()
	conn.close()
	
	return jsonify({"items": results})
```

**Key insight:** Build parameters list alongside conditions list, only adding when condition is used.

---

**Did this help you?** ⭐ **Star the repo:** https://github.com/fosres/AppSec-Exercises

**Questions or feedback?** Drop a comment below! 👇
