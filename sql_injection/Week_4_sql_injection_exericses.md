Snippet 1:

```
import sqlite3

def authenticate_user(username, password):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
	cursor.execute(query)
	
	user = cursor.fetchone()
	conn.close()
	
	if user:
		return {"status": "success", "user_id": user[0]}
	else:
		return {"status": "failed"}
```

The below line is vulnerable to Classic SQL Injection:

```
	query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
	cursor.execute(query)

```

Below is the fix:

```
import sqlite3

def authenticate_user(username, password):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	query = f"SELECT * FROM users WHERE username = ? AND password = ?"

	cursor.execute(query,(username,password))
	
	user = cursor.fetchone()
	conn.close()
	
	if user:
		return {"status": "success", "user_id": user[0]}
	else:
		return {"status": "failed"}
```

Snippet 2:

```
import psycopg2

def search_products(search_term):
	conn = psycopg2.connect("dbname=store")
	cursor = conn.cursor()
	
	query = "SELECT name, price FROM products WHERE name ILIKE %s"
	cursor.execute(query, (f"%{search_term}%",))
	
	results = cursor.fetchall()
	conn.close()
	return results
```
Snippet 2 is not vulnerable.

Snippet 3:

```
import mysql.connector

def check_account_exists(email):
	conn = mysql.connector.connect(host="localhost", database="accounts")
	cursor = conn.cursor()
	
	query = "SELECT 1 FROM users WHERE email = '" + email + "' LIMIT 1"
	cursor.execute(query)
	
	exists = cursor.fetchone() is not None
	conn.close()
	
	return {"exists": exists}
```

The below lines are vulnerable to Classic SQLi:

```
	query = "SELECT 1 FROM users WHERE email = '" + email + "' LIMIT 1"
	cursor.execute(query)
```

And the below lines are the fix:

```
	query = "SELECT 1 FROM users WHERE email = %s LIMIT 1"
	cursor.execute(query,(email,))
```

Snippet 4:

```
from sqlalchemy import create_engine, text

def get_order_status(order_id):
	engine = create_engine('postgresql://localhost/orders')
	
	with engine.connect() as conn:
		query = text("SELECT status FROM orders WHERE id = :order_id")
		result = conn.execute(query, {"order_id": order_id})
		
		row = result.fetchone()
		if row:
			return {"status": row[0]}
		return {"status": "not_found"}
```
The above snippet is not vulnerable.

Snippet 5:

```
import sqlite3
import time

def generate_report(table_name, date_filter):
	conn = sqlite3.connect('reports.db')
	cursor = conn.cursor()
	
	allowed_tables = ['sales', 'inventory', 'customers']
	
	if table_name not in allowed_tables:
		return {"error": "Invalid table"}
	
	query = f"SELECT * FROM {table_name} WHERE created_at > '{date_filter}'"
	cursor.execute(query)
	
	results = cursor.fetchall()
	conn.close()
	return {"data": results}
```

The below lines are vulnerable to Blind SQLi - Boolean based:

```
	query = f"SELECT * FROM {table_name} WHERE created_at > '{date_filter}'"
	cursor.execute(query)
```

The below lines are the fix:

```
	query = f"SELECT * FROM {table_name} WHERE created_at > ?"
	cursor.execute(query,(date_filter,))
```

Snippet 6:

```
import sqlite3

def get_user_profile(user_id):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	if not user_id.isdigit():
		return {"error": "Invalid user ID"}
	
	query = f"SELECT username, email, bio FROM users WHERE id = {user_id}"
	cursor.execute(query)
	
	profile = cursor.fetchone()
	conn.close()
	
	if profile:
		return {"username": profile[0], "email": profile[1], "bio": profile[2]}
	return {"error": "User not found"}
```

The following lines are vulnerable to Classic SQLi:

```
	query = f"SELECT username, email, bio FROM users WHERE id = {user_id}"
	cursor.execute(query)
```

Below is the fix:

```
	query = f"SELECT username, email, bio FROM users WHERE id = ?"
	cursor.execute(query,(user_id,))
```

Snippet 7:

```
from flask import Flask, request
import psycopg2

app = Flask(__name__)

@app.route('/search')
def search():
	query_param = request.args.get('q', '')
	sort_by = request.args.get('sort', 'name')
	
	conn = psycopg2.connect("dbname=products")
	cursor = conn.cursor()
	
	allowed_sort = ['name', 'price', 'date_added']
	if sort_by not in allowed_sort:
		sort_by = 'name'
	
	query = f"SELECT * FROM products WHERE name ILIKE %s ORDER BY {sort_by}"
	cursor.execute(query, (f"%{query_param}%",))
	
	results = cursor.fetchall()
	conn.close()
	return {"results": results}
```

Below lines are vulnerable to Classic SQLi:

```
	query = f"SELECT * FROM products WHERE name ILIKE %s ORDER BY {sort_by}"
	cursor.execute(query, (f"%{query_param}%",))
```

And below lines are the fix:

```
	query = f"SELECT * FROM products WHERE name ILIKE %s ORDER BY %s"
	cursor.execute(query, (f"%{query_param}%",))
```

Snippet 7:

```
from flask import Flask, request
import psycopg2

app = Flask(__name__)

@app.route('/search')
def search():
	query_param = request.args.get('q', '')
	sort_by = request.args.get('sort', 'name')
	
	conn = psycopg2.connect("dbname=products")
	cursor = conn.cursor()
	
	allowed_sort = ['name', 'price', 'date_added']
	if sort_by not in allowed_sort:
		sort_by = 'name'
	
	query = f"SELECT * FROM products WHERE name ILIKE %s ORDER BY {sort_by}"
	cursor.execute(query, (f"%{query_param}%",))
	
	results = cursor.fetchall()
	conn.close()
	return {"results": results}
```

Below lines vulnerable to classic SQLi:

```
	query = f"SELECT * FROM products WHERE name ILIKE %s ORDER BY {sort_by}"
	cursor.execute(query, (f"%{query_param}%",))
```

And below lines are the fix:

```
	query = f"SELECT * FROM products WHERE name ILIKE %s ORDER BY %s"
	cursor.execute(query, (f"%{query_param}%",sort_by))
```

Snippet 8:

```
import mysql.connector

def delete_users(user_ids: list):
	conn = mysql.connector.connect(host="localhost", database="app")
	cursor = conn.cursor()
	
	placeholders = ','.join(['%s'] * len(user_ids))
	query = f"DELETE FROM users WHERE id IN ({placeholders})"
	cursor.execute(query, tuple(user_ids))
	
	conn.commit()
	deleted_count = cursor.rowcount
	conn.close()
	
	return {"deleted": deleted_count}
```

Above snippet is not vulnerable.

Snippet 9:

```
import sqlite3
import hashlib

def login(username, password, remember_token=None):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	if remember_token:
		query = f"SELECT * FROM users WHERE remember_token = '{remember_token}'"
		cursor.execute(query)
	else:
		password_hash = hashlib.sha256(password.encode()).hexdigest()
		query = "SELECT * FROM users WHERE username = ? AND password_hash = ?"
		cursor.execute(query, (username, password_hash))
	
	user = cursor.fetchone()
	conn.close()
	
	if user:
		return {"status": "success", "user_id": user[0]}
	return {"status": "failed"}
```

Below lines are vulnerable to Classic SQLi:

```
		query = f"SELECT * FROM users WHERE remember_token = '{remember_token}'"
		cursor.execute(query)
```

Below lines are the fix:

```
		query = f"SELECT * FROM users WHERE remember_token = ?"
		cursor.execute(query,(remember_token,))
```

Snippet 10:

```
from django.db import connection

def get_orders_by_status(status, customer_id):
	with connection.cursor() as cursor:
		cursor.execute(
			"SELECT * FROM orders WHERE status = %s AND customer_id = %s",
			[status, customer_id]
		)
		rows = cursor.fetchall()
	
	return [{"id": row[0], "total": row[1], "status": row[2]} for row in rows]
```

The above snippet is not vulnerable.

Snippet 11:

```
import psycopg2
from datetime import datetime

def search_audit_logs(action_type, start_date, end_date, limit=100):
	conn = psycopg2.connect("dbname=audit")
	cursor = conn.cursor()
	
	query = """
		SELECT timestamp, user_id, action, details 
		FROM audit_logs 
		WHERE action = %s 
		AND timestamp BETWEEN %s AND %s
		ORDER BY timestamp DESC
		LIMIT """ + str(limit)
	
	cursor.execute(query, (action_type, start_date, end_date))
	
	logs = cursor.fetchall()
	conn.close()
	return {"logs": logs}
```

The above snippet is not vulnerable.

Snippet 12:

```
import sqlite3
import hashlib

def register_user(username, email, password):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	# Check if username exists
	cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
	if cursor.fetchone():
		conn.close()
		return {"error": "Username taken"}
	
	# Check if email exists  
	cursor.execute("SELECT 1 FROM users WHERE email = ?", (email,))
	if cursor.fetchone():
		conn.close()
		return {"error": "Email already registered"}
	
	# Insert new user
	password_hash = hashlib.sha256(password.encode()).hexdigest()
	cursor.execute(
		"INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
		(username, email, password_hash)
	)
	
	conn.commit()
	user_id = cursor.lastrowid
	conn.close()
	
	return {"success": True, "user_id": user_id}
```

The above snippet is not vulnerable.

Snippet 13:

```
import psycopg2

def build_report(table, columns, filters):
	"""
	table: string - table name
	columns: list - columns to select
	filters: dict - {column: value} pairs for WHERE clause
	"""
	conn = psycopg2.connect("dbname=reports")
	cursor = conn.cursor()
	
	allowed_tables = ['sales', 'inventory', 'employees']
	allowed_columns = ['id', 'name', 'amount', 'date', 'department']
	
	if table not in allowed_tables:
		return {"error": "Invalid table"}
	
	safe_columns = [c for c in columns if c in allowed_columns]
	if not safe_columns:
		return {"error": "No valid columns"}
	
	column_str = ', '.join(safe_columns)
	
	where_clauses = []
	values = []
	for col, val in filters.items():
		if col in allowed_columns:
			where_clauses.append(f"{col} = %s")
			values.append(val)
	
	query = f"SELECT {column_str} FROM {table}"
	if where_clauses:
		query += " WHERE " + " AND ".join(where_clauses)
	
	cursor.execute(query, tuple(values))
	results = cursor.fetchall()
	conn.close()
	
	return {"data": results}
```

The below lines vulnerable to Blind SQL Injection - Boolean
vulnerability:

```

			where_clauses.append(f"{col} = %s")

	query = f"SELECT {column_str} FROM {table}"
```

And below are the fixes:

```
			where_clauses.append(f"%s = %s")

	query = f"SELECT %s FROM %s"
```

Snippet 14:

```
import sqlite3
import secrets

def request_password_reset(email):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	# Check if email exists
	cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
	user = cursor.fetchone()
	
	if not user:
		conn.close()
		return {"message": "If email exists, reset link sent"}
	
	# Generate reset token
	reset_token = secrets.token_urlsafe(32)
	
	# Store token
	cursor.execute(
		"UPDATE users SET reset_token = ?, reset_expires = datetime('now', '+1 hour') WHERE id = ?",
		(reset_token, user[0])
	)
	conn.commit()
	conn.close()
	
	# send_email(email, reset_token)  # Assume this works
	return {"message": "If email exists, reset link sent"}


def reset_password(token, new_password):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	query = f"SELECT id FROM users WHERE reset_token = '{token}' AND reset_expires > datetime('now')"
	cursor.execute(query)
	user = cursor.fetchone()
	
	if not user:
		conn.close()
		return {"error": "Invalid or expired token"}
	
	# Update password (assume hashing happens here)
	cursor.execute(
		"UPDATE users SET password_hash = ?, reset_token = NULL WHERE id = ?",
		(new_password, user[0])
	)
	conn.commit()
	conn.close()
	
	return {"success": True}
```

Below lines vulnerable to Blind SQL Injection -- Time-Based

Vulnerability:

```
	query = f"SELECT id FROM users WHERE reset_token = '{token}' AND reset_expires > datetime('now')"
	cursor.execute(query)
```

Below is the fix:

```
	query = f"SELECT id FROM users WHERE reset_token = ? AND reset_expires > datetime('now')"
	cursor.execute(query,(token,))
```

Snippet 1
