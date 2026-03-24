Case 1:

```
import sqlite3

def get_user_by_username(username: str) -> dict | None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	query = "SELECT id, username, email FROM users WHERE username = '" + username + "'"
	cursor.execute(query)
	row = cursor.fetchone()
	conn.close()
	if row:
		return {"id": row[0], "username": row[1], "email": row[2]}
	return None
```

1. Vulnerable line(s):

```
	query = "SELECT id, username, email FROM users WHERE username = '" + username + "'"
``` 

2. Below is sample payload:

```
username: "user' UNION SELECT id, username, email FROM users--"
```

3. Below is the fix:

```
import sqlite3

def get_user_by_username(username: str) -> dict | None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	query = "SELECT id, username, email FROM users WHERE username = ?"
	cursor.execute(query,(username,))
	row = cursor.fetchone()
	conn.close()
	if row:
		return {"id": row[0], "username": row[1], "email": row[2]}
	return None
```

Case 2:

```
import sqlite3

def delete_session(session_token: str) -> None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	cursor.execute(f"DELETE FROM sessions WHERE token = '{session_token}'")
	conn.commit()
	conn.close()
```

1. Below vulnerable line(s):

```
	cursor.execute(f"DELETE FROM sessions WHERE token = '{session_token}'")
```

2. Below is sample payload:

```
session_token: "valid_token_here' OR '1' = '1"
```

3. Below is the fix:

```
import sqlite3

def delete_session(session_token: str) -> None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	cursor.execute("DELETE FROM sessions WHERE token = ?",(session_token,))
	conn.commit()
	conn.close()
```

Case 3:

```
import sqlite3

def search_products(keyword: str, category: str) -> list[dict]:
	conn = sqlite3.connect("shop.db")
	cursor = conn.cursor()
	query = "SELECT id, name, price FROM products WHERE name LIKE '%{}%' AND category = '{}'".format(
		keyword, category
	)
	cursor.execute(query)
	rows = cursor.fetchall()
	conn.close()
	return [{"id": r[0], "name": r[1], "price": r[2]} for r in rows]
```

1. Below vulnerable line(s):

```
	query = "SELECT id, name, price FROM products WHERE name LIKE '%{}%' AND category = '{}'".format(
		keyword, category
	)
	cursor.execute(query)
```

2. Below are sample payloads:

```
keyword: "product_here%' UNION SELECT id, name, price FROM products--"

category: "category_here' UNION SELECT id, name, price FROM products--"
```

3. Below is the fix:


```
import sqlite3

def search_products(keyword: str, category: str) -> list[dict]:

	conn = sqlite3.connect("shop.db")

	cursor = conn.cursor()

	query = "SELECT id, name, price FROM products WHERE name LIKE ? AND category = ?"

	cursor.execute(query,("%" + keyword + "%", category))

	rows = cursor.fetchall()

	conn.close()

	return [{"id": r[0], "name": r[1], "price": r[2]} for r in rows]
```

Case 4:

```
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user'
);
```

```
import sqlite3

def authenticate_user(username: str, password_hash: str) -> bool:
	conn = sqlite3.connect("auth.db")
	cursor = conn.cursor()
	query = "SELECT 1 FROM users WHERE username = '%s' AND password_hash = '%s'" % (
		username, password_hash
	)
	cursor.execute(query)
	result = cursor.fetchone()
	conn.close()
	return result is not None
```

1. Below line(s) vulnerable:

```
	query = "SELECT 1 FROM users WHERE username = '%s' AND password_hash = '%s'" % (
		username, password_hash
	)
	cursor.execute(query)
```

2. Below sample payloads:

```
username: "user_here' OR '1'='1"
```

3. Timing Vulnerability when comparing password hashes.

4. Below is the fix:


```
import sqlite3
import hmac

def authenticate_user(username: str, password_hash: str) -> bool:

	conn = sqlite3.connect("auth.db")

	cursor = conn.cursor()
	
	query = "SELECT username,password_hash FROM users WHERE username = ?" 
	
	cursor.execute(query,(username,))

	result = cursor.fetchone()

	if result is None:
		
		conn.close()

		return False

	pwhash = result[1]

	if not hmac.compare_digest(pwhash,password_hash):
		
		conn.close()

		return False
	
	elif hmac.compare_digest(pwhash,password_hash):
		
		conn.close()

		return True

```

Case 5:

```
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    role          TEXT    NOT NULL DEFAULT 'user',
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);
```

```
import sqlite3

def list_users(sort_column: str, sort_dir: str) -> list[dict]:
	conn = sqlite3.connect("admin.db")
	cursor = conn.cursor()
	query = f"SELECT id, username, role FROM users ORDER BY {sort_column} {sort_dir}"
	cursor.execute(query)
	rows = cursor.fetchall()
	conn.close()
	return [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]
```

1. Below are vulnerable lines:

```
	query = f"SELECT id, username, role FROM users ORDER BY {sort_column} {sort_dir}"
	cursor.execute(query)
```

2. You cannot apply SQL Parameterization since that binds values.

ORDER BY expects identifiers of the database. You must rely

on input validation instead.

3.


sort_column: "(SELECT password_hash FROM users WHERE username='admin' LIMIT 1)--"
```

4. Below is the fix:


```
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    role          TEXT    NOT NULL DEFAULT 'user',
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);
```

```
import sqlite3

def list_users(sort_column: str, sort_dir: str) -> list[dict]:

	conn = sqlite3.connect("admin.db")

	cursor = conn.cursor()

	allowed_columns = ["id","username","role","created_at"]

	if sort_column not in allowed_columns or sort_dir not in ["ASC","DESC","asc","desc"]:
	
		conn.close()

		raise Exception("Invalid parameters")

	query = f"SELECT id, username, role FROM users ORDER BY {sort_column} {sort_dir}"

	cursor.execute(query)

	rows = cursor.fetchall()

	conn.close()

	return [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]
```

Case 6:

```
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);
```

```
import sqlite3

def register_user(username: str, email: str) -> None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	# Correctly parameterized — this INSERT is safe
	cursor.execute(
		"INSERT INTO users (username, email) VALUES (?, ?)",
		(username, email),
	)
	conn.commit()
	conn.close()

def update_email_by_username(username: str, new_email: str) -> None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	cursor.execute("SELECT username FROM users WHERE email = ?", (new_email,))
	row = cursor.fetchone()
	if not row:
		return
	stored_username = row[0]
	# Update using the stored value
	query = "UPDATE users SET email = '" + new_email + "' WHERE username = '" + stored_username + "'"
	cursor.execute(query)
	conn.commit()
	conn.close()
```

1. and 2. No, `update_email_by_username` still has a SQL Injection

Vulnerability:

```
	query = "UPDATE users SET email = '" + new_email + "' WHERE username = '" + stored_username + "'"
	cursor.execute(query)
```

3. The following is the payload that allows the attacker to replace

the original password and email for a known.

```
new_email: "attacker@attacker_email.com',password_hash ='password_hash_here"
```

4. Below is the fix:


```
import sqlite3

def register_user(username: str, email: str,password_hash: str,created_at: str) -> None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	# Correctly parameterized — this INSERT is safe
	cursor.execute(
		"INSERT INTO users (username,
email,password_hash,created_at) VALUES (?,?,?,?)",
		(username,email,password_hash,created_at),
	)
	conn.commit()
	conn.close()

def update_email_by_username(username: str, new_email: str) -> None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()

	cursor.execute("SELECT username FROM users WHERE email = ?", (new_email,))

	row = cursor.fetchone()

	if not row:
		return

	stored_username = row[0]

	# Update using the stored value
	
	query = "UPDATE users SET email = ? WHERE username = ?"

	cursor.execute(query,(new_email,stored_username))

	conn.commit()

	conn.close()
```

Case 7:

```
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL
);

CREATE TABLE messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id    INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    body         TEXT    NOT NULL,
    sent_at      TEXT    NOT NULL
);
```

```
import sqlite3

def get_messages_for_users(user_ids: list[int]) -> list[dict]:
	conn = sqlite3.connect("chat.db")
	cursor = conn.cursor()
	ids_str = ", ".join(str(uid) for uid in user_ids)
	query = f"SELECT id, sender_id, body FROM messages WHERE sender_id IN ({ids_str})"
	cursor.execute(query)
	rows = cursor.fetchall()
	conn.close()
	return [{"id": r[0], "sender_id": r[1], "body": r[2]} for r in rows]
```

1. Below line(s) vulnerable:

```
	query = f"SELECT id, sender_id, body FROM messages WHERE sender_id IN ({ids_str})"
	cursor.execute(query)
```

2. No, the attacker can still inject a SQL Injection payload that

converts to a string such as:

3. Below is a sample payload

```
user_ids: ["3) UNION SELECT sender_id,recipient_id,body FROM messages--"]
```

4. Below is the fix:

 
```
import sqlite3

def get_messages_for_users(user_ids: list[int]) -> list[dict]:

	conn = sqlite3.connect("chat.db")

	cursor = conn.cursor()
	
	parameters = ", ".join("?" for _ in user_ids)

	query = f"SELECT id, sender_id, body FROM messages WHERE sender_id IN ({parameters})"

	cursor.execute(query,tuple(int(uid) for uid in user_ids))

	rows = cursor.fetchall()

	conn.close()

	return [{"id": r[0], "sender_id": r[1], "body": r[2]} for r in rows]
```

Case 8:

```
CREATE TABLE orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    total      REAL    NOT NULL,
    status     TEXT    NOT NULL,  -- 'pending', 'shipped', 'delivered', 'cancelled'
    created_at TEXT    NOT NULL
);
```

```
from sqlalchemy import create_engine, text

engine = create_engine("sqlite:///app.db")

def get_orders_by_status(status: str) -> list[dict]:
	with engine.connect() as conn:
		result = conn.execute(text(f"SELECT id, user_id, total FROM orders WHERE status = '{status}'"))
		return [dict(row._mapping) for row in result]
```

1. NO.

2. Below vulnerable line(s):

```
		result = conn.execute(text(f"SELECT id, user_id, total FROM orders WHERE status = '{status}'"))
```

Because the attacker can attack with the below payload:

```
status: "status_here' UNION SELECT id, user_id, total FROM orders--"
```

3. Below is the fix:

```
from sqlalchemy import create_engine, text

engine = create_engine("sqlite:///app.db")

def get_orders_by_status(status: str) -> list[dict]:
	
	with engine.connect() as conn:

		result = conn.execute(text("SELECT id, user_id, total FROM orders WHERE status = :status"),{"status": status})

		return [dict(row._mapping) for row in result]
```

Case 9:

```
CREATE TABLE audit_logs (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    action     TEXT    NOT NULL,
    table_name TEXT    NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user'
);
```

```
import psycopg2

def search_audit_logs(user_id: int, action: str, table_name: str) -> list[dict]:
	conn = psycopg2.connect("dbname=app user=app password=secret host=localhost")
	cursor = conn.cursor()
	# Developer parameterizes user_id correctly but forgets the others
	query = (
		"SELECT id, user_id, action, table_name, created_at "
		"FROM audit_logs "
		"WHERE user_id = %s "
		"AND action = '" + action + "' "
		"AND table_name = '" + table_name + "'"
	)
	cursor.execute(query, (user_id,))
	rows = cursor.fetchall()
	cursor.close()
	conn.close()
	return [
		{"id": r[0], "user_id": r[1], "action": r[2], "table_name": r[3], "created_at": r[4]}
		for r in rows
	]
```

1. Below line(s) vulnerable:

```
query = (
		"SELECT id, user_id, action, table_name, created_at "
		"FROM audit_logs "
		"WHERE user_id = %s "
		"AND action = '" + action + "' "
		"AND table_name = '" + table_name + "'"
	)
	cursor.execute(query, (user_id,))
```

2. No, because neither `action` nor `table_name` are protected

with SQL Parameterization.

3. 

```
action: "action_here' UNION SELECT * FROM users--"
```
4. Below is the fix:


```
import psycopg2

def search_audit_logs(user_id: int, action: str, table_name: str) -> list[dict]:
	conn = psycopg2.connect("dbname=app user=app password=secret host=localhost")
	cursor = conn.cursor()
	# Developer parameterizes user_id correctly but forgets the others
	query = (
		"SELECT id, user_id, action, table_name, created_at "
		"FROM audit_logs "
		"WHERE user_id = %s "
		"AND action = %s "
		"AND table_name = %s "
	)
	cursor.execute(query, (user_id,action,table_name))
	rows = cursor.fetchall()
	cursor.close()
	conn.close()
	return [
		{"id": r[0], "user_id": r[1], "action": r[2], "table_name": r[3], "created_at": r[4]}
		for r in rows
	]
```


Case 10:

```
CREATE TABLE employees (
    id         SERIAL PRIMARY KEY,
    name       TEXT   NOT NULL,
    salary     NUMERIC(10, 2) NOT NULL,
    department TEXT   NOT NULL,
    title      TEXT   NOT NULL,
    hire_date  DATE   NOT NULL
);
```

```
import psycopg2

def get_employee(department: str, min_salary: int) -> list[dict]:
	conn = psycopg2.connect("dbname=hr user=app password=secret host=localhost")
	cursor = conn.cursor()
	query = (
		"SELECT id, name, salary FROM employees "
		"WHERE department = '" + department + "' AND salary >= " + str(min_salary)
	)
	cursor.execute(query)
	rows = cursor.fetchall()
	cursor.close()
	conn.close()
	return [{"id": r[0], "name": r[1], "salary": r[2]} for r in rows]
```

1. Below line(s) vulnerable:

```
	query = (
		"SELECT id, name, salary FROM employees "
		"WHERE department = '" + department + "' AND salary >= " + str(min_salary)
	)
	
	cursor.execute(query)

```

2. NO. One must apply SQL Parameterization as a defense.

3. Below is the payload:

```
department: "department_here' UNION SELECT id, name, salary FROM employees--"
```

4. psycopg2 uses `%s` for SQL Parameterization.

5. Below is the fix:

```
import psycopg2

def get_employee(department: str, min_salary: int) -> list[dict]:
	conn = psycopg2.connect("dbname=hr user=app password=secret host=localhost")
	cursor = conn.cursor()
	query = (
		"SELECT id, name, salary FROM employees "
		"WHERE department = %s AND salary >= %s" 
	)
	cursor.execute(query,(department,min_salary))
	rows = cursor.fetchall()
	cursor.close()
	conn.close()
	return [{"id": r[0], "name": r[1], "salary": r[2]} for r in rows]
```

Case 11:

```
CREATE TABLE logs (
    id         SERIAL PRIMARY KEY,
    level      TEXT   NOT NULL,  -- 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
    message    TEXT   NOT NULL,
    source     TEXT   NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```


```
import psycopg2

def search_logs(level: str, search_term: str) -> list[dict]:
	conn = psycopg2.connect("dbname=logs user=app password=secret host=localhost")
	cursor = conn.cursor()
	# Developer uses mogrify "for safety"
	safe_query = cursor.mogrify(
		"SELECT id, message, created_at FROM logs WHERE level = %s",
		(level,),
	).decode()
	# Then appends the second filter manually
	full_query = safe_query + f" AND message LIKE '%{search_term}%'"
	cursor.execute(full_query)
	rows = cursor.fetchall()
	cursor.close()
	conn.close()
	return [{"id": r[0], "message": r[1], "ts": r[2]} for r in rows]
```

1. `mogrify()` alone is not enough. SQL Parameterization is the

defense that is necessary, which is done in the code snippet.

2. Below line(s) vulnerable:

```
	full_query = safe_query + f" AND message LIKE '%{search_term}%'"

	cursor.execute(full_query)
```

3. Below sample payload:

```
search_term: "search_term_here%' UNION SELECT level, message, source FROM logs--"

4. Below is the fix:

```
import psycopg2

def search_logs(level: str, search_term: str) -> list[dict]:
	conn = psycopg2.connect("dbname=logs user=app password=secret host=localhost")
	cursor = conn.cursor()
	# Developer uses mogrify "for safety"
	safe_query = cursor.mogrify(
		"SELECT id, message, created_at FROM logs WHERE level = %s",
		(level,),
	).decode()
	# Then appends the second filter manually
	full_query = safe_query + " AND message LIKE %s"
	cursor.execute(full_query,('%' + search_term + '%',))
	rows = cursor.fetchall()
	cursor.close()
	conn.close()
	return [{"id": r[0], "message": r[1], "ts": r[2]} for r in rows]
```

Case 12:

```
CREATE TABLE products (
    id          SERIAL PRIMARY KEY,
    name        TEXT           NOT NULL,
    description TEXT           NOT NULL,
    price       NUMERIC(10, 2) NOT NULL,
    category    TEXT           NOT NULL
);

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
```

```
from fastapi import FastAPI, Query
from sqlalchemy import create_engine, text

app = FastAPI()
engine = create_engine("postgresql+psycopg2://app:secret@localhost/shop")

@app.get("/api/v1/products")
def search_products(q: str = Query(default="")):
	with engine.connect() as conn:
		sql = text(
			"SELECT id, name, description, price FROM products "
			"WHERE name ILIKE '%" + q + "%' OR description ILIKE '%" + q + "%'"
		)
		result = conn.execute(sql)
		return [dict(row._mapping) for row in result]
```

1. Below line(s) vulnerable:

```
sql = text(
			"SELECT id, name, description, price FROM products "
			"WHERE name ILIKE '%" + q + "%' OR description ILIKE '%" + q + "%'"
		)
result = conn.execute(sql)
```

2. No not at all.

3. Below is sample payload:

```
q: "name_here' UNION SELECT * FROM users--"
```

4. Below is the fix:

```
from fastapi import FastAPI, Query
from sqlalchemy import create_engine, text

app = FastAPI()
engine = create_engine("postgresql+psycopg2://app:secret@localhost/shop")

@app.get("/api/v1/products")
def search_products(q: str = Query(default="")):
	with engine.connect() as conn:
		sql = text(
			"SELECT id, name, description, price FROM products "
			"WHERE name ILIKE :q OR description ILIKE :q"
		)
		result = conn.execute(sql,{"q" : '%' + q + '%' })
		return [dict(row._mapping) for row in result]
```

Case 13:

```
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user'
);
```

```
import sqlite3

def check_username_exists(username: str) -> bool:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	query = "SELECT COUNT(*) FROM users WHERE username = '" + username + "'"
	cursor.execute(query)
	count = cursor.fetchone()[0]
	conn.close()
	return count > 0
```

1. Below line(s) vulnerable:

```
	query = "SELECT COUNT(*) FROM users WHERE username = '" + username + "'"
	cursor.execute(query)
```

2. The attacker can still deduce the password hashes of matching

usernames by counting how many database entries contain password

hashes with a matching substring.

3. Below sample payload:

```
username: "username_here' AND SUBSTR((SELECT password_hash FROM users
WHERE username = 'admin'),1,1) = 'a'--" 
```

4. Below is the fix:

```
import sqlite3

def check_username_exists(username: str) -> bool:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	query = "SELECT COUNT(*) FROM users WHERE username = ?"
	cursor.execute(query,(username,))
	count = cursor.fetchone()[0]
	conn.close()
	return count > 0
```

Case 14:

```
CREATE TABLE sales_2024 (
    id         SERIAL PRIMARY KEY,
    region     TEXT           NOT NULL,
    revenue    NUMERIC(12, 2) NOT NULL,
    created_at DATE           NOT NULL
);

CREATE TABLE sales_2025 (
    id         SERIAL PRIMARY KEY,
    region     TEXT           NOT NULL,
    revenue    NUMERIC(12, 2) NOT NULL,
    created_at DATE           NOT NULL
);

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user'
);
```

```
from sqlalchemy import create_engine, text

engine = create_engine("postgresql+psycopg2://app:secret@localhost/reporting")

def get_sales_report(table_name: str, region: str) -> list[dict]:
	"""Return sales rows for a given year table and region."""
	with engine.connect() as conn:
		result = conn.execute(
			text(f"SELECT id, region, revenue, created_at FROM {table_name} WHERE region = :region"),
			{"region": region},
		)
		return [dict(row._mapping) for row in result]
```

1. No.

2. `table_name`

3. Since `table_name` is an identifier the developer must use

Input Validation as a defense--not SQL Parameterization

4. Below is sample payload:

```
table_name: "sales_2025 WHERE region = :region UNION SELECT username,email,password_hash,role FROM users--"
```

5. Below is the fix:


```
from sqlalchemy import create_engine, text

engine = create_engine("postgresql+psycopg2://app:secret@localhost/reporting")

def get_sales_report(table_name: str, region: str) -> list[dict]:
	"""Return sales rows for a given year table and region."""
	with engine.connect() as conn:

		allowlist = ['sales_2024','sales_2025']

		if table_name not in allowlist:

			raise Exception("Invalid table_name")

		result = conn.execute(
			text(f"SELECT id, region, revenue, created_at FROM {table_name} WHERE region = :region"),
			{"region": region},
		)
		return [dict(row._mapping) for row in result]
```

Case 15:

```
CREATE TABLE invoices (
    id         SERIAL PRIMARY KEY,
    tenant_id  TEXT           NOT NULL,
    amount     NUMERIC(10, 2) NOT NULL,
    due_date   DATE           NOT NULL,
    paid       BOOLEAN        NOT NULL DEFAULT FALSE
);

CREATE TABLE contracts (
    id         SERIAL PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    title      TEXT NOT NULL,
    signed_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE projects (
    id        SERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name      TEXT NOT NULL,
    status    TEXT NOT NULL
);
```

```
from sqlalchemy import create_engine, text

engine = create_engine("postgresql+psycopg2://app:secret@localhost/saas")

def get_tenant_data(tenant_id: str, table: str) -> list[dict]:
	"""Return all rows from a tenant-specific table."""
	with engine.connect() as conn:
		result = conn.execute(
			text(f"SELECT * FROM {table} WHERE tenant_id = :tid"),
			{"tid": tenant_id},
		)
		return [dict(row._mapping) for row in result]
```

1. No.

2. `table`

3.

```
In the below payload `tenant_id` can be made to be `TENANT_A`:

table: "invoices WHERE tenant_id = 'TENANT_B' AND" 
```

4. Below is the fix:

```
from sqlalchemy import create_engine, text

engine = create_engine("postgresql+psycopg2://app:secret@localhost/saas")

def get_tenant_data(tenant_id: str, table: str) -> list[dict]:
	"""Return all rows from a tenant-specific table."""
	with engine.connect() as conn:

		allowlist = ['invoices','projects','contracts','users']

		if table not in allowlist:

			raise Exception("Invalid table")

		result = conn.execute(
			text(f"SELECT * FROM {table} WHERE tenant_id = :tid"),
			{"tid": tenant_id},
		)

		
		return [dict(row._mapping) for row in result]
```
