---
title: "SQL Injection Audit Challenge: Can You Spot the Bug? (15 Cases)"
published: false
description: "Hands-on SQL injection code audit — find the vulnerable line, write an exploit, and fix the bug across sqlite3, SQLAlchemy, and psycopg2."
tags: security, python, appsec, sql
cover_image:
---

# SQL Injection Audit Challenge: Can You Spot the Bug?

**Difficulty:** Intermediate  
**Skills:** SQL Injection, Secure Coding, Python, sqlite3, SQLAlchemy, psycopg2  
**Time:** 60–90 minutes

---

## The Breach That Should Never Have Happened

It is 2:47 AM on a Tuesday when the DBA at a mid-sized SaaS company notices something wrong. Query latency has spiked. Rows in the `users` table are being read at a rate no legitimate application traffic could explain. By 3:15 AM the forensics team confirms what everyone feared: 4.2 million user records — usernames, emails, and bcrypt password hashes — are gone. Exfiltrated through the company's own API.

The root cause? A single Python function. A developer had written:

```python
query = "SELECT id, email FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

One string concatenation. One missing parameterized query. That was all it took for an attacker to craft a payload that turned a routine user lookup into a full database dump. The attack took eleven minutes. The breach notification process took four months. The regulatory fines took two years.

SQL injection has been on the OWASP Top 10 since 2003. It is not a new vulnerability. It is not exotic. It is caused by one mistake — mixing user-controlled data with SQL syntax without separation — and it is still being made in production codebases today.

This challenge is designed to train your eye to spot it before it ships.

---

## How This Challenge Works

Each of the 15 cases below presents a realistic Python function that queries a SQL database. Your job for every case is to do exactly what a security engineer does during a code review:

1. **Identify the vulnerable line** — which exact line is exploitable and why?
2. **Write a sample exploit** — what input would an attacker pass to cause damage?
3. **Write the fix** — rewrite the vulnerable code so the bug cannot be exploited.

The cases cover three Python database libraries — `sqlite3`, `SQLAlchemy`, and `psycopg2` — and escalate from classic string concatenation through second-order injection, blind boolean extraction, partial parameterization traps, and multi-tenant isolation failures.

Work through all 15 cases before scrolling to the **Answer Key** at the bottom.

> 💡 These challenges are part of an open source secure coding exercise library. If you find them useful, [⭐ star the repo](https://github.com/fosres/SecEng-Exercises/) — it helps more engineers find it.

---

> **Sources:**
> - *API Security in Action*, Neil Madden (Manning, 2023), Ch. 2 — Secure API Development, pp. 42–44
> - *Full Stack Python Security*, Dennis Byrne (Manning, 2022), Ch. 13 — pp. 206–207
> - *Hacking APIs*, Corey Ball (No Starch Press, 2022), Ch. 12 — Injection, pp. 254–257
> - *Secure by Design*, Johnsson, Deogun, Sawano (Manning, 2019)
> - OWASP SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
> - PortSwigger Web Security Academy — https://portswigger.net/web-security/sql-injection

---

## Case 1: The Classic String Concat (sqlite3)

**Schema — `app.db`:**
```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    created_at    TEXT    NOT NULL
);
```

```python
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

**Questions:**
1. Which line is vulnerable?
2. What input causes it to dump every row in `users`?
3. Rewrite it safely.

---

## Case 2: The f-String Footgun (sqlite3)

**Schema — `app.db`:**
```sql
CREATE TABLE sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token      TEXT    NOT NULL UNIQUE,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT    NOT NULL
);
```

```python
import sqlite3

def delete_session(session_token: str) -> None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	cursor.execute(f"DELETE FROM sessions WHERE token = '{session_token}'")
	conn.commit()
	conn.close()
```

**Questions:**
1. Which line is vulnerable?
2. What value of `session_token` deletes **all** sessions?
3. In one sentence, why are f-strings unsafe for SQL even when the logic looks simple?
4. Fix it.

---

## Case 3: The `.format()` Trap (sqlite3)

**Schema — `shop.db`:**
```sql
CREATE TABLE products (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT    NOT NULL,
    price    REAL    NOT NULL,
    category TEXT    NOT NULL,
    sku      TEXT    NOT NULL UNIQUE,
    in_stock INTEGER NOT NULL DEFAULT 1
);
```

```python
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

**Questions:**
1. Which line is vulnerable?
2. What value of `keyword` bypasses the LIKE filter and returns every product regardless of category?
3. Fix it — note that the `%` wildcard must still work after the fix.

---

## Case 4: The Authentication Query (sqlite3)

**Schema — `auth.db`:**
```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user'
);
```

```python
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

**Questions:**
1. Which line is vulnerable?
2. What value of `username` bypasses the password check entirely?
3. Even after fixing the SQLi, what additional security mistake exists in comparing passwords inside SQL?
4. Fix it.

---

## Case 5: Dynamic ORDER BY — Identifier Injection (sqlite3)

**Schema — `admin.db`:**
```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    role          TEXT    NOT NULL DEFAULT 'user',
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);
```

```python
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

**Questions:**
1. Which line is vulnerable?
2. Why can't you fix this with a `?` placeholder?
3. What value of `sort_column` turns the ORDER BY into a subquery that leaks `password_hash`?
4. Fix it properly. For your allowlist: valid `sort_dir` values are defined by SQL itself (`ASC`, `DESC`). Valid `sort_column` values come from the schema above — exclude any column you would not want exposed through sort order behavior.

> **Hint for Question 3:** A subquery inside `ORDER BY` is valid SQL. The database evaluates it per row and uses the result as the sort key. Think about how that evaluation could be observed by an attacker. Look at the schema — `password_hash` is in the table but not in the SELECT.

---

## Case 6: Second-Order Injection — Store Then Detonate (sqlite3)

**Schema — `app.db`:**
```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);
```

```python
import sqlite3
from datetime import datetime, timezone

def register_user(username: str, email: str, password_hash: str) -> None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	# Correctly parameterized — this INSERT is safe
	cursor.execute(
		"INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
		(username, email, password_hash, datetime.now(timezone.utc).isoformat()),
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

**Questions:**
1. The `register_user` function is parameterized correctly. Is the app safe? Why or why not?
2. Which line in `update_email_by_username` is vulnerable?
3. Describe the two-step attack: what does the attacker register, and what happens when `update_email_by_username` runs?
4. Fix it.

---

## Case 7: IN-Clause Injection (sqlite3)

**Schema — `chat.db`:**
```sql
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

```python
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

**Questions:**
1. Which line is vulnerable?
2. The type hint says `list[int]` — does that make the code safe at runtime? Why or why not?
3. Write an exploit list that exfiltrates the `users` table via a UNION attack.
4. Fix it.

---

## Case 8: SQLAlchemy `text()` with f-String (SQLAlchemy)

**Schema — `app.db`:**
```sql
CREATE TABLE orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    total      REAL    NOT NULL,
    status     TEXT    NOT NULL,  -- 'pending', 'shipped', 'delivered', 'cancelled'
    created_at TEXT    NOT NULL
);
```

```python
from sqlalchemy import create_engine, text

engine = create_engine("sqlite:///app.db")

def get_orders_by_status(status: str) -> list[dict]:
	with engine.connect() as conn:
		result = conn.execute(text(f"SELECT id, user_id, total FROM orders WHERE status = '{status}'"))
		return [dict(row._mapping) for row in result]
```

**Questions:**
1. Does using SQLAlchemy protect you from SQL injection automatically?
2. Which line is vulnerable and why?
3. Fix it using SQLAlchemy's safe parameter binding.

> **SQLAlchemy note:** In SQLAlchemy 2.0+, `conn.execute()` no longer accepts raw strings — it raises `ObjectNotExecutableError`. You must wrap raw SQL in `text()`. However, `text()` alone provides **no protection** — it is simply a required wrapper that tells SQLAlchemy "this is a raw SQL string." The actual protection comes from the `:name` placeholder syntax combined with passing values as a separate dict: `conn.execute(text("... WHERE x = :val"), {"val": input})`. Think of it this way: `text()` is the gate, `:name` binding is the lock.

---

## Case 9: psycopg2 — The Partial Parameterization Trap (PostgreSQL)

**Schema — `app` database:**
```sql
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

```python
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

**Questions:**
1. Which line(s) are vulnerable?
2. `user_id` is correctly parameterized with `%s`. Does that make the function safe?
3. Write a payload using `action` that dumps all rows from the `users` table via a UNION attack.
4. Fix it.

---

## Case 10: psycopg2 — String Concatenation (PostgreSQL)

**Schema — `hr` database:**
```sql
CREATE TABLE employees (
    id         SERIAL PRIMARY KEY,
    name       TEXT   NOT NULL,
    salary     NUMERIC(10, 2) NOT NULL,
    department TEXT   NOT NULL,
    title      TEXT   NOT NULL,
    hire_date  DATE   NOT NULL
);
```

```python
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

**Questions:**
1. Which line is vulnerable?
2. The `min_salary` parameter is cast to `str` — does that make the integer injection-safe?
3. Write a payload using `department` that dumps all employee names and salaries regardless of department.
4. What placeholder character does psycopg2 use? (Trick: it looks like Python's `%` operator but is not.)
5. Fix it.

---

## Case 11: psycopg2 — `mogrify()` Misuse (PostgreSQL)

**Schema — `logs` database:**
```sql
CREATE TABLE logs (
    id         SERIAL PRIMARY KEY,
    level      TEXT   NOT NULL,  -- 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
    message    TEXT   NOT NULL,
    source     TEXT   NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

```python
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

**Questions:**
1. The developer used `mogrify()` — is that sufficient protection?
2. Which line is the real vulnerability?
3. Write an exploit targeting `search_term`.
4. Fix it.

---

## Case 12: FastAPI + SQLAlchemy — Injection Through Query Param (SQLAlchemy + Web)

**Schema — `shop` database (PostgreSQL):**
```sql
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

```python
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

**Questions:**
1. Which line is the vulnerability?
2. This is a GET endpoint — does the HTTP method make SQL injection less dangerous?
3. Write a sample payload for `q` that dumps the `users` table via a UNION attack.
4. Fix it.

---

## Case 13: Blind Boolean-Based Injection Setup (sqlite3)

**Schema — `app.db`:**
```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user'
);
```

```python
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

**Questions:**
1. Which line is vulnerable?
2. This endpoint only returns `True`/`False` — can an attacker still extract data? Explain how in one sentence.
3. Write a blind boolean payload that reveals whether the first character of the admin's `password_hash` is `'a'`. Use SQLite's `SUBSTR()`.
4. Fix it.

---

## Case 14: SQLAlchemy `text()` — Dynamic Table Name (SQLAlchemy)

**Schema — `reporting` database (PostgreSQL):**
```sql
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

```python
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

**Questions:**
1. `region` is safely parameterized with `:region`. Is the function safe?
2. Which parameter is the actual vulnerability?
3. Why can't you fix the vulnerable parameter with a `:name` placeholder?
4. Write a sample payload for the vulnerable parameter that dumps the `users` table.
5. Fix it properly.

> **Hint for Question 3:** Recall Case 5 — the same reason `?` couldn't fix `ORDER BY` applies here.

---

## Case 15: Multi-Tenant Data Isolation Failure (SQLAlchemy)

**Schema — `saas` database (PostgreSQL):**
```sql
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

> **Note:** Every table has a `tenant_id` column used to isolate rows between customers. The function is supposed to enforce that isolation — but does it?

```python
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

**Questions:**
1. `tenant_id` is safely parameterized as `:tid`. Is the function safe?
2. Which parameter is the actual vulnerability — `tenant_id` or `table`?
3. Write an exploit that reads TENANT_B's `invoices` data while authenticated as TENANT_A.
4. Fix it.

---

## Summary Table

| Case | Library | Injection Vector | Root Cause |
|------|---------|-----------------|------------|
| 1 | sqlite3 | `+` concatenation | Classic string building |
| 2 | sqlite3 | f-string | Python interpolation before driver |
| 3 | sqlite3 | `.format()` | Python interpolation before driver |
| 4 | sqlite3 | `%` formatting | Python interpolation before driver |
| 5 | sqlite3 | `ORDER BY` identifier | Identifiers can't be parameterized |
| 6 | sqlite3 | Second-order | DB data treated as trusted |
| 7 | sqlite3 | `IN (...)` clause | List items joined as string |
| 8 | SQLAlchemy | `text()` + f-string | `text()` is not magic protection |
| 9 | psycopg2 | Partial parameterization | One safe param hides two unsafe ones |
| 10 | psycopg2 | `+` concatenation | Classic string building |
| 11 | psycopg2 | `mogrify()` + append | Partial parameterization |
| 12 | FastAPI+SA | Query param in `text()` | Web layer feeds injection |
| 13 | sqlite3 | Blind boolean | Binary response still leaks data |
| 14 | SQLAlchemy | Dynamic table name in `text()` | Identifier vs value confusion |
| 15 | SQLAlchemy | Dynamic table name | Identifier vs value confusion |

---

## Resources

- *API Security in Action*, Neil Madden (Manning, 2023) — Ch. 2, pp. 42–44
- *Full Stack Python Security*, Dennis Byrne (Manning, 2022) — Ch. 13, pp. 206–207
- *Hacking APIs*, Corey Ball (No Starch Press, 2022) — Ch. 12, pp. 254–257
- *Secure by Design*, Johnsson, Deogun, Sawano (Manning, 2019)
- PortSwigger SQL Injection Academy: https://portswigger.net/web-security/sql-injection
- OWASP SQLi Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- SQLMap documentation: https://github.com/sqlmapproject/sqlmap

---

## ⭐ Take the Challenge — Then Star the Repo

If you made it through all 15 cases, you've just practiced the exact code review skills that show up in Security Engineering interviews and AppSec code audits.

These exercises are part of an open source project I'm building: a curated library of secure coding challenges designed to train both engineers *and* AI models to write code that doesn't get breached at 2:47 AM.

**If this was useful, please star the repo — it helps the project grow:**

## 👉 [⭐ Star SecEng-Exercises on GitHub](https://github.com/fosres/SecEng-Exercises/)

New challenges are added regularly — SQL injection, XSS, authentication bypass, API security, and more. Each one ships with a full test suite and a Dev.to write-up like this one.

---

## 📊 Quick Poll

One more thing — I'm building out the exercise library and want to focus on what's most useful to you.

**What type of security bug do you want to see next?**

👉 [Cast your vote here](https://strawpoll.com/wby5QoKAkyA)

Takes 10 seconds. Genuinely helps me prioritize.

---

*Part of the [P2P Secure Coding Exercise Repository](https://github.com/fosres/SecEng-Exercises/) — curating high-quality, secure Python code to train AI models to write secure code.*

---
---

# ⚠️ ANSWER KEY — Stop Here Until You've Attempted All 15 Cases ⚠️

---
---

## Answer Key — Case 1: The Classic String Concat

**Vulnerable line:**
```python
query = "SELECT id, username, email FROM users WHERE username = '" + username + "'"
```

**Sample exploit:**
```
username: "user' UNION SELECT id, username, email FROM users--"
```

**Fix:**
```python
import sqlite3

def get_user_by_username(username: str) -> dict | None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	query = "SELECT id, username, email FROM users WHERE username = ?"
	cursor.execute(query, (username,))
	row = cursor.fetchone()
	conn.close()
	if row:
		return {"id": row[0], "username": row[1], "email": row[2]}
	return None
```

---

## Answer Key — Case 2: The f-String Footgun

**Vulnerable line:**
```python
cursor.execute(f"DELETE FROM sessions WHERE token = '{session_token}'")
```

**Sample exploit:**
```
session_token: "valid_token_here' OR '1' = '1"
```

**Fix:**
```python
import sqlite3

def delete_session(session_token: str) -> None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	cursor.execute("DELETE FROM sessions WHERE token = ?", (session_token,))
	conn.commit()
	conn.close()
```

---

## Answer Key — Case 3: The `.format()` Trap

**Vulnerable line:**
```python
query = "SELECT id, name, price FROM products WHERE name LIKE '%{}%' AND category = '{}'".format(
	keyword, category
)
cursor.execute(query)
```

**Sample exploits:**
```
keyword: "product_here%' UNION SELECT id, name, price FROM products--"

category: "category_here' UNION SELECT id, name, price FROM products--"
```

**Fix:**
```python
import sqlite3

def search_products(keyword: str, category: str) -> list[dict]:
	conn = sqlite3.connect("shop.db")
	cursor = conn.cursor()
	query = "SELECT id, name, price FROM products WHERE name LIKE ? AND category = ?"
	cursor.execute(query, ("%" + keyword + "%", category))
	rows = cursor.fetchall()
	conn.close()
	return [{"id": r[0], "name": r[1], "price": r[2]} for r in rows]
```

---

## Answer Key — Case 4: The `%s` %-Format Mistake

**Vulnerable line:**
```python
query = "SELECT 1 FROM users WHERE username = '%s' AND password_hash = '%s'" % (
	username, password_hash
)
cursor.execute(query)
```

**Sample exploit:**
```
username: "user_here' OR '1'='1"
```

**Additional security mistake:** Timing vulnerability when comparing password hashes inside SQL — the database response time leaks whether the username exists even on a failed login. Use `hmac.compare_digest()` in Python instead.

**Fix:**
```python
import sqlite3
import hmac

def authenticate_user(username: str, password_hash: str) -> bool:
	conn = sqlite3.connect("auth.db")
	cursor = conn.cursor()
	query = "SELECT username, password_hash FROM users WHERE username = ?"
	cursor.execute(query, (username,))
	result = cursor.fetchone()
	if result is None:
		conn.close()
		return False
	pwhash = result[1]
	if not hmac.compare_digest(pwhash, password_hash):
		conn.close()
		return False
	elif hmac.compare_digest(pwhash, password_hash):
		conn.close()
		return True
```

---

## Answer Key — Case 5: Dynamic ORDER BY — Identifier Injection

**Vulnerable line:**
```python
query = f"SELECT id, username, role FROM users ORDER BY {sort_column} {sort_dir}"
cursor.execute(query)
```

**Why `?` doesn't work:** You cannot apply SQL parameterization since that binds values. `ORDER BY` expects SQL identifiers — column names — not values. You must rely on input validation instead.

**Sample exploit:**
```
sort_column: "(SELECT password_hash FROM users WHERE username='admin' LIMIT 1)--"
```

**Fix:**
```python
import sqlite3

def list_users(sort_column: str, sort_dir: str) -> list[dict]:
	conn = sqlite3.connect("admin.db")
	cursor = conn.cursor()
	allowed_columns = ["id", "username", "role", "created_at"]
	if sort_column not in allowed_columns or sort_dir not in ["ASC", "DESC", "asc", "desc"]:
		conn.close()
		raise Exception("Invalid parameters")
	query = f"SELECT id, username, role FROM users ORDER BY {sort_column} {sort_dir}"
	cursor.execute(query)
	rows = cursor.fetchall()
	conn.close()
	return [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]
```

---

## Answer Key — Case 6: Second-Order Injection

**Is the app safe?** No — `update_email_by_username` still has a SQL injection vulnerability even though `register_user` is correctly parameterized.

**Vulnerable line:**
```python
query = "UPDATE users SET email = '" + new_email + "' WHERE username = '" + stored_username + "'"
cursor.execute(query)
```

**Sample exploit:**
```
new_email: "attacker@attacker_email.com',password_hash='password_hash_here"
```
This closes the email string early and injects a second column assignment — overwriting `password_hash` in the same UPDATE statement, giving the attacker full account takeover.

**Fix:**
```python
import sqlite3
from datetime import datetime, timezone

def register_user(username: str, email: str, password_hash: str) -> None:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	cursor.execute(
		"INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
		(username, email, password_hash, datetime.now(timezone.utc).isoformat()),
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
	query = "UPDATE users SET email = ? WHERE username = ?"
	cursor.execute(query, (new_email, stored_username))
	conn.commit()
	conn.close()
```

---

## Answer Key — Case 7: IN-Clause Injection

**Vulnerable line:**
```python
query = f"SELECT id, sender_id, body FROM messages WHERE sender_id IN ({ids_str})"
cursor.execute(query)
```

**Does `list[int]` type hint protect at runtime?** No — Python does not enforce type hints at runtime. A caller can pass strings through a JSON body or query parameter and `str(uid)` will embed whatever arrives.

**Sample exploit:**
```
user_ids: ["3) UNION SELECT sender_id, recipient_id, body FROM messages--"]
```

**Fix:**
```python
import sqlite3

def get_messages_for_users(user_ids: list[int]) -> list[dict]:
	conn = sqlite3.connect("chat.db")
	cursor = conn.cursor()
	parameters = ", ".join("?" for _ in user_ids)
	query = f"SELECT id, sender_id, body FROM messages WHERE sender_id IN ({parameters})"
	cursor.execute(query, tuple(int(uid) for uid in user_ids))
	rows = cursor.fetchall()
	conn.close()
	return [{"id": r[0], "sender_id": r[1], "body": r[2]} for r in rows]
```

---

## Answer Key — Case 8: SQLAlchemy `text()` with f-String

**Does SQLAlchemy auto-protect?** No. `text()` is not magic protection — it is a required wrapper for raw SQL strings in SQLAlchemy 2.0+. The protection comes from the `:name` placeholder syntax, not from `text()` itself.

**Vulnerable line:**
```python
result = conn.execute(text(f"SELECT id, user_id, total FROM orders WHERE status = '{status}'"))
```

**Sample exploit:**
```
status: "status_here' UNION SELECT id, user_id, total FROM orders--"
```

**Fix:**
```python
from sqlalchemy import create_engine, text

engine = create_engine("sqlite:///app.db")

def get_orders_by_status(status: str) -> list[dict]:
	with engine.connect() as conn:
		result = conn.execute(
			text("SELECT id, user_id, total FROM orders WHERE status = :status"),
			{"status": status},
		)
		return [dict(row._mapping) for row in result]
```

---

## Answer Key — Case 9: psycopg2 — Partial Parameterization Trap

**Vulnerable lines:**
```python
"AND action = '" + action + "' "
"AND table_name = '" + table_name + "'"
```

**Is the function safe?** No — `user_id` is correctly parameterized but `action` and `table_name` are concatenated directly. One unparameterized input is all an attacker needs.

**Sample exploit:**
```
action: "action_here' UNION SELECT * FROM users--"
```

**Fix:**
```python
import psycopg2

def search_audit_logs(user_id: int, action: str, table_name: str) -> list[dict]:
	conn = psycopg2.connect("dbname=app user=app password=secret host=localhost")
	cursor = conn.cursor()
	query = (
		"SELECT id, user_id, action, table_name, created_at "
		"FROM audit_logs "
		"WHERE user_id = %s AND action = %s AND table_name = %s"
	)
	cursor.execute(query, (user_id, action, table_name))
	rows = cursor.fetchall()
	cursor.close()
	conn.close()
	return [
		{"id": r[0], "user_id": r[1], "action": r[2], "table_name": r[3], "created_at": r[4]}
		for r in rows
	]
```

---

## Answer Key — Case 10: psycopg2 — String Concatenation

**Vulnerable line:**
```python
query = (
	"SELECT id, name, salary FROM employees "
	"WHERE department = '" + department + "' AND salary >= " + str(min_salary)
)
cursor.execute(query)
```

**Is `str(min_salary)` safe?** No. One must apply SQL parameterization as a defense.

**Sample exploit:**
```
department: "department_here' UNION SELECT id, name, salary FROM employees--"
```

**psycopg2 placeholder:** `%s` — psycopg2's parameterization token, not Python's `%` string operator.

**Fix:**
```python
import psycopg2

def get_employee(department: str, min_salary: int) -> list[dict]:
	conn = psycopg2.connect("dbname=hr user=app password=secret host=localhost")
	cursor = conn.cursor()
	query = (
		"SELECT id, name, salary FROM employees "
		"WHERE department = %s AND salary >= %s"
	)
	cursor.execute(query, (department, min_salary))
	rows = cursor.fetchall()
	cursor.close()
	conn.close()
	return [{"id": r[0], "name": r[1], "salary": r[2]} for r in rows]
```

---

## Answer Key — Case 11: psycopg2 — `mogrify()` Misuse

**Is `mogrify()` sufficient?** No. `mogrify()` alone is not enough — SQL parameterization is the necessary defense, and while it is applied for `level`, the f-string appended for `search_term` defeats that protection.

**Vulnerable line:**
```python
full_query = safe_query + f" AND message LIKE '%{search_term}%'"
cursor.execute(full_query)
```

**Sample exploit:**
```
search_term: "search_term_here%' UNION SELECT level, message, source FROM logs--"
```

**Fix:**
```python
import psycopg2

def search_logs(level: str, search_term: str) -> list[dict]:
	conn = psycopg2.connect("dbname=logs user=app password=secret host=localhost")
	cursor = conn.cursor()
	safe_query = cursor.mogrify(
		"SELECT id, message, created_at FROM logs WHERE level = %s",
		(level,),
	).decode()
	full_query = safe_query + " AND message LIKE %s"
	cursor.execute(full_query, ('%' + search_term + '%',))
	rows = cursor.fetchall()
	cursor.close()
	conn.close()
	return [{"id": r[0], "message": r[1], "ts": r[2]} for r in rows]
```

---

## Answer Key — Case 12: FastAPI + SQLAlchemy — Query Param Injection

**Vulnerable line:**
```python
sql = text(
	"SELECT id, name, description, price FROM products "
	"WHERE name ILIKE '%" + q + "%' OR description ILIKE '%" + q + "%'"
)
result = conn.execute(sql)
```

**Does GET reduce severity?** Not at all.

**Sample exploit:**
```
q: "name_here' UNION SELECT * FROM users--"
```

**Fix:**
```python
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
		result = conn.execute(sql, {"q": '%' + q + '%'})
		return [dict(row._mapping) for row in result]
```

---

## Answer Key — Case 13: Blind Boolean-Based Injection

**Vulnerable line:**
```python
query = "SELECT COUNT(*) FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

**Can an attacker extract data with only True/False?** Yes — the attacker can deduce password hashes by crafting payloads that ask yes/no questions about database contents, extracting data one character at a time through the binary response.

**Sample blind payload:**
```
username: "username_here' AND SUBSTR((SELECT password_hash FROM users WHERE username = 'admin'),1,1) = 'a'--"
```
Returns `True` if the first character of admin's password hash is `'a'`, `False` otherwise. Repeat for each position to extract the full hash.

**Fix:**
```python
import sqlite3

def check_username_exists(username: str) -> bool:
	conn = sqlite3.connect("app.db")
	cursor = conn.cursor()
	query = "SELECT COUNT(*) FROM users WHERE username = ?"
	cursor.execute(query, (username,))
	count = cursor.fetchone()[0]
	conn.close()
	return count > 0
```

---

## Answer Key — Case 14: SQLAlchemy `text()` — Dynamic Table Name

**Is the function safe?** No.

**Vulnerable parameter:** `table_name`

**Why `:name` placeholder can't fix it:** Since `table_name` is a SQL identifier, the developer must use input validation as a defense — not SQL parameterization. Parameterization binds values; identifiers must appear in the parsed SQL syntax and cannot be bound as data.

**Sample exploit:**
```
table_name: "sales_2025 WHERE region = :region UNION SELECT username, email, password_hash, role FROM users--"
```

**Fix:**
```python
from sqlalchemy import create_engine, text

engine = create_engine("postgresql+psycopg2://app:secret@localhost/reporting")

def get_sales_report(table_name: str, region: str) -> list[dict]:
	with engine.connect() as conn:
		allowlist = ['sales_2024', 'sales_2025']
		if table_name not in allowlist:
			raise Exception("Invalid table_name")
		result = conn.execute(
			text(f"SELECT id, region, revenue, created_at FROM {table_name} WHERE region = :region"),
			{"region": region},
		)
		return [dict(row._mapping) for row in result]
```

---

## Answer Key — Case 15: Multi-Tenant Data Isolation Failure

**Is the function safe?** No.

**Vulnerable parameter:** `table`

**Sample exploit:**
```
table: "invoices WHERE tenant_id = 'TENANT_B' AND"
```
With `tenant_id` bound as TENANT_A, this reads TENANT_B's invoices — complete cross-tenant isolation failure.

**Fix:**
```python
from sqlalchemy import create_engine, text

engine = create_engine("postgresql+psycopg2://app:secret@localhost/saas")

def get_tenant_data(tenant_id: str, table: str) -> list[dict]:
	"""Return all rows from a tenant-specific table."""
	with engine.connect() as conn:
		allowlist = ['invoices', 'projects', 'contracts', 'users']
		if table not in allowlist:
			raise Exception("Invalid table")
		result = conn.execute(
			text(f"SELECT * FROM {table} WHERE tenant_id = :tid"),
			{"tid": tenant_id},
		)
		return [dict(row._mapping) for row in result]
```

---

## The Three Rules That Prevent Every Case Above

1. **Parameterize values.** Every user-supplied value goes through a `?` (sqlite3), `%s` (psycopg2), or `:name` (SQLAlchemy `text()`) placeholder — never into the SQL string itself.

2. **Allowlist identifiers.** Column names, table names, ORDER BY directions — anything that must appear in the SQL text as a keyword or identifier — must be validated against a hard-coded set of allowed values. There is no driver-level escape for identifiers.

3. **Never trust data from the database.** If a value was originally supplied by a user and stored in a database, it is still untrusted when retrieved. Parameterize it again every time it goes back into a query.
