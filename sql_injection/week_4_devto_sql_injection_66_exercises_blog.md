# Round 6: Advanced Exploitation Patterns (Snippets 53-66)

*Difficulty: Expert*

## Snippet 53: Django Raw SQL Query

```python
from django.contrib.auth.models import User

def get_users_by_role(role_name):
	sql = "SELECT id, username FROM auth_user WHERE first_name = '%s'" % role_name
	users = User.objects.raw(sql)
	
	return [{"id": u.id, "username": u.username} for u in users]
```

---

## Snippet 54: Second-Order SQL Injection Storage

```python
import sqlite3

def update_user_preferences(user_id, display_name):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	# First query - stores user input
	query1 = "UPDATE users SET display_name = ? WHERE id = ?"
	cursor.execute(query1, (display_name, user_id))
	conn.commit()
	
	# Second query - retrieves and uses stored data
	query2 = "SELECT display_name FROM users WHERE id = ?"
	cursor.execute(query2, (user_id,))
	name = cursor.fetchone()[0]
	
	# Third query - uses retrieved data in dynamic SQL
	query3 = f"INSERT INTO audit_log (action, details) VALUES ('name_change', 'New name: {name}')"
	cursor.execute(query3)
	conn.commit()
	conn.close()
	
	return {"status": "updated"}
```

---

## Snippet 55: PostgreSQL Array Operations

```python
import psycopg2

def search_by_tags(tag_list: list):
	conn = psycopg2.connect("dbname=blog")
	cursor = conn.cursor()
	
	# Convert Python list to PostgreSQL array format
	tags_array = '{' + ','.join(tag_list) + '}'
	
	query = f"SELECT * FROM posts WHERE tags && ARRAY{tags_array}::text[]"
	cursor.execute(query)
	
	results = cursor.fetchall()
	conn.close()
	return results
```

---

## Snippet 56: Time-Based Attack Context

```python
import mysql.connector
import time

def check_user_exists_timed(username):
	conn = mysql.connector.connect(host="localhost", database="app")
	cursor = conn.cursor()
	
	# Validate username format first
	if not username.replace('_', '').replace('-', '').isalnum():
		return {"error": "Invalid username format"}
	
	query = f"SELECT COUNT(*) FROM users WHERE username = '{username}'"
	
	start = time.time()
	cursor.execute(query)
	result = cursor.fetchone()[0]
	elapsed = time.time() - start
	
	conn.close()
	
	return {"exists": result > 0, "query_time": elapsed}
```

---

## Snippet 57: Django Database Connection Query

```python
from django.db import connection

def delete_expired_sessions(session_type, days_old):
	sql = f"""DELETE FROM auth_session 
			  WHERE session_type = %s 
			  AND expire_date < DATE_SUB(NOW(), INTERVAL {days_old} DAY)"""
	
	with connection.cursor() as cursor:
		cursor.execute(sql, [session_type])
		deleted = cursor.rowcount
	
	return {"deleted": deleted}
```

---

## Snippet 58: PostgreSQL JSONB Query

```python
import psycopg2

def search_metadata(field_name, field_value):
	conn = psycopg2.connect("dbname=documents")
	cursor = conn.cursor()
	
	allowed_fields = ['status', 'priority', 'category', 'author']
	
	if field_name not in allowed_fields:
		return {"error": "Invalid field"}
	
	query = f"SELECT * FROM documents WHERE metadata->>'{field_name}' = %s"
	cursor.execute(query, (field_value,))
	
	results = cursor.fetchall()
	conn.close()
	return results
```

---

## Snippet 59: Stored Procedure Call

```python
import mysql.connector

def generate_report_via_sp(report_type, start_date, end_date):
	conn = mysql.connector.connect(host="localhost", database="analytics")
	cursor = conn.cursor()
	
	allowed_types = ['sales', 'inventory', 'users', 'transactions']
	
	if report_type not in allowed_types:
		return {"error": "Invalid report type"}
	
	proc_name = f"generate_{report_type}_report"
	
	# Call stored procedure
	cursor.callproc(proc_name, [start_date, end_date])
	
	results = []
	for result in cursor.stored_results():
		results.extend(result.fetchall())
	
	conn.close()
	return {"data": results}
```

---

## Snippet 60: Error-Based Blind SQLi Context

```python
import sqlite3

def validate_license_key(license_key):
	conn = sqlite3.connect('licenses.db')
	cursor = conn.cursor()
	
	# Basic format validation
	if len(license_key) != 36 or license_key.count('-') != 4:
		return {"valid": False, "error": "Invalid format"}
	
	try:
		query = f"SELECT 1 FROM licenses WHERE key = '{license_key}' AND status = 'active'"
		cursor.execute(query)
		result = cursor.fetchone()
		conn.close()
		
		if result:
			return {"valid": True}
		return {"valid": False, "error": "Invalid or inactive license"}
		
	except sqlite3.Error as e:
		conn.close()
		return {"valid": False, "error": str(e)}
```

---

## Snippet 61: Complex Subquery Pattern

```python
import psycopg2

def get_top_customers(metric, limit):
	conn = psycopg2.connect("dbname=sales")
	cursor = conn.cursor()
	
	allowed_metrics = ['revenue', 'orders', 'items_purchased']
	
	if metric not in allowed_metrics:
		metric = 'revenue'
	
	try:
		limit_val = int(limit)
		if limit_val < 1 or limit_val > 100:
			limit_val = 10
	except (ValueError, TypeError):
		limit_val = 10
	
	query = f"""
		SELECT customer_id, SUM({metric}) as total
		FROM (
			SELECT customer_id, {metric}
			FROM orders
			WHERE status = 'completed'
		) subquery
		GROUP BY customer_id
		ORDER BY total DESC
		LIMIT ?
	"""
	
	cursor.execute(query, (limit_val,))
	results = cursor.fetchall()
	conn.close()
	
	return results
```

---

## Snippet 62: Batch Update with Transaction

```python
import mysql.connector

def batch_update_prices(price_updates: dict):
	"""
	price_updates: {"product_123": 29.99, "product_456": 49.99}
	"""
	conn = mysql.connector.connect(host="localhost", database="inventory")
	cursor = conn.cursor()
	
	try:
		conn.start_transaction()
		
		for product_id, new_price in price_updates.items():
			# Validate product_id format
			if not product_id.startswith('product_'):
				continue
			
			# Extract numeric ID
			numeric_id = product_id.replace('product_', '')
			
			if not numeric_id.isdigit():
				continue
			
			query = f"UPDATE products SET price = %s WHERE id = {numeric_id}"
			cursor.execute(query, (new_price,))
		
		conn.commit()
		updated = cursor.rowcount
		
	except Exception as e:
		conn.rollback()
		return {"error": str(e)}
	finally:
		conn.close()
	
	return {"updated": updated}
```

---

## Snippet 63: Dynamic Table Selection with CTE

```python
import psycopg2

def get_monthly_summary(table_suffix, year, month):
	conn = psycopg2.connect("dbname=analytics")
	cursor = conn.cursor()
	
	# Validate year and month
	try:
		year = int(year)
		month = int(month)
		if not (2020 <= year <= 2030) or not (1 <= month <= 12):
			return {"error": "Invalid date range"}
	except (ValueError, TypeError):
		return {"error": "Invalid date format"}
	
	# Validate table suffix
	allowed_suffixes = ['revenue', 'expenses', 'profit']
	if table_suffix not in allowed_suffixes:
		return {"error": "Invalid table"}
	
	table_name = f"monthly_{table_suffix}"
	
	query = f"""
		WITH monthly_data AS (
			SELECT * FROM {table_name}
			WHERE year = %s AND month = %s
		)
		SELECT SUM(amount) as total FROM monthly_data
	"""
	
	cursor.execute(query, (year, month))
	result = cursor.fetchone()
	conn.close()
	
	return {"total": result[0] if result else 0}
```

---

## Snippet 64: XML Path Context

```python
import sqlite3

def query_xml_field(doc_id, xpath_expr):
	conn = sqlite3.connect('documents.db')
	cursor = conn.cursor()
	
	# Validate doc_id is numeric
	if not str(doc_id).isdigit():
		return {"error": "Invalid document ID"}
	
	# Allowlist common XPath expressions
	allowed_paths = [
		'//title',
		'//author',
		'//date',
		'//content',
		'/document/metadata/tags'
	]
	
	if xpath_expr not in allowed_paths:
		return {"error": "Invalid XPath expression"}
	
	query = f"SELECT xpath('{xpath_expr}', xml_content) FROM documents WHERE id = ?"
	cursor.execute(query, (doc_id,))
	
	result = cursor.fetchone()
	conn.close()
	
	return {"data": result[0] if result else None}
```

---

## Snippet 65: NoSQL-Style Operators in SQL

```python
import psycopg2

def find_users_by_criteria(filter_op, field, value):
	conn = psycopg2.connect("dbname=users")
	cursor = conn.cursor()
	
	# Map NoSQL-style operators to SQL
	operator_map = {
		'$eq': '=',
		'$ne': '!=',
		'$gt': '>',
		'$lt': '<',
		'$gte': '>=',
		'$lte': '<='
	}
	
	if filter_op not in operator_map:
		return {"error": "Invalid operator"}
	
	sql_op = operator_map[filter_op]
	
	allowed_fields = ['age', 'created_at', 'last_login', 'points']
	
	if field not in allowed_fields:
		return {"error": "Invalid field"}
	
	query = f"SELECT id, username FROM users WHERE {field} {sql_op} %s"
	cursor.execute(query, (value,))
	
	results = cursor.fetchall()
	conn.close()
	
	return results
```

---

## Snippet 66: SQLAlchemy Text with Named Parameters

```python
from sqlalchemy import create_engine, text

def advanced_search(filters: dict):
	"""
	filters: {
		"status": "active",
		"min_price": 100,
		"sort_by": "price",
		"sort_dir": "DESC"
	}
	"""
	engine = create_engine('postgresql://localhost/products')
	
	allowed_sort_cols = ['price', 'name', 'created_at', 'stock']
	sort_col = filters.get('sort_by', 'name')
	
	if sort_col not in allowed_sort_cols:
		sort_col = 'name'
	
	allowed_directions = ['ASC', 'DESC']
	sort_dir = filters.get('sort_dir', 'ASC').upper()
	
	if sort_dir not in allowed_directions:
		sort_dir = 'ASC'
	
	base_query = f"""
		SELECT * FROM products 
		WHERE status = :status 
		AND price >= :min_price
		ORDER BY {sort_col} {sort_dir}
	"""
	
	with engine.connect() as conn:
		result = conn.execute(
			text(base_query),
			{
				"status": filters.get("status", "active"),
				"min_price": filters.get("min_price", 0)
			}
		)
		rows = result.fetchall()
	
	return [dict(row._mapping) for row in rows]
```

---

<details>
<summary>💡 Round 6 Answers & Fixes (Click to Expand)</summary>

## Round 6 Answers

| Snippet | Vulnerable? | Reason |
|---------|-------------|--------|
| 53 | ✅ Yes | Django `raw()` with string interpolation |
| 54 | ✅ Yes | Second-order injection in audit log query |
| 55 | ✅ Yes | Array literal not parameterized |
| 56 | ✅ Yes | Time-based context with string concatenation |
| 57 | ✅ Yes | `INTERVAL {days_old} DAY` not parameterized |
| 58 | ❌ No | JSONB key allowlisted, value parameterized |
| 59 | ✅ Yes | Stored procedure name dynamically constructed |
| 60 | ✅ Yes | Error messages leak SQL details enabling blind injection |
| 61 | ❌ No | Metric allowlisted, limit validated and parameterized |
| 62 | ✅ Yes | `numeric_id` interpolated into WHERE clause |
| 63 | ❌ No | Table allowlisted, parameters validated and parameterized |
| 64 | ❌ No | XPath expression allowlisted, doc_id parameterized |
| 65 | ❌ No | Operators mapped via allowlist, field allowlisted, value parameterized |
| 66 | ❌ No | Sort columns/directions allowlisted, values use named parameters |

### Snippet 53 Fix (Django raw SQL)

```python
# Vulnerable
sql = "SELECT id, username FROM auth_user WHERE first_name = '%s'" % role_name
users = User.objects.raw(sql)

# Fixed (use parameterization with list)
sql = "SELECT id, username FROM auth_user WHERE first_name = %s"
users = User.objects.raw(sql, [role_name])
```

**Source:** Full Stack Python Security, pp. 205-207 — Django's `raw()` method requires manual parameterization by passing parameter values as a list. Never use string interpolation (`%` operator) with raw SQL.<sup>1</sup>

---

### Snippet 54 Fix (Second-order SQL injection)

```python
# Vulnerable (third query uses unescaped stored data)
query3 = f"INSERT INTO audit_log (action, details) VALUES ('name_change', 'New name: {name}')"
cursor.execute(query3)

# Fixed (parameterize all queries, even with previously stored data)
query3 = "INSERT INTO audit_log (action, details) VALUES ('name_change', ?)"
cursor.execute(query3, (f'New name: {name}',))
```

**Critical Insight:** Second-order SQL injection occurs when data stored safely (via parameterization) is later retrieved and used unsafely in a subsequent query. Always parameterize queries even when using data from your own database.<sup>2</sup>

---

### Snippet 55 Fix (PostgreSQL array operations)

```python
# Vulnerable
tags_array = '{' + ','.join(tag_list) + '}'
query = f"SELECT * FROM posts WHERE tags && ARRAY{tags_array}::text[]"
cursor.execute(query)

# Fixed (use ANY with parameterized array)
query = "SELECT * FROM posts WHERE tags && %s"
cursor.execute(query, (tag_list,))

# Alternative: Use psycopg2's array adaptation
from psycopg2.extensions import adapt
query = "SELECT * FROM posts WHERE tags && %s::text[]"
cursor.execute(query, (tag_list,))
```

**Source:** PostgreSQL array operations require special handling. Use psycopg2's built-in array adaptation or the `ANY` operator with parameterization.<sup>3</sup>

---

### Snippet 56 Fix (Time-based attack context)

```python
# Vulnerable (even with validation, string concatenation enables time-based attacks)
query = f"SELECT COUNT(*) FROM users WHERE username = '{username}'"
cursor.execute(query)

# Fixed
query = "SELECT COUNT(*) FROM users WHERE username = %s"
cursor.execute(query, (username,))
```

**Attack Vector:** An attacker could inject `admin' AND SLEEP(5)-- -` to determine if user 'admin' exists based on response time. Input validation doesn't prevent time-based blind SQL injection — only parameterization does.<sup>4</sup>

---

### Snippet 57 Fix (Django database connection)

```python
# Vulnerable
sql = f"""DELETE FROM auth_session 
		  WHERE session_type = %s 
		  AND expire_date < DATE_SUB(NOW(), INTERVAL {days_old} DAY)"""
cursor.execute(sql, [session_type])

# Fixed (parameterize ALL dynamic values)
sql = """DELETE FROM auth_session 
		 WHERE session_type = %s 
		 AND expire_date < DATE_SUB(NOW(), INTERVAL %s DAY)"""
cursor.execute(sql, [session_type, days_old])
```

**Source:** Full Stack Python Security, pp. 206-207 — Django's `connection.cursor()` requires the `params` argument for parameterization. Never mix f-strings with partial parameterization.<sup>1</sup>

---

### Snippet 59 Fix (Stored procedure call)

```python
# Vulnerable (procedure name dynamically constructed)
proc_name = f"generate_{report_type}_report"
cursor.callproc(proc_name, [start_date, end_date])

# Fixed (explicit procedure mapping)
procedure_map = {
	'sales': 'generate_sales_report',
	'inventory': 'generate_inventory_report',
	'users': 'generate_users_report',
	'transactions': 'generate_transactions_report'
}

if report_type not in procedure_map:
	return {"error": "Invalid report type"}

proc_name = procedure_map[report_type]
cursor.callproc(proc_name, [start_date, end_date])
```

**Critical:** Stored procedure names cannot be parameterized. Use explicit string mapping from allowlist to procedure name. Never construct procedure names dynamically.<sup>5</sup>

---

### Snippet 60 Fix (Error-based blind injection)

```python
# Vulnerable (returns detailed SQL errors)
except sqlite3.Error as e:
	conn.close()
	return {"valid": False, "error": str(e)}

# Fixed (use generic error messages)
except sqlite3.Error as e:
	conn.close()
	# Log detailed error server-side only
	logger.error(f"License validation error: {e}")
	# Return generic message to client
	return {"valid": False, "error": "License validation failed"}
```

**Critical:** Even with parameterized queries, verbose error messages enable blind SQL injection by revealing query structure. Always return generic errors to clients; log details server-side.<sup>6</sup>

---

### Snippet 62 Fix (Batch update)

```python
# Vulnerable
query = f"UPDATE products SET price = %s WHERE id = {numeric_id}"
cursor.execute(query, (new_price,))

# Fixed (parameterize both values)
query = "UPDATE products SET price = %s WHERE id = %s"
cursor.execute(query, (new_price, numeric_id))
```

**Common Mistake:** Developers often validate input (`.isdigit()`) and assume this makes direct interpolation safe. Validation is insufficient — always parameterize. An attacker could manipulate the request to bypass validation logic before it reaches this function.<sup>2</sup>

---

</details>

---

## 🎓 Advanced Security Lessons from Round 6

### Second-Order SQL Injection (Snippet 54)
**Real-World Example:** The 2014 eBay data breach involved second-order SQL injection where attackers stored malicious payloads in user profiles, which were later executed when administrators viewed audit logs.<sup>7</sup>

**Defense:** Treat ALL data as untrusted, even data from your own database. Previous parameterization doesn't make data "safe" for future queries.

### Time-Based Blind SQL Injection (Snippet 56)
**Real-World Example:** In 2017, security researchers demonstrated time-based blind SQL injection in major telecom provider APIs, extracting entire customer databases using `SLEEP()` functions to map database structure.<sup>8</sup>

**Defense:** Parameterization prevents time-based attacks by ensuring user input can never be interpreted as SQL commands, even when validation appears sufficient.

### Error-Based Blind SQL Injection (Snippet 60)
**Real-World Example:** The 2013 Yahoo! data breach began with error-based SQL injection where attackers used verbose SQL error messages to map database schema before exfiltration.<sup>9</sup>

**Defense Strategy:**
1. ✅ Always parameterize queries
2. ✅ Return generic error messages to clients  
3. ✅ Log detailed errors server-side only
4. ✅ Implement rate limiting on error responses
5. ✅ Monitor for repeated error-triggering patterns

### Stored Procedures (Snippet 59)
**Critical Rule:** Stored procedure names are SQL identifiers and cannot be parameterized. Any dynamic construction of procedure names requires strict allowlist validation.

### PostgreSQL-Specific Patterns (Snippets 55, 58, 63)
PostgreSQL's advanced features (arrays, JSONB, CTEs) create unique injection vectors:
- **Arrays:** Use psycopg2's built-in array adaptation
- **JSONB operators:** `->`, `->>` keys must be allowlisted (cannot parameterize)
- **CTEs:** Table names must be allowlisted; only data values can be parameterized

---

## 📚 Extended References

**Primary Sources for Round 6:**

1. **Full Stack Python Security** by Dennis Byrne (Manning, 2021)
   - Chapter 13.7: "SQL Injection" (pp. 205-207)
   - Django `raw()` method parameterization
   - Database connection query safety
   - Error handling best practices

2. **API Security in Action** by Neil Madden (Manning, 2020)
   - Chapter 2.4: "Preventing Injection Attacks" (pp. 42-44)
   - Prepared statements vs string escaping
   - Second-order injection prevention
   - Input validation limitations

3. **Hacking APIs** by Corey Ball (No Starch Press, 2022)
   - Chapter 12: "Injection" (pp. 254-258)
   - Blind SQL injection techniques
   - Time-based and error-based attacks
   - NoSQL injection patterns
   - SQLmap exploitation methodology

4. **Secure by Design** by Johnsson, Deogun, Sawano (Manning, 2019)
   - Chapter 5: "Domain Primitives"
   - Validation vs parameterization trade-offs
   - Secure-by-default API design

5. **PortSwigger Web Security Academy**
   - SQL Injection Labs: Blind SQL injection module
   - Time delays and information retrieval
   - Out-of-band techniques
   - Filter bypass via XML encoding

**Additional Research:**

6. OWASP: "Blind SQL Injection" (https://owasp.org/www-community/attacks/Blind_SQL_Injection)
   - Time-based attack patterns
   - Error-based exploitation
   - Boolean-based techniques

7. CWE-89: "Improper Neutralization of Special Elements used in an SQL Command"
   - Common Weakness Enumeration database
   - Real-world vulnerability examples
   - Mitigation strategies

8. PostgreSQL Documentation: "Arrays" (https://www.postgresql.org/docs/current/arrays.html)
   - Array type handling in queries
   - Safe array parameter binding

9. Django Documentation: "Performing raw SQL queries" (https://docs.djangoproject.com/en/stable/topics/db/sql/)
   - Official guidance on `raw()` method
   - `connection.cursor()` parameterization

---

## 🎯 Final Mastery Check

If you scored 62-66 correctly (including fixes), you've mastered:

✅ **Second-order injection** — Understanding that database-stored data isn't inherently safe  
✅ **Blind SQL injection** — Time-based and error-based attack patterns  
✅ **Framework-specific patterns** — Django raw SQL, PostgreSQL arrays/JSONB  
✅ **Stored procedures** — Identifier parameterization limitations  
✅ **Defensive error handling** — Preventing information leakage  
✅ **Advanced SQL features** — CTEs, subqueries, XML/XPath contexts  

**You're ready for:**
- 🏢 Senior Security Engineer interviews
- 🔍 Production code review responsibilities  
- 🛡️ SAST/DAST tool customization
- 📝 Security architecture design documents
- 🎓 OSWE certification exam

---

## 🚀 What's Next?

### Continue Your Training

**Week 5-6:** Cross-Site Scripting (XSS) Fundamentals
- Reflected XSS pattern detection
- Stored XSS vulnerability analysis  
- DOM-based XSS in modern JavaScript
- Content Security Policy (CSP) implementation

**Week 7-8:** Authentication & Session Security
- JWT vulnerability patterns
- OAuth 2.0 misconfigurations
- Session fixation attacks
- CSRF token validation

**Week 11-24:** System Design for Security Interviews
- Designing secure authentication systems
- Rate limiting architectures
- API gateway security patterns
- Threat modeling with STRIDE methodology

### Join the Community

⭐ **Star the repo:** [github.com/fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)

**What's coming:**
- 🔐 100+ additional SQL injection exercises with real CVE patterns
- 🛡️ XSS exercise suite (reflected, stored, DOM-based)
- 🔑 Authentication security challenges (JWT, OAuth, SAML)
- 📡 API security exercises (rate limiting, IDOR, BOLA)
- 🧪 100+ test cases per exercise with detailed explanations
- 📝 Companion blog posts for every challenge

### Share Your Progress

Did you complete all 66 exercises? Share your score on:
- 🐦 Twitter: Tag [@fosres](https://twitter.com/fosres) with `#SQLInjectionMastery`
- 💼 LinkedIn: Share your completion badge
- 📝 Dev.to: Write about what you learned

---

*Building secure software one exercise at a time. Follow [@fosres](https://twitter.com/fosres) for weekly security challenges.*
