Snippet 15:

```
import psycopg2

def filter_products(column, value):
	conn = psycopg2.connect("dbname=store")
	cursor = conn.cursor()
	
	allowed_columns = ['category', 'brand', 'status']
	
	if column not in allowed_columns:
		return {"error": "Invalid filter column"}
	
	query = f"SELECT * FROM products WHERE {column} = %s"
	cursor.execute(query, (value,))
	
	results = cursor.fetchall()
	conn.close()
	return {"products": results}
```
Above snippet not vulnerable.

Snippet 16:

```
import sqlite3

def get_users_sorted(sort_dir):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	query = f"SELECT id, username, created_at FROM users ORDER BY created_at {sort_dir}"
	cursor.execute(query)
	
	users = cursor.fetchall()
	conn.close()
	return {"users": users}
```

Below line is vulnerable:


```
	query = f"SELECT id, username, created_at FROM users ORDER BY created_at {sort_dir}"

```

Below line is fix:

```
import sqlite3

def get_users_sorted(sort_dir):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()

	if sort_dir not in ['ASC','DESC']:
		
		print("Error: not safe to execute query")
		return
	else:	
		query = f"SELECT id, username, created_at FROM users ORDER BY created_at {sort_dir}"

		cursor.execute(query)
	
	users = cursor.fetchall()
	conn.close()
	return {"users": users}
```

Snippet 17:

```
import mysql.connector

def get_order(order_id):
	conn = mysql.connector.connect(host="localhost", database="shop")
	cursor = conn.cursor()
	
	try:
		order_id = int(order_id)
	except ValueError:
		return {"error": "Invalid order ID"}
	
	query = f"SELECT * FROM orders WHERE id = {order_id}"
	cursor.execute(query)
	
	order = cursor.fetchone()
	conn.close()
	return {"order": order}
```

The below lines are vulnerable:

```
	query = f"SELECT * FROM orders WHERE id = {order_id}"
	cursor.execute(query)
```

The below lines are the fix:

```
	query = f"SELECT * FROM orders WHERE id = ?"
	cursor.execute(query,(order_id,))
```

Snippet 18:

```
import psycopg2

def search_inventory(search_term, sort_columns: list):
	conn = psycopg2.connect("dbname=warehouse")
	cursor = conn.cursor()
	
	allowed_sorts = ['name', 'quantity', 'price', 'updated_at']
	
	safe_sorts = [col for col in sort_columns if col in allowed_sorts]
	if not safe_sorts:
		safe_sorts = ['name']
	
	sort_str = ', '.join(safe_sorts)
	
	query = f"SELECT * FROM inventory WHERE name ILIKE %s ORDER BY {sort_str}"
	cursor.execute(query, (f"%{search_term}%",))
	
	results = cursor.fetchall()
	conn.close()
	return {"items": results}
```

Above Snippet is not vulnerable.

Snippet 19:

```
import sqlite3

def get_posts(page, per_page):
	conn = sqlite3.connect('blog.db')
	cursor = conn.cursor()
	
	offset = (page - 1) * per_page
	
	query = f"SELECT * FROM posts ORDER BY created_at DESC LIMIT {per_page} OFFSET {offset}"
	cursor.execute(query)
	
	posts = cursor.fetchall()
	conn.close()
	return {"posts": posts}
```

Above snippet not vulnerable.

Snippet 20:

```
import psycopg2

def get_table_columns(table_name):
	conn = psycopg2.connect("dbname=app")
	cursor = conn.cursor()
	
	query = f"""
		SELECT column_name, data_type 
		FROM information_schema.columns 
		WHERE table_name = '{table_name}'
	"""
	cursor.execute(query)
	
	columns = cursor.fetchall()
	conn.close()
	return {"columns": columns}
```

The below line is vulnerable:

```
		WHERE table_name = '{table_name}'
	cursor.execute(query)
```

Below line is the fix:

```
		WHERE table_name = %s
	cursor.execute(query,(table_name,))
```

Snippet 21:

```
import mysql.connector

def get_sales_summary(group_by_col, year):
	conn = mysql.connector.connect(host="localhost", database="sales")
	cursor = conn.cursor()
	
	allowed_groups = ['product_id', 'category', 'region', 'salesperson']
	
	if group_by_col not in allowed_groups:
		group_by_col = 'category'
	
	if not isinstance(year, int) or year < 2000 or year > 2100:
		return {"error": "Invalid year"}
	
	query = f"""
		SELECT {group_by_col}, SUM(amount) as total
		FROM sales
		WHERE YEAR(sale_date) = {year}
		GROUP BY {group_by_col}
	"""
	cursor.execute(query)
	
	results = cursor.fetchall()
	conn.close()
	return {"summary": results}
```

Above snippet has no vulnerabilities.

Snippet 22:

```
import sqlite3

def update_preference(user_id, pref_key, pref_value):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	allowed_prefs = ['theme', 'language', 'timezone', 'notifications']
	
	if pref_key not in allowed_prefs:
		return {"error": "Invalid preference"}
	
	query = f"UPDATE user_preferences SET {pref_key} = ? WHERE user_id = ?"
	cursor.execute(query, (pref_value, user_id))
	
	conn.commit()
	conn.close()
	return {"success": True}
```

Above snippet not vulnerable.

Snippet 23:

```
import psycopg2

def search_logs(start_date, end_date, log_level):
	conn = psycopg2.connect("dbname=logging")
	cursor = conn.cursor()
	
	query = """
		SELECT timestamp, level, message 
		FROM logs 
		WHERE timestamp >= %s 
		AND timestamp <= %s
		AND level = '""" + log_level + "' ORDER BY timestamp DESC"
	
	cursor.execute(query, (start_date, end_date))
	
	logs = cursor.fetchall()
	conn.close()
	return {"logs": logs}
```

Below lines vulnerable:

```
		AND level = '""" + log_leve+ "' ORDER BY timestamp DESC"
	
	cursor.execute(query, (start_date, end_date))
```

Should be replaced with:


```
		AND level = %s ORDER BY timestamp DESC"
	
	cursor.execute(query, (start_date, end_date,log_level))
```

Snippet 24:

```
import sqlite3

def get_users_by_role(roles: list):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	allowed_roles = ['admin', 'editor', 'viewer', 'guest']
	safe_roles = [r for r in roles if r in allowed_roles]
	
	if not safe_roles:
		return {"error": "No valid roles provided"}
	
	placeholders = ','.join(['?'] * len(safe_roles))
	query = f"SELECT id, username, role FROM users WHERE role IN ({placeholders})"
	cursor.execute(query, tuple(safe_roles))
	
	users = cursor.fetchall()
	conn.close()
	return {"users": users}
```

Above snippet not vulnerable.

Snippet 25:

```
import mysql.connector

def export_users(include_email, include_phone):
	conn = mysql.connector.connect(host="localhost", database="app")
	cursor = conn.cursor()
	
	columns = ['id', 'username']
	
	if include_email:
		columns.append('email')
	if include_phone:
		columns.append('phone')
	
	column_str = ', '.join(columns)
	query = f"SELECT {column_str} FROM users"
	cursor.execute(query)
	
	users = cursor.fetchall()
	conn.close()
	return {"users": users}
```

Above snippet not vulnerable.

Snippet 26:

```
import psycopg2

def get_active_items(category, is_active):
	conn = psycopg2.connect("dbname=inventory")
	cursor = conn.cursor()
	
	if not isinstance(is_active, bool):
		return {"error": "is_active must be boolean"}
	
	query = f"SELECT * FROM items WHERE category = %s AND active = {is_active}"
	cursor.execute(query, (category,))
	
	items = cursor.fetchall()
	conn.close()
	return {"items": items}
```

Above snippet is not vulnerable.
