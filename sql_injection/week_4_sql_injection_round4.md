Snippet 27:

```
import psycopg2

def advanced_search(filters: dict):
	"""
	filters: {"name": "widget", "min_price": 10, "max_price": 100}
	"""
	conn = psycopg2.connect("dbname=store")
	cursor = conn.cursor()
	
	allowed_filters = ['name', 'min_price', 'max_price', 'category', 'brand']
	
	where_clauses = []
	values = []
	
	for key, val in filters.items():
		if key not in allowed_filters:
			continue
		if key == 'name':
			where_clauses.append("name ILIKE %s")
			values.append(f"%{val}%")
		elif key == 'min_price':
			where_clauses.append("price >= %s")
			values.append(val)
		elif key == 'max_price':
			where_clauses.append("price <= %s")
			values.append(val)
		elif key in ('category', 'brand'):
			where_clauses.append(f"{key} = %s")
			values.append(val)
	
	query = "SELECT * FROM products"
	if where_clauses:
		query += " WHERE " + " AND ".join(where_clauses)
	
	cursor.execute(query, tuple(values))
	results = cursor.fetchall()
	conn.close()
	return {"products": results}
```

Above snippet not vulnerable.

Snippet 28:

```
import sqlite3
import json

def search_metadata(field_name, field_value):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	query = f"SELECT * FROM documents WHERE json_extract(metadata, '$.{field_name}') = ?"
	cursor.execute(query, (field_value,))
	
	results = cursor.fetchall()
	conn.close()
	return {"documents": results}
```

Above snippet not vulnerable.

Snippet 29:

```
import mysql.connector

def update_order_status(order_ids: list, new_status):
	conn = mysql.connector.connect(host="localhost", database="shop")
	cursor = conn.cursor()
	
	allowed_statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled']
	
	if new_status not in allowed_statuses:
		return {"error": "Invalid status"}
	
	if not all(isinstance(oid, int) for oid in order_ids):
		return {"error": "Invalid order IDs"}
	
	placeholders = ','.join(['%s'] * len(order_ids))
	query = f"UPDATE orders SET status = %s WHERE id IN ({placeholders})"
	cursor.execute(query, (new_status, *order_ids))
	
	conn.commit()
	conn.close()
	return {"updated": cursor.rowcount}
```

Above snippet not vulnerable.

Snippet 30:

```
import psycopg2

def get_report(value_column, label):
	conn = psycopg2.connect("dbname=reports")
	cursor = conn.cursor()
	
	allowed_columns = ['revenue', 'expenses', 'profit', 'units_sold']
	
	if value_column not in allowed_columns:
		return {"error": "Invalid column"}
	
	query = f"SELECT date, {value_column} AS {label} FROM monthly_reports ORDER BY date"
	cursor.execute(query)
	
	results = cursor.fetchall()
	conn.close()
	return {"report": results}
```

The below lines vulnerable:

```
	query = f"SELECT date, {value_column} AS {label} FROM monthly_reports ORDER BY date"
	cursor.execute(query)
```

And should be replaced with:

```
	query = f"SELECT date, {value_column} AS %s FROM monthly_reports ORDER BY date"
	cursor.execute(query,(label,))
```

Snippet 31:

```
from sqlalchemy import create_engine, text

def find_user_by_field(field, value):
	engine = create_engine('postgresql://localhost/app')
	
	allowed_fields = ['username', 'email', 'phone']
	
	if field not in allowed_fields:
		return {"error": "Invalid field"}
	
	with engine.connect() as conn:
		query = text(f"SELECT * FROM users WHERE {field} = :value")
		result = conn.execute(query, {"value": value})
		user = result.fetchone()
	
	return {"user": user}
```

Above snippet not vulnerable.

Snippet 32:

```
import sqlite3
import re

def get_events(start_date, end_date):
	conn = sqlite3.connect('events.db')
	cursor = conn.cursor()
	
	date_pattern = r'^\d{4}-\d{2}-\d{2}$'
	
	if not re.match(date_pattern, start_date) or not re.match(date_pattern, end_date):
		return {"error": "Invalid date format. Use YYYY-MM-DD"}
	
	query = f"SELECT * FROM events WHERE event_date BETWEEN '{start_date}' AND '{end_date}'"
	cursor.execute(query)
	
	events = cursor.fetchall()
	conn.close()
	return {"events": events}
```

Above snippet not vulnerable.

Snippet 33:

```
import psycopg2

def get_top_customers(min_orders):
	conn = psycopg2.connect("dbname=shop")
	cursor = conn.cursor()
	
	try:
		min_orders = int(min_orders)
	except (ValueError, TypeError):
		return {"error": "Invalid minimum orders value"}
	
	query = """
		SELECT c.id, c.name, c.email
		FROM customers c
		WHERE (SELECT COUNT(*) FROM orders o WHERE o.customer_id = c.id) >= %s
	"""
	cursor.execute(query, (min_orders,))
	
	customers = cursor.fetchall()
	conn.close()
	return {"customers": customers}
```

Above snippet not vulnerable.

Snippet 34:

```
import mysql.connector

def search_products(search_term, match_type):
	conn = mysql.connector.connect(host="localhost", database="store")
	cursor = conn.cursor()
	
	if match_type == 'starts_with':
		pattern = f"{search_term}%"
	elif match_type == 'ends_with':
		pattern = f"%{search_term}"
	elif match_type == 'contains':
		pattern = f"%{search_term}%"
	else:
		pattern = search_term
	
	query = "SELECT * FROM products WHERE name LIKE %s"
	cursor.execute(query, (pattern,))
	
	results = cursor.fetchall()
	conn.close()
	return {"products": results}
```

Above snippet not vulnerable.

Snippet 35:

```
from django.contrib.auth.models import User

def search_users(search_term, order_by):
	allowed_ordering = ['username', 'email', 'date_joined', '-username', '-email', '-date_joined']
	
	if order_by not in allowed_ordering:
		order_by = 'username'
	
	users = User.objects.filter(
		username__icontains=search_term
	).order_by(order_by)
	
	return list(users.values('id', 'username', 'email'))
```

Above snippet not vulnerable.

Snippet 36:

```
import sqlite3

def get_order_details(order_id, include_customer):
	conn = sqlite3.connect('shop.db')
	cursor = conn.cursor()
	
	if include_customer:
		query = """
			SELECT o.*, c.name, c.email 
			FROM orders o 
			JOIN customers c ON o.customer_id = c.id 
			WHERE o.id = ?
		"""
	else:
		query = "SELECT * FROM orders WHERE id = ?"
	
	cursor.execute(query, (order_id,))
	
	order = cursor.fetchone()
	conn.close()
	return {"order": order}
```

Above snippet not vulnerable.

Snippet 37:

```
import psycopg2
import re

def get_column_stats(column_name):
	conn = psycopg2.connect("dbname=analytics")
	cursor = conn.cursor()
	
	if not re.match(r'^[a-z_]+$', column_name):
		return {"error": "Invalid column name"}
	
	query = f"SELECT MIN({column_name}), MAX({column_name}), AVG({column_name}) FROM metrics"
	cursor.execute(query)
	
	stats = cursor.fetchone()
	conn.close()
	return {"min": stats[0], "max": stats[1], "avg": stats[2]}
```

Above snippet not vulnerable.

Snippet 38:

```
import psycopg2

def get_paginated_items(cursor_id, limit, direction):
	conn = psycopg2.connect("dbname=app")
	cursor = conn.cursor()
	
	if not isinstance(cursor_id, int):
		cursor_id = 0
	
	if not isinstance(limit, int) or limit < 1 or limit > 100:
		limit = 20
	
	if direction == 'next':
		operator = '>'
		order = 'ASC'
	elif direction == 'prev':
		operator = '<'
		order = 'DESC'
	else:
		return {"error": "Invalid direction"}
	
	query = f"SELECT * FROM items WHERE id {operator} %s ORDER BY id {order} LIMIT %s"
	cursor.execute(query, (cursor_id, limit))
	
	items = cursor.fetchall()
	conn.close()
	return {"items": items}
```

Above snippet not vulnerable.
