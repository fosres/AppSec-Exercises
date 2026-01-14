Snippet 53:

```
import psycopg2

def get_archived_data(archive_table, start_date):
	"""
	archive_table: one of the archived data tables
	Valid tables: 'archive_2023', 'archive_2024', 'archive_2025', 'archive_logs'
	"""
	conn = psycopg2.connect("dbname=warehouse")
	cursor = conn.cursor()
	
	query = f"SELECT * FROM {archive_table} WHERE archived_at > '{start_date}'"
	cursor.execute(query)
	
	results = cursor.fetchall()
	conn.close()
	return {"data": results}
```

Below lines vulnerable:

```
	query = f"SELECT * FROM {archive_table} WHERE archived_at > '{start_date}'"
	cursor.execute(query)
```

Below is the fix:

```
import psycopg2

def get_archived_data(archive_table, start_date):
	"""
	archive_table: one of the archived data tables
	Valid tables: 'archive_2023', 'archive_2024', 'archive_2025', 'archive_logs'
	"""

	if archive_table not in ['archive_2023','archive_2024','archive_2025', 'archive_logs']:
		print("Error: archive_table not valid table_name")
		
		return

	conn = psycopg2.connect("dbname=warehouse")

	cursor = conn.cursor()
	
	query = f"SELECT * FROM {archive_table} WHERE archived_at > %s"

	cursor.execute(query,(start_date,))
	
	results = cursor.fetchall()
	conn.close()
	return {"data": results}
```

Snippet 54:

```
import sqlite3

def get_users(columns: list, max_results):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	allowed_columns = ['id', 'username', 'email', 'created_at']
	safe_columns = [c for c in columns if c in allowed_columns]
	
	if not safe_columns:
		safe_columns = ['id', 'username']
	
	col_str = ', '.join(safe_columns)
	query = f"SELECT {col_str} FROM users LIMIT {max_results}"
	cursor.execute(query)
	
	users = cursor.fetchall()
	conn.close()
	return {"users": users}
```

Below lines vulnerable:

```
	query = f"SELECT {col_str} FROM users LIMIT {max_results}"
	cursor.execute(query)
```

Below lines are the fix:

```
	query = f"SELECT {col_str} FROM users LIMIT ?"
	cursor.execute(query,(max_results,))
```

Snippet 56:

```
import psycopg2

def get_sales_by_region(min_total, group_column):
	"""
	group_column: column to group sales by
	Valid columns: 'region', 'category', 'salesperson', 'quarter'
	"""
	conn = psycopg2.connect("dbname=sales")
	cursor = conn.cursor()
	
	query = f"""
		SELECT {group_column}, SUM(amount) as total
		FROM sales
		GROUP BY {group_column}
		HAVING SUM(amount) >= {min_total}
	"""
	cursor.execute(query)
	
	results = cursor.fetchall()
	conn.close()
	return {"sales": results}
```

Below lines vulnerable:

```
	query = f"""
		SELECT {group_column}, SUM(amount) as total
		FROM sales
		GROUP BY {group_column}
		HAVING SUM(amount) >= {min_total}
	"""
	cursor.execute(query)
```

Below is the fix:

```
import psycopg2

def get_sales_by_region(min_total, group_column):
	"""
	group_column: column to group sales by
	Valid columns: 'region', 'category', 'salesperson', 'quarter'
	"""
	conn = psycopg2.connect("dbname=sales")
	cursor = conn.cursor()

	if group_column not in ['region', 'category','salesperson','quarter']:
		print("Error: group_column invalid")
		return
	
	query = f"""
		SELECT {group_column}, SUM(amount) as total
		FROM sales
		GROUP BY {group_column}
		HAVING SUM(amount) >= %s 
	"""
	cursor.execute(query,(min_total,))
	results = cursor.fetchall()
	conn.close()
	return {"sales": results}
```

Snippet 58:

```
import sqlite3

def get_users_with_status_label(status_mapping: dict):
	"""
	status_mapping: {0: 'Inactive', 1: 'Active', 2: 'Pending'}
	"""
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	case_parts = []
	for code, label in status_mapping.items():
		if isinstance(code, int):
			case_parts.append(f"WHEN status = {code} THEN '{label}'")
	
	case_expr = "CASE " + " ".join(case_parts) + " ELSE 'Unknown' END"
	
	query = f"SELECT id, username, {case_expr} as status_label FROM users"
	cursor.execute(query)
	
	users = cursor.fetchall()
	conn.close()
	return {"users": users}
```

Below lines vulnerable:

```
			case_parts.append(f"WHEN status = {code} THEN '{label}'")
```

Below lines are the fix:

```
import sqlite3

def get_users_with_status_label(status_mapping: dict):
	"""
	status_mapping: {0: 'Inactive', 1: 'Active', 2: 'Pending'}
	"""
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	case_parts = []
	labels = []
	for code, label in status_mapping.items():
		if isinstance(code, int):
			case_parts.append(f"WHEN status = {code} THEN ?")
		
			labels.append(label)
	
	case_expr = "CASE " + " ".join(case_parts) + " ELSE 'Unknown' END"
	
	query = f"SELECT id, username, {case_expr} as status_label FROM users"
	cursor.execute(query,(tuple(labels))
	
	users = cursor.fetchall()
	conn.close()
	return {"users": users}
```

Snippet 59:

```
import psycopg2

def get_top_customers(subquery_alias, min_orders):
	"""
	subquery_alias: alias name for the subquery
	Valid aliases: 'customer_orders', 'order_summary', 'order_counts'
	"""
	conn = psycopg2.connect("dbname=shop")
	cursor = conn.cursor()
	
	try:
		min_orders = int(min_orders)
	except (ValueError, TypeError):
		return {"error": "Invalid min_orders"}
	
	query = f"""
		SELECT * FROM (
			SELECT customer_id, COUNT(*) as order_count
			FROM orders
			GROUP BY customer_id
		) AS {subquery_alias}
		WHERE order_count >= %s
	"""
	cursor.execute(query, (min_orders,))
	
	results = cursor.fetchall()
	conn.close()
	return {"customers": results}
```

Below lines vulnerable:

```
	query = f"""
		SELECT * FROM (
			SELECT customer_id, COUNT(*) as order_count
			FROM orders
			GROUP BY customer_id
		) AS {subquery_alias}
		WHERE order_count >= %s
	"""

```

Below is the fix:

```
import psycopg2

def get_top_customers(subquery_alias, min_orders):
	"""
	subquery_alias: alias name for the subquery
	Valid aliases: 'customer_orders', 'order_summary', 'order_counts'
	"""
	conn = psycopg2.connect("dbname=shop")
	cursor = conn.cursor()
	
	try:
		min_orders = int(min_orders)
	except (ValueError, TypeError):
		return {"error": "Invalid min_orders"}

	if subquery_alias not in ['customer_orders','order_summary','order_counts']:
		
		print("Error: subquery_alias not allowed")
		return
	
	query = f"""
		SELECT * FROM (
			SELECT customer_id, COUNT(*) as order_count
			FROM orders
			GROUP BY customer_id
		) AS {subquery_alias}
		WHERE order_count >= %s
	"""
	cursor.execute(query, (min_orders,))
	
	results = cursor.fetchall()
	conn.close()
	return {"customers": results}

```

Snippet 61:

```
import psycopg2

def get_user_tags(user_id, separator):
	"""
	separator: delimiter for combining tags
	Valid separators: ', ', ' | ', ' - ', '; '
	"""
	conn = psycopg2.connect("dbname=app")
	cursor = conn.cursor()
	
	query = f"""
		SELECT STRING_AGG(tag_name, '{separator}')
		FROM user_tags
		WHERE user_id = %s
	"""
	cursor.execute(query, (user_id,))
	
	result = cursor.fetchone()
	conn.close()
	return {"tags": result[0] if result else None}
```

Below lines vulnerable:

```
	query = f"""
		SELECT STRING_AGG(tag_name, '{separator}')
		FROM user_tags
		WHERE user_id = %s
	"""
```

Below is the fix:

```
import psycopg2

def get_user_tags(user_id, separator):
	"""
	separator: delimiter for combining tags
	Valid separators: ', ', ' | ', ' - ', '; '
	"""
	conn = psycopg2.connect("dbname=app")
	cursor = conn.cursor()

	if separator not in [', ', ' | ', ' - ', '; ']:
		print("Error: separator not valid")
		return
	
	query = f"""
		SELECT STRING_AGG(tag_name, '{separator}')
		FROM user_tags
		WHERE user_id = %s
	"""
	cursor.execute(query, (user_id,))
	
	result = cursor.fetchone()
	conn.close()
	return {"tags": result[0] if result else None}
```

Snippet 63:

```
import psycopg2

def get_latest_per_category(category_column, sort_column):
	"""
	category_column: column to get distinct values from
	Valid category columns: 'brand', 'category', 'supplier'
	
	sort_column: column to determine which row to keep
	Valid sort columns: 'created_at', 'updated_at', 'price'
	"""
	conn = psycopg2.connect("dbname=products")
	cursor = conn.cursor()
	
	query = f"""
		SELECT DISTINCT ON ({category_column}) *
		FROM products
		ORDER BY {category_column}, {sort_column} DESC
	"""
	cursor.execute(query)
	
	results = cursor.fetchall()
	conn.close()
	return {"products": results}
```

Below lines vulnerable:

```
	query = f"""
		SELECT DISTINCT ON ({category_column}) *
		FROM products
		ORDER BY {category_column}, {sort_column} DESC
	"""
```

Below is the fix:

```
import psycopg2

def get_latest_per_category(category_column, sort_column):
	"""
	category_column: column to get distinct values from
	Valid category columns: 'brand', 'category', 'supplier'
	
	sort_column: column to determine which row to keep
	Valid sort columns: 'created_at', 'updated_at', 'price'
	"""

	if category_column not in ['brand', 'category', 'supplier']:

		print("Error: category_column invalid")

		return

	if sort_column not in ['created_at', 'updated_at', 'price']:
		
		print("Error: sort_column invalid")
		
		return
		
	conn = psycopg2.connect("dbname=products")
	cursor = conn.cursor()
	
	query = f"""
		SELECT DISTINCT ON ({category_column}) *
		FROM products
		ORDER BY {category_column}, {sort_column} DESC
	"""
	cursor.execute(query)
	
	results = cursor.fetchall()
	conn.close()
	return {"products": results}
```
