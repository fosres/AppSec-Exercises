Snippet 39:

```
import sqlite3
import re

def get_session(session_id):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	uuid_pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
	
	if not re.match(uuid_pattern, session_id):
		return {"error": "Invalid session ID"}
	
	query = f"SELECT * FROM sessions WHERE id = '{session_id}'"
	cursor.execute(query)
	
	session = cursor.fetchone()
	conn.close()
	return {"session": session}
```

Above snippet not vulnerable.

Snippet 40:

```
import psycopg2

def search_by_tag(tag_name):
	conn = psycopg2.connect("dbname=content")
	cursor = conn.cursor()
	
	query = f"SELECT * FROM articles WHERE metadata->>'tags' ILIKE '%{tag_name}%'"
	cursor.execute(query)
	
	results = cursor.fetchall()
	conn.close()
	return {"articles": results}
```

Below lines vulnerable:

```
	query = f"SELECT * FROM articles WHERE metadata->>'tags' ILIKE '%{tag_name}%'"
	cursor.execute(query)
```

Below is the code fix:

```
	query = f"SELECT * FROM articles WHERE metadata->>'tags' ILIKE %s"
	cursor.execute(query, (f"%{tag_name}%",))
```
Snippet 43:

```
import sqlite3

def get_user_display_name(user_id, default_name):
	conn = sqlite3.connect('app.db')
	cursor = conn.cursor()
	
	query = f"SELECT COALESCE(display_name, '{default_name}') FROM users WHERE id = ?"
	cursor.execute(query, (user_id,))
	
	result = cursor.fetchone()
	conn.close()
	return {"display_name": result[0] if result else None}
```

Below lines vulnerable:

```
	query = f"SELECT COALESCE(display_name, '{default_name}') FROM users WHERE id = ?"
	cursor.execute(query, (user_id,))
```

Below code is the fix:

```
	query = f"SELECT COALESCE(display_name, ?) FROM users WHERE id = ?"
	cursor.execute(query, (default_name,user_id))
```

Snippet 45:

```
import mysql.connector

def search_by_year(year_input):
	conn = mysql.connector.connect(host="localhost", database="archive")
	cursor = conn.cursor()
	
	query = f"SELECT * FROM documents WHERE CAST(created_year AS CHAR) = '{year_input}'"
	cursor.execute(query)
	
	results = cursor.fetchall()
	conn.close()
	return {"documents": results}
```

Below lines vulnerable:

```
	query = f"SELECT * FROM documents WHERE CAST(created_year AS CHAR) = '{year_input}'"
	cursor.execute(query)
```

Below lines are the fix:

```
	query = f"SELECT * FROM documents WHERE CAST(created_year AS CHAR) = %s"

	cursor.execute(query,(year_input,))
```


