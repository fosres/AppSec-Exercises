"""
SQL Injection Vulnerability Pattern Recognition
================================================

Exercise inspired by:
- Python Workout (2nd Edition) by Reuven M. Lerner
  * Chapter 1-2 "Numeric Types" (pages 3-46) - Pattern recognition and scoring
- Hacking APIs by Corey J. Ball
  * Chapter 12 "Injection" (pages 253-261) - SQL injection vulnerability patterns
- API Security in Action by Neil Madden
  * Chapter 4 "Securing APIs" (pages 93-132) - Parameterized queries

INSTRUCTIONS:
=============
Review each code snippet below and determine if it is VULNERABLE or SAFE.

VULNERABLE = Code can be exploited via SQL injection
SAFE = Code properly prevents SQL injection

Mark each snippet as either VULNERABLE or SAFE, then check your answers
at the bottom of this file.

HINTS:
- Look for string concatenation with user input in SQL queries
- Parameterized queries use placeholders (?, %s) with separate parameters
- ORMs typically provide safe parameter binding
- Comments/documentation containing SQL examples are safe
"""


# ============================================================================
# CODE SNIPPETS TO REVIEW
# ============================================================================

# Snippet 1
cursor.execute("DELETE FROM posts WHERE author=%s", (username,))

# Snippet 2
db.query(f"SELECT * FROM users WHERE role IN ('{role1}', '{role2}')")

# Snippet 3
sql = f"SELECT * FROM {table} WHERE status='active'"

# Snippet 4
sql = "SELECT * FROM posts WHERE published=1 AND author_id=" + str(author_id)

# Snippet 5
sql = "UPDATE users SET role='{}' WHERE id={}".format(role, user_id)

# Snippet 6
cursor.execute("SELECT * FROM config WHERE key='database_version'")

# Snippet 7
User.objects.filter(username=username)

# Snippet 8
connection.query("SELECT * FROM users WHERE username='" + req.body.username + "'");

# Snippet 9
db.query("SELECT * FROM orders WHERE customer_id=?", [custId]);

# Snippet 10
const query = `INSERT INTO logs (action, user) VALUES ('${action}', '${userId}')`;

# Snippet 11
cursor.execute("INSERT INTO logs VALUES (?, ?)", (message, timestamp))

# Snippet 12
query = "SELECT * FROM posts WHERE id=%s" % post_id

# Snippet 13
const sql = "DELETE FROM comments WHERE id=" + commentId;

# Snippet 14
$query = "SELECT * FROM users WHERE email='" . $_GET['email'] . "'";

# Snippet 15
Product.objects.filter(name__icontains=search_term)

# Snippet 16
query = "SELECT * FROM items WHERE category=%s AND price < %s"
cursor.execute(query, (category, max_price))

# Snippet 17
query = f"DROP TABLE {table_name}"

# Snippet 18
cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))

# Snippet 19
cursor.execute("SELECT COUNT(*) FROM users")

# Snippet 20
query = "SELECT * FROM users WHERE id=" + user_id
cursor.execute(query)

# Snippet 21
User.query.filter_by(username=username, password=password).first()

# Snippet 22
db.query("SELECT * FROM products WHERE id=" + product_id + " AND active=1")

# Snippet 23
connection.query("SELECT * FROM users WHERE username=?", [req.body.username]);

# Snippet 24
cursor.execute("SELECT * FROM posts WHERE id=%s", (post_id,))

# Snippet 25
cursor.execute("UPDATE users SET last_login=NOW() WHERE id=?", (user_id,))

# Snippet 26
# Example SQL injection: query = "SELECT * FROM users WHERE id=" + user_id

# Snippet 27
db.query("UPDATE users SET role=%s WHERE id=%s", (role, user_id))

# Snippet 28
connection.execute(`UPDATE users SET verified=1 WHERE email='${email}'`);

# Snippet 29
$query = "INSERT INTO comments (post_id, content) VALUES (" . $post_id . ", '" . $content . "')";

# Snippet 30
db.query("INSERT INTO logs (action, user) VALUES (?, ?)", [action, userId]);

# Snippet 31
# TODO: Fix SQL injection vulnerability in login query

# Snippet 32
Post.objects.filter(published=True, author_id=author_id)

# Snippet 33
$stmt = $mysqli->prepare("UPDATE products SET price=? WHERE id=?");

# Snippet 34
$stmt = $conn->prepare("DELETE FROM sessions WHERE user_id=? AND expired < NOW()");

# Snippet 35
db.execute(f"SELECT * FROM users WHERE email='{email}' AND verified=1")

# Snippet 36
Comment.objects.create(post_id=post_id, content=content)

# Snippet 37
connection.execute("UPDATE users SET verified=1 WHERE email=?", [email]);

# Snippet 38
query = "SELECT * FROM items WHERE name='" + item_name + "'"

# Snippet 39
$stmt = $pdo->prepare("SELECT * FROM users WHERE email=?"); $stmt->execute([$email]);

# Snippet 40
"""Documentation: Use query = "SELECT * FROM users WHERE id=" + user_id"""

# Snippet 41
const query = `SELECT * FROM orders WHERE customer_id=${custId}`;

# Snippet 42
db.session.query(User).filter_by(email=email).first()

# Snippet 43
query = "DELETE FROM " + table_name + " WHERE id=" + record_id

# Snippet 44
$sql = "UPDATE products SET price=" . $price . " WHERE id=" . $product_id;

# Snippet 45
$query = "SELECT * FROM orders WHERE status='" . $status . "' AND customer_id=" . $cust_id;

# Snippet 46
sql = "UPDATE users SET last_login=NOW() WHERE id=" + user_id

# Snippet 47
query = "SELECT * FROM users WHERE username='{0}' AND password='{1}'".format(username, password)

# Snippet 48
sql = f"SELECT * FROM posts WHERE author='{username}'"

# Snippet 49
sql = "INSERT INTO logs VALUES ('%s', %d)" % (message, timestamp)

# Snippet 50
session.query(Order).filter(Order.status == status, Order.customer_id == cust_id).all()

# ============================================================================
# ANSWER KEY
# ============================================================================
"""
ANSWERS:
========

Snippet  1: SAFE        - Parameterized query
Snippet  2: VULNERABLE  - f-string
Snippet  3: VULNERABLE  - f-string table name
Snippet  4: VULNERABLE  - String concatenation
Snippet  5: VULNERABLE  - .format()
Snippet  6: SAFE        - Hardcoded query
Snippet  7: SAFE        - Django ORM
Snippet  8: VULNERABLE  - Node.js concatenation
Snippet  9: SAFE        - Node.js parameterized
Snippet 10: VULNERABLE  - Template literal
Snippet 11: SAFE        - Parameterized query
Snippet 12: VULNERABLE  - % formatting
Snippet 13: VULNERABLE  - Node.js concatenation
Snippet 14: VULNERABLE  - PHP concatenation
Snippet 15: SAFE        - Django ORM
Snippet 16: SAFE        - Parameterized query
Snippet 17: VULNERABLE  - f-string
Snippet 18: SAFE        - Parameterized query
Snippet 19: SAFE        - Hardcoded query
Snippet 20: VULNERABLE  - String concatenation
Snippet 21: SAFE        - Flask-SQLAlchemy ORM
Snippet 22: VULNERABLE  - String concatenation
Snippet 23: SAFE        - Node.js parameterized
Snippet 24: SAFE        - Parameterized query
Snippet 25: SAFE        - Parameterized query
Snippet 26: SAFE        - Comment
Snippet 27: SAFE        - Parameterized query
Snippet 28: VULNERABLE  - Template literal
Snippet 29: VULNERABLE  - PHP concatenation
Snippet 30: SAFE        - Node.js parameterized
Snippet 31: SAFE        - Comment/TODO
Snippet 32: SAFE        - Django ORM
Snippet 33: SAFE        - PHP prepared statement
Snippet 34: SAFE        - PHP prepared statement
Snippet 35: VULNERABLE  - f-string
Snippet 36: SAFE        - Django ORM
Snippet 37: SAFE        - Node.js parameterized
Snippet 38: VULNERABLE  - String concatenation
Snippet 39: SAFE        - PHP prepared statement
Snippet 40: SAFE        - Documentation string
Snippet 41: VULNERABLE  - Template literal
Snippet 42: SAFE        - SQLAlchemy ORM
Snippet 43: VULNERABLE  - String concatenation
Snippet 44: VULNERABLE  - PHP concatenation
Snippet 45: VULNERABLE  - PHP concatenation
Snippet 46: VULNERABLE  - String concatenation
Snippet 47: VULNERABLE  - .format()
Snippet 48: VULNERABLE  - f-string
Snippet 49: VULNERABLE  - % formatting
Snippet 50: SAFE        - SQLAlchemy ORM


VULNERABILITY PATTERNS TO REMEMBER:
====================================
VULNERABLE:
- String concatenation: +, ., ||
- Python f-strings: f"...{variable}..."
- Python .format(): "...{}...".format(variable)
- Python % formatting: "...%s..." % variable
- JavaScript template literals: `...${variable}...`
- PHP string concatenation: "..." . $variable

SAFE:
- Parameterized queries: ?, %s with separate parameter tuple/list
- Prepared statements: prepare() + execute() with bound parameters
- ORM methods: Django/SQLAlchemy/Flask filter/filter_by methods
- Hardcoded queries: No user input involved
- Comments/documentation: Not executable code


KEY TAKEAWAY:
=============
User input should NEVER be directly concatenated into SQL queries.
Always use parameterized queries or ORM methods that properly escape/bind parameters.
"""
