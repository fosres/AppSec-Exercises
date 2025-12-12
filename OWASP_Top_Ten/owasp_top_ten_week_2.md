# 51 Questions That Will Prepare You For Your AppSec Phone Interview

The following questions prepare you for the AppSec Engineer phone

interview--where you are tested on your conceptual mastery of

AppSec Engineering concepts.

Recruiters and hiring managers typically ask questions like:
- "How do prepared statements prevent SQL injection?"
- "What's the difference between authentication and authorization?"
- "When should you use hashing versus encryption?"
- "What is IDOR and how would you prevent it?"

**They're testing if you understand security fundamentals at a deep level** - not whether you can implement a binary search tree.

This quiz contains **51 real interview-style questions** based on the **OWASP Top 10 2025** that will prepare you for exactly these conversations. These aren't trivia questions - they're the security concepts that separate candidates who've studied from those who truly understand AppSec principles.

## How This Quiz Prepares You for Phone Interviews

**Phone screen interviews (30-45 minutes) typically follow this pattern:**

1. **Behavioral intro** (5 min): "Tell me about your security background"
2. **Conceptual deep-dive** (20-30 min): Questions about OWASP Top 10, secure coding, defense patterns
3. **Scenario discussion** (10 min): "How would you secure this endpoint?"
4. **Questions for them** (5 min): Your turn to ask

**This quiz focuses on Part 2** - the conceptual deep-dive that makes or breaks your phone screen.

### What Makes These Questions Realistic?

✅ **Multi-part format** - Just like real interviews where they ask follow-ups  
✅ **"Explain why" emphasis** - Interviewers want to see your reasoning, not just answers  
✅ **Cross-category thinking** - Real code has multiple vulnerabilities simultaneously  
✅ **Defense-in-depth focus** - Understanding primary vs. secondary defenses  
✅ **Practical scenarios** - Code review situations you'll encounter on the job

### How to Use This Quiz

1. **First pass:** Answer all questions in one category (don't peek at answers!)
2. **Check answers:** Review explanations at the bottom
3. **Second pass:** Retry questions you missed after 24-48 hours
4. **Practice explaining:** Say your answers out loud as if in an interview

**Target: 80%+ correct answers = you're ready for phone screens**

---

## 📚 Want More Security Practice?

This quiz is part of a larger collection of **LeetCode-style AppSec exercises** designed to help you master secure coding fundamentals. If you found this helpful:

⭐ **Star the repo:** [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)  
📖 **More quizzes and challenges coming soon**

The repository includes:
- Security code review exercises
- Vulnerable code challenges with test suites
- Interview preparation materials
- Real-world exploitation scenarios

---

# The Questions

## Category 1: SQL Injection Fundamentals

### Question 1: SQL Injection - Subverting Application Logic

You're testing a login form that uses this vulnerable code:

```python
username = request.form.get('username')
password = request.form.get('password')

query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
result = db.execute(query)

if result:
	login_success()
else:
	login_failed()
```

What SQL injection payload could you enter in the `username` field to bypass authentication and log in without knowing any valid password? Explain how your payload works.

---

### Question 2: Defense in Depth for SQL Injection

The OWASP SQL Injection Prevention Cheat Sheet describes multiple "Defense Options" that can be layered together.

You've already implemented Defense Option 1 (Prepared Statements) in your application:

```python
query = "SELECT * FROM products WHERE category = ?"
results = db.execute(query, (user_category,))
```

Your security lead asks you to add Defense Option 2 as a secondary layer. What is Defense Option 2, and provide a concrete code example of how you would implement it for the `user_category` input in this query?

---

### Question 3: SQL Injection - Retrieving Hidden Data

You're testing an e-commerce site that has a product filtering feature. The URL looks like this:

```
https://shop.example.com/products?category=electronics&show=available
```

The backend code (vulnerable):
```python
category = request.args.get('category')
show = request.args.get('show')

query = f"SELECT * FROM products WHERE category = '{category}' AND released = '{show}'"
results = db.execute(query)
```

The database has these products:
- Electronics (released='available'): Laptop, Phone
- Electronics (released='unreleased'): Secret Phone Model X
- Books (released='available'): Python Guide
- Books (released='unreleased'): Upcoming Novel

You want to see ALL electronics products, including the unreleased ones that are normally hidden. What SQL injection payload would you use in the `category` parameter to achieve this? Explain how your payload modifies the SQL query.

---

### Question 4: SQL Injection - Error Messages

You're testing a login form and notice these different behaviors:

**Test 1:** Enter username `admin'` and password `test123`
- Result: Database error displayed: `"SQL syntax error near ''test123'"`

**Test 2:** Enter username `admin` and password `test123`
- Result: `"Invalid username or password"`

**Test 3:** Enter username `admin` and password `admin'--`
- Result: Successfully logged in as admin

**Answer ALL of the following:**

**Part 1:** Which test(s) confirm the application is vulnerable to SQL injection?

**Part 2:** What type of SQL injection attack did Test 3 use? (retrieving hidden data, subverting application logic, or UNION attack)

**Part 3:** According to OWASP Top 10 2021, why is displaying the database error message in Test 1 also a security problem?

**Part 4:** What should the application do instead of showing database errors to users?

---

### Question 5: SQL Injection - Safe vs. Unsafe Code

A team reviews three different implementations of a user search feature:

**Implementation A:**
```python
search = request.args.get('search')
query = "SELECT * FROM users WHERE username = ?"
results = db.execute(query, (search,))
```

**Implementation B:**
```python
search = request.args.get('search')
query = "SELECT * FROM users WHERE username = '" + search + "'"
results = db.execute(query)
```

**Implementation C:**
```python
search = request.args.get('search')
# Validate: only allow alphanumeric characters
if search.isalnum():
	query = "SELECT * FROM users WHERE username = '" + search + "'"
	results = db.execute(query)
```

**Answer ALL of the following:**

**Part 1:** Which implementation(s) use Defense Option 1 (Prepared Statements with Parameterized Queries)?

**Part 2:** Which implementation is the SAFEST and why?

**Part 3:** Implementation C uses input validation. According to the OWASP SQL Injection Prevention Cheat Sheet, why is input validation NOT sufficient as the primary defense against SQL injection?

---

### Question 6: SQL Injection - Multiple Vulnerable Parameters

You're testing an e-commerce site with this search URL:
```
https://shop.example.com/products?category=electronics&max_price=500
```

The vulnerable backend code:
```python
category = request.args.get('category')
max_price = request.args.get('max_price')

query = f"SELECT * FROM products WHERE category = '{category}' AND price <= {max_price}"
results = db.execute(query)
```

**Answer ALL of the following:**

**Part 1:** Both parameters are vulnerable to SQL injection. Which parameter (`category` or `max_price`) is MORE dangerous for an attacker to exploit, and why?

**Part 2:** Write a SQL injection payload for the `category` parameter that would display all products regardless of category or price.

**Part 3:** The developer says: "I'll fix the `category` parameter with a prepared statement, but `max_price` is safe because it's a number." Is the developer correct? Explain why or why not.

---

### Question 7: SQL Injection - Defense Implementation

A team lead asks you to review a junior developer's code fix for a SQL injection vulnerability:

**Original Vulnerable Code:**
```python
username = request.form.get('username')
query = f"SELECT * FROM users WHERE username = '{username}'"
user = db.execute(query)
```

**Developer's "Fixed" Code:**
```python
username = request.form.get('username')
# Remove SQL injection characters
username = username.replace("'", "").replace('"', "").replace(";", "")
query = f"SELECT * FROM users WHERE username = '{username}'"
user = db.execute(query)
```

**Answer ALL of the following:**

**Part 1:** According to OWASP SQL Injection Prevention Cheat Sheet, which Defense Option is the developer attempting to use?

**Part 2:** Why is this fix insufficient to prevent SQL injection? Give a concrete example of a payload that would still work.

**Part 3:** Rewrite the code using Defense Option 1 (Prepared Statements with Parameterized Queries) to properly fix the vulnerability.

**Part 4:** If the team wants defense-in-depth, what secondary defense could they add while still keeping the prepared statement?

---

### Question 8: SQL Injection - Basic Attack Identification

You're testing a shopping website's search feature. The URL is:
```
https://shop.example.com/search?query=laptop
```

You try three different inputs in the search box:

**Test 1:** `laptop`
- Result: Shows 5 laptop products

**Test 2:** `laptop' OR 1=1--`
- Result: Shows ALL products (laptops, phones, tablets, everything)

**Test 3:** `laptop'; DROP TABLE products;--`
- Result: Shows 5 laptop products (no change, same as Test 1)

**Answer ALL of the following:**

**Part 1:** Which test(s) prove the application is vulnerable to SQL injection?

**Part 2:** Why did Test 2 return all products instead of just laptops?

**Part 3:** Why did Test 3 NOT drop the products table? (Hint: Think about how SQL queries are typically sent to databases in modern applications)

---

### Question 9: SQL Injection - Pattern Recognition

You're training a new team member to recognize SQL injection vulnerabilities. You show them four code snippets:

**Snippet A:**
```python
user_id = request.args.get('id')
query = "SELECT * FROM users WHERE id = " + user_id
result = db.execute(query)
```

**Snippet B:**
```python
user_id = request.args.get('id')
query = "SELECT * FROM users WHERE id = ?"
result = db.execute(query, (user_id,))
```

**Snippet C:**
```python
category = request.args.get('category')
if category in ['electronics', 'books', 'clothing']:
	query = f"SELECT * FROM products WHERE category = '{category}'"
	result = db.execute(query)
```

**Snippet D:**
```python
search = request.args.get('search')
query = "SELECT * FROM products WHERE name LIKE ?"
result = db.execute(query, (f"%{search}%",))
```

**Answer ALL of the following:**

**Part 1:** Which snippet(s) are vulnerable to SQL injection?

**Part 2:** For Snippet C, explain why input validation (checking against allowed values) is NOT sufficient as the primary defense when using string concatenation.

**Part 3:** Between Snippets B and D, both use parameterized queries. Are both equally safe? Explain your reasoning.

---

### Question 10: SQL Injection - Attack Surface Analysis

A web application has these three endpoints:

**Endpoint 1: Product Search**
```python
@app.route('/search')
def search():
	query_param = request.args.get('q')
	sql = "SELECT * FROM products WHERE name LIKE ?"
	results = db.execute(sql, (f"%{query_param}%",))
	return render_template('results.html', products=results)
```

**Endpoint 2: Product Details**
```python
@app.route('/product/<product_id>')
def product_details(product_id):
	sql = f"SELECT * FROM products WHERE id = {product_id}"
	product = db.execute(sql)
	return render_template('product.html', product=product)
```

**Endpoint 3: Category Filter**
```python
@app.route('/category/<category_name>')
def category(category_name):
	allowed_categories = ['electronics', 'books', 'clothing', 'toys']
	if category_name not in allowed_categories:
		return {'error': 'Invalid category'}, 400
	
	sql = "SELECT * FROM products WHERE category = ?"
	results = db.execute(sql, (category_name,))
	return render_template('results.html', products=results)
```

**Answer ALL of the following:**

**Part 1:** Which endpoint(s) are vulnerable to SQL injection?

**Part 2:** For Endpoint 2, write a SQL injection payload that would display all products instead of just the one with the specified product_id.

**Part 3:** Endpoint 3 uses both input validation AND prepared statements. Explain why using BOTH defenses (defense-in-depth) is better than using just one, even though prepared statements alone would be sufficient.

---

### Question 11: SQL Injection - Quote vs. No-Quote Parameters

You're testing four different endpoints for SQL injection vulnerabilities:

**Endpoint A: Search by name**
```python
name = request.args.get('name')
query = f"SELECT * FROM users WHERE name = '{name}'"
```

**Endpoint B: Lookup by ID**
```python
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"
```

**Endpoint C: Filter by age**
```python
age = request.args.get('age')
query = f"SELECT * FROM users WHERE age >= {age}"
```

**Endpoint D: Search by email**
```python
email = request.args.get('email')
query = f"SELECT * FROM users WHERE email = \"{email}\""
```

**Answer ALL of the following:**

**Part 1:** All four endpoints are vulnerable to SQL injection. For which endpoint(s) would you need to include a quote character (`'` or `"`) in your SQL injection payload?

**Part 2:** Write a SQL injection payload for Endpoint B that would return ALL users instead of just one.

**Part 3:** Write a SQL injection payload for Endpoint A that would return ALL users instead of searching for a specific name.

**Part 4:** Explain the key difference between your payloads for Endpoint A and Endpoint B.

---

### Question 12: Defense Options - Complete Implementation

A developer is fixing SQL injection vulnerabilities in their codebase and asks you to review their proposed changes:

**Original vulnerable code:**
```python
@app.route('/user/<user_id>')
def get_user(user_id):
	query = f"SELECT * FROM users WHERE id = {user_id}"
	user = db.execute(query)
	return render_template('profile.html', user=user)
```

**Proposed fix:**
```python
@app.route('/user/<user_id>')
def get_user(user_id):
	# Validate input
	if not user_id.isdigit():
		return {'error': 'Invalid ID'}, 400
	
	# Use prepared statement
	query = "SELECT * FROM users WHERE id = ?"
	user = db.execute(query, (user_id,))
	return render_template('profile.html', user=user)
```

**Answer ALL of the following:**

**Part 1:** Which Defense Options from the OWASP SQL Injection Prevention Cheat Sheet are implemented in the proposed fix?

**Part 2:** If the developer removed the input validation but kept the prepared statement, would the code still be secure against SQL injection? Explain why.

**Part 3:** According to OWASP, is this the correct order of defenses (validation first, then prepared statement), or should prepared statements come first?

---

## Category 2: Broken Access Control

### Question 13: Horizontal vs. Vertical Privilege Escalation

You're performing a security assessment and discover two access control vulnerabilities:

**Vulnerability A:**
```python
# Regular user can change their role to admin
POST /api/update-profile
{
	"user_id": 123,
	"name": "John",
	"role": "admin"  # Changed from "user" to "admin"
}
```

**Vulnerability B:**
```python
# Regular user can access another user's profile at same privilege level
GET /api/users/456/profile  # Viewing user 456's profile
# Current user is user 123, but can see user 456's data
```

**According to OWASP Top 10 2021 A01 (Broken Access Control):**

**Part 1:** Which vulnerability is **horizontal privilege escalation**?

**Part 2:** Which vulnerability is **vertical privilege escalation**?

**Part 3:** Explain the difference between these two types of privilege escalation.

---

### Question 14: Principle of Least Privilege

A developer shows you two different implementations for checking if a user can edit a document:

**Implementation A:**
```python
def can_edit_document(user, document):
	# Allow by default, then add restrictions
	allowed = True
	
	if document.is_locked:
		allowed = False
	
	if document.owner != user and user.role != 'admin':
		allowed = False
	
	return allowed
```

**Implementation B:**
```python
def can_edit_document(user, document):
	# Deny by default, then explicitly grant
	if document.owner == user:
		return True
	
	if user.role == 'admin':
		return True
	
	if document.is_locked:
		return False
	
	return False  # Deny by default
```

**Answer ALL of the following:**

**Part 1:** Which implementation correctly follows the "deny by default" principle from OWASP Top 10 2021 A01?

**Part 2:** What vulnerability exists in Implementation A that doesn't exist in Implementation B?

**Part 3:** Give one concrete example of how an attacker could exploit Implementation A's design flaw.

---

### Question 15: Broken Access Control - Missing Authentication

You're performing a security assessment of a banking API. You discover these endpoints:

**Endpoint 1:**
```python
@app.route('/api/user/profile', methods=['GET'])
def get_profile():
	token = request.headers.get('Authorization')
	user = verify_token(token)
	
	if not user:
		return {'error': 'Unauthorized'}, 401
	
	return {'name': user.name, 'email': user.email}
```

**Endpoint 2:**
```python
@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
	users = db.query("SELECT * FROM users")
	return {'users': users}
```

According to OWASP Top 10 2021 A01 (Broken Access Control), which endpoint has a critical security flaw? What specific type of broken access control is this, and what is the potential impact?

---

### Question 16: IDOR Identification

You're reviewing an API endpoint that allows users to view their order history:

```python
@app.route('/api/orders/<order_id>', methods=['GET'])
def get_order(order_id):
	order = db.query("SELECT * FROM orders WHERE id = ?", (order_id,))
	
	if not order:
		return {'error': 'Order not found'}, 404
	
	return {'order': order}
```

A test reveals:
- User A (id=123) can access their order: `/api/orders/1001` ✓
- User A can also access User B's order: `/api/orders/2002` ✓
- Anonymous users (not logged in) can access any order ✓

**Answer ALL of the following:**

**Part 1:** What type of vulnerability is this according to OWASP Top 10 2021 A01?

**Part 2:** Which TWO security checks are completely missing from this code?

**Part 3:** The code uses a parameterized query (`?` placeholder). Does this prevent the access control vulnerability? Explain why or why not.

---

### Question 17: Access Control - Complete Security Implementation

You're implementing a document management API endpoint that should only allow users to delete their own documents:

**Current Implementation:**
```python
@app.route('/api/document/<doc_id>/delete', methods=['DELETE'])
def delete_document(doc_id):
	db.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
	return {'success': True}
```

**Answer ALL of the following:**

**Part 1:** List ALL the security checks missing from this implementation according to OWASP Top 10 2021 A01 (Broken Access Control).

**Part 2:** Describe what security checks should be added and in what order they should execute.

**Part 3:** Which specific access control vulnerability (from OWASP Top 10 A01) does the current implementation have?

---

### Question 18: Access Control - Real-World Scenario

A banking application has these two API endpoints:

**Endpoint 1: View Account Balance**
```python
@app.route('/api/account/<account_id>/balance', methods=['GET'])
def get_balance(account_id):
	user = get_current_user()
	
	if not user:
		return {'error': 'Unauthorized'}, 401
	
	balance = db.query("SELECT balance FROM accounts WHERE id = ?", (account_id,))
	return {'balance': balance}
```

**Endpoint 2: Update Account Email**
```python
@app.route('/api/account/<account_id>/email', methods=['PUT'])
def update_email(account_id):
	user = get_current_user()
	
	if not user:
		return {'error': 'Unauthorized'}, 401
	
	if user.account_id != account_id:
		return {'error': 'Forbidden'}, 403
	
	new_email = request.json.get('email')
	db.execute("UPDATE accounts SET email = ? WHERE id = ?", (new_email, account_id))
	return {'success': True}
```

**Answer ALL of the following:**

**Part 1:** Which endpoint has an IDOR vulnerability?

**Part 2:** For the vulnerable endpoint, what specific check is missing?

**Part 3:** Both endpoints check authentication (if user is logged in). Why is authentication alone not sufficient for Endpoint 1?

---

### Question 19: Access Control - Security Check Ordering

A banking API endpoint for transferring money has these security checks in different orders:

**Implementation A:**
```python
@app.route('/transfer', methods=['POST'])
def transfer():
	from_account = request.json.get('from_account')
	to_account = request.json.get('to_account')
	amount = request.json.get('amount')
	
	# Check 1: Verify account has sufficient balance
	balance = db.query("SELECT balance FROM accounts WHERE id = ?", (from_account,))
	if balance < amount:
		return {'error': 'Insufficient funds'}, 400
	
	# Check 2: Verify user is authenticated
	user = get_current_user()
	if not user:
		return {'error': 'Unauthorized'}, 401
	
	# Check 3: Verify user owns the from_account
	if user.account_id != from_account:
		return {'error': 'Forbidden'}, 403
	
	# Execute transfer
	execute_transfer(from_account, to_account, amount)
	return {'success': True}
```

**Implementation B:**
```python
@app.route('/transfer', methods=['POST'])
def transfer():
	from_account = request.json.get('from_account')
	to_account = request.json.get('to_account')
	amount = request.json.get('amount')
	
	# Check 1: Verify user is authenticated
	user = get_current_user()
	if not user:
		return {'error': 'Unauthorized'}, 401
	
	# Check 2: Verify user owns the from_account
	if user.account_id != from_account:
		return {'error': 'Forbidden'}, 403
	
	# Check 3: Verify account has sufficient balance
	balance = db.query("SELECT balance FROM accounts WHERE id = ?", (from_account,))
	if balance < amount:
		return {'error': 'Insufficient funds'}, 400
	
	# Execute transfer
	execute_transfer(from_account, to_account, amount)
	return {'success': True}
```

**Answer ALL of the following:**

**Part 1:** Which implementation has better security check ordering?

**Part 2:** What vulnerability exists in Implementation A that doesn't exist in Implementation B?

**Part 3:** According to the principle of "fail securely," why should authentication and authorization checks come BEFORE business logic checks (like balance verification)?

---

### Question 20: Access Control Principles - Scenario Analysis

A developer shows you three different approaches to access control for a user profile endpoint:

**Approach 1:**
```python
@app.route('/profile/<username>')
def view_profile(username):
	profile = db.query("SELECT * FROM profiles WHERE username = ?", (username,))
	return render_template('profile.html', profile=profile)
```
*Anyone can view any profile by changing the username in the URL*

**Approach 2:**
```python
@app.route('/profile')
def view_profile():
	user = get_current_user()
	if user:
		profile = db.query("SELECT * FROM profiles WHERE username = ?", (user.username,))
		return render_template('profile.html', profile=profile)
	return redirect('/login')
```
*Only logged-in users can view their own profile*

**Approach 3:**
```python
@app.route('/profile/<username>')
def view_profile(username):
	user = get_current_user()
	if not user:
		return {'error': 'Unauthorized'}, 401
	
	profile = db.query("SELECT * FROM profiles WHERE username = ?", (username,))
	return render_template('profile.html', profile=profile)
```
*Logged-in users can view any profile*

**Answer ALL of the following:**

**Part 1:** If profiles should be public (anyone can view any profile), which approach is acceptable?

**Part 2:** If profiles should be private (users can only view their own profile), which approach correctly implements this requirement?

**Part 3:** What is the specific vulnerability in Approach 3, and what security principle from OWASP Top 10 2021 A01 is it violating?

---

## Category 3: Cryptographic Failures

### Question 21: Cryptographic Failures - Password Storage

You're reviewing a legacy authentication system. The database stores passwords like this:

```sql
CREATE TABLE users (
	id INT PRIMARY KEY,
	username VARCHAR(100),
	password_hash VARCHAR(64)  -- Stores MD5 hash of password
);
```

```python
def create_user(username, password):
	password_hash = hashlib.md5(password.encode()).hexdigest()
	db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
			   (username, password_hash))
```

According to OWASP Top 10 2025 A02 (Cryptographic Failures), identify TWO critical weaknesses in this password storage approach. Why are these weaknesses dangerous?

---

### Question 22: Cryptographic Failures - Algorithm Selection

A development team is debating which approach to use for storing credit card numbers in their database:

**Developer A:** "Let's encrypt credit card numbers using MD5. At least they're not stored in plaintext."

**Developer B:** "MD5 is broken. Let's use SHA-256 with a salt instead. It's more secure."

**Developer C:** "We shouldn't store credit card numbers at all. Use tokenization with a payment processor like Stripe."

**According to OWASP Top 10 2021 A02 (Cryptographic Failures):**

**Part 1:** Why is Developer A's approach (MD5) wrong? (Hint: MD5 is not an encryption algorithm)

**Part 2:** What potential problem exists with Developer B's approach (SHA-256 with salt), even though SHA-256 is stronger than MD5?

**Part 3:** Why is Developer C's approach (tokenization) the best from a security perspective?

---

### Question 23: Cryptographic Failures - Transmission Security

You're reviewing security for a healthcare application that handles patient medical records. The team has these configurations:

**Configuration 1:** Website uses HTTPS for the login page only, then switches to HTTP for the main application

**Configuration 2:** Application sends password reset tokens via unencrypted email

**Configuration 3:** Mobile app communicates with API over HTTPS, but doesn't validate the SSL certificate

**Answer ALL of the following:**

**Part 1:** Which configuration(s) have cryptographic failures according to OWASP Top 10 2021 A02?

**Part 2:** For Configuration 1, explain why using HTTPS only for login is insufficient.

**Part 3:** For Configuration 3, what specific attack does failing to validate SSL certificates enable?

**Part 4:** What is the recommended fix for each of the three configurations?

---

### Question 24: Cryptographic Failures - Data Classification

You're reviewing a web application and discover these configurations:

**Configuration A:**
```python
# API endpoint for user login
@app.route('/api/login', methods=['POST'])
def login():
	username = request.form.get('username')
	password = request.form.get('password')  # Sent over HTTP
	# ... authentication logic
```

**Configuration B:**
```python
# Database connection
db_config = {
	'host': 'db.example.com',
	'user': 'app_user',
	'password': 'secret123',
	'ssl': False  # Database connection without TLS
}
```

**According to OWASP Top 10 2021 A02 (Cryptographic Failures):**

**Part 1:** What specific cryptographic failure exists in Configuration A?

**Part 2:** What specific cryptographic failure exists in Configuration B?

**Part 3:** What is the recommended fix for each?

---

### Question 25: Hashing vs. Encryption - Understanding the Difference

A team is building a medical records application and needs to decide how to secure different types of data:

**Data Type 1:** Doctor's login passwords
- Need to: Verify password during login
- Don't need to: Ever retrieve the original password

**Data Type 2:** Patient insurance claim numbers
- Need to: Send to insurance companies for processing
- Don't need to: Display to patients (kept internal)

**Data Type 3:** Medical record checksums (to detect file tampering)
- Need to: Verify file hasn't been modified
- Don't need to: Reverse the checksum back to original file

**Answer ALL of the following:**

**Part 1:** For each data type (1, 2, and 3), state whether you would use hashing or encryption. Format your answer as: "Data Type 1: [hashing/encryption], Data Type 2: [hashing/encryption], Data Type 3: [hashing/encryption]"

**Part 2:** For Data Type 1 (passwords), the team suggests using SHA-256 with a random salt. Explain why this is better than plain SHA-256, but still not the best solution according to OWASP Top 10 2021 A02.

**Part 3:** According to OWASP Top 10 2021 A02 (Cryptographic Failures), if this application transmits patient data over the network, what protection should be in place for "data in transit"?

---

### Question 26: Hashing vs. Encryption - Decision Making

A developer asks you for advice on securing different types of data:

**Scenario A:** Storing user passwords for login authentication

**Scenario B:** Storing user email addresses that need to be displayed on their profile page

**Scenario C:** Storing API keys that the application needs to use to call external services

**Answer ALL of the following:**

**Part 1:** For Scenario A (passwords), should you use hashing or encryption? Explain why.

**Part 2:** For Scenario B (email addresses), should you use hashing or encryption? Explain why.

**Part 3:** For Scenario C (API keys), should you use hashing or encryption? Explain why.

**Part 4:** What is the key question you should ask yourself to decide between hashing and encryption for any piece of data?

---

### Question 27: Cryptographic Failures - Multiple Scenarios

A healthcare application handles different types of sensitive data. The security team proposes these approaches:

**Data Type A: Patient passwords for portal login**
- Proposed solution: Store bcrypt hashes

**Data Type B: Patient Social Security Numbers (needed for insurance claims)**
- Proposed solution: Store encrypted with AES-256

**Data Type C: Doctor's digital signatures on prescriptions**
- Proposed solution: Store SHA-256 hashes

**Data Type D: Session tokens for logged-in users**
- Proposed solution: Store in plain text in database, but only transmit over HTTPS

**Answer ALL of the following:**

**Part 1:** Which data types are using the CORRECT approach (hashing vs encryption)?

**Part 2:** For Data Type D (session tokens), identify TWO problems with the proposed approach.

**Part 3:** According to OWASP Top 10 2021 A02, why is using HTTPS important for Data Type D, and what specific threat does it protect against?

---

## Category 4: Comprehensive Security Reviews

### Question 28: Putting It All Together - Multiple Vulnerabilities

You're reviewing a simple blog application with this comment posting endpoint:

```python
@app.route('/post/<post_id>/comment', methods=['POST'])
def add_comment(post_id):
	username = request.form.get('username')
	comment = request.form.get('comment')
	
	# Check if post exists
	post = db.execute(f"SELECT * FROM posts WHERE id = {post_id}")
	
	if not post:
		return {'error': 'Post not found'}, 404
	
	# Insert comment
	query = "INSERT INTO comments (post_id, username, comment) VALUES (?, ?, ?)"
	db.execute(query, (post_id, username, comment))
	
	return {'success': True}
```

**Answer ALL of the following:**

**Part 1:** Identify the SQL injection vulnerability in this code. Which specific line is vulnerable?

**Part 2:** The INSERT statement uses prepared statements. Does this mean the entire function is safe from SQL injection? Explain.

**Part 3:** From an access control perspective (OWASP Top 10 A01), what security check is missing from this endpoint?

**Part 4:** If this application uses HTTP instead of HTTPS, which OWASP Top 10 2021 category would that violate?

---

### Question 29: Comprehensive Security Review

You're conducting a security review of a password reset feature:

```python
@app.route('/reset-password', methods=['POST'])
def reset_password():
	email = request.form.get('email')
	new_password = request.form.get('new_password')
	
	# Find user by email
	query = f"SELECT * FROM users WHERE email = '{email}'"
	user = db.execute(query)
	
	if user:
		# Hash the new password
		password_hash = hashlib.md5(new_password.encode()).hexdigest()
		
		# Update password
		update_query = "UPDATE users SET password = ? WHERE email = ?"
		db.execute(update_query, (password_hash, email))
		
		return {'success': True}
	
	return {'error': 'User not found'}, 404
```

**This application uses HTTP (not HTTPS).**

**Answer ALL of the following:**

**Part 1:** Identify ALL security vulnerabilities in this code. List them by OWASP Top 10 2021 category (A01, A02, A03, etc.).

**Part 2:** For the SQL injection vulnerability, which specific line is vulnerable and why?

**Part 3:** For the cryptographic failure in password storage, what specific problem exists and what should be used instead?

**Part 4:** What additional OWASP Top 10 category is violated by using HTTP instead of HTTPS for this password reset feature?

---

### Question 30: OWASP Top 10 - Vulnerability Classification

You're reviewing a login system and find these issues:

**Issue 1:** Login form sends credentials over HTTP instead of HTTPS

**Issue 2:** Passwords are stored as plain MD5 hashes without salt

**Issue 3:** The login query is: `SELECT * FROM users WHERE username = '{username}' AND password = '{password}'`

**Issue 4:** After successful login, any authenticated user can access `/admin/dashboard` without role verification

**Answer ALL of the following:**

**Part 1:** Classify each issue by OWASP Top 10 2021 category (A01, A02, A03, etc.). Format: "Issue 1: [Category], Issue 2: [Category], Issue 3: [Category], Issue 4: [Category]"

**Part 2:** Which TWO issues relate to A02 (Cryptographic Failures)?

**Part 3:** For Issue 3 (SQL injection in login), explain why this is particularly dangerous compared to SQL injection in a product search feature.

**Part 4:** If you could only fix ONE issue immediately, which should it be and why?

---

### Question 31: Comprehensive Security Thinking

You're reviewing a password change endpoint:

```python
@app.route('/change-password', methods=['POST'])
def change_password():
	username = request.form.get('username')
	old_password = request.form.get('old_password')
	new_password = request.form.get('new_password')
	
	# Verify old password
	query = "SELECT * FROM users WHERE username = ? AND password = ?"
	user = db.execute(query, (username, old_password))
	
	if user:
		# Hash new password with bcrypt
		new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
		
		# Update password
		update = "UPDATE users SET password = ? WHERE username = ?"
		db.execute(update, (new_hash, username))
		
		return {'success': True}
	
	return {'error': 'Invalid credentials'}, 401
```

**The application uses HTTPS. Passwords in the database are currently stored as bcrypt hashes.**

**Answer ALL of the following:**

**Part 1:** Is this code vulnerable to SQL injection? Explain your reasoning.

**Part 2:** From an access control perspective (OWASP Top 10 A01), what critical security check is missing?

**Part 3:** The code compares `old_password` (plaintext) directly against the stored `password` (bcrypt hash). Will this work? If not, what should be done instead?

**Part 4:** If you had to identify ONE issue that represents the most serious security flaw in this code, what would it be and why?

---

## Category 5: Defense in Depth & Security Principles

### Question 32: SQL Injection - Why Parameterized Queries Work

A junior developer asks you: "I understand that prepared statements prevent SQL injection, but I don't understand HOW. What's the difference between these two approaches?"

**Vulnerable approach:**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
db.execute(query)
```

**Safe approach:**
```python
query = "SELECT * FROM users WHERE username = ? AND password = ?"
db.execute(query, (username, password))
```

Explain to the junior developer why the second approach prevents SQL injection. What happens differently when user input contains SQL syntax like `' OR '1'='1'--` in each approach?

---

### Question 33: Broken Access Control - Basic Concepts

You're explaining OWASP Top 10 2021 A01 (Broken Access Control) to a new developer. They ask you to clarify some terms.

**Answer ALL of the following:**

**Part 1:** What is the difference between authentication and authorization? Give a simple example of each.

**Part 2:** A developer says: "Our API checks if the user is logged in before allowing any action, so we don't have broken access control." Explain why this statement is incorrect using the principle of "deny by default."

**Part 3:** What does IDOR stand for, and give one simple example of an IDOR vulnerability?

---

### Question 34: Cryptographic Failures - Understanding the Difference

A team is securing their application and discussing different security measures:

**Measure 1:** "We're using HTTPS for our website, so all data is encrypted in transit between the browser and our server."

**Measure 2:** "We're storing user passwords as bcrypt hashes in our database, so even if our database is stolen, attackers can't get the passwords."

**Measure 3:** "We're encrypting credit card numbers with AES-256 before storing them in the database, and keeping the encryption key in a separate secure location."

**Answer ALL of the following:**

**Part 1:** Which measure(s) protect "data in transit"?

**Part 2:** Which measure(s) protect "data at rest"?

**Part 3:** Which measure(s) use encryption (reversible)?

**Part 4:** Which measure(s) use hashing (one-way)?

**Part 5:** Explain the difference between "data in transit" and "data at rest" in your own words.

---

### Question 35: Defense in Depth - Multiple Layers

According to the OWASP SQL Injection Prevention Cheat Sheet, there are four primary defense options. A developer implements the following security measures for a login form:

**Security Layer 1:** Uses prepared statements for all database queries

**Security Layer 2:** Validates that username contains only letters and numbers (alphanumeric)

**Security Layer 3:** Limits password length to maximum 128 characters

**Security Layer 4:** Uses HTTPS for all traffic

**Answer ALL of the following:**

**Part 1:** Which security layer is Defense Option 1 (the primary defense against SQL injection)?

**Part 2:** Which security layer is Defense Option 3 (a secondary defense against SQL injection)?

**Part 3:** Which security layer addresses OWASP Top 10 2021 A02 (Cryptographic Failures) instead of A03 (Injection)?

**Part 4:** If the developer removed Security Layer 1 (prepared statements) but kept the other three layers, would the application still be vulnerable to SQL injection? Explain why.

---

### Question 36: SQL Injection - Recognizing Safe Code

A developer shows you four different ways they've "secured" a search feature:

**Version 1:**
```python
search = request.args.get('search')
# Remove dangerous characters
search = search.replace("'", "").replace(";", "").replace("--", "")
query = f"SELECT * FROM users WHERE name = '{search}'"
results = db.execute(query)
```

**Version 2:**
```python
search = request.args.get('search')
query = "SELECT * FROM users WHERE name = ?"
results = db.execute(query, (search,))
```

**Version 3:**
```python
search = request.args.get('search')
# Only allow safe characters
if re.match(r'^[a-zA-Z0-9]+$', search):
	query = "SELECT * FROM users WHERE name = ?"
	results = db.execute(query, (search,))
else:
	return {'error': 'Invalid input'}
```

**Version 4:**
```python
search = request.args.get('search')
# Escape special characters
search = search.replace("'", "''")  # SQL escaping
query = f"SELECT * FROM users WHERE name = '{search}'"
results = db.execute(query)
```

**Answer ALL of the following:**

**Part 1:** Which version(s) use Defense Option 1 (Prepared Statements)?

**Part 2:** Which version is the MOST secure and why?

**Part 3:** Version 1 tries to remove dangerous characters. Why is this approach (Defense Option 4: Escaping) considered the LEAST reliable defense according to OWASP?

**Part 4:** Version 3 combines two defenses. What are they, and why is this defense-in-depth approach better than using input validation alone?

---

### Question 37: SQL Injection Impact vs. IDOR Impact

You're explaining the difference between SQL injection and IDOR to a junior developer.

**Scenario A: SQL Injection in Search**
- Attacker finds SQL injection in product search
- Can retrieve entire products table in one query
- Can potentially access other database tables
- One successful attack compromises large amount of data

**Scenario B: IDOR in Order API**
- Attacker can access individual orders by changing order_id
- Must make one request per order to steal data
- Limited to orders table only
- Must iterate through many IDs to get significant data

**Answer ALL of the following:**

**Part 1:** Which vulnerability typically has higher frequency (how often it occurs in applications)?

**Part 2:** Which vulnerability typically has higher impact per successful exploitation?

**Part 3:** Explain the key difference in how these vulnerabilities are exploited and why that affects their relative impact.

---

### Question 38: SQL Injection - Missing Authorization in Checkout

You're reviewing an e-commerce checkout endpoint:

```python
@app.route('/api/checkout', methods=['POST'])
def checkout():
	cart_id = request.json.get('cart_id')
	
	# Get cart items
	items = db.query("SELECT * FROM cart_items WHERE cart_id = ?", (cart_id,))
	
	# Calculate total
	total = sum(item.price * item.quantity for item in items)
	
	# Process payment
	process_payment(total)
	
	return {'success': True, 'total': total}
```

**Answer ALL of the following:**

**Part 1:** Is this code vulnerable to SQL injection? Why or why not?

**Part 2:** What critical access control checks are missing from this endpoint?

**Part 3:** What is the potential impact if a malicious user calls this endpoint with someone else's cart_id?

---

### Question 39: Cryptographic Failures - Password Storage Weaknesses

A legacy system stores passwords using this code:

```python
def store_password(username, password):
	password_hash = hashlib.md5(password.encode()).hexdigest()
	db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
			   (username, password_hash))
```

**Answer ALL of the following:**

**Part 1:** Identify TWO cryptographic weaknesses in this password storage approach.

**Part 2:** Why is not using a salt particularly dangerous for password storage?

**Part 3:** What should be used instead of MD5 for password hashing according to OWASP Top 10 2021 A02?

---

### Question 40: Cryptographic Failures - Deprecated Algorithms

A team is reviewing their authentication system and discussing password hashing:

**Team Member A:** "We should use SHA-1 for password hashing. It's faster than bcrypt."

**Team Member B:** "No, let's use SHA-256. It's more secure than SHA-1."

**Team Member C:** "We should use bcrypt or Argon2. They're designed for password hashing."

**Answer ALL of the following:**

**Part 1:** Which team member is correct and why?

**Part 2:** Explain why SHA-256 (even though it's cryptographically stronger than SHA-1) is still not appropriate for password hashing.

**Part 3:** What makes bcrypt and Argon2 better choices for password storage compared to SHA-256?

---

### Question 41: Broken Access Control - Deny by Default Implementation

A developer shows you two implementations of a file access control system:

**Implementation A:**
```python
def can_access_file(user, file):
	# Check specific denial conditions
	if file.is_deleted:
		return False
	if file.owner == user:
		return True
	if user.role == 'admin':
		return True
	# If no condition matches, allow access
	return True
```

**Implementation B:**
```python
def can_access_file(user, file):
	# Deny by default
	if file.is_deleted:
		return False
	if file.owner == user:
		return True
	if user.role == 'admin':
		return True
	# Deny by default
	return False
```

**Answer ALL of the following:**

**Part 1:** Which implementation correctly follows the "deny by default" principle?

**Part 2:** Give a concrete example of how Implementation A could be exploited.

**Part 3:** Implementation B still has a logical bug. What happens if a deleted file's owner tries to access it? Should they be allowed?

---

### Question 42: Comprehensive Security Review - Multiple Issues

You're reviewing a blog comment system:

```python
@app.route('/post/<post_id>/comments', methods=['GET'])
def get_comments(post_id):
	query = f"SELECT * FROM comments WHERE post_id = {post_id}"
	comments = db.execute(query)
	return {'comments': comments}

@app.route('/post/<post_id>/comment', methods=['POST'])
def add_comment(post_id):
	user_id = request.json.get('user_id')
	comment_text = request.json.get('comment')
	
	query = "INSERT INTO comments (post_id, user_id, comment) VALUES (?, ?, ?)"
	db.execute(query, (post_id, user_id, comment_text))
	
	return {'success': True}
```

**Application uses HTTP (not HTTPS).**

**Answer ALL of the following:**

**Part 1:** Identify ALL vulnerabilities by OWASP Top 10 2021 category for BOTH endpoints.

**Part 2:** For the GET endpoint, what is the specific vulnerability and how could it be exploited?

**Part 3:** For the POST endpoint, what critical access control issue exists?

**Part 4:** Why is using HTTP (instead of HTTPS) particularly concerning for the POST endpoint?

---

### Question 43: SQL Injection - Cryptographic Data Protection

You're reviewing these three configurations for a password reset system:

**Config 1: Email transmission**
```python
# Send password reset token via email
send_email(user.email, f"Reset token: {reset_token}")  # Email sent over SMTP without TLS
```

**Config 2: Token storage**
```python
# Store reset token in database
db.execute("INSERT INTO reset_tokens (user_id, token) VALUES (?, ?)",
		   (user_id, reset_token))  # Token stored in plaintext
```

**Config 3: Token validation**
```python
# Validate reset token
@app.route('/reset/<token>')  # URL sent over HTTP
def reset_password(token):
	# Validation logic
```

**Answer ALL of the following:**

**Part 1:** Which configuration(s) have cryptographic failures according to OWASP Top 10 2021 A02?

**Part 2:** For Config 1 (email transmission), what is the specific threat?

**Part 3:** For Config 2 (token storage), what should be done instead of storing tokens in plaintext?

**Part 4:** For Config 3 (HTTP transmission), what specific attack does this enable?

---

### Question 44: SQL Injection - Error-Based Detection

You're testing a login form and observe these behaviors:

**Test 1:** Username: `admin`, Password: `test123`
- Response: `Invalid credentials`

**Test 2:** Username: `admin'`, Password: `test123`
- Response: `Database error: unterminated string literal`

**Test 3:** Username: `admin' OR 1=1--`, Password: `anything`
- Response: `Login successful` (logged in as admin)

**Answer ALL of the following:**

**Part 1:** Which test(s) definitively prove SQL injection exists?

**Part 2:** What is the vulnerability in the query that allows Test 3 to succeed?

**Part 3:** Why is the error message in Test 2 also a security problem beyond just revealing SQL injection?

**Part 4:** What should the application do with database errors instead of displaying them?

---

### Question 45: Broken Access Control - Authorization vs. Business Logic

A file sharing service has this download endpoint:

```python
@app.route('/download/<file_id>')
def download_file(file_id):
	user = get_current_user()
	if not user:
		return {'error': 'Unauthorized'}, 401
	
	file = db.query("SELECT * FROM files WHERE id = ?", (file_id,))
	
	if not file:
		return {'error': 'File not found'}, 404
	
	# Check if file is shared publicly
	if file.is_public:
		return send_file(file.path)
	
	# Check if user owns the file
	if file.owner_id == user.id:
		return send_file(file.path)
	
	return {'error': 'Forbidden'}, 403
```

**Answer ALL of the following:**

**Part 1:** Does this endpoint have proper authentication? Why or why not?

**Part 2:** Does this endpoint have proper authorization? Why or why not?

**Part 3:** Is there any security issue with this implementation? If so, what is it?

---

### Question 46: SQL Injection - Defense Option Identification

You're reviewing different SQL injection defenses in a codebase:

**Defense A:**
```python
user_input = request.args.get('search')
query = "SELECT * FROM products WHERE name LIKE ?"
results = db.execute(query, (f"%{user_input}%",))
```

**Defense B:**
```python
user_input = request.args.get('category')
allowed = ['electronics', 'books', 'clothing']
if user_input not in allowed:
	return error('Invalid category')
query = f"SELECT * FROM products WHERE category = '{user_input}'"
results = db.execute(query)
```

**Defense C:**
```python
user_input = request.args.get('id')
if not user_input.isdigit():
	return error('Invalid ID')
query = "SELECT * FROM products WHERE id = ?"
results = db.execute(query, (user_input,))
```

**Answer ALL of the following:**

**Part 1:** Which defense(s) use Defense Option 1 (Prepared Statements)?

**Part 2:** Which defense(s) use Defense Option 3 (Allow-list Input Validation)?

**Part 3:** Defense B uses allow-list validation but still uses string concatenation. Is this secure? Why or why not?

**Part 4:** Defense C combines two defenses. What are the benefits of this defense-in-depth approach?

---

### Question 47: Cryptographic Failures - Data Classification

An application handles different types of data:

**Data 1:** User session tokens (needed to validate logged-in users)

**Data 2:** User credit card CVV codes (three-digit security codes)

**Data 3:** User profile pictures (uploaded images)

**Data 4:** API keys for external services (needed to make API calls)

**Answer ALL of the following:**

**Part 1:** For Data 1 (session tokens), should they be hashed, encrypted, or stored in plaintext? Explain why.

**Part 2:** For Data 2 (CVV codes), what is the correct approach according to PCI-DSS standards?

**Part 3:** For Data 3 (profile pictures), do they need encryption at rest? Explain your reasoning.

**Part 4:** For Data 4 (API keys), should they be hashed or encrypted? Explain why.

---

### Question 48: Comprehensive Security - Vulnerability Prioritization

You discover these vulnerabilities during a security audit:

**Vulnerability A:** SQL injection in admin login page (high traffic)

**Vulnerability B:** IDOR in user profile API (allows viewing other users' private profile data)

**Vulnerability C:** Passwords stored as MD5 hashes without salt

**Vulnerability D:** Missing HTTPS on payment processing page

**Answer ALL of the following:**

**Part 1:** Classify each vulnerability by OWASP Top 10 2021 category.

**Part 2:** If you could only fix TWO vulnerabilities immediately, which would you choose and why?

**Part 3:** Which vulnerability has the highest exploitability (easiest for attacker to exploit)?

**Part 4:** Which vulnerability has the highest business impact if exploited?

---

### Question 49: SQL Injection - Numeric vs. String Parameters

You're testing these four endpoints:

**Endpoint A:** User search by name
```python
name = request.args.get('name')
query = f"SELECT * FROM users WHERE name = '{name}'"
```

**Endpoint B:** User lookup by ID
```python
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"
```

**Endpoint C:** Filter by age
```python
age = request.args.get('age')
query = f"SELECT * FROM users WHERE age >= {age}"
```

**Endpoint D:** Search by email
```python
email = request.args.get('email')
query = f"SELECT * FROM users WHERE email = \"{email}\""
```

**Answer ALL of the following:**

**Part 1:** All four endpoints are vulnerable. For which endpoint(s) do you need to include a quote character (`'` or `"`) in your SQL injection payload?

**Part 2:** Write a SQL injection payload for Endpoint B that returns ALL users.

**Part 3:** Write a SQL injection payload for Endpoint A that returns ALL users.

**Part 4:** Explain the key difference between your payloads for Endpoint A and Endpoint B.

---

### Question 50: Defense Options - Proper Implementation Order

A developer is fixing SQL injection vulnerabilities:

**Original code:**
```python
@app.route('/user/<user_id>')
def get_user(user_id):
	query = f"SELECT * FROM users WHERE id = {user_id}"
	user = db.execute(query)
	return render_template('profile.html', user=user)
```

**Proposed fix:**
```python
@app.route('/user/<user_id>')
def get_user(user_id):
	# Validate input
	if not user_id.isdigit():
		return {'error': 'Invalid ID'}, 400
	
	# Use prepared statement
	query = "SELECT * FROM users WHERE id = ?"
	user = db.execute(query, (user_id,))
	return render_template('profile.html', user=user)
```

**Answer ALL of the following:**

**Part 1:** Which OWASP Defense Options are implemented in the fix?

**Part 2:** If the developer removed validation but kept prepared statements, would the code still be secure against SQL injection?

**Part 3:** What is the benefit of including both defenses (defense-in-depth)?

---

### Question 51: Comprehensive Security - Password Change Endpoint

You're reviewing this password change endpoint:

```python
@app.route('/change-password', methods=['POST'])
def change_password():
	username = request.form.get('username')
	old_password = request.form.get('old_password')
	new_password = request.form.get('new_password')
	
	# Verify old password
	query = "SELECT * FROM users WHERE username = ? AND password = ?"
	user = db.execute(query, (username, old_password))
	
	if user:
		# Hash new password
		new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
		
		# Update password
		update = "UPDATE users SET password = ? WHERE username = ?"
		db.execute(update, (new_hash, username))
		
		return {'success': True}
	
	return {'error': 'Invalid credentials'}, 401
```

**The application uses HTTPS. Passwords are stored as bcrypt hashes.**

**Answer ALL of the following:**

**Part 1:** Is this code vulnerable to SQL injection? Explain.

**Part 2:** What critical access control check is missing?

**Part 3:** The code compares `old_password` (plaintext) against stored `password` (hash). Will this work?

**Part 4:** What is the MOST serious security flaw in this code?

---

## 🎯 How Did You Score?

**Scoring Guide:**
- **85-100% (43+ correct):** Ready for phone interviews! You have strong Week 1 fundamentals
- **70-84% (36-42 correct):** Solid understanding, review weak areas before interviews
- **50-69% (26-35 correct):** Good foundation, need more practice on core concepts
- **Below 50% (<26 correct):** Review OWASP Top 10 documentation and try again

---

## 📚 Want More Practice?

If you found this quiz helpful, check out the **AppSec-Exercises** repository for more interview preparation materials:

⭐ **[Star the repository](https://github.com/fosres/AppSec-Exercises)** for:
- More OWASP Top 10 quizzes
- LeetCode-style secure coding challenges
- Vulnerable code review exercises
- Real-world exploitation scenarios
- Weekly new content

**Why star the repo?**
- Get notified when new quizzes are added
- Help other AppSec learners find quality resources
- Support the creation of more free security content
- Build your GitHub profile with security-focused repos

---

## 🚀 Next Steps

**After completing this quiz:**

1. **Review missed questions** - Focus on understanding WHY, not just memorizing answers
2. **Practice explaining** - Say answers out loud as if in an interview
3. **Read OWASP documentation** - Deep dive into categories you struggled with
4. **Build projects** - Apply concepts to actual code in the AppSec-Exercises repo
5. **Do mock interviews** - Practice with peers or mentors

**Week 2 Preparation:**
- Advanced SQL injection (UNION attacks, blind SQLi)
- XSS (Cross-Site Scripting) fundamentals
- CSRF (Cross-Site Request Forgery)
- Authentication and session management

---

## 📖 Resources Referenced

All questions in this quiz are based on:
- **OWASP Top 10 2021:** https://owasp.org/Top10/
- **OWASP SQL Injection Prevention Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- **PortSwigger Web Security Academy:** https://portswigger.net/web-security

---

# Answer Key

Below are the answers and explanations for all 51 questions. Try to answer all questions before checking!

---

## SQL Injection Fundamentals - Answers

### Answer 1:
**Payload:** `admin'--` or `' OR '1'='1'--`

**How it works:**
- The single quote `'` closes the username parameter
- `--` comments out everything after (including password check)
- Example: `SELECT * FROM users WHERE username = 'admin'--' AND password = '...'`
- Result: Password check is ignored, logs in as admin

**Source:** OWASP SQL Injection Prevention Cheat Sheet - Subverting application logic is one of the most common SQL injection attacks.

---

### Answer 2:
**Defense Option 2:** Stored Procedures

Stored procedures are SQL code defined and stored in the database, then called from the application. When implemented safely (using parameterized queries internally), they provide similar protection to prepared statements.

**Note:** For Week 1 level, knowing that Defense Option 2 is "Stored Procedures" is sufficient. Implementation details vary by database (MySQL, PostgreSQL, SQL Server) and are typically covered in advanced coursework.

**Source:** OWASP SQL Injection Prevention Cheat Sheet - "Defense Option 2: Stored Procedures"

---

### Answer 3:
**Payload:** `electronics'--`

**How it works:**
```python
# Original query:
SELECT * FROM products WHERE category = 'electronics' AND released = 'available'

# With payload 'electronics'--':
SELECT * FROM products WHERE category = 'electronics'--' AND released = 'available'

# Everything after -- is commented out:
SELECT * FROM products WHERE category = 'electronics'
# Returns ALL electronics (both available and unreleased)
```

**Source:** PortSwigger SQL Injection - "Retrieving hidden data" is the first SQL injection technique covered in basic labs.

---

### Answer 4:
**Part 1:** Tests 1 AND 3 both confirm SQL injection vulnerability. Test 1 shows error-based SQLi detection, Test 3 shows successful exploitation.

**Part 2:** Subverting application logic - bypassing authentication by commenting out the password check.

**Part 3:** Error messages reveal SQL syntax structure, helping attackers craft exploits. This is information disclosure under OWASP A02 (Cryptographic Failures).

**Part 4:** Log errors server-side for debugging, but show users generic error messages like "An error occurred. Please try again." Never display database errors, SQL syntax, table names, or column names.

**Source:** OWASP Top 10 2021 A02 covers sensitive data exposure through error messages.

---

### Answer 5:
**Part 1:** Implementation A uses prepared statements (Defense Option 1).

**Part 2:** Implementation A is the safest because it uses prepared statements with parameterized queries. This treats user input as data, not code, making SQL injection impossible regardless of input.

**Part 3:** Input validation (Defense Option 3) is a secondary defense. Validated data is not necessarily safe when inserted via string concatenation. An attacker could potentially bypass validation, or validation might miss edge cases.

**Source:** OWASP SQL Injection Prevention Cheat Sheet - "Validated data is not necessarily safe to insert into SQL queries via string building."

---

### Answer 6:
**Part 1:** Both parameters are equally dangerous in terms of impact (can retrieve all data). However, `max_price` (numeric, no quotes) is slightly easier to exploit because it doesn't require quote escaping.

**Part 2:** Payload: `electronics' OR 1=1--`
- Results in: `SELECT * FROM products WHERE category = 'electronics' OR 1=1--' AND price <= 500`
- The `OR 1=1` makes the condition always true, returning all products

**Part 3:** The developer is wrong. Even if `category` uses prepared statements, `max_price` remains vulnerable because it's concatenated directly into the query. An attacker could inject: `500 OR 1=1--` to bypass the price filter.

**Key lesson:** ALL parameters must use prepared statements, not just string parameters.

**Source:** OWASP SQL Injection Prevention Cheat Sheet - Defense Option 1 must be applied to all user inputs.

---

### Answer 7:
**Part 1:** Defense Option 4: Escaping User Input (specifically, attempting to remove dangerous characters)

**Part 2:** Escaping is unreliable because:
- It's database-specific (different databases have different escaping rules)
- Easy to miss edge cases
- Not guaranteed to work in all situations

While it's difficult to bypass the specific filter shown (which removes single quotes), the approach is fundamentally flawed because it depends on anticipating all dangerous characters rather than using a safe API.

**Part 3:** 
```python
username = request.form.get('username')
query = "SELECT * FROM users WHERE username = ?"
user = db.execute(query, (username,))
```

**Part 4:** Allow-list input validation (Defense Option 3) as a secondary defense.

**Source:** OWASP SQL Injection Prevention Cheat Sheet - "This methodology is frail compared to other defenses, and we CANNOT guarantee that this option will prevent all SQL injections in all situations."

---

### Answer 8:
**Part 1:** Test 2 proves SQL injection vulnerability exists (unexpected behavior - shows all products).

**Part 2:** The `OR 1=1` clause makes the WHERE condition always true, so the query returns all products instead of just laptops.

**Part 3:** Most database configurations don't allow stacked queries (multiple SQL statements separated by semicolons in a single query execution). Only the first statement executes, so the DROP TABLE command is never reached.

**Source:** PortSwigger SQL Injection Guide mentions stacked queries are database-dependent and often disabled.

---

### Answer 9:
**Part 1:** Snippets A and C are vulnerable.
- Snippet A: String concatenation with `+`
- Snippet C: f-string interpolation despite input validation

**Part 2:** Input validation is a secondary defense, not sufficient as primary defense. Even though the input is validated, it's still inserted via string concatenation, which is inherently unsafe. If validation is ever bypassed or modified, the vulnerability returns.

**Part 3:** Yes, both are equally safe. Snippet D constructs the parameter value using an f-string (`f"%{search}%"`), but this operates on the PARAMETER, not the SQL query. The query structure remains fixed (`LIKE ?`), and the database treats the entire value (including % wildcards) as data, not code.

**Source:** OWASP SQL Injection Prevention Cheat Sheet - Input validation should be used alongside prepared statements, not instead of them.

---

### Answer 10:
**Part 1:** Endpoint 2 is vulnerable (uses f-string interpolation without prepared statements).

**Part 2:** Payload: `1 OR 1=1--` (note: no quotes needed because the parameter isn't wrapped in quotes)
- Results in: `SELECT * FROM products WHERE id = 1 OR 1=1--`

**Part 3:** Defense-in-depth provides multiple layers of protection:
- If prepared statements have an implementation bug, validation catches it
- Validates input early (fail fast principle)
- Prevents unexpected data types from reaching the database
- Adds resilience against future code changes

Even though prepared statements alone are sufficient, the extra validation layer adds robustness.

**Source:** OWASP principle of defense-in-depth - multiple layers provide better security than single defenses.

---

### Answer 11:
**Part 1:** Endpoints A and D require quote characters in payloads (A uses single quotes `'`, D uses double quotes `"`).

**Part 2:** Payload: `1 OR 1=1--` (no quotes needed)

**Part 3:** Payload: `admin' OR 1=1--` (single quote needed to escape)

**Part 4:** Endpoint A wraps the parameter in single quotes, so the payload must include `'` to close the opening quote. Endpoint B has no quotes around the parameter (numeric context), so the payload doesn't need quote escaping.

**Key principle:** String parameters with quotes require quote escaping; numeric parameters without quotes don't.

**Source:** PortSwigger SQL Injection - Different injection techniques for different parameter types.

---

### Answer 12:
**Part 1:** Defense Option 1 (Prepared Statements) and Defense Option 3 (Allow-list Input Validation using `isdigit()`)

**Part 2:** Yes, prepared statements alone are sufficient to prevent SQL injection. The database treats all input as data, not code, regardless of content. However, OWASP recommends adding validation as a secondary defense for defense-in-depth.

**Part 3:** Yes, this is the correct order. Validate input early (fail fast), then perform database operations. This prevents invalid data from reaching the database and provides better error messages.

**Source:** OWASP SQL Injection Prevention Cheat Sheet - "Input validation is also recommended as a secondary defense in ALL cases."

---

## Broken Access Control - Answers

### Answer 13:
**Part 1:** Vulnerability B is horizontal privilege escalation (accessing resources of another user at the same privilege level).

**Part 2:** Vulnerability A is vertical privilege escalation (gaining higher privileges - user becoming admin).

**Part 3:** 
- **Horizontal:** Same privilege level, different user (neighbor's mailbox)
- **Vertical:** Higher privilege level (customer becoming employee)

**Source:** OWASP Top 10 2021 A01 - "Elevation of privilege. Acting as a user without being logged in or acting as an admin when logged in as a user."

---

### Answer 14:
**Part 1:** Implementation B follows "deny by default" correctly.

**Part 2:** Implementation A allows access by default (starts with `allowed = True`). Any edge case or new scenario not covered by if statements defaults to granting access. Implementation B denies by default (returns `False` unless explicitly authorized).

**Part 3:** Example: If a new user role like "contractor" is added without updating Implementation A, contractors would get full access by default because they're not explicitly blocked.

**Source:** OWASP Top 10 2021 A01 - "Deny by default. Access should be denied by default unless explicitly granted."

---

### Answer 15:
**Endpoint 2** has a critical flaw: **missing authentication and authorization entirely**. 

- **Vulnerability type:** Missing access control enforcement
- **Impact:** Anyone (even anonymous users) can access `/api/admin/users` and retrieve all user data from the database without any login or role verification
- **This is broken access control (A01)** because there's no authentication check (is user logged in?) and no authorization check (does user have admin role?)

**Source:** OWASP Top 10 2021 A01 - Access control must be enforced on the server side.

---

### Answer 16:
**Part 1:** Insecure Direct Object Reference (IDOR) under Broken Access Control (A01).

**Part 2:** Two missing checks:
1. **Authentication:** No check if user is logged in
2. **Authorization:** No check if logged-in user owns the order (no ownership verification)

**Part 3:** No, parameterized queries prevent SQL injection (A03), not access control vulnerabilities (A01). These are separate security concerns. SQL injection prevention ≠ Access control. Both defenses are needed.

**Source:** OWASP Top 10 2021 A01 covers IDOR as a common access control vulnerability.

---

### Answer 17:
**Part 1:** Missing checks:
1. Authentication (is user logged in?)
2. Authorization (does user own this document?)

**Part 2:** Security checks should be added in this order:
1. First: Check authentication (verify user is logged in)
2. Second: Check authorization (verify user owns the document)
3. Third: Perform the deletion

This follows "fail securely" - deny access as early as possible.

**Part 3:** IDOR (Insecure Direct Object Reference) - anyone can delete any document by changing the `doc_id` parameter.

**Source:** OWASP Top 10 2021 A01 - Proper access control requires both authentication and authorization checks.

---

### Answer 18:
**Part 1:** Endpoint 1 has an IDOR vulnerability.

**Part 2:** Missing authorization check: The code should verify `user.account_id == account_id` before returning the balance.

**Part 3:** Authentication verifies WHO you are (logged in), but authorization verifies WHAT you can access. Endpoint 1 checks authentication but not authorization, allowing any logged-in user to access any account's balance by changing the `account_id` parameter.

**Source:** OWASP Top 10 2021 A01 - Authentication ≠ Authorization. Both are required.

---

### Answer 19:
**Part 1:** Implementation B has better security check ordering.

**Part 2:** Implementation A has an IDOR vulnerability: An attacker can check if another user has less than a given amount of money by testing the balance check before authentication/authorization. This is information disclosure.

**Part 3:** Authentication and authorization checks should come first (fail securely) to prevent unauthorized users from accessing sensitive business logic like balance information. Checking balance before verifying ownership exposes account balance data to attackers.

**Principle:** Fail securely - deny access as early as possible before processing sensitive data.

**Source:** OWASP Top 10 2021 A01 - Security checks should be performed in the correct order.

---

### Answer 20:
**Part 1:** Approach 1 is acceptable if profiles should be public.

**Part 2:** Approach 2 correctly implements private profiles (users can only view their own profile).

**Part 3:** Approach 3 has an IDOR vulnerability. It checks authentication but not authorization. Any logged-in user can view any profile by changing the username parameter. This violates the principle of "least privilege" or more precisely, it's missing authorization enforcement.

**Source:** OWASP Top 10 2021 A01 - Authorization checks must verify resource ownership, not just authentication.

---

## Cryptographic Failures - Answers

### Answer 21:
**Two critical weaknesses:**

**Weakness 1: Not using a password-based key derivation function (KDF)**
- MD5 is a fast hash function designed for checksums, not passwords
- Can compute billions of MD5 hashes per second on modern GPUs
- Makes brute-force attacks trivial

**Weakness 2: Not using a salt**
- Identical passwords produce identical hashes
- Vulnerable to rainbow table attacks (pre-computed hash tables)
- Pattern recognition - duplicate hashes reveal users with same password
- One crack compromises multiple accounts

**Why dangerous:** An attacker who steals the database can quickly crack passwords using rainbow tables or GPU-accelerated brute force.

**Source:** OWASP Top 10 2021 A02 - "Use of weak or deprecated cryptographic algorithms, particularly for password hashing (e.g., MD5, SHA1)"

---

### Answer 22:
**Part 1:** Developer A is wrong because **MD5 is a hash function, not an encryption algorithm**. Hashing is one-way (cannot be reversed). To process payments, you need the actual credit card number, which means you must be able to decrypt it. Hashing credit cards makes them permanently unusable.

**Part 2:** Developer B's approach (encryption) requires key management. The encryption key must be stored somewhere accessible to the application, creating risk. If an attacker breaches the database AND gets the encryption key, all credit cards are compromised. Additionally, storing credit cards (even encrypted) requires expensive PCI-DSS compliance.

**Part 3:** Developer C's approach (tokenization) is best because:
- You don't store credit card data at all (it's stored by the payment processor)
- If your database is breached, tokens are useless without access to the processor's systems
- The payment processor handles PCI compliance
- Tokens can be revoked if compromised

**Source:** OWASP Top 10 2021 A02 covers sensitive data protection and recommends not storing sensitive data when possible.

---

### Answer 23:
**Part 1:** All three configurations have cryptographic failures.

**Part 2:** Using HTTPS only for login is insufficient because attackers can still intercept traffic after login. Session cookies, patient records, and all data sent over HTTP (after login) can be sniffed by attackers on the network (Man-in-the-Middle attack).

**Part 3:** Failing to validate SSL certificates enables Man-in-the-Middle (MITM) attacks. An attacker on the network (e.g., public WiFi) can present their own fake certificate, intercept the connection, and read/modify all traffic between app and server.

**Part 4:** 
- Config 1: Enforce HTTPS for entire session, not just login page
- Config 2: Make reset tokens short-lived (15-30 min), single-use, AND ensure reset page uses HTTPS
- Config 3: Enforce proper SSL certificate validation; consider certificate pinning for additional security

**Source:** OWASP Top 10 2021 A02 - "Is data transmitted in clear text?"

---

### Answer 24:
**Part 1:** Configuration A fails to encrypt data in transit (credentials sent over HTTP). This is cryptographic failure because sensitive data (passwords) are transmitted unencrypted.

**Part 2:** Configuration B has two issues: database connection without TLS (data in transit not encrypted between app and database), and hardcoded database credentials in source code (secrets management issue).

**Part 3:** 
- Config A: Use HTTPS for all pages, especially login
- Config B: Enable TLS/SSL for database connections (`ssl: True`), and use environment variables or secrets manager (AWS Secrets Manager, HashiCorp Vault) for credentials instead of hardcoding

**Source:** OWASP Top 10 2021 A02 - "Is data transmitted in clear text? This concerns protocols such as HTTP, SMTP, FTP also using TLS upgrades like STARTTLS. External internet traffic is especially dangerous. Verify all internal traffic, e.g., between load balancers, web servers, or back-end systems."

---

### Answer 25:
**Part 1:**
- Data Type 1: Hashing (only need to verify, never retrieve)
- Data Type 2: Encryption (need to retrieve for insurance processing)
- Data Type 3: Hashing (only need to verify integrity, never reverse)

**Part 2:** SHA-256 with salt is better than plain SHA-256 because salt ensures unique hashes even for identical passwords (prevents rainbow tables). However, SHA-256 is still not ideal because:
- Too fast (billions of hashes/sec on GPUs)
- Not a password-based KDF
- Cannot increase work factor as hardware improves

Use Argon2, bcrypt, or PBKDF2 instead (deliberately slow, adaptive work factors).

**Part 3:** HTTPS (TLS/SSL encryption) should protect all data transmitted over the network between client and server.

**Source:** OWASP Top 10 2021 A02 and OWASP Password Storage Cheat Sheet.

---

### Answer 26:
**Part 1:** Use hashing. Server only needs to verify the user knows the password during login authentication. Never needs to retrieve the original password.

**Part 2:** Use encryption. The email must be decrypted and displayed on the user's profile page. Encryption protects the email if the database is compromised, while still allowing retrieval.

**Part 3:** Use encryption. The application needs to retrieve API keys to make external API calls. Encryption protects keys if database is compromised while still allowing the application to use them.

**Part 4:** Key question: **"Do I need to retrieve the original data later?"**
- If YES → Use encryption (reversible)
- If NO (only verify/compare) → Use hashing (one-way)

**Source:** Fundamental cryptography principles - hashing for verification, encryption for confidential storage.

---

### Answer 27:
**Part 1:** Data Types A and B are correct (passwords → bcrypt hash, SSNs → encryption).

**Part 2:** Two problems with Data Type D:
1. Session tokens stored in plain text in database (if database is breached, all session tokens are stolen)
2. Should hash session tokens in database and compare hashes during validation

**Part 3:** HTTPS protects session tokens as data in transit from Man-in-the-Middle (MITM) attacks, where attackers on the network eavesdrop and steal data being transmitted between client and server.

**Source:** OWASP Top 10 2021 A02 and session management best practices.

---

## Comprehensive Security Reviews - Answers

### Answer 28:
**Part 1:** The vulnerable line is:
```python
post = db.execute(f"SELECT * FROM posts WHERE id = {post_id}")
```
This uses f-string interpolation (string concatenation) without prepared statements.

**Part 2:** No, the function is not safe overall. Even though the INSERT statement uses prepared statements, the SELECT query for checking post existence is still vulnerable to SQL injection via the `post_id` parameter.

**Part 3:** Missing authentication check. There's no verification that the user submitting the comment is logged in or is who they claim to be. An attacker can impersonate any username when posting comments.

**Part 4:** A02 - Cryptographic Failures (data transmitted unencrypted over HTTP).

**Source:** OWASP Top 10 2021 - Multiple categories can be violated in a single endpoint.

---

### Answer 29:
**Part 1:** Vulnerabilities by OWASP category:
- **A01 - Broken Access Control:** Missing authentication (no verification of current password before reset)
- **A02 - Cryptographic Failures:** MD5 is not a password KDF (use Argon2/bcrypt/PBKDF2 instead)
- **A02 - Cryptographic Failures:** HTTP instead of HTTPS (passwords transmitted unencrypted)
- **A03 - Injection:** SQL injection in SELECT query (f-string interpolation)

**Part 2:** The vulnerable line:
```python
query = f"SELECT * FROM users WHERE email = '{email}'"
```
Uses f-string interpolation instead of prepared statements.

**Part 3:** MD5 is not a password-based key derivation function. It's too fast (vulnerable to brute-force) and commonly used without salt (vulnerable to rainbow tables). Use Argon2 (preferred), bcrypt, or PBKDF2 instead.

**Part 4:** A02 - Cryptographic Failures (HTTP instead of HTTPS for password transmission).

**Source:** OWASP Top 10 2021 - comprehensive security reviews identify multiple vulnerabilities.

---

### Answer 30:
**Part 1:**
- Issue 1: A02 - Cryptographic Failures (HTTP instead of HTTPS)
- Issue 2: A02 - Cryptographic Failures (weak hashing without KDF or salt)
- Issue 3: A03 - Injection (SQL injection vulnerability)
- Issue 4: A01 - Broken Access Control (missing authorization/role verification)

**Part 2:** Issues 1 and 2 both relate to A02 (Cryptographic Failures).

**Part 3:** SQL injection in login is more dangerous because:
- Can reveal all usernames and password hashes for all users
- Can bypass authentication entirely (no account needed)
- Can modify data (change passwords, grant admin access)
- Product search SQLi only reveals product data (lower value target)

**Part 4:** This is debatable, but strong arguments can be made for:
- **Issue 3 (SQL injection):** Bypasses all authentication, can dump entire database, highest technical severity
- **Issue 4 (Access control):** Every registered user already has admin access, immediate widespread damage without exploitation needed

Both answers are valid depending on the scenario.

**Source:** OWASP Top 10 2021 - Understanding attack severity and impact.

---

### Answer 31:
**Part 1:** No, the code is not vulnerable to SQL injection. Both queries use prepared statements with parameterized queries (`?` placeholders).

**Part 2:** Missing authentication check. The endpoint doesn't verify:
1. Is the user logged in (session-based authentication)?
2. Does the logged-in user match the username in the request?

Anyone (even anonymous attackers) can change any user's password if they know/guess the old password.

**Part 3:** No, this won't work. The code compares plaintext `old_password` directly against the stored `password` (bcrypt hash). You cannot compare plaintext to hash directly. Should use:
```python
if bcrypt.checkpw(old_password.encode(), stored_hash):
	# Password matches
```

**Part 4:** The most serious flaw is missing session-based authentication. There's no check that the request comes from a logged-in user, or that the logged-in user matches the username parameter. This is a fundamental access control failure (A01).

**Source:** OWASP Top 10 2021 A01 - Authentication and authorization must be properly implemented.

---

## Defense in Depth & Security Principles - Answers

### Answer 32:
Prepared statements prevent SQL injection by **separating code from data**.

**Vulnerable approach (string concatenation):**
- User input is mixed into the SQL query string
- Database cannot tell where YOUR code ends and USER data begins
- Input like `' OR '1'='1'--` is interpreted as SQL code

**Safe approach (prepared statements):**
- Query structure is defined first (with `?` placeholders)
- User input is sent separately as parameters
- Database knows these are separate things
- The database treats parameters as DATA only, never as CODE
- Even if input contains `' OR '1'='1'--`, the entire string is treated as a literal value to search for

**Key principle:** Parameterized queries make it impossible for user input to become code, no matter what characters they include.

**Source:** OWASP SQL Injection Prevention Cheat Sheet - "This coding style allows the database to distinguish between code and data, regardless of what user input is supplied."

---

### Answer 33:
**Part 1:**
- **Authentication:** Verifying WHO you are (username/password, tokens, biometrics) - "Who are you?"
- **Authorization:** Verifying WHAT you can access (permissions, roles, access control) - "What can you do?"
- Example: Authentication confirms you're user "John"; Authorization checks if John can delete files

**Part 2:** This is incorrect because authentication ≠ authorization. Checking if users are logged in (authentication) doesn't verify what they're allowed to do (authorization). The API needs to implement "deny by default" - explicitly check if the logged-in user is authorized to perform each specific action on each specific resource.

**Part 3:** IDOR = Insecure Direct Object Reference. Example: URL like `/api/user/123/profile` allows accessing user 123's profile by changing the ID parameter, without verifying if the current user owns that profile.

**Source:** OWASP Top 10 2021 A01 covers these fundamental access control concepts.

---

### Answer 34:
**Part 1:** Measure 1 protects data in transit (HTTPS encrypts data traveling over the network).

**Part 2:** Measures 2 and 3 protect data at rest (bcrypt hashes and AES-256 encryption protect data stored in the database).

**Part 3:** Measures 1 and 3 use encryption (reversible):
- HTTPS uses TLS/SSL encryption (can decrypt at destination)
- AES-256 is encryption (can decrypt with key)

**Part 4:** Measure 2 uses hashing (one-way):
- bcrypt is a hash function (cannot reverse to get original password)

**Part 5:**
- **Data in transit:** Data traveling over a network (browser→server, app→database) - vulnerable to network sniffing
- **Data at rest:** Data stored in database, disk, or backup - vulnerable when storage is compromised

**Source:** OWASP Top 10 2021 A02 covers data protection for both transit and rest.

---

### Answer 35:
**Part 1:** Security Layer 1 (Prepared statements) is Defense Option 1.

**Part 2:** Security Layer 2 (Alphanumeric validation) is Defense Option 3 (Allow-list Input Validation).

**Part 3:** Security Layer 4 (HTTPS) addresses A02 Cryptographic Failures (protects data in transit, not SQL injection).

**Part 4:** Yes, the application would still be vulnerable to SQL injection. Input validation (Layer 2) is not sufficient as primary defense. Length limits (Layer 3) don't prevent SQL injection syntax. HTTPS (Layer 4) protects different attack vector. Only prepared statements (Layer 1) truly prevent SQL injection by treating all input as data.

**Source:** OWASP SQL Injection Prevention Cheat Sheet - "Input validation is also recommended as a secondary defense... Validated data is not necessarily safe to insert into SQL queries via string building."

---

### Answer 36:
**Part 1:** Versions 2 and 3 use prepared statements (Defense Option 1).

**Part 2:** Version 3 is most secure because it uses both Defense Option 1 (Prepared Statements) as primary defense AND Defense Option 3 (Allow-list Input Validation) as secondary defense. This is defense-in-depth.

**Part 3:** Escaping (Defense Option 4) is the least reliable because:
- Database-specific (different databases have different escaping rules)
- Not guaranteed to work in all situations
- Easy to miss edge cases
- OWASP states: "we CANNOT guarantee that this option will prevent all SQL injections"

**Part 4:** Version 3 uses:
1. Prepared Statements (Defense Option 1) - primary defense
2. Allow-list Input Validation (Defense Option 3) - secondary defense

Defense-in-depth is better because if one defense fails or has a bug, the other provides backup protection. Input validation alone is not sufficient (can be bypassed), but adding it alongside prepared statements provides robustness.

**Source:** OWASP SQL Injection Prevention Cheat Sheet covers all four defense options and recommends layered security.

---

### Answer 37:
**Part 1:** IDOR typically has higher frequency - it's easier for developers to miss authorization checks than to write vulnerable SQL queries.

**Part 2:** SQL injection typically has higher impact per successful exploitation - one query can dump entire database.

**Part 3:** Key difference:
- **SQL injection:** Low frequency, high impact (entire database at once)
- **IDOR:** Higher frequency, lower impact (one record at a time, must iterate)

**Source:** OWASP Top 10 2021 discusses relative frequencies and impacts of different vulnerability types.

---

### Answer 38:
**Part 1:** No, this is not vulnerable to SQL injection. The query uses parameterized queries (`?` placeholder) which is Defense Option 1.

**Part 2:** Missing checks:
1. **Authentication:** No check if user is logged in
2. **Authorization:** No check if logged-in user owns the cart

**Part 3:** Impact: Attacker can checkout other users' carts, charging arbitrary amounts to the payment method. Classic IDOR vulnerability with financial impact.

**Source:** OWASP Top 10 2021 A01 - Missing authentication and authorization in critical business logic.

---

### Answer 39:
**Part 1:** Two weaknesses:
1. MD5 is not a password-based key derivation function (too fast for GPUs)
2. No salt used (identical passwords produce identical hashes)

**Part 2:** Without salt, identical passwords produce identical hashes, enabling:
- Rainbow table attacks (pre-computed hash tables)
- Pattern recognition (duplicate hashes reveal users with same password)
- One password crack compromises multiple accounts

**Part 3:** Use Argon2 (preferred), bcrypt, or PBKDF2 - these are password-based KDFs designed to be slow and include automatic salt handling.

**Source:** OWASP Top 10 2021 A02 and OWASP Password Storage Cheat Sheet.

---

### Answer 40:
**Part 1:** Team Member C is correct. bcrypt and Argon2 are purpose-built password hashing functions.

**Part 2:** SHA-256 is too fast - can compute billions of hashes per second on GPUs, making brute-force attacks feasible. It's designed for checksums and integrity, not password storage.

**Part 3:** bcrypt and Argon2 are better because:
- Deliberately slow (memory-hard, computationally expensive)
- Adjustable work factor (can increase difficulty as hardware improves)
- Built-in salt handling
- Designed specifically to resist brute-force attacks

**Source:** OWASP Top 10 2021 A02 recommends password-based KDFs.

---

### Answer 41:
**Part 1:** Implementation B follows "deny by default" (returns `False` at the end).

**Part 2:** Implementation A exploitation: Any new file sharing feature (e.g., "shared with team members") would default to allowing access because the final `return True` catches all unhandled cases.

**Part 3:** Logical bug: If `file.is_deleted` is True, the function returns False immediately, even if the owner tries to access it. The check order should be: owner/admin checks first, THEN deleted check, OR allow owners to access deleted files for recovery.

**Source:** OWASP Top 10 2021 A01 - Deny by default principle.

---

### Answer 42:
**Part 1:** Vulnerabilities:
- **GET endpoint:**
  - A03 - Injection (SQL injection in query using f-string)
- **POST endpoint:**
  - A01 - Broken Access Control (no authentication, attacker can impersonate any user_id)
- **Both endpoints:**
  - A02 - Cryptographic Failures (HTTP instead of HTTPS)

**Part 2:** GET endpoint has SQL injection via `post_id` parameter. Exploit: `/post/1 OR 1=1--/comments` could return all comments.

**Part 3:** POST endpoint allows anyone to submit comments as any `user_id` (no authentication check that logged-in user matches the submitted user_id).

**Part 4:** HTTP means comment content transmitted in plaintext - network attackers can read/modify comments, and session tokens (if any) can be stolen.

**Source:** OWASP Top 10 2021 - Multiple vulnerabilities often coexist in real applications.

---

### Answer 43:
**Part 1:** All three configurations have cryptographic failures.

**Part 2:** Config 1: Email sent without TLS encryption - attackers on the network can intercept reset tokens in transit.

**Part 3:** Config 2: Hash the token before storing (like session tokens). Store the hash in database, compare hash during validation. This protects tokens if database is compromised.

**Part 4:** Config 3: HTTP enables Man-in-the-Middle (MITM) attacks where attackers intercept the reset token from the URL.

**Source:** OWASP Top 10 2021 A02 - Protect sensitive data in transit and at rest.

---

### Answer 44:
**Part 1:** Tests 2 and 3 both prove SQL injection. Test 2 shows error-based detection, Test 3 shows successful exploitation.

**Part 2:** The query likely uses string concatenation: `SELECT * FROM users WHERE username = '{username}' AND password = '{password}'`. The payload `admin' OR 1=1--` closes the username quote, adds always-true condition, and comments out password check.

**Part 3:** Error messages reveal SQL syntax, table structure, and database type, helping attackers craft more targeted exploits. This is information disclosure.

**Part 4:** Log errors server-side for debugging but show users generic messages like "An error occurred." Never expose SQL syntax, table names, or database errors.

**Source:** OWASP Top 10 2021 A02 covers sensitive information exposure through error messages.

---

### Answer 45:
**Part 1:** Yes, proper authentication exists - the endpoint checks if user is logged in with `get_current_user()`.

**Part 2:** Yes, proper authorization exists - the endpoint checks both public sharing status AND ownership before allowing access.

**Part 3:** No security issues in the authorization logic shown. This is a well-implemented access control that follows proper deny-by-default principles (returns 403 if no conditions match).

**Source:** OWASP Top 10 2021 A01 - This demonstrates correct access control implementation.

---

### Answer 46:
**Part 1:** Defense A and Defense C use Defense Option 1 (Prepared Statements with `?` placeholders).

**Part 2:** Defense B and Defense C use Defense Option 3 (Allow-list Input Validation).

**Part 3:** Defense B is NOT secure despite allow-list validation. Validated data inserted via string concatenation is still vulnerable if:
- Validation is bypassed or modified in the future
- Edge cases exist in validation logic
The primary defense should be prepared statements, with validation as secondary defense.

**Part 4:** Defense C benefits:
- Validation catches invalid input early (fail fast)
- Prepared statements provide guaranteed SQL injection protection
- If either defense fails, the other provides backup
- Defense-in-depth creates resilient security

**Source:** OWASP SQL Injection Prevention Cheat Sheet - "Validated data is not necessarily safe to insert into SQL queries via string building."

---

### Answer 47:
**Part 1:** Session tokens should be **hashed** before storing. Store hash in database, compare hash during validation. This protects if database is compromised (stolen hashes can't be used directly).

**Part 2:** CVV codes should **NEVER be stored** (not hashed, not encrypted, not anything). PCI-DSS explicitly forbids storing CVV after transaction authorization.

**Part 3:** Profile pictures typically don't need encryption at rest (they're meant to be displayed publicly). However, consider encryption if:
- They contain sensitive content (medical images)
- Privacy regulations require it (GDPR in some cases)
- Application explicitly promises privacy

**Part 4:** API keys should be **encrypted** (not hashed) because the application needs to retrieve and use them for external API calls. Encryption allows retrieval while protecting keys if database is compromised.

**Source:** OWASP Top 10 2021 A02 and PCI-DSS standards.

---

### Answer 48:
**Part 1:**
- Vulnerability A: A03 - Injection (SQL injection)
- Vulnerability B: A01 - Broken Access Control (IDOR)
- Vulnerability C: A02 - Cryptographic Failures (weak password hashing)
- Vulnerability D: A02 - Cryptographic Failures (missing encryption in transit)

**Part 2:** Fix A and D immediately:
- **Vulnerability A (SQLi in admin login):** Bypasses authentication entirely, allows complete database compromise
- **Vulnerability D (no HTTPS on payment page):** Credit cards transmitted in plaintext, regulatory violations (PCI-DSS), immediate legal liability

**Part 3:** Vulnerability A (SQL injection) has highest exploitability - can be exploited with simple payloads, no special access needed.

**Part 4:** Vulnerability D (payment page over HTTP) has highest business impact - regulatory fines, payment processor could revoke ability to process cards, loss of customer trust, potential lawsuits.

**Source:** OWASP Top 10 2021 - Prioritization considers both exploitability and business impact.

---

### Answer 49:
**Part 1:** Endpoints A and D need quote characters (A uses `'`, D uses `"`).

**Part 2:** Endpoint B payload: `1 OR 1=1--` (no quotes needed - numeric parameter)

**Part 3:** Endpoint A payload: `admin' OR 1=1--` (single quote needed to close string)

**Part 4:** Endpoint A wraps parameter in quotes, requiring quote escape. Endpoint B has no quotes (numeric context), so payload uses numbers directly without quote escaping.

**Key principle:** String parameters need quote escaping; numeric parameters don't.

**Source:** PortSwigger SQL Injection - Different techniques for different parameter types.

---

### Answer 50:
**Part 1:** Two Defense Options:
- Defense Option 1: Prepared Statements (parameterized query with `?`)
- Defense Option 3: Allow-list Input Validation (`isdigit()` check)

**Part 2:** Yes, prepared statements alone provide complete SQL injection protection. The database treats all input as data, not code, regardless of content.

**Part 3:** Benefits of defense-in-depth:
- Validation fails fast (early rejection of invalid input)
- If prepared statements have implementation bug, validation catches it
- Better error messages for users
- Protects against future code changes

**Source:** OWASP SQL Injection Prevention Cheat Sheet - Prepared statements are sufficient, validation adds robustness.

---

### Answer 51:
**Part 1:** No SQL injection - both queries use prepared statements with parameterized queries (`?` placeholders).

**Part 2:** Missing **session-based authentication**:
- No check if user is logged in
- No check if logged-in user matches username parameter
Anyone can change any user's password if they guess/know the old password.

**Part 3:** No, this won't work. Cannot compare plaintext directly to bcrypt hash. Must use:
```python
if bcrypt.checkpw(old_password.encode(), stored_hash):
	# Password matches
```

**Part 4:** Most serious flaw: **Missing authentication** (A01 - Broken Access Control). The endpoint doesn't verify the request comes from a logged-in user, or that the logged-in user matches the username. This is a fundamental access control failure allowing anyone to change anyone's password.

**Source:** OWASP Top 10 2021 A01 - Authentication and authorization must be properly implemented.

---

## 🎉 Congratulations on Completing the Quiz!

If you found this helpful, please:

⭐ **[Star the AppSec-Exercises repository](https://github.com/fosres/AppSec-Exercises)** to support more free security content

📚 **Follow for more quizzes** covering Week 2-28 of AppSec curriculum

🚀 **Share with others** preparing for AppSec interviews

---

**Good luck with your interviews!** 🔒
