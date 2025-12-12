---
series: AppSec Series
---

# OWASP Top 10 2025 Quiz: Are You Interview-Ready?

**Time to complete:** 90-120 minutes  
**Difficulty:** Intermediate to Advanced  
**Topics:** A01 Broken Access Control, A04 Cryptographic Failures, A05 Injection

---

## Why This Matters for Your AppSec Career

If you're interviewing for Application Security Engineer roles you'll face questions about the OWASP Top 10. Not just "What is it?" but deep, practical questions like:

- "Why does this code have an IDOR vulnerability?"
- "What's wrong with this password hashing implementation?"
- "When can ORMs still introduce SQL injection?"

This quiz contains **51 real interview-style questions** based on the **OWASP Top 10 2025 Release Candidate**.

**What you'll practice:**
- 🔐 Access control concepts (IDOR, privilege escalation, "deny by default")
- 🔑 Cryptographic failures (weak algorithms, IV management, KDFs)
- 💉 Injection vulnerabilities (SQL injection, XSS, context-specific defenses)
- 🛡️ Prevention techniques actually used in production

**After completing this quiz, you'll be able to:**
- Answer 80%+ of OWASP Top 10 questions in AppSec interviews
- Identify access control vulnerabilities in code reviews
- Explain cryptographic best practices with confidence
- Understand when "safe" libraries can still be misused

---

## How to Use This Quiz

1. **Read each question carefully** - many test subtle distinctions
2. **Write down your answers** before checking the solutions
3. **Don't peek at answers!** The learning happens when you struggle
4. **Check your work at the bottom** - detailed explanations included
5. **Track weak areas** - questions you miss reveal what to study

**Scoring guide:**
- 45-51 correct (88%+): Interview-ready! 🎯
- 38-44 correct (75-86%): Strong foundation, study weak areas
- 30-37 correct (59-74%): Good start, review OWASP docs
- Below 30 (58%-): Study OWASP Top 10 2025 thoroughly first

---

## The Questions

### 📋 Section 1: A05 - Injection Fundamentals

**Question 1:**
According to OWASP Top 10 2025 A05, what is the **preferred defense option** to prevent injection attacks?

**Question 2:**
You're reviewing code and see this:
```java
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery();
```
The application URL is: `https://example.com/app/accountInfo?acct=12345`

What vulnerability is this (according to OWASP Top 10 2025 A01 Scenario #1), and how could an attacker exploit it?

**Question 5:**
OWASP Top 10 2025 A05 states that injection affects **100% of tested applications**. It distinguishes between:
- **Cross-site Scripting (XSS)**: high frequency / low impact
- **SQL Injection**: low frequency / high impact

Explain why SQL injection has "low frequency" but "high impact" compared to XSS.

**Question 10:**
OWASP Top 10 2025 A05 mentions that **stored procedures** can still introduce SQL injection vulnerabilities even when parameterized. Under what condition do stored procedures remain vulnerable?

**Question 16:**
According to OWASP Top 10 2025 A05, when you cannot use parameterized queries or a safe API, what technique should you use to reduce injection threats?

**Question 27:**
OWASP Top 10 2025 A05 states that XSS has **30,000+ CVEs** while SQL injection has **14,000+ CVEs**. Given that XSS has more than double the CVEs, why is SQL injection characterized as "low frequency"?

**Question 36:**
OWASP Top 10 2025 A05 includes 37 CWEs covering many types of injection beyond SQL injection. Name **TWO** other types of injection vulnerabilities mentioned in the A05 CWE list.

**Question 45:**
**True or False:** "ORMs (like SQLAlchemy, Django ORM) are 100% safe from SQL injection and can never introduce SQL injection vulnerabilities."

If false, explain when ORMs can still be vulnerable.

**Question 48:**
A developer asks: "I'm using Python's `input()` function to get user data and then using it in a SQL query with parameterized queries like this:
```python
user_id = input("Enter user ID: ")
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```
Is this safe from SQL injection?"

A) Yes, completely safe - parameterized queries prevent all SQL injection  
B) No, `input()` is never safe and allows injection  
C) Yes for SQL injection, but there might be other injection risks depending on context  
D) No, you need to use an ORM instead

**Question 51:**
OWASP Top 10 2025 A05 recommends: "Use positive server-side input validation."

What does "**positive**" validation mean (as opposed to negative validation)? Give an example.

---

### 🔐 Section 2: A01 - Broken Access Control Fundamentals

**Question 4:**
According to OWASP Top 10 2025 A01, why does implementing access control **only in the front-end (client-side JavaScript)** fail to protect an application? Give a concrete example from the OWASP documentation.

**Question 7:**
OWASP Top 10 2025 A01 recommends: **"Except for public resources, deny by default."**

What does this principle mean in practice? Give an example of how this would work in a web application.

**Question 9:**
An application puts all of their access control in their front-end. An attacker cannot access `https://example.com/app/admin_getappInfo` due to JavaScript restrictions, but they can execute:
```bash
curl https://example.com/app/admin_getappInfo
```
And successfully retrieve admin information. What is the root cause according to OWASP Top 10 2025 A01 Scenario #3?

**Question 11:**
Bob is logged in as a regular user. He discovers that by accessing:
`https://example.com/admin/deleteUser?userId=500`
He can delete user accounts, even though he's not an administrator.

This is an example of:
A) Horizontal privilege escalation (IDOR)  
B) Vertical privilege escalation (elevation of privilege)  
C) Authentication failure  
D) Session hijacking

**Question 13:**
A user changes the URL parameter from `?userId=123` to `?userId=456` and successfully views another user's private profile data. What is the specific name for this type of vulnerability according to OWASP Top 10 2025 A01?

**Question 15:**
OWASP Top 10 2025 A01 recommends: "Stateful session identifiers should be invalidated on the server after logout."

Why is server-side invalidation critical? What attack does this prevent?

**Question 17:**
User Alice (ID=100) accesses her profile: `https://example.com/profile?userId=100`

She changes the URL to: `https://example.com/profile?userId=200` and successfully views Bob's (ID=200) private profile.

This is an example of:
A) Vertical privilege escalation  
B) Horizontal privilege escalation (IDOR)  
C) Client-side access control bypass  
D) Authentication failure

**Question 19:**
Bob is logged in as a regular user. He discovers that by accessing:
`https://example.com/admin/deleteUser?userId=500`
He can delete user accounts, even though he's not an administrator.

This is an example of:
A) Horizontal privilege escalation (IDOR)  
B) Vertical privilege escalation (elevation of privilege)  
C) Authentication failure  
D) Session hijacking

**Question 21:**
According to OWASP Top 10 2025 A01, for stateless JWT tokens, what two security measures are recommended to minimize the window of opportunity for attackers?

**Question 22:**
According to OWASP Top 10 2025 A01, "Metadata manipulation" is listed as a common access control vulnerability. One specific example given is "replaying or tampering with a JSON Web Token (JWT) access control token." What does "tampering with a JWT" typically involve?

**Question 24:**
Complete this statement from OWASP Top 10 2025 A01: "CORS misconfiguration allows ____________"

**Question 25:**
According to OWASP Top 10 2025 A01, what is "force browsing"? Give a concrete example.

**Question 28:**
According to OWASP Top 10 2025 A01, when should access control failures be logged? And what additional action should be taken when appropriate (e.g., repeated failures)?

**Question 31:**
According to OWASP Top 10 2025 A01 prevention guidance, why should rate limits be implemented on API and controller access? What specific threat does this mitigate?

**Question 33:**
Fill in the blanks with the correct terms:

"__________ answers the question 'Who are you?' - it verifies your identity using passwords, tokens, or biometrics.

__________ answers the question 'What can you access?' - it determines your permissions and enforces access control policies like 'deny by default'."

**Question 34:**
A developer implements access control like this:
```python
@app.route('/api/user/<user_id>/profile')
def get_profile(user_id):
    user = db.query("SELECT * FROM users WHERE id = ?", user_id)
    if user:
        return jsonify(user)
    return "User not found", 404
```
What critical access control check is missing?

A) Authentication check (is user logged in?)  
B) Authorization check (should current user access this user_id?)  
C) Input validation (is user_id a valid format?)  
D) Rate limiting (prevent automated enumeration)

**Question 37:**
According to OWASP Top 10 2025 A01 prevention guidance, what should you do about web server directory listing? And what types of files should NOT be present within web roots?

**Question 39:**
OWASP Top 10 2025 A01 states: "Model access controls should enforce record ownership rather than allowing users to create, read, update, or delete any record."

What does "enforce record ownership at the model level" mean in practice?

**Question 40:**
According to OWASP Top 10 2025 A01 prevention guidance, which teams should include functional access control testing in their unit and integration tests?

A) Only the security team  
B) Only QA engineers  
C) Developers and QA staff  
D) Only penetration testers

**Question 42:**
OWASP Top 10 2025 A01 recommends: "Implement access control mechanisms once and reuse them throughout the application."

Why is it better to implement access control ONCE and reuse it, rather than implementing checks separately in each controller/endpoint? Give at least two reasons.

**Question 46:**
According to OWASP Top 10 2025 A01, one common access control vulnerability is "Violation of the principle of least privilege." Give a concrete code example of violating "least privilege" in an API endpoint.

---

### 🔑 Section 3: A04 - Cryptographic Failures

**Question 3:**
According to OWASP Top 10 2025 A04, the most common CWEs involve weak pseudo-random number generators. Name **one** of the four specific CWEs mentioned.

**Question 6:**
According to OWASP Top 10 2025 A04, when using **initialization vectors (IVs)** in encryption, what is a critical security requirement?

A) The IV must be stored in the same database table as the encrypted data  
B) The IV must never be used twice for a fixed key  
C) The IV must be exactly 256 bits long  
D) The IV must be encrypted before being stored

**Question 8:**
According to OWASP Top 10 2025 A04, which of the following hash functions are **deprecated** and should NOT be used?

A) SHA-256 and bcrypt  
B) MD5 and SHA1  
C) Argon2 and PBKDF2  
D) AES-256 and RSA-2048

**Question 12:**
According to OWASP Top 10 2025 A04, what's the difference between:
- **Encryption only** (e.g., AES in CBC mode)
- **Authenticated encryption** (e.g., AES-GCM)

Why does OWASP recommend authenticated encryption?

**Question 14:**
According to OWASP Top 10 2025 A04, when converting a password to an encryption key, what must you use?

A) Hash the password with SHA-256  
B) Encrypt the password with AES  
C) Use a password-based key derivation function (like PBKDF2, bcrypt, Argon2)  
D) Store the password in plaintext as the key

**Question 18:**
**True or False:** "According to OWASP Top 10 2025 A04, ECB (Electronic Codebook) mode is a secure mode of operation for block ciphers and is recommended for encrypting sensitive data."

If false, why is ECB problematic?

**Question 23:**
OWASP Top 10 2025 A04 states: "The first thing is to determine the protection needs of data in transit and at rest."

Which types of data require extra protection? Name at least 3 examples from the documentation.

**Question 26:**
You're storing user passwords in a database. According to OWASP Top 10 2025 A04 cryptographic best practices, which approach should you use?

A) Store passwords in plaintext for easy password recovery  
B) Hash passwords with SHA-256  
C) Encrypt passwords with AES-256  
D) Use adaptive password hashing (bcrypt, Argon2, PBKDF2)

**Question 29:**
**Statement:** "According to OWASP Top 10 2025 A04, if you must use an initialization vector (IV) with encryption, the IV needs to be generated with a CSPRNG (cryptographically secure pseudo-random number generator) for ALL cipher modes."

True or False? Explain your answer.

**Question 32:**
You're conducting a security assessment and discover:
- All HTTP traffic is unencrypted (using http:// not https://)
- User passwords are transmitted in plaintext
- Credit card numbers are sent without encryption

According to OWASP Top 10 2025 A04, what is the first question you should ask when determining protection needs?

**Question 35:**
According to OWASP Top 10 2025 A04, at which OSI layer should data in transit be encrypted? And what technology is commonly used at this layer for web applications?

**Question 38:**
According to OWASP Top 10 2025 A04, where should your "most sensitive keys" be stored?

A) In environment variables  
B) In a configuration file with restricted permissions  
C) In a hardware or cloud-based HSM (Hardware Security Module)  
D) Encrypted in the database

**Question 41:**
You're reviewing code and find this implementation:
```python
import hashlib

def store_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    db.store(hashed)
    return hashed
```
According to OWASP Top 10 2025 A04, identify at least TWO problems with this password storage approach.

**Question 44:**
You're reviewing this code that encrypts user data:
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def encrypt_data(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    db.store(ciphertext)  # IV is NOT stored!
    
    return ciphertext
```
According to OWASP Top 10 2025 A04 cryptographic principles, what critical mistake makes this data **unrecoverable**?

**Question 47:**
You're conducting a security assessment and discover the following data types:
- User email addresses
- Marketing preferences (newsletter yes/no)
- Credit card numbers (last 4 digits only)
- Full credit card numbers with CVV
- User's favorite color
- Social Security Numbers

According to OWASP Top 10 2025 A04, which of these require **extra protection** (encryption at rest)? Select all that apply.

---

### 🔍 Section 4: Integration & Advanced Topics

**Question 20:**
You're reviewing this stored procedure for SQL injection vulnerabilities:
```sql
CREATE PROCEDURE SearchUsers(@searchTerm varchar(100))
AS
BEGIN
    DECLARE @query varchar(500)
    SET @query = 'SELECT * FROM users WHERE name LIKE ''%' + @searchTerm + '%'''
    EXEC(@query)
END
```
According to OWASP Top 10 2025 A05, is this vulnerable to SQL injection? If yes, what specific line makes it vulnerable?

**Question 30:**
You're reviewing this Python Flask code:
```python
@app.route('/delete_user')
def delete_user():
    user_id = request.args.get('user_id')
    query = f"DELETE FROM users WHERE id = {user_id}"
    db.execute(query)
    return "User deleted"
```
This code has vulnerabilities from BOTH A01 (Broken Access Control) AND A05 (Injection). Identify one vulnerability from each category.

---

## 🎯 Check Your Answers

Ready to see how you did? Scroll down for detailed explanations...

*(Keep scrolling)*

*(Answers below)*

*(Don't peek yet!)*

---
---
---
---
---

## ✅ Answer Key & Explanations

### Section 1: A05 - Injection Fundamentals

**Answer 1:**
Use a safe API that avoids using the interpreter entirely, provides a parameterized interface, or migrates to Object Relational Mapping Tools (ORMs).

Source: OWASP Top 10 2025 A05 - "The preferred option is to use a safe API..."

---

**Answer 2:**
**Vulnerability:** Insecure Direct Object Reference (IDOR) under Broken Access Control

**Exploitation:** An attacker can modify the `acct` parameter (e.g., change `acct=12345` to `acct=67890`) to access any user's account information without authorization checks.

**Why it's vulnerable:** The code checks if the account exists but doesn't verify if the current user should have access to that account.

Source: OWASP Top 10 2025 A01 Scenario #1

---

**Answer 5:**
**SQL Injection - Low Frequency:**
- Modern frameworks use ORMs and parameterized queries by default
- Developers must explicitly write dangerous raw SQL
- SAST tools easily detect SQL concatenation patterns
- Result: Harder to introduce accidentally in modern codebases

**SQL Injection - High Impact:**
- Can compromise the entire database in one attack
- Dump all passwords, credit cards, personal data
- Potential for privilege escalation and OS command execution
- Affects ALL users simultaneously

**XSS - High Frequency:**
- Hundreds of potential injection points (search boxes, comments, profiles)
- Easy to introduce accidentally (forgot to encode one field)
- Context-dependent encoding is complex

**XSS - Low Impact (relatively):**
- Typically affects individual users one at a time
- Requires victims to visit the malicious page
- Can't directly access the database
- More limited attack scope per exploitation

The "frequency" refers to how often vulnerabilities are found in NEW applications being tested, not total historical CVE count.

---

**Answer 10:**
Stored procedures are vulnerable when they **internally concatenate strings** or use **dynamic SQL execution** (EXECUTE IMMEDIATE in Oracle, exec() in SQL Server).

Example vulnerable stored procedure:
```sql
DECLARE @sql varchar(200)
SET @sql = 'SELECT * FROM users WHERE id = ' + @userId  -- Concatenation!
EXEC(@sql)  -- Dynamic execution!
```

Even if the application calls the stored procedure safely with parameterized queries, the stored procedure itself concatenates user input into SQL strings.

Source: OWASP Top 10 2025 A05

---

**Answer 16:**
**Use positive server-side input validation.** However, this is NOT a complete defense as many applications require special characters.

You can also **escape special characters** as allowed by the interpreter, but both techniques are error-prone.

Key points:
- **Positive** (whitelist) validation - only allow known good patterns
- **Server-side** - never trust client-side validation
- **Not complete** - applications often need special characters (text areas, APIs)
- **Error-prone** - easy to miss edge cases

Source: OWASP Top 10 2025 A05

---

**Answer 27:**
SQL injection has "low frequency" because:

1. **Modern frameworks prevent it by default:**
   - ORMs (Django, Rails, SQLAlchemy) use parameterized queries
   - Developers must explicitly write dangerous raw SQL
   
2. **SAST tools detect it easily:**
   - Pattern matching for string concatenation with SQL
   - Static analysis catches before deployment
   
3. **Well-understood defense:**
   - Parameterized queries are standard practice
   - Extensive developer training on this vulnerability

XSS has "high frequency" because:
- Hundreds of injection points in typical applications
- Context-dependent encoding (HTML, JavaScript, attribute, URL, CSS)
- Harder for SAST to detect (depends on template engine settings)

The "frequency" refers to how often found in applications being tested today, not total CVEs across all history.

---

**Answer 36:**
Two examples from OWASP Top 10 2025 A05 CWE list:
- **CWE-79: Cross-Site Scripting (XSS)**
- **CWE-91: XML Injection (Blind XPath Injection)**

Other correct answers include:
- CWE-90: LDAP Injection
- CWE-88: Argument Injection (Command Injection)
- CWE-78: OS Command Injection
- CWE-917: Expression Language Injection

Source: OWASP Top 10 2025 A05 CWE list

---

**Answer 45:**
**FALSE**

ORMs can still introduce SQL injection when developers:
1. Use raw SQL with string concatenation instead of ORM's safe methods
2. Bypass ORM's parameterization features

Examples:

**Django (vulnerable):**
```python
User.objects.raw(f"SELECT * FROM users WHERE name = '{user_input}'")  # ❌
```

**SQLAlchemy (vulnerable):**
```python
session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))  # ❌
```

**Safe usage:**
```python
User.objects.raw("SELECT * FROM users WHERE name = %s", [user_input])  # ✓
session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})  # ✓
```

Source: OWASP Top 10 2025 A05

---

**Answer 48:**
**C) Yes for SQL injection, but there might be other injection risks depending on context**

The parameterized query (`?` placeholder with tuple) prevents SQL injection regardless of input source. However, the `user_id` data might be used elsewhere in the code:

- **Command injection risk:** If later used in `os.system(f"backup_user_{user_id}.sh")`
- **XSS risk:** If displayed in HTML without encoding
- **Path traversal:** If used in file operations

Defense-in-depth: validate input even when using parameterized queries.

Source: OWASP Top 10 2025 A05

---

**Answer 51:**
**Positive Validation (Whitelist):** Allow ONLY what you expect
```python
def validate_user_id(user_id):
    if user_id.isdigit() and 1 <= int(user_id) <= 999999:
        return True
    return False
```

**Negative Validation (Blacklist):** Block known bad patterns
```python
def validate_user_id(user_id):
    bad_chars = ["'", '"', ';', 'DROP', 'SELECT']
    for bad in bad_chars:
        if bad in user_id:
            return False
    return True
```

**Why positive is better:**
- Default deny - only allow explicitly permitted inputs
- Can't forget edge cases
- More secure against unknown attacks

**Why negative is worse:**
- Impossible to enumerate all bad inputs
- Attackers find creative bypasses

Source: OWASP Top 10 2025 A05

---

### Section 2: A01 - Broken Access Control Fundamentals

**Answer 4:**
Client-side access control fails because attackers can bypass browser restrictions entirely by making direct HTTP requests.

**OWASP Scenario #3 Example:**
An application blocks access to `https://example.com/app/admin_getappInfo` using JavaScript. The attacker simply runs:
```bash
curl https://example.com/app/admin_getappInfo
```
And successfully retrieves admin information.

**Why:** Client-side code (JavaScript) runs in the attacker's browser, which they fully control. They can use curl, Postman, Burp Suite, or any HTTP client to bypass frontend restrictions.

**Key principle:** "Access control is only effective when implemented in trusted server-side code or serverless APIs, where the attacker cannot modify the access control check or metadata."

Source: OWASP Top 10 2025 A01 Scenario #3

---

**Answer 7:**
**"Deny by default" means:** All resources are inaccessible by default unless explicitly granted permission.

**Example:**
```python
# ✅ GOOD - Deny by default
def get_user_data(user_id, current_user):
    # Default: DENY
    if current_user.id != user_id and not current_user.is_admin:
        return "Access denied"  # Denied by default!
    return database.get_user(user_id)

# ❌ BAD - Allow by default
def get_user_data(user_id):
    # Default: ALLOW (unless explicitly blocked)
    if user_id in BLOCKED_USERS:
        return "Access denied"
    return database.get_user(user_id)  # Anyone can access!
```

**In practice:**
- Public blog posts → Explicitly marked as public
- User profiles → Denied by default, only accessible if you own it OR are admin
- Admin dashboard → Denied by default, only accessible with explicit admin role grant

Source: OWASP Top 10 2025 A01

---

**Answer 9:**
**Root cause:** Access control is only implemented on the client-side (front-end) instead of the server-side.

The server serves the admin page to anyone who requests it - only the JavaScript tries to block it. When the attacker bypasses the browser (using curl), there's no server-side check to prevent access.

**Prevention:** "Access control is only effective when implemented in trusted server-side code or serverless APIs, where the attacker cannot modify the access control check or metadata."

Source: OWASP Top 10 2025 A01 Scenario #3

---

**Answer 11:**
**B) Vertical privilege escalation (elevation of privilege)**

Bob is a **regular user** (lower privilege) accessing **admin functionality** (delete users - higher privilege). He's elevating from user → admin capabilities, which is vertical movement up the privilege hierarchy.

**From OWASP A01:** "Elevation of privilege. Acting as a user without being logged in or acting as an admin when logged in as a user."

**Not horizontal:** Would be if Bob (user) accessed Alice's (user) profile - same privilege level.

Source: OWASP Top 10 2025 A01

---

**Answer 13:**
**IDOR (Insecure Direct Object Reference)**

This is the specific vulnerability name when users can manipulate object identifiers (like userId) to access other users' resources.

**Also correct (but more general):** Horizontal privilege escalation - accessing other users' data at the same privilege level.

**OWASP states:** "Permitting viewing or editing someone else's account by providing its unique identifier (insecure direct object references)"

Source: OWASP Top 10 2025 A01

---

**Answer 15:**
Server-side invalidation prevents **session replay attacks** and **session hijacking**.

**Why it's critical:**
Without server-side invalidation, even after a user logs out, the session token remains valid. If an attacker stole the token (via XSS, network sniffing, etc.), they can continue using it to impersonate the victim.

**Example:**
- User logs out at coffee shop
- Attacker captured session cookie earlier
- Without server-side invalidation: Attacker can still access the account
- With server-side invalidation: Token is marked invalid, attack fails

**Client-side only (insecure):**
```javascript
document.cookie = "sessionId=; expires=Thu, 01 Jan 1970"  // ❌ Token still valid on server!
```

**Server-side (secure):**
```python
sessions.delete(session_id)  # ✓ Server marks session invalid
```

Source: OWASP Top 10 2025 A01

---

**Answer 17:**
**B) Horizontal privilege escalation (IDOR)**

Alice and Bob are **same privilege level** (both regular users). Alice accesses Bob's data by **manipulating the identifier** (userId parameter). This is horizontal movement across same privilege level.

**From OWASP:** "Permitting viewing or editing someone else's account by providing its unique identifier (insecure direct object references)"

Source: OWASP Top 10 2025 A01

---

**Answer 19:**
**B) Vertical privilege escalation (elevation of privilege)**

Bob is a regular user accessing admin-level functionality (delete users), which is elevation to higher privilege.

**From OWASP:** "Elevation of privilege. Acting as a user without being logged in or acting as an admin when logged in as a user."

Source: OWASP Top 10 2025 A01

---

**Answer 21:**
Two security measures:

1. **JWT tokens should be short-lived** (e.g., 15-minute expiration) to minimize the window of opportunity if stolen

2. **For longer-lived JWTs, follow OAuth standards to revoke access** (implement server-side revocation capability)

**Why both are needed:**
- Short-lived: Natural expiration limits damage
- Revocation: Manual invalidation when needed (logout, password change, suspicious activity)

Source: OWASP Top 10 2025 A01

---

**Answer 22:**
**JWT tampering** involves modifying claims in the JWT payload to escalate privileges.

**Example:**
Original JWT payload:
```json
{
  "userId": "123",
  "role": "user",
  "exp": 1234567890
}
```

Attacker tampers to:
```json
{
  "userId": "123",
  "role": "admin",  ← Changed!
  "exp": 9999999999  ← Extended!
}
```

If the JWT signature isn't properly verified, the attacker gains admin access.

Source: OWASP Top 10 2025 A01

---

**Answer 24:**
"CORS misconfiguration allows API access from unauthorized or untrusted **origins**."

**Key term:** "origins" (not regions) - refers to web security concept (scheme + host + port)

**Example origins:**
- `https://example.com:443`
- `https://attacker.com:443`

**Attack scenario:**
```javascript
// Attacker's site: https://evil.com
fetch('https://yourbank.com/api/accounts', {
  credentials: 'include'  // Sends victim's cookies!
})
```

If CORS allows `https://evil.com`, attacker can steal data.

Source: OWASP Top 10 2025 A01

---

**Answer 25:**
**Force browsing** is guessing URLs to access authenticated pages as an unauthenticated user, or privileged pages as a standard user.

**Examples:**

**Unauthenticated access:**
```
User (not logged in) tries:
https://example.com/app/dashboard
https://example.com/app/settings
```

**Privilege escalation:**
```
Regular user tries:
https://example.com/admin/users
https://example.com/admin/deleteUser
```

It's called "force" browsing because attackers "force" their way by guessing/enumerating URLs using tools like DirBuster or Gobuster.

Source: OWASP Top 10 2025 A01

---

**Answer 28:**
**Log access control failures:** Always (every time a failure occurs)

**Alert admins when appropriate:** For repeated failures, patterns suggesting reconnaissance, or privilege escalation attempts

**Example alert scenario:**
```
User ID 12345 attempted to access:
- /admin/users (failed) - 10:01 AM
- /admin/delete (failed) - 10:01 AM  
- /admin/logs (failed) - 10:02 AM
🚨 Alert: Possible privilege escalation attack!
```

**Why both matter:**
- Logs provide audit trail for incident response
- Alerts enable real-time response to active attacks

Source: OWASP Top 10 2025 A01

---

**Answer 31:**
**Why implement rate limits:** To minimize the harm from automated attack tooling

**Threats mitigated:**
- **Brute force attacks:** Password guessing, credential stuffing
- **Enumeration attacks:** Discovering valid usernames, user IDs
- **DoS prevention:** Resource exhaustion from automated requests

**Example:**
Without rate limiting:
- Attacker tries 10,000 passwords/second
- Finds valid password in minutes

With rate limiting (5 requests/minute):
- Attacker limited to 5 attempts/minute
- Would take 33+ hours for 10,000 attempts
- Attack becomes impractical

Source: OWASP Top 10 2025 A01

---

**Answer 33:**
**"Authentication** answers the question 'Who are you?' - it verifies your identity using passwords, tokens, or biometrics.

**Authorization** answers the question 'What can you access?' - it determines your permissions and enforces access control policies like 'deny by default'."

**Examples:**
- Authentication: Login with username/password
- Authorization: Regular user can't access `/admin/dashboard`

Source: OWASP Top 10 2025 A01 (concept throughout)

---

**Answer 34:**
**B) Authorization check (should current user access this user_id?)**

**The missing check:**
```python
# Authorization check needed!
if current_user.id != user_id and not current_user.is_admin:
    return "Access Denied", 403
```

The code checks if the user exists but doesn't verify if the **current user** should have access to that **specific user_id**. This is an IDOR vulnerability - anyone can access any user's profile by changing the user_id parameter.

**From OWASP:** "Model access controls should enforce record ownership rather than allowing users to create, read, update, or delete any record."

Source: OWASP Top 10 2025 A01

---

**Answer 37:**
**Three security measures:**

1. **Disable web server directory listing**
2. **Ensure file metadata (e.g., .git) is not present within web roots**
3. **Ensure backup files are not present within web roots**

**Why this matters:**

Directory listing enabled:
```
https://example.com/uploads/
  - secret_passwords.txt  ← Attacker sees all files!
  - database_backup.sql
```

File metadata exposed:
```
https://example.com/.git/config  ← Attacker downloads source code!
```

Backup files exposed:
```
https://example.com/config.php.bak  ← Attacker gets credentials!
```

Source: OWASP Top 10 2025 A01

---

**Answer 39:**
"Enforce record ownership at the model level" means building authorization checks into the data access layer, not just controllers.

**❌ Controller level only (easy to forget):**
```python
@app.route('/posts/<post_id>')
def get_post(post_id):
    # Might forget to check ownership!
    post = Post.query.get(post_id)
    return jsonify(post)
```

**✅ Model level enforcement (automatic):**
```python
# Model with built-in ownership check
class Post(db.Model):
    @classmethod
    def get_for_user(cls, post_id, user_id):
        # Ownership check built into model!
        return cls.query.filter_by(
            id=post_id, 
            owner_id=user_id
        ).first()

# Controller - ownership automatically enforced
@app.route('/posts/<post_id>')
def get_post(post_id):
    post = Post.get_for_user(post_id, current_user.id)
    if not post:
        return "Not found", 404
    return jsonify(post)
```

**Key principle:** Ownership is built into data access patterns, impossible to forget.

Source: OWASP Top 10 2025 A01

---

**Answer 40:**
**C) Developers and QA staff**

**Why both:**

**Developers:**
- Write unit tests as they code
- Understand business logic and edge cases
- Find bugs early (100x cheaper to fix)

**QA:**
- Write integration tests before release
- Know user workflows
- Test complete authorization scenarios

**Why not just security team:**
- Security team can't scale to review all features
- Developers ship 50-100 features/week
- Need distributed ownership for shift-left security

Source: OWASP Top 10 2025 A01

---

**Answer 42:**
**Two reasons:**

**1. Consistency (reduced errors):**
- 100 endpoints × separate checks = 100 chances to make mistakes
- 1 centralized mechanism × reuse = 1 place to get right
- Human error is inevitable - minimize attack surface

**2. Maintainability:**
- **Business rule changes:** Update 1 decorator vs 50 different files
- **Security patches:** Fix vulnerability once, applies everywhere
- **Auditing:** Review 1 implementation, not 100

**Example:**
```python
# ✅ Centralized (reusable)
@require_ownership('post')
def get_post(id):
    return post

@require_ownership('comment')
def get_comment(id):  # Can't forget - obvious it's needed!
    return comment
```

Source: OWASP Top 10 2025 A01

---

**Answer 46:**
**Example code violating least privilege:**
```python
# ❌ Violates Least Privilege
@app.route('/api/users/<user_id>/profile')
def get_profile(user_id):
    # No access control - ANYONE can access ANY profile!
    user = User.query.get(user_id)
    return jsonify(user)
```

**Correct implementation:**
```python
# ✅ Follows Least Privilege
@app.route('/api/users/<user_id>/profile')
@login_required
def get_profile(user_id):
    # Access granted only to owner or admin
    if current_user.id != user_id and not current_user.is_admin:
        return "Access Denied", 403
    
    user = User.query.get(user_id)
    return jsonify(user)
```

Source: OWASP Top 10 2025 A01

---

### Section 3: A04 - Cryptographic Failures

**Answer 3:**
Any ONE of these four CWEs:
- **CWE-327:** Use of a Broken or Risky Cryptographic Algorithm
- **CWE-331:** Insufficient Entropy
- **CWE-1241:** Use of Predictable Algorithm in Random Number Generator
- **CWE-338:** Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)

Source: OWASP Top 10 2025 A04

---

**Answer 6:**
**B) The IV must never be used twice for a fixed key**

**From OWASP:** "In all cases, the IV should never be used twice for a fixed key."

**Why this matters:**
- Reusing an IV with the same key can reveal patterns in encrypted data
- In some cipher modes (like CTR), IV reuse completely breaks encryption
- This is a common real-world vulnerability ("nonce reuse" attacks)

Source: OWASP Top 10 2025 A04

---

**Answer 8:**
**B) MD5 and SHA1**

**From OWASP:** "Are deprecated hash functions such as MD5 or SHA1 in use?"

**Why they're deprecated:**
- **MD5:** Collision attacks proven since 2004
- **SHA1:** Collision attacks proven since 2017 (Google demonstrated practical attack)

**What to use instead:**
- SHA-256, SHA-384, SHA-512 (SHA-2 family)
- SHA-3
- For passwords: bcrypt, Argon2, PBKDF2

Source: OWASP Top 10 2025 A04

---

**Answer 12:**
**Encryption only (e.g., AES-CBC):**
- Provides **confidentiality** (can't read the message)
- Does NOT provide **integrity** (can't detect tampering)
- Vulnerable to padding oracle attacks, bit-flipping

**Authenticated encryption (e.g., AES-GCM):**
- Provides **confidentiality** (can't read the message)
- Provides **integrity** (detects tampering via MAC/authentication tag)
- Provides **authenticity** (proves sender had the key)

**Why OWASP recommends authenticated encryption:**
Without it, attackers can modify ciphertext undetected. For example, modifying encrypted credit card data in transit. Authenticated encryption detects and rejects any modifications.

Source: OWASP Top 10 2025 A04

---

**Answer 14:**
**C) Use a password-based key derivation function (like PBKDF2, bcrypt, Argon2)**

**From OWASP:** "If a password is used, then it must be converted to a key via an appropriate password base key derivation function."

**Why:**
- **Direct password:** Weak (short, low entropy)
- **SHA-256 hash:** Too fast, vulnerable to brute-force
- **KDF (PBKDF2/Argon2):** Intentionally slow, salted, stretches weak passwords into strong keys

Source: OWASP Top 10 2025 A04

---

**Answer 18:**
**FALSE**

**Why ECB is problematic:**
- **Deterministic:** Same plaintext → same ciphertext (reveals patterns)
- **Statistical analysis vulnerability:** Famous "ECB penguin" example where image patterns remain visible after encryption
- **Block replacement attacks:** Attacker can swap encrypted blocks

**From OWASP:** "Is an insecure mode of operation such as ECB in use?"

**Better alternatives:**
- CBC mode with random IV
- CTR mode with unique nonce
- GCM mode (provides AEAD - authenticated encryption)

Source: OWASP Top 10 2025 A04

---

**Answer 23:**
Data requiring extra protection (any 3):
1. **Passwords**
2. **Credit card numbers**
3. **Health records**
4. **Personal information** (including email addresses under GDPR)
5. **Business secrets**

**From OWASP:** "For example, passwords, credit card numbers, health records, personal information, and business secrets require extra protection, mainly if that data falls under privacy laws, e.g., EU's General Data Protection Regulation (GDPR), or regulations, e.g., financial data protection such as PCI Data Security Standard (PCI DSS)."

Source: OWASP Top 10 2025 A04

---

**Answer 26:**
**D) Use adaptive password hashing (bcrypt, Argon2, PBKDF2)**

**Why:**
- **Adaptive hashing** = intentionally slow, configurable work factor
- As computers get faster, increase iterations/cost
- Built-in salt prevents rainbow table attacks
- Protects against brute-force

**Why other options fail:**
- **A (Plaintext):** Catastrophic - immediate compromise if breached
- **B (SHA-256):** Too fast - billions of hashes/second on GPU
- **C (AES-256):** Reversible - if key is compromised, all passwords exposed

Source: OWASP Top 10 2025 A04 best practices

---

**Answer 29:**
**FALSE**

**From OWASP:** "For many modes, this means using a CSPRNG (cryptographically secure pseudo random number generator). For modes that require a nonce, then the initialization vector (IV) does not need a CSPRNG."

**The distinction:**

**Modes requiring CSPRNG (random IV):**
- CBC mode - IV must be unpredictable
- CFB mode - IV must be random

**Modes requiring only a NONCE (unique value):**
- CTR mode - Just needs unique nonce (can be counter: 1, 2, 3...)
- GCM mode - Nonce can be sequential

**Critical for ALL modes:** Never reuse IV/nonce with the same key

Source: OWASP Top 10 2025 A04

---

**Answer 32:**
**The first question to ask:** "Is any data transmitted in clear text?"

**From OWASP:** "The first thing is to determine the protection needs of data in transit and at rest. For example, passwords, credit card numbers, health records, personal information, and business secrets require extra protection... For all such data: Is any data transmitted in clear text?"

**The assessment flow:**
1. **First:** Identify what data exists and its sensitivity (data classification)
2. **Then:** Ask technical questions about encryption, algorithms, etc.

Source: OWASP Top 10 2025 A04

---

**Answer 35:**
**OSI Layer 4 (Transport Layer)** according to OWASP documentation

**Technology:** TLS/SSL (Transport Layer Security)

**From OWASP:** "Generally speaking, all data in transit should be encrypted at the transport layer (OSI layer 4)."

**Technical note:** There's debate about TLS placement - it technically operates between TCP (Layer 4) and HTTP (Layer 7), spanning Session/Presentation layers (5-6). OWASP uses "Layer 4" as industry shorthand.

Source: OWASP Top 10 2025 A04

---

**Answer 38:**
**C) In a hardware or cloud-based HSM (Hardware Security Module)**

**From OWASP:** "Store your most sensitive keys in a hardware or cloud-based HSM."

**Why HSM:**
- Dedicated tamper-resistant hardware
- Keys never leave the device
- FIPS 140-2/3 certified
- Physical security protections

**Cloud-based HSM examples:**
- AWS CloudHSM / AWS KMS
- Azure Key Vault (Premium tier)
- Google Cloud KMS / Cloud HSM

Source: OWASP Top 10 2025 A04

---

**Answer 41:**
**Two problems:**

**1. Not using a password-based key derivation function (KDF):**
- SHA-256 is too fast (~2 billion hashes/second on GPU)
- Brute force attacks are trivial
- No work factor/cost parameter
- Should use bcrypt, Argon2, or PBKDF2

**2. No salt:**
- Same password → same hash
- Rainbow table attacks work
- Attacker can crack all instances of "password123" at once

**Example attack:**
```
User1: password123 → 9af15b336e...
User2: password123 → 9af15b336e...  ← Same hash!
```

Source: OWASP Top 10 2025 A04

---

**Answer 44:**
**The IV is not stored!**

CBC mode decryption requires the **exact same IV** used during encryption. Without storing the IV alongside the ciphertext, the data becomes permanently unrecoverable.

**Decryption requires:**
```
plaintext = decrypt(ciphertext, key, iv)
                                    ^^
                          Need the original IV!
```

**Secure implementation:**
```python
# Store BOTH ciphertext AND IV
db.store({
    'ciphertext': ciphertext,
    'iv': iv  # ✓ Must store IV!
})
```

**Note:** The IV doesn't need to be secret, but it MUST be unique per encryption and available for decryption.

Source: OWASP Top 10 2025 A04 cryptographic principles

---

**Answer 47:**
**Require extra protection (encryption at rest):**
1. ✅ **User email addresses** (Personal information under GDPR)
2. ✅ **Full credit card numbers with CVV** (PCI DSS regulated)
3. ✅ **Social Security Numbers** (PII)

**Do NOT require extra protection:**
- ❌ Marketing preferences (Not sensitive)
- ❌ Credit card last 4 digits only (Masked/truncated - PCI DSS allows)
- ❌ Favorite color (Not sensitive)

**From OWASP:** "passwords, credit card numbers, health records, personal information, and business secrets require extra protection, mainly if that data falls under privacy laws, e.g., EU's General Data Protection Regulation (GDPR)"

Source: OWASP Top 10 2025 A04

---

### Section 4: Integration & Advanced Topics

**Answer 20:**
**Yes, vulnerable to SQL injection.**

**Vulnerable line:** `SET @query = 'SELECT * FROM users WHERE name LIKE ''%' + @searchTerm + '%'''`

**The problem:** String concatenation (`+ @searchTerm +`) embeds user input directly into the SQL string. An attacker can inject:
```
searchTerm = "'; DROP TABLE users; --"
Result: SELECT * FROM users WHERE name LIKE '%'; DROP TABLE users; --%'
```

**From OWASP:** "Even when parameterized, stored procedures can still introduce SQL injection if PL/SQL or T-SQL concatenates queries and data or executes hostile data with EXECUTE IMMEDIATE or exec()."

The `EXEC(@query)` then executes this malicious SQL.

Source: OWASP Top 10 2025 A05

---

**Answer 30:**
**A01 (Broken Access Control) vulnerabilities:**
- **No authentication check** - anyone can call the endpoint
- **No authorization check** - no verification of permissions
- **IDOR vulnerability** - direct manipulation of user_id parameter
- **Missing "deny by default"** - endpoint is wide open

**A05 (Injection) vulnerability:**
- **SQL Injection** in the line: `query = f"DELETE FROM users WHERE id = {user_id}"`
- F-string concatenation directly embeds user input
- Attack: `/delete_user?user_id=1; DROP TABLE users; --`

**Secure version:**
```python
@app.route('/delete_user')
@login_required  # Authentication
def delete_user():
    user_id = request.args.get('user_id')
    
    # Authorization check
    if not current_user.is_admin:
        return "Access Denied", 403
    
    # Parameterized query
    query = "DELETE FROM users WHERE id = ?"
    db.execute(query, (user_id,))
    return "User deleted"
```

Sources: OWASP Top 10 2025 A01 & A05

---

## 🎯 Your Score

Count your correct answers and see where you stand:

- **45-51 correct (88%+):** 🔥 Interview-ready! You have strong OWASP Top 10 knowledge
- **38-44 correct (75-86%):** 💪 Solid foundation - study your weak areas
- **30-37 correct (59-74%):** 📚 Good start - review OWASP 2025 documentation
- **Below 30 (58%-):** 📖 Study OWASP Top 10 2025 thoroughly, then retake

---

## 🚀 Level Up Your AppSec Skills

Want more challenges like this?

⭐ **Star my GitHub repository:** [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)

I'm building a comprehensive collection of **LeetCode-style security exercises** to help developers write more secure code and prepare for AppSec interviews. Each exercise includes:
- 30+ comprehensive test cases
- Real-world security scenarios
- Detailed explanations
- Production-applicable skills

**Coming soon:**
- Rate limiting challenges
- JWT security exercises
- CSRF token validation
- Input sanitization problems
- Authentication system design
- And 15+ more exercises!

By starring the repo, you'll:
- Get notified of new exercises
- Support the creation of quality AppSec training materials
- Help build better secure coding education for the community

---

## 📚 Additional Resources

**Study these to master OWASP Top 10 2025:**
- [OWASP Top 10 2025 RC1](https://owasp.org/Top10/2025/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) (Free labs!)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

**For interview preparation:**
- Complete 85 PortSwigger Web Security Academy labs
- Build security tools (SQLi scanner, XSS detector, IDOR tester)
- Read "API Security in Action" by Neil Madden
- Practice threat modeling with STRIDE

---

## 💬 Let's Connect

How did you score? What questions tripped you up? Drop a comment below!

Follow me for more AppSec content:
- 🐦 Twitter: [@fosres](https://twitter.com/tanveerasalim)
- 💼 LinkedIn: [fosres](https://linkedin.com/in/fosres)
- 🔗 GitHub: [fosres](https://github.com/fosres)

---

**Tags:** #appsec #security #owasp #cybersecurity #infosec #webappsec #hacking #bugbounty #pentesting #interview

---

*This quiz is based on the OWASP Top 10 2025 Release Candidate. All questions reference official OWASP documentation.*

