# Product Security - Question 4: SQL Injection

**Practice Exercise - Week 5 Application**  
**Candidate:** Tanveer Salim (fosres)  
**Date:** January 15, 2026

---

## Instructions

This is Question 4 from a Product Security technical assessment, focused on SQL injection vulnerabilities.

**Time Limit:** No strict time limit for practice (original exam: 3 hours total)

**Goal:** Identify all vulnerabilities, explain exploitation, and suggest comprehensive mitigations.

**Skills Tested:**
- SQL injection identification
- Attack vector analysis
- Secure coding practices
- Python security knowledge

---

## Scenario

You are a member of the Product Security Team. You are being engaged by the Software Engineering Team which is currently working on a project to develop and deploy a new web application.

The engineering team now wants to add user authentication to their file server. They send you the following code for a security review.

**Assume you can reach this code via HTTP, fully controlling the values of `username` and `password`.**

---

## Vulnerable Code

```python
import sqlite3

_DATABASE = "users.db"

def authenticate_user(username, password):
	cursor = sqlite3.connect(_DATABASE).cursor()
	cursor.execute(f"select password, allowed_files from users where username = '{username}'")
	expected_password, allowed_files = cursor.fetchone()
	if password != expected_password:
		raise Exception(f"Invalid password")
	return allowed_files
```

---

## Questions

### Part 1: What vulnerabilities exist in the code?

**Instructions:** List ALL vulnerabilities you can identify. Be specific about the security implications of each vulnerability.

**Your Answer:**


The below line has a SQL injection vulnerability:

```
	cursor.execute(f"select password, allowed_files from users where username = '{username}'")

```

For an example an attacker can launch a UNION SQL Injection Attack

to reveal all passwords for all users in the `username` field.


The `password` user input should also first be hashed

using a cryptographically secure password-based key derivation function

and this result is what should be stored in the database.

Storing raw passwords in the database is a vulnerability. If the

database is compromised so are all user passwords.


NOTE: As of now I have not learned how to do secure password

authentication just yet, Claude.

Finally there is a timing attack vulnerability in the password

comparision test below:

```
	if password != expected_password:
		raise Exception(f"Invalid password")
```

An attacker can carefully send inputs and measure the timing of

responses to discern the password.

---

### Part 2: How would you exploit them?

**Instructions:** Provide concrete exploitation examples. Show actual payloads or attack scenarios.

**Your Answer:**

For an example an attacker can launch a UNION SQL Injection Attack

to reveal all password for all users either in the `username`fields..

---

### Part 3: What mitigations would you suggest?

**Instructions:** Provide comprehensive, production-ready mitigations. Include code examples where appropriate.

**Your Answer:**

I would recommend Parameterized SQL Queries as primary

defense for the `username` field as shown below:

```
	cursor.execute(f"select password, allowed_files from users where
username = ?",(username,))
```

I would also recommend input validation as secondary defense for

`username` where `username` is checked against an allowed

regex pattern of usernames.

Finally I would recommend developers to first calculate the hash

of the `password` using a password-based key derivation function

and storing the hash in the database. 

---

## Recommended Secure Implementation

**Instructions:** Provide a complete, secure rewrite of the `authenticate_user` function incorporating all your suggested mitigations.


```python
import sqlite3

_DATABASE = "users.db"

def authenticate_user(username, password):
	cursor = sqlite3.connect(_DATABASE).cursor()

	# password first hashed using cryptographically secure password
	# based key derivation function, the result is `hashed_password`

	'''
	# Below is partial pseudocode
	if username does not match expected regex pattern:
		raise Exception(f"Invalid username")
	'''

	cursor.execute(f"select password, allowed_files from users where username = ?",(username,))

	expected_hashed_password, allowed_files = cursor.fetchone()

	if not hmac.compare_digest(hashed_password,expected_hashed_password):
		
		raise Exception(f"Invalid password")

	return allowed_files
```

---

## Testing Your Answer

### Test Cases to Consider:

1. **Basic SQL Injection:**
   - Input: `username = "admin' OR '1'='1"`
   - Expected behavior:

2. **Authentication Bypass:**
   - Input: `username = "admin' --"`
   - Expected behavior:

3. **Information Disclosure:**
   - Input: `username = "' UNION SELECT ..."`
   - Expected behavior:

4. **Timing Attacks:**
   - Input: Various username/password combinations
   - Expected behavior:

5. **Edge Cases:**
   - Empty strings
   - NULL values
   - Special characters
   - Very long inputs

---

## Evaluation Criteria

Your answer will be evaluated on:

- ✅ **Completeness:** Did you identify ALL vulnerabilities?
- ✅ **Technical Accuracy:** Are your exploits and mitigations correct?
- ✅ **Practical Understanding:** Do you understand real-world implications?
- ✅ **Code Quality:** Is your secure implementation production-ready?
- ✅ **Defense in Depth:** Did you suggest multiple layers of security?

---

## Resources

**Allowed Resources for This Practice:**
- OWASP Top 10 (A03: Injection)
- PortSwigger SQL Injection Labs (your completed labs)
- Python sqlite3 documentation
- Your Week 2-4 SQL injection notes

**Reference Materials:**
- OWASP SQL Injection Cheat Sheet
- CWE-89: SQL Injection
- Python DB-API 2.0 Specification (PEP 249)

---

## Hints (Optional - Use Only If Stuck)

<details>
<summary>Hint 1: Primary Vulnerability Class</summary>

The most obvious vulnerability is related to user input directly concatenated into SQL queries. This is a classic injection vulnerability covered in OWASP A03.

</details>

<details>
<summary>Hint 2: Authentication Logic Issues</summary>

Look carefully at how password verification is performed. Is the comparison secure against timing attacks? What happens if the user doesn't exist?

</details>

<details>
<summary>Hint 3: Database Connection Handling</summary>

Consider resource management. Are database connections properly closed? What about error handling?

</details>

<details>
<summary>Hint 4: Password Storage</summary>

Look at how passwords are stored and compared. Are they being hashed? This relates directly to your Week 5 password hashing challenge!

</details>

---

## Submission Checklist

Before considering your answer complete, verify:

- [ ] All vulnerabilities identified with severity ratings
- [ ] Concrete exploitation examples provided with payloads
- [ ] Comprehensive mitigations suggested with code examples
- [ ] Secure implementation provided and tested mentally
- [ ] Defense-in-depth approach demonstrated
- [ ] Edge cases considered
- [ ] Answers are clear and well-organized

---

## Notes Section

Use this space for scratch work, research notes, or additional observations:

```
[Your notes here]
```

---

## Time Tracking (Optional)

Track your time to simulate exam conditions:

- Start Time: __________
- End Time: __________
- Total Time: __________
- Target: < 20 minutes (Q4 represents ~11% of 3-hour exam)

---

**Good luck! Remember: The goal is to demonstrate thorough security thinking, not just find the obvious vulnerability.**

---

*Practice Exercise Created: January 15, 2026*  
*Based on: Product Security Technical Assessment*  
*Curriculum Week: 5 (SQL Injection + Password Security)*
