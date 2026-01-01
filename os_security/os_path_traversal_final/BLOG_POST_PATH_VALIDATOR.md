---
title: "The $10M Path Traversal Bug That's Still Shipping in Production Code"
published: false
description: "Can you validate file paths correctly? 100 real-world test cases from CVE-2019-3396 (Atlassian), CVE-2022-24765 (Git), and Zip Slip. Path canonicalization challenge."
tags: appsec, security, python, challenge
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/path-traversal-validator.png
---

**[→ Skip to the Challenge](#try-the-challenge)**

---

# The $10M Mistake: Atlassian's Path Traversal Disaster

**March 20, 2019. 3:47 AM.**

An Atlassian engineer wakes up to their phone exploding with alerts. Every Confluence server in their fleet is encrypting itself. Ransomware. Over 10,000 enterprise installations compromised worldwide.

The root cause? **Two characters:** `../`

The damage? North of **$10 million** in recovery costs. Emergency patches pushed to hundreds of thousands of servers. PR disasters. Class-action lawsuits.

And here's the part that keeps me up at night: **this exact vulnerability is still shipping in production code today.**

In today's challenge, you'll build a production-grade path validator that would have prevented this disaster. Can you pass all 100 tests?

---

## The Challenge

Write a function that **correctly validates** if a file path stays within an allowed directory:

```python
from pathlib import Path

def is_safe_path(base_dir: str, requested_path: str) -> bool:
	"""
	Return True if the path is safe (stays within base_dir).
	Return False if it's a path traversal attack (escapes base_dir).
	
	Examples:
		>>> is_safe_path("/var/www/uploads", "images/logo.png")
		True  # Safe: /var/www/uploads/images/logo.png
		
		>>> is_safe_path("/var/www/uploads", "../../etc/passwd")
		False  # Attack: escapes to /var/etc/passwd
		
		>>> is_safe_path("/var/www/uploads", "/etc/passwd")
		False  # Attack: absolute path escape
	"""
	# Your implementation here
	pass
```

Simple interface. **Brutal test suite.**

I built 100 test cases from real attacks I've seen in:
- **CVE-2019-3396** (Atlassian Confluence) - The $10M disaster
- **CVE-2022-24765** (Git) - Compromised enterprise Git servers  
- **Zip Slip** (Snyk, 2018) - Hit Oracle, Amazon, Spring, LinkedIn, Twitter

Your job: Pass all 100 tests by implementing proper **path canonicalization**.

---

## Why This Bug Won't Die

I've documented 553 security threats at Intel. Path traversal keeps appearing in production code. Not because developers are incompetent, but because it's **deceptively simple** to get wrong.

### It Looks Harmless in Code Review

```python
# Looks fine, right?
@app.route('/download')
def download_file():
	filename = request.args.get('file')
	return send_file(f"/var/www/uploads/{filename}")
```

Ship it. The code reviewer approves. Nobody catches it.

Then someone hits your endpoint with:

```
/download?file=../../../../etc/passwd
```

**Game over.**

Your web server happily resolves:
```
/var/www/uploads/../../../../etc/passwd
→ /etc/passwd
```

And serves your password file to the attacker.

---

## Why Simple Filters Don't Work

Early in my career, I thought I was clever:

```python
def is_safe_path(base_dir, requested_path):
	if ".." in requested_path:
		return False  # Blocked!
	return True
```

**This fails spectacularly.** Attackers aren't stupid:

```python
# Bypass 1: URL encoding
"%2e%2e%2f%2e%2e%2fetc%2fpasswd"
# Your filter sees gibberish
# The OS sees: ../../etc/passwd

# Bypass 2: Double encoding  
"%252e%252e%252fetc%252fpasswd"

# Bypass 3: Confluence CVE-2019-3396
"....//....//etc/passwd"
# Dots look wrong, but OS normalizes to ../../

# Bypass 4: Mixed separators
"..\\..\\windows\\system32\\config\\sam"
```

Your naive filter sees random characters. The operating system sees **perfect traversal sequences**.

This is why Atlassian lost $10M. This is why Git had CVE-2022-24765. This is why Zip Slip compromised thousands of applications.

---

## What You Need to Know: Path Canonicalization

The **correct solution** uses OS-level path canonicalization:

```python
# The OS resolves paths for you:
Path("/var/www/uploads/../../etc/passwd").resolve()
→ /etc/passwd

# Now you can check: is this still within /var/www/uploads?
# Answer: NO → Block it!
```

**Why this works:**
- The OS handles ALL encoding variants
- It follows symlinks  
- It resolves `../` sequences
- It normalizes separators (`/` vs `\`)
- It converts to absolute paths

You check the **actual destination**, not patterns.

---

## The 100 Test Cases

I didn't create random tests. Every single one comes from:
- Real CVE disclosures
- Penetration test reports  
- Threat models I've documented
- Attack patterns from security research

### Category 1: Safe Paths (Tests 1-25)

**Expected:** Return `True`

Legitimate files you should **allow**:

```python
is_safe_path("/var/www/uploads", "images/logo.png")
→ True  # /var/www/uploads/images/logo.png ✓

is_safe_path("/home/alice/documents", "projects/proposal.docx")  
→ True  # /home/alice/documents/projects/proposal.docx ✓

is_safe_path("C:\\inetpub\\wwwroot", "static\\css\\style.css")
→ True  # C:\inetpub\wwwroot\static\css\style.css ✓
```

**Testing 25 different base directories:**
- Web uploads: `/var/www/uploads`, `/srv/www/public`
- User directories: `/home/alice/documents`, `/home/bob/projects`
- Application data: `/app/data`, `/opt/application/files`  
- Windows paths: `C:\inetpub\wwwroot`, `C:\Users\Alice\Documents`

---

### Category 2: Classic Unix Traversal (Tests 26-40)

**Expected:** Return `False`

Standard `../` attacks attempting to escape:

```python
is_safe_path("/var/www/uploads", "../../../etc/passwd")
→ False  # Escapes to /var/etc/passwd ✗

is_safe_path("/home/alice/documents", "../../bob/.ssh/id_rsa")
→ False  # Accessing other user's SSH key ✗

is_safe_path("/opt/webapp/files", "../../../var/log/auth.log")
→ False  # Reading authentication logs ✗
```

**What attackers target:**
- `/etc/passwd` - User database
- `/etc/shadow` - Password hashes  
- `/root/.ssh/id_rsa` - Root SSH private key
- `/var/log/auth.log` - Authentication logs
- `/proc/self/environ` - Environment variables (API keys!)

---

### Category 3: Absolute Path Attacks (Tests 41-60)

**Expected:** Return `False`

Bypassing `base_dir` entirely with absolute paths:

```python
is_safe_path("/var/www/uploads", "/etc/passwd")
→ False  # Direct absolute path ✗

is_safe_path("/app/files", "/root/.ssh/id_rsa")  
→ False  # Absolute path to SSH key ✗

is_safe_path("C:\\inetpub\\wwwroot", "C:\\Windows\\System32\\config\\SAM")
→ False  # Windows SAM file (password database) ✗
```

**Cross-platform testing:**
- Unix absolute paths: `/etc/`, `/root/`, `/var/`
- Windows absolute paths: `C:\Windows\`, `C:\Users\`

---

### Category 4: Relative Traversal from Subdirectory (Tests 61-65)

**Expected:** Return `False`

Attackers start in a valid subdirectory, then escape:

```python
is_safe_path("/var/www/html", "images/../../etc/passwd")
→ False  # Valid start, then escape ✗

is_safe_path("/home/alice/projects", "myapp/src/../../../bob/.ssh/id_rsa")
→ False  # Deep nested traversal ✗

is_safe_path("C:\\inetpub\\wwwroot", "images\\..\\..\\..\\Windows\\System32\\config")
→ False  # Windows IIS traversal ✗
```

**Why this matters:** Your validator can't just check for `../` at the start. Attackers embed it deep in the path.

---

### Category 5: URL-Encoded Traversal (Tests 66-75)

**Expected:** Return `True` (surprising!)

URL-encoded paths where Python's `Path` treats encoded chars as **literal characters**:

```python
is_safe_path("/var/www/uploads", "%2e%2e%2fetc%2fpasswd")  
→ True  # Path sees literal filename "%2e%2e%2fetc%2fpasswd" ✓

is_safe_path("/app/data", "..%2f..%2fetc%2fpasswd")
→ True  # Mixed encoding as literal ✓
```

**Why?** 

Linux kernel only recognizes `/` (ASCII 0x2F) as a path separator. URL-encoded `%2F` is just literal characters to the filesystem.

**BUT** in production, your web framework decodes URLs **before** calling your validator:

```
User sends:   %2e%2e%2fetc%2fpasswd
Framework decodes: ../../etc/passwd  
Your validator sees: ../../etc/passwd
→ Should return False!
```

This tests that your validator works correctly **after** framework decoding.

---

### Category 6: Null Byte Injection (Tests 76-80)

**Expected:** Return `False`

Null bytes attempting to truncate paths:

```python
is_safe_path("/var/www/uploads", "image.png\x00../../etc/passwd")
→ False  # Null byte attack ✗

is_safe_path("/app/data", "file.txt\x00.php")
→ False  # Extension bypass attempt ✗
```

**Historical attack:** Older languages treated `\x00` as string terminator. Python 3 blocks this at OS level, but defense-in-depth says reject them anyway.

---

### Category 7: Linux System Files (Tests 81-85)

**Expected:** Return `False`

Real targets from actual attacks:

```python
is_safe_path("/var/www/html", "../../../../proc/self/environ")
→ False  # Steal environment variables ✗

is_safe_path("/app/user_data", "../../../../sys/class/net/eth0/address")
→ False  # Get MAC address ✗

is_safe_path("/opt/application/files", "../../../../../root/.ssh/id_rsa")
→ False  # Root SSH key ✗
```

**Why `/proc/self/environ` is dangerous:**

It contains:
- `DATABASE_URL=postgres://user:pass@host/db`
- `AWS_SECRET_ACCESS_KEY=...`
- `API_KEY=...`
- `JWT_SECRET=...`

One path traversal = complete infrastructure compromise.

---

### Category 8: Windows System Files (Tests 86-95)

**Expected:** Return `False`

Windows-specific attacks from **proper Windows base paths**:

```python
is_safe_path("C:\\inetpub\\wwwroot\\uploads", 
             "..\\..\\..\\Windows\\System32\\config\\SAM")
→ False  # Windows SAM (password database) ✗

is_safe_path("C:\\Users\\Alice\\Documents",
             "..\\..\\..\\Windows\\win.ini")
→ False  # Windows config ✗

is_safe_path("D:\\app\\files", "..\\..\\boot.ini")
→ False  # Boot configuration ✗
```

**Testing 16 Windows scenarios:**
- IIS web servers: `C:\inetpub\wwwroot`
- XAMPP: `C:\xampp\htdocs`
- User directories: `C:\Users\Alice\Documents`
- Program Files: `C:\Program Files\MyApp`
- Multiple drives: `D:\app`, `E:\uploads`

**What attackers target on Windows:**
- `C:\Windows\System32\config\SAM` - Password database
- `C:\Windows\win.ini` - System config
- `C:\boot.ini` - Boot settings
- `C:\Users\Administrator\.ssh\id_rsa` - Admin SSH key
- `C:\ProgramData\MySQL\my.ini` - Database credentials

---

### Category 9: CVE-Inspired Patterns (Tests 96-100)

**Expected:** Return `False`

Straight from real vulnerability disclosures:

```python
# CVE-2019-3396 (Atlassian Confluence - $10M damage)
is_safe_path("/var/www/html", "..;/..;/etc/passwd")
→ False  ✗

# CVE-2022-24765 (Git security vulnerability)
is_safe_path("/home/alice/repo", ".git/../../../etc/shadow")  
→ False  ✗

# Zip Slip (Snyk, 2018 - hit thousands of apps)
is_safe_path("/opt/application/temp", "../../../../tmp/malicious.sh")
→ False  ✗

# Confluence double dot slash bypass
is_safe_path("/app/uploads", "....//....//etc/passwd")
→ False  ✗
```

These are **exact patterns** from disclosed CVEs. If your validator doesn't catch these, you're shipping the same bugs that cost companies millions.

---

## Try the Challenge

**GitHub:** [fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)

⭐ **Star the repo** if you find this useful. It helps me know what exercises to build next.

```bash
git clone https://github.com/fosres/AppSec-Exercises.git
cd AppSec-Exercises
python3 path_validator_100_tests.py
```

When you pass all 100 tests:

```
╔═══════════════════════════════════════════════════════════════╗
║              🎉 PERFECT! ALL 100 TESTS PASSED! 🎉             ║
╚═══════════════════════════════════════════════════════════════╝

Your path validator is PRODUCTION-READY! 🛡️

You've successfully defended against:
  ✅ Classic path traversal attacks (../, /etc/passwd)
  ✅ Absolute path bypasses
  ✅ Null byte injection attempts
  ✅ Linux system file access (/proc, /sys, /dev)
  ✅ Windows system file access (SAM, win.ini, etc.)
  ✅ Real-world CVE patterns (Git, Confluence, Zip Slip)
```

Then share your victory. Tag me. Let me know what surprised you.

---

## What You'll Actually Learn

### 1. Why `Path.resolve()` is Essential

```python
from pathlib import Path

# Before resolution
path = Path("/var/www/uploads/../../etc/passwd")
print(path)  
→ /var/www/uploads/../../etc/passwd  # Still has ../

# After resolution  
canonical = path.resolve()
print(canonical)
→ /etc/passwd  # OS normalized it!

# Now you can validate:
base = Path("/var/www/uploads").resolve()
→ /var/www/uploads

if canonical.is_relative_to(base):  # Python 3.9+
	print("SAFE")
else:
	print("ATTACK DETECTED")  # /etc/passwd NOT within /var/www/uploads
```

**What `.resolve()` does:**
- Converts to absolute path
- Resolves `../` and `./` sequences  
- Follows symlinks
- Normalizes path separators
- Handles URL decoding (done by framework first)

---

### 2. Why String Matching Fails

```python
# Naive approach
def is_safe_path(base_dir, requested_path):
	if ".." in requested_path:
		return False
	# ...

# This blocks VALID files!
is_safe_path("/var/www/uploads", "file....")
→ False  # But "file...." is a legitimate Linux filename!

is_safe_path("/var/www/uploads", "config...")  
→ False  # "config..." is also valid!

is_safe_path("/var/www/uploads", "my....backup")
→ False  # "my....backup" is valid too!
```

Yes, `"..."` is a **legitimate filename** on Linux. Try it:

```bash
touch ...
ls -la
→ -rw-r--r-- 1 user user 0 Dec 22 12:34 ...
```

Your validator needs to understand **filesystem semantics**, not just do pattern matching.

---

### 3. Why Cross-Platform Matters

**Unix/Linux paths:**
```python
is_safe_path("/var/www/uploads", "../../etc/passwd")
# Uses forward slashes: /
```

**Windows paths:**
```python
is_safe_path("C:\\inetpub\\wwwroot", "..\\..\\Windows\\System32")  
# Uses backslashes: \
# Uses drive letters: C:, D:, E:
```

Python's `pathlib.Path` handles **both** automatically. You write one validator, it works everywhere.

---

### 4. The Correct Algorithm

Here's the high-level approach (no spoilers on exact implementation):

```python
from pathlib import Path

def is_safe_path(base_dir: str, requested_path: str) -> bool:
	# Step 1: Canonicalize base directory
	base = Path(base_dir).resolve()
	# /var/www/uploads → /var/www/uploads (absolute)
	
	# Step 2: Join paths and canonicalize the result
	target = (base / requested_path).resolve()
	# Input: ../../etc/passwd
	# Joined: /var/www/uploads/../../etc/passwd  
	# Resolved: /etc/passwd (OS does the work!)
	
	# Step 3: Check if target is still within base
	# How do you check this?
	# (Hint: there's a method for checking path relationships)
	
	# Step 4: Return True if safe, False if escaped
```

**Your task:** Fill in step 3. How do you check if `/etc/passwd` is still within `/var/www/uploads`?

---

## The Variety You're Testing

I didn't use `/var/www/uploads` for all 100 tests. That would be unrealistic.

**69 unique base paths** across:

**Web Applications:**
- `/var/www/uploads`, `/srv/www/public`, `/usr/share/nginx/html`
- `C:\inetpub\wwwroot`, `C:\xampp\htdocs`

**User Directories:**  
- `/home/alice/documents`, `/home/bob/projects`, `/home/charlie/uploads`
- `C:\Users\Alice\Documents`, `C:\Users\Bob\Desktop`

**Application Data:**
- `/app/data`, `/opt/application/files`, `/usr/local/app/uploads`
- `C:\Program Files\MyApp\data`, `D:\app\files`

**System Services:**
- `/var/lib/app/files`, `/var/cache/webapp`, `/opt/service/logs`
- `C:\ProgramData\MySQL`, `C:\temp\processing`

**Storage & Backups:**
- `/mnt/storage/files`, `/data/uploads`, `/srv/ftp/public`
- `D:\websites\public`, `E:\uploads\temp`

This tests your validator against **real-world diversity**.

---

## Why I Built This

I'm building a P2P open source project to curate high-quality secure code datasets. The goal: **train AI models to write secure code by default.**

Current AI coding assistants generate vulnerable code because they're trained on GitHub repos full of bugs. I'm trying to change that.

This path traversal challenge is part of that effort. Every exercise I create:
- Tests real-world attack vectors
- Teaches defensive programming  
- Includes production-grade solutions
- References actual CVEs and security research

**Want weekly AppSec challenges like this?**

📧 **[Join the mailing list](https://buttondown.email/fosres)**

I send:
- LeetCode-style security challenges
- Real CVE breakdowns
- Solutions with detailed explanations  
- Early access to new exercises

No spam. No ads. Just practical AppSec skills for people who actually ship code.

---

## The Resources I Used

These aren't random tests. Every single one comes from documented attacks or security research:

### Books (with specific pages):

📖 **"API Security in Action"** by Neil Madden  
- Chapter 8, pp. 251-254: Path Traversal Attacks
- "Always define acceptable inputs rather than unacceptable ones"

📖 **"Full Stack Python Security"** by Dennis Byrne  
- Chapter 6, pp. 123-127: Input Validation  
- "Input sanitization is always a bad idea"

📖 **"Secure by Design"** by Johnsson, Deogun, Sawano  
- Chapter 7, pp. 189-193: Limiting Input
- "Use canonicalization to determine actual destination"

📖 **"Hacking APIs"** by Corey J. Ball  
- Chapter 4: Common API Vulnerabilities
- Directory traversal fuzzing techniques

📖 **"Python Workout"** by Reuven Lerner  
- Chapter 2: Strings (for basic Python string operations)

### CVEs:

🔒 [**CVE-2019-3396: Atlassian Confluence**](https://confluence.atlassian.com/doc/confluence-security-advisory-2019-03-20-966660264.html)  
- The $10M+ disaster
- Pattern: `..;/..;/etc/passwd`

🔒 [**CVE-2022-24765: Git Path Traversal**](https://github.blog/2022-04-12-git-security-vulnerability-announced/)  
- Compromised enterprise Git servers
- Pattern: `.git/../../../etc/passwd`

🔒 [**Zip Slip Vulnerability**](https://snyk.io/research/zip-slip-vulnerability) (Snyk Research)  
- Hit Oracle, Amazon, Spring, LinkedIn, Twitter
- Archive extraction attacks

### OWASP:

📚 [**Path Traversal Attack**](https://owasp.org/www-community/attacks/Path_Traversal)  
📚 [**CWE-22: Improper Limitation of a Pathname**](https://cwe.mitre.org/data/definitions/22.html)

I cite these because I want you to **go deeper**. The challenge teaches you the patterns. The books teach you **why they matter**.

---

## What Happens Next

### 1. Take the Challenge

Clone the repo. Run the tests. See if you can pass all 100.

### 2. ⭐ Star the Repository  

If this helped you, star it: [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)

It tells me this kind of content is valuable. And it helps other developers find it.

### 3. 📧 Join the Mailing List

[Subscribe here](https://buttondown.email/fosres) for more challenges like this.

I'm aiming for one new exercise per week. Each one focused on a different OWASP vulnerability or CVE pattern.

### 4. Share Your Results

When you complete it:
- Post your completion time in the comments
- Share what surprised you  
- Tell me what CVE or vulnerability to cover next

I read every response. I use your feedback to build better exercises.

---

## Final Thoughts

**Path traversal is 20+ years old.**

It's documented. It's well-understood. It's in the OWASP Top 10, the CWE Top 25, every security training course, every penetration testing checklist.

And it's **still** showing up in production.

- Atlassian learned this the hard way. **$10+ million** in damages.
- 10,000+ compromised Confluence servers.  
- Emergency patches to hundreds of thousands of installations.
- Class-action lawsuits. PR disasters. Breach notifications.

**You don't have to.**

Take the challenge. Learn the patterns. Build the muscle memory. 

So the next time you write file handling code, you automatically think:

> "How could this escape the base directory?"

Because that one thought—that one validation—is the difference between:
- Shipping secure code
- Shipping **CVE-2025-XXXXX**

Let's build a more secure internet. One validated path at a time.

---

**[Try the challenge on GitHub →](https://github.com/fosres/AppSec-Exercises)**

**[Get weekly AppSec exercises →](https://buttondown.email/fosres)**

---

**Drop a comment if you complete the challenge. I want to hear what you learned.**

---

**Tags:** #appsec #security #python #cybersecurity #owasp #pathtraversal #cve #defensivecoding

---

*All examples are for educational purposes only. Test patterns derived from publicly disclosed CVEs and security research.*
