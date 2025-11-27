---
title: "Challenge: Can You Spot Path Traversal Attacks on Linux? (AppSec Exercise)"
published: false
description: "A hands-on AppSec challenge testing your ability to detect directory traversal attacks on GNU/Linux systems - 60 comprehensive tests including tricky edge cases that break naive solutions!"
tags: appsec, security, python, linux, challenge
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/...
---

# Challenge: Can You Spot Path Traversal Attacks on Linux?

**Time to complete:** 60-90 minutes  
**Difficulty:** Intermediate to Advanced (Post Python Workout Chapter 2)  
**Skills tested:** String Manipulation, Security Validation, Defensive Programming  
**Platform:** GNU/Linux (Unix-style paths)

## The Challenge

You're implementing a file download feature for a Linux web application. Users request files like "images/logo.png" and you need to validate the path is safe before serving the file. **Can your validator catch all 60 attack attempts** while allowing legitimate files?

**Plot twist:** Did you know `...` is a valid filename in Linux? What about handling root directory as base? These 60 comprehensive tests will push your solution to its limits!

[→ Skip to the challenge](#the-exercise)

---

## Why This Matters: The $10 Million String Vulnerability

In 2018, a path traversal vulnerability in thousands of applications led to what researchers called **"Zip Slip"** - a critical security flaw that affected over 2,500 projects including ones from Oracle, Amazon, Spring, LinkedIn, and Twitter.

**The attack was absurdly simple:**
```python
# Attacker creates a zip file with this path:
"../../../../etc/passwd"

# Vulnerable code extracts without validation:
extract_zip(archive)  # Oops! Just overwrote /etc/passwd
```

### Real-World Path Traversal Attacks

#### **GitHub Enterprise (2022)**
- **CVE-2022-24765:** Path traversal in Git
- **Impact:** Remote code execution on enterprise installations
- **Cause:** Improper validation of repository paths
- **Fix:** Added strict path normalization

#### **Atlassian Confluence (2019)**
- **CVE-2019-3396:** Path traversal in widget connector
- **Impact:** 10,000+ servers compromised, ransomware deployed
- **Damage:** Estimated $10M+ in recovery costs
- **Attack:** `../../../../etc/passwd` in template path

#### **Minecraft Servers (2021)**
- **CVE-2021-44228 (Log4Shell) exacerbation:** Combined with path traversal
- **Impact:** Millions of game servers compromised
- **Cause:** File paths in logging configuration

#### **npm Ecosystem (Ongoing)**
- **Multiple packages:** tar, unzip, extract-zip
- **Impact:** Supply chain attacks affecting thousands of projects
- **Pattern:** Zip extraction without path validation

---

## The Attack: Just Two Characters

Path traversal (also called **directory traversal**) uses `../` to escape the intended directory:

```python
# INTENDED: User downloads their profile picture
base_dir = "/var/www/uploads"
requested = "user123/avatar.jpg"
# Serves: /var/www/uploads/user123/avatar.jpg ✅ Safe

# ATTACK: User requests system password file
base_dir = "/var/www/uploads"  
requested = "../../../../etc/passwd"
# Serves: /etc/passwd ❌ SECURITY BREACH!
```

### What Attackers Can Access

**Configuration Files:**
```
../../config/database.yml    # Database credentials
../../../.env                # API keys, secrets
```

**System Files:**
```
../../../../etc/passwd       # User accounts
../../../../etc/shadow       # Password hashes
../../../../root/.ssh/id_rsa # SSH private keys
```

**Application Source Code:**
```
../../src/admin/dashboard.py # Business logic
../../../lib/payment.js      # Payment processing code
```

**Log Files:**
```
../../../../var/log/auth.log    # Authentication logs
../../../logs/application.log   # Sensitive data in logs
```

---

## The Security Implications

### 🔐 What Happens When Path Validation Fails?

**1. Data Breaches**
```python
# Real attack on healthcare provider (2019)
GET /download?file=../../../patient_records/all.csv
# Result: 1.2 million patient records exposed
```

**2. Remote Code Execution**
```python
# Overwrite application code
PUT /upload?path=../../app/main.py
# Upload malicious code → next request executes it
```

**3. Privilege Escalation**
```python
# Read admin credentials
GET /file?path=../../../../config/admin.json
# Use credentials to become admin
```

**4. Container Escape**
```python
# Docker container path traversal
GET /logs?file=../../../../proc/self/cgroup
# Identify and escape container boundaries
```

---

## The Challenge: Secure Path Validator

### The Problem

You need to implement this function:

```python
from typing import bool

def is_safe_path(base_dir: str, requested_path: str) -> bool:
    """
    Validate that requested_path stays within base_dir.
    
    Args:
        base_dir: The base directory (e.g., "/var/www/uploads")
        requested_path: User-provided path (e.g., "user/file.pdf")
    
    Returns:
        True if safe, False if path traversal attack
    """
    # YOUR CODE HERE
    pass
```

### Real-World Example

```python
# Legitimate file access
is_safe_path("/var/www/html", "images/logo.png")
# → True: /var/www/html/images/logo.png ✅

# Path traversal attack
is_safe_path("/var/www/html", "../../../etc/passwd")
# → False: Escapes to /etc/passwd ❌

# Absolute path attack
is_safe_path("/uploads", "/etc/shadow")
# → False: Ignores base_dir ❌

# Tricky normalization
is_safe_path("/app", "static/../../../etc/hosts")
# → False: Normalizes to /etc/hosts ❌
```

---

## Why This Is Harder Than It Looks

### Edge Case 1: Path Normalization 🐛

**The problem:** Paths can be written many ways:

```python
# All these refer to the SAME file:
"images/logo.png"
"images/./logo.png"
"images//logo.png"
"images/../images/logo.png"
"./images/logo.png"
```

**Your validator must normalize before checking:**
```python
# WRONG: String comparison doesn't work
def is_safe_path_WRONG(base, path):
    return not ".." in path  # ❌ Misses: images/../../../etc/passwd

# CORRECT: Normalize first
import os
def is_safe_path_CORRECT(base, path):
    normalized = os.path.normpath(os.path.join(base, path))
    return normalized.startswith(os.path.abspath(base))  # ✅
```

### Edge Case 2: Absolute Paths

**The attack:** User provides absolute path, bypassing base_dir entirely:

```python
is_safe_path("/var/www", "/etc/passwd")
# Naive check: "/var/www" + "/etc/passwd" = "/var/www/etc/passwd" ✅ Safe?
# WRONG! os.path.join() handles absolute paths specially
# Result: "/etc/passwd" ❌ Attack succeeds!
```

### Edge Case 3: Encoded Characters

**The attack:** URL-encoded path separators:

```python
# URL encoding might bypass naive filters
requested = "images%2F..%2F..%2Fetc%2Fpasswd"
# %2F is the URL encoding for /

# However, Python's os.path.join() and normpath() 
# work on already-decoded strings, so this typically
# won't bypass validation if done correctly
```

### Edge Case 4: Multiple Dot Filenames (The Tricky One!)

**The gotcha:** In Linux, `...` is a valid filename (not the same as `..`):

```python
# These are ALL valid Linux filenames:
"..."      # Three dots - perfectly valid file
"...."     # Four dots - also valid
"....."    # Five dots - still valid
"file..."  # Trailing dots - valid

# But THIS is directory traversal:
".."       # Two dots - parent directory

# And this can trick naive validators:
is_safe_path("/var/www", "...")
# Expected: True (it's a filename, not parent directory!)

# Even trickier:
is_safe_path("/var/www", ".../../../etc/passwd")
# Expected: False (attack! The ... is a dir, then ../../ escapes)
```

**Why this matters:**
- Naive solutions checking for `".."` in the string will fail
- You need proper path normalization with `os.path`
- String matching alone won't work!

### Edge Case 5: Empty and Special Cases

```python
is_safe_path("/var/www", "")        # Empty string - safe or unsafe?
is_safe_path("/var/www", ".")       # Current dir - safe?
is_safe_path("/var/www", "..")      # Parent dir - definitely unsafe!
is_safe_path("/var/www", "/var/www")  # Same as base - safe?
```

---

## The Testing Gauntlet

Your implementation will face **60 comprehensive tests**:

### ✅ Basic Functionality (Tests 1-5)
- Simple safe files
- Nested directories
- Files in base directory
- Deep nesting

### 🎯 Boundary Conditions (Tests 6-10)
- Empty paths
- Current directory (`.`)
- Trailing slashes
- Paths same as base

### 🚨 Attack Scenarios (Tests 11-15)
- Single `../` escape
- Multiple `../` escapes
- Classic `../../../etc/passwd`
- Escape then descend
- Many parent directories

### 🔧 Normalization (Tests 16-20)
- Current directory in middle (`./`)
- Redundant slashes (`//`)
- Parent then child (`../`)
- Complex safe normalization

### ⚡ Advanced Attacks (Tests 21-25)
- Absolute paths
- Double dots without slash
- Parent directory as entire path
- Triple dots (edge case)

### 🔬 Edge Cases (Tests 26-30)
- Deep nested escapes
- URL-encoded attempts
- Dots in filenames (`.config`)
- Hidden files
- Spaces and special characters

### 🗂️ Base Directory Variations (Tests 31-35)
- Different base directories (`/home`, `/opt`, `/tmp`, `/srv`)
- Attacks from various bases
- Different directory structures

### 🎭 Multiple Dot Filenames (Tests 36-40)
- `...` as filename (valid!)
- `....` as filename (valid!)
- `.....` as filename (valid!)
- Mix of `..` and `...` (tricky!)
- Three dots with parent directory (attack!)

### 🌐 Advanced Linux Cases (Tests 41-45)
- Unicode filenames (文档.pdf)
- Emoji filenames (🔒)
- Very long paths (255 chars)
- Special characters (-, _, ~)
- Complex combinations

### 🔐 Root and System Directories (Tests 46-50)
- Root directory (`/`) as base
- System config directories (`/etc`)
- Attacks from privileged locations
- `/proc` filesystem access attempts

### 💥 Complex Attack Combinations (Tests 51-55)
- Multiple escape sequences
- Mixed normalization trickery
- Deeply hidden parent escapes
- Alternating navigation patterns
- Current directory flooding

### 🎯 Extreme Edge Cases (Tests 56-60)
- Special character combinations
- Multiple consecutive slashes with escapes
- Hidden files with parent escapes
- Ultimate stress test with everything combined

---

## The Exercise

### What You'll Get

1. **LeetCode-style test file** (`path_validator_60_tests.py`)
   - Implement your solution in the designated section
   - Run the file to see results instantly
   - Beautiful colored output showing pass/fail
   - 45 comprehensive test cases

2. **Detailed failure reports**
   - See exactly what went wrong
   - Identifies false negatives (attacks allowed!) vs false positives
   - Security-focused feedback

3. **Progressive difficulty**
   - Basic tests → boundary conditions → attacks → edge cases → tricky multiple-dot filenames
   - Build confidence as you solve more

### Sample Output

```bash
$ python3 path_validator_60_tests.py

╔══════════════════════════════════════════════════════════════╗
║          SECURE PATH VALIDATOR CHALLENGE                     ║
║                  45 TEST CASES                               ║
╚══════════════════════════════════════════════════════════════╝

✅ PASS - Test 1: Simple safe file → SAFE
✅ PASS - Test 2: Safe nested directory → SAFE
✅ PASS - Test 11: Single parent escape → BLOCKED
✅ PASS - Test 12: Multiple parent escapes → BLOCKED
✅ PASS - Test 36: Three dots as filename → SAFE
✅ PASS - Test 37: Four dots as filename → SAFE
...
✅ PASS - Test 45: Complex combination → BLOCKED

═══════════════════════════════════════════════════════════════
SUMMARY
═══════════════════════════════════════════════════════════════

Tests Passed: 60/60

╔══════════════════════════════════════════════════════════════╗
║            🎉 PERFECT! ALL 60 TESTS PASSED! 🎉              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Why This Exercise Builds Real AppSec Skills

### 1. **String Manipulation Security**
After Python Workout Chapter 2, you know strings. Now learn how string operations affect security:
- Normalization pitfalls
- Special character handling
- Cross-platform path handling

### 2. **Defensive Programming**
- Never trust user input
- Validate before processing
- Think like an attacker

### 3. **Real-World Vulnerability**
- Used in OWASP Top 10
- Affects production systems daily
- Critical for web developers

### 4. **Testing Security Controls**
- Positive tests (legitimate files)
- Negative tests (attacks blocked)
- Edge cases matter in security

### 5. **Python Standard Library**
Learn security-relevant functions:
- `os.path.normpath()` - Normalize paths
- `os.path.abspath()` - Get absolute paths
- `os.path.join()` - Safely combine paths
- `os.path.commonpath()` - Find common base

---

## Common Mistakes to Avoid

### ❌ Mistake #1: String Matching
```python
# WRONG - Easily bypassed
def is_safe_path(base, path):
    return ".." not in path  # ❌
    
# Bypasses:
"images/....//....//etc/passwd"  # Double dots with extra dots
"images/..%2F..%2Fetc%2Fpasswd"  # URL encoding
```

### ❌ Mistake #2: Regex-Based Validation
```python
# WRONG - Incomplete
def is_safe_path(base, path):
    import re
    return not re.search(r'\.\./', path)  # ❌
    
# Misses:
"/etc/passwd"  # Absolute path
".."           # Parent without slash
"..\\windows"  # Backslashes
```

### ❌ Mistake #3: Forgetting Normalization
```python
# WRONG - Doesn't normalize
def is_safe_path(base, path):
    full = base + "/" + path
    return full.startswith(base)  # ❌ Always true!
    
# Allows:
"images/../../../etc/passwd"  # String starts with base, but resolves outside
```

---

## Take the Challenge

### Get the Exercise Files

```bash
# Download the exercise
curl -O https://github.com/YOUR_USERNAME/appsec-challenges/path_validator_30_tests.py

# Run the tests
python3 path_validator_30_tests.py
```

**Files included:**
- `path_validator_30_tests.py` - Main test file (30 tests)
- `solution_example.py` - Minimal example (for after completion)
- `README.md` - Complete instructions

### Time Yourself

- ⏱️ **30 minutes:** Excellent - you understand path security
- ⏱️ **45 minutes:** Good - solid problem-solving
- ⏱️ **60 minutes:** Normal - thorough and careful

### Share Your Results

When you pass all 60 tests:
```bash
# Share on Twitter/X
Just passed 60/60 tests on the Path Traversal AppSec Challenge! 
🛡️ 45 comprehensive security tests
🐛 Caught all directory traversal attacks
💡 Even handled the tricky "..." filename edge case!
💪 Production-ready validator!

#AppSec #Python #Security #100DaysOfCode
```

---

## What You'll Learn

By completing this challenge, you'll understand:

✅ **Path traversal attacks** and real-world impact  
✅ **String manipulation security** pitfalls  
✅ **Python os.path functions** for safe file handling  
✅ **Defensive validation** techniques  
✅ **Security testing** with positive and negative tests  

---

## For Hiring Managers

This exercise tests candidates on:
- ✅ Security awareness (understanding attack vectors)
- ✅ Defensive programming (validating all inputs)
- ✅ Python standard library knowledge
- ✅ Edge case handling (including tricky multi-dot filenames)
- ✅ Testing thoroughness

**If a candidate passes all 60 tests,** they demonstrate:
- Understanding of OWASP vulnerabilities
- Ability to think like an attacker
- Production-ready code quality
- Security-first mindset
- Attention to subtle edge cases

---

## Real-World Impact

### Before You Had This Skill
```python
# Vulnerable file download endpoint
@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(f"/uploads/{filename}")  # ❌ DANGEROUS!

# Attack: /download?file=../../../../etc/passwd
```

### After You Pass This Challenge
```python
# Secure file download endpoint
@app.route('/download')
def download():
    filename = request.args.get('file')
    
    if not is_safe_path("/uploads", filename):  # ✅ Validation!
        abort(400, "Invalid file path")
        
    return send_file(os.path.join("/uploads", filename))

# Attack blocked, logged for security monitoring
```

---

## Level Up: After You Pass

### 1. **Test Against Real Exploits**
```python
# Try OWASP's path traversal test cases
owasp_attacks = [
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
]
```

### 2. **Add Logging**
```python
def is_safe_path(base, path):
    result = validate(base, path)
    if not result:
        logging.warning(f"Path traversal attempt blocked: {path}")
    return result
```

### 3. **Build a Real API**
```python
from fastapi import FastAPI, HTTPException
from pathlib import Path

app = FastAPI()

@app.get("/files/{filepath:path}")
async def read_file(filepath: str):
    if not is_safe_path("/var/www/uploads", filepath):
        raise HTTPException(400, "Invalid file path")
    # ... serve file
```

### 4. **Add More Defenses**
- Allowlist file extensions (only `.pdf`, `.jpg`, etc.)
- Maximum path length checks
- Character allowlist (alphanumeric + underscore)
- Rate limiting on file requests

---

## Resources

### Recommended Reading
- 📖 **"API Security in Action"** by Neil Madden (Chapter 8, pp. 251-254)
- 📖 **"Full Stack Python Security"** by Dennis Byrne (Chapter 6, pp. 123-127)
- 📖 **"Secure by Design"** by Johnsson, Deogun, Sawano (Chapter 7, pp. 189-193)
- 📖 **"Python Workout"** by Reuven Lerner (Chapter 2: Strings)

### Real-World Examples
- [OWASP: Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Zip Slip Vulnerability](https://snyk.io/research/zip-slip-vulnerability)
- [GitHub CVE-2022-24765](https://github.blog/2022-04-12-git-security-vulnerability-announced/)
- [Atlassian Confluence CVE-2019-3396](https://confluence.atlassian.com/doc/confluence-security-advisory-2019-03-20-966660264.html)

### Security Tools
- [OWASP ZAP](https://www.zaproxy.org/) - Test your applications
- [Burp Suite](https://portswigger.net/burp) - Security testing
- [Snyk](https://snyk.io/) - Dependency scanning

---

## Ready to Start?

Download the exercise and prove your security skills:

👉 **[Get the Exercise Files](#)**

Remember: Path traversal is in the **OWASP Top 10** and affects production systems every day. This isn't just an exercise - it's a critical security skill.

Good luck! 🛡️

---

## Discussion

- What edge cases surprised you most?
- Have you seen path traversal in real applications?
- How would you combine this with other security controls?
- Share your completion time in the comments!

---

*This exercise is part of a series on practical AppSec skills. Follow for more hands-on security challenges after Python Workout!*

#AppSec #Security #Python #PathTraversal #Challenge #PythonWorkout #100DaysOfCode
