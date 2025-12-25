---
title: "Security Code Review Challenge: Spot the Path Traversal Attacks"
published: false
description: "Your first day as a security intern - can you identify which API requests are path traversal attempts? Week 2 Python exercise."
tags: appsec, security, python, beginners
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/path-traversal-detector.png
---

# Your First Security Code Review: Spot the Path Traversal

**⏱️ Time:** 30-45 minutes  
**🎯 Difficulty:** Beginner (Week 2 Python)  
**💼 Skills:** Pattern recognition, string operations, security awareness  
**📚 Prerequisites:** Basic Python (strings, loops, functions)

## The Scenario

It's your first week as a security intern at a fast-growing startup. Your manager drops by your desk:

> "Hey, we just discovered the previous developer left behind a file upload API with some... questionable code. We have 10,000 logged API requests from last month. I need you to write a quick Python script to flag which requests might be path traversal attempts. Can you handle that?"

You nod confidently. After all, how hard can it be?

Then you look at the logs:

```
/api/download?file=report.pdf
/api/download?file=../../etc/passwd
/api/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
/api/download?file=..\\..\\windows\\system32\\config\\sam
```

**Three of these are attacks. Can you spot them?**

---

## What is Path Traversal?

Path traversal (also called directory traversal) is when attackers manipulate file paths to access files outside the intended directory.

**From "Hacking APIs"** by Corey Ball (Chapter 9, pp. 218-219):

> "Directory traversal... allows an attacker to direct the web application to move to a parent directory using some form of the expression `../` and then read arbitrary files."

### A Real Example

Here's vulnerable code (like what you might find):

```python
def download_file(filename):
    # Get filename from user
    path = f"/var/app/data/{filename}"
    
    # Open and return the file
    return open(path, 'rb').read()
```

**Looks innocent, right?**

Now watch what happens when an attacker sends this:

```python
filename = "../../etc/passwd"

# The path becomes:
# /var/app/data/../../etc/passwd
#
# Which the operating system resolves to:
# /etc/passwd
#
# Result: Password file leaked! 💥
```

---

## Why This Matters

### Real Breach: Capital One (2019)

In 2019, Capital One suffered a massive breach where an attacker used path traversal-style techniques to access cloud server metadata and steal **100 million customer records**.

The attacker used sequences like `../` to escape intended directories and access AWS credential files.

**Cost:** $80 million in fines.

### What Attackers Can Access

When path traversal succeeds, attackers can read:

**On Linux/Unix systems:**
- `/etc/passwd` - User account information
- `/etc/shadow` - Password hashes
- `/root/.ssh/id_rsa` - SSH private keys (full server access!)
- `/var/log/auth.log` - Authentication logs
- `/proc/self/environ` - Environment variables (may contain secrets)

**On Windows systems:**
- `C:\Windows\System32\config\SAM` - Password database
- `C:\Windows\win.ini` - System configuration
- `\windows\system32\drivers\etc\hosts` - Network configuration

---

## Attack Patterns You Need to Recognize

### Pattern 1: Classic Traversal Sequences

The most common attack uses `../` (Unix) or `..\` (Windows):

```
/download?file=../../../etc/passwd
/download?file=..\\..\\windows\\system32\\config\\sam
```

**Why it works:**
- `..` means "parent directory"
- Each `../` goes up one level
- Repeat enough times to escape the data directory

### Pattern 2: Absolute Paths

Sometimes attackers just specify the full path:

```
/download?file=/etc/passwd
/download?file=C:\Windows\System32\config\SAM
```

**If the vulnerable code doesn't validate, this works directly!**

### Pattern 3: URL Encoding

To bypass naive filters, attackers encode the path:

```
Normal:  ../../../etc/passwd
Encoded: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

**URL Encoding Translation:**
- `%2e` = `.` (dot)
- `%2f` = `/` (forward slash)
- `%5c` = `\` (backslash)

So `%2e%2e%2f` = `../`

### Pattern 4: Case Variations

On Windows, paths are case-insensitive:

```
/etc/passwd    ← Unix (case-sensitive)
/ETC/passwd    ← Still works on case-insensitive systems
/Etc/Passwd    ← Mixed case
```

Your detector needs to handle these!

---

## The Challenge

Write a Python function that detects these patterns:

```python
def contains_path_traversal(url_path: str) -> bool:
    """
    Detect if a URL path contains path traversal patterns.
    
    Args:
        url_path: A URL path string
    
    Returns:
        True if traversal detected, False otherwise
    
    Examples:
        >>> contains_path_traversal("/api/files/report.pdf")
        False  # Safe
        
        >>> contains_path_traversal("/download?file=../../etc/passwd")
        True  # Traversal detected!
    """
    pass  # Your code here
```

### What You Need to Detect

✅ **Classic traversal:** `../` and `..\`  
✅ **Sensitive paths:** `/etc/`, `/root/`, `C:\Windows`  
✅ **URL encoding:** `%2e%2e%2f`, `%2e%2e%5c`  
✅ **Case variations:** `/ETC/`, `/Root/`, `C:\WINDOWS`  

---

## Test Cases You'll Face

Your function will be tested against 100 real-world scenarios across 8 categories:

### Category 1: Safe Paths (Tests 1-20)
**Expected:** Return False

These are legitimate files that should NOT be flagged:
```python
"/api/v1/users"                      # Normal API
"/files/reports/2024/annual.pdf"    # Legitimate file
"/download?file=document.docx"       # Safe download
"/graphql?query=users"               # GraphQL endpoint
"/cdn/fonts/roboto-regular.woff2"   # Font file
```

### Category 2: Classic Unix Traversal (Tests 21-35)
**Expected:** Return True

Standard `../` attacks:
```python
"/files/../../../etc/passwd"         # Unix traversal
"/api/files/../../../../root/.ssh/id_rsa"  # SSH keys
"/docs/../../var/log/auth.log"       # Log files
"/upload/../../../etc/crontab"       # Cron jobs
"/static/../../etc/mysql/my.cnf"     # MySQL config
```

### Category 3: Classic Windows Traversal (Tests 36-50)
**Expected:** Return True

Standard `..\` attacks:
```python
"/download?file=..\\..\\windows\\system32\\config\\sam"
"/files/..\\..\\..\\windows\\win.ini"
"/api/load?path=..\\..\\windows\\system32\\drivers\\etc\\hosts"
"/download?file=..\\..\\..\\boot.ini"
"/files/..\\..\\program files\\app\\config.xml"
```

### Category 4: Absolute Paths - Unix (Tests 51-60)
**Expected:** Return True

Direct absolute path attacks:
```python
"/api/load?file=/etc/passwd"         # Direct path
"/download?file=/root/.bashrc"       # Root files
"/api/read?path=/var/log/syslog"     # System logs
"/load?file=/proc/version"           # Kernel info
"/files/path=/etc/ssh/sshd_config"   # SSH config
```

### Category 5: Absolute Paths - Windows (Tests 61-70)
**Expected:** Return True

Windows absolute paths:
```python
"/files/C:\\Windows\\System32\\config\\SAM"
"/download?file=C:\\Users\\Administrator\\.ssh\\id_rsa"
"/load?file=D:\\backup\\database\\users.sql"
"/api/read?file=C:\\Windows\\Panther\\Unattend.xml"
```

### Category 6: URL Encoded (Tests 71-80)
**Expected:** Return True

Encoded traversal attempts:
```python
"/files/%2e%2e/%2e%2e/etc/passwd"    # Encoded ../
"/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"  # Full encoding
"/api/load?path=..%2f..%2fetc%2fpasswd"  # Partial encoding
"/files/%2e%2e%5c%2e%2e%5cwindows"   # Encoded backslashes
```

### Category 7: Case Variations (Tests 81-90)
**Expected:** Return True

Mixed case bypass attempts:
```python
"/files/../../ETC/passwd"            # Uppercase
"/download?file=..\\..\\WINDOWS\\system32"  # WINDOWS caps
"/api/load?path=/Root/.ssh/id_rsa"   # Mixed case
"/files/../../Var/Log/auth.log"      # Mixed Var
```

### Category 8: Advanced Evasion (Tests 91-100)
**Expected:** Return True

Sophisticated bypass techniques:
```python
"/files/....//....//etc/passwd"      # Double dot slash
"/download?file=..;/..;/etc/passwd"  # Semicolon separator
"/api/load?path=..//..//..//etc/passwd"  # Extra slashes
"/files/..%00/..%00/etc/passwd"      # Null byte injection
"/api/load?file=%252e%252e%252fetc%252fpasswd"  # Double encoding
```

---

## Hints (Without Spoilers!)

### Python String Operations You'll Need

**1. Checking if a substring exists:**
```python
if 'substring' in my_string:
    # Found it!
```

**2. Case-insensitive checking:**
```python
if 'etc' in my_string.lower():
    # Matches 'etc', 'ETC', 'Etc', etc.
```

**3. Checking multiple conditions:**
```python
if condition1 or condition2 or condition3:
    return True
```

### Strategy

Think about your function like this:

```python
def contains_path_traversal(url_path: str) -> bool:
    # Check for pattern 1: Classic traversal
    if ??? in url_path:
        return True
    
    # Check for pattern 2: Windows traversal
    if ??? in url_path:
        return True
    
    # Check for pattern 3: Sensitive paths
    if ??? in url_path.lower():
        return True
    
    # Check for pattern 4: URL encoding
    if ??? in url_path.lower():
        return True
    
    # No traversal detected
    return False
```

**Fill in the `???` parts!**

### Common Gotchas

❌ **Wrong:** `if '..' in url_path`  
✅ **Right:** `if '../' in url_path`

**Why?** Just checking for `..` would flag legitimate files like `version-2..0.tar.gz`

❌ **Wrong:** `if '/etc/' in url_path`  
✅ **Right:** `if '/etc/' in url_path.lower()`

**Why?** Attackers use `/ETC/`, `/Etc/`, etc. to bypass filters

❌ **Wrong:** Forgetting Windows backslashes  
✅ **Right:** Check for BOTH `../` AND `..\\`

---

## What You'll Learn

By completing this exercise, you'll understand:

- ✅ What path traversal attacks look like
- ✅ How attackers use URL encoding to bypass filters
- ✅ Why case-insensitive checks matter
- ✅ The difference between Unix and Windows path separators
- ✅ How to use Python string operations for security

**This builds your security intuition** - you'll start seeing these patterns everywhere!

---

## Important Note: Learning vs. Production

🎓 **This is a LEARNING exercise**

In this challenge, you're building pattern recognition skills. You're learning to **identify** attacks by spotting common patterns.

🏭 **Production code is different**

In Week 8+ of your curriculum, you'll learn the **correct** way to prevent path traversal using:
- Path canonicalization
- Directory confinement
- Allowlist validation

**Pattern matching (what you're doing now) is NOT enough for production** because attackers have dozens of bypass techniques.

But you need to **recognize attacks** before you can **prevent them**, so this is the right place to start! 🚀

---

## Download the Exercise

```bash
git clone https://github.com/fosres/AppSec-Exercises
cd AppSec-Exercises/path-traversal-detector-week2

python3 path_traversal_detector_week2.py
```

---

## Success Criteria

### 🥉 Bronze (60/100 - 60%)
You're catching basic `../` patterns. Keep going!

**What you're detecting:**
- Classic Unix traversal (`../`)
- Some Windows patterns (`..\`)
- Basic sensitive paths

**Still missing:**
- URL encoding variations
- Case-insensitive checks
- Advanced evasion techniques

### 🥈 Silver (80/100 - 80%)
You're handling most cases including URL encoding. Almost there!

**You're now detecting:**
- ✓ All basic traversal patterns
- ✓ Most URL encoding variants
- ✓ Common sensitive paths
- ✓ Some case variations

**Still need:**
- Advanced evasion (null bytes, double encoding)
- Edge case handling

### 🥇 Gold (100/100 - 100%)
Perfect! You can now recognize path traversal in the wild.

**You've mastered:**
- ✓ Unix and Windows traversal
- ✓ All sensitive file paths
- ✓ URL encoding (single and double)
- ✓ Case-insensitive matching
- ✓ Advanced evasion techniques
- ✓ Edge cases and corner scenarios

**You're ready for:**
- PortSwigger labs
- Real security code reviews
- Week 8 advanced prevention techniques

---

## After You Pass

### 1. Practice on Real Sites

Try the **PortSwigger Directory Traversal Labs** (free):
- https://portswigger.net/web-security/file-path-traversal

These let you exploit path traversal on practice sites.

### 2. Add to Your Portfolio

This demonstrates:
- Security awareness
- Pattern recognition
- Python string manipulation
- Problem-solving

### 3. Continue Your Journey

- **Week 8:** Learn proper prevention with `pathlib`
- **Week 10:** Bug bounty preparation
- **Week 11:** AppSec system design

---

## Resources

### Books
- **"Hacking APIs"** by Corey Ball (Chapter 9, pp. 218-219)
  - Directory traversal fuzzing techniques
- **"Full Stack Python Security"** by Dennis Byrne
  - Input validation principles

### Labs & Practice
- [PortSwigger Directory Traversal](https://portswigger.net/web-security/file-path-traversal)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

### Python Documentation
- [String methods](https://docs.python.org/3/library/stdtypes.html#string-methods)
- [`str.lower()`](https://docs.python.org/3/library/stdtypes.html#str.lower)

---

## The Bottom Line

Path traversal is one of the **most common vulnerabilities** in web applications. Learning to recognize these patterns is your first step toward:

1. **Understanding attacks** - How do hackers think?
2. **Code review skills** - Spotting vulnerabilities in code
3. **Building defenses** - You'll learn prevention in Week 8+

**Start with recognition. Build to prevention.**

---

## Comments? Questions?

- Did you catch all 30 patterns?
- What was the hardest pattern to detect?
- Have you seen path traversal in real code?

Let's discuss! 👇

---

**Tags:** #appsec #security #python #beginners #webdev #cybersecurity #pathtraversal

---

*Based on attack patterns from "Hacking APIs" by Corey Ball. All examples are for educational purposes only.*
