# Secure Path Validator Challenge - 60 Comprehensive Tests

## 🎯 The Challenge

Implement a secure path validator that detects directory traversal attacks on **GNU/Linux systems**. Your function must pass 60 tests covering:
- ✅ Legitimate file access
- ✅ Path traversal attacks (`../../../etc/passwd`)
- ✅ Absolute path attacks
- ✅ Path normalization edge cases
- ✅ Linux-specific path handling
- ✅ **Tricky multi-dot filenames** (`...`, `....`, etc.)
- ✅ Root directory handling
- ✅ Complex attack combinations
- ✅ Extreme edge cases

**Perfect for:** Developers who completed Python Workout Chapter 2 (Strings)  
**Platform:** GNU/Linux (Unix-style forward slash paths)  
**Difficulty:** Intermediate to Advanced

**Edge case alert:** Did you know `...` is a valid Linux filename? Can your validator handle root (`/`) as the base directory? These 60 tests will thoroughly challenge your solution!

---

## 🚨 What is Path Traversal?

Path traversal (directory traversal) is a web security vulnerability that allows attackers to access files outside the intended directory using `../` sequences.

### Real-World Impact

**Zip Slip (2018):** Affected 2,500+ projects including Oracle, Amazon, LinkedIn  
**Atlassian Confluence (2019):** CVE-2019-3396, 10,000+ servers compromised  
**GitHub Enterprise (2022):** CVE-2022-24765, remote code execution  

---

## 🚀 Quick Start

### 1. Download the file
```bash
curl -O [GitHub URL]/path_validator_60_tests.py
```

### 2. Open and find the implementation section
```python
def is_safe_path(base_dir: str, requested_path: str) -> bool:
    """YOUR SOLUTION GOES HERE"""
    pass  # Replace this with your code
```

### 3. Implement your solution

### 4. Run the tests
```bash
python3 path_validator_60_tests.py
```

### 5. See instant feedback
```
✅ PASS - Test 1: Simple safe file → SAFE
✅ PASS - Test 11: Single parent escape → BLOCKED
✅ PASS - Test 36: Three dots as filename → SAFE
...
Tests Passed: 60/60

🎉 PERFECT! ALL 60 TESTS PASSED! 🎉
```

---

## 📋 The 60 Tests

### Basic Functionality (1-5)
- Simple safe files in subdirectories
- Nested directory structures
- Files in base directory
- Deep nesting

### Boundary Conditions (6-10)
- Empty paths
- Current directory (`.`)
- Trailing slashes
- Paths identical to base

### Attack Scenarios (11-15)
- `../` escapes
- `../../../etc/passwd` attacks
- Multiple parent directory sequences
- Escape then descend patterns

### Normalization Tests (16-20)
- Current directory in middle (`./`)
- Redundant slashes (`//`)
- Parent then child (`images/../images/`)
- Complex but safe paths

### Advanced Attacks (21-25)
- Absolute paths (`/etc/passwd`)
- Double dots without slash
- Parent directory as entire path
- Edge cases with special sequences

### Edge Cases (26-30)
- Deep nested escapes
- URL-encoded attempts
- Dots in filenames
- Hidden files (`.config`)
- Spaces and special characters

### Base Directory Variations (31-35)
- Different base directories (`/home`, `/opt`, `/tmp`, `/srv`)
- Attacks from various base paths
- Different directory structures

### Multiple Dot Filenames (36-40)
- `...` as filename (valid!)
- `....` as filename (valid!)
- `.....` as filename (valid!)
- Mix of `..` and `...` (tricky!)
- Three dots with parent escape (attack!)

### Advanced Linux Cases (41-45)
- Unicode filenames (文档.pdf)
- Emoji filenames (🔒)
- Very long path components (255 chars)
- Special characters (-, _, ~)
- Complex combinations

### Root and System Directories (46-50)
- Root directory (`/`) as base
- System config directories (`/etc`)
- Attacks from privileged locations
- `/proc` filesystem attempts

### Complex Attack Combinations (51-55)
- Multiple escape sequences
- Mixed normalization trickery
- Deeply hidden parent escapes
- Alternating navigation patterns

### Extreme Edge Cases (56-60)
- Special character combinations
- Multiple consecutive slashes
- Hidden files with escapes
- Ultimate stress test

---

## 🔑 Function Signature

```python
def is_safe_path(base_dir: str, requested_path: str) -> bool:
    """
    Validate that requested_path stays within base_dir.
    
    Args:
        base_dir: Base directory (e.g., "/var/www/uploads")
        requested_path: User-provided path (e.g., "user/file.pdf")
    
    Returns:
        True if safe, False if path traversal attack detected
    """
```

---

## 💡 Critical Requirements

1. **Return type:** MUST be `bool` (True = safe, False = attack)
2. **Block `../` escapes:** Prevent directory traversal
3. **Block absolute paths:** Paths starting with `/`
4. **Normalize paths:** Handle `.`, `..`, `//` correctly
5. **Use `os.path`:** Leverage Python standard library
6. **Linux paths only:** Forward slashes (`/`) as separator

---

## ⚠️ Common Mistakes

### ❌ Simple String Matching
```python
# WRONG - Easily bypassed
def is_safe_path(base, path):
    return ".." not in path  # Misses many attacks!
```

### ❌ Forgetting Normalization
```python
# WRONG - Doesn't resolve ..
def is_safe_path(base, path):
    full = base + "/" + path
    return full.startswith(base)  # Always true!
```

### ❌ Not Using `os.path`
```python
# WRONG - Manual parsing is error-prone
def is_safe_path(base, path):
    parts = path.split("/")
    # Complex manual logic... bugs everywhere!
```

### ✅ Correct Approach Hints
```python
import os

def is_safe_path(base_dir, requested_path):
    # 1. Combine paths
    # 2. Normalize (resolve .., ., //)
    # 3. Get absolute paths
    # 4. Check if result is within base
    # Use: os.path.join(), os.path.normpath(), os.path.abspath()
```

---

## 🎯 Example Usage

### Safe Paths
```python
is_safe_path("/var/www", "images/logo.png")
# → True: /var/www/images/logo.png ✅

is_safe_path("/uploads", "user123/doc.pdf")
# → True: /uploads/user123/doc.pdf ✅

is_safe_path("/app", "static/css/main.css")
# → True: /app/static/css/main.css ✅
```

### Attack Paths
```python
is_safe_path("/var/www", "../../../etc/passwd")
# → False: Escapes to /etc/passwd ❌

is_safe_path("/uploads", "/etc/shadow")
# → False: Absolute path attack ❌

is_safe_path("/app", "..")
# → False: Parent directory escape ❌
```

---

## 🏆 Success Criteria

**Pass all 60 tests!**

When you see this:
```
╔══════════════════════════════════════════════════════════════╗
║            🎉 PERFECT! ALL 60 TESTS PASSED! 🎉              ║
╚══════════════════════════════════════════════════════════════╝

Your path validator is secure! 🛡️
```

You've built a production-ready path validator! 💪

---

## 🔒 Security Notes

### What This Validates
✅ Path stays within base directory  
✅ No `../` escapes  
✅ No absolute path attacks  
✅ Proper normalization  

### What This Doesn't Validate
❌ File existence  
❌ File permissions  
❌ Symbolic links  
❌ File content  

### Defense in Depth

**Always combine path validation with:**
- Filesystem permissions (chroot, user isolation)
- File extension allowlists
- Maximum path length checks
- Rate limiting on file operations
- Security logging and monitoring

---

## 📚 Inspired By

- **"API Security in Action"** by Neil Madden (Chapter 8, pp. 251-254)
- **"Full Stack Python Security"** by Dennis Byrne (Chapter 6, pp. 123-127)
- **"Secure by Design"** by Johnsson, Deogun, Sawano (Chapter 7, pp. 189-193)
- **"Python Workout"** by Reuven Lerner (Chapter 2: Strings)

Real-world vulnerabilities:
- **Zip Slip:** Path traversal in archive extraction
- **GitHub CVE-2022-24765:** Git path traversal
- **Atlassian CVE-2019-3396:** Confluence path traversal

---

## 🚀 Next Steps

After passing all tests:

### 1. **Test Against OWASP Examples**
```python
# Try encoded attacks
"..%2F..%2Fetc%2Fpasswd"
"%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

### 2. **Add Security Logging**
```python
import logging

def is_safe_path(base, path):
    result = validate(base, path)
    if not result:
        logging.warning(f"Path traversal blocked: {path}")
    return result
```

### 3. **Build a File API**
```python
from fastapi import FastAPI, HTTPException

@app.get("/download/{filepath:path}")
async def download(filepath: str):
    if not is_safe_path("/uploads", filepath):
        raise HTTPException(400, "Invalid path")
    return FileResponse(f"/uploads/{filepath}")
```

### 4. **Add More Validations**
- File extension allowlist
- Maximum path length
- Character allowlist
- Rate limiting

---

## 💬 Discussion Questions

- What edge cases surprised you?
- How would you handle symbolic links?
- Should empty paths be safe or unsafe?
- How does this apply to containerized Linux environments?

---

## 🎓 Learning Objectives

By completing this challenge:

✅ Understand path traversal attacks  
✅ Master Python `os.path` functions  
✅ Practice defensive programming  
✅ Write security-focused tests  
✅ Build production-ready validators  

---

## 📄 License

MIT License - Use for learning, portfolios, interviews, hiring

---

**Ready to secure your file systems?** Open `path_validator_60_tests.py` and start coding! 🛡️
