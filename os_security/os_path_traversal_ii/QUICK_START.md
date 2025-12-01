# Secure File Path Validator Exercise - Quick Start

## What You Have

I've created a comprehensive Python Workout-style exercise that bridges **Effective Python correctness** with **real-world AppSec vulnerabilities**. Here's what's included:

### 📁 Files Created

1. **secure_path_validator.py** - Challenge stub with function signatures
2. **test_secure_path_validator.py** - 30+ comprehensive test cases
3. **BLOG_POST_secure_path_validator.md** - Detailed explanation of concepts
4. **README.md** - Complete exercise instructions

## 🎯 Learning Objectives

This exercise teaches you:

✅ **Effective Python Item 10** - bytes/str handling that prevents crashes  
✅ **Effective Python Item 15** - Unicode encoding/decoding issues  
✅ **Hacking APIs Ch. 13** - Encoding-based attack bypasses  
✅ **API Security Ch. 2** - Allowlist validation principles  
✅ **Real CVEs** - Path traversal attacks from Pulse Secure, Apache, Atlassian

## 🚀 Quick Start (5 Minutes)

### Step 1: Read the Blog Post First (15 minutes)
```bash
# Open and read: BLOG_POST_secure_path_validator.md
# This explains all the concepts you need
```

### Step 2: Review the Challenge File (5 minutes)
```bash
# Open: secure_path_validator.py
# Read the docstrings and understand what each function should do
```

### Step 3: Start Implementing (2-4 hours)
```python
# Implement functions in this order:
1. safe_decode()      # Handles bytes/str conversion
2. normalize_path()   # URL decoding + Unicode normalization  
3. validate_path()    # Security validation (the core)
4. get_safe_path()    # Combines everything
```

### Step 4: Run Tests Frequently
```bash
# Test as you go:
python test_secure_path_validator.py

# Or with pytest for better output:
python -m pytest test_secure_path_validator.py -v
```

## 📊 Test Coverage Breakdown

**30+ Test Cases Cover:**

**Correctness (Effective Python):**
- Valid bytes → str conversion
- Valid str passthrough
- Unicode handling (both bytes and str)
- Invalid UTF-8 detection
- Type error handling
- Empty input handling

**Security (AppSec):**
- Path traversal: `../`, `..\\`
- URL encoded: `..%2F..%2Fetc%2Fpasswd`
- Double encoded: `..%252F` (WAF bypass)
- Overlong UTF-8: `\xc0\xaf` instead of `/`
- Null byte injection: `file\x00.jpg`
- Absolute paths: `/etc/passwd`, `C:\\Windows`
- Special characters: `;`, `|`, backticks
- Unicode normalization bypass
- **Real CVE scenarios**: Pulse Secure, Apache HTTP Server

## 💡 Key Implementation Hints

### For safe_decode():
```python
# Use isinstance() to check type
# Use .decode('utf-8') for bytes
# Detect overlong UTF-8 by checking if multiple encodings exist
```

### For normalize_path():
```python
from urllib.parse import unquote
import unicodedata

# URL decode with unquote()
# Unicode normalize with unicodedata.normalize('NFC', path)
# Detect double encoding: if unquote twice changes it, it's suspicious
```

### For validate_path():
```python
import re

# Allowlist pattern: ^[a-zA-Z0-9_\-/]+$
# Check for: ../, ..\, null bytes, absolute paths
# Use safe_decode() first to handle bytes input
```

### For get_safe_path():
```python
from pathlib import Path

# Call safe_decode(), normalize_path(), validate_path()
# Use Path.resolve() to resolve .. and symlinks
# Check with .is_relative_to() that result stays in base_dir
```

## 🎓 Concept Map

```
Effective Python Item 10 (Correctness)
         ↓
    safe_decode()
         ↓
    normalize_path() ← Hacking APIs Ch. 13 (URL/Unicode tricks)
         ↓
    validate_path() ← API Security Ch. 2 (Allowlist validation)
         ↓
    get_safe_path() ← Production-ready integration
```

## 🔍 Example Test Cases

**Simple Valid Case:**
```python
assert validate_path("documents/report.pdf") == True
```

**Path Traversal Attack:**
```python
assert validate_path("../etc/passwd") == False
```

**URL Encoded Attack (CVE-2019-11510 style):**
```python
with self.assertRaises(SecurityError):
    get_safe_path("..%2F..%2Fetc%2Fpasswd", "/uploads")
```

**Null Byte Injection:**
```python
assert validate_path("../../etc/passwd\x00.jpg") == False
```

## 📚 Source Citations (Already in Code)

All code comments include page references:

- **Effective Python Third Edition** by Brett Slatkin
  - Item 10: pages 42-47
  - Item 15: pages 70-72

- **API Security in Action** by Neil Madden
  - Chapter 2: pages 47-50

- **Hacking APIs** by Corey Ball
  - Chapter 13: pages 271-274

## 🏆 Success Criteria

Your implementation is complete when:

✅ All 30+ tests pass  
✅ No crashes on invalid input (TypeError, UnicodeDecodeError handled)  
✅ All path traversal variants detected  
✅ Encoding bypasses prevented  
✅ Code follows Effective Python patterns

## 🚨 Common Mistakes (Don't Do These!)

❌ Using blocklists (`if "../" in path`) - attackers bypass with encoding  
❌ Forgetting null bytes - classic vulnerability  
❌ Skipping Unicode normalization - combining chars bypass checks  
❌ Only decoding once - double encoding is real  
❌ Using `os.path.normpath()` alone - doesn't prevent all attacks  
❌ Comparing bytes == str - silently returns False!

## 🎯 Career Value

This exercise demonstrates skills tested in **AppSec Engineering interviews** at:
- Trail of Bits
- NCC Group  
- Anthropic
- Datadog
- Cisco Talos

Interview questions this prepares you for:
- "How do you prevent path traversal?"
- "Explain bytes vs str security implications"
- "What's allowlist vs blocklist validation?"
- "How would you detect encoding bypasses?"

## 📅 Fits Your Week 1 Curriculum

This exercise perfectly complements your current study:

**Week 1 Focus:** Python Workout Ch. 1-2 + SQL Injection labs

**This Exercise Adds:**
- Python security patterns
- Real-world vulnerability scenarios
- Test-driven security development
- Foundation for OWASP Top 10 (coming in Weeks 2-4)

## ⏱️ Time Investment

- **Reading blog post:** 15-20 minutes
- **Understanding tests:** 10-15 minutes  
- **Implementation:** 2-4 hours
- **Total:** ~3-4 hours

**ROI:** Builds foundational skills used throughout your 18-week curriculum and in actual AppSec engineering roles.

## 🎁 Bonus Challenge

After completing the basic exercise, try:

1. **Add more attack detection:**
   - HTML entity encoding (`&#46;&#46;&#47;`)
   - UTF-16 encoding
   - Case variation (`..%2f` vs `..%2F`)

2. **Write a companion tool:**
   - CLI tool that validates file paths
   - Flask endpoint that uses your validator
   - Burp Suite extension to test APIs

3. **Blog about it:**
   - Write your own Dev.to post
   - Share on LinkedIn
   - Add to GitHub portfolio

---

## 🚀 Ready to Start?

1. Open **README.md** for full instructions
2. Read **BLOG_POST_secure_path_validator.md** to understand concepts
3. Open **secure_path_validator.py** and start implementing
4. Run **test_secure_path_validator.py** frequently

**Good luck!** This exercise will significantly strengthen your AppSec skills. 🔒

---

*Questions? Review the detailed explanations in the blog post or re-read the relevant book sections cited in the code comments.*
