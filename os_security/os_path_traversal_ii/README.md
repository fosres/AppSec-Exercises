# Secure File Path Validator - AppSec Python Exercise

## Overview

This exercise combines **Python correctness** (Effective Python) with **security best practices** (API Security in Action, Hacking APIs) to build a production-ready file path validator that prevents real-world attacks.

**Difficulty**: Intermediate  
**Time**: 2-4 hours  
**Prerequisites**: Basic Python, understanding of file systems

## Real-World Relevance

This exercise is inspired by actual CVEs affecting major companies:

- **CVE-2019-11510**: Pulse Secure VPN (path traversal via URL encoding)
- **CVE-2021-41773**: Apache HTTP Server (path traversal)
- **CVE-2022-24112**: Atlassian Confluence (Unicode normalization bypass)

These vulnerabilities exposed sensitive data from thousands of organizations.

## Learning Objectives

After completing this exercise, you will:

✅ Understand `bytes` vs `str` type confusion and security implications  
✅ Implement the "Unicode sandwich" pattern (Effective Python, p.42)  
✅ Detect encoding-based attack bypasses (URL encoding, double encoding)  
✅ Use allowlist validation correctly (API Security in Action, p.50)  
✅ Prevent path traversal vulnerabilities  
✅ Handle Unicode normalization attacks  
✅ Write security-focused test cases

## Files Included

```
secure_path_validator/
├── README.md                          # This file
├── secure_path_validator.py           # Challenge stub (implement here)
├── test_secure_path_validator.py      # 30+ test cases
└── BLOG_POST_secure_path_validator.md # Detailed explanation
```

## Your Task

Implement four functions in `secure_path_validator.py`:

### 1. `safe_decode(path_input: bytes | str) -> str`
- Convert bytes or str to str safely
- Detect invalid UTF-8 sequences
- Detect overlong UTF-8 encoding (security attack)

### 2. `normalize_path(path: str) -> str`
- Decode URL encoding (%2e%2e%2f → ../)
- Apply Unicode normalization (NFC)
- Detect double encoding attacks

### 3. `validate_path(path_input: bytes | str, base_dir: str) -> bool`
- Return True if safe, False if attack detected
- Detect: path traversal, absolute paths, null bytes, special chars
- Use allowlist validation (not blocklist)

### 4. `get_safe_path(path_input: bytes | str, base_dir: str) -> str`
- Combine all security checks
- Return full safe path under base_dir
- Raise SecurityError if attack detected

## Getting Started

### Step 1: Read the Blog Post

Start by reading `BLOG_POST_secure_path_validator.md` to understand:
- The bytes/str gotchas from Effective Python
- Real-world encoding attacks
- The Unicode sandwich pattern
- Implementation patterns

### Step 2: Review the Challenge File

Open `secure_path_validator.py` and read:
- Function signatures and type hints
- Docstrings explaining requirements
- Example attacks to detect

### Step 3: Study the Tests

Review `test_secure_path_validator.py` to understand:
- Expected behavior for valid inputs
- Attack patterns to detect
- Edge cases to handle

### Step 4: Implement Your Solution

Start with `safe_decode()` and work your way through each function:

```python
# Recommended implementation order:
1. safe_decode()       # Foundation: bytes/str handling
2. normalize_path()    # URL decoding and Unicode normalization
3. validate_path()     # Security validation logic
4. get_safe_path()     # Integration of all functions
```

### Step 5: Run Tests

```bash
# Run all tests
python -m pytest test_secure_path_validator.py -v

# Or run without pytest
python test_secure_path_validator.py

# Run specific test class
python -m pytest test_secure_path_validator.py::TestSafeDecode -v
```

## Hints & Resources

### Required Python Libraries

```python
import urllib.parse    # For URL decoding
import unicodedata     # For Unicode normalization
import re              # For allowlist regex validation
from pathlib import Path  # For path resolution
```

### Key Implementation Hints

**Hint 1: Detecting Overlong UTF-8**
```python
# Standard: / = 0x2F (1 byte)
# Overlong: / = 0xC0 0xAF (2 bytes - INVALID!)

# Check: if bytes decode but have multiple representations
```

**Hint 2: URL Decoding**
```python
from urllib.parse import unquote

decoded = unquote(path)
# If decoding again changes it, double encoding detected!
double_check = unquote(decoded)
if decoded != double_check:
    raise SecurityError("Double encoding detected")
```

**Hint 3: Unicode Normalization**
```python
import unicodedata

# Use NFC (Canonical Composition)
normalized = unicodedata.normalize('NFC', path)
```

**Hint 4: Allowlist Validation**
```python
import re

# Only allow: alphanumeric, hyphen, underscore, forward slash
pattern = r'^[a-zA-Z0-9_\-/]+$'
if not re.match(pattern, path):
    return False
```

**Hint 5: Path Resolution**
```python
from pathlib import Path

base = Path(base_dir).resolve()
target = (base / path).resolve()

# Ensure target stays within base
if not target.is_relative_to(base):  # Python 3.9+
    raise SecurityError("Path escapes base directory")
```

## Test Coverage

The test suite includes:

**Correctness Tests** (Effective Python Item 10):
- ✅ Valid bytes/str conversion
- ✅ Invalid UTF-8 handling
- ✅ Type error handling
- ✅ Empty input handling
- ✅ Unicode filename support

**Security Tests** (AppSec):
- 🔒 Path traversal detection (`../`, `..\\`)
- 🔒 URL encoding bypasses (`..%2F`)
- 🔒 Double encoding attacks (`..%252F`)
- 🔒 Overlong UTF-8 encoding
- 🔒 Null byte injection (`\x00`)
- 🔒 Absolute path rejection (`/etc/passwd`, `C:\\Windows`)
- 🔒 Special character filtering (`;`, `|`, backticks)
- 🔒 Unicode normalization bypasses
- 🔒 Real CVE scenarios

## Success Criteria

Your implementation should:

✅ Pass all 30+ test cases  
✅ Handle both bytes and str inputs correctly  
✅ Detect all path traversal variants  
✅ Use allowlist validation (not blocklist)  
✅ Apply the Unicode sandwich pattern  
✅ Raise appropriate exceptions (`SecurityError`, `ValueError`, `TypeError`)  
✅ Be production-ready (no crashes on edge cases)

## Common Mistakes to Avoid

❌ **Don't use blocklists** - attackers will find bypasses  
❌ **Don't forget null bytes** - classic PHP vulnerability (CVE-2006-7243)  
❌ **Don't skip Unicode normalization** - combining chars bypass string matching  
❌ **Don't decode only once** - double encoding is real  
❌ **Don't trust `os.path.normpath()`** - it doesn't prevent all attacks  
❌ **Don't compare bytes and str** - silently fails!

## Sources & References

📚 **Books**:
- *Effective Python Third Edition* by Brett Slatkin
  - Item 10: bytes/str differences (pages 42-47)
  - Item 15: Stride/slice Unicode issues (pages 70-72)

- *API Security in Action* by Neil Madden
  - Chapter 2: Input validation (pages 47-50)

- *Hacking APIs* by Corey Ball
  - Chapter 13: Encoding bypasses (pages 271-274)

🔗 **Online Resources**:
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Unicode Security FAQ](https://unicode.org/faq/security.html)
- [CVE-2019-11510 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11510)

## Career Relevance

This exercise directly prepares you for:

🎯 **AppSec Engineering Interviews** at companies like:
- Trail of Bits
- NCC Group
- Anthropic
- Datadog
- Cisco Talos

🎯 **Common Interview Questions**:
- "How do you prevent path traversal attacks?"
- "Explain bytes vs str in Python security context"
- "What's the difference between allowlist and blocklist validation?"
- "How would you detect encoding-based bypasses?"

🎯 **Demonstrated Skills**:
- Secure coding practices
- Input validation
- Encoding attack awareness
- Python security best practices
- Test-driven security development

## Next Steps

After completing this exercise:

1. **Build similar validators** for:
   - SQL injection detection
   - XSS prevention in user input
   - Command injection prevention

2. **Read ahead** in your curriculum:
   - OWASP Top 10 (Week 2-4)
   - PortSwigger Path Traversal labs
   - Input validation in "Secure by Design"

3. **Add to your portfolio**:
   - Push to GitHub with good README
   - Write a blog post about your implementation
   - Share on LinkedIn to demonstrate AppSec skills

## Support

If you get stuck:

1. Re-read the blog post section on that specific attack
2. Review the test case for that scenario
3. Check the hints in this README
4. Review the source book pages cited

**Remember**: No reference implementation is provided intentionally - building from scratch is how you learn!

---

**Good luck!** This exercise will significantly strengthen your AppSec engineering skills. 🔒

*Part of the 18-week AppSec Engineering curriculum (Week 1)*
