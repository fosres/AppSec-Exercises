# TLS Certificate Validator - Automated Grader

## 📋 Overview

This grader script automatically tests your `tls_cert_validator.py` implementation against a comprehensive test suite of 68+ test certificates.

**Features:**
- ✅ Runs all test cases automatically  
- ✅ Compares your output against expected results
- ✅ Provides detailed scoring (0-100 per test)
- ✅ Identifies problem areas (checks with high failure rates)
- ✅ Color-coded terminal output
- ✅ Optional JSON report export
- ✅ Verbose mode for detailed debugging

---

## 🚀 Quick Start

### 1. Extract Test Data

```bash
unzip test_data.zip
```

This creates a `test_certs_text/` directory with 68 test certificate files.

### 2. Ensure TLD File Exists

Your validator requires `tlds-alpha-by-domain.txt` in the same directory. This file is included with the grader.

```bash
ls tlds-alpha-by-domain.txt  # Should exist
```

### 3. Run the Grader

```bash
python3 grader.py tls_cert_validator.py test_certs_text/
```

---

## 📝 Command Line Options

### Basic Usage

```bash
python3 grader.py <validator_script> <test_directory>
```

### With Options

```bash
# Verbose mode - shows full validator output for each test
python3 grader.py tls_cert_validator.py test_certs_text/ --verbose

# Save JSON report
python3 grader.py tls_cert_validator.py test_certs_text/ --json

# Both
python3 grader.py tls_cert_validator.py test_certs_text/ -v --json
```

---

## 📊 Understanding Output

### Sample Output

Your grader will show:
1. **Progress** for each test (✓ pass / ✗ fail)
2. **Summary statistics** (total, passed, failed, average score)
3. **Per-check statistics** (how each CHECK performed)
4. **Problem areas** (checks with >20% failure rate)
5. **Score distribution** (how tests scored 0-59, 60-69, etc.)
6. **Final grade** (A-F based on average score)

See full documentation in GRADER_README.md for detailed examples.

---

## 🎯 Grading Criteria

Each test scored 0-100:
- **70 points**: Catching expected failures
- **20 points**: No false positives
- **10 points**: No false negatives

Final grade based on average score:
- **90-100 (A)**: Excellent
- **80-89 (B)**: Good
- **70-79 (C)**: Acceptable
- **60-69 (D)**: Needs work
- **0-59 (F)**: Major issues

---

## 🐛 Debugging

### View Detailed Output

```bash
python3 grader.py tls_cert_validator.py test_certs_text/ --verbose
```

This shows full output for each test to help debug failures.

### Test Individual Certificate

```bash
python3 tls_cert_validator.py www.example.com test_certs_text/test_001_perfect_cert.txt
```

---

## 📚 Test Coverage

68 test cases covering:
- ✅ All 20 validation checks
- ✅ Edge cases (wildcards, empty subjects, self-signed, etc.)
- ✅ Production certificates (Let's Encrypt, Cloudflare, etc.)
- ✅ Invalid certificates (expired, wrong algorithms, etc.)

---

## 🏆 Achieving High Scores

Common issues:
1. **CHECK 14 failure (100%)**: Not counting SCTs correctly
2. **CHECK 7 high failure**: Wildcard matching bugs
3. **CHECK 5 failures**: Not handling empty Subject correctly

Fix these for big score improvements!

---

## 📞 Files Included

- `grader.py` - Main grader script
- `tlds-alpha-by-domain.txt` - TLD list (required by validator)
- `test_data.zip` - 68 test certificates
- `GRADER_README.md` - This file (full documentation)

---

**Good luck!** 🚀

*For complete documentation, see GRADER_README.md*
