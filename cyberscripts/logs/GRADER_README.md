# Log Parser Grader - Usage Instructions

## Overview

This automated grader tests your `log_parser.py` solution against 11 test log files and provides a comprehensive score breakdown.

**Total Points:** 100 (95 required + 15 bonus)

---

## Setup

### 1. Directory Structure

```
your-project/
├── log_parser.py          # Your solution
├── grader.py              # The grader script
└── sample_logs/           # Test log files
    ├── access.log
    ├── 01_normal_traffic_only.log
    ├── 02_sql_injection_heavy.log
    ├── 03_path_traversal_heavy.log
    ├── 04_mixed_attacks_multi_ip.log
    ├── 05_brute_force_multi_ip.log
    ├── 06_edge_cases.log
    ├── 07_successful_attacks.log
    ├── 08_distributed_attack.log
    ├── 09_url_encoded_attacks.log
    └── 10_mixed_http_methods.log
```

### 2. Run the Grader

```bash
python3 grader.py
```

That's it! The grader will:
- Check for required files
- Run your parser against each test file
- Validate JSON output structure
- Check detection accuracy
- Award points for each test
- Display final grade

---

## Grading Breakdown

### Required Tests (85 points)

| Test | Points | Description |
|------|--------|-------------|
| **Test 1: access.log** | 30 | Validates against blog post example |
| **Test 2: Normal Traffic** | 10 | Zero false positives required |
| **Test 3: SQL Injection** | 15 | Detects 8 SQLi attacks |
| **Test 4: Path Traversal** | 10 | Detects 7-8 path traversal attacks |
| **Test 5: Brute Force** | 10 | Detects 1 brute force pattern |
| **Test 6: Edge Cases** | 5 | No crashes, no false positives |
| **Test 7: User Agents** | 5 | Detects sqlmap, curl, python-requests |

### Bonus Test (15 points)

| Test | Points | Description |
|------|--------|-------------|
| **Bonus: No Crashes** | 15 | All 12 files parse without errors |

---

## Sample Output

```
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║          Apache/Nginx Log Parser - Automated Grader               ║
║                   Week 2 AppSec Exercise                           ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

======================================================================
                       Checking Required Files
======================================================================

✅ Found log_parser.py
✅ Found sample_logs/ directory
✅ Found 12 log files

======================================================================
                Test 1: access.log (Original Example)
======================================================================

✅   Correct total_requests: 11
✅   Correct unique_ips: 5
✅   Correct SQL_INJECTION detections: 2
✅   Correct PATH_TRAVERSAL detections: 2
✅   Correct BRUTE_FORCE detections: 0 (only 2 failed attempts)
✅ Test 1: access.log: 30/30 points

[... more tests ...]

======================================================================
                          FINAL GRADE REPORT
======================================================================

Test Results:
------------------------------------------------------------
Test 1: access.log................................ 30/30 (100.0%)
Test 2: Normal Traffic............................ 10/10 (100.0%)
Test 3: SQL Injection............................. 15/15 (100.0%)
Test 4: Path Traversal............................ 10/10 (100.0%)
Test 5: Brute Force............................... 10/10 (100.0%)
Test 6: Edge Cases................................  5/ 5 (100.0%)
Test 7: User Agents...............................  5/ 5 (100.0%)
Bonus: No Crashes................................. 15/15 (100.0%)
------------------------------------------------------------

TOTAL SCORE: 100/100 (100.0%)
LETTER GRADE: A+

🎉 EXCELLENT WORK!
Your parser is production-ready!
```

---

## Letter Grades

| Score | Grade |
|-------|-------|
| 90-100% | A+ |
| 80-89% | A |
| 70-79% | B |
| 60-69% | C |
| <60% | F |

---

## Common Issues & Fixes

### ❌ "log_parser.py not found"

**Fix:** Make sure `log_parser.py` is in the same directory as `grader.py`

### ❌ "sample_logs/ directory not found"

**Fix:** Create the `sample_logs/` directory and add all test log files

### ❌ "Parser failed: Invalid JSON output"

**Fix:** Your parser must output valid JSON. Test with:
```bash
python3 log_parser.py sample_logs/access.log | python3 -m json.tool
```

### ❌ "Parser timed out (>10 seconds)"

**Fix:** Optimize your parser - it should complete in under 10 seconds per file

### ❌ False positive on `/temporary`

**Fix:** Change SQL detection from `'or'` to `' or '` (with spaces) or use patterns like `' OR '`

### ❌ Missing brute force detection

**Fix:** 
1. Only count 401/403 status codes
2. Only paths containing "login"
3. Need 3+ failures per IP
4. Check AFTER processing all entries

---

## What the Grader Tests

### 1. JSON Structure Validation
- ✅ Has required top-level keys: `summary`, `top_ips`, `security_findings`, `suspicious_user_agents`
- ✅ Summary has correct fields and data types
- ✅ Arrays use correct structure (not dictionaries)

### 2. Summary Statistics
- ✅ `total_requests` - counts all log entries
- ✅ `unique_ips` - counts distinct IP addresses
- ✅ `failed_requests` - counts 4xx and 5xx status codes
- ✅ `total_bytes_transferred` - sums all bytes (handles `-` for missing)
- ✅ `most_common_status_codes` - tracks status code frequencies

### 3. Top IPs
- ✅ Format: `[{"ip": "...", "requests": N}, ...]`
- ✅ Sorted by request count (descending)
- ✅ Includes all unique IPs

### 4. SQL Injection Detection
- ✅ Detects: `OR`, `AND`, `UNION`, `SELECT`, `DROP`, `TABLE`, `--`
- ✅ Severity: `HIGH`
- ✅ No false positives on normal words (e.g., "temporary")

### 5. Path Traversal Detection
- ✅ Detects: `../` patterns
- ✅ Detects: `/etc/passwd`, `/windows/system32`
- ✅ Severity: `MEDIUM`

### 6. Brute Force Detection
- ✅ Groups by IP address
- ✅ Only counts 401/403 to paths containing "login"
- ✅ Threshold: 3+ failed attempts
- ✅ Severity: `LOW`
- ✅ Includes `failed_request_count` field

### 7. User Agent Detection
- ✅ Flags: `sqlmap`, `curl`, `wget`, `python-requests`, `nikto`, `nmap`
- ✅ Format: `[{"user_agent": "...", "count": N}, ...]`
- ✅ Counts occurrences correctly

### 8. Edge Case Handling
- ✅ Handles missing bytes field (`-`)
- ✅ Handles large files (1GB+)
- ✅ Handles various HTTP methods (GET, POST, PUT, DELETE, PATCH, etc.)
- ✅ Handles all status codes (2xx, 3xx, 4xx, 5xx)
- ✅ No crashes on unusual data

---

## Tips for Perfect Score

1. **Test incrementally** - Run grader after each feature implementation
2. **Read error messages** - The grader provides specific feedback
3. **Validate JSON** - Use `python3 -m json.tool` to check output
4. **Handle edge cases** - Use try/except for bytes conversion
5. **Use spaces in SQL patterns** - Prevents false positives
6. **Check brute force logic** - Only login endpoints, only 401/403
7. **Test manually first** - Run your parser on access.log before grading

---

## Example: Debugging Failed Test

If you see:
```
❌   Wrong SQL_INJECTION count: 1 (expected 2)
```

**Debug steps:**
1. Run your parser manually:
   ```bash
   python3 log_parser.py sample_logs/access.log | python3 -m json.tool
   ```

2. Look at the `security_findings` array

3. Count SQL_INJECTION entries

4. Check the log file for expected attacks:
   ```bash
   grep "OR\|UNION\|SELECT" sample_logs/access.log
   ```

5. Fix your detection logic

6. Re-run grader

---

## Support

If you encounter issues:

1. **Check the blog post** - Detailed requirements and examples
2. **Review test files** - See what attacks look like
3. **Test manually** - Run parser on individual files
4. **Check JSON format** - Validate with json.tool
5. **Read error messages** - Grader provides specific feedback

---

## License

This grader is part of the Week 2 AppSec Exercise curriculum.

**Good luck! 🚀**
