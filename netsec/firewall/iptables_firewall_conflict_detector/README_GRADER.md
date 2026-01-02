# VPN Log Analyzer Grader

Comprehensive grading system for the VPN Log Analyzer challenge that detects brute force attacks, session hijacking, and credential stuffing in VPN authentication logs.

## Overview

This grader validates student submissions against 100 test cases covering:
- **Files 001-020**: Normal activity baselines
- **Files 021-040**: Brute force attacks (≥5 failed attempts)
- **Files 041-060**: Session hijacking (≥3 different IPs)
- **Files 061-080**: Credential stuffing (≥5 users from same IP)
- **Files 081-095**: Mixed attack scenarios
- **Files 096-100**: Edge cases (malformed data, empty files, large logs)

## Inspiration & Citations

This grader implements testing patterns from:

**"Python Workout, 2nd Edition" by Reuven M. Lerner (Manning, 2024)**
- Chapter 5: Dictionaries and Sets (Exercise 15: "Restaurant", Pages 143-147)
- Testing with multiple test cases and comprehensive validation

**"Effective Python, 3rd Edition" by Brett Slatkin (Addison-Wesley, 2024)**
- Item 76: "Use unittest to Test Everything" (Pages 301-308)
- Item 52: "Use subprocess to Manage Child Processes" (Pages 195-201)
- Item 70: "Use json for Data Interchange" (Pages 270-274)

**"Secure by Design" by Dan Bergh Johnsson et al. (Manning, 2019)**
- Chapter 8: Secure-by-default design (Pages 179-195)
- Input validation and sanitization principles

## Files

1. **vpn_log_analyzer_grader.py** - Main grading script
2. **generate_expected_results.py** - Creates expected results from reference implementation
3. **README.md** - This documentation file

## Quick Start

### Step 1: Generate Expected Results

First, run your reference implementation against all test files to generate the baseline:

```bash
python3 generate_expected_results.py \
	vpn_log_analyzer.py \
	test_logs/ \
	expected_results.json
```

This creates `expected_results.json` containing the correct output for each test file.

### Step 2: Grade a Submission

Run the grader against a student submission:

```bash
python3 vpn_log_analyzer_grader.py \
	student_solution.py \
	test_logs/ \
	expected_results.json
```

### Step 3: Review Results

The grader provides:
- ✓/✗ status for each test file
- Category-wise breakdown (normal, brute force, session hijacking, etc.)
- Overall pass rate and score
- Performance statistics (average/max runtime)
- Detailed JSON report (`grading_report.json`)

## Output Format Requirements

Student solutions MUST output a Python dictionary with this exact structure:

```python
{
	'brute_force': ['admin', 'user1'],           # List of usernames
	'session_hijacking': ['alice', 'bob'],       # List of usernames
	'credential_stuffing': ['192.168.1.1']       # List of IP addresses
}
```

### Detection Rules

1. **Brute Force**: Username with ≥5 failed login attempts
2. **Session Hijacking**: Username with successful logins from ≥3 different IPs
3. **Credential Stuffing**: IP address attempting ≥5 different usernames

## Example Usage

### Complete Grading Workflow

```bash
# 1. Extract test files
cd netsec/vpn/vpn_log_analyzer/
tar -xzf vpn_test_logs.tar.gz

# 2. Generate expected results from your reference implementation
python3 generate_expected_results.py \
	vpn_log_analyzer.py \
	test_logs/ \
	expected_results.json

# 3. Grade a student submission
python3 vpn_log_analyzer_grader.py \
	student_vpn_analyzer.py \
	test_logs/ \
	expected_results.json

# 4. Review detailed report
cat grading_report.json
```

### Output Example

```
VPN Log Analyzer Grader
========================

✓ Loaded expected results from expected_results.json
✓ Loaded student solution: student_solution.py

Running Test Suite
======================================================================
Found 100 test files

✓ vpn_auth_001.log (12.3ms)
✓ vpn_auth_002.log (10.8ms)
✗ vpn_auth_025.log - Mismatches:
    brute_force: Missing {'admin'}
...

Test Summary
======================================================================

Results by Category:
  normal              : 20/20 (100.0%)
  brute_force         : 18/20 ( 90.0%)
  session_hijack      : 20/20 (100.0%)
  cred_stuffing       : 19/20 ( 95.0%)
  mixed               : 14/15 ( 93.3%)
  edge_cases          :  5/ 5 (100.0%)

Overall Score:
  EXCELLENT: 96/100 (96.0%)

Performance:
  Average: 15.2ms
  Slowest: 89.7ms

✓ Detailed report saved to grading_report.json
```

## Validation Features

The grader validates:

### 1. Output Structure
- Dictionary with exactly 3 keys
- Each key maps to a list
- All list elements are strings
- No extra or missing keys

### 2. Detection Logic
- Brute force threshold (≥5 failed attempts)
- Session hijacking threshold (≥3 different IPs)
- Credential stuffing threshold (≥5 different users)

### 3. Edge Cases
- Malformed log entries (should skip, not crash)
- Empty files (should return empty lists)
- Large files (>1000 entries, <100ms expected)
- Mixed attack types (detect all simultaneously)

### 4. Performance
- Timeout at 10 seconds per file
- Warning if any test exceeds 100ms
- Reports average and maximum runtimes

## Error Handling

The grader catches and reports:

- **Syntax Errors**: Line number and description
- **Import Errors**: Missing modules or invalid imports
- **Runtime Errors**: Exceptions during execution
- **Timeout Errors**: Execution exceeding 10 seconds
- **Format Errors**: Invalid output structure
- **Logic Errors**: Incorrect detections (compared against expected)

## Grading Report

The JSON report contains:

```json
{
	"summary": {
		"total_tests": 100,
		"passed": 96,
		"failed": 4,
		"pass_rate": 96.0
	},
	"tests": [
		{
			"filename": "vpn_auth_001.log",
			"passed": true,
			"expected": {...},
			"actual": {...},
			"error": null,
			"runtime_ms": 12.3
		},
		...
	]
}
```

## Grading Criteria

### Score Interpretation

- **100%**: Perfect score - production ready
- **90-99%**: Excellent - minor edge case issues
- **70-89%**: Good - core logic solid, needs refinement
- **Below 70%**: Needs significant work

### Common Failure Patterns

1. **Incorrect Thresholds**
   - Using ≥3 instead of ≥5 for brute force
   - Using ≥2 instead of ≥3 for session hijacking

2. **Logic Errors**
   - Counting all attempts instead of only failed ones (brute force)
   - Not filtering by success status (session hijacking)
   - Including successful attempts in credential stuffing

3. **Edge Case Handling**
   - Crashing on malformed entries instead of skipping
   - Not handling empty files
   - Timeout on large files (inefficient algorithm)

4. **Output Format**
   - Missing required keys
   - Wrong data types (e.g., returning sets instead of lists)
   - Including extra keys in output

## Advanced Usage

### Testing Without Expected Results

You can run format validation without expected results:

```bash
python3 vpn_log_analyzer_grader.py \
	student_solution.py \
	test_logs/
```

This validates:
- Output structure correctness
- No crashes or timeouts
- Basic format compliance

But does NOT validate:
- Correctness of detections
- Logic implementation
- Threshold accuracy

### Custom Test Subsets

Grade only specific file ranges:

```bash
# Test only brute force files (021-040)
mkdir test_subset
cp test_logs/vpn_auth_0{21..40}.log test_subset/
python3 vpn_log_analyzer_grader.py student_solution.py test_subset/
```

### Performance Profiling

To identify slow operations:

```bash
# Run with Python profiler
python3 -m cProfile -s cumtime vpn_log_analyzer_grader.py \
	student_solution.py test_logs/ expected_results.json
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Grade VPN Analyzer

on: [push, pull_request]

jobs:
  grade:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - name: Extract test files
        run: tar -xzf vpn_test_logs.tar.gz
      - name: Run grader
        run: |
          python3 vpn_log_analyzer_grader.py \
            vpn_log_analyzer.py \
            test_logs/ \
            expected_results.json
      - name: Upload report
        uses: actions/upload-artifact@v2
        with:
          name: grading-report
          path: grading_report.json
```

## Troubleshooting

### Issue: "Could not load module spec"
**Solution**: Ensure student solution is valid Python file with `.py` extension

### Issue: "No test files found"
**Solution**: Extract test files with `tar -xzf vpn_test_logs.tar.gz`

### Issue: "Missing required keys"
**Solution**: Student solution must output dict with all 3 required keys

### Issue: "Execution timeout"
**Solution**: Student algorithm may be O(n²) instead of O(n) - optimize

### Issue: All tests show "?" instead of "✓" or "✗"
**Solution**: Generate expected_results.json first using generate_expected_results.py

## References

### Books
1. **"Python Workout, 2nd Edition"** - Reuven M. Lerner (Manning, 2024)
2. **"Effective Python, 3rd Edition"** - Brett Slatkin (Addison-Wesley, 2024)
3. **"API Security in Action"** - Neil Madden (Manning, 2020)
4. **"Hacking APIs"** - Corey J. Ball (No Starch Press, 2022)
5. **"Secure by Design"** - Dan Bergh Johnsson et al. (Manning, 2019)

### Standards
- OWASP API Security Top 10 2023 (API4:2023 - Unrestricted Resource Consumption)
- NIST SP 800-63B: Digital Identity Guidelines
- MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts)

## License

MIT License - Use freely for educational purposes

## Author

Tanveer Salim - AppSec Engineering Curriculum Week 3
- GitHub: [@fosres](https://github.com/fosres)
- LinkedIn: [tanveer-salim](https://linkedin.com/in/tanveer-salim)
- Blog: [dev.to/fosres](https://dev.to/fosres)

## Acknowledgments

- Grace Nolan ([gracenolan/Notes](https://github.com/gracenolan/Notes)) - Google Security Engineer interview prep
- Intel IPAS Team - Real-world threat modeling experience
- OWASP LA Community - Security best practices
- Null Space Labs - Weekly security discussions
