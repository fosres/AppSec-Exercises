---
title: "Week 3 Security Challenge: VPN Authentication Log Analyzer 🔐"
published: false
description: "Build a VPN log analyzer to detect brute force, session hijacking, and credential stuffing attacks - Grace Nolan interview prep"
tags: appsec, python, cybersecurity, security
cover_image: https://dev.to/social_previews/article/XXXXX.png
series: 48-Week AppSec Engineering Journey
---

# VPN Authentication Log Analyzer: Detecting Real-World Attacks

Welcome to **Week 3** of my 48-week journey from Intel Security Engineer to Application Security Engineer! This week, I'm tackling a critical security engineering problem: **analyzing VPN authentication logs to detect credential-based attacks**.

This challenge is inspired by **Grace Nolan's Google Security Engineering interview questions** and covers a skill that appears in every AppSec role: **log parsing and threat detection**.

---

## 🎯 The Problem

You're the security engineer responsible for monitoring a VPN gateway that handles 10,000+ daily authentication attempts. Your task is to build an automated log analyzer that detects three types of attacks:

### Attack Types

**1. Brute Force Attack** 🔨
- **Pattern:** Multiple failed login attempts for a single username
- **Risk:** Attacker systematically guessing passwords
- **Real Example:** 2019 Citrix VPN breach (CVE-2019-19781)

**2. Session Hijacking** 🎭  
- **Pattern:** Successful logins from many different locations
- **Risk:** Stolen credentials being used from multiple IPs
- **Real Example:** SolarWinds compromise (credential theft + lateral movement)

**3. Credential Stuffing** 💉
- **Pattern:** Failed logins for many different usernames from same IP
- **Risk:** Attacker using leaked credential databases
- **Real Example:** 2020 Zoom credential stuffing attacks

---

## 📋 Challenge Specifications

### Input: VPN Log File

Your script will process **actual VPN log files**. Each log entry follows this format:

```
YYYY-MM-DD HH:MM:SS | user:USERNAME | IP:IP_ADDRESS | status:STATUS
```

**Example Log File (`vpn_auth_025.log`):**
```
2026-01-02 14:00:00 | user:grace | IP:192.168.5.214 | status:success
2026-01-02 14:02:45 | user:diana | IP:192.168.6.156 | status:success
...
2026-01-02 14:14:20 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:16:18 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:18:00 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:19:12 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:20:52 | user:admin | IP:10.0.0.5 | status:failed
...
(14 total failed attempts for admin)
```

### Command-Line Interface

```bash
python3 vpn_analyzer.py vpn_auth_025.log
```

### Expected Output

Your script should print a simple dictionary:

```python
{'brute_force': ['admin'], 'session_hijacking': ['grace', 'eve'], 'credential_stuffing': []}
```

**That's it!** Clean and focused on the detection results.

---

## 📏 Detection Rules

### Rule 1: Brute Force Detection

**Question:** Is someone trying to guess passwords for a specific account?

**How to Detect:**
- Count the number of **failed login attempts** for each username
- If any username has **5 or more failed attempts**, flag it as a brute force target
- Output: List of **usernames** being attacked

**Real Example from Test File 025:**
```
Input: 14 failed attempts for 'admin' from IP 10.0.0.5
Output: 'brute_force': ['admin']
```

**Key Concepts:**
- Track failures per username (frequency counting)
- Only count entries where status is "failed"
- Threshold: ≥5 failures

---

### Rule 2: Session Hijacking Detection

**Question:** Is someone using stolen credentials from multiple locations?

**How to Detect:**
- Track how many **different IP addresses** each username logs in from (successful logins only)
- If any username has successful logins from **3 or more different IPs**, flag it as hijacked
- Output: List of **usernames** that are compromised

**Real Example from Test File 025:**
```
grace logged in from IPs: 192.168.5.214, 192.168.7.87, 192.168.3.120, 192.168.10.232, 192.168.4.85
(5 different IPs → DETECTED)

eve logged in from IPs: 192.168.1.165, 192.168.6.83, 192.168.6.134
(3 different IPs → DETECTED)

Output: 'session_hijacking': ['grace', 'eve']
```

**Key Concepts:**
- Track unique IPs per username
- Only count entries where status is "success"
- Ignore duplicate IPs (same IP appearing multiple times = 1 unique IP)
- Threshold: ≥3 different IPs

---

### Rule 3: Credential Stuffing Detection

**Question:** Is an attacker trying a leaked password database?

**How to Detect:**
- Track how many **different usernames** each IP address tries to log in as (failed attempts only)
- If any IP has failed login attempts for **5 or more different usernames**, flag it as stuffing
- Output: List of **IP addresses** performing the attack

**Real Example from Test File 065:**
```
Input logs show IP 10.0.0.5 trying:
2026-01-02 16:12:40 | user:bob | IP:10.0.0.5 | status:failed
2026-01-02 16:13:39 | user:user | IP:10.0.0.5 | status:failed
2026-01-02 16:13:55 | user:sarah | IP:10.0.0.5 | status:failed
2026-01-02 16:14:12 | user:mike | IP:10.0.0.5 | status:failed
2026-01-02 16:14:29 | user:root | IP:10.0.0.5 | status:failed

(5 different usernames → DETECTED)

Output: 'credential_stuffing': ['10.0.0.5']
```

**Key Concepts:**
- Track unique usernames per IP
- Only count entries where status is "failed"
- Ignore duplicate usernames (same user appearing multiple times = 1 unique user)
- Threshold: ≥5 different usernames

---

## 💡 Implementation Approach

### What You'll Need

**Data Structures:**
1. Something to count failures per username (brute force)
2. Something to track unique IPs per username (session hijacking)
3. Something to track unique usernames per IP (credential stuffing)

**Processing Steps:**
1. Read the log file line by line
2. Parse each line to extract: username, IP, status
3. Update your tracking structures based on status
4. After processing all lines, check thresholds
5. Print the results dictionary

### Parsing Hint

Each line looks like:
```
2026-01-02 14:23:15 | user:alice | IP:192.168.1.10 | status:success
```

You need to extract:
- Username: "alice"
- IP: "192.168.1.10"  
- Status: "success"

**Approach:** Split by delimiters (`|` and `:`) and extract the parts you need.

---

## 🧪 Test Data: 100 VPN Log Files

I've generated **100 realistic VPN log files** covering every test scenario:

### Test File Categories

**Normal Activity (Files 001-020):**
- Example output: `{'brute_force': [], 'session_hijacking': ['diana', 'bob', 'henry'], 'credential_stuffing': []}`
- Some users legitimately log in from multiple locations

**Brute Force Attacks (Files 021-040):**
- Example (File 025): `{'brute_force': ['admin'], 'session_hijacking': ['grace', 'eve'], 'credential_stuffing': []}`
- 5-15 failed attempts per targeted user

**Session Hijacking (Files 041-060):**
- Example (File 045): `{'brute_force': [], 'session_hijacking': ['alice', 'charlie', 'frank', 'henry', 'diana'], 'credential_stuffing': []}`
- Users logging in from 3-7 different IPs

**Credential Stuffing (Files 061-080):**
- Example (File 065): `{'brute_force': [], 'session_hijacking': ['eve'], 'credential_stuffing': ['10.0.0.5']}`
- Single IP trying 5-20 different usernames

**Mixed Attacks (Files 081-095):**
- Example (File 085): `{'brute_force': ['admin'], 'session_hijacking': ['frank', 'alice', 'henry'], 'credential_stuffing': ['203.0.113.42']}`
- Multiple attack types in same log

**Edge Cases (Files 096-100):**
- Empty log files
- Exactly 5 failures (threshold boundary)
- Exactly 3 IPs (threshold boundary)
- Very large files (1,000+ entries)
- Malformed entries (test error handling)

### Testing Your Solution

```bash
# Extract test logs
tar -xzf vpn_test_logs.tar.gz
cd test_logs/

# Test on a single file
python3 vpn_analyzer.py vpn_auth_025.log

# Test on all files
for log in vpn_auth_*.log; do
    echo "Testing $log..."
    python3 vpn_analyzer.py "$log"
done
```

---

## ✅ Success Criteria

Your solution should:

**Functional Requirements:**
- ✅ Parse 100/100 test log files correctly
- ✅ Detect all brute force attacks (≥5 failures per user)
- ✅ Detect all session hijacking (≥3 IPs per user)
- ✅ Detect all credential stuffing (≥5 users per IP)
- ✅ Handle edge cases (empty files, malformed entries)
- ✅ Output simple dictionary format

**Code Quality:**
- ✅ Use appropriate data structures for counting and tracking
- ✅ Handle uniqueness correctly (don't count duplicates)
- ✅ Descriptive variable names
- ✅ Handle file I/O errors gracefully

**Performance:**
- ✅ Process 1,000-entry log file in <1 second

---

## 📚 Security Context: Why This Matters

### OWASP API Security Top 10 - API4:2023

This exercise maps directly to **API4:2023 Unrestricted Resource Consumption**:

> "APIs vulnerable to this issue expose functionalities that, when called multiple times, can result in resource exhaustion or make it impossible for legitimate users to access the application."

**Real-World Application:**
- **GitHub API:** Rate limits authentication attempts (5,000/hour per IP)
- **AWS IAM:** Locks accounts after 5 failed login attempts
- **Cloudflare:** Blocks IPs exhibiting credential stuffing patterns

### Interview Question (Grace Nolan Style)

**Q:** *"How would you detect brute force attacks in authentication logs?"*

**Expected Answer Pattern:**
1. Parse logs into structured data
2. Use frequency counting to track failed attempts per user
3. Apply threshold-based detection (≥5 failures = suspicious)
4. Consider time windows (bonus: within 5 minutes)
5. Alert on patterns that exceed thresholds

### Book Citations

**"Hacking APIs" by Corey J. Ball (No Starch Press, 2022)**
- **Chapter 3: "Authentication Attacks"** (Pages 67-72)
  - Credential stuffing detection patterns
  - Rate limiting best practices

**"API Security in Action" by Neil Madden (Manning, 2020)**
- **Section 4.1.3: "Rate-limiting authentication attempts"** (Pages 124-127)
  - Failed login thresholds (recommends ≥5 as brute force indicator)

---

## 💡 Hints & Tips

### Python Concepts You'll Need (Week 3 Skills)

**1. Dictionaries for Frequency Counting**
- Pattern: Track how many times something appears
- From Python Workout Ch 5, Exercise 14

**2. Sets for Uniqueness**
- Pattern: Track unique items (automatically ignores duplicates)
- From Python Workout Ch 5, Exercise 17
- Perfect for "how many different IPs" or "how many different users"

**3. File I/O Basics**
- Read file line by line
- Strip whitespace from each line
- Handle files that don't exist or are empty

**4. String Parsing**
- Split strings by delimiters (` | ` and `:`)
- Extract specific parts of formatted text

### Common Pitfalls to Avoid

**1. Counting Duplicates**
- ❌ Wrong: Count "alice from 1.1.1.1" three times = 3 IPs
- ✅ Right: Count "alice from 1.1.1.1" three times = 1 unique IP

**2. Off-by-One Errors**
- ❌ Wrong: Threshold "greater than 5" (detects 6+)
- ✅ Right: Threshold "greater than or equal to 5" (detects 5+)

**3. Tracking Wrong Status**
- ❌ Wrong: Count successful logins for brute force
- ✅ Right: Only count failed logins for brute force

**4. Output Wrong Data Type**
- ❌ Wrong: `'brute_force': ['192.168.1.10']` (IP address)
- ✅ Right: `'brute_force': ['admin']` (username)

---

## 🎓 My Results

### Implementation Journey

**Time Spent:** 3-4 hours total
- Understanding requirements: 30 min
- Initial implementation: 2 hours
- Debugging and testing: 1 hour
- Documentation: 30 min

**Test Results:** **100/100 Files Passed** ✅

### Real Test Outputs

**File 001 (Normal Activity):**
```python
{'brute_force': [], 'session_hijacking': ['diana', 'bob', 'henry'], 'credential_stuffing': []}
```
✓ Correctly identified legitimate users with multiple login locations

**File 025 (Brute Force):**
```python
{'brute_force': ['admin'], 'session_hijacking': ['grace', 'eve'], 'credential_stuffing': []}
```
✓ Detected 14 failed login attempts for 'admin'

**File 045 (Session Hijacking):**
```python
{'brute_force': [], 'session_hijacking': ['alice', 'charlie', 'frank', 'henry', 'diana'], 'credential_stuffing': []}
```
✓ Five users logging in from 3+ different locations

**File 065 (Credential Stuffing):**
```python
{'brute_force': [], 'session_hijacking': ['eve'], 'credential_stuffing': ['10.0.0.5']}
```
✓ IP 10.0.0.5 attempted 5 different usernames

**File 085 (Mixed Attacks):**
```python
{'brute_force': ['admin'], 'session_hijacking': ['frank', 'alice', 'henry'], 'credential_stuffing': ['203.0.113.42']}
```
✓ All three attack types detected simultaneously

**File 099 (Large File - 1000+ entries):**
```python
{'brute_force': ['grace', 'charlie', 'alice', 'henry', 'eve', 'frank', 'bob', 'diana', 'attacked_user'],
 'session_hijacking': ['eve', 'bob', 'alice', 'diana', 'henry', 'grace', 'frank', 'charlie', 'mobile_user'],
 'credential_stuffing': ['192.168.4.85', '192.168.3.120', ... (16 IPs total)]}
```
✓ Processed in <0.1 seconds

### Key Challenges

**Challenge 1: String Parsing**
- Had to correctly extract values from `"user:alice"` format
- Solution: `.split(":")[1].strip()`

**Challenge 2: Tracking Uniqueness**
- Sets automatically handle duplicates
- No need to check "if IP not in set" before adding

**Challenge 3: Malformed Entries**
- Initially crashed on bad lines
- Solution: `continue` instead of `exit(1)` to skip and keep processing

---

## 📊 Performance Metrics

| Metric | Target | Achieved |
|--------|--------|----------|
| Parse Speed | <1s for 1K entries | <0.1s ✓ |
| Detection Accuracy | 100% | 100% ✓ |
| False Positives | 0 | 0 ✓ |
| Test Coverage | 100 files | 100/100 ✓ |

---

## 🔗 Resources

**GitHub Repository:**  
[github.com/fosres/AppSec-Exercises/Week3/Exercise1](https://github.com/fosres)

**Test Log Files (100 files):**  
[Download vpn_test_logs.tar.gz]

**Curriculum:**  
[Complete 48-Week Security Engineering Curriculum]

---

## 💬 What I Learned

### Python Skills (Week 3 Focus)

**Dictionaries:**
- Safe counting with `.get()` method
- Building dictionaries incrementally
- Iterating with `.items()`

**Sets:**
- Automatic uniqueness handling
- No duplicate checking needed
- Counting unique items with `len()`

**File Processing:**
- Reading files line by line efficiently
- Handling malformed data gracefully (skip, don't crash)
- Command-line argument handling

### Security Concepts

**Attack Pattern Recognition:**
- Brute force: High failure rate, single target
- Session hijacking: Successful logins, multiple locations
- Credential stuffing: Multiple targets, single source

**Threshold-Based Detection:**
- Why ≥5 failures? Balance between false positives and detection
- Too low (≥2): Many false alarms from legitimate typos
- Too high (≥10): Miss slow-and-low attacks

**Production Resilience:**
- Real logs contain corrupt entries
- Security tools must be fault-tolerant
- Skip bad data, process what you can

---

## 🚀 Next Steps in My Journey

**Week 3 Progress:**
- ✅ Exercise 1: VPN Log Analyzer (COMPLETE)
- 🔄 Exercise 2: Firewall Rule Conflict Detector
- 📅 Exercise 3: Network Segmentation Validator
- 📅 Exercise 4: IOC Correlator
- 📅 Exercise 5: Cipher Suite Auditor

**My AppSec Journey Timeline:**
- ✅ Week 1: Networking fundamentals (port scanner, Wireshark)
- ✅ Week 2: DNS/TLS deep dive (SQL injection basics)
- ✅ **Week 3: VPN/Firewall security (THIS POST)**
- 🔜 Week 4: Linux security hardening
- 🎯 Week 24: Begin job applications (GitLab, Trail of Bits, Stripe)
- 🎯 June 2026: Target start date

---

## 🙏 Acknowledgments

**Inspired by:**
- **Grace Nolan's Google Security Engineering Notes** (GitHub: gracenolan/Notes)
- **Python Workout, Second Edition** by Reuven M. Lerner (Chapter 5: Dictionaries & Sets)
- **"Hacking APIs"** by Corey J. Ball (No Starch Press)
- **"API Security in Action"** by Neil Madden (Manning)

**Special Thanks:**
- Intel IPAS Team (for real-world security engineering experience with 553+ threat models)
- OWASP LA Community (for weekly security discussions)
- Null Space Labs (for Tuesday hacking nights)

---

**Tags:** #appsec #python #cybersecurity #security #devops #100daysofcode #gracenolan #securityengineering

**Series:** 48-Week AppSec Engineering Journey

---

*Like this post? Follow for Week 4: Linux Security Hardening & Log Analysis! 🚀*

*Questions? Drop them in the comments below! 👇*

*Want the test files? Leave a comment and I'll share the link!*
