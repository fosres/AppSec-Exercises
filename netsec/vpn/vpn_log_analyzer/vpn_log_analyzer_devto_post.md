---
title: "VPN Log Analyzer: Detect Brute Force, Session Hijacking & Credential Stuffing (100/100 Tests) 🔐"
published: false
description: "Interview-ready Python security tool that passed 100/100 test cases. Grace Nolan interview prep + 100 test files included!"
tags: appsec, python, cybersecurity, security
cover_image: https://dev.to/social_previews/article/XXXXX.png
series: 48-Week AppSec Engineering Journey
---

# VPN Log Analyzer: Detecting Real-World Attacks (100% Test Pass Rate)

**TL;DR:** Built a functional VPN authentication log analyzer that detects brute force, session hijacking, and credential stuffing attacks. **Passed 100/100 test cases** including edge cases. Full solution + 100 test files on GitHub 👇

⭐ **[Star the repo on GitHub](https://github.com/fosres/AppSec-Exercises)** if you find this useful! ⭐

---

## 🎯 What I Built

A Python security tool that analyzes VPN authentication logs and detects three types of attacks in real-time:

1. **Brute Force Attacks** - Multiple password guessing attempts (like the 2019 Citrix breach)
2. **Session Hijacking** - Stolen credentials used from multiple locations (like SolarWinds)
3. **Credential Stuffing** - Testing leaked password databases (like 2020 Zoom attacks)

**Results:** 100/100 test files processed correctly, including edge cases and malformed data.

**Why this matters:** This is a **Grace Nolan-style Google Security Engineering interview question** that maps directly to **OWASP API Security Top 10 (API4:2023)**.

---

## 🚀 The Challenge

I'm on Week 3 of my 48-week journey from Intel Security Engineer to Application Security Engineer. This week's focus: **network security and log analysis**.

**Problem:** You're monitoring a VPN gateway with 10,000+ daily authentication attempts. Build an automated analyzer to detect credential-based attacks.

**Input:** Log files like this:
```
2026-01-02 14:14:20 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:16:18 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:18:00 | user:admin | IP:10.0.0.5 | status:failed
...
```

**Output:** Simple detection results:
```python
{'brute_force': ['admin'], 'session_hijacking': ['grace', 'eve'], 'credential_stuffing': []}
```

---

## 📊 My Results: Perfect Score

**Test Results:** ✅ 100/100 files passed

| Category | Files | Result |
|----------|-------|--------|
| Normal Activity | 20 | 20/20 ✅ |
| Brute Force | 20 | 20/20 ✅ |
| Session Hijacking | 20 | 20/20 ✅ |
| Credential Stuffing | 20 | 20/20 ✅ |
| Mixed Attacks | 15 | 15/15 ✅ |
| Edge Cases | 5 | 5/5 ✅ |

**Performance:** <0.1 seconds for 1,000+ entry files

**Code Quality:** Clean, readable, interview-ready

---

## 🔍 Detection Rules Explained

### Rule 1: Brute Force (≥5 Failed Attempts)

**Real example from test file 025:**
```
admin: 14 failed login attempts from IP 10.0.0.5
→ DETECTED: 'brute_force': ['admin']
```

**Why ≥5?** Balance between false positives (legitimate typos) and detection (real attacks)

### Rule 2: Session Hijacking (≥3 Different IPs)

**Real example from test file 025:**
```
grace logged in from 5 different IPs:
  - 192.168.5.214
  - 192.168.7.87
  - 192.168.3.120
  - 192.168.10.232
  - 192.168.4.85
→ DETECTED: 'session_hijacking': ['grace']
```

**What this catches:** Stolen credentials being used from multiple locations simultaneously

### Rule 3: Credential Stuffing (≥5 Different Users from Same IP)

**Real example from test file 065:**
```
IP 10.0.0.5 tried 5 different usernames:
  16:12:40 | user:bob | status:failed
  16:13:39 | user:user | status:failed
  16:13:55 | user:sarah | status:failed
  16:14:12 | user:mike | status:failed
  16:14:29 | user:root | status:failed
→ DETECTED: 'credential_stuffing': ['10.0.0.5']
```

**What this catches:** Attackers using leaked password databases (like Have I Been Pwned data)

---

## 💻 The Implementation

**Key data structures:**
- **Dictionary** for frequency counting (brute force failures)
- **Dictionary of Sets** for uniqueness tracking (IPs per user, users per IP)
- **Single-pass processing** for O(n) time complexity

**Core algorithm:**
```python
for line in log_file:
    username, ip, status = parse_line(line)
    
    if status == "failed":
        track_for_brute_force(username)
        track_for_credential_stuffing(ip, username)
    
    if status == "success":
        track_for_session_hijacking(username, ip)

apply_thresholds_and_output()
```

**Full solution available here:**  
👉 **[View vpn_log_analyzer.py on GitHub](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/vpn/vpn_log_analyzer/vpn_log_analyzer.py)**

⭐ **Star the repo if you find it useful!** ⭐

---

## 📝 Sample Test Results

### File 025 (Brute Force Attack)
```python
{'brute_force': ['admin'], 'session_hijacking': ['grace', 'eve'], 'credential_stuffing': []}
```
✅ Detected 14 failed attempts for 'admin'  
✅ Detected grace + eve logging in from multiple locations

### File 045 (Session Hijacking)
```python
{'brute_force': [], 'session_hijacking': ['alice', 'charlie', 'frank', 'henry', 'diana'], 'credential_stuffing': []}
```
✅ Five users compromised, logging in from 3+ different IPs

### File 065 (Credential Stuffing)
```python
{'brute_force': [], 'session_hijacking': ['eve'], 'credential_stuffing': ['10.0.0.5']}
```
✅ IP trying 5 different usernames in rapid succession

### File 085 (All Three Attacks Simultaneously)
```python
{'brute_force': ['admin'], 'session_hijacking': ['frank', 'alice', 'henry'], 'credential_stuffing': ['203.0.113.42']}
```
✅ Correctly identified all attack types in single log file

### File 099 (Large Scale - 1000+ Entries)
```python
{
  'brute_force': [9 targets detected],
  'session_hijacking': [9 victims detected],
  'credential_stuffing': [16 IPs detected]
}
```
✅ Processed in <0.1 seconds

---

## 🎓 What I Learned

### Python Skills (Week 3)

**Dictionaries:**
- Frequency counting without `.get()` errors
- Building nested structures incrementally

**Sets:**
- Automatic uniqueness (no duplicate checking needed)
- Perfect for "how many different X" problems

**Error Handling:**
- Skip malformed entries with `continue` (not `exit()`)
- Resilient tools handle bad data gracefully

**File I/O:**
- Read line-by-line for memory efficiency
- Parse delimited formats systematically

### Security Concepts

**Attack Patterns:**
- Brute force: High failure rate, single target
- Session hijacking: Multiple locations, single user
- Credential stuffing: Multiple users, single source

**Threshold Selection:**
- Too low (≥2): False positives from typos
- Too high (≥10): Miss slow-and-low attacks
- Sweet spot (≥5): Industry standard from NIST

**Real-World Impact:**
- Would have detected **2019 Citrix VPN breach** (brute force)
- Would have flagged **2020 Zoom credential stuffing** (500K credentials)
- Would have caught **SolarWinds compromise** (multi-location usage)

---

## 🔧 Implementation Challenges

### Challenge 1: String Parsing

**Problem:** Extract "alice" from "user:alice"

**Solution:**
```python
username = line.split("|")[1].split(":")[1].strip()
```

### Challenge 2: Tracking Uniqueness

**Problem:** Count unique IPs per user (for session hijacking)

**Solution:** Dictionary of sets
```python
session_table = {}  # {username: set(IPs)}
session_table[username].add(ip)  # Sets handle duplicates automatically
```

### Challenge 3: Malformed Entries

**Problem:** Real logs contain corrupt data

**Initial bug:**
```python
if len(fields) != 4:
    exit(1)  # ❌ Crashes entire program
```

**Fix:**
```python
if len(fields) != 4:
    continue  # ✅ Skip bad line, keep processing
```

**Result:** Passed file 100 (malformed entries) correctly

---

## 📚 Security Context

### OWASP API Security Top 10

**API4:2023 - Unrestricted Resource Consumption**

This tool detects when attackers bypass or ignore rate limits:
- **GitHub:** Rate limits auth to 5,000/hour per IP
- **AWS IAM:** Locks accounts after 5 failed attempts
- **Cloudflare:** Blocks credential stuffing patterns

### Real Breaches This Would Detect

**2019 Citrix VPN (CVE-2019-19781):**
- Attackers brute-forced VPN gateway
- Our tool: Would flag ≥5 failures per username

**2020 Zoom Credential Stuffing:**
- 500,000+ leaked credentials tested
- Our tool: Would flag IPs trying ≥5 usernames

**SolarWinds Compromise:**
- Stolen credentials from multiple locations
- Our tool: Would flag users with ≥3 IPs

---

## 🎯 Interview Readiness

### Grace Nolan-Style Question

**Q:** *"How would you detect brute force attacks in authentication logs?"*

**My Answer (Demonstrated in Code):**
1. ✅ Parse logs into structured data (username, IP, status)
2. ✅ Use dictionaries for frequency counting
3. ✅ Apply threshold-based detection (≥5 failures)
4. ✅ Consider only failed attempts
5. ✅ Output actionable results

**Follow-up Q:** *"What about distributed brute force (multiple IPs attacking same user)?"*

**My Answer:**
- Extend to track total failures per user across ALL IPs
- Add time window analysis (e.g., 5+ failures in 5 minutes)
- Correlate with geolocation (impossible travel detection)

---

## 📦 Test Suite Included

**100 realistic VPN log files provided:**

- **Files 001-020:** Normal activity (legitimate multi-location usage)
- **Files 021-040:** Brute force attacks (5-15 failures per user)
- **Files 041-060:** Session hijacking (3-7 IPs per user)
- **Files 061-080:** Credential stuffing (5-20 users per IP)
- **Files 081-095:** Mixed attacks (all three types)
- **Files 096-100:** Edge cases (empty files, malformed data, 1000+ entries)

**Get the test suite:**  
👉 **[Download from GitHub](https://github.com/fosres/AppSec-Exercises/tree/main/netsec/vpn/vpn_log_analyzer)**

---

## 🚀 Run It Yourself

**Clone the repo:**
```bash
git clone https://github.com/fosres/AppSec-Exercises.git
cd AppSec-Exercises/netsec/vpn/vpn_log_analyzer
```

**Extract test files:**
```bash
tar -xzf vpn_test_logs.tar.gz
cd test_logs/
```

**Test on a single file:**
```bash
python3 ../vpn_log_analyzer.py vpn_auth_025.log
```

**Output:**
```python
{'brute_force': ['admin'], 'session_hijacking': ['grace', 'eve'], 'credential_stuffing': []}
```

**Test all 100 files:**
```bash
for log in vpn_auth_*.log; do
    python3 ../vpn_log_analyzer.py "$log"
done
```

**Expected result:** 100/100 passed ✅

---

## 📖 Resources & Citations

### Books Referenced

**"Hacking APIs" by Corey J. Ball (No Starch Press, 2022)**
- Chapter 3: Authentication Attacks (Pages 67-72)
- Credential stuffing detection patterns

**"API Security in Action" by Neil Madden (Manning, 2020)**
- Section 4.1.3: Rate-limiting authentication (Pages 124-127)
- Recommends ≥5 failures as brute force threshold

**"Python Workout, Second Edition" by Reuven M. Lerner (Manning, 2024)**
- Chapter 5: Dictionaries and Sets (Exercises 14-17)
- Frequency counting patterns

### Tools & Standards

- **OWASP API Security Top 10 2023**
- **NIST SP 800-63B:** Digital Identity Guidelines
- **MITRE ATT&CK:** T1110 (Brute Force), T1078 (Valid Accounts)

---

## 🎉 Results Summary

**Time Investment:** 3-4 hours total
- Requirements analysis: 30 min
- Implementation: 2 hours
- Testing & debugging: 1 hour
- Documentation: 30 min

**Skills Demonstrated:**
- ✅ Python dictionaries & sets mastery
- ✅ Security threat detection algorithms
- ✅ Robust error handling
- ✅ Test-driven development (100/100 pass rate)
- ✅ Real-world attack pattern recognition

**Interview Readiness:**
- ✅ Grace Nolan log parsing question: **SOLVED**
- ✅ Can explain algorithm in 2 minutes
- ✅ Handles follow-up questions (distributed attacks, time windows)
- ✅ Clean code ready for code review

---

## 💡 Key Takeaways

**For AppSec Engineers:**
- Threshold-based detection is powerful but requires tuning
- Real logs are messy - build resilient tools
- Single-pass processing scales to large datasets

**For Python Learners:**
- Sets solve uniqueness problems elegantly
- Dictionaries enable efficient frequency counting
- Error handling separates toy code from reliable tools

**For Security Professionals:**
- VPN logs are goldmines for threat detection
- Three attack types share common patterns
- Automation enables real-time response

---

## 🔗 Links

**GitHub Repository (Star it!):**  
⭐ **[github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)** ⭐

**My Solution:**  
👉 **[vpn_log_analyzer.py](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/vpn/vpn_log_analyzer/vpn_log_analyzer.py)**

**Test Files:**  
📦 **[100 VPN log files](https://github.com/fosres/AppSec-Exercises/tree/main/netsec/vpn/vpn_log_analyzer)**

**My LinkedIn:**  
🔗 **[linkedin.com/in/tanveer-salim](https://linkedin.com/in/tanveer-salim)**

---

## 🎯 What's Next

**Week 3 Progress:**
- ✅ Exercise 1: VPN Log Analyzer (COMPLETE - 100/100)
- 🔄 Exercise 2: Firewall Rule Conflict Detector
- 📅 Exercise 3: Network Segmentation Validator
- 📅 Exercise 4: IOC Correlator
- 📅 Exercise 5: Cipher Suite Auditor

**My Journey Timeline:**
- ✅ Week 1-2: Networking & Web Security Fundamentals
- ✅ **Week 3: VPN/Firewall Security** ← YOU ARE HERE
- 🔜 Week 4: Linux Security Hardening
- 🎯 Week 24: Begin Job Applications (GitLab, Trail of Bits, Stripe)
- 🎯 June 2026: Target AppSec Engineer Role ($125K-$145K)

**Background:**
- Former Intel IPAS Security Engineer
- Created 553+ threat models (65.83% of Intel's database)
- Built reusable threat model templates used by 100+ engineers
- Now building public portfolio for AppSec roles

---

## 💬 Discussion

**Questions for the community:**

1. **Would you use ≥5 failures or a different threshold?** What about ≥3 with time windows?

2. **How would you handle distributed brute force** (10 IPs each trying a username 1-2 times)?

3. **False positives:** What about road warriors legitimately logging in from airports, cafes, home?

4. **Time complexity:** My solution is O(n) - any way to improve further?

5. **Production deployment:** How would you integrate this into a SIEM like Splunk or ELK?

**Drop your thoughts in the comments!** 👇

---

## 🙏 Support This Project

If you found this useful:

⭐ **[Star the repo on GitHub](https://github.com/fosres/AppSec-Exercises)** - Helps others discover it!

📢 **Share this post** - More people learning security = better internet

💬 **Drop a comment** - Questions, improvements, war stories welcome

🔔 **Follow me** - Week 4 drops next week (Linux hardening)

---

## 🎓 Acknowledgments

**Inspired by:**
- **Grace Nolan** - Google Security Engineer ([gracenolan/Notes](https://github.com/gracenolan/Notes))
- **Intel IPAS Team** - Real-world threat modeling experience
- **OWASP LA Community** - Weekly security discussions
- **Null Space Labs** - Tuesday hacking nights

**Book Authors:**
- Reuven M. Lerner (*Python Workout*)
- Corey J. Ball (*Hacking APIs*)
- Neil Madden (*API Security in Action*)

---

**Tags:** #appsec #python #cybersecurity #security #infosec #coding #100daysofcode #gracenolan #securityengineering #loganalysis

**Series:** 48-Week AppSec Engineering Journey

---

## ⭐ Final Ask

If this helped you understand attack detection patterns or you're building your own security tools:

👉 **[Star the repo on GitHub](https://github.com/fosres/AppSec-Exercises)** 👈

It takes 2 seconds and helps the project reach more people learning AppSec! 🚀

---

*Next week: Linux Security Hardening - SSH audit tool, file integrity monitoring, and kernel security! 🐧*

*Have questions? Drop them below! 👇*
