# Building a Security Log Correlator: Fast Incident Detection

## 3:47 AM - When Log Correlation Stopped a Ransomware Attack

The Slack alert woke up Sarah Chen, Senior Security Engineer at FinSecure Technologies. **"CRITICAL: 47 failed login attempts on admin_svc_backup account"** - her automated correlation tool had flagged something.

Most analysts would have dismissed it. Failed logins happen constantly. But Sarah's log correlator had done something crucial: it had **correlated authentication failures with a successful login 90 seconds later** - and that success came from an IP address in Belarus, not their Virginia data center.

She pulled up the full incident timeline:

```
03:42:15 - admin_svc_backup: login FAILURE (IP: 178.248.xxx.xxx)
03:42:18 - admin_svc_backup: login FAILURE (IP: 178.248.xxx.xxx)
[... 45 more failures in 3 minutes ...]
03:45:47 - admin_svc_backup: login SUCCESS (IP: 178.248.xxx.xxx) ⚠️
03:46:12 - admin_svc_backup: privilege_change to "domain_admin" ⚠️
03:46:34 - admin_svc_backup: file_access /etc/shadow ⚠️
03:47:01 - admin_svc_backup: file_access /backup/customer_data/* ⚠️
```

**The attacker had gotten in.** They'd brute forced a backup service account (weak password: "Backup2023!"), immediately escalated to domain admin, and started accessing customer financial data. Sarah's correlation tool had caught them 14 minutes into what would have become a $200M ransomware attack.

By 4:15 AM, the compromised account was locked, the attacker's session terminated, and the security team was analyzing how they'd obtained the credential list. **The breach was contained before a single customer record was exfiltrated.**

Without automated log correlation, this attack would have been discovered during Monday's routine log review - 72 hours and millions of stolen records later.

**Note:** This scenario combines elements from documented breach patterns including credential stuffing attacks against service accounts. The attack timeline and detection methods reflect real SOC incident response procedures.

---

## Introduction

This is the power of effective log correlation. As Security Engineers, we spend significant time analyzing logs to detect security incidents. But when you're dealing with thousands of authentication attempts and security events per minute, efficiency matters. A lot.

**In this post, you'll build the exact type of log correlator that caught Sarah's attack.** This isn't a theoretical exercise - it's the same pattern-detection logic that SOC teams use to stop real attacks in progress.

In this post, I'll walk you through building a production-grade log correlator that efficiently processes authentication and security logs to detect incidents. This is exactly the type of challenge you'll face in Security Engineering interviews - and the exact skill that stops breaches like Sarah's ransomware attack.

**What you'll learn:**
- Parsing heterogeneous log formats (CSV and JSON) securely
- Building efficient data structures for log correlation (the key to real-time detection)
- Detecting common attack patterns (brute force, privilege escalation, anomalous access)
- Applying secure coding principles to systems programming
- **Why this matters:** These are the exact patterns that security teams use to catch real breaches before they cause catastrophic damage

**Prerequisites:**
- Intermediate Python knowledge
- Basic understanding of security concepts
- Familiarity with time complexity analysis

## 🎯 How This Exercise Relates to Production Security Work

**"Will I actually write Python log parsers in my Security Engineering job?"**

The honest answer: **Probably not.** In production, you'll use SIEM platforms (Splunk, Azure Sentinel, ELK Stack) that handle log ingestion and parsing automatically. You'll write detection rules in query languages like SPL or KQL, not Python parsers.

**So why build this from scratch?**

### What You're Actually Learning (The Real Value)

**1. Detection Logic & Pattern Recognition** ✅ **100% Transferable**
- The brute force detection logic (5+ failures → success within window) is *exactly* how SIEM rules work
- Privilege escalation patterns (login → immediate sudo) are standard SOC detections
- These concepts transfer directly to writing Splunk/Sentinel queries

**2. Understanding What's Happening Under the Hood** ✅ **Critical for Interviews**
When a company asks: *"How would you detect credential stuffing in authentication logs?"*
- **Weak answer:** "I'd use Splunk"
- **Strong answer:** "I'd correlate failed login attempts by source IP and user, flagging when we see 5+ failures within a 5-minute window followed by success. The key challenge is the time window calculation and handling distributed attacks from botnets..."

You need to understand the logic to explain it, optimize it, and debug it.

**3. Foundation for SIEM Work** ✅ **Career-Critical**
When you start writing detection rules in production:
```spl
# Real Splunk query for brute force detection
index=auth action=login status=failure 
| stats count by user src_ip 
| where count > 5
| join user [search index=auth action=login status=success]
```

You'll understand *why* this query works because you implemented the logic yourself. You'll know:
- Why the time window matters
- What makes queries slow
- How to optimize detection rules
- When correlation is feasible vs. too expensive

**4. Interview Preparation** ✅ **Directly Tested**
Security Engineering interviews commonly include:
- "Build a tool to detect X pattern in these logs" ← This exercise
- "How would you correlate authentication and security events?" ← You can explain it
- "What's the time complexity of your approach?" ← You understand the trade-offs

According to the Team Blind Security Engineering guide, log correlation challenges appear frequently in technical interviews.

### What's Different in Production

| This Exercise | Production Reality |
|---------------|-------------------|
| Parse CSV/JSON manually | Logs auto-ingested by forwarders (Filebeat, Splunk Universal Forwarder) |
| Process files in memory | SIEM indexes billions of events in distributed databases |
| Write Python detection logic | Write SPL/KQL/YARA-L detection rules |
| Return structured results | Trigger alerts → tickets → incident response workflows |
| Test with 50K events | Process millions of events per day across clusters |

### Where You WILL Write Python in Security Engineering

Even though you won't write log parsers, Python is essential for:
1. **Security automation**: Scripts for repetitive SOC tasks
2. **API integrations**: Pulling threat intel, updating firewalls
3. **Custom tooling**: Gaps your SIEM can't fill
4. **Threat hunting**: Processing forensic dumps, analyzing malware
5. **Detection engineering**: Testing and validating SIEM rules

### The Bottom Line

**This exercise teaches you:**
- ✅ How log correlation fundamentally works
- ✅ Attack pattern recognition (brute force, privilege escalation)
- ✅ Why time windows and thresholds matter
- ✅ The signal-to-noise challenge (5% attacks in 95% legitimate traffic)

**You won't use this exact code in production, but you'll use these concepts every single day.**

Think of it like learning to drive: You practice fundamentals in an empty parking lot before driving on highways with traffic. This exercise is your parking lot - learning correlation fundamentals before working with enterprise SIEM platforms.

---

## What These Logs Represent in the Real World

Before we dive in, let's be clear: these aren't toy examples. The log formats and attack patterns you'll work with mirror **actual production security logs** that SOC analysts investigate daily.

### `auth.log` - Authentication Events
In production, this data comes from:
- **Linux/Unix systems**: `/var/log/auth.log`, `/var/log/secure` (SSH, sudo attempts)
- **Windows**: Security Event Log (Event IDs 4624/4625)
- **Cloud platforms**: AWS CloudTrail, Azure Activity Logs, GCP Audit Logs
- **Applications**: Web app logins, VPN gateways, corporate SSO systems

**Example real scenario:** An attacker in Eastern Europe attempts 10,000 password combinations against admin accounts. Each attempt generates an auth.log entry. When they succeed with "Password123!", that's your signal to investigate.

### `security.log` - Post-Authentication Activity
In production, this data comes from:
- **SIEM systems**: Log aggregation and correlation platforms
- **EDR tools**: Endpoint detection and response platforms
- **File integrity monitoring**: OSSEC, Tripwire, Linux auditd
- **Cloud APIs**: AWS API calls, Azure Resource Manager operations

**Example real scenario:** After successful login, an attacker immediately accesses `/etc/shadow` (password hashes), escalates to root, and creates backdoor accounts. Each action generates a security.log entry. Your correlator detects this suspicious sequence.

### Attack Patterns You're Detecting

The test cases simulate **real security incidents:**

- **Brute Force (Test 031+)**: Similar to documented attacks where attackers try thousands of password combinations
- **Privilege Escalation (Test 046+)**: Mirrors real breaches where compromised credentials led to immediate admin access from foreign IPs
- **Distributed Attacks (Test 043)**: Reflects ongoing account takeover attempts from 500+ bot IPs

**These aren't hypotheticals - they're based on published incident reports and MITRE ATT&CK patterns.**

---

**📊 ABOUT THE TEST DATA:**

The test files for this exercise contain **production-realistic volumes**:
- **53,556 total log entries** across 101 test cases
- **Real signal-to-noise ratios**: 5-20% attacks hidden in 80-95% legitimate traffic
- **Actual breach patterns**: Based on documented real-world incidents
- **Scalable testing**: From 50 entries (small) to 25,000 entries (enterprise scale)

**Why this matters:** Testing with 3 log entries proves nothing. Testing with 10,000 entries where attacks are buried in normal traffic? That proves your code works in production.

---

## The Problem

You're investigating a potential security incident. You have two log sources:

1. **Authentication Log** (`auth.log`) - CSV format tracking all login attempts
2. **Security Events Log** (`security.log`) - JSON format tracking file access, privilege changes, and alerts

You need to:
- Correlate events by user **efficiently**
- Detect brute force attacks
- Identify suspicious privilege escalations
- Flag anomalous access patterns

Sounds straightforward, right? Let's dig into the details.

## Log Formats

**Authentication Log (CSV):**
```csv
timestamp,user_id,action,ip_address,status,session_id
2024-01-15T10:23:45Z,user123,login,192.168.1.50,success,sess_abc123
2024-01-15T10:24:01Z,user456,login,203.0.113.42,failure,sess_def456
```

**Security Events Log (JSON):**
```json
{"timestamp": "2024-01-15T10:24:12Z", "user_id": "user123", "event_type": "file_access", "resource": "/etc/passwd", "session_id": "sess_abc123", "ip_address": "192.168.1.50"}
{"timestamp": "2024-01-15T10:25:30Z", "user_id": "user456", "event_type": "privilege_change", "resource": "sudo_access", "session_id": "sess_def456", "ip_address": "203.0.113.99"}
```

## Input & Output Examples

### Sample Input Files

**auth.log** (50 entries showing brute force attack):
```csv
timestamp,user_id,action,ip_address,status,session_id
2024-01-15T10:00:00Z,attacker01,login,203.0.113.42,failure,sess_fail_01
2024-01-15T10:00:48Z,attacker01,login,203.0.113.42,failure,sess_fail_02
2024-01-15T10:01:36Z,attacker01,login,203.0.113.42,failure,sess_fail_03
2024-01-15T10:02:24Z,attacker01,login,203.0.113.42,failure,sess_fail_04
2024-01-15T10:03:12Z,attacker01,login,203.0.113.42,failure,sess_fail_05
2024-01-15T10:04:00Z,attacker01,login,203.0.113.42,success,sess_success_01
2024-01-15T10:05:00Z,normal_user01,login,192.168.1.100,success,sess_norm_01
2024-01-15T10:06:00Z,normal_user02,login,192.168.1.101,success,sess_norm_02
...
(42 more normal user logins)
```

**security.log** (75 entries showing post-compromise activity):
```json
{"timestamp": "2024-01-15T10:04:30Z", "user_id": "attacker01", "event_type": "file_access", "resource": "/etc/shadow", "session_id": "sess_success_01", "ip_address": "203.0.113.42"}
{"timestamp": "2024-01-15T10:04:45Z", "user_id": "attacker01", "event_type": "privilege_change", "resource": "sudo_access", "session_id": "sess_success_01", "ip_address": "203.0.113.42"}
{"timestamp": "2024-01-15T10:05:00Z", "user_id": "attacker01", "event_type": "file_access", "resource": "/root/.ssh/authorized_keys", "session_id": "sess_success_01", "ip_address": "203.0.113.42"}
{"timestamp": "2024-01-15T10:05:30Z", "user_id": "normal_user01", "event_type": "file_access", "resource": "/home/normal_user01/report.pdf", "session_id": "sess_norm_01", "ip_address": "192.168.1.100"}
{"timestamp": "2024-01-15T10:06:15Z", "user_id": "normal_user02", "event_type": "file_access", "resource": "/home/normal_user02/data.csv", "session_id": "sess_norm_02", "ip_address": "192.168.1.101"}
...
(70 more normal user activities)
```

### Expected Output

**1. After Parsing:**
```python
# parse_auth_log() returns:
[
    {"timestamp": "2024-01-15T10:00:00Z", "user_id": "attacker01", "action": "login", 
     "ip_address": "203.0.113.42", "status": "failure", "session_id": "sess_fail_01"},
    {"timestamp": "2024-01-15T10:00:48Z", "user_id": "attacker01", "action": "login", 
     "ip_address": "203.0.113.42", "status": "failure", "session_id": "sess_fail_02"},
    # ... more events
]

# parse_security_log() returns:
[
    {"timestamp": "2024-01-15T10:04:30Z", "user_id": "attacker01", "event_type": "file_access",
     "resource": "/etc/shadow", "session_id": "sess_success_01", "ip_address": "203.0.113.42"},
    # ... more events
]
```

**2. After Correlation:**
```python
# correlate_events() returns:
{
    "attacker01": {
        "auth_events": [
            {"timestamp": "2024-01-15T10:00:00Z", "status": "failure", ...},
            {"timestamp": "2024-01-15T10:00:48Z", "status": "failure", ...},
            {"timestamp": "2024-01-15T10:01:36Z", "status": "failure", ...},
            {"timestamp": "2024-01-15T10:02:24Z", "status": "failure", ...},
            {"timestamp": "2024-01-15T10:03:12Z", "status": "failure", ...},
            {"timestamp": "2024-01-15T10:04:00Z", "status": "success", ...}
        ],
        "security_events": [
            {"timestamp": "2024-01-15T10:04:30Z", "resource": "/etc/shadow", ...},
            {"timestamp": "2024-01-15T10:04:45Z", "resource": "sudo_access", ...},
            {"timestamp": "2024-01-15T10:05:00Z", "resource": "/root/.ssh/authorized_keys", ...}
        ]
    },
    "normal_user01": {
        "auth_events": [
            {"timestamp": "2024-01-15T10:05:00Z", "status": "success", ...}
        ],
        "security_events": [
            {"timestamp": "2024-01-15T10:05:30Z", "resource": "/home/normal_user01/report.pdf", ...}
        ]
    },
    # ... more users
}
```

**3. After Detection:**
```python
# detect_brute_force("attacker01", user_events) returns:
True  # 5 failures within 5 minutes, then success

# detect_brute_force("normal_user01", user_events) returns:
False  # No attack pattern detected

# detect_anomalous_access("attacker01", user_events) returns:
True  # Accessed /etc/shadow (sensitive file)

# detect_anomalous_access("normal_user01", user_events) returns:
False  # Only accessed normal files
```

**4. Final Incident Report:**
```python
# generate_incident_report("attacker01", user_events) returns:
{
    "user_id": "attacker01",
    "auth_events": [6 events],  # 5 failures + 1 success
    "security_events": [3 events],  # 3 suspicious file accesses
    "incident_flags": ["brute_force", "anomalous_access"]
}

# When printed:
"""
User: attacker01
Auth Events: 6
Security Events: 3
Incident Flags: ['brute_force', 'anomalous_access']

Timeline:
  2024-01-15T10:00:00Z - Login attempt from 203.0.113.42 - FAILURE
  2024-01-15T10:00:48Z - Login attempt from 203.0.113.42 - FAILURE
  2024-01-15T10:01:36Z - Login attempt from 203.0.113.42 - FAILURE
  2024-01-15T10:02:24Z - Login attempt from 203.0.113.42 - FAILURE
  2024-01-15T10:03:12Z - Login attempt from 203.0.113.42 - FAILURE
  2024-01-15T10:04:00Z - Login attempt from 203.0.113.42 - SUCCESS ⚠️
  2024-01-15T10:04:30Z - File access: /etc/shadow ⚠️
  2024-01-15T10:04:45Z - Privilege change: sudo_access ⚠️
  2024-01-15T10:05:00Z - File access: /root/.ssh/authorized_keys ⚠️

⚠️ SECURITY INCIDENT DETECTED ⚠️
- Brute force attack: 5 failed logins followed by success
- Anomalous access: Accessed sensitive system files
- Privilege escalation: Gained sudo access immediately after login
"""
```

### Running Your Implementation

```bash
$ python3 log_correlator.py
Parsing logs...
Parsed 50 auth events
Parsed 75 security events

Correlating events...
Correlated events for 43 users

Analyzing users...
⚠️  INCIDENT: attacker01 - brute_force, anomalous_access, privilege_escalation
✅  NORMAL: normal_user01 - no incidents detected
✅  NORMAL: normal_user02 - no incidents detected
...

Incident Summary:
- Total users: 43
- Users with incidents: 1
- Brute force attacks detected: 1
- Privilege escalations detected: 1
- Anomalous file access detected: 1
```

This is exactly what SOC analysts see when investigating alerts in SIEM systems!

## Detection Criteria - What Counts as an Attack?

Before you start coding, you need to know **exactly** what your detection functions should flag. Here are the precise criteria:

### 🚨 Brute Force Attack Detection

**Where to look in the data structure:**
```python
user_events = {
    "user123": {
        "auth_events": [               # ← CHECK THIS for login patterns
            {"timestamp": "10:00:00Z", "status": "failure", "ip_address": "203.0.113.42", ...},
            {"timestamp": "10:00:48Z", "status": "failure", "ip_address": "203.0.113.42", ...},
            {"timestamp": "10:01:36Z", "status": "failure", "ip_address": "203.0.113.42", ...},
            {"timestamp": "10:02:24Z", "status": "failure", "ip_address": "203.0.113.42", ...},
            {"timestamp": "10:03:12Z", "status": "failure", "ip_address": "203.0.113.42", ...},
            {"timestamp": "10:04:00Z", "status": "success", "ip_address": "203.0.113.42", ...}
        ],
        "security_events": [...]       # ← NOT used for brute force detection
    }
}
```

**When to flag as brute force:**
- **5 or more** failed login attempts for the same user
- All failures must occur within a **5-minute time window**
- **A successful login must occur within the SAME 5-minute window**
- **Record the EXACT successful login event** within that window

**CRITICAL IMPLEMENTATION NOTE:** 
- The 5-minute window is measured from the **first failure to the last failure** in the sequence
- Success must be within this same window to be detected as brute force
- If success occurs OUTSIDE the window → Return `None` (don't detect)
- If success occurs WITHIN the window → Return attack details with that exact success event
- This keeps the logic clean: either detect a complete attack (with success), or don't detect at all

**Example 1: Attack DETECTED (Success Within Window)**
```
10:00:00 - user123 login FAILURE (IP: 203.0.113.42)   ← Window starts
10:00:48 - user123 login FAILURE (IP: 203.0.113.42)
10:01:36 - user123 login FAILURE (IP: 203.0.113.42)
10:02:24 - user123 login FAILURE (IP: 203.0.113.42)
10:03:12 - user123 login FAILURE (IP: 203.0.113.42)   ← 5th failure
10:04:00 - user123 login SUCCESS (IP: 203.0.113.42)   ← Within 5-min window!
                                                         (4 min from first failure)
```
**Time window:** 10:00:00 to 10:05:00 (5 minutes)  
**Detection result:** ✅ **DETECTED** - 5 failures + success within window  
**Return:** Attack dict with `success_event` = the 10:04:00 login event

**Example 2: Attack NOT DETECTED (Success Outside Window)**
```
10:00:00 - user123 login FAILURE (IP: 203.0.113.42)   ← Window starts
10:01:00 - user123 login FAILURE (IP: 203.0.113.42)
10:02:00 - user123 login FAILURE (IP: 203.0.113.42)
10:03:00 - user123 login FAILURE (IP: 203.0.113.42)
10:04:00 - user123 login FAILURE (IP: 203.0.113.42)   ← 5th failure
                                                       ← Window ends at 10:05:00
10:07:00 - user123 login SUCCESS (IP: 203.0.113.42)   ← Outside window!
                                                         (7 min from first failure)
```
**Time window:** 10:00:00 to 10:05:00 (5 minutes)  
**Detection result:** ❌ **NOT DETECTED** - Success outside window  
**Return:** `None` (attack attempt blocked or unrelated success)

**When NOT to flag (false positive examples):**
```
# Only 4 failures (below threshold)
10:00:00 - user123 login FAILURE
10:00:30 - user123 login FAILURE
10:01:00 - user123 login FAILURE
10:01:30 - user123 login FAILURE   ← Only 4 failures
10:02:00 - user123 login SUCCESS
```
**Detection result:** ❌ **Do NOT flag** (below 5-failure threshold)

```
# Failures outside time window
10:00:00 - user123 login FAILURE
10:07:00 - user123 login FAILURE   ← More than 5 minutes apart
10:14:00 - user123 login FAILURE
10:21:00 - user123 login FAILURE
10:28:00 - user123 login FAILURE
10:35:00 - user123 login SUCCESS
```
**Detection result:** ❌ **Do NOT flag** (failures too spread out)

#### Handling Multiple Attacks on Same User (detect_brute_force)

**What if a user experiences multiple separate brute force attacks?**

In production, attackers often try multiple times - they might brute force an account in the morning, get locked out, then try again in the afternoon with a different password list. Your **`detect_brute_force()` function** should detect **ALL attacks**.

**Example: Two separate attacks on same user:**
```
# Morning attack (Attack 1)
08:00:00 - admin login FAILURE (IP: 203.0.113.42)
08:01:00 - admin login FAILURE (IP: 203.0.113.42)
08:02:00 - admin login FAILURE (IP: 203.0.113.42)
08:03:00 - admin login FAILURE (IP: 203.0.113.42)
08:04:00 - admin login FAILURE (IP: 203.0.113.42)
08:05:00 - admin login SUCCESS (IP: 203.0.113.42)  ← Attack 1 succeeded

# Normal activity for several hours...

# Afternoon attack (Attack 2) - more aggressive
14:00:00 - admin login FAILURE (IP: 45.134.142.XX)
14:00:30 - admin login FAILURE (IP: 45.134.142.XX)
14:01:00 - admin login FAILURE (IP: 45.134.142.XX)
14:01:30 - admin login FAILURE (IP: 45.134.142.XX)
14:02:00 - admin login FAILURE (IP: 45.134.142.XX)
14:02:30 - admin login FAILURE (IP: 45.134.142.XX)
14:03:00 - admin login FAILURE (IP: 45.134.142.XX)
14:03:30 - admin login FAILURE (IP: 45.134.142.XX)
14:04:00 - admin login SUCCESS (IP: 45.134.142.XX)  ← Attack 2 succeeded
```

**Your `detect_brute_force()` function should return:**
```python
{
    "user_id": "admin",
    "attacks": [
        {
            "failure_count": 5,
            "failure_chain": [/* 5 morning failures */],
            "success_event": {/* 08:05:00 success */},
            "attack_duration_seconds": 300
        },
        {
            "failure_count": 8,
            "failure_chain": [/* 8 afternoon failures */],
            "success_event": {/* 14:04:00 success */},
            "attack_duration_seconds": 240
        }
    ],
    "total_attacks": 2
}
```

This is the return value from calling:
```python
result = detect_brute_force("admin", user_events)
# result contains the structure shown above
```

**Why this matters for SOC:** A single attack might be an opportunistic attacker. Multiple attacks in one day? That's a targeted, persistent threat that needs immediate investigation. Your correlator provides the complete attack timeline.

**Implementation note for `detect_brute_force()`:** If you detect only ONE attack, you can return either the single attack structure OR the multiple attacks structure with one item in the array - both are valid. But if you detect multiple attacks, you MUST use the multiple attacks structure shown above.

### 🔓 Privilege Escalation Detection

**Where to look in the data structure:**
```python
user_events = {
    "user456": {
        "auth_events": [               # ← CHECK THIS for login events
            {"timestamp": "...", "status": "success", "ip_address": "...", ...}
        ],
        "security_events": [           # ← CHECK THIS for privilege_change events
            {"timestamp": "...", "event_type": "privilege_change", "resource": "sudo_access", ...}
        ]
    }
}

# Your code needs to check BOTH lists:
auth_events = user_events["user456"]["auth_events"]        # Step 1: Find login
security_events = user_events["user456"]["security_events"]  # Step 2: Find privilege change
```

**When to flag as privilege escalation:**

**Core detection criteria (ALWAYS check these):**
1. User has a **successful login** (any IP address)
2. Within **10 minutes** of that login, there's a security event with `event_type: "privilege_change"`
3. The `resource` field indicates elevated access: "sudo_access", "admin_role", "root_access", "elevated_privileges", "administrator"

**Why this is suspicious:**
Normal users login and work for hours before needing elevated privileges. Attackers login and **immediately** escalate to maximize their access time.

**Optional enhancement (BONUS, not required):**
You can make detection MORE sophisticated by also checking for:
- Failed login attempts before the successful login (indicates credential guessing)
- Login from different IP than usual (indicates account compromise)
- Multiple privilege escalations in short time (indicates automated attack)

But for the basic exercise, just detect: **Login → Privilege change within 10 minutes**

**Example attack pattern:**
```
# auth.log
10:02:00 - user456 login SUCCESS (IP: 203.0.113.99)       ← User logs in

# security.log  
10:03:30 - user456 privilege_change: "sudo_access" (IP: 203.0.113.99)  ← Escalates 90 seconds later!
```
**Detection result:** ✅ **Flag as privilege escalation** (privilege gained within 10 min of login)

**Why suspicious:** Normal users work for hours before needing sudo. Immediate escalation indicates attacker maximizing their access window.

**Real-world breach pattern:**
1. Attacker obtained credentials
2. Used credentials to login via VPN
3. **Immediately escalated to admin privileges** ← This pattern!
4. This is what your code should detect

**Additional example with failed attempts (more suspicious):**
```
# auth.log
10:00:00 - user456 login FAILURE (IP: 192.168.1.100)      ← Failed from corporate
10:02:00 - user456 login SUCCESS (IP: 203.0.113.99)       ← Success from external

# security.log
10:03:30 - user456 privilege_change: "sudo_access"         ← Immediate escalation
```
**Detection result:** ✅ **Flag as privilege escalation** (even more suspicious with failed attempts first)

**When NOT to flag:**
```
# Normal admin workflow
10:00:00 - admin_user login SUCCESS (IP: 192.168.1.100)
14:30:00 - admin_user privilege_change: "sudo_access"      ← 4.5 hours later (outside 10-min window)
```
**Detection result:** ❌ **Do NOT flag** (privilege change happened hours later = normal work pattern)

```
# User already logged in, no privilege change
10:00:00 - user456 login SUCCESS
10:05:00 - (no privilege_change event)
```
**Detection result:** ❌ **Do NOT flag** (no privilege escalation occurred)

---

## 🚨 CRITICAL IMPLEMENTATION REQUIREMENT - Filtering Login Sessions

**YOU MUST ONLY RETURN LOGIN SESSIONS THAT HAVE PRIVILEGE ESCALATIONS.**

This is a common mistake that causes test failures. Read carefully:

### The Common Mistake:

Students often return **ALL** login sessions, even those with zero privilege escalations.

**Example of the problem:**
- User logs in 5 times during normal work
- Only 1 of those logins has a privilege escalation within 10 minutes
- **Wrong approach:** Returns all 5 login sessions in the result
- **Correct approach:** Returns only the 1 session that had an escalation

**Why this matters:**
- `login_sessions` should contain ONLY sessions where privilege escalation occurred
- `total_login_sessions` represents "logins that led to escalation" (not total logins)
- If user logged in 10 times but only 2 had escalations → `total_login_sessions` = 2

### What You Need to Implement:

Before adding a login session to your results, **check if it actually has any privilege escalations**. Only include sessions where escalations occurred within the time window.

### Example Timeline:
```
User's login timeline:
08:00 - login SUCCESS → no privilege change → ❌ Don't include
09:00 - login SUCCESS → no privilege change → ❌ Don't include
10:00 - login SUCCESS → privilege_change at 10:02 → ✅ Include this session!
11:00 - login SUCCESS → no privilege change → ❌ Don't include
12:00 - login SUCCESS → privilege_change at 12:01 → ✅ Include this session!

Your return value should have:
- login_sessions array with 2 items (10:00 and 12:00 sessions)
- total_login_sessions = 2
- total_escalations = 2
```

**Key principle:** Filter your results to include only login sessions that have associated privilege escalations. Empty sessions don't belong in a security report.

---

**ONLY include login sessions that have privilege escalations.** Do NOT include login sessions with zero escalations.

This means:
- If a user logs in 5 times during the day
- Only 1 of those logins has a privilege escalation within 10 minutes
- Your `login_sessions` array should contain **ONLY that 1 session**
- `total_login_sessions` should be **1** (not 5)

**Example of CORRECT filtering:**
```python
# WRONG - includes ALL login sessions:
for login in auth_events:
    if login['status'] == 'success':
        session = find_escalations_after_login(login)
        session['escalation_count'] = len(session['privilege_escalations'])
        login_sessions.append(session)  # ❌ Adds session even if escalation_count is 0

# CORRECT - only includes sessions WITH escalations:
for login in auth_events:
    if login['status'] == 'success':
        session = find_escalations_after_login(login)
        session['escalation_count'] = len(session['privilege_escalations'])
        if session['escalation_count'] > 0:  # ✅ Only add if there ARE escalations
            login_sessions.append(session)
```

**Why this matters:**
- `total_login_sessions` represents "logins that led to privilege escalation"
- NOT "total number of logins the user had"
- Only suspicious sessions should be in the report

**What counts as "privilege_change":**
Look for security events where:
- `event_type` field equals `"privilege_change"` 
- `resource` field contains indicators like:
  - "sudo_access"
  - "admin_role"
  - "root_access"
  - "elevated_privileges"
  - "administrator"

### 📁 Anomalous File Access Detection

**Where to look in the data structure:**
```python
user_events = {
    "user123": {
        "auth_events": [...],           # ← NOT used for anomalous access
        "security_events": [...]         # ← CHECK THIS for file_access events
    }
}
```

**When to flag as anomalous access:**
User accessed **ANY** of these sensitive files in their security events:

**CRITICAL SYSTEM FILES:**
- `/etc/passwd` - User account database (world-readable but attackers enumerate it)
- `/etc/shadow` - Encrypted passwords (should NEVER be accessed except by root)
- `/etc/sudoers` - Sudo permissions configuration
- `/etc/group` - Group definitions

**SSH & AUTHENTICATION:**
- `/root/.ssh/authorized_keys` - Root SSH keys (backdoor installation)
- `/home/*/.ssh/authorized_keys` - User SSH keys (persistence mechanism)
- `/home/*/.ssh/id_rsa` - Private SSH keys (credential theft)
- `/home/*/.ssh/id_ed25519` - Private SSH keys (newer format)

**SYSTEM CONFIGURATION:**
- `/boot/grub/grub.cfg` - Bootloader configuration
- `/etc/crontab` - System-wide scheduled tasks (persistence)
- `/var/spool/cron/*` - User cron jobs (persistence)

**LOGS (tampering attempts):**
- `/var/log/auth.log` - Authentication logs (covering tracks)
- `/var/log/secure` - Security logs (covering tracks)
- `/var/log/audit/audit.log` - Audit logs (covering tracks)

**Example attack pattern:**
```json
# security.log
{"timestamp": "10:04:30Z", "user_id": "attacker01", 
 "event_type": "file_access", "resource": "/etc/shadow", ...}
```
**Detection result:** ✅ **Flag as anomalous** (/etc/shadow is sensitive)

```json
{"timestamp": "10:05:00Z", "user_id": "attacker01",
 "event_type": "file_access", "resource": "/root/.ssh/authorized_keys", ...}
```
**Detection result:** ✅ **Flag as anomalous** (installing backdoor)

**When NOT to flag (normal file access):**
```json
# User's own documents
{"event_type": "file_access", "resource": "/home/alice/documents/report.pdf"}
```
**Detection result:** ❌ **Do NOT flag** (normal file)

```json
# Temporary files
{"event_type": "file_access", "resource": "/tmp/upload_12345.tmp"}
```
**Detection result:** ❌ **Do NOT flag** (temp files are normal)

```json
# Web content (if user is web admin)
{"event_type": "file_access", "resource": "/var/www/html/index.html"}
```
**Detection result:** ❌ **Do NOT flag** (web admin accessing web files)

```json
# Shared system files
{"event_type": "file_access", "resource": "/usr/share/icons/theme.png"}
```
**Detection result:** ❌ **Do NOT flag** (normal system file)

**Implementation tip:**
Check if the `resource` field in security events **contains** any of the sensitive file paths. Use string matching:
```python
sensitive_files = ["/etc/passwd", "/etc/shadow", "/root/.ssh/authorized_keys", ...]
for event in security_events:
    resource = event.get("resource", "")
    for sensitive_path in sensitive_files:
        if sensitive_path in resource:
            return True  # Found sensitive file access!
```

## Core Requirements

**⚠️ CRITICAL: Defensive Programming for Detect Functions**

All three detect functions MUST handle missing data gracefully. Here's what to return:

| Function | Missing user_id | Missing auth_events | Missing security_events |
|----------|----------------|---------------------|------------------------|
| `detect_brute_force` | `{"user_id": user_id}` | `{"user_id": user_id}` | N/A (doesn't need it) |
| `detect_privilege_escalation` | Full empty structure* | Full empty structure* | Full empty structure* |
| `detect_anomalous_access` | `None` | N/A (doesn't need it) | `None` |

*Full empty structure for `detect_privilege_escalation`:
```python
{
    "user_id": user_id,
    "login_sessions": [],
    "total_login_sessions": 0,
    "total_escalations": 0
}
```

**Why this matters:**
- Grader checks these fields without try/except
- Returning wrong type (None vs dict) causes test failures
- Each function has different requirements based on what data it needs

**Example defensive code pattern:**
```python
def detect_brute_force(user_id, user_events, ...):
    # ✅ ALWAYS check these first
    if user_id not in user_events:
        return {"user_id": user_id}
    
    if "auth_events" not in user_events[user_id]:
        return {"user_id": user_id}
    
    # ✅ Now safe to process
    auth_events = user_events[user_id]["auth_events"]
    # ... rest of implementation
```

---

Your implementation must include these **functions** (no classes needed):

### 1. **Data Representation** (Use Dictionaries)

```python
# Authentication event (dictionary)
auth_event = {
    "timestamp": "2024-01-15T10:23:45Z",
    "user_id": "user123",
    "action": "login",
    "ip_address": "192.168.1.50",
    "status": "success",
    "session_id": "sess_abc123"
}

# Security event (dictionary)
security_event = {
    "timestamp": "2024-01-15T10:24:12Z",
    "user_id": "user123",
    "event_type": "file_access",
    "resource": "/etc/passwd",
    "session_id": "sess_abc123",
    "ip_address": "192.168.1.50"
}

# Correlated events (dictionary with lists)
user_events = {
    "user123": {
        "auth_events": [auth_event1, auth_event2, ...],
        "security_events": [security_event1, security_event2, ...],
        "incident_flags": ["brute_force", "privilege_escalation"]
    }
}
```

### 2. **Parsing Functions**

**NOTE:** There are two valid implementation approaches:

**Approach A:** Parse functions return lists, then correlate separately
**Approach B:** Parse functions build correlated structure directly (recommended for grader)

```python
# Approach A (returns lists)
def parse_auth_log(filepath):
    """
    Parse CSV authentication log.
    Returns: List of dictionaries (auth events)
    
    Must handle:
    - Malformed CSV lines
    - Invalid timestamps
    - Invalid IP addresses
    - Missing fields
    """
    # TODO: Implement
    pass

def parse_security_log(filepath):
    """
    Parse JSON security events log.
    Returns: List of dictionaries (security events)
    
    Must handle:
    - Malformed JSON
    - Missing required fields
    - Encoding issues
    """
    # TODO: Implement
    pass
```

```python
# Approach B (builds user_events directly - used by grader)
def parse_auth_log(filepath, user_events):
    """
    Parse CSV authentication log and populate user_events in-place.
    
    Args:
        filepath: Path to auth.log
        user_events: Dictionary to populate with structure:
            {user_id: {"auth_events": [...], "security_events": [...]}}
    
    Modifies user_events in-place, building:
        user_events[user_id]["auth_events"] = [list of auth event dicts]
    
    Must handle:
    - Malformed CSV lines
    - Invalid timestamps
    - Invalid IP addresses
    - Missing fields
    """
    # TODO: Implement
    pass

def parse_security_log(filepath, user_events):
    """
    Parse JSON security events log and populate user_events in-place.
    
    Args:
        filepath: Path to security.log
        user_events: Dictionary to populate (same dict from parse_auth_log)
    
    Modifies user_events in-place, building:
        user_events[user_id]["security_events"] = [list of security event dicts]
    
    Must handle:
    - Malformed JSON
    - Missing required fields
    - Encoding issues
    """
    # TODO: Implement
    pass
```

### 3. **Correlation Function**

```python
def correlate_events(auth_events, security_events):
    """
    Correlate events by user_id for efficient lookup.
    
    **NOTE:** This function is OPTIONAL. You can instead build the correlated structure
    directly during parsing by having parse_auth_log() and parse_security_log() accept
    a user_events dictionary parameter and populate it in-place. Both approaches are valid:
    
    **Approach A (Three-function):**
    ```python
    auth_events = parse_auth_log(filepath)  # Returns list
    security_events = parse_security_log(filepath)  # Returns list  
    user_events = correlate_events(auth_events, security_events)  # Returns dict
    ```
    
    **Approach B (Two-function, correlation during parsing):**
    ```python
    user_events = {}
    parse_auth_log(filepath, user_events)  # Modifies dict in-place
    parse_security_log(filepath, user_events)  # Modifies dict in-place
    ```
    
    Args:
        auth_events: List of auth event dictionaries
        security_events: List of security event dictionaries
    
    Returns:
        Dictionary mapping user_id -> {"auth_events": [...], "security_events": [...]}
    
    Example:
        {
            "user123": {
                "auth_events": [{...}, {...}],
                "security_events": [{...}, {...}, {...}]
            },
            "user456": {
                "auth_events": [{...}],
                "security_events": [{...}]
            }
        }
    """
    # TODO: Implement correlation logic
    pass
```

### 4. **Detection Functions**

```python
def detect_brute_force(user_id, user_events, time_window_minutes=5, failure_threshold=5):
    """
    Detect brute force attacks: 5+ failed logins within time window + success within same window.
    
    Only detects COMPLETED attacks where the attacker succeeded within the time window.
    Does NOT detect failed attempts where success occurred outside the window.
    
    See "Detection Criteria - Brute Force Attack Detection" section above for examples.
    
    Args:
        user_id: User to check
        user_events: Dictionary of correlated events (from correlate_events)
        time_window_minutes: Time window for failures AND success (default 5)
        failure_threshold: Number of failures to trigger detection (default 5)
    
    Returns:
        dict or None: Attack details if detected, None otherwise
        
        **DEFENSIVE PROGRAMMING - CRITICAL:**
        If user_id doesn't exist in user_events OR user has no auth_events:
        → Return {"user_id": user_id} (NOT None!)
        
        This empty dict signals "no attack detected" without crashing.
        
        Example:
        ```python
        if user_id not in user_events:
            return {"user_id": user_id}  # ✅ Safe empty response
        
        if "auth_events" not in user_events[user_id]:
            return {"user_id": user_id}  # ✅ Safe empty response
        ```
        
        This function returns one of three options:
        1. None - if no brute force detected
        2. Single attack dict - if ONE brute force detected (see structure below)
        3. Multiple attacks dict - if TWO OR MORE brute force detected (see structure below)
        
        Attack details structure (SINGLE attack):
        {
            "user_id": "user123",
            "failure_count": 7,
            "failure_chain": [
                {"timestamp": "...", "status": "failure", "ip_address": "...", ...},
                {"timestamp": "...", "status": "failure", "ip_address": "...", ...}
            ],
            "success_event": {"timestamp": "...", "status": "success", ...},
                # ^ This must be the EXACT successful login event within the time window.
                #   It proves the brute force attack succeeded.
                #   If success is OUTSIDE the window, don't detect at all (return None).
            "attack_duration_seconds": 245.5
        }
        
        Attack details structure (MULTIPLE attacks detected):
        {
            "user_id": "user123",
            "attacks": [
                {
                    "failure_count": 5,
                    "failure_chain": [...],  # First attack failures
                    "success_event": {...},  # Success within window
                    "attack_duration_seconds": 300
                },
                {
                    "failure_count": 8,
                    "failure_chain": [...],  # Second attack failures
                    "success_event": {...},  # Success within window
                    "attack_duration_seconds": 240
                }
            ],
            "total_attacks": 2
        }
        
        NOTE: Only attacks where success occurs WITHIN the 5-minute window are detected.
        If 5+ failures occur but success is outside the window, return None for that sequence.
        If multiple separate attacks are detected (each with success in window), return ALL 
        in the "attacks" array.
        
    Example (SINGLE attack):
        attack = detect_brute_force("user123", user_events)
        if attack:
            print(f"🚨 Brute force detected: {attack['failure_count']} failures")
            print(f"   Success at: {attack['success_event']['timestamp']}")
            for event in attack['failure_chain']:
                print(f"   Failed: {event['timestamp']} from {event['ip_address']}")
    
    Example (MULTIPLE attacks):
        attack = detect_brute_force("user456", user_events)
        if attack and "attacks" in attack:
            print(f"🚨 Multiple brute force attacks: {attack['total_attacks']} detected")
            for i, single_attack in enumerate(attack['attacks'], 1):
                print(f"  Attack {i}: {single_attack['failure_count']} failures")
                print(f"    Success: {single_attack['success_event']['timestamp']}")
                print(f"    Duration: {single_attack['attack_duration_seconds']}s")
    """
    # TODO: Implement
    # - Get user's auth events: auth_events = user_events[user_id]["auth_events"]
    # - Loop through auth_events, check status field ("failure" or "success")
    # - Build failure_chain list with full event details
    # - Count failures within time window (first failure to last failure <= 5 minutes)
    # - When 5+ failures found within window:
    #   * Check if there's a SUCCESS within the SAME 5-minute window
    #   * If YES and within window: Create attack dict with that success_event
    #   * If NO or outside window: Skip this sequence (return None for it)
    #   Example: First failure at 10:00:00, last failure at 10:04:00
    #            Window is 10:00:00 to 10:05:00
    #            Success at 10:04:30 → DETECT (within window)
    #            Success at 10:07:00 → DON'T DETECT (outside window)
    # - Keep scanning for MORE brute force attacks (user might be attacked multiple times)
    # - If ONE attack found (with success in window), return single attack structure
    # - If MULTIPLE attacks found (each with success in window), return "attacks" array
    # - If no complete attacks found, return None
    pass

def detect_privilege_escalation(user_id, user_events, time_window_minutes=10):
    """
    Detect suspicious privilege escalation:
    Successful login followed by privilege_change within 10 minutes.
    
    See "Detection Criteria - Privilege Escalation Detection" section above for:
    - Complete specification
    - Real-world breach pattern example
    - What counts as "privilege_change"
    
    Args:
        user_id: User to check
        user_events: Dictionary of correlated events
        time_window_minutes: Time window (default 10)
    
    Returns:
        dict or None: Attack details if detected, None otherwise
        
        **DEFENSIVE PROGRAMMING - CRITICAL:**
        If user_id doesn't exist, has no auth_events, OR has no security_events:
        → Return full empty structure (NOT None!)
        
        ```python
        if user_id not in user_events:
            return {
                "user_id": user_id,
                "login_sessions": [],
                "total_login_sessions": 0,
                "total_escalations": 0
            }
        
        if "auth_events" not in user_events[user_id]:
            return {
                "user_id": user_id,
                "login_sessions": [],
                "total_login_sessions": 0,
                "total_escalations": 0
            }
        
        if "security_events" not in user_events[user_id]:
            return {
                "user_id": user_id,
                "login_sessions": [],
                "total_login_sessions": 0,
                "total_escalations": 0
            }
        ```
        
        This ensures grader can safely check fields without crashes.
        
        Always returns grouped structure by login sessions (even for single escalation).
        
        Attack details structure (ALWAYS uses login_sessions):
        {
            "user_id": "user456",
            "login_sessions": [
                {
                    "login_event": {        # Full auth event from auth.log
                        "timestamp": "2024-01-15T10:00:00Z",
                        "user_id": "user456",
                        "action": "login",
                        "ip_address": "192.168.1.100",
                        "status": "success",
                        "session_id": "sess_123"
                    },
                    "privilege_escalations": [
                        {
                            "privilege_event": {    # Full security event from security.log
                                "timestamp": "2024-01-15T10:02:00Z",
                                "user_id": "user456",
                                "event_type": "privilege_change",
                                "resource": "sudo_access",  # or "admin_role", "root_access", etc.
                                "session_id": "sess_123",
                                "ip_address": "192.168.1.100",
                                # ... any other fields from security.log
                            },
                            "time_to_escalation_seconds": 90.5
                        }
                        # ... more escalations after this login
                    ],
                    "escalation_count": 1  # Number of escalations after this login
                }
                # ... more login sessions
            ],
            "total_login_sessions": 1,      # Total logins with escalations
            "total_escalations": 1          # Total escalations across all logins
        }
        
        Example scenarios:
        - Single login, single escalation:
          total_login_sessions=1, total_escalations=1, escalation_count=1
        
        - Single login, multiple escalations:
          total_login_sessions=1, total_escalations=3, escalation_count=3
        
        - Multiple logins, one escalation each:
          total_login_sessions=2, total_escalations=2, escalation_count=1 (per session)
        
        - Multiple logins, multiple escalations:
          total_login_sessions=2, total_escalations=5, escalation_count varies
        
        NOTE: Multiple privilege escalations can occur after the SAME login (e.g., escalate
        to sudo, then root, then admin in sequence). They are grouped by login_event.
        
    Example (always use login_sessions structure):
        attack = detect_privilege_escalation("admin", user_events)
        if attack:
            print(f"🚨 Detected {attack['total_login_sessions']} login session(s) with escalations")
            print(f"   Total escalations: {attack['total_escalations']}")
            
            for i, session in enumerate(attack['login_sessions'], 1):
                print(f"\n  Session {i} - Login: {session['login_event']['timestamp']}")
                print(f"  Escalations in this session: {session['escalation_count']}")
                
                for j, esc in enumerate(session['privilege_escalations'], 1):
                    print(f"    {j}. {esc['privilege_event']['resource']} "
                          f"({esc['time_to_escalation_seconds']}s after login)")
    """
    # TODO: Implement
    # Step 1: Get auth events: auth_events = user_events[user_id]["auth_events"]
    # Step 2: Find all successful logins (status == "success"), store with timestamps
    # Step 3: Get security events: security_events = user_events[user_id]["security_events"]
    # Step 4: Look for event_type == "privilege_change" events
    # Step 5: For EACH login, find ALL privilege_change events within 10 minutes
    # Step 6: GROUP escalations by their associated login (same login can have multiple escalations)
    # Step 7: Verify resource field contains "sudo_access", "admin_role", "root_access", etc.
    # Step 8: ALWAYS return "login_sessions" structure (even for single login/escalation)
    # Step 9: CRITICAL - Only include login sessions that HAVE escalations (escalation_count > 0)
    #         Do NOT include sessions with zero escalations in login_sessions array
    # Step 10: If no escalations found, return None
    pass

def detect_anomalous_access(user_id, user_events):
    """
    Detect anomalous file access patterns.
    
    See "Detection Criteria - Anomalous File Access Detection" section above for:
    - Complete list of sensitive files to detect
    - Examples of what to flag vs. ignore
    - Implementation tips
    
    Args:
        user_id: User to check
        user_events: Dictionary of correlated events
    
    Returns:
        dict or None: Attack details if detected, None otherwise
        
        **DEFENSIVE PROGRAMMING - CRITICAL:**
        If user_id doesn't exist OR has no security_events:
        → Return None (different from other detect functions!)
        
        ```python
        if user_id not in user_events:
            return None  # ✅ User doesn't exist
        
        if "security_events" not in user_events[user_id]:
            return None  # ✅ User has no security events
        ```
        
        NOTE: This function returns None for missing data (unlike the other 
        two detect functions which return empty dicts). This is intentional -
        anomalous access detection requires security_events to work.
        
        Attack details structure:
        {
            "user_id": "user789",
            "sensitive_files_accessed": [
                {
                    "file": "/etc/shadow",
                    "timestamp": "...",
                    "event": {...}  # Full security event
                },
                {
                    "file": "/root/.ssh/authorized_keys",
                    "timestamp": "...",
                    "event": {...}
                }
            ],
            "access_count": 2
        }
        
    Example:
        attack = detect_anomalous_access("user789", user_events)
        if attack:
            print(f"🚨 Anomalous access: {attack['access_count']} sensitive files")
            for access in attack['sensitive_files_accessed']:
                print(f"  {access['file']} at {access['timestamp']}")
    
    Flag as anomalous if security_events contain file_access to ANY of:
        - /etc/passwd, /etc/shadow, /etc/sudoers, /etc/group
        - /root/.ssh/authorized_keys, /home/*/.ssh/authorized_keys, /home/*/.ssh/id_rsa
        - /etc/crontab, /var/spool/cron/*
        - /var/log/auth.log, /var/log/secure, /var/log/audit/audit.log
    
    Do NOT flag normal files like:
        - /home/username/documents/* (user's own files)
        - /tmp/* (temporary files)
        - /usr/share/* (shared system files)
    """
    # TODO: Implement
    # Step 1: Get security events: security_events = user_events[user_id]["security_events"]
    # Step 2: Loop through security_events
    # Step 3: Check if event["event_type"] == "file_access"
    # Step 4: Get the file path: resource = event["resource"]
    # Step 5: Check if resource contains any sensitive file path
    # Step 6: Build list of sensitive_files_accessed with full event details
    # Step 7: If found, return dict with all access details
    # Step 8: If not found, return None
    pass
```

### 5. **Utility Functions**

```python
def get_user_timeline(user_id, user_events):
    """
    Get chronological timeline of all events for a user.
    
    Args:
        user_id: User to get timeline for
        user_events: Dictionary of correlated events
    
    Returns:
        List of tuples: [(timestamp, event_description), ...]
        Sorted chronologically
    """
    # TODO: Implement
    # - Retrieve all events for user
    # - Merge auth and security events
    # - Sort by timestamp
    pass

def generate_incident_report(user_id, user_events):
    """
    Generate security incident report for a user.
    
    Args:
        user_id: User to generate report for
        user_events: Dictionary of correlated events
    
    Returns:
        Dictionary with incident details, or None if user not found
        {
            "user_id": "user123",
            "auth_events": [...],
            "security_events": [...],
            "incident_flags": ["brute_force", "anomalous_access"]
        }
    """
    # TODO: Implement
    # - Check if user exists in dictionary
    # - Run all detection functions
    # - Compile incident flags
    pass
```

### 6. **Main Function**

```python
def main():
    """Main entry point - test your implementation"""
    # Parse logs
    auth_events = parse_auth_log("auth.log")
    security_events = parse_security_log("security.log")
    
    # Correlate
    user_events = correlate_events(auth_events, security_events)
    
    # Analyze specific user
    report = generate_incident_report("user123", user_events)
    if report:
        print(f"User: {report['user_id']}")
        print(f"Incidents: {report['incident_flags']}")

if __name__ == "__main__":
    main()
```

## Key Python Concepts Used

**No OOP required!** This exercise uses:

1. **Dictionaries** - Main data structure (hashmap)
2. **Lists** - Store multiple events per user
3. **Functions** - All logic in standalone functions
4. **CSV module** - Parse auth.log
5. **JSON module** - Parse security.log
6. **datetime module** - Handle timestamps
7. **collections.defaultdict** - Efficient dictionary of lists (Effective Python Item 18, p. 67-70)

These are all covered in **Python Workout Chapters 1-5** and **Effective Python** foundational items.

## The Challenge: Your Turn

Now it's your turn to implement this system. Here's what you need to do:

### Implementation Requirements

1. **Implement all methods** with proper error handling
2. **Test against 65 provided test cases** covering these categories:
   - Parsing Tests (15 tests)
   - Correlation Tests (15 tests)
   - Brute Force Detection (15 tests)
   - Privilege Escalation Detection (10 tests)
   - Security Analysis Tests (10 tests)
3. **Ensure efficient lookup time** for user queries
4. **Follow secure coding principles** from the references below

**CRITICAL: Use Production-Realistic Test Data**

Don't test with 3-5 log entries! Real SOC analysts process thousands of events daily. Your test files should contain:
- **Small tests**: 50-200 entries (quick validation)
- **Medium tests**: 200-1,000 entries (realistic workload) 
- **Large tests**: 10,000+ entries (stress testing)
- **Signal-to-noise**: 5-20% attack traffic hidden in 80-95% legitimate activity

**Why this matters:** In production, attacks are buried in normal traffic. Testing with 100% attack data doesn't prove your detection logic works in the real world. A proper test might have:
- 10 attackers attempting brute force (60 total failed logins)
- 190 normal users logging in successfully (190 logins + 300+ file access events)
- **Total: 550+ log entries where only 11% are attack-related**

This mirrors what security engineers see daily in production environments.

### Test Categories Breakdown

**Category 1: Parsing Tests (15 tests)**
- Valid CSV auth log
- Malformed CSV (missing fields, extra commas)
- Invalid timestamps
- Invalid IP addresses
- Empty files
- Large files (10k+ entries)
- Unicode characters in user_ids
- Valid JSON security log
- Malformed JSON (missing braces, invalid syntax)
- Mixed valid/invalid entries

**Category 2: Correlation Tests (15 tests)**
- Single user, multiple events
- Multiple users, single event each
- No matching user_ids
- Duplicate session_ids
- Events with same timestamp
- Empty auth log, populated security log
- Populated auth log, empty security log
- Efficient lookup verification (timing test)

**Category 3: Brute Force Detection (15 tests)**
- Exactly 5 failures then success within window
- 4 failures (below threshold)
- 6 failures spread over 10 minutes (outside window)
- 5 failures, no success
- Success without failures
- Failures from multiple IPs
- Failures then success from different IPs
- Time window edge cases

**Category 4: Privilege Escalation Detection (10 tests)**
- Failed login IP1, success + admin access IP2
- Same IP for all events (not suspicious)
- Time window violations
- No admin access events
- Multiple escalation attempts

**Category 5: Security Analysis Tests (10 tests)**
- Access to /etc/passwd
- Access to /etc/shadow
- Normal file access
- Mixed suspicious/normal activity
- Correlate session_ids across logs

**Category 6: Edge Cases (5+ tests)**
- Null/None user_ids
- Empty strings
- SQL injection attempts in user_ids
- Path traversal in resource names
- XSS attempts in log fields

## Security Considerations

Your implementation must address these security concerns from **Secure by Design** (Chapter 7):

1. **Validate all input** (p. 159-162): Reject malformed log entries gracefully
2. **Use domain primitives** (p. 153-156): EventType enum instead of raw strings
3. **Make illegal states unrepresentable** (p. 165-168): Use dataclasses with type hints
4. **Fail securely** (p. 170-173): Don't expose system details in error messages
5. **Sanitize log data**: Prevent log injection attacks per **Hacking APIs** (Chapter 8, p. 189-195)

## Realistic Test Data Volumes

The test data you'll work with contains **production-realistic volumes**:

| Test Category | Entries per Test | Real-World Equivalent |
|---------------|------------------|----------------------|
| **Parsing Tests** | 50-200 entries | Hourly logs from small web server |
| **Correlation Tests** | 200-1,000 entries | Daily logs from department (50-100 users) |
| **Brute Force Tests** | 100-500 entries | Attack buried in normal traffic |
| **Privilege Escalation** | 150-300 entries | SOC investigation scope |
| **Large File Tests** | 10,000-25,000 entries | Enterprise daily logs (500-1,000 users) |

### Example: Brute Force Test (Realistic)

```
test_031_brute_force/
├── auth.log: 250 entries
│   ├── 10 attackers: 5 failures each → success (60 entries)
│   └── 190 normal users: legitimate logins (190 entries)
└── security.log: 200 entries
    ├── Attackers: file access to /etc/shadow (30 entries)
    └── Normal users: regular file access (170 entries)

Attack signal: 90 / 450 total = 20% (realistic!)
```

**Compare this to unrealistic test data:**
```
BAD Example:
├── auth.log: 7 entries (all attack traffic)
└── security.log: 1 entry

Attack signal: 8 / 8 total = 100% (unrealistic!)
```

In production, **attacks are always hidden in legitimate traffic**. If your detection works on 100% attack data but fails on 20% attack data, it won't work in production.

### Real-World Context

When a SOC analyst investigates a brute force alert:
1. **SIEM query returns**: 10,000 auth events from the last hour
2. **Analyst needs to find**: The 50 failed login attempts that matter
3. **Your correlator helps**: "User 'admin' had 8 failures from IP 203.0.113.42, then success from 203.0.113.42 at 14:23:15"
4. **Incident confirmed**: Attacker succeeded, investigate session activity

Your test data simulates this workflow. You're not just parsing logs - you're **finding needles in haystacks**.

## Why This Matters for Security Engineering Roles

This exercise builds skills directly applicable to Security Engineering positions:

1. **Log Analysis**: Core competency for SOC operations and incident response. You're learning what analysts at CrowdStrike, Palo Alto Networks, and Mandiant do daily.

2. **Efficient Data Structures**: Critical for analyzing high-volume log streams. Production SIEM systems process millions of events per day - efficient lookup optimization mirrors real performance requirements.

3. **Attack Pattern Recognition**: Understanding common attack vectors (brute force, privilege escalation, lateral movement) is fundamental. These patterns are documented in [MITRE ATT&CK](https://attack.mitre.org/) and are tested in SOC interviews.

4. **Secure Coding**: Implementing security tools that don't introduce vulnerabilities. Your correlator must safely parse untrusted log data without crashes or injection vulnerabilities.

5. **Python Proficiency**: Primary language for security tooling. This exercise covers file I/O, data structures, datetime handling, and CSV/JSON parsing - all commonly tested in interviews.

### Real Interview Scenarios

**Common technical interview questions:**

- Security Consulting: "Build a tool to detect privilege escalation in these Linux audit logs" → *This is your test_046*
- Payments Security: "How would you detect credential stuffing attacks in our authentication logs?" → *This is your test_043*  
- Crypto Security: "Parse these API logs and identify suspicious access patterns" → *This is your correlation tests*

**Log correlation challenges are common in Security Engineering technical interviews.**

### Production Impact

The techniques you're learning have direct production applications:

**Detecting Privilege Escalation Attacks (Test 046 Pattern):**
```python
# Your code detects this pattern
correlator.detect_privilege_escalation("contractor_account")
# Returns: True

# Why? Failed login from Dallas, Texas (192.168.1.50)
#       Success from Poland (45.134.142.X) 8 minutes later
#       Immediate sudo access to privileged systems
# This matches documented real-world breach patterns
```

**Detecting Password Spray Attacks (Test 031 Pattern):**
```python
# Your code detects this pattern  
correlator.detect_brute_force("admin_account")
# Returns: True

# Why? 47 failures from 203.0.113.X within 3 minutes
#       Success on attempt 48
#       Immediate access to sensitive data
# This mirrors real-world password spray attacks
```

**These aren't academic exercises - they're real security scenarios.**

## References

This exercise draws from multiple authoritative sources:

1. **Python Workout, Second Edition** (Reuven M. Lerner):
   - Chapter 5 "Files" - Parsing and processing log files (p. 117-124)
   - Exercise 23 "Reverse Lines" - File processing patterns (p. 117-120)
   - Exercise 24 "Longest Word" - Working with file data (p. 121-124)

2. **Effective Python, Third Edition** (Brett Slatkin):
   - Item 14: "Sort by Complex Criteria Using the key Parameter" (p. 54-57) - For chronological timeline sorting
   - Item 18: "Know How to Construct Key-Dependent Default Values with __missing__" (p. 67-70) - **Useful for efficient dictionary operations**
   - Item 20: "Prefer Raising Exceptions to Returning None" (p. 74-76) - Error handling patterns

3. **Full Stack Python Security** (Dennis Byrne):
   - Chapter 8 "Logging and Monitoring" (p. 187-210) - Log analysis techniques for attack detection

4. **Secure by Design** (Johnsson, Deogun, Sawano):
   - Chapter 7 "Validation" (p. 153-178) - Input validation at system boundaries

5. **Hacking APIs** (Corey J. Ball):
   - Chapter 8 on log security (p. 189-195) - Preventing log injection attacks

6. **Team Blind Security Engineering Interview Guide**:
   - [85 Security Engineer On-Sites Study Guide](https://www.teamblind.com/post/i-did-85-security-engineer-on-sites-with-top-tech-companiesa-prep-guide-lyanpve6)

**Key Technical Focus**: This exercise emphasizes efficient data structure choices and file processing patterns - core skills for production security engineering.

## Testing Your Solution with the Grader

The exercise includes an automated grader that tests your implementation against **101 realistic test cases** covering parsing, correlation, attack detection, and edge cases.

### Setup

The grader expects this directory structure:
```
your_project/
├── grader.py                    # The grader script
├── log_correlator.py            # Your solution
└── test_data_complete/          # Test data (directory or .zip)
    ├── 01_parsing/
    ├── 02_correlation/
    ├── 03_brute_force/
    ├── 04_privilege_escalation/
    ├── 05_security_analysis/
    └── 06_edge_cases/
```

### Basic Usage

**Run all tests:**
```bash
python3 grader.py log_correlator.py
```

**Run with verbose output:**
```bash
python3 grader.py log_correlator.py --verbose
```

**Run a specific test:**
```bash
python3 grader.py log_correlator.py --test 031
# Tests brute force detection with exactly 5 failures
```

**Run all tests in a category:**
```bash
python3 grader.py log_correlator.py --category brute_force
# Runs tests 031-045 (all brute force scenarios)
```

**Use custom test data location:**
```bash
# With directory
python3 grader.py log_correlator.py --test-data /path/to/test_data_complete/

# With zip file
python3 grader.py log_correlator.py --test-data test_data_complete.zip
```

### Test Categories

The 101 test cases are organized into 6 categories:

| Category | Tests | Description |
|----------|-------|-------------|
| **parsing** | 001-015 | CSV/JSON parsing, malformed data handling |
| **correlation** | 016-030 | Event correlation by user_id |
| **brute_force** | 031-045 | Attack detection (5+ failures + success) |
| **privilege_escalation** | 046-055 | Rapid escalation after login |
| **security_analysis** | 056-065 | Sensitive file access detection |
| **edge_cases** | 066-101 | Empty logs, single events, large datasets |

### Example Output

```
================================================================================
SECURITY LOG CORRELATOR GRADER
================================================================================
Solution: log_correlator.py
Test Data: test_data_complete/

Running 101 tests...

✓ Test 001 (parsing): PASS (0.02s)
✓ Test 002 (parsing): PASS (0.01s)
...
✓ Test 031 (brute_force): PASS (0.15s) - Exactly 5 failures then success
✓ Test 032 (brute_force): PASS (0.12s) - Below threshold (4 failures)
...
✗ Test 045 (brute_force): FAIL (0.18s) - Should NOT detect but did (false positive)
...

================================================================================
SUMMARY
================================================================================
✅ Passed:     98 (97.0%)
❌ Failed:     2 (2.0%)
💥 Errors:     1 (1.0%)
⏱️  Total Time: 15.42s
================================================================================

📁 BY CATEGORY:
  parsing             : 15/15 passed
  correlation         : 15/15 passed
  brute_force         : 14/15 passed
  privilege_escalation: 10/10 passed
  security_analysis   : 10/10 passed
  edge_cases          : 34/36 passed

❌ FAILED/ERROR TESTS (3):
  Test 045 (brute_force): Should NOT detect but did (false positive)
  Test 073 (edge_cases): parse_auth_log failed: list index out of range
  Test 089 (edge_cases): Timeout after 30 seconds
================================================================================
👍 GOOD! 97.0% tests passed
```

### Required Function Signatures

Your `log_correlator.py` must implement:

```python
def parse_auth_log(filepath, user_events):
    """Parse CSV auth log and populate user_events in-place"""
    # user_events[user_id]["auth_events"] = [...]
    pass

def parse_security_log(filepath, user_events):
    """Parse JSON security log and populate user_events in-place"""
    # user_events[user_id]["security_events"] = [...]
    pass

def detect_brute_force(user_id, user_events, time_window_minutes=5, failure_threshold=5):
    """Detect brute force attacks"""
    # Returns dict or None
    pass

def detect_privilege_escalation(user_id, user_events, time_window_minutes=10):
    """Detect rapid privilege escalation"""
    # Returns dict or None
    pass

def detect_anomalous_access(user_id, user_events):
    """Detect sensitive file access"""
    # Returns dict or None
    pass
```

### Tips for Passing Tests

1. **Start with parsing tests (001-015)** - Get CSV/JSON parsing solid first
2. **Handle edge cases early** - Empty files, missing fields, malformed data
3. **Test correlation (016-030)** - Verify user_events structure is correct
4. **Brute force is tricky (031-045)** - Success must be within SAME 5-minute window as failures
5. **Privilege escalation (046-055)** - Use grouped `login_sessions` structure
6. **False positives matter** - Tests verify you DON'T detect normal activity

### Debugging Failed Tests

**Run a specific failing test with verbose output:**
```bash
python3 grader.py log_correlator.py --test 045 --verbose
```

**Check the test data manually:**
```bash
cat test_data_complete/03_brute_force/test_045_brute_force/auth.log
cat test_data_complete/03_brute_force/test_045_brute_force/security.log
```

**Add debug prints to your solution:**
```python
def detect_brute_force(user_id, user_events, ...):
    print(f"DEBUG: Checking {user_id}")
    auth_events = user_events[user_id]["auth_events"]
    print(f"DEBUG: Found {len(auth_events)} auth events")
    # ... your logic
```

### Performance Expectations

The grader includes stress tests with large datasets:
- **Test 066-080**: 1,000-5,000 events per file
- **Test 081-095**: 10,000-15,000 events per file  
- **Test 096-101**: 20,000-25,000 events per file (enterprise scale)

Your solution should handle these within reasonable time:
- Small tests (001-065): < 1 second each
- Medium tests (066-080): 1-5 seconds each
- Large tests (081-101): 5-30 seconds each

**Timeout**: Tests automatically fail after 30 seconds.

## Next Steps

1. **Implement the solution**: Start with parsing functions, then build up to correlation and detection
2. **Write comprehensive tests**: Don't skip edge cases - they're where security bugs hide
3. **Benchmark performance**: Verify your implementation with timing tests on large datasets
4. **Handle adversarial inputs**: Logs can be manipulated by attackers

**Get the realistic test data**: The complete test suite with 53,556 log entries simulating production scenarios is available for this exercise. It includes everything from basic parsing tests (50-200 entries) to enterprise stress tests (25,000 entries).

## Conclusion

Building a log correlator is more than just a coding exercise - it's foundational Security Engineering work. You're learning to:

- Process untrusted input securely (just like production SIEM systems)
- Build efficient data structures for real-time analysis (fast lookups at scale)
- Detect attack patterns that matter (based on real breaches and MITRE ATT&CK)
- Write production-quality security tools (tested with realistic data volumes)

### The Realistic Data Advantage

By testing with **production-realistic log volumes** (50-25,000 entries per test), you're not just building a toy project - you're developing skills that transfer directly to:

- **SOC Analyst work**: Investigating alerts in SIEM systems with thousands of events
- **Incident Response**: Correlating authentication failures with post-compromise activity
- **Security Engineering**: Building detection rules that work with real signal-to-noise ratios
- **Technical interviews**: Demonstrating you understand production security operations

### Interview Confidence

When asked in interviews:

**"Have you worked with security logs?"**

**Weak answer:** "I built a parser for some test files."

**Strong answer:** "I built a security log correlator that processes authentication logs and security events - similar to SOC workflows in SIEM systems. It detects brute force attacks and privilege escalation by correlating failed logins with suspicious post-compromise activity. I tested it with 50,000+ entries simulating realistic attack scenarios - including distributed brute force from botnets (test_043) and lateral movement patterns (test_046) based on published breach reports."

**The difference?** You tested with **real-world volumes and patterns**, not toy examples.

This is exactly the type of practical security engineering that security teams look for in candidates.

**What challenges did you face implementing this? What attack patterns would you add? Share your solutions and insights in the comments below!**

---

*This post is part of a series on practical Security Engineering skills. The test data includes 50,000+ log entries simulating real production scenarios - because security engineering isn't learned from toy examples.* 

**Follow me for more hands-on security challenges and real-world interview preparation!**

**Tags:** #security #python #cybersecurity #infosec #devsecops #coding #tutorial #interview #soc #siem

---

## 📚 Reference Materials

### GitHub Repository

All materials for this exercise are available on GitHub:

**Repository:** [SecEng-Exercises/cyberscripts/log_correlator](https://github.com/fosres/SecEng-Exercises/tree/main/cyberscripts/log_correlator)

### Reference Solution

**File:** [log_correlator.py](https://github.com/fosres/SecEng-Exercises/blob/main/cyberscripts/log_correlator/log_correlator.py)

The reference solution demonstrates:
- Defensive programming patterns for all detect functions
- Efficient event correlation using dictionaries
- Proper handling of edge cases and missing data
- Clean, readable code structure following Python best practices

### Grader Script

**File:** [grader.py](https://github.com/fosres/SecEng-Exercises/blob/main/cyberscripts/log_correlator/grader.py)

The grader includes:
- 65 comprehensive test cases across 5 categories
- Realistic test data with 50-25,000 log entries per test
- Clear pass/fail feedback with detailed error messages
- Production-scale testing scenarios

### Test Data

**Directory:** [test_data_complete/](https://github.com/fosres/SecEng-Exercises/tree/main/cyberscripts/log_correlator/test_data_complete)

The test data directory contains:
- 65 complete test scenarios with auth.log and security.log files
- Production-realistic log volumes (50-25,000 entries per test)
- Attack patterns based on documented real-world breaches
- Signal-to-noise ratios matching real SOC environments (5-20% attacks in normal traffic)
- Organized by category: parsing, correlation, brute_force, privilege_escalation, security_analysis

### How to Use

1. **Clone the repository:**
   ```bash
   git clone https://github.com/fosres/SecEng-Exercises.git
   cd SecEng-Exercises/cyberscripts/log_correlator
   ```

2. **Run the grader on your solution:**
   ```bash
   python3 grader.py your_solution.py
   ```

3. **Study the reference solution** after attempting the exercise yourself

### Contributing

Found a bug or want to suggest improvements? Open an issue or pull request on GitHub!

---
