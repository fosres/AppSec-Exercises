# VPN Authentication Log Test Files

This directory contains **100 realistic VPN authentication log files** for testing your VPN Log Analyzer solution.

## 📁 File Structure

```
test_logs/
├── vpn_auth_001.log through vpn_auth_020.log  (Normal Activity)
├── vpn_auth_021.log through vpn_auth_040.log  (Brute Force Attacks)
├── vpn_auth_041.log through vpn_auth_060.log  (Session Hijacking)
├── vpn_auth_061.log through vpn_auth_080.log  (Credential Stuffing)
├── vpn_auth_081.log through vpn_auth_095.log  (Mixed Attacks)
└── vpn_auth_096.log through vpn_auth_100.log  (Edge Cases)
```

## 📊 Test Categories

### Category 1: Normal Activity (Files 001-020)
**Characteristics:**
- 20-50 log entries per file
- 80% success rate (realistic for normal operations)
- Single IP per user (no suspicious patterns)
- Mix of legitimate usernames (alice, bob, charlie, etc.)
- Time intervals: 30 seconds to 5 minutes between logins

**Expected Detection:**
- ✅ Brute Force: 0
- ✅ Session Hijacking: 0
- ✅ Credential Stuffing: 0

**Example (vpn_auth_001.log):**
```
2026-01-02 08:00:00 | user:diana | IP:192.168.6.65 | status:success
2026-01-02 08:04:04 | user:bob | IP:192.168.6.95 | status:success
2026-01-02 08:06:17 | user:grace | IP:192.168.6.65 | status:success
```

---

### Category 2: Brute Force Attacks (Files 021-040)
**Characteristics:**
- 5-15 failed login attempts targeting **single username**
- Attacker IP: One of `10.0.0.5`, `203.0.113.42`, `198.51.100.88`, `192.0.2.123`
- Attack embedded in normal traffic (noise + signal)
- Time intervals: 30 seconds to 2 minutes between attempts
- Common targets: admin, root, bob, charlie

**Expected Detection:**
- ✅ Brute Force: 1-2 users detected
- ❓ Session Hijacking: Possibly 0 (depends on normal activity)
- ❓ Credential Stuffing: Possibly 0 (single user targeted)

**Example (vpn_auth_025.log):**
```
2026-01-02 14:14:20 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:16:18 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:18:00 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:19:12 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:20:52 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:21:50 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 14:22:38 | user:admin | IP:10.0.0.5 | status:failed
```

---

### Category 3: Session Hijacking (Files 041-060)
**Characteristics:**
- **Same user** logging in from **3-7 different IP addresses**
- All login attempts successful
- Mix of internal (192.168.x.x) and external IPs
- Simulates stolen credentials used from multiple locations
- Targeted users: alice, diana, frank

**Expected Detection:**
- ❓ Brute Force: Possibly 0 (all logins successful)
- ✅ Session Hijacking: 1 user detected
- ❓ Credential Stuffing: Possibly 0 (single user, not multiple)

**Example (vpn_auth_045.log):**
```
2026-01-02 10:03:06 | user:alice | IP:141.47.43.179 | status:success
2026-01-02 10:09:30 | user:alice | IP:141.47.43.179 | status:success
2026-01-02 10:15:10 | user:alice | IP:10.148.128.22 | status:success   ← Different IP!
2026-01-02 10:31:05 | user:alice | IP:192.168.3.120 | status:success   ← Another IP!
2026-01-02 10:35:01 | user:alice | IP:209.125.98.47 | status:success   ← Yet another!
```

---

### Category 4: Credential Stuffing (Files 061-080)
**Characteristics:**
- **Single IP** attempting to log in as **5-20 different users**
- All attempts failed
- Simulates attacker with leaked credential database
- Fast attempts: 10 seconds to 1 minute between tries
- Targets: Wide variety of usernames (admin, root, test, user, developer, etc.)

**Expected Detection:**
- ❓ Brute Force: Possibly multiple (if same user tried ≥5 times)
- ❓ Session Hijacking: Possibly 0 (failures, not successes)
- ✅ Credential Stuffing: 1 IP detected

**Example (vpn_auth_065.log):**
```
2026-01-02 16:05:00 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 16:05:45 | user:root | IP:10.0.0.5 | status:failed
2026-01-02 16:06:30 | user:test | IP:10.0.0.5 | status:failed
2026-01-02 16:07:15 | user:user | IP:10.0.0.5 | status:failed
2026-01-02 16:08:00 | user:developer | IP:10.0.0.5 | status:failed
2026-01-02 16:08:45 | user:manager | IP:10.0.0.5 | status:failed
```

---

### Category 5: Mixed Attacks (Files 081-095)
**Characteristics:**
- **Multiple attack types in same log file**
- High complexity (noise + multiple signals)
- Realistic scenario: Multiple attackers targeting same VPN
- Includes: Brute force + Session hijacking + Credential stuffing

**Expected Detection:**
- ✅ Brute Force: 1+ users
- ✅ Session Hijacking: 1+ users
- ✅ Credential Stuffing: 1+ IPs

**Example (vpn_auth_085.log):**
```
# Brute force attack on 'admin'
2026-01-02 18:00:00 | user:admin | IP:10.0.0.5 | status:failed
2026-01-02 18:01:30 | user:admin | IP:10.0.0.5 | status:failed
... (5+ failures)

# Session hijacking for 'alice'
2026-01-02 18:10:00 | user:alice | IP:192.168.1.10 | status:success
2026-01-02 18:15:00 | user:alice | IP:203.0.113.42 | status:success
2026-01-02 18:20:00 | user:alice | IP:198.51.100.88 | status:success
... (3+ different IPs)

# Credential stuffing from single IP
2026-01-02 18:30:00 | user:test | IP:192.0.2.123 | status:failed
2026-01-02 18:30:45 | user:admin | IP:192.0.2.123 | status:failed
2026-01-02 18:31:30 | user:root | IP:192.0.2.123 | status:failed
... (5+ different users)
```

---

### Category 6: Edge Cases (Files 096-100)
**Special test scenarios for robust error handling**

#### vpn_auth_096.log - Empty File
- **File size:** 0 bytes
- **Test:** Handling empty input
- **Expected:** Graceful handling, no crashes

#### vpn_auth_097.log - Threshold Boundary (Exactly 5 Failures)
- **Exactly 5 failed logins** for same user
- **Test:** Brute force detection at exact threshold
- **Expected:** User should be flagged (≥5 failures)

#### vpn_auth_098.log - Threshold Boundary (Exactly 3 IPs)
- **Exactly 3 different IPs** for same user (all successful)
- **Test:** Session hijacking detection at exact threshold
- **Expected:** User should be flagged (≥3 IPs)

#### vpn_auth_099.log - Large File (1,000+ Entries)
- **1,000 log entries** with embedded attacks
- **Test:** Performance with large datasets
- **Expected:** Process in <1 second, detect all attacks
- **Contains:**
  - Brute force attack (entries 100-110)
  - Session hijacking (entries 200-206)
  - Credential stuffing (entries 500-508)

#### vpn_auth_100.log - Malformed Entries
- **Invalid log formats** mixed with valid entries
- **Test:** Error handling and resilience
- **Expected:** Skip malformed lines, process valid ones
- **Malformed examples:**
  ```
  MALFORMED ENTRY WITH NO DELIMITERS
  2026-01-02 22:10:00 | incomplete entry
  | | | |
  2026-01-02 22:12:00 | user:alice | IP:192.168.1.10 | status:UNKNOWN_STATUS
  ```

---

## 🧪 Testing Your Solution

### Run Tests on All Files

```bash
# Test all 100 files
for log in vpn_auth_*.log; do
	echo "Testing $log..."
	python3 vpn_analyzer.py "$log"
done
```

### Validate Expected Results

**Category 1 (Normal Activity):**
```bash
# Should detect NO attacks
for i in {001..020}; do
	python3 vpn_analyzer.py vpn_auth_${i}.log | grep '"threats_detected"'
done
```

**Category 2 (Brute Force):**
```bash
# Should detect brute_force attacks
for i in {021..040}; do
	python3 vpn_analyzer.py vpn_auth_${i}.log | grep '"brute_force"'
done
```

**Category 3 (Session Hijacking):**
```bash
# Should detect session_hijacking
for i in {041..060}; do
	python3 vpn_analyzer.py vpn_auth_${i}.log | grep '"session_hijacking"'
done
```

**Category 4 (Credential Stuffing):**
```bash
# Should detect credential_stuffing IPs
for i in {061..080}; do
	python3 vpn_analyzer.py vpn_auth_${i}.log | grep '"credential_stuffing"'
done
```

---

## ✅ Expected Detection Summary

| File Range | Brute Force | Session Hijacking | Credential Stuffing |
|------------|-------------|-------------------|---------------------|
| 001-020    | 0           | 0                 | 0                   |
| 021-040    | 1-2 users   | 0                 | 0                   |
| 041-060    | 0           | 1 user            | 0                   |
| 061-080    | 0-2 users   | 0                 | 1 IP                |
| 081-095    | 1+ users    | 1+ users          | 1+ IPs              |
| 096        | 0           | 0                 | 0                   |
| 097        | 1 user      | 0                 | 0                   |
| 098        | 0           | 1 user            | 0                   |
| 099        | 1 user      | 1 user            | 1 IP                |
| 100        | varies      | varies            | varies              |

---

## 🎯 Success Criteria

Your VPN Log Analyzer should:

✅ **Parse all 100 files without crashing**  
✅ **Detect 100% of brute force attacks (files 021-040, 097)**  
✅ **Detect 100% of session hijacking (files 041-060, 098)**  
✅ **Detect 100% of credential stuffing (files 061-080)**  
✅ **Handle edge cases gracefully (files 096-100)**  
✅ **Process large file (099) in <1 second**  
✅ **Skip malformed entries (100) without crashing**

---

## 📝 Log Format Specification

Each log entry follows this format:

```
YYYY-MM-DD HH:MM:SS | user:USERNAME | IP:IP_ADDRESS | status:STATUS
```

**Field Descriptions:**
- **Timestamp:** ISO 8601 date and time (e.g., `2026-01-02 14:23:15`)
- **Username:** Alphanumeric username (e.g., `alice`, `admin`, `test`)
- **IP Address:** IPv4 address (e.g., `192.168.1.10`, `10.0.0.5`)
- **Status:** Either `success` or `failed`

**Parsing Pattern:**
```python
parts = line.split(' | ')
timestamp = parts[0]
username = parts[1].split(':')[1]
ip = parts[2].split(':')[1]
status = parts[3].split(':')[1]
```

---

## 🔍 Attack Detection Thresholds

**Brute Force:**
- Condition: `≥5 failed login attempts` for **same username**
- Logic: `failed_attempts[user] >= 5`

**Session Hijacking:**
- Condition: `≥3 different IP addresses` for **same username** (successful logins)
- Logic: `len(user_ips[user]) >= 3`

**Credential Stuffing:**
- Condition: `≥5 different usernames` tried from **same IP** (failed attempts)
- Logic: `len(ip_users[ip]) >= 5`

---

## 🛠️ Troubleshooting

**Problem:** "File not found" error

**Solution:**
```bash
# Make sure you're in the correct directory
cd test_logs/
ls vpn_auth_001.log  # Verify file exists
```

**Problem:** "Permission denied"

**Solution:**
```bash
chmod +r vpn_auth_*.log  # Make files readable
```

**Problem:** "Invalid JSON output"

**Solution:**
```python
import json
# Use json.dumps() to ensure valid JSON
print(json.dumps(report, indent=2))
```

---

## 📚 Additional Resources

**Python File I/O:**
```python
# Basic file reading
with open('vpn_auth_001.log', 'r') as f:
	for line in f:
		line = line.strip()  # Remove \n
		# Process line
```

**Python Dictionaries (Week 3 Focus):**
```python
# Frequency counting with .get()
count = {}
count[key] = count.get(key, 0) + 1

# Dictionary iteration
for key, value in my_dict.items():
	print(f"{key}: {value}")
```

**Python Sets (Week 3 Focus):**
```python
# Automatic uniqueness
ips = set()
ips.add('192.168.1.10')
ips.add('192.168.1.10')  # Duplicate ignored
print(len(ips))  # Output: 1
```

---

**Generated:** January 1, 2026  
**Author:** Claude (for Tanveer Salim - fosres)  
**Exercise:** Week 3, Exercise 1 - VPN Authentication Log Analyzer  
**Curriculum:** 48-Week AppSec Engineering Journey
