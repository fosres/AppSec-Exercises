---
title: "🔐 Security Challenge: Build an Auth Log Failed Login Scraper in Python"
published: true
description: "A LeetCode-style Python challenge to parse Linux auth logs and detect brute force attacks. 105 test cases. No hand-holding."
tags: python, security, linux, challenge
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/security-log-analysis.png
canonical_url: https://github.com/fosres/appsec-exercises
---

## The Breach That Started With Ignored Logs

In December 2020, SolarWinds disclosed one of the most devastating supply chain attacks in history. But here's what most people don't know: **the attackers tested their access for months before deploying SUNBURST**. Failed login attempts. Unusual authentication patterns. All of it sitting in log files that nobody was parsing.

The Verizon 2023 Data Breach Investigations Report found that **74% of breaches involve the human element**—and a massive chunk of those start with credential attacks that leave obvious traces in auth logs.

If you're pursuing a Security Engineering role, you *will* be asked to parse logs. Not with fancy SIEM tools. With Python. From scratch.

This is that exercise.

> 🌟 **This challenge is part of [AppSec Exercises](https://github.com/fosres/appsec-exercises)** — a growing collection of LeetCode-style security challenges. Star the repo to get notified when new challenges drop.

---

## The Challenge

Write a function called `parse_auth_log` that reads a Linux authentication log file and returns a dictionary containing analysis of failed login attempts.

```python
def parse_auth_log(filepath: str) -> dict:
	"""
	Parse a Linux auth.log file and analyze failed login attempts.
	
	Args:
		filepath: Path to the auth.log file
	
	Returns:
		A dictionary with the following structure:
		{
			"total_failed": int,           # Total failed login attempts
			"unique_ips": list[str],       # Unique source IPs (sorted)
			"unique_users": list[str],     # Unique usernames attempted (sorted)
			"attempts_by_ip": dict,        # {ip: count} for each IP
			"attempts_by_user": dict,      # {username: count} for each user
			"top_offender_ips": list[str], # IPs with most failures (sorted, empty if none)
			"top_targeted_users": list[str], # Most targeted usernames (sorted, empty if none)
			"first_failure": str | None,   # Timestamp of first failure (None if no failures)
			"last_failure": str | None,    # Timestamp of last failure (None if no failures)
			"potential_brute_force": list[str], # IPs with 5+ failures (sorted)
		}
	
	Log Format (standard sshd failed authentication):
		"Mon DD HH:MM:SS hostname sshd[PID]: Failed password for [invalid user] USERNAME from IP port PORT ssh2"
		"Mon DD HH:MM:SS hostname sshd[PID]: Failed publickey for [invalid user] USERNAME from IP port PORT ssh2"
	
	Examples of lines to match:
		"Jan  5 14:22:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
		"Jan  5 14:22:02 server sshd[12346]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2"
		"Jan  5 14:22:03 server sshd[12347]: Failed publickey for root from 192.168.1.100 port 22 ssh2"
		"Jan  5 14:22:04 server sshd[12348]: Failed publickey for invalid user git from 10.0.0.1 port 22 ssh2"
	
	Lines to ignore:
		- Successful logins ("Accepted password", "Accepted publickey")
		- Connection closed/reset messages
		- Any line not containing "Failed password" or "Failed publickey"
	"""
	pass  # YOUR IMPLEMENTATION HERE
```

---

## Why This Matters

### Real Attack Patterns You'll Detect

**1. Credential Stuffing**
Attackers use leaked password databases to try username/password combos across multiple services. In 2019, a single credential stuffing campaign against a major financial institution generated **over 100 million failed login attempts in 48 hours**. All of it logged. Most of it ignored until the breach.

**2. SSH Brute Force**
Every internet-facing SSH server gets hammered. Shodan data shows the average exposed SSH server receives **hundreds of failed login attempts per day**. The top targeted usernames? `root`, `admin`, `test`, `user`, `oracle`, `postgres`.

**3. Password Spraying**
Instead of trying many passwords against one user, attackers try one common password against many users. This evades per-user lockout policies. Your log parser needs to catch both patterns.

---

## Log Format Reference

This challenge detects **all SSH authentication failures** - both password and publickey. Your parser must correctly identify both "Failed password" and "Failed publickey" entries while ignoring everything else.

### Lines to MATCH (Signal)

These are the four formats your regex MUST capture:

**1. Valid User - Failed Password:**
```
Jan  5 14:22:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 54321 ssh2
```

**2. Invalid User - Failed Password:**
```
Jan  5 14:22:02 server sshd[12346]: Failed password for invalid user admin from 10.0.0.1 port 54322 ssh2
```

**3. Valid User - Failed Publickey:**
```
Jan  5 14:22:03 server sshd[12347]: Failed publickey for root from 192.168.1.100 port 54323 ssh2: RSA SHA256:abc123...
```

**4. Invalid User - Failed Publickey:**
```
Jan  5 14:22:04 server sshd[12348]: Failed publickey for invalid user git from 10.0.0.1 port 54324 ssh2: ED25519 SHA256:def456...
```

Note: "invalid user" appears *before* the username in both patterns. Your regex needs to handle all four cases.

**Why track both?** From a security perspective, both indicate authentication failures:
- **Password failures**: Credential stuffing, brute force attacks
- **Publickey failures**: Key enumeration, stolen key testing, lateral movement attempts

A comprehensive security monitoring tool should track ALL failed authentication attempts.

### Lines to IGNORE (Noise)

Real auth.log files contain dozens of entry types. Your parser must **ignore all of these**:

| Entry Type | Example | Why Ignore |
|------------|---------|------------|
| **Successful Password** | `Accepted password for deploy from 10.0.0.50 port 22 ssh2` | Not a failure |
| **Successful Pubkey** | `Accepted publickey for admin from 10.0.0.51 port 45615 ssh2` | Not a failure |
| **Connection Closed** | `Connection closed by 10.0.0.52 port 24091 [preauth]` | No credentials |
| **Disconnected** | `Disconnected from authenticating user root 10.0.0.1 port 22 [preauth]` | No failure type |
| **Session Opened** | `pam_unix(sshd:session): session opened for user deploy(uid=3050) by (uid=0)` | Session management |
| **Session Closed** | `pam_unix(sshd:session): session closed for user deploy` | Session management |
| **CRON Jobs** | `CRON[16419]: pam_unix(cron:session): session opened for user root...` | Not SSH |
| **Sudo Commands** | `sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=...` | Not SSH |
| **Systemd Sessions** | `systemd-logind[319]: New session 6002 of user www-data.` | Not SSH |
| **PAM Failures** | `pam_unix(sshd:auth): authentication failure; logname= uid=0...` | Generic PAM (no IP) |
| **Invalid User Disconnect** | `Disconnected from invalid user test 192.168.1.100 port 22 [preauth]` | No auth attempt |

### Timestamp Format

| Field | Example | Notes |
|-------|---------|-------|
| Month | `Jan` | 3-letter abbreviation |
| Day | `5` or `15` | Space-padded for single digits (` 5` not `05`) |
| Time | `14:22:01` | 24-hour format HH:MM:SS |
| Hostname | `webserver` | System hostname (varies) |
| Service | `sshd[12345]` | Service name and PID |
| Message | `Failed password for...` or `Failed publickey for...` | The actual event |

---

## Edge Cases That Will Break Your First Implementation

### 1. The "invalid user" Variation
```
Failed password for root from 192.168.1.1 port 22 ssh2
Failed password for invalid user h4ck3r from 192.168.1.1 port 22 ssh2
Failed publickey for root from 192.168.1.1 port 22 ssh2
Failed publickey for invalid user git from 192.168.1.1 port 22 ssh2
```
Four different patterns. Your regex must handle all of them.

### 2. Password vs Publickey
```
Failed password for root from 192.168.1.1 port 22 ssh2
Failed publickey for root from 192.168.1.1 port 22 ssh2: RSA SHA256:abc123
```
Both are failed authentications. Both should be counted. Note that publickey failures often include the key type and fingerprint at the end.

### 3. Single-Digit Days
```
Jan  5 14:22:01 ...   # Two spaces before 5
Jan 15 14:22:01 ...   # One space before 15
```
That extra space trips up naive splitting.

### 3. IPv6 Addresses
```
Failed password for root from 2001:db8::1 port 22 ssh2
Failed password for root from ::1 port 22 ssh2
Failed password for root from fe80::1 port 22 ssh2
```
Your IP extraction regex probably doesn't handle these. Should it? (Yes.)

### 4. Empty Files
What happens when the log file exists but contains zero failed logins? Your function shouldn't crash—it should return sensible defaults.

### 5. Ties in "Top Offender"
If two IPs both have the highest count, pick the one that sorts first alphabetically. Same for usernames. Deterministic output matters for testing.

### 6. Mixed Content
Real auth.log files contain *thousands* of lines that aren't failed passwords:
```
Jan  5 14:22:00 server sshd[12344]: Accepted publickey for deploy from 10.0.0.50
Jan  5 14:22:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan  5 14:22:02 server systemd[1]: Started Session 4521 of user deploy.
Jan  5 14:22:03 server sshd[12346]: Connection closed by 192.168.1.100 port 22
```
Only one of those lines matters.

### 7. Unusual Usernames
Attackers try everything:
```
Failed password for invalid user test-user from ...     # hyphens
Failed password for invalid user john.doe from ...     # dots
Failed password for invalid user user@domain from ...  # @ signs
Failed password for invalid user 12345 from ...        # all numeric
Failed password for invalid user _ from ...            # single underscore
```

### 8. First and Last Failure Timestamps

Your parser must track **when** the attack started and when the most recent attempt occurred. This is critical for incident response.

**Why?** Security analysts need to know:
- "When did this attack start?" → `first_failure`
- "Is this still happening?" → `last_failure`
- "How long did the attack last?" → difference between them

**Format:** Preserve the exact timestamp string from the log:
```python
first_failure = "Jan  5 14:22:01"  # Note: two spaces before single-digit day
last_failure = "Jan  5 18:45:30"
```

**Edge cases to handle:**
- Single failure → `first_failure == last_failure`
- No failures → Both are `None`
- Log file not in chronological order → Still find true first and last

**Hints:**
- The timestamp is always at the beginning of each line
- Think about what happens when you encounter the *first* failure vs subsequent ones
- What should `last_failure` be after processing *every* failure line?

**Why this matters for security:**

| Scenario | first_failure | last_failure | Interpretation |
|----------|---------------|--------------|----------------|
| `14:22:01` | `14:22:45` | 44-second burst attack |
| `09:00:00` | `18:00:00` | Sustained all-day attack |
| `23:30:00` | `23:30:00` | Single probe attempt |
| `None` | `None` | No attacks detected |

This tells you if you're dealing with a quick scan or a persistent threat.

---

## The 105 Test Cases

Your implementation will be tested against these 7 categories:

### Category 1: Basic Parsing (15 tests)
- Single failed login line
- Multiple failed logins from same IP
- Multiple failed logins for same user
- Mix of valid and invalid users
- Extract correct timestamp hour
- Correct total count
- Correct unique IP list (sorted)
- Correct unique user list (sorted)
- Basic attempts_by_ip accuracy
- Basic attempts_by_user accuracy
- Different months parsed correctly
- Different hostnames handled
- Different PID formats
- Different port numbers
- All required dict keys present

### Category 2: Edge Cases - Empty & Minimal (15 tests)
- Empty file returns correct structure
- File with only successful logins
- File with only non-SSH entries
- Single character username
- Very long username (128+ chars)
- File with blank lines mixed in
- Malformed lines ignored
- **Mixed password and publickey failures**
- Only invalid user attempts
- Only valid user attempts
- File with only whitespace
- Connection closed messages ignored
- Disconnected messages ignored
- PAM messages ignored
- Large file simulation (50+ entries)

### Category 3: IP Address Handling (15 tests)
- Standard IPv4 addresses
- Private range 10.x IPs
- Private range 172.16.x IPs
- Localhost (127.0.0.1)
- IPv6 full format
- IPv6 compressed (::1)
- IPv6 with double colon
- IPv6 link-local (fe80::)
- Multiple IPs same user
- Same IP multiple users
- IP sorting (lexicographic)
- Mixed IPv4/IPv6 sorting
- Edge IP 0.0.0.0
- Edge IP 255.255.255.255
- Many unique IPs (20+)

### Category 4: Brute Force Detection (15 tests)
- IP with exactly 4 failures (not brute force)
- IP with exactly 5 failures (is brute force)
- IP with exactly 6 failures
- IP with 100+ failures
- Multiple IPs qualifying as brute force
- Brute force list sorted correctly
- No brute force when max is 4
- Mix of brute force and normal IPs
- All IPs are brute force
- Single IP with 5+ failures
- IPv6 brute force detection
- Boundary testing (4 vs 5)
- Empty brute force when no failures
- Mixed IPv4/IPv6 brute force
- Large scale brute force (10+ IPs)

### Category 5: Timeline Analysis (15 tests)
- First and last failure timestamps
- Single failure (first == last)
- Burst attacks (all within seconds)
- One minute apart
- One hour apart
- All-day attacks (00:00 to 23:59)
- Morning attack patterns
- Night attack patterns
- Multiple attackers at different times
- Timestamp precision (seconds matter)
- Midnight exactly (00:00:00)
- End of day (23:59:59)
- Extended multi-hour attacks
- Periodic attacks (every N hours)

### Category 6: Top Offender Logic (15 tests)
- Clear winner (single IP in list)
- Clear winner (single user in list)
- Two-way tie returns both IPs
- Two-way tie returns both users
- Single entry is top offender
- Empty list when no failures
- Three-way tie returns all three (sorted)
- Large dataset accuracy
- Numeric usernames in tie
- Case-sensitive sorting (ADMIN ≠ admin)
- Single attempt each (all tied)
- Top offenders change with data
- IPv6 in top offenders list
- Underscore in username
- Special chars in username

### Category 7: Username Edge Cases (15 tests)
- Username with numbers
- All numeric username
- Username with underscore
- Username with hyphen
- Username with dot
- Common attack usernames (root, admin, oracle, etc.)
- Username starting with number
- Mixed case username (JohnDoe)
- Single underscore username
- Two character username
- Service account usernames (www-data, nobody)
- Email-like usernames (user@domain)
- Username with plus sign
- Multiple similar usernames
- Backslash in username

---

## Common Mistakes

### ❌ Mistake 1: Forgetting "invalid user"
```python
# WRONG - only matches existing users
match = re.search(r'Failed password for (\w+) from', line)

# RIGHT - handles both cases
match = re.search(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from', line)
```

### ❌ Mistake 2: Only Matching Password Failures
```python
# WRONG - misses publickey failures
match = re.search(r'Failed password for', line)

# RIGHT - catches both authentication types
match = re.search(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port', line)
```

### ❌ Mistake 3: Hardcoding IPv4 Only
```python
# WRONG - misses IPv6
ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

# RIGHT - captures IP before "port"
ip_pattern = r'from (\S+) port'
```

### ❌ Mistake 4: Not Handling Empty Results
```python
# WRONG - crashes on empty dictionary
top_ips = [max(attempts_by_ip, key=attempts_by_ip.get)]
# TypeError: max() arg is an empty sequence
```

**Think about:** What should `top_offender_ips` be when there are zero failures?

### ❌ Mistake 5: Forgetting to Sort
```python
# WRONG - order depends on insertion
unique_ips = list(ip_set)

# RIGHT - deterministic output
unique_ips = sorted(ip_set)
```

### ❌ Mistake 6: Wrong First/Last Failure Logic
```python
# WRONG - not tracking timestamps correctly
first_failure = None
for line in log:
    if is_failure(line):
        first_failure = extract_timestamp(line)  # Keeps overwriting!
# Result: first_failure is actually the LAST one

# WRONG - forgetting to handle no failures
first_failure = extract_timestamp(lines[0])  # Crashes on empty file
```

**Think about:**
- How do you know when you've seen the *first* failure?
- What should happen to `last_failure` every time you see a failure?
- What values should both have if the file contains zero failures?

**Why this matters:** Incident response needs to know attack duration. Getting timestamps wrong ruins your timeline.

### ❌ Mistake 7: Only Returning One Top Offender
```python
# WRONG - only returns one IP, even when multiple are tied
top_ip = max(attempts_by_ip, key=attempts_by_ip.get)
# If 3 IPs all have 10 failures, you only get one of them!
```

**The requirement:** When multiple IPs (or users) are tied for most failures, return **ALL of them** in a sorted list.

**Think about:**
- First find the maximum count
- Then find ALL items that have that count
- Return them sorted alphabetically

### ❌ Mistake 8: Brute Force Threshold
```python
# WRONG - off by one
if count > 5:
    brute_force.append(ip)
```

**The requirement:** An IP is flagged for brute force if it has **5 or more** failures.

Does 5 failures qualify? Read the requirement carefully.

---

## What You'll Learn

By completing this exercise, you'll practice:

1. **File I/O** - Reading and iterating through text files (Python Workout Ch. 6)
2. **Regular Expressions** - Pattern matching for log parsing
3. **Dictionary Operations** - Counting, aggregating, finding max values
4. **Sorting** - Custom sort keys, tie-breaking logic
5. **Edge Case Handling** - Empty inputs, malformed data, boundary conditions
6. **Security Mindset** - Thinking like an attacker to understand what to detect
7. **IPv4 and IPv6** - Handling both address formats

---

## Get Started

### Option 1: Clone the Exercise Repository

```bash
git clone https://github.com/fosres/appsec-exercises.git
cd appsec-exercises/auth-log-scraper
python auth_log_scraper_105_tests.py
```

### Option 2: Create Your Own Test File

Create a sample `auth.log` for testing:

```bash
cat > test_auth.log << 'EOF'
Jan  5 14:22:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan  5 14:22:02 server sshd[12346]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan  5 14:23:01 server sshd[12347]: Failed password for root from 10.0.0.1 port 22 ssh2
Jan  5 15:00:00 server sshd[12348]: Accepted publickey for deploy from 10.0.0.50 port 22 ssh2
Jan  5 15:01:01 server sshd[12349]: Failed password for invalid user test from 192.168.1.100 port 22 ssh2
EOF
```

Expected output for this file:
```python
{
    "total_failed": 4,
    "unique_ips": ["10.0.0.1", "192.168.1.100"],
    "unique_users": ["admin", "root", "test"],
    "attempts_by_ip": {"192.168.1.100": 3, "10.0.0.1": 1},
    "attempts_by_user": {"root": 2, "admin": 1, "test": 1},
    "top_offender_ips": ["192.168.1.100"],  # All IPs tied for most failures
    "top_targeted_users": ["root"],          # All users tied for most targeted
    "first_failure": "Jan 5 14:22:01",  # When attack started
    "last_failure": "Jan 5 15:01:01",   # Most recent attempt
    "potential_brute_force": [],  # No IP has 5+ failures
}
```

---

## Scoring

```
╔═════════════════════════════════════════════╗
║          AUTH LOG SCRAPER                   ║
║             RESULTS                         ║
╠═════════════════════════════════════════════╣
║  Tests Passed: XXX / 105                    ║
║  Score: XX.X%                               ║
╠═════════════════════════════════════════════╣
║  0-29:   Keep reading Python Workout        ║
║  30-59:  Making progress                    ║
║  60-74:  Solid foundation                   ║
║  75-89:  Production-ready                   ║
║  90-104: Excellent! Almost perfect          ║
║  105:    🎉 Ready for Security Engineering  ║
╚═════════════════════════════════════════════╝
```

---

## Resources

This exercise draws inspiration from:

- **Python Workout, Second Edition** by Reuven M. Lerner - Chapter 6: Files (pages 90-120) for file iteration patterns and the `/etc/passwd` parsing exercise
- **Complete 48-Week Security Engineering Curriculum** - Week 4: Linux Security + Python Files (pages 13-15) for the log analyzer requirement
- **Grace Nolan's Security Engineering Interview Notes** - Emphasis on practical scripting exercises
- **Hacking APIs** by Corey Ball - Chapter 6 (pages 138-141) for reconnaissance scripting patterns

---

## Reference Solution

Stuck? Compare your approach to the [reference solution](https://github.com/fosres/AppSec-Exercises/blob/main/cyberscripts/auth_log/auth_log_solution.py).

Try to solve it yourself first — you'll learn more by struggling through the edge cases than by reading the answer.

### Grader

Use the [grader script](https://github.com/fosres/AppSec-Exercises/blob/main/cyberscripts/auth_log/grader.py) to test your solution:

```bash
python grader.py your_solution.py
```

---

## Share Your Solution

Completed the challenge? Here's how to join the community:

1. 🐦 **Post your score** with `#AppSecExercises` on Twitter/X
2. 🔀 **Submit a PR** with your solution or propose a new test case
3. ✍️ **Write your own blog post** explaining your approach (I'll link to it!)

---

## Next Challenge

Once you've mastered auth log parsing, you're ready for:

| Challenge | Difficulty | Skills |
|-----------|------------|--------|
| **IOC Extractor** | ⭐⭐ | Regex, threat intel formats |
| **JWT Validator** | ⭐⭐⭐ | Cryptography, authentication |
| **SAST Rule Writer** | ⭐⭐⭐ | AST parsing, vulnerability patterns |
| **API Fuzzer** | ⭐⭐⭐⭐ | HTTP, edge cases, error handling |

---

**Found a bug? Have a better test case?** [Open an issue](https://github.com/fosres/appsec-exercises/issues). Security is a team sport.

**Found this useful?** [⭐ Star the repo](https://github.com/fosres/appsec-exercises) — more challenges coming soon.
