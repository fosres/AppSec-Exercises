---
title: "AppSec Challenge: Build a Log Parser to Detect SQL Injection & Path Traversal (Week 2/48)"
published: false
description: "Learn security log analysis by building a real attack detector. Part of a 48-week journey from Intel → Remote AppSec Engineer."
tags: appsec, python, security, cybersecurity
cover_image: https://dev.to/social_previews/article/12345.png
series: AppSec Fundamentals
canonical_url: https://github.com/fosres/AppSec-Exercises
---

# 🔍 The Challenge: Can You Spot the Attackers in Your Logs?

Every second, your web server is writing access logs. Most entries are legitimate users browsing your site. But buried in thousands of normal requests are attackers probing for vulnerabilities, attempting SQL injection, and scanning for exposed files.

**Your mission:** Build a log parser that extracts critical security information and detects attack patterns.

> 💡 **Part of a 48-week Intel → Remote AppSec Engineer curriculum**  
> Follow along as I transition from Intel Security Engineering to a remote AppSec role by June 2026.

## 🎯 Real-World Relevance

When Equifax was breached in 2017 (compromising 147 million people), investigators found the attackers had been in their systems for **76 days**. The evidence? **Buried in access logs that nobody was parsing.**

GitHub's security team processes millions of log entries daily to detect:
- Credential stuffing attacks
- API abuse patterns  
- Automated vulnerability scanners
- Path traversal attempts

**Every security engineer needs to parse logs.** This is Day 1 skills.

## 📦 What's in the Full Repository

This challenge is part of my AppSec learning series:

- **Weekly Security Challenges** (releasing through June 2026)
- **LeetCode-style format** with 60+ test cases per exercise  
- **Production-quality code** following "Secure by Design" principles
- **Real interview prep** for Trail of Bits, GitLab, Stripe, Coinbase
- **Public accountability** - tracking my Intel → Remote AppSec transition

**Repository:** https://github.com/fosres/AppSec-Exercises

---

## 🚨 What You're Preventing

Without proper log analysis:
- **SQL injection attempts** go undetected until your database is dumped on the dark web
- **Directory traversal attacks** (`../../etc/passwd`) succeed because you didn't notice the pattern
- **Brute force login attempts** from 100+ IPs look like normal traffic
- **Reconnaissance scans** map your entire infrastructure before the real attack

Companies that parse logs well detect breaches in **hours, not months**.

## 📝 The Challenge

**Difficulty:** Week 2 (Python Workout Chapters 1-4 only)  
**Skills Required:** String methods, lists, dictionaries, basic I/O  
**Time Estimate:** 2-3 hours

Write a Python script `log_parser.py` that parses web access logs and extracts security-relevant information.

### Input Format

Your script will process Apache/nginx **Combined Log Format** entries:

```
192.168.1.100 - - [15/Dec/2025:14:23:45 +0000] "GET /index.html HTTP/1.1" 200 1024 "https://google.com" "Mozilla/5.0"
10.0.0.50 - admin [15/Dec/2025:14:24:12 +0000] "POST /login.php HTTP/1.1" 401 512 "-" "curl/7.68.0"
203.0.113.42 - - [15/Dec/2025:14:25:03 +0000] "GET /admin' OR '1'='1 HTTP/1.1" 403 2048 "-" "sqlmap/1.5"
198.51.100.23 - - [15/Dec/2025:14:26:30 +0000] "GET /../../etc/passwd HTTP/1.1" 404 256 "-" "Mozilla/5.0"
```

**Log Format Breakdown:**
```
IP_ADDRESS - USERNAME [TIMESTAMP] "METHOD PATH PROTOCOL" STATUS_CODE BYTES "REFERRER" "USER_AGENT"
```

### Sample Input File

You can test your parser with this sample log file (save as `access.log`):

```
192.168.1.100 - - [15/Dec/2025:14:23:45 +0000] "GET /index.html HTTP/1.1" 200 1024 "https://google.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.100 - - [15/Dec/2025:14:23:48 +0000] "GET /about.html HTTP/1.1" 200 2048 "https://example.com/index.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
10.0.0.50 - admin [15/Dec/2025:14:24:12 +0000] "POST /login.php HTTP/1.1" 401 512 "-" "curl/7.68.0"
10.0.0.50 - admin [15/Dec/2025:14:24:15 +0000] "POST /login.php HTTP/1.1" 401 512 "-" "curl/7.68.0"
10.0.0.50 - admin [15/Dec/2025:14:24:18 +0000] "POST /login.php HTTP/1.1" 200 1024 "-" "curl/7.68.0"
203.0.113.42 - - [15/Dec/2025:14:25:03 +0000] "GET /products.php?id=1' OR '1'='1 HTTP/1.1" 200 4096 "-" "sqlmap/1.5#dev"
203.0.113.42 - - [15/Dec/2025:14:25:08 +0000] "GET /products.php?id=1 UNION SELECT password FROM users-- HTTP/1.1" 403 256 "-" "sqlmap/1.5#dev"
198.51.100.23 - - [15/Dec/2025:14:26:30 +0000] "GET /../../etc/passwd HTTP/1.1" 404 256 "-" "Mozilla/5.0"
198.51.100.23 - - [15/Dec/2025:14:26:35 +0000] "GET /../../../windows/system32/config/sam HTTP/1.1" 404 256 "-" "Mozilla/5.0"
172.16.0.5 - - [15/Dec/2025:14:27:10 +0000] "GET /api/users HTTP/1.1" 200 8192 "-" "python-requests/2.28.0"
172.16.0.5 - - [15/Dec/2025:14:27:45 +0000] "POST /api/upload HTTP/1.1" 201 128 "https://example.com/dashboard" "Mozilla/5.0"
```

### Required Output Format

Your script **must** output JSON with this exact structure:

```json
{
	"summary": {
		"total_requests": 11,
		"unique_ips": 4,
		"failed_requests": 4,
		"total_bytes_transferred": 18432,
		"most_common_status_codes": {
			"200": 6,
			"401": 2,
			"403": 1,
			"404": 2
		}
	},
	"top_ips": [
		{"ip": "10.0.0.50", "requests": 3},
		{"ip": "192.168.1.100", "requests": 2},
		{"ip": "203.0.113.42", "requests": 2},
		{"ip": "198.51.100.23", "requests": 2},
		{"ip": "172.16.0.5", "requests": 2}
	],
	"security_findings": [
		{
			"severity": "HIGH",
			"finding_type": "SQL_INJECTION",
			"ip": "203.0.113.42",
			"path": "/products.php?id=1' OR '1'='1",
			"timestamp": "15/Dec/2025:14:25:03 +0000",
			"user_agent": "sqlmap/1.5#dev"
		},
		{
			"severity": "HIGH",
			"finding_type": "SQL_INJECTION",
			"ip": "203.0.113.42",
			"path": "/products.php?id=1 UNION SELECT password FROM users--",
			"timestamp": "15/Dec/2025:14:25:08 +0000",
			"user_agent": "sqlmap/1.5#dev"
		},
		{
			"severity": "MEDIUM",
			"finding_type": "PATH_TRAVERSAL",
			"ip": "198.51.100.23",
			"path": "/../../etc/passwd",
			"timestamp": "15/Dec/2025:14:26:30 +0000",
			"user_agent": "Mozilla/5.0"
		},
		{
			"severity": "MEDIUM",
			"finding_type": "PATH_TRAVERSAL",
			"ip": "198.51.100.23",
			"path": "/../../../windows/system32/config/sam",
			"timestamp": "15/Dec/2025:14:26:35 +0000",
			"user_agent": "Mozilla/5.0"
		},
		{
			"severity": "LOW",
			"finding_type": "BRUTE_FORCE",
			"ip": "10.0.0.50",
			"description": "3 failed login attempts detected",
			"failed_request_count": 3,
			"target_path": "/login.php"
		}
	],
	"suspicious_user_agents": [
		{"user_agent": "sqlmap/1.5#dev", "count": 2},
		{"user_agent": "curl/7.68.0", "count": 3},
		{"user_agent": "python-requests/2.28.0", "count": 1}
	]
}
```

**Important Notes:**
- `top_ips` must be sorted by `requests` in descending order (highest first). In the example above, `10.0.0.50` with 3 requests is listed first.
- For IPs with the same request count, the order doesn't matter (any order is acceptable).

### Detection Requirements

Your parser **must** detect these attack patterns:

#### 1. SQL Injection (HIGH severity)
Detect these patterns in the URL path:
- `' OR '1'='1`
- `' OR 1=1--`
- `UNION SELECT`
- `; DROP TABLE`
- `--` (SQL comment)
- `'` followed by SQL keywords (OR, AND, UNION, SELECT, etc.)

#### 2. Path Traversal (MEDIUM severity)  

**Web Server Configuration:**
The web server's document root is `/var/www/html`. All requested files must stay within this directory.

**Your Task:**
Detect when a requested path would escape the document root.

**Examples:**
- `GET /docs/index.html` → Safe (stays in `/var/www/html/docs/`)
- `GET /../../etc/passwd` → Attack (escapes to `/var/etc/passwd`)
- `GET /../../../windows/system32/config/sam` → Attack (escapes to `/windows/system32/`)

**Detection (Week 2 Level):**
Use pattern matching to detect dangerous path patterns:
- Look for `../` or `..\` in the path
- Check for sensitive file paths like `/etc/passwd`, `/windows/system32`
- Any method that correctly identifies the attacks in the sample log is acceptable

**OPTIONAL/ADVANCED:** URL encoding (covered in Week 13-14)
- Attackers may URL-encode paths: `..%2f..%2fetc%2fpasswd`
- Or double-encode: `..%252f..%252fetc%252fpasswd`
- For Week 2, you can ignore URL encoding
- You'll enhance this detection later when studying "Hacking APIs" Chapter 13

#### 3. Brute Force Attempts (LOW severity)

Detect when an attacker is trying to guess passwords by making multiple failed login attempts.

**Exact Detection Rules:**

**Rule 1: What counts as a "failed login attempt"?**
A request is a failed login attempt if **ALL** of these conditions are true:
- Status code is `401` (Unauthorized) OR `403` (Forbidden)
- Path contains the word `login` (case-insensitive, anywhere in the path)

**Rule 2: What are valid login endpoints?**
Any path containing `login` (case-insensitive):
- ✅ `/login`, `/login.php`, `/admin/login`, `/api/login`, `/LOGIN`
- ❌ `/admin` (no "login"), `/auth` (different word), `/signin` (different word)

**Rule 3: Detection threshold**
- Track failed login attempts **per IP address**
- If the same IP has **3 or more** failed login attempts → Create a BRUTE_FORCE finding
- Check this **after processing all log entries** (not per line)

**Rule 4: Output format**
Create **one finding per IP** that meets the threshold:
```json
{
	"severity": "LOW",
	"finding_type": "BRUTE_FORCE",
	"ip": "10.0.0.50",
	"description": "3 failed login attempts detected",
	"failed_request_count": 3,
	"target_path": "/login.php"
}
```

**Examples:**

✅ **Brute Force Detected:**
```
10.0.0.50 - - [15/Dec/2025:14:00:00 +0000] "POST /login.php HTTP/1.1" 401 512
10.0.0.50 - - [15/Dec/2025:14:00:02 +0000] "POST /login.php HTTP/1.1" 401 512
10.0.0.50 - - [15/Dec/2025:14:00:04 +0000] "POST /login.php HTTP/1.1" 401 512
```
Result: 3 failed attempts to `/login.php` from `10.0.0.50` = BRUTE_FORCE

❌ **NOT Brute Force:**
```
10.0.0.50 - - [15/Dec/2025:14:00:00 +0000] "POST /admin HTTP/1.1" 401 512
10.0.0.50 - - [15/Dec/2025:14:00:02 +0000] "POST /admin HTTP/1.1" 401 512
10.0.0.50 - - [15/Dec/2025:14:00:04 +0000] "POST /admin HTTP/1.1" 401 512
```
Result: Path `/admin` doesn't contain "login" = NOT brute force

**Note:** For Week 2, we're simplifying this - just count total failures per IP to login endpoints, ignore timing windows.

#### 4. Suspicious User Agents
Flag these patterns:
- `sqlmap` - SQL injection tool
- `nikto` - vulnerability scanner  
- `nmap` - port scanner
- `curl` / `wget` - scripted access (not browsers)
- `python-requests` - scripted access

### Grading Criteria

Your script will be graded on:

1. **Correct JSON Structure** (30 points)
   - Exact field names as specified
   - Proper data types (numbers as numbers, not strings)
   - Valid JSON syntax

2. **Summary Statistics** (20 points)
   - Accurate `total_requests` count
   - Correct `unique_ips` count
   - Accurate `failed_requests` (4xx/5xx status codes)
   - Correct `total_bytes_transferred` sum
   - Proper `most_common_status_codes` dictionary
   - `top_ips` sorted by request count (descending - highest first)

3. **SQL Injection Detection** (20 points)
   - Detects `' OR '1'='1` pattern
   - Detects `UNION SELECT` pattern
   - Captures IP, path, timestamp, user_agent
   - Marks as HIGH severity

4. **Path Traversal Detection** (15 points)
   - Correctly identifies both path traversal attempts in the sample log
   - Marks as MEDIUM severity
   - Captures IP, path, timestamp, user_agent
   - **Note:** Any detection method that correctly identifies the attacks is acceptable

5. **Brute Force Detection** (10 points)
   - Groups failed attempts (401/403) by IP
   - Only counts failures to login endpoints (path contains "login")
   - Detects 3+ failed login attempts from same IP
   - Marks as LOW severity
   - Includes failed_request_count field

6. **User Agent Analysis** (5 points)
   - Flags `sqlmap`, `curl`, `python-requests`
   - Counts occurrences of each suspicious user agent

### Usage

Your script should be runnable like this:

```bash
python3 log_parser.py access.log
```

Output should print the JSON to stdout (or save to `output.json`).

## 🧠 What You'll Learn (Week 2 Skills)

By completing this challenge, you'll master:

1. **String Parsing with .split()** - Extract structured data from text using basic string methods
2. **String Slicing** - Use `[start:end]` to extract substrings from log lines
3. **String Methods** - `.lower()`, `.find()`, `.strip()`, `in` operator for pattern matching
4. **Dictionaries & Counting** - Use `.get()` method to count occurrences
5. **List Comprehensions** - Filter and transform log entries efficiently
6. **Path Security Concepts** - Understand how directory traversal attacks work and how to detect dangerous path patterns
7. **OWASP Top 10** - Real SQL injection and path traversal attack patterns
8. **JSON Output** - Format data for security tools (SIEM, alerting)

**Note:** This exercise uses Python skills from Chapters 1-4 of Python Workout (no regex, no datetime, no OOP). URL encoding detection and advanced path validation are optional enhancements you can add later in Week 13-14 when studying evasion techniques in "Hacking APIs" Chapter 13.

---

**💡 Coming up in future weeks:** SQLi detection (Week 4), PCAP analysis (Week 9), reverse engineering (Week 13), and full SIEM engines (Week 20).

---

## 💡 Hints (Conceptual Guidance Only)

**Approach to parsing log lines:**
- Each log line has a consistent format with fields separated by spaces and quotes
- The IP address is always the first element
- The timestamp is wrapped in square brackets `[]`
- The HTTP request is wrapped in double quotes `"GET /path HTTP/1.1"`
- The status code and bytes come after the request
- The user agent is the last quoted string
- Think about: How can you use `.split()`, `.find()`, and string slicing `[start:end]` to extract these fields?

**Detecting SQL injection patterns:**
- SQL injection often includes SQL keywords like `OR`, `AND`, `UNION`, `SELECT`, `DROP`
- Look for single quotes `'` combined with SQL logic
- SQL comments like `--` or `/* */` are suspicious
- Remember to check case-insensitively (`.lower()` is your friend)
- Think about: How can you check if certain substrings exist in the path using the `in` operator?

**Detecting path traversal:**
- The web server's document root is `/var/www/html`
- Requests that escape this directory are path traversal attacks
- Think about: How do you check if a path like `/../../etc/passwd` escapes `/var/www/html`?
- You can use simple pattern matching OR figure out how to resolve and validate paths
- **Optional (Week 13+):** Python has built-in modules that can help with path operations and URL decoding

**Counting and aggregating:**
- You'll need to count requests per IP, count status codes, and group failed attempts
- Dictionaries are perfect for counting: use IP or status code as the key, count as the value
- The `.get(key, default)` method is useful: `counts.get(ip, 0) + 1`
- Think about: How do you iterate through all log entries and update your count dictionaries?

**Detecting brute force:**
- For this simplified version, just count how many failed attempts (401/403 status) each IP has
- Group failed attempts by IP address using a dictionary
- If an IP has 3 or more failed attempts total, it's a potential brute force
- Think about: How do you filter entries by status code and count them per IP?

**General strategy:**
1. Read the log file line by line
2. Parse each line to extract: IP, timestamp, method, path, status, user_agent
3. Store parsed data in a list of dictionaries
4. Analyze the list to generate summary statistics
5. Check each entry for attack patterns (SQLi, path traversal, suspicious user agents)
6. Group and count for brute force detection
7. Format everything as JSON and output

## 🎓 Common Mistakes

1. **Not handling missing fields** - Some logs have `-` for bytes/referrer, check before converting to int
2. **Case sensitivity** - SQL keywords can be `UNION`, `Union`, or `union` - use `.lower()` first
3. **Partial matches** - `union` in `reunion.html` is NOT SQL injection - be careful with `in` checks
4. **String splitting edge cases** - User agents and referrers contain spaces, can't just split the whole line on spaces
5. **Quote handling** - The request and user agent are wrapped in quotes, need to extract carefully
6. **JSON formatting** - Use `json.dumps()` with `indent=2` for readable output

## 🏆 Success Criteria

Your parser successfully:
- ✅ Parses all 11 sample log entries without errors
- ✅ Outputs valid JSON matching the exact schema
- ✅ Detects all 2 SQL injection attempts from `203.0.113.42`
- ✅ Detects all 2 path traversal attempts from `198.51.100.23`
- ✅ Detects the brute force pattern from `10.0.0.50`
- ✅ Flags `sqlmap`, `curl`, and `python-requests` as suspicious
- ✅ Calculates summary statistics correctly

## 📚 Resources (Week 2 Level)

- **Apache Log Format Docs**: https://httpd.apache.org/docs/current/logs.html
- **OWASP Injection**: https://owasp.org/www-community/Injection_Flaws
- **Python String Methods**: https://docs.python.org/3/library/stdtypes.html#string-methods
- **Python Dictionaries**: https://docs.python.org/3/tutorial/datastructures.html#dictionaries
- **Grace Nolan's Security Notes**: https://github.com/gracenolan/Notes

**Note:** This exercise uses only Python Workout Chapters 1-4 skills. You don't need regex, datetime parsing, or OOP yet!

## 🔮 Future Enhancements (Later in Curriculum)

This exercise focuses on Week 2 fundamentals, but you'll enhance it later:

**Week 13-14: WAF Evasion & URL Encoding**
- URL encoding detection: `..%2f` vs `../`
- Double URL encoding: `..%252f` (bypasses filters)
- Case switching bypasses
- String terminators (null bytes)
- Reading: "Hacking APIs" Chapter 13

**Week 20-23: Production SIEM**
- 1000+ events/second processing
- Multi-stage attack correlation
- Geographic IP analysis
- False positive reduction

For now, focus on the basics: parsing, pattern matching, JSON output!

## 🚀 Next Steps (After You Master Week 2)

Once you've completed the basic parser and progressed further in your curriculum:

1. **Week 5+: Add regex patterns** - Use `re` module for more sophisticated pattern matching
2. **Week 6+: Add time-based detection** - Parse timestamps with `datetime` to detect rapid attacks
3. **Week 9+: Create a LogEntry class** - Use OOP to organize your code better
4. **Week 12+: GeoIP lookup** - Map IPs to countries using `geoip2` library
5. **Week 15+: Export to SIEM** - Format output for Splunk/ELK ingestion

**For now:** Focus on mastering string methods, dictionaries, and list comprehensions. These are your foundation!

---

## 🚀 Get Involved

### ⭐ Like This Challenge?

**Star the repository to get more weekly security challenges:**  
👉 **https://github.com/fosres/AppSec-Exercises**

New challenges every Monday covering: SQLi detection, PCAP analysis, reverse engineering, SIEM correlation, API security, and more.

### 📬 Stay Connected

- **GitHub**: [@fosres](https://github.com/fosres)
- **Dev.to**: [@fosres](https://dev.to/fosres) - Weekly security posts

### 🎯 Submit Your Solution

Complete the challenge and submit a PR! Check the repository for submission instructions.

---

---

*Part of a 48-week journey from Intel Security Engineer → Remote AppSec Engineer. All challenges, solutions, and progress documented publicly at [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)*

#security #python #appsec #cybersecurity #loganalysis #jobsearch
