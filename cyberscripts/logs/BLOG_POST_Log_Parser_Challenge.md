---
title: "Security Challenge: Build a Web Access Log Parser to Detect Attacks"
published: false
description: "Parse Apache/nginx logs to extract IPs, detect SQL injection attempts, and identify suspicious patterns - a core security engineering skill"
tags: appsec, python, security, challenge
cover_image: https://dev.to/social_previews/article/12345.png
---

# 🔍 The Challenge: Can You Spot the Attackers in Your Logs?

Every second, your web server is writing access logs. Most entries are legitimate users browsing your site. But buried in thousands of normal requests are attackers probing for vulnerabilities, attempting SQL injection, and scanning for exposed files.

**Your mission:** Build a log parser that extracts critical security information and detects attack patterns.

## 🎯 Real-World Relevance

When Equifax was breached in 2017 (compromising 147 million people), investigators found the attackers had been in their systems for **76 days**. The evidence? **Buried in access logs that nobody was parsing.**

GitHub's security team processes millions of log entries daily to detect:
- Credential stuffing attacks
- API abuse patterns  
- Automated vulnerability scanners
- Path traversal attempts

**Every security engineer needs to parse logs.** This is Day 1 skills.

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
		{"user_agent": "sqlmap/1.5#dev", "count": 2, "reason": "Known attack tool"},
		{"user_agent": "curl/7.68.0", "count": 3, "reason": "Scripted access"}
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
Detect these patterns:
- `../` or `..\` anywhere in path
- `/etc/passwd`
- `/windows/system32`
- `%2e%2e%2f` (URL-encoded `../`)

#### 3. Brute Force Attempts (LOW severity)
- 3+ failed requests (status 401 or 403) from same IP
- Must group by IP and count failures
- **Note:** For Week 2, we're simplifying this - just count total failures per IP, ignore timing

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
   - Detects `../` patterns  
   - Detects `/etc/passwd` and `/windows/system32`
   - Marks as MEDIUM severity

5. **Brute Force Detection** (10 points)
   - Groups failed attempts (401/403) by IP
   - Detects 3+ failed attempts from same IP
   - Marks as LOW severity
   - Includes failed_request_count field

6. **User Agent Analysis** (5 points)
   - Flags `sqlmap`, `curl`, `python-requests`
   - Provides reason for flagging

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
6. **OWASP Top 10** - Real SQL injection and path traversal attack patterns
7. **JSON Output** - Format data for security tools (SIEM, alerting)

**Note:** This exercise uses only Python skills from Chapters 1-4 of Python Workout (no regex, no datetime parsing, no classes).

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
- Attackers try to navigate outside the web root with `../` or `..\`
- Common targets: `/etc/passwd` (Linux), `/windows/system32` (Windows)
- These patterns can appear anywhere in the URL path
- Think about: How can you check if any of these dangerous patterns exist in the path?

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

## 🚀 Next Steps (After You Master Week 2)

Once you've completed the basic parser and progressed further in your curriculum:

1. **Week 5+: Add regex patterns** - Use `re` module for more sophisticated pattern matching
2. **Week 6+: Add time-based detection** - Parse timestamps with `datetime` to detect rapid attacks
3. **Week 9+: Create a LogEntry class** - Use OOP to organize your code better
4. **Week 12+: GeoIP lookup** - Map IPs to countries using `geoip2` library
5. **Week 15+: Export to SIEM** - Format output for Splunk/ELK ingestion

**For now:** Focus on mastering string methods, dictionaries, and list comprehensions. These are your foundation!

Share your solution in the comments or on GitHub! Tag me if you build something cool.

---

**This is Exercise #2 in my AppSec Fundamentals series.** Working on your Python skills for security engineering? Check out my other challenges at https://github.com/fosres/AppSec-Exercises

*Written by Tanveer Salim (fosres) | Currently learning: Week 2 of 48-week Security Engineering curriculum*

#security #python #appsec #cybersecurity #loganalysis
