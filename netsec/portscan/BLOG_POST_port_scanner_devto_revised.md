# Challenge: Build a Production TCP Port Scanner

**Time:** 60-90 minutes  
**Difficulty:** Intermediate  
**Skills:** Application Security, Socket Programming, Network Reconnaissance  

## The Challenge

Every security professional needs to understand how port scanning works. It's the first step in reconnaissance - before you can secure a system, you need to know what services are exposed. Today, you'll build a production-grade TCP port scanner that handles real-world edge cases and error conditions.

But here's the twist: **this isn't a tutorial**. You get an auto-grader with 60 comprehensive test cases and must figure out the implementation yourself. Just like a real security engineering interview.

### What You Get

- ✅ **Auto-grader:** 60 tests with instant feedback
- ✅ **Detailed specification:** Clear requirements document
- ✅ **Letter grade:** A through F based on tests passed
- ✅ **No paywalls:** 100% free and open source
- ✅ **Reusable:** Run the grader unlimited times

**Direct Links:**
- 📥 [port_scan.py](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/portscan/port_scan.py) - My Solution to this challenge
- 📥 [grade_port_scanner.py](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/portscan/grade_port_scanner.py) - Auto-grader
- 📂 [Challenge directory](https://github.com/fosres/AppSec-Exercises/tree/main/netsec/portscan) - All files

**Repository:** [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)

⭐ **Star the repo if you find it useful!** Helps others discover these challenges.

## Why This Matters in Real Life

### GitHub's 2019 Incident
In 2019, GitHub's security team discovered unauthorized port scans against their infrastructure. The scans targeted common service ports (SSH, HTTP, databases) to map their attack surface. **Port scanning is reconnaissance 101** - it's how attackers find vulnerable services.

### Stripe's Red Team Exercises
Stripe's internal red team regularly conducts network reconnaissance as part of their security testing. They use port scanning to identify forgotten services, misconfigured firewalls, and unauthorized deployments. According to their engineering blog, they've found critical issues by scanning for unexpected ports in production.

### The Numbers
- **27% of data breaches** start with network reconnaissance (Verizon DBIR 2023)
- **Port 3389 (RDP)** receives ~3 million scan attempts daily (Shodan)
- **Database ports** (3306, 5432, 27017) are among the top 10 most-scanned globally

## The Security Implications

### What Happens When Port Scanning Goes Wrong?

**Scenario 1: Denial of Service**
Aggressive port scanning without proper timeouts can flood a target with TCP SYN packets, causing legitimate connection failures. Your scanner must implement proper rate limiting and timeout handling.

**Scenario 2: Alert Fatigue**
Poorly designed scanners trigger thousands of IDS alerts without providing actionable intelligence. Security teams ignore these "noise alerts" - potentially missing real attacks. Your implementation must be precise.

**Scenario 3: Legal Consequences**
In 2013, a researcher was arrested for unauthorized port scanning of a government website. The Computer Fraud and Abuse Act (CFAA) considers unauthorized network scanning a federal crime. **Only scan systems you own or have explicit permission to scan.**

## The Challenge: scan_port()

Implement a function that performs TCP port scanning with comprehensive error handling:

```python
import socket

def scan_port(host: str, port: int, timeout: float) -> str:
	"""
	Scan a single TCP port on the specified host.
	
	Args:
		host: Target hostname or IP address
		port: Port number to scan (1-65535)
		timeout: Connection timeout in seconds (must be 1.0-2.0)
	
	Returns:
		Status string: "OPEN", "CLOSED", "FILTERED", or "ERROR"
	
	Required Behavior:
		1. PRINT a human-readable message explaining the result
		2. RETURN a status string
	"""
	# TODO: Implement your solution
	pass
```

### Expected Output Format

**Your function must do TWO things:**

**1. Print a message (for humans):**
```python
print(f"Port {port} on {host} is OPEN")
print(f"Port {port} on {host} is CLOSED")
print(f"Port {port} on {host} is FILTERED")
print(f"ERROR: Port {port} is invalid (must be 1-65535)")
```

**2. Return a status string (for programs):**
```python
return "OPEN"     # When connection succeeds
return "CLOSED"   # When connection is refused
return "FILTERED" # When connection times out
return "ERROR"    # When validation fails or DNS errors
```

**Critical:** Your function must RETURN (not `sys.exit()`), so it can be called multiple times and tested automatically.

## Why This Is Harder Than It Looks

### Edge Case 1: The Three Port States
Not all closed ports are the same:
- **OPEN:** Service is listening (successful TCP connection)
- **CLOSED:** Nothing listening, but host responds with RST (ConnectionRefusedError)
- **FILTERED:** Firewall drops packets silently (timeout)

Your implementation must distinguish all three states correctly.

### Edge Case 2: DNS Resolution Failures
What happens when you scan "thisdomaindoesnotexist123456789.com"? The socket library throws `socket.gaierror` - but your function must return a proper error status instead of crashing.

### Edge Case 3: The IPv6 Gotcha
Most developers forget about IPv6. Your scanner must handle both:
- IPv4: `127.0.0.1`
- IPv6: `::1`

The Python socket library handles this automatically, but you need to test it.

### Edge Case 4: Banner Grabbing Safety
Reading from an open socket can hang indefinitely if the service doesn't send a banner. You must:
1. Set a receive timeout
2. Limit buffer size (1024 bytes max)
3. Handle binary data (decode with `errors='ignore'`)

### Edge Case 5: Resource Leaks
Every `socket.socket()` call allocates a file descriptor. If you don't close sockets properly, you'll hit OS limits (usually 1024 open files). Use context managers or explicit cleanup.

## The Testing Gauntlet

Your implementation faces 60 comprehensive tests organized in 6 categories:

### Category 1: Input Validation (Tests 1-10)
- Invalid port numbers (negative, 0, > 65535)
- Invalid timeout values (negative, zero)
- DNS resolution failures
- Empty hostnames

### Category 2: HTTP/HTTPS Services (Tests 11-20)
- Port 80 (HTTP), 443 (HTTPS), 8080 (HTTP-alt)
- Web development ports: 3000, 5000, 8443, 9000
- Service name mapping accuracy

### Category 3: SSH/FTP/Email Services (Tests 21-30)
- SSH (22), FTP (21, 20), Telnet (23)
- SMTP (25), POP3 (110), IMAP (143)
- DNS (53), RDP (3389)

### Category 4: Database Services (Tests 31-40)
- MySQL (3306), PostgreSQL (5432), MongoDB (27017)
- Redis (6379), Elasticsearch (9200), Cassandra (9042)
- Oracle (1521), MS SQL (1433), CouchDB (5984)

### Category 5: Localhost Variations (Tests 41-50)
- Testing via "localhost", "127.0.0.1", "::1"
- High port numbers (50000+)
- Ephemeral port range (60000+)
- Privilege boundary (port 1024)

### Category 6: Timeout & Structure (Tests 51-60)
- Various timeout values (0.1s to 3.0s)
- Result dictionary structure validation
- Error field population tests

## The Exercise

### What You'll Get

1. **60-test Python file** with colored output (✅/❌)
2. **Detailed failure reports** showing expected vs actual
3. **Progressive difficulty** - tests get harder as you progress
4. **Category breakdown** showing your weak areas

### Sample Output

```bash
$ python3 port_scanner_60_tests.py

╔══════════════════════════════════════════════════════════════════════════════╗
║                    TCP PORT SCANNER - SECURITY RECONNAISSANCE                ║
║                             60 COMPREHENSIVE TEST CASES                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

✅ PASS - Test 1: Invalid port - negative number
✅ PASS - Test 2: Invalid port - zero
❌ FAIL - Test 3: Invalid port - exceeds maximum (65536)
   Expected status=ERROR, got OPEN
   Result: {'port': 65536, 'status': PortStatus.OPEN, ...}

...

===============================================================================
CATEGORY BREAKDOWN
===============================================================================
Input Validation......................... 8/10 (80%)
HTTP/HTTPS Services...................... 10/10 (100%)
SSH/FTP/Telnet Services.................. 10/10 (100%)
Database Services........................ 10/10 (100%)
Localhost Variations..................... 9/10 (90%)
Timeout & Structure...................... 10/10 (100%)

===============================================================================
OVERALL SUMMARY
===============================================================================
Tests Passed: 57/60 (95.0%)
Tests Failed: 3/60
```

## Why This Builds Real AppSec Skills

### 1. Defensive Programming
Input validation BEFORE network operations prevents crashes and security bugs. This pattern applies to every security tool you'll build.

### 2. Error Handling Patterns
Learning to distinguish `ConnectionRefusedError` from `socket.timeout` from `socket.gaierror` teaches you to handle the messy reality of network programming.

### 3. Resource Management
Properly closing sockets is like properly closing database connections or file handles - **resource leaks kill production systems**.

### 4. Service Detection Fundamentals
Mapping ports to services (80→http, 22→ssh) is the foundation of vulnerability assessment. Tools like Nmap build on this concept.

### 5. Security Reconnaissance
This is how every penetration test begins. Understanding port scanning from the inside helps you:
- Design better IDS rules
- Configure firewalls effectively
- Detect unauthorized reconnaissance

## Common Mistakes

### ❌ Mistake 1: Forgetting Input Validation
```python
def scan_port(host, port, timeout):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((host, port))  # Crashes on port -1!
```
**Fix:** Validate port (1-65535) and timeout (> 0) before ANY network operation.

### ❌ Mistake 2: Catching Exceptions Too Broadly
```python
try:
	sock.connect((host, port))
	return "OPEN"
except Exception:  # Too broad!
	return "ERROR"
```
**Fix:** Catch specific exceptions:
- `ConnectionRefusedError` → return "CLOSED"
- `socket.timeout` → return "FILTERED"
- `socket.gaierror` → return "ERROR"

### ❌ Mistake 3: Not Closing Sockets
```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(timeout)
sock.connect((host, port))
# Missing: sock.close()
return result
```
**Fix:** Use `try...finally` or context managers:
```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
	sock.connect((host, port))
	return result
finally:
	sock.close()
```

### ❌ Mistake 4: Using sys.exit() Instead of return
```python
def scan_port(host, port, timeout):
	if port < 1:
		sys.exit("ERROR: Invalid port")  # KILLS YOUR PROGRAM!
	# ...
```
**Problem:** `sys.exit()` terminates the entire program. You can never scan a second port!

**Fix:** Use `return` so your function can be called multiple times:
```python
def scan_port(host, port, timeout):
	if port < 1:
		print("ERROR: Invalid port")
		return "ERROR"  # Function returns, program continues
```

### ❌ Mistake 5: Returning None Instead of Status String
```python
def scan_port(host, port, timeout):
	print(f"Port {port} is CLOSED")
	return  # Returns None - auto-grader fails!
```
**Fix:** Always return a status string:
```python
def scan_port(host, port, timeout):
	print(f"Port {port} on {host} is CLOSED")
	return "CLOSED"  # Grader can verify this!
```

## Take the Challenge

### Step 1: Create Your Solution

Create a file named `port_scan.py` with your implementation:

**Option A: Start from scratch**
```python
import socket

def scan_port(host: str, port: int, timeout: float) -> str:
	# Your implementation here
	# Must PRINT a message AND RETURN a status string
	pass
```

**Option B: See my solution to this challenge**
```bash
# View or download my complete solution
curl -O https://raw.githubusercontent.com/fosres/AppSec-Exercises/main/netsec/portscan/port_scan.py
```

📂 **View on GitHub:** [port_scan.py - My Solution](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/portscan/port_scan.py)

**Remember:**
- ✅ PRINT: Human-readable message like `"Port 80 on localhost is CLOSED"`
- ✅ RETURN: Status string: `"OPEN"`, `"CLOSED"`, `"FILTERED"`, or `"ERROR"`
- ✅ Use `return` (NOT `sys.exit()` - it kills your program!)

### Step 2: Download the Auto-Grader

The auto-grader runs 60 comprehensive tests and gives you instant feedback.

**Option A: Clone the entire repository**
```bash
git clone https://github.com/fosres/AppSec-Exercises.git
cd AppSec-Exercises/netsec/portscan
```

**Option B: Download just the grader**
```bash
# Download the auto-grader directly
curl -O https://raw.githubusercontent.com/fosres/AppSec-Exercises/main/netsec/portscan/grade_port_scanner.py
```

**Option C: Download both files at once**
```bash
# Download template + grader
curl -O https://raw.githubusercontent.com/fosres/AppSec-Exercises/main/netsec/portscan/port_scan.py
curl -O https://raw.githubusercontent.com/fosres/AppSec-Exercises/main/netsec/portscan/grade_port_scanner.py
```

📂 **View on GitHub:** 
- [grade_port_scanner.py](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/portscan/grade_port_scanner.py) (the auto-grader)
- [Challenge directory](https://github.com/fosres/AppSec-Exercises/tree/main/netsec/portscan) (all files)

**⭐ If this challenge helps you, please star the repo! It helps others discover these free security exercises.**

### Step 3: Run the Grader

Place your `port_scan.py` in the same directory as `grade_port_scanner.py`, then:

```bash
# Make sure both files are in the same directory
ls
# Should show: port_scan.py  grade_port_scanner.py

# Run the grader
python3 grade_port_scanner.py
```

**You'll see:**
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                 WEEK 1 PORT SCANNER - COMPREHENSIVE GRADING                  ║
║                                60 TEST CASES                                 ║
║                      Networking Fundamentals Assessment                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

✅ PASS - Test 1: Invalid port - negative number (-1)
✅ PASS - Test 2: Invalid port - negative (-999)
✅ PASS - Test 3: Invalid port - zero (0)
...

================================================================================
CATEGORY BREAKDOWN
================================================================================
Port Validation (15 tests)................................. 15/15 (100%)
Timeout Validation (10 tests).............................. 10/10 (100%)
DNS & Host Resolution (10 tests)........................... 10/10 (100%)
Port States - Closed Ports (10 tests)...................... 10/10 (100%)
Return Value Validation (10 tests)......................... 10/10 (100%)
Edge Cases & Combined (5 tests)............................ 5/5 (100%)

================================================================================
FINAL GRADE
================================================================================
Tests Passed: 60/60 (100.0%)
Letter Grade: A

🎉 PERFECT SCORE! ALL 60 TESTS PASSED! 🎉
```

### Grading Scale

- **A (90-100%):** Production-ready code, excellent understanding
- **B (80-89%):** Good fundamentals, minor improvements needed
- **C (70-79%):** Basic functionality working, needs refinement
- **D (60-69%):** Partial implementation, significant gaps
- **F (<60%):** Core concepts need review

### What the Grader Tests

**Category 1: Port Validation (15 tests)**
- Invalid ports: negative, zero, > 65535
- Valid ports: 1, 65535, common ports (22, 80, 443)
- Edge cases: boundary values

**Category 2: Timeout Validation (10 tests)**
- Invalid timeouts: < 1.0, > 2.0, negative, zero
- Valid timeouts: 1.0, 1.5, 2.0
- Boundary conditions

**Category 3: DNS & Host Resolution (10 tests)**
- Nonexistent domains
- Invalid hostnames
- localhost, IPv4 (127.0.0.1), IPv6 (::1)

**Category 4: Port States (10 tests)**
- Detecting CLOSED ports correctly
- Testing various port numbers
- Multiple host formats

**Category 5: Return Values (10 tests)**
- Returns strings (not None)
- Status strings contain correct keywords
- Function callable multiple times

**Category 6: Edge Cases (5 tests)**
- Combined invalid inputs
- Boundary combinations
- IPv6 edge cases

### Iterate and Improve

The grader gives you detailed feedback on each failure:

```bash
❌ FAIL - Test 3: Invalid port - zero (0)
   Expected ERROR status, got: CLOSED
```

Fix the issue, save your file, and run the grader again. **No limit on attempts!**

### Minimum Requirements
- Python 3.8+
- No external dependencies (uses only stdlib)
- Works on Linux, macOS, Windows

## What You'll Learn

- ✅ **Socket programming fundamentals** - TCP connections, timeouts, error handling
- ✅ **Network reconnaissance techniques** - How attackers map services
- ✅ **Defensive programming patterns** - Input validation, resource cleanup
- ✅ **Service detection methodology** - Port-to-service mapping
- ✅ **IPv4 and IPv6 networking** - Modern network protocol support
- ✅ **Production-grade error handling** - Distinguishing error types correctly

## Share Your Results! 🎯

**Got an A?** Drop a comment with your score and any insights you discovered!

**Found this useful?** 
- ⭐ Star the [AppSec-Exercises repo](https://github.com/fosres/AppSec-Exercises) - it helps others discover these free challenges
- 🔄 Share on Twitter/LinkedIn with your test results
- 💬 Join the discussion - what was the trickiest part for you?

**Sample share:**
> "Just completed the Week 1 Port Scanner challenge from @fosres - scored 58/60 (A) on the auto-grader! 🎉 
> 
> Learned: socket programming, exception handling, and why you should NEVER use sys.exit() in functions 😅
> 
> Free challenge: [link]
> #AppSec #Python #Security"

**Want more challenges like this?** The repo includes:
- Auto-graders for every exercise
- Real-world security scenarios
- More challenges as they become available

**All free, all open source.** Star the repo to follow along! ⭐

## For Hiring Managers

This exercise tests candidates on:
1. **Systems programming** - socket operations, resource management
2. **Error handling** - dealing with network failures gracefully
3. **Security fundamentals** - understanding reconnaissance concepts
4. **Attention to detail** - 60 tests cover many edge cases
5. **Code quality** - proper cleanup, validation, documentation

Candidates who pass 55+ tests demonstrate senior-level proficiency in network security fundamentals.

## Level Up: After You Pass

### Optimization Challenge
Scan all 65,535 ports in under 10 seconds using:
- Threading (10-100 worker threads)
- Asyncio (1000+ concurrent connections)
- Raw sockets with SYN scanning (requires root)

### Feature Extensions
1. **UDP scanning** - Stateless protocol, requires different detection
2. **Version detection** - Parse banners to identify software versions
3. **OS fingerprinting** - TCP/IP stack analysis
4. **Scan profiles** - Quick scan (common ports), thorough scan (all ports), stealth scan (slow, randomized)

### Build a Real Tool
Create a CLI scanner with:
- Target specification (CIDR ranges, hostname lists)
- Output formats (JSON, XML, plain text)
- Scan timing templates (polite, normal, aggressive)
- IDS evasion techniques (timing randomization, fragmentation)

Compare your implementation to [Nmap's source code](https://github.com/nmap/nmap) - industry standard for 20+ years.

## Resources

### Required Reading
- **"Full Stack Python Security"** by Dennis Byrne
  - Chapter 12: Network Security and Socket Programming
- **"Hacking APIs"** by Corey Ball
  - Chapter 3: Reconnaissance and Information Gathering
- **"Python Workout"** by Reuven Lerner
  - Exercise format inspiration and testing methodology

### Reference Documentation
- [Python socket module](https://docs.python.org/3/library/socket.html)
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
- [RFC 793: Transmission Control Protocol](https://tools.ietf.org/html/rfc793)
- [IANA Service Names Registry](https://www.iana.org/assignments/service-names-port-numbers/)

### Related Content
- My previous post: [Building Secure APIs: Rate Limiting Deep Dive](#)
- Next in series: [Banner Grabbing and Service Fingerprinting](#)

---

**Legal Disclaimer:** This educational exercise is for learning security concepts on systems you own or have explicit permission to scan. Unauthorized port scanning may violate the Computer Fraud and Abuse Act (CFAA), Terms of Service agreements, and local/international laws. The author and publisher are not responsible for misuse of this information.

---

## 🚀 Ready to Start?

**Download the files:**

📥 [**port_scan.py**](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/portscan/port_scan.py) - My Solution to this challenge  
📥 [**grade_port_scanner.py**](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/portscan/grade_port_scanner.py) - Auto-grader with 60 tests

**Or use the command line:**

```bash
# Option 1: Clone the entire repo
git clone https://github.com/fosres/AppSec-Exercises.git
cd AppSec-Exercises/netsec/portscan

# Option 2: Download just these two files
curl -O https://raw.githubusercontent.com/fosres/AppSec-Exercises/main/netsec/portscan/port_scan.py
curl -O https://raw.githubusercontent.com/fosres/AppSec-Exercises/main/netsec/portscan/grade_port_scanner.py

# Implement your solution
vim your_port_scan_solution.py

# Get graded
python3 grade_port_scanner.py
```

**⭐ Star the repo if this challenge helped you!** ⭐

It's free, takes 2 seconds, and helps others discover these security exercises.

🔗 **Repository:** [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)

---

## 📚 More Free Security Challenges

This is part of a comprehensive security engineering curriculum. All challenges include:
- ✅ Auto-graders with 60+ tests
- ✅ Real-world scenarios
- ✅ Detailed feedback
- ✅ No paywalls, 100% free

**Browse all challenges:**
📂 [View all exercises on GitHub](https://github.com/fosres/AppSec-Exercises/tree/main/netsec)

**This challenge:**
📂 [Week 1: Port Scanner](https://github.com/fosres/AppSec-Exercises/tree/main/netsec/portscan)

**Repository:** ⭐ [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises) ⭐

---

## 💬 Discussion

**Questions? Got stuck?** Comment below or open a GitHub issue!

**Passed the challenge?** Share your:
- Final score (X/60)
- Time taken
- Trickiest test case
- "Aha!" moments

**Found a bug in the grader?** PRs welcome! This is a community project.

---

**Part of:** Security Engineering Exercise Series  
**Author:** [@fosres](https://github.com/fosres)  
**Repository:** ⭐ [AppSec-Exercises](https://github.com/fosres/AppSec-Exercises) ⭐  
**Dev.to:** [@fosres](https://dev.to/fosres)  

---

### Other Resources

**Reference Documentation:**
- [Python socket module](https://docs.python.org/3/library/socket.html)
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
- [RFC 793: TCP Specification](https://tools.ietf.org/html/rfc793)
- [Nmap source code](https://github.com/nmap/nmap) - Learn from the best

**Recommended Books:**
- "Full Stack Python Security" by Dennis Byrne (Chapter 12)
- "Hacking APIs" by Corey Ball (Chapter 3)
- "Python Workout" by Reuven Lerner (Exercise format inspiration)

---

🎯 **Challenge accepted?** Drop your score below! Let's see who gets 60/60! 🎯
