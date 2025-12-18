# Week 1 Port Scanner Specification

**Target Audience:** Week 1 Security Engineering Students  
**Python Level:** 5/10 (Basic proficiency, not advanced)  
**Time Budget:** 2-3 hours implementation + testing  
**Learning Focus:** Networking fundamentals, not Python mastery  

---

## What You're Building

A **basic TCP port scanner** that can scan a single port on a target host and report whether it's open, closed, or filtered. This is your first hands-on security tool - the foundation of network reconnaissance.

**Core Concept:** Try to establish a TCP connection to a port. The result tells you if a service is running there.

---

## Minimum Requirements

Your port scanner MUST be able to:

### 1. Accept Three Inputs
- **Target host** (hostname like "localhost" or IP like "127.0.0.1")
- **Port number** (integer between 1-65535)
- **Timeout** (how long to wait for connection, in seconds)

**Why this matters:** Real scanners need configurable timeouts - too short causes false negatives (filtered vs open), too long wastes time.

### 2. Detect Three Port States

**OPEN - Service is listening**
- TCP connection succeeds
- Example: Web server on port 80

**CLOSED - Nothing listening, but host responds**
- Connection gets actively refused
- (Hint: Try scanning a closed port and see what exception gets raised)

**FILTERED - Firewall blocking, no response**
- Connection times out
- (Hint: Try scanning with a very short timeout and see what happens)

**Why this matters:** These three states tell different security stories. OPEN = attack surface. CLOSED = service stopped. FILTERED = firewall present.

### 3. Return Structured Results

Return information in a **simple, consistent format**. At Week 1, keep it simple:

**RECOMMENDED: Return a tuple**
```python
# Simple tuple with (port, status)
return (80, "OPEN")
return (443, "CLOSED")
return (22, "FILTERED")
```

**OPTIONAL: Add more info with a longer tuple**
```python
# Tuple with (port, status, service_name)
return (80, "OPEN", "http")
return (22, "OPEN", "ssh")
return (999, "CLOSED", None)
```

**Why tuples?** Simple, built-in Python feature. No need to learn dictionaries yet.

**Minimum requirement:** Your function must return AT LEAST:
- The port number scanned
- The port status ("OPEN", "CLOSED", "FILTERED", or "ERROR")

**Why this matters:** Your results will be parsed by other tools or displayed to users. Consistent structure is essential.

### 4. Handle Basic Errors Gracefully

Your scanner should NOT crash when given:
- Invalid port numbers (negative, zero, > 65535)
- Invalid hostnames (DNS lookup fails)
- Network timeouts

**Why this matters:** Production security tools must handle bad input without dying. Real networks are messy.

---

## Optional But Recommended Features

These aren't required but will make your scanner more useful:

### Service Name Detection
Map common ports to service names:
- Port 80 → "http"
- Port 443 → "https"  
- Port 22 → "ssh"
- Port 3306 → "mysql"

**Hint:** Python has `socket.getservbyport()` for this, or you can use if/elif statements:
```python
if port == 80:
	service = "http"
elif port == 443:
	service = "https"
elif port == 22:
	service = "ssh"
# ... etc
```

### Banner Grabbing
For OPEN ports, try to read the service banner (first 1024 bytes). Many services announce themselves:
- HTTP servers send headers
- SSH servers send version strings
- FTP servers send welcome messages

**Warning:** Some services won't send anything. Set a receive timeout or your scanner will hang.

### IPv6 Support
Handle IPv6 addresses like "::1" in addition to IPv4 like "127.0.0.1"

**Hint:** Python's socket library handles this if you use the right approach.

---

## What We DON'T Expect (Week 1)

You do NOT need to implement:

❌ **Multi-threaded scanning** - That's Week 3+ material  
❌ **UDP port scanning** - Different protocol, more complex  
❌ **SYN scanning** - Requires raw sockets and root privileges  
❌ **OS fingerprinting** - Advanced reconnaissance technique  
❌ **Command-line argument parsing** - Keep it simple, hardcode test values  
❌ **Fancy output formatting** - Plain print statements are fine  
❌ **Configuration files** - Not needed for Week 1  

Focus on getting the **core TCP connection logic** correct. Advanced features come later.

---

## Implementation Guidance

### Start Simple
1. Write a function that scans ONE port
2. Test it manually on localhost
3. Handle errors one by one as you discover them
4. Add features incrementally

### Safe Testing Targets

**PRIMARY: Test on Localhost First**
```python
# These should work on any machine:
scan("localhost", 80, timeout=1.0)    # Probably closed
scan("127.0.0.1", 22, timeout=1.0)    # Might be open (SSH)
scan("::1", 443, timeout=1.0)         # IPv6 localhost
```

**SECONDARY: Domains That Explicitly Allow Scanning**

The following domains have publicly stated they allow port scanning for educational purposes:

1. **scanme.nmap.org** (Official Nmap test server)
   - Maintained by the Nmap Security Scanner Project
   - Explicitly allows testing Nmap and other security tools
   - Policy: https://nmap.org/book/legal-issues.html
   ```python
   scan("scanme.nmap.org", 80, timeout=2.0)   # Usually OPEN (HTTP)
   scan("scanme.nmap.org", 22, timeout=2.0)   # Usually OPEN (SSH)
   scan("scanme.nmap.org", 443, timeout=2.0)  # Check HTTPS
   ```

2. **scanme.org** (Alternative Nmap test server)
   - Another test server maintained by Nmap project
   - Same permission policy as scanme.nmap.org
   ```python
   scan("scanme.org", 80, timeout=2.0)
   ```

⚠️ **IMPORTANT RESTRICTIONS:**
- **Rate Limiting:** Don't scan more than once per day per host
- **No Aggressive Scanning:** Use reasonable timeouts (1-2 seconds minimum)
- **Check Current Policy:** Policies can change - verify before scanning
- **Be Respectful:** These are free services provided by the security community

⚠️ **DO NOT SCAN WITHOUT PERMISSION:**
- ❌ Your employer's systems (unless you're on the security team)
- ❌ Your school's network (unless part of approved coursework)
- ❌ Cloud services (AWS, Google Cloud, Azure) you don't own
- ❌ Any website or service without explicit written permission

**For Week 1, stick to localhost.** You don't need external targets to learn socket programming - localhost is sufficient to test CLOSED and FILTERED states.

### Key Python Concepts You'll Use

**Socket creation:**
```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
```

**Setting timeout:**
```python
sock.settimeout(1.0)  # 1 second timeout
```

**Attempting connection:**
```python
sock.connect((host, port))  # Note: tuple!
```

**CRITICAL:** Always close your socket:
```python
sock.close()  # Or use try/finally to guarantee cleanup
```

---

## Example Function Signatures

Choose whatever makes sense to you. Here are three valid approaches:

### Option 1: Simple Tuple Return (RECOMMENDED for Week 1)
```python
def scan_port(host: str, port: int, timeout: float) -> tuple:
	"""
	Scan a single port, return (port, status).
	
	Returns:
		tuple: (port_number, status_string)
		Example: (80, "OPEN") or (443, "CLOSED")
	"""
	pass
```

### Option 2: Extended Tuple with Service Name
```python
def scan_port(host: str, port: int, timeout: float) -> tuple:
	"""
	Scan a single port, return (port, status, service).
	
	Returns:
		tuple: (port_number, status_string, service_name)
		Example: (80, "OPEN", "http") or (999, "CLOSED", None)
	"""
	pass
```

### Option 3: Multiple Return Values (Unpacking)
```python
def scan_port(host: str, port: int, timeout: float):
	"""
	Scan a single port, return multiple values.
	
	Usage:
		port, status, service = scan_port("localhost", 80, 1.0)
	"""
	pass
	# In your code, you'd return like this:
	# return port, status, service_name
```

**All three are acceptable.** Pick what feels natural. **Tuples are simplest for Week 1.**

---

## Edge Cases to Consider

As you implement, think about these scenarios:

### Input Validation
- What if port is -1? Or 0? Or 70000?
- What if timeout is negative? Or zero?
- What if hostname is empty string?

### Network Conditions
- What if DNS lookup fails? (host doesn't exist)
- What if connection hangs forever? (need timeout)
- What if you scan port 80 but nothing is listening?

### Resource Management
- Are you closing sockets after each scan?
- What happens if you scan 1000 ports in a loop? (file descriptor leak?)

### Cross-Platform
- Does it work on Linux? macOS? Windows?
- Does it handle both IPv4 and IPv6?

You don't need to solve ALL of these perfectly, but think about them.

---

## Success Criteria

Your port scanner is successful if it can:

1. ✅ Scan localhost port 80 and report CLOSED (assuming no web server)
2. ✅ Scan a high port (55555) and report CLOSED or FILTERED
3. ✅ Handle invalid port numbers without crashing
4. ✅ Timeout on filtered ports instead of hanging forever
5. ✅ Return consistent results every time

**Bonus points if:**
- It maps common ports to service names
- It grabs banners from open services
- It supports both IPv4 and IPv6
- It validates all inputs before attempting connections

---

## Common Mistakes to Avoid

### 🚫 Mistake 1: Not Closing Sockets
```python
def scan_port(host, port, timeout):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((host, port))
	# Forgot to close socket! 💀
	return result
```
**Problem:** After 1024 scans, your OS runs out of file descriptors.

**Fix:** Use `try...finally` or context managers (`with` statement).

### 🚫 Mistake 2: Catching Exception Too Broadly
```python
try:
	sock.connect((host, port))
	return "OPEN"
except Exception:  # Too generic!
	return "ERROR"
```
**Problem:** Can't distinguish different failure types.

**Fix:** You need to figure out which specific exceptions to catch and how to handle each one differently. Experiment and see what gets raised!

### 🚫 Mistake 3: No Timeout
```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))  # Hangs forever on filtered ports! ⏰
```
**Problem:** Filtered ports will block indefinitely.

**Fix:** Always call `sock.settimeout(timeout_value)` before connecting.

### 🚫 Mistake 4: Forgetting the Tuple
```python
sock.connect(host, port)  # ❌ WRONG - TypeError!
```
**Fix:** Connection address must be a tuple:
```python
sock.connect((host, port))  # ✅ CORRECT - note the parentheses!
```

### 🚫 Mistake 5: No Input Validation
```python
def scan_port(host, port, timeout):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((host, port))  # Crashes on port=99999! 💥
```
**Fix:** Validate port range (1-65535) BEFORE attempting connection.

---

## Testing Your Scanner

### Manual Testing (Do This First)

**Phase 1: Localhost Testing (Required)**
```python
# Test 1: Closed port on localhost
result = scan_port("localhost", 12345, 1.0)
print(result)  # Should show CLOSED - e.g., (12345, "CLOSED") or (12345, "CLOSED", None)

# Test 2: Another closed port (high number)
result = scan_port("127.0.0.1", 54321, 1.0)
print(result)  # Should show CLOSED - e.g., (54321, "CLOSED")

# Test 3: Invalid port
result = scan_port("localhost", 99999, 1.0)
print(result)  # Should handle gracefully - e.g., (99999, "ERROR")

# Test 4: Negative port
result = scan_port("localhost", -1, 1.0)
print(result)  # Should handle gracefully - e.g., (-1, "ERROR")

# Test 5: DNS failure
result = scan_port("thisdomaindoesnotexist123.com", 80, 1.0)
print(result)  # Should handle gracefully - e.g., (80, "ERROR")

# Test 6: IPv6
result = scan_port("::1", 80, 1.0)
print(result)  # Should work - e.g., (80, "CLOSED")
```

**Phase 2: Real Target Testing (Optional, After localhost works)**

Only proceed if your localhost tests pass. Use **scanme.nmap.org** (official Nmap test server):

```python
# Test 7: Open HTTP port (real target)
result = scan_port("scanme.nmap.org", 80, 2.0)
print(result)  # Should show OPEN - e.g., (80, "OPEN", "http")

# Test 8: Open SSH port (real target)
result = scan_port("scanme.nmap.org", 22, 2.0)
print(result)  # Should show OPEN - e.g., (22, "OPEN", "ssh")

# Test 9: Closed/Filtered port (real target)
result = scan_port("scanme.nmap.org", 8080, 2.0)
print(result)  # Might be CLOSED or FILTERED - e.g., (8080, "CLOSED") or (8080, "FILTERED")
```

**⚠️ Testing Etiquette:**
- Test scanme.nmap.org **at most once per day**
- Use timeout ≥ 2.0 seconds (be polite)
- Don't scan all 65,535 ports (rate limiting)
- If you get errors, wait 24 hours before trying again

### What to Look For
- ✅ No crashes on bad input
- ✅ Returns consistent tuple structure (same number of elements every time)
- ✅ Completes within timeout period
- ✅ Distinguishes CLOSED from FILTERED correctly

### When You're Ready
Upload your implementation here and I'll create a comprehensive test suite (60+ tests) that:
- Validates your design works correctly
- Identifies any bugs or edge cases you missed
- Tests security best practices (resource cleanup, error handling)
- Gives you detailed feedback on your code quality

---

## Learning Objectives (Week 1)

By implementing this port scanner, you will:

### Networking Concepts
- ✅ Understand TCP 3-way handshake (SYN, SYN-ACK, ACK)
- ✅ Learn difference between CLOSED and FILTERED ports
- ✅ Experience socket programming fundamentals
- ✅ Handle network timeouts and errors

### Python Skills
- ✅ Use the `socket` module
- ✅ Handle multiple exception types
- ✅ Manage resources properly (socket cleanup)
- ✅ Return structured data from functions

### Security Mindset
- ✅ Understand reconnaissance methodology
- ✅ Learn how attackers map attack surface
- ✅ Think about input validation and error handling
- ✅ Consider resource exhaustion (file descriptor limits)

---

## References for Help

### Official Documentation
- **Python socket module:** https://docs.python.org/3/library/socket.html
- Look for: `socket.socket()`, `connect()`, `settimeout()`, exception types

### Your Week 1 Reading
- **Beej's Guide to Network Programming** (Simple Stream Client section)
- **HPBN Chapter 2** (TCP fundamentals)

### When You Get Stuck
- Google: "Python socket detect closed port"
- Google: "Python socket connection refused vs timeout"
- Ask me (Claude) for help with specific errors or concepts

---

## Legal Reminder

⚠️ **IMPORTANT:** Only scan systems you own or have explicit permission to scan.

Unauthorized port scanning may violate:
- **Computer Fraud and Abuse Act (CFAA)** - U.S. federal law criminalizing unauthorized access
- **Terms of Service agreements** - Many cloud providers explicitly prohibit scanning
- **Network usage policies** - Schools and employers often ban security testing
- **International laws** - Other countries have similar computer security laws

**Legal Targets for This Exercise:**
1. ✅ **localhost / 127.0.0.1 / ::1** - Your own machine (always legal)
2. ✅ **scanme.nmap.org / scanme.org** - Explicitly allows testing (see Nmap Legal Issues page)
3. ✅ **Your own VMs/containers** - Systems you personally own and control

**Illegal Without Written Permission:**
- ❌ Your employer's production systems
- ❌ Your school's network infrastructure
- ❌ Cloud services (AWS, GCP, Azure) you don't own
- ❌ ANY external website, server, or network

**Case Law Example:** In *United States v. Morris (1991)*, Robert Morris was convicted under CFAA for releasing the Morris Worm, which performed port scanning as part of its reconnaissance. Port scanning was considered unauthorized access.

**When in doubt, ask permission in writing.**

**Sources:**
- Nmap Legal Issues: https://nmap.org/book/legal-issues.html
- 18 U.S.C. § 1030 (CFAA): https://www.law.cornell.edu/uscode/text/18/1030

---

## Ready to Build?

**Your mission:**
1. Implement a `scan_port()` function (or whatever you want to call it)
2. Test it manually on localhost with various ports
3. Make sure it handles errors gracefully
4. Upload your code here

**I'll then:**
1. Create 60+ test cases tailored to YOUR implementation
2. Identify any bugs or edge cases you missed
3. Suggest improvements and optimizations
4. Grade your security practices

**No pressure to be perfect.** This is Week 1 - the goal is learning, not perfection. Write the best scanner you can, and we'll improve it together.

Good luck! 🚀

---

**Part of:** Week 1 Networking Fundamentals  
**Curriculum:** 48-Week Security Engineering Interview Prep  
**Estimated Time:** 2-3 hours for initial implementation
