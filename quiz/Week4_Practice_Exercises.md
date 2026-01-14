# Week 4 Security Engineering Practice Exercises
## Based on ACME Product Security Tech Test

**Curriculum Reference**: Complete 48-Week Security Engineering Curriculum, Weeks 1-4 (pp. 3-20)  
**Target Completion**: End of Week 4 (January 12, 2026)  
**Estimated Time**: 3 hours (simulates timed tech test conditions)

---

## Overview

These exercises are derived from the ACME Product Security Tech Test format and aligned with skills you should have developed by the end of Week 4 of your curriculum:

| Week | Topics Covered | Relevant Exercises |
|------|----------------|-------------------|
| 1 | TCP/IP, OSI Model, OWASP Top 10, Python Basics | Q2, Q3 (partial), Q4 |
| 2 | DNS, TLS/Certificates, SQL Injection Fundamentals | Q4, Q6 |
| 3 | Firewalls, VPN, Network Segmentation, Burp Suite | Q8 |
| 4 | Linux Internals, iptables, System Hardening, Forensics | Q1, Q7 (partial), Q8 |

**References Used**:
- *API Security in Action* by Neil Madden, Chapter 2: "Secure API Development" (pp. 47-49) - Buffer overflows, input validation, injection attacks
- *Complete 48-Week Security Engineering Curriculum* (pp. 3-20) - Weeks 1-4 content
- *OWASP Top 10 2021* - A03: Injection, A10: SSRF

---

## Exercise 1: C Memory Safety Code Review

**Curriculum Alignment**: Week 4 - Linux Internals, Common Linux Attacks  
**Source**: *API Security in Action*, Chapter 2, pp. 47-48 (Buffer Overflow definition and RCE explanation)

### Scenario

You are reviewing file server code written in C. The engineering team needs a security assessment before deployment.

```c
#include <stdlib.h>
#include <string.h>

char *deserialize(const char *s) {
	size_t len = strnlen(s, 4096);
	char *b = (char *) malloc(len);
	strcpy(b, s);
	return b;
}
```

### Questions

**1a. Vulnerability Identification** (5 points)

Identify ALL vulnerabilities present in this code. For each vulnerability:
- Name the vulnerability class: Buffer Overflow
- Explain the root cause: 

The following line causes the vulnerability:

```
	strcpy(b, s);
```

- Describe potential impact:

An attacker can exploit this vulnerability to launch a shellcode

exploit--which could further lead to arbitrary code execution.

**1b. Exploitation Strategy** (5 points)

For each vulnerability identified:
- Describe how an attacker could exploit it:

An attacker can send a string longer than the max capacity of

buffer `b` as buffer `s`--including a shellcode exploit.

- What prerequisites does the attacker need?

Claude we agree to skip this question due to redundancy.

- What is the worst-case outcome?

As explained previously the attacker can launch a shellcode exploit.

If the attacker succeeds the attacker can even spawn a shell allowing

for arbitrary code execution.

**1c. Mitigations** (5 points)

Propose secure alternatives for this code. Address:
- Memory allocation strategy
- String handling approach
- Input validation requirements

### Expected Knowledge

By Week 4, you should understand:
- Buffer overflow mechanics (*API Security in Action*, p. 48)
- Difference between `strnlen()` and `strlen()` behavior
- Off-by-one errors in C string handling
- Why memory-safe languages prevent these issues

The following is the fixed code snippet:

```
#include <stdlib.h>
#include <string.h>

char *deserialize(const char *s,size_t slen) {

	if ( slen == 0 )
	{
		fprintf(stderr,"Error: slen is 0\n");

		return NULL;
	}	

	char *b = (char *) calloc(slen+1,sizeof(char));

	snprintf(b,slen,"%s",a);
	
	return b;
}
```
---

## Exercise 2: Python Command Injection Code Review

**Curriculum Alignment**: Week 2 - SQL Injection Fundamentals (injection patterns), Week 4 - Python Files  
**Source**: *API Security in Action*, Chapter 2, pp. 43-47 (Injection attacks and input validation)

### Scenario

The engineering team rewrote the file server in Python. Review this code for security issues.

```python
import subprocess

def get_file(file):

	# OS Command Injection Vulnerability below
	path = subprocess.check_output(f"find . -name '{file}'", shell=True)
	with open(path, "rb") as f:
		return f.read()
```

### Questions

**2a. Vulnerability Identification** (5 points)

Identify ALL vulnerabilities in this code:
- Name each vulnerability class (use OWASP terminology where
  applicable):

The code snippet is vulnerable to OS Command Injection.

- Explain why Python doesn't automatically prevent these issues
- What is the blast radius of successful exploitation?

**2b. Exploitation Payloads** (5 points)

Construct THREE different attack payloads that exploit this code:
1. A payload that reads `/etc/passwd`
2. A payload that creates a reverse shell
3. A payload that exfiltrates data to an external server

**2c. Secure Rewrite** (5 points)

Rewrite this function securely using:
- No shell=True
- Proper input validation
- Path traversal prevention

### Expected Knowledge

By Week 4, you should understand:
- Command injection vs SQL injection similarities
- Why `shell=True` is dangerous
- Input validation strategies from OWASP

---

## Exercise 3: SSRF Vulnerability Identification

**Curriculum Alignment**: Week 1 - OWASP Top 10 (A10: SSRF) - *Awareness Level Only*  
**Full Exploitation Skills**: Week 8 (PortSwigger SSRF Labs)  
**Source**: *OWASP Top 10 2021* - A10: Server-Side Request Forgery

### Scenario

The team integrated a third-party file server. Review this integration code.

```python
import requests

_FILE_SERVER = "http://files.local"
_ACCESS_KEY = "aGVsbG8gd29ybGQK"

def get_file(file):
	url = f"{_FILE_SERVER}{file}?accesskey={_ACCESS_KEY}"
	return requests.get(url).content
```

### Questions (Week 4 Scope)

**3a. Vulnerability Identification** (5 points)

Identify the security issues you can recognize from your OWASP Top 10 overview:
- What vulnerability class from OWASP Top 10 2021 does this represent?
- What is the basic concept of this vulnerability? (server makes requests based on user input)
- What secondary issue exists with the `_ACCESS_KEY` variable?

**3b. Basic Risk Assessment** (5 points)

Without detailed exploitation knowledge, assess:
- Why is it dangerous for a server to make HTTP requests based on user input?
- What types of internal resources might an attacker try to access?
- Why is the hardcoded access key a problem?

**3c. Conceptual Mitigations** (5 points)

Propose high-level mitigations based on your OWASP knowledge:
- How should user input be validated before making requests?
- What network-level controls might help?
- How should the access key be handled?

### What You'll Learn in Week 8

*Note: The following exploitation techniques are covered in Week 8 PortSwigger SSRF Labs:*
- Accessing cloud metadata services (169.254.169.254)
- Internal port scanning via SSRF
- SSRF filter bypass techniques (blacklist/whitelist evasion)
- Blind SSRF with out-of-band detection

### Expected Knowledge (Week 4)

By Week 4, you should understand:
- SSRF is A10 in OWASP Top 10 2021
- Basic concept: server makes requests on behalf of attacker
- Recognition of obvious SSRF patterns in code
- General principle that user input should not control server-side requests

---

## Exercise 4: SQL Injection Authentication Bypass

**Curriculum Alignment**: Weeks 1-4 - SQL Injection Labs (PortSwigger Labs 1-20)  
**Source**: *API Security in Action*, Chapter 2, pp. 43-47 (SQL Injection section)

### Scenario

The team added authentication to the file server. Review the login code.

```python
import sqlite3

_DATABASE = "users.db"

def authenticate_user(username, password):
	cursor = sqlite3.connect(_DATABASE).cursor()
	cursor.execute(f"select password, allowed_files from users where username = '{username}'")
	expected_password, allowed_files = cursor.fetchone()
	if password != expected_password:
		raise Exception(f"Invalid password")
	return allowed_files
```

### Questions

**4a. Vulnerability Identification** (5 points)

Identify the SQL injection vulnerability:
- What type of SQL injection is this? (Error-based, Blind, UNION, etc.)
- Why is string formatting dangerous here?
- What additional issues exist beyond SQLi?

**4b. Exploitation Scenarios** (10 points)

Write SQL injection payloads to accomplish:
1. Bypass authentication entirely
2. Extract all usernames and passwords using UNION
3. Enumerate table names
4. Modify allowed_files for your user
5. Delete the users table (if permissions allow)

**4c. Parameterized Query Rewrite** (5 points)

Rewrite this function using:
- Parameterized queries (prepared statements)
- Proper password hashing verification (assume passwords are stored as bcrypt hashes)
- Secure connection handling

### Expected Knowledge

By Week 4, you should have completed:
- 20 PortSwigger SQL injection labs
- SQL Injection Prevention Cheat Sheet from OWASP
- Understanding of parameterized queries

---

## Exercise 5: JWT Implementation Security Review

**Curriculum Alignment**: Week 2 - TLS/Cryptography Basics  
**Source**: *API Security in Action*, Chapters 5-6 (Token-based authentication)

### Scenario

The team implemented JWT-based sessions. Review the token generation and verification code.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

secret_key = Ed25519PrivateKey.generate()
public_key = secret_key.public_key()

def get_token(username, password):
	allowed_files = authenticate_user(username, password)

	jwt = { "user": username, "files": allowed_files }
	data = jwt["user"]
	data += jwt["files"][0]
	sig = secret_key.sign(data)
	jwt["sig"] = sig
	return jwt

def verify_token(jwt):
	data = jwt["user"]
	data += jwt["files"][0]
	assert public_key.verify(jwt["sig"], data)
	return jwt["user"], jwt["files"]
```

### Questions

**5a. Cryptographic Weaknesses** (5 points)

Identify ALL cryptographic and implementation issues:
- What data is actually being signed?
- What data is NOT being signed but returned?
- How could an attacker manipulate unsigned fields?

**5b. Token Manipulation Attack** (5 points)

Demonstrate how an attacker could:
1. Expand their file access beyond what was authorized
2. Access files belonging to other users
3. Achieve privilege escalation

**5c. Secure JWT Implementation** (5 points)

Propose a secure implementation that:
- Signs ALL claims in the token
- Uses standard JWT format with proper serialization
- Includes expiration and replay protection

### Expected Knowledge

By Week 4, you should understand:
- Digital signature basics from Week 2 TLS studies
- Why signing only partial data is dangerous
- Standard JWT structure (header.payload.signature)

---

## Exercise 6: TLS Certificate Analysis

**Curriculum Alignment**: Week 2 - TLS/Certificate Security  
**Source**: Week 2 curriculum - TLS handshake, certificate analysis, SSL Labs

### Scenario

The engineering team deployed HTTPS but has certificate issues. Analyze this certificate.

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            04:50:8c:6e:7e:70:c2:ee:26:7e:9f:ea:43:92:6c:97:d4:8e:d5:68
        Signature Algorithm: md5WithRSAEncryption
        Issuer: C = US, ST = California, O = ACME, OU = Engineering, CN = files.acme.com
        Validity
            Not Before: Feb  1 08:00:31 2023 GMT
            Not After : Feb  1 08:00:31 2024 GMT
        Subject: C = US, ST = California, O = ACME, OU = Engineering, CN = files.acme.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
```

### Questions

**6a. Certificate Problems** (10 points)

Identify ALL security issues with this certificate:
- Algorithm weaknesses
- Key size issues
- Validity period problems
- Trust chain issues
- CA flag implications

**6b. Attack Scenarios** (5 points)

For each weakness identified:
- What attack does it enable?
- What tools would an attacker use?
- What is the likelihood of successful exploitation?

**6c. Certificate Requirements** (5 points)

Specify requirements for a secure replacement certificate:
- Minimum key size
- Acceptable signature algorithms
- Validity period best practices
- Proper CA/trust chain configuration

### Expected Knowledge

By Week 4, you should understand:
- TLS certificate structure from Week 2
- Deprecated algorithms (MD5, SHA-1)
- Minimum RSA key sizes (2048-bit minimum)
- Self-signed vs CA-signed certificates

---

## Exercise 7: Basic File Analysis and Forensic Artifacts

**Curriculum Alignment**: Week 4 - Linux Forensics Basics  
**Full Malware Analysis Skills**: Week 12 (Ghidra, x86 Assembly, YARA)  
**Source**: Week 4 curriculum - Log files, command history, file timestamps, finding modified files

### Scenario

A suspicious file was found on the server. Perform initial triage using Week 4 skills.

```
/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4AI5AexdAD2IiaczqOaooQTUvYvrOTtlBM046l0zq3OWGNHrTbAOi96Co4nh+rjwB/eS
XwPZixupEx+2fybd37UvRxdXqaiQU4TMTMfhh8Znvu2dB6V9FNyNnnLlcOGR83ZvdtIjIFL0Lo70fMMkXCFgyXFTgIde6Zd/J5oN
vziyxA3Y79lbWLDwASuLwVF45lclGAahtm9cJN8y4tFc4DW0xv0XxppTHsjgNTUW93KusEsI6b8p8ArUkz1Pvyas4DPY2RGPLCXe
LzIfbv3fFZ/obm1Und0OLuftaAunWCYRv7F5B15zW+rwNGbxrwLrw+/hBowBr6bB6ALKPl2YfBKXZ8bCh4J0BzpKT4iFTvzNSJCK
B7/yWK6pJHSnf7Otpa27YNyzzmRV4TVQuDAs7fSHa3OGR//Y8QqU6EumjrPud3QlXTh7jD3zSnfsBplTBoG0wijrd6MHmkauLPtA
nyy+KpCmVsIqQvHKhXxS2Zdo1Dk9pjGqY6/UkgTmjO0oxQ3zsweCU3WekW/trjVUUlUT8w+koXBqZAugVXggMThMLZYh6hzCxiwq
I+AQt5h+29V/cj2j8FNYv3KDaEA7AYR2j0M9ZRBs+7Fzh1qklrBlKheUMgyC8kw2LgBqUc62E8/BiJiOhKJ7ZE0VO6ZEnMOMAAC1
67rGYwT5OgABiAS6BAAAiuLwsbHEZ/sCAAAAAARZWg==
```

### Questions (Week 4 Scope)

**7a. Initial File Identification** (5 points)

Using basic Linux forensics commands, determine:
- Decode the base64: `echo "<blob>" | base64 -d > suspicious_file`
- Use `file suspicious_file` to identify the file type
- Use `xxd suspicious_file | head` to examine magic bytes
- Use `strings suspicious_file` to extract readable content
- Document your methodology step-by-step

**7b. Forensic Artifact Collection** (5 points)

If this file was found on a compromised server, what forensic artifacts would you collect using Week 4 skills?
- Which log files would you examine? (`/var/log/auth.log`, `/var/log/syslog`, etc.)
- How would you find recently modified files? (`find / -mtime -1`)
- What timestamps would you check? (atime, mtime, ctime)
- How would you check command history? (`.bash_history`)

**7c. Basic Containment Recommendations** (5 points)

Based on finding a suspicious file, what immediate actions would you recommend?
- Should the system be isolated from the network?
- What evidence should be preserved before any remediation?
- Who should be notified?

### What You'll Learn in Week 12

*Note: The following malware analysis techniques are covered in Week 12:*
- Ghidra reverse engineering
- x86 assembly analysis
- PE header analysis
- YARA rule creation
- Dynamic analysis in sandboxes
- Behavioral analysis (file system, registry, network monitoring)

### Expected Knowledge (Week 4)

By Week 4, you should be able to:
- Decode base64 encoded files
- Use `file` command to identify file types
- Use `strings` to extract readable content
- Know which Linux log files to examine
- Find recently modified files with `find`
- Understand file timestamps (atime, mtime, ctime)

---

## Exercise 8: iptables Firewall Troubleshooting

**Curriculum Alignment**: Week 3-4 - Firewalls, iptables, Network Segmentation  
**Source**: Week 4 curriculum - iptables packet filtering rules, chains (INPUT, OUTPUT, FORWARD)

### Scenario

The file server has iptables configured but clients cannot connect. Debug the configuration.

**Network Topology**:
```
Client (192.168.1.145) → Router/NAT (192.168.1.1 / 104.44.226.100) → Router (104.44.226.150 / 20.141.12.1) → File Server (20.141.12.34)
```

**Current iptables Rules**:
```
Chain INPUT (policy DROP)
target    prot   opt    source           destination
ACCEPT    all    --     anywhere         anywhere       ctstate RELATED,ESTABLISHED
ACCEPT    tcp    --     anywhere         20.141.12.34   tcp dpt:https
ACCEPT    tcp    --     192.168.1.145    20.141.12.34   tcp dpt:ssh

Chain OUTPUT (policy ACCEPT)
target    prot   opt    source           destination
ACCEPT    all    --     anywhere         anywhere       ctstate ESTABLISHED
```

### Questions

**8a. ICMP/Ping Failure** (5 points)

The client cannot ping the server. Diagnose and fix:
- Why does ping fail?
- What protocol does ping use?
- Write the iptables rule to allow ping
- Are there security implications to allowing ICMP?

**8b. SSH Connection Failure** (5 points)

The client cannot SSH to the server. Diagnose and fix:
- The SSH rule exists but doesn't work - why?
- What happens to the source IP after NAT?
- Write corrected iptables rules for SSH access
- What is a more secure alternative to IP-based access control?

**8c. Firewall Best Practices** (5 points)

Propose a complete, secure iptables configuration for this file server:
- HTTPS access from anywhere
- SSH access from internal network only
- ICMP rate-limited
- Logging for denied connections
- Defense against common attacks

### Expected Knowledge

By Week 4, you should understand:
- iptables chains (INPUT, OUTPUT, FORWARD)
- Connection tracking (ESTABLISHED, RELATED, NEW)
- NAT and how it affects source IP addresses
- ICMP vs TCP protocol differences

---

## Scoring Guide

| Exercise | Topic | Max Points | Week 4 Scope |
|----------|-------|------------|--------------|
| 1 | C Memory Safety | 15 | Full |
| 2 | Python Command Injection | 15 | Full |
| 3 | SSRF | 15 | Identification Only (Exploitation in Week 8) |
| 4 | SQL Injection | 20 | Full |
| 5 | JWT Security | 15 | Full |
| 6 | TLS Certificates | 20 | Full |
| 7 | File Analysis/Forensics | 15 | Basic Triage Only (Full Analysis in Week 12) |
| 8 | iptables Firewall | 15 | Full |
| **Total** | | **130** | |

**Passing Score**: 100/130 (77%)  
**Target Score for Interviews**: 115/130 (88%)

---

## Curriculum Alignment Summary

### Exercises You Should Fully Complete by Week 4:
- **Exercise 1**: C Memory Safety (Week 4 Linux Internals)
- **Exercise 2**: Python Command Injection (Weeks 2-4 Injection patterns)
- **Exercise 4**: SQL Injection (20 PortSwigger labs by Week 4)
- **Exercise 5**: JWT Security (Week 2 TLS/Crypto basics)
- **Exercise 6**: TLS Certificates (Week 2 certificate analysis)
- **Exercise 8**: iptables (Weeks 3-4 firewall configuration)

### Exercises with Partial Week 4 Coverage:
- **Exercise 3**: SSRF - You can identify the vulnerability class and propose basic mitigations, but detailed exploitation techniques come in Week 8
- **Exercise 7**: Forensics - You can do initial file triage (decode, identify type, extract strings) and collect forensic artifacts, but full malware reverse engineering comes in Week 12

---

## Self-Assessment Checklist

After completing these exercises, verify you can:

- [ ] Identify buffer overflow vulnerabilities in C code
- [ ] Recognize command injection in Python subprocess calls
- [ ] Identify SSRF as an OWASP Top 10 vulnerability (A10)
- [ ] Write SQL injection payloads and parameterized queries
- [ ] Analyze JWT implementations for cryptographic weaknesses
- [ ] Evaluate TLS certificates for security issues
- [ ] Perform basic file identification using `file`, `strings`, `xxd`
- [ ] Collect forensic artifacts from Linux systems
- [ ] Debug and configure iptables firewall rules

---

## Additional Resources

**For Exercise 1 (C Memory Safety)**:
- *API Security in Action*, Chapter 2, pp. 47-49
- CWE-120: Buffer Copy without Checking Size of Input

**For Exercises 2-4 (Injection Attacks)**:
- *API Security in Action*, Chapter 2, pp. 43-47
- OWASP Injection Prevention Cheat Sheet
- PortSwigger SQL Injection Labs

**For Exercise 5 (JWT Security)**:
- *API Security in Action*, Chapters 5-6
- RFC 7519 (JSON Web Tokens)

**For Exercise 6 (TLS Certificates)**:
- SSL Labs documentation
- Mozilla SSL Configuration Generator

**For Exercise 7 (Forensics - Week 4 Scope)**:
- Week 4 curriculum: Linux Forensics Basics (pp. 13-14)
- `file`, `strings`, `xxd` command documentation

**For Exercise 8 (iptables)**:
- Week 4 curriculum: iptables section (p. 13)
- NIST SP 800-41r1: Guidelines on Firewalls

---

*Document generated based on ACME Product Security Tech Test format*  
*Aligned with Complete 48-Week Security Engineering Curriculum, Weeks 1-4*  
*Version 2: Corrected scope for Exercises 3 and 7*
