---
title: "The Port Numbers Every AppSec Engineer Must Know (And Why Interviewers Love Asking About Them)"
published: false
description: "Master the 10 critical port numbers that appear in every Security Engineering interview - with 40 hands-on exercises and real nmap scenarios"
tags: appsec, security, networking, career
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ports-security-banner.png
series: AppSec Interview Prep
---

## Why Port Numbers Are More Than Just Memorization

Port numbers seem like trivia until you're in a Security Engineering interview.

**Common interview question:** "You see traffic on port 3389 from multiple international IPs at 2 AM. What's happening?"

If you can't answer instantly, you're done.

Here's the truth: **Port numbers aren't trivia. They're the language of network security.**

When you're analyzing logs, investigating incidents, or building security tools, you need to recognize ports *instantly*. No Googling. No hesitation. You see "443" and your brain immediately thinks "HTTPS, encrypted, check the cert."

This blog post covers the **10 critical ports** that appear in every AppSec interview - plus the `nmap` concepts that separate junior engineers from seniors.

---

## Why Port Numbers Matter for Security Engineers

### Real-World Scenario: The Telnet Disaster

In 2019, a Fortune 500 company got breached because a developer left **port 23 (Telnet)** open during testing.

The attacker:
1. Scanned for open port 23
2. Connected and saw **plaintext credentials** in transit
3. Gained admin access to production systems
4. Exfiltrated 2TB of customer data

**Cost:** $47M in damages + regulatory fines

**If the security team had known:** Port 23 = Telnet = Never use in production = Always SSH (port 22) instead

---

## The 10 Ports You MUST Memorize

Every Security Engineering interview expects you to know these cold:

| Port | Service | Protocol | Security Note |
|------|---------|----------|---------------|
| **22** | SSH | TCP | Secure remote access (replaces Telnet) |
| **23** | Telnet | TCP | **NEVER USE** - plaintext credentials |
| **25** | SMTP | TCP | Sends emails (not receives!) |
| **53** | DNS | TCP/UDP | Only port using BOTH protocols |
| **80** | HTTP | TCP | Plaintext web traffic |
| **110** | POP3 | TCP | Receives emails (downloads, deletes) |
| **143** | IMAP | TCP | Receives emails (syncs, keeps on server) |
| **443** | HTTPS | TCP | Encrypted web traffic (TLS) |
| **3389** | RDP | TCP | Remote Desktop (high-value target) |
| **20/21** | FTP | TCP | File transfer (21=control, 20=data) |

### Critical Interview Pattern

**Interviewers love testing email protocols because most candidates confuse them:**

❌ **WRONG:** "Port 143 is for sending and receiving emails"  
✅ **RIGHT:** "Port 25 (SMTP) sends. Port 110 (POP3) and 143 (IMAP) receive."

**The mental model:**
- **SMTP (port 25)** = Postal truck (delivers mail TO mailbox)
- **POP3 (port 110)** = Take mail, empty mailbox
- **IMAP (port 143)** = View mail, keep in mailbox

---

## nmap States: Open vs Closed vs Filtered

Here's where junior engineers fail technical screens: **misunderstanding `nmap` output.**

### The Three States

When you run `nmap -p 22 192.168.1.100`, you'll see one of three states:

#### 1. **"22/tcp open"**
- **Meaning:** Service is listening and accepting connections
- **Action:** Investigate further (is SSH configured securely?)
- **Interview answer:** "Port is open, I'd verify SSH key-only auth and check for weak ciphers"

#### 2. **"22/tcp closed"**
- **Meaning:** Nothing is listening, host responded with RST (reset) packet
- **Action:** This is GOOD - port is secure
- **Interview answer:** "Port is closed, no service running, this is the desired state"

#### 3. **"22/tcp filtered"**
- **Meaning:** Firewall blocked the scan, can't determine if open/closed
- **Action:** Ambiguous - could be secure or could be hiding something
- **Interview answer:** "Firewall is blocking, need different scan techniques or access"

### Common Interview Trap

**Interviewer:** "You scan port 23 and see 'closed'. Is this good or bad?"

❌ **WRONG:** "Bad, the service is refusing connections"  
✅ **RIGHT:** "Good! 'Closed' means nothing is listening. We don't want Telnet running."

**Why this trips people up:** They think "closed" = "broken" when actually "closed" = "secure"

---

## Why You Need This For Your Port Scanner

Before you can build a production-grade port scanner (Week 6 of most AppSec curricula), you need to understand:

1. **What you're scanning for** - these 10 common ports
2. **What the results mean** - open/closed/filtered states
3. **What to do next** - security implications of each finding

**Example concept from a port scanner:**

When you scan a port and find it open, you need to know what service is running:
- Port 22 open → Investigate SSH configuration (key-only auth? weak ciphers?)
- Port 3389 open → Investigate RDP exposure (should never be on internet)
- Port 23 open → **CRITICAL** - Telnet should NEVER be running

**Without knowing port meanings, your scanner is just printing numbers.**

---

## Real Interview Questions I've Encountered

### Question 1: Email Security
**"Your company uses port 25 for outgoing mail and port 110 for incoming. A user's credentials were compromised. What protocol weakness allowed this?"**

**Answer:** Port 110 is POP3, which transmits credentials in plaintext. Should use **POP3S (port 995)** or **IMAP with TLS (port 993)** instead.¹

### Question 2: Privileged Ports
**"A developer tries to run a Flask app on port 80 and gets 'Permission denied'. Why?"**

**Answer:** Ports below 1024 are privileged ports on Unix/Linux, requiring root. Developer should use port 8080 (non-privileged) for development.²

### Question 3: Attack Detection
**"You see unusual traffic on port 3389 from 50 different IPs at 3 AM. What's happening?"**

**Answer:** Port 3389 is RDP (Remote Desktop Protocol). This is likely a **brute force attack** or **credential stuffing** attempt. Should block the IPs, enable account lockout policies, and never expose RDP directly to internet.

---

## How I Finally Memorized All 10 Ports

### The LLM Quiz Method

Use an LLM like Claude, ChatGPT, or Gemini to quiz you interactively:

**Example prompt:**
```
Quiz me on the 10 common port numbers used in Security Engineering:
22, 23, 25, 53, 80, 110, 143, 443, 3389, and 20/21.

Ask me 5 random questions at a time. After I answer, tell me which 
ones I got wrong and quiz me again on those specific ports until I 
get 100%.
```

**Why this works:**
- Adaptive learning - focuses on your weak areas
- Instant feedback - no waiting to flip cards
- Variety - LLM can ask questions in different ways
- Scalable - can quiz on 10 ports or 100 ports
- Interview simulation - mirrors actual interview questioning

**Advanced LLM prompts:**
```
Give me realistic Security Engineering interview scenarios involving 
ports 22, 3389, and 110. Include security implications.
```

```
I keep confusing SMTP, POP3, and IMAP. Quiz me specifically on email 
protocols until I can explain the difference perfectly.
```

### The Real-World Association Method

**Port 443 (HTTPS):** Every website you visit securely  
**Port 22 (SSH):** Every time you `ssh` to a server  
**Port 3389 (RDP):** Every Windows remote desktop session  
**Port 25 (SMTP):** Every email you SEND  
**Port 110/143:** Every email you RECEIVE

---

## Comprehensive Port Number Exercises

**Challenge yourself:** Try to complete all 40 exercises WITHOUT looking at the solutions. This is exactly how interviews work - no Googling, no hints, just your knowledge.

**Scoring:**
- 35-40 correct: Interview ready ✅
- 28-34 correct: Almost there - review weak areas
- 20-27 correct: Solid foundation - needs more practice
- < 20 correct: Focus on fundamentals first

These exercises mirror real Security Engineering interview questions. Try them without Googling - that's exactly how you'll be tested in interviews.

### Exercise Set 1: Basic Port Identification

**Fill in the blanks:**

1. Port **____**: HTTP
2. Port **____**: HTTPS  
3. Port **____**: SSH
4. Port **____**: RDP (Remote Desktop Protocol)
5. Port **____**: FTP (two port numbers)
6. Port **____**: Telnet
7. Port **____**: SMTP
8. Port **____**: DNS
9. Port **____**: POP3
10. Port **____**: IMAP

### Exercise Set 2: Protocol Specification

**Answer in format: Port X - Service - TCP/UDP:**

1. Port 20/21: ____ - ____
2. Port 22: ____ - ____
3. Port 23: ____ - ____
4. Port 25: ____ - ____
5. Port 53: ____ - ____
6. Port 80: ____ - ____
7. Port 110: ____ - ____
8. Port 143: ____ - ____
9. Port 443: ____ - ____
10. Port 3389: ____ - ____

### Exercise Set 3: Email Protocol Deep Dive

11. True or False: IMAP can send emails.

12. True or False: SMTP can receive emails.

13. Which protocol is used to SEND emails from your client to a mail server?
    a) POP3
    b) IMAP
    c) SMTP
    d) SSH

14. Which protocols are used to RECEIVE emails from a mail server? (Select all that apply)
    a) SMTP (port 25)
    b) POP3 (port 110)
    c) IMAP (port 143)
    d) All of the above

15. Fill in the blanks:
    - To SEND an email: Use ____ protocol on port ____
    - To RECEIVE an email: Use ____ or ____ protocols on ports ____ or ____

16. Complete the email flow:
    ```
    SENDING: Your client → _____ (port ___) → Mail server
    RECEIVING: Your client ← _____ or _____ (port ___ or ___) ← Mail server
    ```

17. Your company email uses port 25 for outgoing mail and port 143 for incoming mail. 
    - Outgoing uses: ____ protocol
    - Incoming uses: ____ protocol

18. What's the main difference between POP3 and IMAP in how they handle emails on the server?
    - POP3: ____
    - IMAP: ____

### Exercise Set 4: nmap State Interpretation

19. You run `nmap -p 3389 10.0.0.5` and get "3389/tcp closed"
    What does this mean?
    a) RDP service is running but refusing connections
    b) Nothing is listening on port 3389
    c) A firewall is blocking the scan
    d) The RDP service crashed

20. Which nmap state indicates "nothing is listening on this port"?
    a) open
    b) closed
    c) filtered
    d) refused

21. You're securing a server. You run nmap and see "23/tcp closed" for Telnet. Is this good or bad?
    - Good or Bad: ____
    - Why: ____

22. Match each scenario to the correct nmap state:
    - SSH service is running and accepting connections: ____
    - Nothing is listening on the port, host responded with RST: ____
    - Firewall dropped the packet, nmap can't tell: ____
    
    Options: open, closed, filtered

23. True or False: If nmap shows "closed", you should investigate because something suspicious is happening.

24. Rank these nmap states from MOST secure to LEAST secure:
    ____ → ____ → ____
    
    Options: open, closed, filtered

25. You scan port 22 on three servers:
    - Server A: "22/tcp open"
    - Server B: "22/tcp closed"  
    - Server C: "22/tcp filtered"
    
    Which server has SSH definitely NOT running?

### Exercise Set 5: Security Scenarios

26. You capture network traffic and see connections to port 110. The data appears to be plaintext email credentials. What protocol is being used, and what secure alternative should be recommended?
    - Protocol being used: ____
    - Secure alternative protocol: ____
    - Secure alternative port: ____

27. An application developer wants to run their development web server on port 80. Why might this be problematic on a Unix/Linux system?

28. You need to verify that Telnet (port 23) is actually closed. Write the exact nmap command to scan ONLY port 23 on IP address 192.168.1.100.

29. You run the command from question 28 and see "23/tcp closed". Does this mean port 23 is secure? Explain the difference between "closed" and "filtered" in nmap output.

30. Which protocol on port 23 should never be used in production and why?

### Exercise Set 6: Advanced Understanding

31. Why does SMTP (port 25) use TCP instead of UDP?

32. Why does DNS (port 53) need both TCP and UDP capabilities?

33. A security consultant recommends "security through obscurity" by running SSH on port 2222 instead of port 22. What are the pros and cons of this approach?

34. True or False: If a service runs on port 443, the traffic is automatically encrypted and secure. Explain your answer.

35. On Unix/Linux systems, which ports require root/superuser privileges to bind? (Give the range)

### Exercise Set 7: Real Interview Questions

36. Your company email uses port 25 for outgoing mail and port 110 for incoming. A user's credentials were compromised. What protocol weakness allowed this?

37. A developer tries to run `python3 app.py` to start a Flask web server on port 80 and gets "Permission denied." What's the problem and how can they fix it without using sudo?

38. You see unusual traffic on port 3389 from multiple international IP addresses at 2 AM. What type of attack is likely occurring?

39. FTP uses two ports - what are they and what is each used for?

40. A web application is accessible on port 8080 instead of the standard port. How can you determine if it's HTTP or HTTPS?

**Scroll down for complete solutions →**

---

---

## Complete Solutions

### Exercise Set 1: Basic Port Identification

1. Port **80**: HTTP
2. Port **443**: HTTPS  
3. Port **22**: SSH
4. Port **3389**: RDP (Remote Desktop Protocol)
5. Port **20, 21**: FTP (two port numbers)
6. Port **23**: Telnet
7. Port **25**: SMTP
8. Port **53**: DNS
9. Port **110**: POP3
10. Port **143**: IMAP

### Exercise Set 2: Protocol Specification

1. Port 20/21: **FTP - TCP**
2. Port 22: **SSH - TCP**
3. Port 23: **Telnet - TCP**
4. Port 25: **SMTP - TCP**
5. Port 53: **DNS - TCP/UDP**
6. Port 80: **HTTP - TCP**
7. Port 110: **POP3 - TCP**
8. Port 143: **IMAP - TCP**
9. Port 443: **HTTPS - TCP**
10. Port 3389: **RDP - TCP**

**Key insight:** Port 53 (DNS) is the ONLY port in this list that uses both TCP and UDP. All others use TCP only.

### Exercise Set 3: Email Protocol Deep Dive

11. **False** - IMAP cannot send emails. Only SMTP sends emails.

12. **False** - SMTP cannot receive emails. Only POP3 and IMAP receive emails.

13. **c) SMTP** - SMTP is used to SEND emails from your client to a mail server.

14. **b) and c)** - POP3 (port 110) and IMAP (port 143) receive emails. SMTP (port 25) only sends.

15. Fill in the blanks:
    - To SEND an email: Use **SMTP** protocol on port **25**
    - To RECEIVE an email: Use **POP3** or **IMAP** protocols on ports **110** or **143**

16. Complete the email flow:
    ```
    SENDING: Your client → SMTP (port 25) → Mail server
    RECEIVING: Your client ← POP3 or IMAP (port 110 or 143) ← Mail server
    ```

17. Your company email uses port 25 for outgoing mail and port 143 for incoming mail:
    - Outgoing uses: **SMTP** protocol
    - Incoming uses: **IMAP** protocol

18. What's the main difference between POP3 and IMAP in how they handle emails on the server?
    - **POP3:** Downloads emails to your device and **typically deletes them from the server**
    - **IMAP:** Syncs emails with your device and **keeps them on the server permanently**

**Critical distinction:** SMTP sends (push), POP3/IMAP receive (pull). You cannot use IMAP or POP3 to send emails!

### Exercise Set 4: nmap State Interpretation

19. **b) Nothing is listening on port 3389**
    - "closed" means the host responded with a RST (reset) packet
    - This indicates no service is running on that port
    - This is the SECURE state you want

20. **b) closed** - The "closed" state means nothing is listening on the port.

21. **Good or Bad: Good**
    - **Why:** "Closed" means nothing is listening on port 23. Since Telnet (port 23) should never be used in production due to plaintext transmission, having it closed is exactly what you want.

22. Match scenarios to nmap states:
    - SSH service is running and accepting connections: **open**
    - Nothing is listening on the port, host responded with RST: **closed**
    - Firewall dropped the packet, nmap can't tell: **filtered**

23. **False** - If nmap shows "closed", this is GOOD. It means nothing is listening on that port. You should NOT investigate unless you expected a service to be running there.

24. Rank from MOST secure to LEAST secure:
    **closed → filtered → open**
    - **closed** = Nothing listening (most secure)
    - **filtered** = Can't tell due to firewall (ambiguous)
    - **open** = Service listening (investigate further)

25. **Server B** - When nmap shows "closed", it definitively means SSH is NOT running. Server A has SSH open. Server C is ambiguous (firewall blocking).

**Common mistake:** Many people think "closed" means "something is wrong" when actually "closed" means "secure - nothing listening."

### Exercise Set 5: Security Scenarios

26. Plaintext credentials on port 110:
    - **Protocol being used:** POP3
    - **Secure alternative protocol:** POP3S
    - **Secure alternative port:** 995 (or use IMAP with TLS on port 993)

27. **Why port 80 is problematic on Unix/Linux:**
    - Ports below 1024 are **privileged ports** that require root/superuser privileges to bind
    - Running a development server with root privileges is a security risk (unnecessary privilege escalation)
    - **Solution:** Use port 8080 (non-privileged) for development, or use containers

28. **Exact nmap command:**
    ```bash
    nmap -p 23 192.168.1.100
    ```

29. **Is "23/tcp closed" secure? YES!**
    - **"closed"** means nothing is listening on the port - the host responded with RST (reset)
    - This is GOOD - it confirms Telnet is not running
    - **"filtered"** means a firewall dropped the packet - we can't tell if service is running or not
    - **Key difference:** "closed" is definitive (no service), "filtered" is ambiguous (can't tell)

30. **Telnet (port 23) should never be used in production because:**
    - Transmits all data (including credentials) in **plaintext**
    - No encryption whatsoever
    - Trivial for attackers to intercept credentials via packet sniffing
    - **Always use SSH (port 22) instead** - provides encrypted communication

### Exercise Set 6: Advanced Understanding

31. **Why SMTP uses TCP instead of UDP:**
    - Email delivery requires **reliability** - messages cannot be lost
    - TCP provides:
      - Guaranteed delivery (retransmission of lost packets)
      - Ordered delivery (messages arrive in correct sequence)
      - Error checking (corrupted packets detected and resent)
    - UDP would risk losing emails entirely, which is unacceptable for messaging

32. **Why DNS needs both TCP and UDP:**
    - **UDP (default):** Fast, connectionless queries for normal DNS lookups under 512 bytes
    - **TCP:** Used for:
      - Zone transfers between DNS servers
      - Responses larger than 512 bytes
    - UDP provides speed for common queries, TCP provides reliability for large transfers

33. **Running SSH on port 2222 (security through obscurity):**
    - **Pros:**
      - Reduces automated bot scans targeting default port 22
      - May reduce noise in logs from random scans
      - Can be part of defense-in-depth strategy
    - **Cons:**
      - Not a substitute for real security (strong keys, key-only auth, fail2ban)
      - Determined attackers will still find it (port scans)
      - Adds operational complexity (need to document non-standard port)
      - Security through obscurity is NOT a security control
    - **Verdict:** Can be useful as one layer, but never rely on it alone

34. **False: Port 443 does NOT automatically mean secure**
    - Just because a service runs on port 443 doesn't guarantee encryption
    - You must verify with: `openssl s_client -connect example.com:443`
    - **Scenarios where port 443 ≠ secure:**
      - Misconfigured TLS (weak ciphers, expired certificates)
      - Self-signed certificates (MITM vulnerability)
      - TLS stripping attacks
      - HTTP running on port 443 (non-standard but possible)
    - **Always verify** - don't assume based on port alone

35. **Privileged ports on Unix/Linux:**
    - **Ports < 1024** (ports 0-1023) require root/superuser privileges to bind
    - This is a security feature to prevent unprivileged users from running potentially malicious services on well-known ports
    - Ports ≥ 1024 can be bound by any user

### Exercise Set 7: Real Interview Questions

36. **Credential compromise with port 110:**
    - Port 110 is **POP3**, which transmits credentials in **plaintext**
    - This protocol weakness allowed credential interception
    - **Fix:** Use **POP3S (port 995)** or **IMAP with TLS (port 993)**

37. **Flask app on port 80 gets "Permission denied":**
    - **Problem:** Port 80 is a privileged port (< 1024) requiring root privileges
    - **Solutions without sudo:**
      1. **Run on port 8080** (recommended for dev): `python3 app.py --port 8080`
      2. Use `setcap` (advanced): `sudo setcap cap_net_bind_service=+ep /usr/bin/python3`
      3. Use containers (Docker/Podman) which handle port mapping
    - **Never run development servers with sudo** - unnecessary privilege escalation

38. **Traffic on port 3389 from multiple international IPs at 2 AM:**
    - Port 3389 is **RDP (Remote Desktop Protocol)**
    - This pattern indicates a **brute force attack** or **credential stuffing**
    - **Response:**
      - Block the attacking IPs immediately
      - Enable account lockout policies
      - Never expose RDP directly to internet (use VPN)
      - Check for any successful authentications
      - Review logs for compromise indicators

39. **FTP uses two ports:**
    - **Port 21:** FTP **Control/Command** channel (authentication, directory navigation, file commands)
    - **Port 20:** FTP **Data** channel (actual file transfer)
    - **Think of it:** Port 21 is the "brain" (commands), Port 20 is the "muscle" (data)

40. **Determining if port 8080 is HTTP or HTTPS:**
    - **You CANNOT definitively tell from port number alone**
    - Port 8080 is **conventionally** used for HTTP, but it's not guaranteed
    - **How to actually determine:**
      1. Check the URL scheme: `http://` vs `https://`
      2. Use `curl -I http://example.com:8080` to inspect headers
      3. Use `nmap` with SSL detection: `nmap -p 8080 --script ssl-enum-ciphers <target>`
      4. Use Wireshark - HTTP shows plaintext, HTTPS shows encrypted TLS records
    - **Key principle:** Conventions ≠ guarantees. Always verify.

---

## Build This Into Muscle Memory

Here's my challenge: **Complete the 40 exercises above until you score 100%.**

Then, take it further with my **LeetCode-style port scanner exercise** with 60+ test cases covering:
- ✅ Port number identification
- ✅ Protocol distinction (TCP vs UDP)
- ✅ nmap output interpretation
- ✅ Security implications of each service
- ✅ Real-world attack scenarios

**⭐️ Star the repo to save it for your interview prep:** [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)

The exercise includes:
- **60 comprehensive test cases** (not just 10 basic ones)
- **Instant feedback** with colored output (✅/❌)
- **Progressive hints** based on your score
- **Real interview questions** from top security companies

### What You'll Learn

After completing the **40 exercises in this blog post** plus the port scanner coding challenge:
- ✅ Instant port recognition (no Googling)
- ✅ Understand TCP vs UDP trade-offs
- ✅ Interpret `nmap` output like a senior engineer
- ✅ Explain security implications in interviews
- ✅ Build production-grade security tools

---

## Why This Matters for Your Career

**Entry-level AppSec roles expect:**
- Memorization of 10+ common ports
- Understanding of TCP/UDP protocols
- Basic `nmap` proficiency
- Security implications of each service

**Senior AppSec roles expect:**
- Instant port recognition (20+ ports)
- Advanced `nmap` techniques (NSE scripts, firewall evasion)
- Custom tool building (port scanners, traffic analyzers)
- Threat modeling from port scan results

**The difference between levels?** Seniors don't just know port 22 is SSH - they know:
- Common SSH misconfigurations (weak ciphers, password auth)
- How to detect SSH brute force attacks
- When to use port knocking or VPN instead
- How attackers pivot from SSH to lateral movement

**That knowledge starts with mastering the basics: these 10 ports.**

---

## Next Steps

1. **Memorize the 10 ports** (use the LLM quiz method above)
2. **Install nmap** (`sudo apt install nmap` on Linux)
3. **Scan your local network** (legally! only scan systems you own)
4. **Complete the port scanner exercise** ([github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises))
5. **Practice explaining out loud** (use the "rubber duck" method)

---

## Resources for Going Deeper

**Free tutorials:**
- High Performance Browser Networking (Chapter 2: TCP, Chapter 3: UDP)³
- Omnisecu TCP/IP Tutorial (OSI Model, IP Addressing)³
- Beej's Guide to Network Programming (socket programming)³

**Books:**
- *Hacking APIs* by Corey Ball (API security fundamentals)
- *Full Stack Python Security* (web application security)

**Week 1 study guide:** Available in my [AppSec curriculum repo](https://github.com/fosres/AppSec-Exercises) - includes 15-hour learning path with labs.

---

## Join the Community

Building AppSec skills? Let's learn together:

- 🌟 **Star the repo:** [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)
- 💬 **Share your port scanner results** in the comments
- 🔥 **Follow me on Dev.to** for weekly AppSec challenges
- 🐛 **Contribute exercises** via pull requests

**Goal:** Create the best open source AppSec training platform - curated secure coding exercises that teach AI models (and engineers) to write secure code.

---

## The Bottom Line

Port numbers aren't memorization busywork. They're the **fundamental vocabulary of network security.**

Many engineers learn this the hard way in technical interviews: **you can't Google your way through a security screen.**

Master these 10 ports. Understand `nmap` states. Build the muscle memory.

**Your next interview will thank you.**

---

**References:**
1. Week 1 Networking Study Guide - Common Port Numbers Reference  
2. Beej's Guide to Network Programming - Socket Programming Fundamentals  
3. High Performance Browser Networking (O'Reilly) - https://hpbn.co/

---

*Did this help you? Star the [AppSec-Exercises repo](https://github.com/fosres/AppSec-Exercises) and share with someone preparing for AppSec interviews!*

*Next in the series: "Building Your First Port Scanner: From Socket Basics to Production Tool"*
