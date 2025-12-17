# The Ultimate Networking Fundamentals Challenge for Security Engineers

> **⭐ Star this repo for more exercises:** [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)
>
> This challenge is part of a larger collection of **LeetCode-style security exercises** designed to help you master Application Security fundamentals. Star the repo to get notified when new challenges are added!

[![GitHub stars](https://img.shields.io/github/stars/fosres/AppSec-Exercises?style=social)](https://github.com/fosres/AppSec-Exercises)
[![GitHub forks](https://img.shields.io/github/forks/fosres/AppSec-Exercises?style=social)](https://github.com/fosres/AppSec-Exercises/fork)

---

## 🔗 Quick Links

- 📦 [GitHub Repository](https://github.com/fosres/AppSec-Exercises) - Star for more exercises!
- 📚 [Lecture Notes](#-lecture-notes-complete-reference-guide) - Study materials
- 🎯 [Start Challenge](#-the-challenge-100-questions) - Jump to questions
- 📝 [Answer Key](#-answer-key) - Check your solutions
- 🏆 [Scoring Guide](#-scoring-guide) - Evaluate your performance

---

## Introduction: Why Networking Fundamentals Matter

If you're pursuing a career in Application Security, Security Engineering, or any cybersecurity role, you'll face networking questions in interviews. Not because interviewers want to test your Network Engineering skills, but because **security architecture requires deep understanding of network boundaries, attack surfaces, and defense-in-depth strategies**.

### Real Interview Scenarios

Consider these actual questions from Security Engineering technical screens:

- *"How would you segment a network for PCI compliance?"*
- *"Design secure architecture for a web app with public API and private database"*
- *"We detected traffic from 192.168.1.50 to 8.8.8.8 - is this internal or external?"*
- *"What security risks exist with exposing 10.0.0.5 to the internet?"* (Trick question!)
- *"An EC2 instance is making requests to 169.254.169.254 - should we be concerned?"*

To answer these confidently, you need instant recognition of IP address classes, private vs public ranges, subnetting, CIDR notation, and special address types.

### About This Challenge

This is **the first challenge** in the [AppSec-Exercises](https://github.com/fosres/AppSec-Exercises) open-source project - a growing collection of **LeetCode-style security exercises** designed to bridge the gap between academic security knowledge and real-world Application Security skills.

**What makes this different:**
- ✅ Interview-focused questions from actual technical screens
- ✅ Progressive difficulty (basic → advanced)
- ✅ Complete explanations, not just answers
- ✅ Open-source and community-driven
- ✅ Regularly updated with new challenges

**📊 Challenge Stats:**
- **100+ questions** across 8 sections
- **226 total points** available
- **3-4 hours** estimated completion time
- **85%+ pass threshold** for interview readiness

**🎯 Learning Objectives:**
**🎯 Learning Objectives:**
- IP address classes (A, B, C, D, E)
- Private vs public IP ranges
- Subnetting and CIDR notation
- Special address types (loopback, APIPA, multicast)
- Network segmentation principles
- Host-to-mask calculations
- VLSM (Variable Length Subnet Masking)

**🚀 Why Take This Challenge:**
1. **Prepare for technical interviews** at GitLab, Stripe, Trail of Bits, Anthropic, etc.
2. **Build foundational security knowledge** for AppSec roles
3. **Get hands-on practice** with realistic scenarios
4. **Benchmark your skills** against interview standards
5. **Join a community** of security learners on GitHub

**⭐ If you find value in this challenge, please [star the repo](https://github.com/fosres/AppSec-Exercises) to support the project!**

This challenge contains **100+ questions** covering everything from basic IP classification to complex VLSM allocation. It's designed to prepare you for technical screens at companies like GitLab, Stripe, Trail of Bits, and other top security-focused organizations.

**Target completion time:** 3-4 hours
**Difficulty progression:** Basic → Intermediate → Advanced
**Pass threshold:** 85% correct (interview-ready)

---

## 🚀 About the AppSec Exercises Project

This networking challenge is the **first in a series** of security-focused exercises designed to bridge the gap between academic knowledge and real-world Application Security skills.

**📦 What's in the GitHub repo:**
- **Networking Fundamentals** (this challenge - 100+ questions)
- **OWASP Top 10 Exploitation** (coming soon)
- **Secure Code Review Challenges** (coming soon)
- **API Security Exercises** (coming soon)
- **Cryptography Implementation** (coming soon)

**🎯 Project Mission:** Create high-quality, LeetCode-style security challenges to help developers write more secure code and prepare for Security Engineering roles.

**⭐ [Star the repo](https://github.com/fosres/AppSec-Exercises)** to support the project and get notified when new challenges drop!

---

## 📚 Lecture Notes: Complete Reference Guide

Before starting the challenge, study these reference materials. **You'll need to memorize key tables**, but understanding the concepts is more important than rote memorization.

### Part 1: IP Address Classes

Every IPv4 address belongs to one of five classes based on its first octet:

| Class | First Octet | Binary Pattern | Default Mask | Structure | Use |
|-------|-------------|----------------|--------------|-----------|-----|
| A | 0-127 | 0xxxxxxx | 255.0.0.0 (/8) | N.H.H.H | Very large networks |
| B | 128-191 | 10xxxxxx | 255.255.0.0 (/16) | N.N.H.H | Medium networks |
| C | 192-223 | 110xxxxx | 255.255.255.0 (/24) | N.N.N.H | Small networks |
| D | 224-239 | 1110xxxx | N/A | N/A | Multicast |
| E | 240-255 | 1111xxxx | N/A | N/A | Reserved/Experimental |

**Quick classification rule:** Look at the first octet only. If it's 156, you know it's Class B (128-191).

### Part 2: Private IP Ranges (RFC 1918)

**Critical for security:** These ranges are NOT routable on the internet and must be used for internal networks:

- **Class A Private:** 10.0.0.0 - 10.255.255.255 (10.0.0.0/8)
- **Class B Private:** 172.16.0.0 - 172.31.255.255 (172.16.0.0/12)
- **Class C Private:** 192.168.0.0 - 192.168.255.255 (192.168.0.0/16)

**Memory trick:** "10 is a tenant building (private apartments), 172 is ONE-SEVEN-TWO wide (16-31), 192.168 is HOME"

### Part 3: Special Address Types

| Type | Range | Purpose | Security Relevance |
|------|-------|---------|-------------------|
| **Loopback** | 127.0.0.0/8 | Computer talks to itself | Local dev servers, testing |
| **APIPA** | 169.254.0.0/16 | DHCP failure auto-assign | Network misconfiguration indicator |
| **Multicast** | 224.0.0.0 - 239.255.255.255 | One-to-many communication | Routing protocols |
| **Reserved** | 240.0.0.0 - 255.255.255.255 | Experimental | Not used in production |

**Critical Security Examples:**
- `127.0.0.1` - localhost (most common loopback)
- `169.254.169.254` - AWS EC2 metadata service (SSRF target!)
- `224.0.0.5` - OSPF routing protocol

### Part 4: Subnetting & CIDR Basics

**CIDR (Classless Inter-Domain Routing)** notation uses a slash followed by the number of network bits:

```
192.168.1.0/24 means:
- First 24 bits are network
- Last 8 bits are host
- Subnet mask: 255.255.255.0
- Total IPs: 2^8 = 256
- Usable hosts: 256 - 2 = 254
```

**Key Formulas:**
- **Total IP addresses:** 2^(host bits)
- **Usable hosts:** 2^(host bits) - 2
- **Number of subnets:** 2^(borrowed bits)

**Common CIDR Reference Table:**

| CIDR | Subnet Mask | Total IPs | Usable Hosts | Common Use |
|------|-------------|-----------|--------------|------------|
| /30 | 255.255.255.252 | 4 | 2 | Point-to-point links |
| /29 | 255.255.255.248 | 8 | 6 | Very small networks |
| /28 | 255.255.255.240 | 16 | 14 | Small office |
| /27 | 255.255.255.224 | 32 | 30 | Small department |
| /26 | 255.255.255.192 | 64 | 62 | Medium department |
| /25 | 255.255.255.128 | 128 | 126 | Large department |
| /24 | 255.255.255.0 | 256 | 254 | Standard subnet |
| /23 | 255.255.254.0 | 512 | 510 | Multiple departments |
| /22 | 255.255.252.0 | 1024 | 1022 | Small campus |

### Part 5: Host-to-Mask Calculation Method

**Problem:** "I need subnets with 500 hosts each. What subnet mask?"

**Solution Steps:**
1. Find minimum host bits: 2^n - 2 ≥ 500
   - Try n=9: 2^9 - 2 = 510 ✓ (first value ≥ 500)
2. Calculate subnet mask: 32 - 9 = /23
3. Verify: /23 = 9 host bits = 512 total, 510 usable ✓

**Common Mistake:** Don't confuse the exponent with the CIDR notation!
- ❌ Wrong: "2^9 = 512, so /9"
- ✓ Correct: "2^9 needs 9 HOST bits, so 32 - 9 = /23"

### Part 6: VLSM (Variable Length Subnet Masking)

VLSM allows creating subnets of different sizes from a single network. **Always allocate from largest to smallest** to minimize fragmentation.

**Example:** Given 192.168.1.0/24, create:
- 1 subnet with 100 hosts
- 2 subnets with 50 hosts each

**Solution:**
1. **100 hosts:** Need 2^7 - 2 = 126 usable → /25 (128 addresses)
   - Network: 192.168.1.0/25 (192.168.1.0 - 192.168.1.127)
2. **50 hosts each:** Need 2^6 - 2 = 62 usable → /26 (64 addresses each)
   - Network 1: 192.168.1.128/26 (192.168.1.128 - 192.168.1.191)
   - Network 2: 192.168.1.192/26 (192.168.1.192 - 192.168.1.255)

---

## 🎯 The Challenge: 100+ Questions

> **📢 Before you start:** This challenge is hosted on [GitHub](https://github.com/fosres/AppSec-Exercises) where you can:
> - Submit your solutions via Pull Request
> - Compare approaches with other learners
> - Contribute additional test cases
> - Report issues or suggest improvements
>
> **⭐ Star the repo** if you find this valuable!

Work through all sections sequentially. **Show your work** for subnetting problems - this is what interviewers want to see!

---

## Section 1: Networking Fundamentals (10 Questions)

**Instructions:** Answer each question completely.

### Question 1
List all 7 layers of the OSI Model from Layer 7 (top) to Layer 1 (bottom) and give one example protocol or function for each layer.

### Question 2
Explain the TCP/IP model's 4 layers and how they map to the OSI model's 7 layers.

### Question 3
What is encapsulation? Describe what happens to data as it travels down the OSI layers from Application to Physical.

### Question 4
Given the IP address **172.20.45.100**, identify:
- What class is this IP address?
- What is the default subnet mask for this class?
- What is the default structure (Network vs Host octets)?

### Question 5
What are the three private IPv4 address ranges (one for each Class A, B, and C)? Why do we need private IP addresses?

### Question 6
What is the loopback network and what is it used for?

### Question 7
For the network **192.168.10.0/24**, answer:
- How many total IP addresses are in this network?
- How many **usable** IP addresses are available for hosts?
- What is the network address and what is the broadcast address?

### Question 8
Convert the CIDR notation **/27** to its dotted decimal subnet mask format. Then calculate how many usable hosts this provides.

### Question 9
What are the key differences between IPv4 and IPv6? (Name at least 3 differences including address length and format)

### Question 10
Explain what NAT (Network Address Translation) is and why organizations use it. What problem does it solve?

---

## Section 2: IP Address Classification (10 Questions)

**Instructions:** For each IP address, identify the class (A, B, C, D, or E).

1. 10.45.120.8
2. 200.100.50.25
3. 135.78.200.150
4. 224.0.0.5
5. 191.255.255.254
6. 126.0.0.1
7. 192.0.2.1
8. 172.31.255.255
9. 223.255.255.255
10. 128.0.0.1

---

## Section 3: CIDR Notation Conversion (10 Questions)

**Instructions:** Convert each CIDR to dotted decimal subnet mask, then calculate total IPs and usable hosts.

**Example format:**
```
/24 → 255.255.255.0, Total: 256, Usable: 254
```

1. /8
2. /16
3. /24
4. /25
5. /26
6. /28
7. /29
8. /30
9. /19
10. /22

---

## Section 4: Basic Subnetting (6 Questions)

### Problem 1
Given network **192.168.100.0/24**, you need to create **4 equal subnets**.
- What is the new subnet mask?
- What is the CIDR notation?
- List all 4 subnet ranges (network address and broadcast address for each)
- How many usable hosts per subnet?

### Problem 2
Given network **10.0.0.0/8**, you need to create **64 subnets**.
- What is the new subnet mask?
- What is the CIDR notation?
- How many usable hosts per subnet?

### Problem 3
You have **172.16.0.0/16** and need subnets that support **500 hosts each**.
- What subnet mask should you use?
- How many such subnets can you create?
- What is the CIDR notation?

### Problem 4
Given **192.168.1.64/26**:
- What is the network address?
- What is the broadcast address?
- What is the first usable host address?
- What is the last usable host address?
- How many total usable hosts?

### Problem 5
You need to subnet **10.50.0.0/16** to create subnets with **exactly 30 usable hosts** each.
- What subnet mask will you use?
- What is the CIDR notation?
- How many subnets can you create?

### Problem 6
Given the IP address **172.20.45.130** with subnet mask **255.255.255.192**:
- What subnet does this IP belong to?
- What is the broadcast address for this subnet?
- What is the range of usable IP addresses?

---

## Section 5: Host-to-Mask Calculation (9 Questions)

### Problem 1
You have network **10.20.0.0/16** and need to create subnets that each support **1,000 hosts**.
- What subnet mask should you use?
- What is the CIDR notation?
- How many such subnets can you create from the /16 network?
- How many usable hosts will each subnet actually have?

### Problem 2
You're given **172.25.0.0/16** and need subnets with exactly **250 hosts each**.
- What is the minimum subnet mask needed?
- What is the CIDR notation?
- How many subnets can you create?
- How many hosts will be wasted per subnet?

### Problem 3
You have **192.168.0.0/16** and must create subnets supporting **50 hosts each**.
- What subnet mask will you use?
- What is the CIDR notation?
- Calculate the total number of subnets available.
- Verify: Does (subnets × addresses per subnet) = total address space?

### Problem 4
Given **10.0.0.0/8**, create subnets that support **8,000 hosts each**.
- Determine the required subnet mask.
- What is the CIDR notation?
- How many such subnets can be created?

### Problem 5
You have **172.16.0.0/12** and need subnets with **30 hosts each**.
- What subnet mask should you use?
- What is the CIDR notation?
- How many subnets can you create?

### Problem 6
Your company has **192.168.100.0/22** and needs:
- Minimum of **100 subnets**
- Each subnet must support at least **6 hosts**

Can you satisfy both requirements? If yes, what subnet mask achieves this?

### Problem 7
You're allocated **10.50.0.0/16**. Requirements:
- Create **512 subnets**
- Each must support **at least 100 hosts**

Is this possible? Show your calculations. What's the maximum hosts per subnet you can actually provide?

### Problem 8
Given **172.30.0.0/16**, you need:
- At least **200 subnets**
- Subnets supporting **200 hosts each**

Can this be done? If not, what's the closest you can get? Explain the trade-off.

### Problem 9
You have **198.18.0.0/22** (1,024 addresses) and need to subnet for:
- 1 subnet with 200 hosts (Data center)
- 3 subnets with 50 hosts each (Office floors)
- 5 subnets with 10 hosts each (Conference rooms)

Design a VLSM allocation:
- What subnet mask for each requirement?
- Allocate specific IP ranges for each subnet
- Calculate total address consumption
- How much address space remains for future growth?

---

## Section 6: IP Address Type Classification - Speed Challenge (25 Questions)

**Instructions:** Classify each IP (A-E) and identify type where applicable.

**Set A: Basic Classification**
1. 15.200.100.50
2. 128.0.0.1
3. 191.255.255.254
4. 192.0.0.1
5. 223.255.255.255
6. 224.0.0.1
7. 127.0.0.1
8. 172.16.0.1
9. 200.50.100.150
10. 255.255.255.255

**Set B: Edge Cases**
11. 126.255.255.255
12. 128.0.0.0
13. 191.255.255.255
14. 192.0.0.0
15. 223.255.255.254
16. 224.0.0.0
17. 239.255.255.255
18. 240.0.0.0
19. 1.1.1.1
20. 8.8.8.8

**Set C: Private/Public Identification**

For questions 21-25, identify class AND whether private or public (or special type):

21. 10.0.0.1
22. 172.31.255.255
23. 192.168.1.1
24. 169.254.10.20
25. 127.100.50.25

---

## Section 7: Special Address Types (30 Questions)

**Instructions:** For each IP, identify class AND type (Private, Public, Loopback, APIPA, Multicast, or Reserved).

**Set A: Basic Special Types**
1. 127.0.0.1
2. 169.254.100.50
3. 10.20.30.40
4. 192.168.1.1
5. 172.16.0.1
6. 8.8.8.8
7. 1.1.1.1
8. 172.31.255.255
9. 127.50.100.200
10. 169.254.0.1

**Set B: Tricky Boundaries**
11. 172.15.255.255 (Is this private?)
12. 172.32.0.1 (Is this private?)
13. 10.0.0.0
14. 10.255.255.255
15. 192.167.1.1
16. 192.169.1.1
17. 127.255.255.255
18. 128.0.0.1
19. 169.253.255.255
20. 169.255.0.1

**Set C: Real-World IPs**
21. 8.8.4.4 (Hint: Google DNS)
22. 1.1.1.1 (Hint: Cloudflare DNS)
23. 192.168.0.1
24. 10.0.0.1
25. 127.0.0.1

**Set D: Multicast & Reserved**
26. 224.0.0.1
27. 239.255.255.255
28. 240.0.0.0
29. 255.255.255.255
30. 224.0.0.5

---

## Section 8: Full Analysis (4 Questions)

**Instructions:** For each IP address, provide complete analysis:
- Class
- Default subnet mask
- Public or Private?
- Network vs Host octets (N.H.H.H format)

**A.** 172.20.45.100
**B.** 10.255.0.1
**C.** 192.168.100.50
**D.** 8.8.4.4

---

## 🏆 Scoring Guide

Calculate your total score across all sections:

**Section 1 (Fundamentals):** 10 points (1 per question)
**Section 2 (Classification):** 10 points (1 per question)
**Section 3 (CIDR):** 30 points (3 per question - mask, total IPs, usable)
**Section 4 (Basic Subnetting):** 30 points (5 per problem)
**Section 5 (Host-to-Mask):** 45 points (5 per problem)
**Section 6 (Speed Challenge):** 25 points (1 per question)
**Section 7 (Special Types):** 60 points (2 per question)
**Section 8 (Full Analysis):** 16 points (4 per question)

**Total Possible:** 226 points

**Score Interpretation:**
- **192-226 (85-100%):** Interview-ready! Excellent understanding.
- **158-191 (70-84%):** Good foundation. Review weak areas.
- **113-157 (50-69%):** Needs significant practice. Study lecture notes.
- **Below 113 (<50%):** Start with fundamentals. Work through slowly.

---

> **💡 Want solutions explained in more detail?** 
> 
> The [AppSec-Exercises GitHub repo](https://github.com/fosres/AppSec-Exercises) includes:
> - Additional practice problems with step-by-step solutions
> - Interactive examples and test cases
> - Community discussions on different approaches
> - Video walkthroughs (coming soon!)
>
> **⭐ Star the repo** to support the project!

---

## 📝 Answer Key

### Section 1: Networking Fundamentals

**Answer 1:** OSI Model Layers (top to bottom)
1. **Application Layer:** HTTP, HTTPS, FTP, DNS, SMTP - Interface between end-user apps and network
2. **Presentation Layer:** Data translation, ASCII/EBCDIC conversion, encryption/decryption
3. **Session Layer:** Network sessions between machines, Remote Procedure Call (RPC)
4. **Transport Layer:** TCP (Transmission Control Protocol), UDP (User Datagram Protocol)
5. **Network Layer:** IP addressing (IPv4/IPv6), routing, ICMP
6. **Data Link Layer:** Ethernet Protocol, MAC addresses, switches, frames
7. **Physical Layer:** Hardware, coaxial cables, physical transmission of bits

**Answer 2:** TCP/IP Model Mapping
- **Application Layer** (TCP/IP) → OSI Layers 5, 6, 7 (Session, Presentation, Application)
- **Transport Layer** (TCP/IP) → OSI Layer 4 (Transport)
- **Internet Layer** (TCP/IP) → OSI Layer 3 (Network)
- **Network Interface Layer** (TCP/IP) → OSI Layers 1, 2 (Physical, Data Link)

**Answer 3:** Encapsulation
TCP/IP Encapsulation is the process of adding headers at each layer as data travels down the protocol stack. At each layer:
- **Application/Presentation/Session:** Data
- **Transport:** Data → Segment (TCP) or Datagram (UDP)
- **Network:** Segment → Packet (adds IP header)
- **Data Link:** Packet → Frame (adds MAC addresses)
- **Physical:** Frame → Bits (transmitted as electrical/optical signals)

**Answer 4:** 172.20.45.100 Analysis
- **Class:** B (first octet 172 is in range 128-191)
- **Default subnet mask:** 255.255.0.0
- **Structure:** N.N.H.H (first 16 bits network, last 16 bits host)

**Answer 5:** Private IP Ranges
- **Class A:** 10.0.0.0 - 10.255.255.255 (10.0.0.0/8)
- **Class B:** 172.16.0.0 - 172.31.255.255 (172.16.0.0/12)
- **Class C:** 192.168.0.0 - 192.168.255.255 (192.168.0.0/16)

**Why needed:** IPv4 address exhaustion. Organizations use private IPs internally with NAT to share a single public IP, conserving the limited IPv4 address space and improving security by hiding internal network structure.

**Answer 6:** Loopback Network
**Range:** 127.0.0.0 - 127.255.255.255 (127.0.0.0/8)
**Most common:** 127.0.0.1 (localhost)
**Purpose:** Computer sends messages to itself for testing, troubleshooting, and local development servers.

**Answer 7:** 192.168.10.0/24 Analysis
- **Total addresses:** 256 (2^8)
- **Usable addresses:** 254 (256 - 2)
- **Network address:** 192.168.10.0
- **Broadcast address:** 192.168.10.255

**Answer 8:** /27 Conversion
- **Dotted decimal:** 255.255.255.224
- **Calculation:** 27 network bits means 5 host bits (32 - 27 = 5)
- **Total addresses:** 2^5 = 32
- **Usable hosts:** 32 - 2 = 30

**Answer 9:** IPv4 vs IPv6 Differences
1. **Address length:** IPv4 uses 32 bits, IPv6 uses 128 bits
2. **Notation:** IPv4 uses dotted decimal (192.168.1.1), IPv6 uses colon-hexadecimal (2001:0db8::1)
3. **Configuration:** IPv4 requires manual configuration or DHCP, IPv6 has auto-configuration built-in
4. **Security:** IPv4 has no built-in security (IPSec optional), IPv6 has IPSec support built-in
5. **Address exhaustion:** IPv4 has limited address space (4.3 billion), IPv6 has virtually unlimited addresses

**Answer 10:** NAT (Network Address Translation)
**What it is:** NAT allows multiple devices in a private local area network to access the Internet using a single public IP address. The NAT device (router) translates private IP addresses to the public IP for outbound traffic and vice versa for inbound traffic.

**Why used:**
- **IPv4 conservation:** Saves scarce public IP addresses
- **Security:** Hides internal network structure from external attackers
- **Flexibility:** Allows internal IP scheme changes without affecting external connectivity

### Section 2: IP Address Classification

1. 10.45.120.8 → **Class A**
2. 200.100.50.25 → **Class C**
3. 135.78.200.150 → **Class B**
4. 224.0.0.5 → **Class D**
5. 191.255.255.254 → **Class B**
6. 126.0.0.1 → **Class A**
7. 192.0.2.1 → **Class C**
8. 172.31.255.255 → **Class B**
9. 223.255.255.255 → **Class C**
10. 128.0.0.1 → **Class B**

### Section 3: CIDR Notation Conversion

1. /8 → 255.0.0.0, Total: 2^24 = 16,777,216, Usable: 16,777,214
2. /16 → 255.255.0.0, Total: 2^16 = 65,536, Usable: 65,534
3. /24 → 255.255.255.0, Total: 2^8 = 256, Usable: 254
4. /25 → 255.255.255.128, Total: 2^7 = 128, Usable: 126
5. /26 → 255.255.255.192, Total: 2^6 = 64, Usable: 62
6. /28 → 255.255.255.240, Total: 2^4 = 16, Usable: 14
7. /29 → 255.255.255.248, Total: 2^3 = 8, Usable: 6
8. /30 → 255.255.255.252, Total: 2^2 = 4, Usable: 2
9. /19 → 255.255.224.0, Total: 2^13 = 8,192, Usable: 8,190
10. /22 → 255.255.252.0, Total: 2^10 = 1,024, Usable: 1,022

### Section 4: Basic Subnetting

**Problem 1: 192.168.100.0/24 → 4 subnets**
- **New subnet mask:** /26 (borrowed 2 bits: 2^2 = 4 subnets)
- **CIDR:** 192.168.100.0/26
- **Subnets:**
  1. 192.168.100.0/26 (Network: .0, Broadcast: .63)
  2. 192.168.100.64/26 (Network: .64, Broadcast: .127)
  3. 192.168.100.128/26 (Network: .128, Broadcast: .191)
  4. 192.168.100.192/26 (Network: .192, Broadcast: .255)
- **Usable hosts per subnet:** 64 - 2 = 62

**Problem 2: 10.0.0.0/8 → 64 subnets**
- **Calculation:** 2^6 = 64, so need 6 bits borrowed
- **New subnet mask:** /14 (8 + 6 = 14)
- **CIDR:** 10.0.0.0/14
- **Host bits:** 32 - 14 = 18 bits
- **Usable hosts per subnet:** 2^18 - 2 = 262,142

**Problem 3: 172.16.0.0/16 → 500 hosts each**
- **Host calculation:** 2^9 - 2 = 510 (first value ≥ 500)
- **Subnet mask:** 32 - 9 = /23
- **CIDR:** 172.16.0.0/23
- **Borrowed bits:** 23 - 16 = 7
- **Number of subnets:** 2^7 = 128

**Problem 4: 192.168.1.64/26**
- **Network address:** 192.168.1.64
- **Broadcast address:** 192.168.1.127
- **First usable:** 192.168.1.65
- **Last usable:** 192.168.1.126
- **Total usable hosts:** 62

**Problem 5: 10.50.0.0/16 → 30 usable hosts**
- **Host calculation:** 2^5 - 2 = 30, so need 5 host bits
- **Subnet mask:** 32 - 5 = /27
- **CIDR:** 10.50.0.0/27
- **Borrowed bits:** 27 - 16 = 11
- **Number of subnets:** 2^11 = 2,048

**Problem 6: 172.20.45.130 with mask 255.255.255.192 (/26)**
- **Subnet:** 172.20.45.128/26
- **Broadcast:** 172.20.45.191
- **Usable range:** 172.20.45.129 - 172.20.45.190

### Section 5: Host-to-Mask Calculation

**Problem 1: 10.20.0.0/16 → 1,000 hosts**
- **Host calculation:** 2^10 - 2 = 1,022 (first value ≥ 1,000)
- **Subnet mask:** /22 (32 - 10 = 22)
- **CIDR:** 10.20.0.0/22
- **Borrowed bits:** 22 - 16 = 6
- **Number of subnets:** 2^6 = 64
- **Usable hosts per subnet:** 1,022

**Problem 2: 172.25.0.0/16 → 250 hosts**
- **Host calculation:** 2^8 - 2 = 254 (first value ≥ 250)
- **Subnet mask:** /24 (32 - 8 = 24)
- **CIDR:** 172.25.0.0/24
- **Borrowed bits:** 24 - 16 = 8
- **Number of subnets:** 2^8 = 256
- **Usable hosts:** 254
- **Wasted hosts per subnet:** 254 - 250 = 4

**Problem 3: 192.168.0.0/16 → 50 hosts**
- **Host calculation:** 2^6 - 2 = 62 (first value ≥ 50)
- **Subnet mask:** /26 (32 - 6 = 26)
- **CIDR:** 192.168.0.0/26
- **Borrowed bits:** 26 - 16 = 10
- **Number of subnets:** 2^10 = 1,024
- **Verification:** 1,024 subnets × 64 addresses = 65,536 total ✓

**Problem 4: 10.0.0.0/8 → 8,000 hosts**
- **Host calculation:** 2^13 - 2 = 8,190 (first value ≥ 8,000)
- **Subnet mask:** /19 (32 - 13 = 19)
- **CIDR:** 10.0.0.0/19
- **Borrowed bits:** 19 - 8 = 11
- **Number of subnets:** 2^11 = 2,048

**Problem 5: 172.16.0.0/12 → 30 hosts**
- **Host calculation:** 2^5 - 2 = 30
- **Subnet mask:** /27 (32 - 5 = 27)
- **CIDR:** 172.16.0.0/27
- **Borrowed bits:** 27 - 12 = 15
- **Number of subnets:** 2^15 = 32,768

**Problem 6: 192.168.100.0/22 → 100 subnets with 6 hosts**
- **Answer:** YES, can satisfy both
- **Host calculation:** 2^3 - 2 = 6, need 3 host bits
- **Subnet mask:** /29 (32 - 3 = 29)
- **Borrowed bits:** 29 - 22 = 7
- **Number of subnets:** 2^7 = 128 ≥ 100 ✓
- **Usable hosts per subnet:** 6 ✓

**Problem 7: 10.50.0.0/16 → 512 subnets with 100 hosts**
- **Answer:** YES, possible
- **Subnet calculation:** 2^9 = 512, need 9 borrowed bits
- **New subnet mask:** /25 (16 + 9 = 25)
- **Host bits remaining:** 32 - 25 = 7
- **Usable hosts:** 2^7 - 2 = 126 ≥ 100 ✓
- **Maximum hosts per subnet:** 126

**Problem 8: 172.30.0.0/16 → 200 subnets with 200 hosts**
- **Answer:** YES, can be done
- **Subnet calculation:** 2^8 = 256 subnets (≥ 200) ✓
- **Host calculation:** 2^8 - 2 = 254 hosts (≥ 200) ✓
- **Subnet mask:** /24 (16 + 8 = 24)
- **Result:** 256 subnets, each with 254 usable hosts

**Problem 9: 198.18.0.0/22 VLSM**

**Allocation (largest to smallest):**

1. **Data Center (200 hosts):** /24 (256 addresses, 254 usable)
   - Network: 198.18.0.0/24
   - Range: 198.18.0.0 - 198.18.0.255

2. **Office Floor A (50 hosts):** /26 (64 addresses, 62 usable)
   - Network: 198.18.1.0/26
   - Range: 198.18.1.0 - 198.18.1.63

3. **Office Floor B (50 hosts):** /26 (64 addresses, 62 usable)
   - Network: 198.18.1.64/26
   - Range: 198.18.1.64 - 198.18.1.127

4. **Office Floor C (50 hosts):** /26 (64 addresses, 62 usable)
   - Network: 198.18.1.128/26
   - Range: 198.18.1.128 - 198.18.1.191

5. **Conference Room A (10 hosts):** /28 (16 addresses, 14 usable)
   - Network: 198.18.1.192/28
   - Range: 198.18.1.192 - 198.18.1.207

6. **Conference Room B (10 hosts):** /28
   - Network: 198.18.1.208/28
   - Range: 198.18.1.208 - 198.18.1.223

7. **Conference Room C (10 hosts):** /28
   - Network: 198.18.1.224/28
   - Range: 198.18.1.224 - 198.18.1.239

8. **Conference Room D (10 hosts):** /28
   - Network: 198.18.1.240/28
   - Range: 198.18.1.240 - 198.18.1.255

9. **Conference Room E (10 hosts):** /28
   - Network: 198.18.2.0/28
   - Range: 198.18.2.0 - 198.18.2.15

**Total consumption:** 256 + (64×3) + (16×5) = 528 addresses
**Available space:** 1,024 addresses
**Remaining for growth:** 1,024 - 528 = 496 addresses (48.4%)

### Section 6: IP Address Type Classification

**Set A: Basic Classification**
1. 15.200.100.50 → Class A
2. 128.0.0.1 → Class B
3. 191.255.255.254 → Class B
4. 192.0.0.1 → Class C
5. 223.255.255.255 → Class C
6. 224.0.0.1 → Class D
7. 127.0.0.1 → Class A
8. 172.16.0.1 → Class B
9. 200.50.100.150 → Class C
10. 255.255.255.255 → Class E

**Set B: Edge Cases**
11. 126.255.255.255 → Class A (last Class A address)
12. 128.0.0.0 → Class B (first Class B address)
13. 191.255.255.255 → Class B (last Class B address)
14. 192.0.0.0 → Class C (first Class C address)
15. 223.255.255.254 → Class C (almost last Class C)
16. 224.0.0.0 → Class D (first multicast)
17. 239.255.255.255 → Class D (last multicast)
18. 240.0.0.0 → Class E (first reserved)
19. 1.1.1.1 → Class A (Cloudflare DNS)
20. 8.8.8.8 → Class A (Google DNS)

**Set C: Private/Public**
21. 10.0.0.1 → Class A, Private
22. 172.31.255.255 → Class B, Private
23. 192.168.1.1 → Class C, Private
24. 169.254.10.20 → Class B, APIPA (link-local)
25. 127.100.50.25 → Class A, Loopback

### Section 7: Special Address Types

**Set A: Basic Special Types**
1. 127.0.0.1 → Class A, Loopback
2. 169.254.100.50 → Class B, APIPA
3. 10.20.30.40 → Class A, Private
4. 192.168.1.1 → Class C, Private
5. 172.16.0.1 → Class B, Private
6. 8.8.8.8 → Class A, Public
7. 1.1.1.1 → Class A, Public
8. 172.31.255.255 → Class B, Private
9. 127.50.100.200 → Class A, Loopback
10. 169.254.0.1 → Class B, APIPA

**Set B: Tricky Boundaries**
11. 172.15.255.255 → Class B, Public (NOT private - below 172.16)
12. 172.32.0.1 → Class B, Public (NOT private - above 172.31)
13. 10.0.0.0 → Class A, Private
14. 10.255.255.255 → Class A, Private
15. 192.167.1.1 → Class C, Public (NOT 192.168)
16. 192.169.1.1 → Class C, Public (NOT 192.168)
17. 127.255.255.255 → Class A, Loopback
18. 128.0.0.1 → Class B, Public
19. 169.253.255.255 → Class B, Public (NOT APIPA)
20. 169.255.0.1 → Class B, Public (NOT APIPA)

**Set C: Real-World IPs**
21. 8.8.4.4 → Class A, Public (Google DNS secondary)
22. 1.1.1.1 → Class A, Public (Cloudflare DNS)
23. 192.168.0.1 → Class C, Private (common router)
24. 10.0.0.1 → Class A, Private (common gateway)
25. 127.0.0.1 → Class A, Loopback (localhost)

**Set D: Multicast & Reserved**
26. 224.0.0.1 → Class D, Multicast
27. 239.255.255.255 → Class D, Multicast
28. 240.0.0.0 → Class E, Reserved
29. 255.255.255.255 → Class E, Reserved (limited broadcast)
30. 224.0.0.5 → Class D, Multicast (OSPF)

### Section 8: Full Analysis

**A. 172.20.45.100**
- Class: B
- Default mask: 255.255.0.0
- Type: Private (within 172.16.0.0 - 172.31.255.255)
- Structure: N.N.H.H

**B. 10.255.0.1**
- Class: A
- Default mask: 255.0.0.0
- Type: Private (within 10.0.0.0 - 10.255.255.255)
- Structure: N.H.H.H

**C. 192.168.100.50**
- Class: C
- Default mask: 255.255.255.0
- Type: Private (within 192.168.0.0 - 192.168.255.255)
- Structure: N.N.N.H

**D. 8.8.4.4**
- Class: A
- Default mask: 255.0.0.0
- Type: Public (Google DNS)
- Structure: N.H.H.H

---

## 🎓 What's Next After Mastering Networking?

### Continue Your Security Engineering Journey

**⭐ [Star the AppSec-Exercises repo](https://github.com/fosres/AppSec-Exercises)** for upcoming challenges:

#### 📅 Roadmap (Weekly Releases)
- ✅ **Week 1:** Networking Fundamentals (you are here!)
- 🔜 **Week 2:** TCP/UDP Deep Dive + Wireshark Labs
- 🔜 **Week 3:** SQL Injection Exploitation (PortSwigger style)
- 🔜 **Week 4:** XSS Attack Vectors & Bypasses
- 🔜 **Week 5:** Authentication & Session Management
- 🔜 **Week 6:** API Security Testing
- 🔜 **Week 7:** SSRF & XXE Exploitation
- 🔜 **Week 8:** Cryptography Implementation

### 🤝 Contribute to the Project

The **AppSec-Exercises** project is open source and welcomes contributions:

- **Add test cases:** Found an edge case? Submit a PR!
- **Create new challenges:** Have a great security exercise idea? Share it!
- **Report issues:** Found a typo or error? Open an issue!
- **Share solutions:** Different approaches help everyone learn

**[View the repo →](https://github.com/fosres/AppSec-Exercises)**

### Next Steps for Interview Prep

### Next Steps for Interview Prep

If you scored 85% or higher, you're interview-ready for networking fundamentals! Here's what to tackle next:

1. **TCP 3-Way Handshake** - Master SYN, SYN-ACK, ACK (coming to the repo!)
2. **Common Port Numbers** - Memorize 80, 443, 22, 3389, 21, 25, etc.
3. **Wireshark Labs** - Hands-on packet analysis exercises (in the repo!)
4. **Port Scanner Project** - Combine networking + Python (tutorial coming!)

### Recommended Resources

**Books:**
- *Computer Networking: A Top-Down Approach* by Kurose & Ross
- *TCP/IP Illustrated, Volume 1* by W. Richard Stevens

**Free Online:**
- **[AppSec-Exercises GitHub Repo](https://github.com/fosres/AppSec-Exercises)** ⭐ **START HERE**
- Omnisecu TCP/IP Tutorial: https://www.omnisecu.com/tcpip/
- High Performance Browser Networking: https://hpbn.co/
- SubnetIPv4 Practice: https://www.subnetipv4.com/

**Hands-On Practice:**
- PortSwigger Web Security Academy (network-based attacks)
- HackTheBox (real-world network pentesting)
- TryHackMe (guided network security challenges)

---

## 💡 Final Tips for Interviews

**What interviewers actually care about:**

1. **Speed of classification** - Can you identify 172.20.45.100 as Class B Private in under 3 seconds?
2. **Understanding trade-offs** - "Why would you choose /26 over /25 for this network?"
3. **Security implications** - "What's the risk of exposing 10.0.0.5 to the internet?"
4. **Real-world context** - "How would you subnet this network for PCI compliance?"

**Show your work!** When solving subnetting problems, write out:
```
Need 500 hosts
2^9 - 2 = 510 ≥ 500 ✓
9 host bits needed
32 - 9 = /23 subnet mask
```

**Think out loud!** Interviewers want to see your thought process, not just correct answers.

**Ask clarifying questions!**
- "Should I optimize for number of subnets or hosts per subnet?"
- "Is this for production or development networks?"
- "Do we need to plan for growth?"

---

## 🙏 About This Project

This challenge is part of **[AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)**, an open-source project creating high-quality, LeetCode-style security challenges to help developers:

- **Prepare for Security Engineering interviews** at top companies
- **Write more secure code** through hands-on practice
- **Build practical AppSec skills** beyond theoretical knowledge

### The Mission

Current AI coding assistants generate vulnerable code because they're trained on repositories containing security flaws. This project aims to **curate high-quality, secure code training datasets** to eventually train AI models to write more secure code.

### How You Can Help

1. **⭐ Star the repo** to show support and increase visibility
2. **🔀 Fork and contribute** new challenges or improvements
3. **💬 Share feedback** via issues or discussions
4. **📢 Spread the word** to others preparing for security roles

**[→ Visit the GitHub repo](https://github.com/fosres/AppSec-Exercises)**

### Acknowledgments

This challenge was developed through intensive practice sessions preparing for Security Engineering roles at companies like GitLab, Stripe, Trail of Bits, and Anthropic. Special thanks to the open-source networking community and the countless educators who make networking fundamentals accessible.

**Found this helpful?** 
- ⭐ [Star the repo](https://github.com/fosres/AppSec-Exercises) 
- 🔄 Share this post with others preparing for security interviews
- 💬 Leave a comment below with your score!

**Questions, corrections, or suggestions?** 
- 🐛 [Open an issue on GitHub](https://github.com/fosres/AppSec-Exercises/issues)
- 💡 [Start a discussion](https://github.com/fosres/AppSec-Exercises/discussions)

---

**Good luck with your interviews! Remember: networking fundamentals are foundational to security engineering. Master these concepts, and you'll stand out in any technical screen.** 💪🔒

---

## 🌟 Support the Project

If this challenge helped you prepare for interviews or deepen your networking knowledge:

**⭐ [Star the AppSec-Exercises repo](https://github.com/fosres/AppSec-Exercises)**

Your support helps:
- Keep the project active and maintained
- Motivate the creation of new challenges
- Build a community of security-focused developers
- Improve the quality of security education resources

**Next challenges coming soon:**
- TCP/UDP Deep Dive with Wireshark Labs
- SQL Injection Exploitation Techniques
- XSS Attack Vectors & Filter Bypasses
- Authentication & Authorization Flaws

**[Follow the repo →](https://github.com/fosres/AppSec-Exercises)** to get notified when new exercises are released!

---

**Connect & Contribute:**
- 🐙 GitHub: [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)
- 📝 Dev.to: Follow for more security content
- 💼 Preparing for AppSec roles? This challenge is designed for you!

#cybersecurity #networking #interview #appsec #securityengineering #opensource
