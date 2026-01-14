---
title: The One Networking Concept That Fails 90% of Security Engineer Candidates
published: true
description: Master packet tracing through NAT and firewalls with 12 practice problems. The skill that separates junior from senior security engineers.
tags: security, networking, linux, interview
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/firewall-network-security.png
series: Security Engineering Interview Prep
---

## The Interview Question That Exposes Your Networking Gaps

You're in a Security Engineering interview. The interviewer shows you this diagram:

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│ Developer  │         │ Office NAT │         │   Router   │         │ File Server│
│            ├────────►│            ├────────►│            ├────────►│            │
│192.168.1.50│         │ WAN: 198.51.100.10  │            │         │ 20.0.0.100 │
└────────────┘         │ LAN: 192.168.1.1    │ 198.51.100.254       └────────────┘
                       └────────────┘         └────────────┘
```

Then they ask:

> "The File Server has this iptables rule, but the Developer can't SSH in. Why?"
> ```bash
> iptables -A INPUT -s 192.168.1.50 --dport 22 -j ACCEPT
> ```

**Can you answer this in 10 seconds?**

If not, this article is for you. I've compiled 12 packet tracing problems that will permanently fix this gap in your knowledge.

---

## ⭐ Free Practice Problems on GitHub

I'm building an open-source collection of Security Engineering interview prep materials. If you find this useful:

**[👉 Star the repo on GitHub](https://github.com/YOUR_USERNAME/security-engineering-prep)**

Your stars help other security engineers discover these resources!

---

## The Core Insight

Most candidates fail this question because they don't understand one fundamental rule:

| Device Type | Changes Source/Dest IP? |
|-------------|------------------------|
| **NAT** | ✅ Yes |
| **Router** | ❌ No |
| **Firewall** | ❌ No (filtering only) |

The File Server sees `198.51.100.10` (the NAT's public IP), **not** `192.168.1.50` (the Developer's private IP).

**The fix:**
```bash
iptables -A INPUT -s 198.51.100.10 --dport 22 -j ACCEPT
```

This pattern appears in technical assessments at top security companies. Let's master it.

---

## 🎯 12 Packet Tracing Problems

These problems are modeled after real technical assessments used by top security teams.

**Instructions:**
- Time yourself: 30 minutes
- Passing score: 85%
- Answer key is at the bottom — no peeking!

---

# Section A: Outbound NAT (SNAT/MASQUERADE)

## Problem 1: Basic NAT

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│   Client   │         │ NAT Router │         │ Web Server │
│            ├────────►│            ├────────►│            │
│ 10.0.0.50  │         │ WAN: 203.0.113.5     │ 93.184.216.34
└────────────┘         │ LAN: 10.0.0.1│       └────────────┘
                       └────────────┘
```

Client sends HTTP request to Web Server.

**At Point A (Client → NAT Router):**
- Source IP: __________
- Destination IP: __________

**At Point B (NAT Router → Web Server):**
- Source IP: __________
- Destination IP: __________

---

## Problem 2: NAT + Router Chain

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│ Workstation│         │ NAT Router │         │   Router   │         │   Server   │
│            ├────────►│            ├────────►│            ├────────►│            │
│192.168.1.100        │ WAN: 74.125.1.1      │            │         │ 8.8.8.8    │
└────────────┘         │ LAN: 192.168.1.1    │ 74.125.1.254         └────────────┘
                       └────────────┘         └────────────┘
```

Workstation sends DNS query to 8.8.8.8.

**At Point A (Workstation → NAT Router):**
- Source IP: __________
- Destination IP: __________

**At Point B (NAT Router → Router):**
- Source IP: __________
- Destination IP: __________

**At Point C (Router → Server):**
- Source IP: __________
- Destination IP: __________

---

## Problem 3: Double NAT (Carrier-Grade NAT)

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│  Laptop    │         │ Home NAT   │         │  ISP NAT   │         │   Server   │
│            ├────────►│            ├────────►│  (CGNAT)   ├────────►│            │
│192.168.0.25│         │ WAN: 100.64.1.50    │ WAN: 52.1.2.3        │ 151.101.1.69
└────────────┘         │ LAN: 192.168.0.1    │ LAN: 100.64.0.1      └────────────┘
                       └────────────┘         └────────────┘
```

Laptop connects to Server (Double NAT scenario).

**At Point A (Laptop → Home NAT):**
- Source IP: __________
- Destination IP: __________

**At Point B (Home NAT → ISP NAT):**
- Source IP: __________
- Destination IP: __________

**At Point C (ISP NAT → Server):**
- Source IP: __________
- Destination IP: __________

**What source IP does the Server see?** __________

---

# Section B: Inbound NAT (DNAT / Port Forwarding)

## Problem 4: Basic DNAT

```
                       ┌────────────┐
                       │ NAT Router │
┌────────────┐         │            │         ┌────────────┐
│  Internet  ├────────►│ WAN: 203.0.113.10   │ Web Server │
│   Client   │         │ LAN: 10.0.0.1├─────►│            │
│ 72.45.67.89│         │            │         │ 10.0.0.100 │
└────────────┘         │ DNAT:      │         └────────────┘
                       │ 80→10.0.0.100:80
                       └────────────┘
```

Internet Client connects to http://203.0.113.10 (port 80).

**At Point A (Client → NAT Router WAN):**
- Source IP: __________
- Destination IP: __________

**At Point B (NAT Router → Web Server):**
- Source IP: __________
- Destination IP: __________

**What source IP does the Web Server see?** __________

---

## Problem 5: DNAT Through Router (Security Scenario)

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│  Attacker  │         │   Router   │         │  Firewall  │         │ SSH Server │
│            ├────────►│            ├────────►│  (NAT)     ├────────►│            │
│ 45.33.32.1 │         │            │         │ WAN: 104.44.1.1      │ 10.0.0.50  │
└────────────┘         │ 45.33.32.254         │ DNAT: 22→10.0.0.50:22│            │
                       └────────────┘         └────────────┘         └────────────┘
```

Attacker attempts SSH to 104.44.1.1.

**At Point A (Attacker → Router):**
- Source IP: __________
- Destination IP: __________

**At Point B (Router → Firewall):**
- Source IP: __________
- Destination IP: __________

**At Point C (Firewall → SSH Server):**
- Source IP: __________
- Destination IP: __________

**The SSH Server has this firewall rule:**
```bash
iptables -A INPUT -s 45.33.32.254 --dport 22 -j DROP
```

**Will this block the attacker?** __________

**Why?** __________

---

# Section C: Firewall Troubleshooting

## Problem 6: The Classic NAT Trap

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│ Developer  │         │ Office NAT │         │   Router   │         │ File Server│
│            ├────────►│            ├────────►│            ├────────►│            │
│192.168.1.50│         │ WAN: 198.51.100.10  │            │         │ 20.0.0.100 │
└────────────┘         │ LAN: 192.168.1.1    │ 198.51.100.254       └────────────┘
                       └────────────┘         └────────────┘
```

File Server has this iptables rule:
```bash
iptables -A INPUT -s 192.168.1.50 --dport 22 -j ACCEPT
```

**Will the Developer be able to SSH to the File Server?** __________

**What source IP does the File Server actually see?** __________

**Write the corrected iptables rule:** __________

---

## Problem 7: VPN Without NAT

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│   Admin    │         │  VPN GW    │         │   Server   │
│            ├─────────┤            ├────────►│            │
│ 10.8.0.50  │ VPN     │ 10.8.0.1   │         │ 172.16.0.10│
│(VPN tunnel)│         │ 172.16.0.1 │         │            │
└────────────┘         └────────────┘         └────────────┘

Note: VPN Gateway does NOT NAT internal traffic.
```

Admin SSHs to Server (172.16.0.10).

**What source IP does the Server see?** __________

**Server has firewall rule:**
```bash
iptables -A INPUT -s 10.8.0.0/24 --dport 22 -j ACCEPT
```

**Will Admin be allowed to SSH?** __________

---

## Problem 8: Same Private IP, Different Offices

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│ Seattle    │         │ Seattle    │         │            │         │            │
│ Developer  ├────────►│ NAT Router ├────────►│  Internet  ├────────►│ Cloud LB   │
│192.168.1.75│         │ WAN: 52.12.1.1      │            │         │ 35.200.1.1 │
└────────────┘         └────────────┘         │            │         └─────┬──────┘
                                              │            │               │
┌────────────┐         ┌────────────┐         │            │         ┌─────▼──────┐
│ Austin     │         │ Austin     │         │            │         │ Backend    │
│ Developer  ├────────►│ NAT Router ├────────►│            │         │ Server     │
│192.168.1.75│         │ WAN: 104.210.1.1    │            │         │ 10.0.0.50  │
└────────────┘         └────────────┘         └────────────┘         └────────────┘

Note: Both developers have the SAME private IP (192.168.1.75) - different offices.
Cloud Load Balancer DNATs to Backend Server.
```

Backend Server has this firewall rule:
```bash
iptables -A INPUT -s 192.168.1.75 --dport 443 -j ACCEPT
```

**Will Seattle Developer connect?** __________

**Will Austin Developer connect?** __________

**What two source IPs does Backend Server actually see?**
- Seattle: __________
- Austin: __________

**Write corrected firewall rules to allow both offices:** __________

---

## Problem 9: IP Allowlisting

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│ App Server │         │ NAT Gateway│         │ External   │
│            ├────────►│            ├────────►│ API        │
│ 10.0.2.50  │         │ priv: 10.0.2.1      │ 151.101.1.1│
└────────────┘         │ pub: 54.23.45.67    └────────────┘
                       └────────────┘
```

App Server makes HTTPS request to External API.

**What source IP does External API see?** __________

**External API has allowlist:**
```
Allowed IPs: 54.23.45.67, 54.23.45.68
```

**Will the request succeed?** __________

---

## Problem 10: Blocking a Scanner (The Trap)

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│ Malicious  │         │   Router   │         │  Firewall  │         │ Web Server │
│ Scanner    ├────────►│    (no NAT)├────────►│   (NAT)    ├────────►│            │
│ 45.33.32.1 │         │            │         │ WAN: 104.44.1.1      │ 10.0.0.80  │
└────────────┘         │ 45.33.32.254         │ DNAT: 443→10.0.0.80  │            │
                       └────────────┘         └────────────┘         └────────────┘
```

Web Server has this firewall rule to block the scanner:
```bash
iptables -A INPUT -s 45.33.32.254 -j DROP
```

**Will this rule block the scanner?** __________

**What source IP does the Web Server see?** __________

**Write the corrected blocking rule:** __________

---

# Section D: Return Traffic

## Problem 11: Outbound Return Path

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│   Client   │         │ NAT Router │         │   Server   │
│            │◄────────┤            │◄────────┤            │
│ 10.0.0.50  │         │ WAN: 203.0.113.5    │ 93.184.216.34
└────────────┘         │ LAN: 10.0.0.1│       └────────────┘
                       └────────────┘
```

Server sends HTTP response back to Client.

**At Point A (Server → NAT Router):**
- Source IP: __________
- Destination IP: __________

**At Point B (NAT Router → Client):**
- Source IP: __________
- Destination IP: __________

**What changes the destination IP from 203.0.113.5 to 10.0.0.50?** __________

---

## Problem 12: DNAT Return Path

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│ Internet   │         │  Firewall  │         │ Web Server │
│ Client     │◄────────┤    (NAT)   │◄────────┤            │
│ 72.45.67.89│         │ DNAT: 80→10.0.0.100 │ 10.0.0.100 │
└────────────┘         │ WAN: 203.0.113.10   └────────────┘
                       └────────────┘
```

Web Server sends HTTP response back to Internet Client.

**At Point A (Web Server → Firewall):**
- Source IP: __________
- Destination IP: __________

**At Point B (Firewall → Internet Client):**
- Source IP: __________
- Destination IP: __________

---

# ⭐ Found This Useful?

I'm building an open-source Security Engineering interview prep repository with:

- 🔥 More packet tracing problems
- 🔥 iptables scenario labs
- 🔥 SQL injection practice
- 🔥 Threat modeling exercises
- 🔥 System design questions

**[Star the repo on GitHub](https://github.com/YOUR_USERNAME/security-engineering-prep)** to support the project and get notified of new content!

---

# Answer Key

## Section A: Outbound NAT

### Problem 1
- **Point A:** SRC=10.0.0.50, DST=93.184.216.34
- **Point B:** SRC=203.0.113.5, DST=93.184.216.34

**Key insight:** NAT changes the source IP. Destination stays the same.

### Problem 2
- **Point A:** SRC=192.168.1.100, DST=8.8.8.8
- **Point B:** SRC=74.125.1.1, DST=8.8.8.8
- **Point C:** SRC=74.125.1.1, DST=8.8.8.8

**Key insight:** The Router doesn't change the source IP—only NAT does.

### Problem 3
- **Point A:** SRC=192.168.0.25, DST=151.101.1.69
- **Point B:** SRC=100.64.1.50, DST=151.101.1.69
- **Point C:** SRC=52.1.2.3, DST=151.101.1.69
- **Server sees:** 52.1.2.3

**Key insight:** Each NAT changes the source IP. Two NATs = two translations.

---

## Section B: Inbound NAT

### Problem 4
- **Point A:** SRC=72.45.67.89, DST=203.0.113.10
- **Point B:** SRC=72.45.67.89, DST=10.0.0.100
- **Web Server sees:** 72.45.67.89

**Key insight:** DNAT changes the *destination*, not the source. The client's real IP survives.

### Problem 5
- **Point A:** SRC=45.33.32.1, DST=104.44.1.1
- **Point B:** SRC=45.33.32.1, DST=104.44.1.1
- **Point C:** SRC=45.33.32.1, DST=10.0.0.50
- **Will it block?** NO
- **Why?** The rule blocks 45.33.32.254 (the router), but the attacker's real IP is 45.33.32.1. Routers don't change source IPs.

**Correct rule:**
```bash
iptables -A INPUT -s 45.33.32.1 --dport 22 -j DROP
```

---

## Section C: Firewall Troubleshooting

### Problem 6
- **Will Developer SSH?** NO
- **File Server sees:** 198.51.100.10
- **Corrected rule:**
```bash
iptables -A INPUT -s 198.51.100.10 --dport 22 -j ACCEPT
```

**This is the #1 interview question pattern.** Private IPs don't survive NAT.

### Problem 7
- **Server sees:** 10.8.0.50
- **Will Admin SSH?** YES (10.8.0.50 is within 10.8.0.0/24)

**Key insight:** Without NAT, the original source IP is preserved.

### Problem 8
- **Seattle connect?** NO
- **Austin connect?** NO
- **Backend Server sees:**
  - Seattle: 52.12.1.1
  - Austin: 104.210.1.1
- **Corrected rules:**
```bash
iptables -A INPUT -s 52.12.1.1 --dport 443 -j ACCEPT
iptables -A INPUT -s 104.210.1.1 --dport 443 -j ACCEPT
```

**Key insight:** Same private IP in different offices = different public IPs after NAT.

### Problem 9
- **External API sees:** 54.23.45.67
- **Will request succeed?** YES (54.23.45.67 is in the allowlist)

**Real-world application:** This is why companies give their NAT Gateway IPs to third-party APIs.

### Problem 10
- **Will it block?** NO
- **Web Server sees:** 45.33.32.1
- **Corrected rule:**
```bash
iptables -A INPUT -s 45.33.32.1 -j DROP
```

**The trap:** Routers don't change source IPs. The scanner's real IP passes through.

---

## Section D: Return Traffic

### Problem 11
- **Point A:** SRC=93.184.216.34, DST=203.0.113.5
- **Point B:** SRC=93.184.216.34, DST=10.0.0.50
- **What changes it?** NAT connection tracking (conntrack)

**Key insight:** NAT remembers the original mapping and reverses it for return traffic.

### Problem 12
- **Point A:** SRC=10.0.0.100, DST=72.45.67.89
- **Point B:** SRC=203.0.113.10, DST=72.45.67.89

**Key insight:** Conntrack reverses DNAT—the source IP changes back to the public IP so the client recognizes the response.

---

## Scoring

| Section | Questions | Points |
|---------|-----------|--------|
| A: Outbound NAT | Q1-Q3 | 30 |
| B: Inbound NAT | Q4-Q5 | 20 |
| C: Troubleshooting | Q6-Q10 | 40 |
| D: Return Traffic | Q11-Q12 | 10 |

**Total: 100 points**
**Passing: 85 points**

---

## The Golden Rules

| Rule | Explanation |
|------|-------------|
| **NAT changes source (outbound)** | SNAT/MASQUERADE rewrites source IP |
| **NAT changes destination (inbound)** | DNAT rewrites destination IP |
| **Routers DON'T change IPs** | They only forward packets |
| **Source survives DNAT** | Attacker's real IP reaches the server |
| **Conntrack reverses translations** | Return traffic is automatically handled |

---

## Next Steps

If you scored below 85%, review the problems you missed and retry in 24 hours. Spaced repetition is key.

**[⭐ Star the GitHub repo](https://github.com/YOUR_USERNAME/security-engineering-prep)** for more Security Engineering interview prep materials!

---

*Did this help you? Drop a comment with your score! Let's see how many people can hit 100%.*
