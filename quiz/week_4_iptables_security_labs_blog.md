---
title: "Master iptables Security: 4 Production-Ready Firewall Scenarios"
published: false
description: "Hands-on iptables security labs covering web servers, corporate DMZ, NAT troubleshooting, and bastion hosts. Test your skills with realistic scenarios."
tags: security, linux, networking, cybersecurity
canonical_url: 
cover_image: 
---

## Introduction

Understanding iptables is a fundamental skill for Security Engineers, System Administrators, and DevOps professionals. Yet most engineers learn iptables through toy examples that don't reflect real-world complexity. This article presents **four production-grade security scenarios** that will test your understanding of:

- **Stateful firewalls** and connection tracking
- **NAT configurations** (DNAT, SNAT, MASQUERADE)  
- **Defense-in-depth** security controls
- **Attack surface reduction** through network segmentation
- **Security logging** and monitoring

These labs are designed to prepare you for actual Security Engineering interviews and on-the-job firewall configuration. Each scenario includes detailed network diagrams, specific requirements, and security constraints you'd encounter in production environments.

**Time commitment:** 5-7 hours total for all scenarios  
**Difficulty:** Intermediate to Advanced  
**Prerequisites:** Basic understanding of TCP/IP, Linux command line, and iptables syntax

---

## Sources & References

These labs are based on industry-standard security engineering practices and curriculum materials:

- **Grace Nolan's Security Engineering Notes** - [github.com/gracenolan/Notes](https://github.com/gracenolan/Notes) - Comprehensive security interview preparation resource
- **Complete 48-Week Security Engineering Curriculum** (Pages 13-14) - Networking fundamentals and firewall configuration methodology

All exercises follow production security best practices for enterprise firewall configurations.

---

## Scenario 1: Startup Web Application Firewall

**Difficulty:** ⭐⭐☆☆☆ (Intermediate)  
**Time estimate:** 60-90 minutes

You are the first Security Engineer at a startup. The engineering team has deployed their web application and asks you to configure the server's firewall.

### Network Diagram

```
                                    INTERNET
                                        │
                                        │
                                        │
                    ┌───────────────────┴───────────────────┐
                    │                                       │
                    │                                       │
           ┌───────┴───────┐                       ┌───────┴───────┐
           │   Legitimate  │                       │   Attackers   │
           │     Users     │                       │  (anywhere)   │
           │               │                       │               │
           └───────┬───────┘                       └───────┬───────┘
                   │                                       │
                   │                                       │
                   └───────────────────┬───────────────────┘
                                       │
                                       │
                              ┌────────┴────────┐
                              │                 │
                              │   Web Server    │
                              │                 │
                              │  104.196.45.120 │
                              │                 │
                              │  Services:      │
                              │  - HTTPS (443)  │
                              │  - SSH (22)     │
                              │                 │
                              │  eth0 (public)  │
                              │                 │
                              └─────────────────┘
```

### Requirements

1. The web application must be accessible via HTTPS from anywhere on the internet
2. SSH must only be accessible from the CTO's home IP: `73.189.45.22`
3. The server must be able to resolve DNS to function properly
4. The server must be able to download security updates from Ubuntu repositories
5. Protect SSH from brute force attacks (max 4 attempts per minute)
6. Drop all other inbound traffic
7. Log dropped packets for security monitoring

### Your Task

Write a complete iptables firewall configuration for this server. Include comments explaining each rule.

**Hint:** Remember that your server needs to initiate outbound connections for DNS and package updates. Don't forget the loopback interface!

---

## Scenario 2: Corporate Network with DMZ

**Difficulty:** ⭐⭐⭐⭐☆ (Advanced)  
**Time estimate:** 2-3 hours

You've been hired as a Security Engineer at a mid-size company. They have a standard three-tier network architecture and need you to configure the firewall that sits between all three zones.

### Network Diagram

```
                                         INTERNET
                                             │
                                             │
                                    ┌────────┴────────┐
                                    │  ISP Router     │
                                    │  (not managed)  │
                                    └────────┬────────┘
                                             │
                                             │ 203.0.113.1 (gateway)
                                             │
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                     │
│                                      FIREWALL                                       │
│                                                                                     │
│     eth0 (WAN)                    eth1 (DMZ)                    eth2 (LAN)          │
│     203.0.113.10                  10.0.1.1                      10.0.0.1            │
│                                                                                     │
└─────────┬─────────────────────────────┬─────────────────────────────┬───────────────┘
          │                             │                             │
          │                             │                             │
          │                    ┌────────┴────────┐           ┌────────┴────────┐
          │                    │   DMZ Network   │           │   LAN Network   │
          │                    │   10.0.1.0/24   │           │   10.0.0.0/24   │
          │                    └────────┬────────┘           └────────┬────────┘
          │                             │                             │
          │               ┌─────────────┼─────────────┐               │
          │               │             │             │               │
          │        ┌──────┴──────┐ ┌────┴────┐ ┌──────┴──────┐ ┌──────┴──────┐
          │        │ Web Server  │ │  Mail   │ │ DNS Server  │ │ Employee    │
          │        │ 10.0.1.10   │ │ Server  │ │ 10.0.1.30   │ │ Workstations│
          │        │             │ │10.0.1.20│ │             │ │10.0.0.50-200│
          │        │ HTTPS: 443  │ │         │ │ DNS: 53     │ │             │
          │        │ HTTP: 80    │ │SMTP: 25 │ │             │ │             │
          │        └─────────────┘ │IMAPS:993│ └─────────────┘ └─────────────┘
          │                        └─────────┘
          │
          │
   ┌──────┴──────┐
   │ Admin VPN   │
   │ Endpoint    │
   │             │
   │ 198.51.100.50│
   │             │
   │ (needs SSH  │
   │  to all DMZ │
   │  servers)   │
   └─────────────┘
```

### Traffic Flow Requirements

| Source | Destination | Service | Port(s) | Allow? |
|--------|-------------|---------|---------|--------|
| Internet | Web Server | HTTPS | 443 | Yes |
| Internet | Web Server | HTTP | 80 | Yes (redirect to HTTPS) |
| Internet | Mail Server | SMTP | 25 | Yes |
| Internet | Mail Server | IMAPS | 993 | Yes |
| Internet | DNS Server | DNS | 53/udp, 53/tcp | Yes |
| Admin VPN (198.51.100.50) | All DMZ Servers | SSH | 22 | Yes |
| Employee Workstations | Internet | HTTP/HTTPS | 80, 443 | Yes |
| Employee Workstations | Internet | DNS | 53 | Yes |
| DMZ Servers | Internet | DNS | 53 | Yes (for updates) |
| DMZ Servers | Internet | HTTP/HTTPS | 80, 443 | Yes (for updates) |
| Any | Any | ICMP ping | - | Rate limited |
| Everything else | - | - | - | DROP and LOG |

### Security Requirements

1. **Brute Force Protection:** SSH must be protected against brute force (max 5 attempts per 60 seconds per source IP)
2. **Port Scan Detection:** Block packets with invalid TCP flag combinations (NULL, XMAS, SYN+FIN)
3. **SYN Flood Protection:** Rate limit incoming SYN packets to 50/second
4. **Connection Limits:** No single IP can have more than 50 concurrent connections to any server
5. **Logging:** All dropped traffic must be logged with appropriate prefixes
6. **NAT:** 
   - External users access DMZ services via the firewall's public IP (203.0.113.10)
   - Internal users and DMZ servers access internet via MASQUERADE

### Your Task

Write a complete iptables firewall configuration for this corporate network. This firewall handles traffic between all three zones.

**Critical considerations:**
- Use the FORWARD chain for traffic passing through the firewall
- Implement DNAT in PREROUTING for inbound services
- Use MASQUERADE in POSTROUTING for outbound NAT
- Apply security controls (rate limiting, logging) before ACCEPT rules

---

## Scenario 3: Remote File Server Debugging

**Difficulty:** ⭐⭐☆☆☆ (Intermediate)  
**Time estimate:** 60-90 minutes

You're a Security Consultant hired to debug a broken firewall. A company has a cloud-hosted file server that developers access remotely. The firewall was configured by a contractor who is no longer available, and multiple issues have been reported.

### Network Diagram

```
                              SEATTLE OFFICE
                              (NAT Router)
      ┌─────────────────┐     WAN: 52.12.45.100
      │                 │     LAN: 192.168.1.0/24
      │   DEVELOPER A   │     
      │                 │     ┌─────────────────┐
      │  192.168.1.50   │─────│   NAT Router    │─────┐
      │                 │     └─────────────────┘     │
      │  Needs:         │                             │
      │  - HTTPS        │                             │
      │  - SSH          │                             │
      │                 │                             │
      └─────────────────┘                             │
                                                      │
                                                      │
                              INTERNET                │
                                  │                   │
                                  │                   │
      ┌───────────────────────────┴───────────────────┘
      │
      │
      │   AUSTIN OFFICE
      │   (NAT Router)
      │   WAN: 104.210.32.55
      │   LAN: 192.168.1.0/24
      │
      │   ┌─────────────────┐
      └───│   NAT Router    │
          └────────┬────────┘
                   │
                   │
      ┌────────────┴─────────┐
      │                      │
      │   DEVELOPER B        │
      │                      │
      │  192.168.1.75        │
      │                      │
      │  Needs:              │
      │  - HTTPS             │
      │  - SSH               │
      │                      │
      └──────────────────────┘



                                   ┌─────────────────┐
                                   │                 │
                                   │   FILE SERVER   │
                                   │                 │
                                   │  20.141.12.34   │
                                   │                 │
                                   │  Services:      │
                                   │  - HTTPS (443)  │
                                   │  - SSH (22)     │
                                   │                 │
                                   └─────────────────┘
```

### Current File Server Firewall (BROKEN)

```bash
# Chain policies
iptables -P INPUT DROP
iptables -P FORWARD DROP  
iptables -P OUTPUT DROP

# Input rules
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -d 20.141.12.34 --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.1.50 -d 20.141.12.34 --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.1.75 -d 20.141.12.34 --dport 22 -j ACCEPT

# Output rules
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

### Reported Problems

1. **Seattle developer** can access HTTPS but cannot SSH to the server
2. **Austin developer** can access HTTPS but cannot SSH to the server  
3. **Neither developer** can ping the server
4. **Server** cannot download security updates
5. **Server** cannot resolve DNS names

### Your Task

#### Part A: Root Cause Analysis

For each reported problem, explain the root cause. Why is the current configuration failing?

#### Part B: Write the Fixed Firewall

Write a corrected firewall configuration that:
- Fixes all reported problems
- Allows HTTPS from anywhere
- Allows SSH from both office public IPs
- Allows ping (rate limited)
- Allows server to download updates and resolve DNS
- Logs dropped packets

**Critical insight:** Remember that NAT routers translate private IPs to public IPs. The file server sees the WAN IP, not the LAN IP!

---

## Scenario 4: Multi-Tier Application with Bastion Host

**Difficulty:** ⭐⭐⭐⭐⭐ (Expert)  
**Time estimate:** 2-3 hours

Your company runs a production application in AWS. Security policy requires all administrative access go through a bastion (jump) host. You're configuring the bastion's firewall.

### Network Diagram

```
                                        INTERNET
                                            │
                                            │
               ┌────────────────────────────┴────────────────────────────┐
               │                                                         │
               │                                                         │
      ┌────────┴────────┐                                               │
      │                 │                                               │
      │  Security Team  │                                               │
      │  Office NAT     │                                               │
      │                 │                                               │
      │  WAN: 198.51.100.10                                             │
      │  LAN: 10.50.0.1 │                                               │
      │                 │                                               │
      └────────┬────────┘                                               │
               │                                                         │
      ┌────────┴────────┐                                               │
      │  Security       │                                               │
      │  Engineers      │                                               │
      │                 │                                               │
      │  10.50.0.20-30  │                                               │
      │                 │                                               │
      │  Needs SSH to:  │                                               │
      │  - Bastion      │                                               │
      │  - App servers  │                                               │
      │    (via bastion)│                                               │
      └─────────────────┘                                               │
                                                                        │
                                                                        │
                              ┌─────────────────────────────────────────┘
                              │
                              │
                     ┌────────┴────────┐
                     │   AWS VPC       │
                     │   10.0.0.0/16   │
                     │                 │
                     └────────┬────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         │                    │                    │
┌────────┴────────┐  ┌────────┴────────┐  ┌───────┴─────────┐
│ PUBLIC SUBNET   │  │ PRIVATE SUBNET  │  │ DATABASE SUBNET │
│ 10.0.1.0/24     │  │ 10.0.2.0/24     │  │ 10.0.3.0/24     │
│                 │  │                 │  │                 │
│ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │
│ │   BASTION   │ │  │ │  App Server │ │  │ │  Database   │ │
│ │             │ │  │ │  #1         │ │  │ │  Primary    │ │
│ │ eth0:       │ │  │ │             │ │  │ │             │ │
│ │ 10.0.1.10   │ │  │ │ 10.0.2.10   │ │  │ │ 10.0.3.10   │ │
│ │ (has EIP:   │ │  │ │             │ │  │ │             │ │
│ │ 54.23.45.67)│ │  │ └─────────────┘ │  │ └─────────────┘ │
│ │             │ │  │                 │  │                 │
│ │ eth1:       │ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │
│ │ 10.0.2.1    │ │  │ │  App Server │ │  │ │  Database   │ │
│ │ (private    │ │  │ │  #2         │ │  │ │  Replica    │ │
│ │  subnet gw) │ │  │ │             │ │  │ │             │ │
│ │             │ │  │ │ 10.0.2.11   │ │  │ │ 10.0.3.11   │ │
│ └─────────────┘ │  │ │             │ │  │ │             │ │
│                 │  │ └─────────────┘ │  │ └─────────────┘ │
└─────────────────┘  └─────────────────┘  └─────────────────┘

Traffic Flows:
- Security Team SSHs to Bastion (via NAT router WAN IP)
- Bastion SSHs to App Servers (internal)
- App Servers need outbound HTTP/HTTPS/DNS (via Bastion NAT)
- App Servers connect to Database (internal, no NAT)
- Database has NO internet access (strict isolation)
```

### Requirements

1. **External SSH to Bastion:**
   - Only Security Team office (public IP: 198.51.100.10) can SSH to Bastion
   - Rate limit: 3 attempts per minute (strict security)
   - Log all SSH attempts (successful and blocked)

2. **Bastion to Internal SSH:**
   - Bastion can SSH to App Servers (10.0.2.0/24) only
   - Bastion CANNOT SSH to Database subnet (10.0.3.0/24) — separation of duties
   - DBA team has separate access path (not your concern)

3. **NAT Gateway Function:**
   - App Servers access internet via Bastion (MASQUERADE)
   - Restricted egress: DNS (53), HTTP (80), HTTPS (443) only
   - Log denied egress attempts

4. **Database Isolation:**
   - NO traffic from Bastion to Database subnet
   - NO traffic from Database subnet through Bastion
   - This is enforced at Bastion level as defense-in-depth

5. **Port Scan Detection:**
   - Detect and log NULL, XMAS, SYN+FIN scans on external interface
   - Drop invalid packets

### Your Task

Write the complete Bastion host firewall configuration. Remember:
- Enable IP forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward`
- Use INPUT for traffic destined to the bastion itself
- Use OUTPUT for traffic originating from the bastion
- Use FORWARD for traffic passing through the bastion
- Database isolation rules must appear BEFORE any ACCEPT rules

**Defense-in-depth principle:** Even though AWS Security Groups might block database access, the bastion's firewall enforces this rule as well.

---

## Grading Rubric

### Overall Evaluation Criteria

| Criterion | Points |
|-----------|--------|
| Correct chain selection (INPUT/OUTPUT/FORWARD) | 15 |
| Proper stateful rules (ESTABLISHED,RELATED first) | 15 |
| Correct NAT configuration (DNAT/SNAT/MASQUERADE) | 15 |
| Understanding of NAT IP translation | 15 |
| Brute force protection implementation | 10 |
| Port scan detection rules | 10 |
| Proper logging configuration | 5 |
| Complete solution (no missing rules) | 10 |
| Correct syntax | 5 |

**Total: 100 points**  
**Passing Score: 85%**

---

## Answer Key

> ⚠️ **Attempt all scenarios before viewing the answer key!** These solutions represent one valid approach, but multiple correct solutions exist.

### Scenario 1: Startup Web Application - Solution

```bash
#!/bin/bash
# Startup Web Application Firewall
# Server IP: 104.196.45.120
# CTO Home IP: 73.189.45.22

# Default policies (drop everything by default)
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Connection tracking - ACCEPT established connections first (performance)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Loopback interface (required for local services)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# HTTPS from anywhere (public web service)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# SSH with brute force protection (CTO only)
# Track SSH attempts - mark source IP when SSH attempt occurs
iptables -A INPUT -p tcp -s 73.189.45.22 --dport 22 -m conntrack --ctstate NEW -m recent --set

# Rate limit: Drop if >4 attempts in 60 seconds
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# Accept SSH from CTO if under rate limit
iptables -A INPUT -p tcp -s 73.189.45.22 --dport 22 -j ACCEPT

# DNS resolution (TCP and UDP, both needed)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Package updates (HTTP and HTTPS)
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Logging dropped packets
iptables -A INPUT -j LOG --log-prefix "INPUT_DROPPED: "
iptables -A OUTPUT -j LOG --log-prefix "OUTPUT_DROPPED: "

# Default DROP (explicit for clarity, policies already set)
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
```

**Key concepts:**
- Default DROP policies enforce "deny all, permit explicitly"
- Connection tracking reduces rules needed for return traffic
- `recent` module provides stateful rate limiting per source IP
- Both TCP and UDP DNS are required (TCP for large responses)

---

### Scenario 2: Corporate DMZ - Solution

```bash
#!/bin/bash
# Corporate Three-Tier Firewall
# WAN: eth0 (203.0.113.10)
# DMZ: eth1 (10.0.1.1)
# LAN: eth2 (10.0.0.1)

# Default policies
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Connection tracking (FORWARD is critical for router)
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Port scan detection (before other rules)
iptables -A FORWARD -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "PORT_SCAN_NULL: "
iptables -A FORWARD -p tcp --tcp-flags ALL NONE -j DROP

iptables -A FORWARD -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "PORT_SCAN_XMAS: "
iptables -A FORWARD -p tcp --tcp-flags ALL ALL -j DROP

iptables -A FORWARD -p tcp --tcp-flags ALL SYN,FIN -j LOG --log-prefix "PORT_SCAN_SYNFIN: "
iptables -A FORWARD -p tcp --tcp-flags ALL SYN,FIN -j DROP

# SYN flood protection (custom chain for modularity)
iptables -N syn_flood
iptables -A FORWARD -p tcp --syn -j syn_flood
iptables -A syn_flood -m limit --limit 50/s -j RETURN
iptables -A syn_flood -m limit --limit 5/s -j LOG --log-prefix "SYN_FLOOD: "
iptables -A syn_flood -j DROP

# ICMP rate limiting
iptables -A FORWARD -p icmp -m limit --limit 50/s -j ACCEPT
iptables -A FORWARD -p icmp -j LOG --log-prefix "ICMP_FLOOD: "
iptables -A FORWARD -p icmp -j DROP

# NAT - DNAT for inbound services (PREROUTING, before routing decision)
# Internet → Web Server (HTTP/HTTPS)
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 10.0.1.10:80
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to-destination 10.0.1.10:443

# Internet → Mail Server (SMTP/IMAPS)
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 25 -j DNAT --to-destination 10.0.1.20:25
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 993 -j DNAT --to-destination 10.0.1.20:993

# Internet → DNS Server
iptables -t nat -A PREROUTING -i eth0 -p udp --dport 53 -j DNAT --to-destination 10.0.1.30:53
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 53 -j DNAT --to-destination 10.0.1.30:53

# NAT - MASQUERADE for outbound traffic (POSTROUTING, after routing decision)
iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE

# FORWARD rules (traffic passing through firewall)
# Internet → Web Server (with connection limits)
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.10 --dport 80 -j LOG --log-prefix "WEB_CONN_LIMIT: "
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.10 --dport 80 -j DROP
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d 10.0.1.10 --dport 80 -j ACCEPT

iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.10 --dport 443 -j LOG --log-prefix "WEB_CONN_LIMIT: "
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.10 --dport 443 -j DROP
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d 10.0.1.10 --dport 443 -j ACCEPT

# Internet → Mail Server
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d 10.0.1.20 --dport 25 -j ACCEPT
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d 10.0.1.20 --dport 993 -j ACCEPT

# Internet → DNS Server
iptables -A FORWARD -p udp -i eth0 -o eth1 -d 10.0.1.30 --dport 53 -j ACCEPT
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d 10.0.1.30 --dport 53 -j ACCEPT

# Admin VPN → DMZ SSH (with brute force protection)
iptables -A FORWARD -p tcp -s 198.51.100.50 -i eth0 -o eth1 -d 10.0.1.0/24 --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -A FORWARD -p tcp -s 198.51.100.50 -d 10.0.1.0/24 --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 5 -j DROP
iptables -A FORWARD -p tcp -s 198.51.100.50 -i eth0 -o eth1 -d 10.0.1.0/24 --dport 22 -j ACCEPT

# Employee workstations → Internet
iptables -A FORWARD -i eth2 -o eth0 -s 10.0.0.0/24 -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A FORWARD -i eth2 -o eth0 -s 10.0.0.0/24 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i eth2 -o eth0 -s 10.0.0.0/24 -p tcp --dport 53 -j ACCEPT

# DMZ servers → Internet (updates)
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.1.0/24 -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.1.0/24 -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.1.0/24 -p tcp --dport 53 -j ACCEPT

# Loopback for firewall itself
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow firewall to resolve DNS and perform updates
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# ICMP for firewall itself
iptables -A OUTPUT -p icmp -j ACCEPT

# Final logging
iptables -A FORWARD -j LOG --log-prefix "FORWARD_DROPPED: "
iptables -A INPUT -j LOG --log-prefix "INPUT_DROPPED: "
iptables -A OUTPUT -j LOG --log-prefix "OUTPUT_DROPPED: "
```

**Key concepts:**
- DNAT happens in PREROUTING (before routing decision)
- MASQUERADE happens in POSTROUTING (after routing decision)
- Security controls (port scan detection, rate limiting) go BEFORE ACCEPT rules
- Connection tracking eliminates need for explicit return traffic rules
- `-i` and `-o` specify interfaces to prevent routing loops

---

### Scenario 3: Remote File Server - Solution

#### Part A: Root Cause Analysis

**Problem 1 (Seattle SSH fails):**

The File Server exists outside Seattle's LAN. The source address `192.168.1.50` is meaningless to the File Server because NAT translates it to `52.12.45.100`. The firewall rule:

```bash
iptables -A INPUT -p tcp -s 192.168.1.50 -d 20.141.12.34 --dport 22 -j ACCEPT
```

Should be:

```bash
iptables -A INPUT -p tcp -s 52.12.45.100 -d 20.141.12.34 --dport 22 -j ACCEPT
```

**Problem 2 (Austin SSH fails):**

Similar problem - the firewall rule:

```bash
iptables -A INPUT -p tcp -s 192.168.1.75 -d 20.141.12.34 --dport 22 -j ACCEPT
```

Should be:

```bash
iptables -A INPUT -p tcp -s 104.210.32.55 -d 20.141.12.34 --dport 22 -j ACCEPT
```

**Problem 3 (Ping fails):**

No ICMP rules exist in the INPUT chain. Add:

```bash
iptables -A INPUT -p icmp -d 20.141.12.34 -j ACCEPT
```

**Problem 4 (No updates):**

The OUTPUT chain has no rule for HTTP/HTTPS. Add:

```bash
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
```

**Problem 5 (DNS fails):**

The OUTPUT chain has no DNS rules. Add:

```bash
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
```

#### Part B: Fixed Firewall

```bash
#!/bin/bash
# Fixed File Server Firewall
# Server IP: 20.141.12.34
# Seattle Office WAN: 52.12.45.100
# Austin Office WAN: 104.210.32.55

iptables -F

# Chain policies
iptables -P INPUT DROP
iptables -P FORWARD DROP  
iptables -P OUTPUT DROP

# Connection tracking
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# HTTPS from anywhere
iptables -A INPUT -p tcp -d 20.141.12.34 --dport 443 -j ACCEPT

# SSH from Seattle Office (public IP)
iptables -A INPUT -p tcp -s 52.12.45.100 -d 20.141.12.34 --dport 22 -j ACCEPT

# SSH from Austin Office (public IP)
iptables -A INPUT -p tcp -s 104.210.32.55 -d 20.141.12.34 --dport 22 -j ACCEPT

# ICMP (rate limited)
iptables -A INPUT -p icmp -d 20.141.12.34 -m limit --limit 5/min -j ACCEPT
iptables -A INPUT -p icmp -d 20.141.12.34 -j LOG --log-prefix "ICMP_EXCEEDED: "
iptables -A INPUT -p icmp -d 20.141.12.34 -j DROP

# Server outbound for updates and DNS
iptables -A OUTPUT -s 20.141.12.34 -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A OUTPUT -s 20.141.12.34 -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -s 20.141.12.34 -p udp --dport 53 -j ACCEPT

# Final logging
iptables -A INPUT -j LOG --log-prefix "INPUT_DROPPED: "
iptables -A OUTPUT -j LOG --log-prefix "OUTPUT_DROPPED: "
```

**Key lesson:** Always remember that NAT routers translate private IPs to public IPs. Servers behind NAT cannot see RFC 1918 addresses from remote locations.

---

### Scenario 4: Bastion Host - Solution

```bash
#!/bin/bash
# Bastion Host Firewall
# Public Interface: eth0 (10.0.1.10, EIP: 54.23.45.67)
# Private Interface: eth1 (10.0.2.1)
# App Subnet: 10.0.2.0/24
# Database Subnet: 10.0.3.0/24 (BLOCKED)

# Enable IP Forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Default policies
iptables -P FORWARD DROP
iptables -P INPUT DROP
iptables -P OUTPUT DROP

# Connection tracking (critical for all chains)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Port scan detection on external interface (before other INPUT rules)
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "SCAN_NULL: "
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL NONE -j DROP

iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "SCAN_XMAS: "
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL ALL -j DROP

iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL SYN,FIN -j LOG --log-prefix "SCAN_SYNFIN: "
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL SYN,FIN -j DROP

# Drop invalid packets
iptables -A INPUT -i eth0 -m conntrack --ctstate INVALID -j LOG --log-prefix "INVALID: "
iptables -A INPUT -i eth0 -m conntrack --ctstate INVALID -j DROP

# Database isolation (BEFORE any ACCEPT rules in FORWARD)
iptables -A FORWARD -s 10.0.3.0/24 -j LOG --log-prefix "DATABASE_EGRESS_BLOCKED: "
iptables -A FORWARD -s 10.0.3.0/24 -j DROP

iptables -A FORWARD -d 10.0.3.0/24 -j LOG --log-prefix "DATABASE_ACCESS_BLOCKED: "
iptables -A FORWARD -d 10.0.3.0/24 -j DROP

# Database isolation for bastion itself
iptables -A OUTPUT -s 10.0.1.0/24 -d 10.0.3.0/24 -j LOG --log-prefix "BASTION_TO_DB_BLOCKED: "
iptables -A OUTPUT -s 10.0.1.0/24 -d 10.0.3.0/24 -j DROP

# NAT - MASQUERADE for App Servers
iptables -t nat -A POSTROUTING -s 10.0.2.0/24 -o eth0 -j MASQUERADE

# External SSH to Bastion (with rate limiting and logging)
iptables -A INPUT -i eth0 -s 198.51.100.10 -p tcp --dport 22 -m limit --limit 3/min -j LOG --log-prefix "SSH_ALLOWED: "
iptables -A INPUT -i eth0 -s 198.51.100.10 -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT

iptables -A INPUT -i eth0 -s 198.51.100.10 -p tcp --dport 22 -j LOG --log-prefix "SSH_RATE_LIMITED: "
iptables -A INPUT -i eth0 -s 198.51.100.10 -p tcp --dport 22 -j DROP

# Bastion → App Servers SSH (OUTPUT chain - bastion is source)
iptables -A OUTPUT -p tcp -s 10.0.1.0/24 -d 10.0.2.0/24 --dport 22 -j ACCEPT

# App Servers → Internet (FORWARD chain - traffic passing through)
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.2.0/24 -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.2.0/24 -p tcp --dport 53 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.2.0/24 -p udp --dport 53 -j ACCEPT

# Log denied egress from App Servers
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.2.0/24 -j LOG --log-prefix "APP_EGRESS_DENIED: "
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.2.0/24 -j DROP

# Final logging
iptables -A INPUT -j LOG --log-prefix "INPUT_DROPPED: "
iptables -A OUTPUT -j LOG --log-prefix "OUTPUT_DROPPED: "
iptables -A FORWARD -j LOG --log-prefix "FORWARD_DROPPED: "
```

**Key concepts:**
- INPUT: traffic destined TO the bastion
- OUTPUT: traffic originating FROM the bastion
- FORWARD: traffic THROUGH the bastion (acting as router)
- Explicit denies for database access implement defense-in-depth
- Rate limiting on SSH protects against brute force from trusted network

---

## Conclusion & Next Steps

Congratulations on working through these production-grade iptables scenarios! You've now practiced:

✅ **Stateful firewall design** with connection tracking  
✅ **NAT configurations** (DNAT, SNAT, MASQUERADE)  
✅ **Attack surface reduction** through explicit deny rules  
✅ **Defense-in-depth** with multiple security layers  
✅ **Security logging** for incident detection  
✅ **Real-world debugging** of broken configurations

### Want More Security Engineering Challenges?

These labs are part of a larger collection of Security Engineering exercises covering:

- **Application Security:** SAST/DAST, secure code review, vulnerability assessment
- **Cloud Security:** AWS/Azure security configurations, IAM policies
- **Cryptography:** Implementation challenges, protocol security
- **Web Security:** OWASP Top 10, API security, authentication flaws

**⭐ Star the repository for more exercises:**  
👉 **[github.com/fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)** 👈

Each exercise includes:
- Detailed scenarios based on real interview questions
- Step-by-step solutions with explanations
- Grading rubrics for self-assessment
- References to industry-standard resources

### Additional Resources

If you found these labs valuable, here are some recommended resources for deepening your security engineering knowledge:

**Security Engineering References:**
- Grace Nolan's Security Engineering Notes - [github.com/gracenolan/Notes](https://github.com/gracenolan/Notes)
- OWASP Testing Guide - [owasp.org/www-project-web-security-testing-guide](https://owasp.org/www-project-web-security-testing-guide/)
- PortSwigger Web Security Academy - [portswigger.net/web-security](https://portswigger.net/web-security)

**iptables Documentation:**
- Netfilter Documentation - [netfilter.org/documentation](https://netfilter.org/documentation/)
- iptables Tutorial by Oskar Andreasson - Comprehensive iptables guide
- Linux iptables Pocket Reference - Quick reference for common patterns

### Share Your Solutions

Did you find alternative solutions to these scenarios? Security engineering often has multiple valid approaches! Share your solutions and discuss different strategies in the GitHub repository's Discussions section.

### Practice Makes Perfect

The best way to master iptables and firewall security is through hands-on practice. Set up virtual machines, test your rules, intentionally break configurations, and learn to debug them. Each scenario you solve builds your intuition for network security.

Happy firewalling! 🔥🛡️

---

*About the Author: These exercises are designed to help aspiring Security Engineers prepare for technical interviews and real-world security challenges. Follow my journey and more security engineering content at [github.com/fosres](https://github.com/fosres).*
