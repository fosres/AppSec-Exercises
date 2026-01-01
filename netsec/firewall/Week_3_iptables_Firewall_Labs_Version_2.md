# WEEK 3 IPTABLES FIREWALL CHALLENGES - CORRECTED VERSION
## Hands-On Lab Exercises with Grading

**Format:** You write the iptables script, test it, save the ruleset, and upload for grading.

**Time Required:** 4 hours (1 hour per challenge + grading)  
**Prerequisites:** Basic iptables knowledge (chains, rules, stateful tracking)  
**Deliverable:** 4 iptables rulesets saved as text files for grading

---

## HOW TO SUBMIT YOUR WORK

### Step 1: Write Your Solution

```bash
# Create your firewall script
vim firewall-challenge-1.sh

#!/bin/bash
# Your iptables rules here
iptables -A INPUT ...
```

### Step 2: Apply and Test

```bash
# Make executable and run
chmod +x firewall-challenge-1.sh
sudo ./firewall-challenge-1.sh

# Test your rules work
# (Test commands provided in each challenge)
```

### Step 3: Save Ruleset

```bash
# Save your iptables rules to file
sudo iptables-save > challenge-1-rules.txt

# This file contains your complete ruleset for grading
```

### Step 4: Upload for Grading

```
Upload your challenge-X-rules.txt file
I will grade it against:
- Security requirements (40 points)
- Best practices (30 points)
- Compliance requirements (20 points)
- Testing verification (10 points)
```

---

## CHALLENGE 1: DMZ WEB SERVER (Basic)

### Scenario

You're securing a web hosting company's DMZ. The architecture:

```
                    INTERNET
                        ↓
                   [Firewall]  ← You configure this
                        ↓
                    DMZ Zone
               (10.0.1.0/24)
                        ↓
            ┌───────────┴───────────┐
            ↓                       ↓
     [Web Server 1]          [Web Server 2]
     10.0.1.10               10.0.1.11
     - Nginx                 - Nginx
     - Port 80, 443          - Port 80, 443
```

### Requirements

**Your task:** Configure iptables on the firewall to:

1. **Public Access:**
   - Allow HTTP (80) and HTTPS (443) traffic from internet to both web servers
   - Allow ICMP (ping) to web servers for monitoring

2. **Administrative Access:**
   - Allow SSH (22) to web servers ONLY from admin network: 192.168.50.0/24
   - Deny SSH from all other sources

3. **Outbound Requirements:**
   - Web servers can make HTTPS (443) connections for software updates
   - Web servers can make DNS (53) queries
   - Block all other outbound connections from DMZ

4. **Security Baseline:**
   - Implement stateful connection tracking (ESTABLISHED,RELATED)
   - Use default-deny policy (drop everything not explicitly allowed)
   - Allow loopback traffic (lo interface)
   - Log dropped SSH attempts (max 5 per minute to avoid log spam)

5. **Specific Blocks:**
   - Block all traffic to/from RFC 1918 private networks EXCEPT admin network
   - Drop invalid packets (connection tracking INVALID state)
   - Drop NULL packets, XMAS packets, SYN-flood protection

### Constraints

- Must use FORWARD chain (this is a gateway/firewall)
- Must be idempotent (can run script multiple times safely)
- All rules must have comments explaining purpose
- Must work with both IPv4

### Test Cases You Must Pass

```bash
# Test 1: HTTP from internet works
curl -v http://10.0.1.10

# Test 2: HTTPS from internet works
curl -v https://10.0.1.10

# Test 3: SSH from admin network works
ssh -o ConnectTimeout=5 admin@10.0.1.10  # From 192.168.50.0/24

# Test 4: SSH from internet FAILS
ssh -o ConnectTimeout=5 admin@10.0.1.10  # From random internet IP

# Test 5: Web server can reach internet HTTPS
# From web server: curl -v https://example.com

# Test 6: Web server can query DNS
# From web server: nslookup google.com

# Test 7: Ping to web server works
ping -c 3 10.0.1.10

# Test 8: Invalid packets dropped
# Use hping3 to send invalid packets - should be dropped
```

### Hints (Don't Look Until You Try!)

<details>
<summary>Hint 1: Script Structure</summary>

```bash
#!/bin/bash
# Flush existing rules first (idempotent)
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Set default policies LAST (after allow rules)
# Use FORWARD chain since this is a gateway

# Categories of rules:
# 1. Allow established connections (FIRST!)
# 2. Drop invalid packets (SECOND!)
# 3. Allow specific services
# 4. Logging rules
# 5. Default deny
```
</details>

<details>
<summary>Hint 2: Stateful Tracking</summary>

```bash
# Allow return traffic for established connections
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Drop invalid packets
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP
```
</details>

<details>
<summary>Hint 3: DMZ Web Server Rules</summary>

```bash
# Allow HTTP/HTTPS to web servers from anywhere
iptables -A FORWARD -d 10.0.1.10 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -d 10.0.1.11 -p tcp --dport 80 -j ACCEPT
# Repeat for port 443

# Allow SSH only from admin network
iptables -A FORWARD -s 192.168.50.0/24 -d 10.0.1.0/24 -p tcp --dport 22 -j ACCEPT
```
</details>

### Grading Rubric (100 points)

**Security Requirements (40 points):**
- [ ] 10 pts: Stateful tracking (ESTABLISHED,RELATED) present
- [ ] 10 pts: Default-deny policy implemented correctly
- [ ] 10 pts: SSH restricted to admin network only
- [ ] 5 pts: Invalid packets dropped
- [ ] 5 pts: Loopback traffic allowed

**Functional Requirements (30 points):**
- [ ] 10 pts: HTTP/HTTPS allowed from internet to web servers
- [ ] 5 pts: ICMP (ping) allowed to web servers
- [ ] 10 pts: Web servers can make outbound HTTPS connections
- [ ] 5 pts: Web servers can query DNS

**Best Practices (20 points):**
- [ ] 5 pts: Script is idempotent (flushes rules at start)
- [ ] 5 pts: Rules have comments explaining purpose
- [ ] 5 pts: Logging implemented for dropped SSH
- [ ] 5 pts: Protection against common attacks (NULL, XMAS, SYN-flood)

**Advanced Security (10 points):**
- [ ] 5 pts: RFC 1918 networks blocked (except admin network)
- [ ] 5 pts: Rate limiting on logging to prevent log spam

**Common Mistakes to Avoid:**
- ❌ Setting default policy to DROP before adding allow rules (locks you out!)
- ❌ Using INPUT chain instead of FORWARD chain (this is a gateway!)
- ❌ Forgetting ESTABLISHED,RELATED rule (connections will break)
- ❌ Not specifying source/destination correctly (rules too broad)
- ❌ Missing loopback rule (breaks local processes)

### Submit Your Work

```bash
# Save your ruleset
sudo iptables-save > challenge-1-dmz-rules.txt

# Upload challenge-1-dmz-rules.txt for grading
```

---

## CHALLENGE 2: VLAN SEGMENTATION (Intermediate) - CORRECTED

### Scenario

You're securing an enterprise network with multiple VLANs for different departments:

```
                   [Core Router/Firewall]  ← You configure this
                            |
        ┌───────────────────┼───────────────────┐
        ↓                   ↓                   ↓
   VLAN 10             VLAN 20             VLAN 30
 Management          Engineering         Guest WiFi
 10.10.10.0/24      10.10.20.0/24       10.10.30.0/24
        ↓                   ↓                   ↓
  - File Servers      - Workstations      - Laptops
  - Domain Controllers - Build Servers    - Phones
  - Admin Tools       - Dev Databases     - IoT Devices
```

### Requirements

**Network Policies:**

1. **VLAN 10 (Management) - Highest Trust:**
   - Can access ANY network on ANY port (including VLAN 20, VLAN 30, Internet)
   - Can SSH to any system
   - Can access management interfaces (web UIs, databases, etc.)
   - **Has full administrative access everywhere**

2. **VLAN 20 (Engineering) - Medium Trust:**
   - Can access internet on ports 80, 443 (HTTP/HTTPS)
   - Can access VLAN 10 file servers on port 445 (SMB)
   - Can access VLAN 10 domain controllers on port 389 (LDAP)
   - **Cannot access VLAN 30**
   - Cannot be accessed from VLAN 30

3. **VLAN 30 (Guest WiFi) - Lowest Trust:**
   - Can ONLY access internet on ports 80, 443, 53 (HTTP/HTTPS/DNS)
   - **Cannot access any internal VLANs (VLAN 10 or VLAN 20)**
   - Cannot SSH anywhere
   - **Cannot be accessed from VLAN 20 or other Guest WiFi devices**
   - **CAN be accessed from VLAN 10 Management** (admins need to troubleshoot guests)

4. **Inter-VLAN Rules (Definitive Reference):**
   - VLAN 10 → VLAN 20: Allowed (management access)
   - VLAN 10 → VLAN 30: **Allowed (management needs to troubleshoot guest network)**
   - VLAN 10 → Internet: Allowed (all ports)
   - VLAN 20 → VLAN 10: Allowed ONLY on specific ports (file servers 445, LDAP 389)
   - VLAN 20 → VLAN 30: **DENIED**
   - VLAN 20 → Internet: Allowed (HTTP/HTTPS only)
   - VLAN 30 → VLAN 10: **DENIED**
   - VLAN 30 → VLAN 20: **DENIED**
   - VLAN 30 → Internet: Allowed (HTTP/HTTPS/DNS only)

5. **Security Requirements:**
   - Stateful connection tracking
   - Default-deny between VLANs
   - Anti-spoofing: Drop packets from VLAN interfaces with wrong source IPs
   - Log denied traffic between VLANs (rate-limited)

### Network Interfaces

```
eth0: WAN (internet) - 203.0.113.1
eth1: VLAN 10 (Management) - 10.10.10.1/24
eth2: VLAN 20 (Engineering) - 10.10.20.1/24
eth3: VLAN 30 (Guest WiFi) - 10.10.30.1/24
```

### Why Management (VLAN 10) Must Access Guest Network (VLAN 30)

**Critical Management Functions:**
- Troubleshoot guest WiFi connectivity issues
- Manage IoT devices on guest network
- Monitor guest network traffic for security
- Reconfigure guest access points
- Respond to guest network incidents
- Audit guest device compliance

**If VLAN 10 couldn't access VLAN 30:**
- ❌ Can't troubleshoot guest complaints
- ❌ Can't manage IoT devices
- ❌ Can't secure guest network
- ❌ Management VLAN becomes useless

### Test Cases

```bash
# ============================================
# TEST 1: VLAN 10 → VLAN 20 (Should WORK)
# ============================================
# From 10.10.10.5: 
ssh 10.10.20.10      # Management can SSH to engineering ✓
curl http://10.10.20.10  # Management can access any port ✓

# ============================================
# TEST 2: VLAN 10 → VLAN 30 (Should WORK)
# ============================================
# From 10.10.10.5:
ssh 10.10.30.15      # Management can SSH to guest devices ✓
ping 10.10.30.15     # Management can troubleshoot guests ✓

# ============================================
# TEST 3: VLAN 10 → Internet (Should WORK)
# ============================================
# From 10.10.10.5:
curl http://example.com      # Management can browse ✓
ssh git@github.com           # Management can use any port ✓

# ============================================
# TEST 4: VLAN 20 → Internet (Should WORK)
# ============================================
# From 10.10.20.5:
curl http://example.com      # Engineering can browse HTTP ✓
curl https://github.com      # Engineering can browse HTTPS ✓

# ============================================
# TEST 5: VLAN 20 → VLAN 10 SMB (Should WORK)
# ============================================
# From 10.10.20.5:
smbclient //10.10.10.50/share  # Engineering accesses file server (port 445) ✓

# ============================================
# TEST 6: VLAN 20 → VLAN 10 LDAP (Should WORK)
# ============================================
# From 10.10.20.5:
ldapsearch -h 10.10.10.5   # Engineering queries LDAP (port 389) ✓

# ============================================
# TEST 7: VLAN 20 → VLAN 30 (Should FAIL)
# ============================================
# From 10.10.20.5:
ping 10.10.30.15           # Engineering can't access guests ✗
ssh 10.10.30.15            # Blocked ✗

# ============================================
# TEST 8: VLAN 20 → Internet SSH (Should FAIL)
# ============================================
# From 10.10.20.5:
ssh git@github.com         # Only HTTP/HTTPS allowed ✗

# ============================================
# TEST 9: VLAN 30 → Internet (Should WORK)
# ============================================
# From 10.10.30.5:
curl http://example.com    # Guests can browse ✓
curl https://google.com    # Guests can use HTTPS ✓

# ============================================
# TEST 10: VLAN 30 → VLAN 10 (Should FAIL)
# ============================================
# From 10.10.30.5:
ping 10.10.10.5            # Guests can't access management ✗
ssh 10.10.10.5             # Blocked ✗

# ============================================
# TEST 11: VLAN 30 → VLAN 20 (Should FAIL)
# ============================================
# From 10.10.30.5:
ping 10.10.20.10           # Guests can't access engineering ✗

# ============================================
# TEST 12: Anti-Spoofing (Should FAIL)
# ============================================
# From 10.10.30.5: Send packet with spoofed source 10.10.10.5
# Firewall should DROP (wrong interface for source IP) ✗

# ============================================
# TEST 13: Stateful tracking (Should WORK)
# ============================================
# From 10.10.20.5: curl http://example.com
# Return traffic should be allowed automatically ✓
```

### Access Control Matrix (CORRECTED)

**Complete definitive access matrix:**

| Source | Destination | Protocol | Ports | Allowed? | Reason |
|--------|-------------|----------|-------|----------|--------|
| VLAN 10 | VLAN 20 | All | All | ✅ YES | Management needs full access |
| VLAN 10 | VLAN 30 | All | All | ✅ YES | **Management troubleshoots guests** |
| VLAN 10 | Internet | All | All | ✅ YES | Management needs all access |
| VLAN 20 | VLAN 10 | TCP | 445 | ✅ YES | File server access (SMB) |
| VLAN 20 | VLAN 10 | TCP | 389 | ✅ YES | Domain controller (LDAP) |
| VLAN 20 | VLAN 10 | All | Other | ❌ NO | Only specific ports allowed |
| VLAN 20 | VLAN 30 | All | All | ❌ NO | Engineering can't access guests |
| VLAN 20 | Internet | TCP | 80, 443 | ✅ YES | Web browsing only |
| VLAN 20 | Internet | All | Other | ❌ NO | Only HTTP/HTTPS allowed |
| VLAN 30 | VLAN 10 | All | All | ❌ NO | Guests can't access internal |
| VLAN 30 | VLAN 20 | All | All | ❌ NO | Guests can't access internal |
| VLAN 30 | Internet | TCP | 80, 443 | ✅ YES | Web browsing |
| VLAN 30 | Internet | TCP/UDP | 53 | ✅ YES | DNS queries |
| VLAN 30 | Internet | All | Other | ❌ NO | Only HTTP/HTTPS/DNS allowed |

**Return traffic (replies) for ALL connections flows via ESTABLISHED,RELATED rule**

### Hints

<details>
<summary>Hint 1: VLAN Structure</summary>

```bash
# Define VLAN networks as variables for clarity
MGMT_NET="10.10.10.0/24"
ENG_NET="10.10.20.0/24"
GUEST_NET="10.10.30.0/24"
INTERNET="0.0.0.0/0"

# Use FORWARD chain for inter-VLAN routing
```
</details>

<details>
<summary>Hint 2: Anti-Spoofing</summary>

```bash
# Drop packets arriving on wrong interface (anti-spoofing)
# Example: Packets claiming to be from MGMT_NET must arrive on eth1
iptables -A FORWARD -i eth2 -s $MGMT_NET -j DROP  # Wrong interface!
iptables -A FORWARD -i eth3 -s $MGMT_NET -j DROP  # Wrong interface!

# Do this for all VLANs
```
</details>

<details>
<summary>Hint 3: Management Access</summary>

```bash
# VLAN 10 (Management) gets full access to everything
# This INCLUDES VLAN 30 for guest network troubleshooting
iptables -A FORWARD -s $MGMT_NET -j ACCEPT

# This single rule allows:
# - VLAN 10 → VLAN 20 (all ports) ✓
# - VLAN 10 → VLAN 30 (all ports) ✓
# - VLAN 10 → Internet (all ports) ✓
```
</details>

<details>
<summary>Hint 4: Inter-VLAN Policy</summary>

```bash
# Allow VLAN 20 → VLAN 10 on specific ports only
iptables -A FORWARD -s $ENG_NET -d $MGMT_NET -p tcp --dport 445 -j ACCEPT  # SMB
iptables -A FORWARD -s $ENG_NET -d $MGMT_NET -p tcp --dport 389 -j ACCEPT  # LDAP

# Deny everything else from VLAN 20 → VLAN 10
iptables -A FORWARD -s $ENG_NET -d $MGMT_NET -j DROP
```
</details>

### Grading Rubric (100 points)

**VLAN Segmentation (30 points):**
- [ ] 10 pts: Management VLAN has unrestricted access (including to Guest VLAN)
- [ ] 10 pts: Engineering VLAN has appropriate restricted access
- [ ] 10 pts: Guest WiFi VLAN is properly isolated (except from Management)

**Inter-VLAN Security (30 points):**
- [ ] 10 pts: VLAN 10 → VLAN 20/30 allowed (management needs full access)
- [ ] 10 pts: VLAN 20 → VLAN 10 allowed only on specific ports (445, 389)
- [ ] 10 pts: VLAN 30 completely isolated from VLAN 10/20 (guests can't access internal)

**Security Controls (25 points):**
- [ ] 10 pts: Anti-spoofing rules prevent IP address spoofing
- [ ] 10 pts: Stateful tracking implemented correctly
- [ ] 5 pts: Logging implemented for denied inter-VLAN traffic

**Best Practices (15 points):**
- [ ] 5 pts: Clear variable definitions for networks
- [ ] 5 pts: Comments explain security rationale
- [ ] 5 pts: Script organized by VLAN/policy sections

### Submit Your Work

```bash
sudo iptables-save > challenge-2-vlan-rules.txt
```

---

## CHALLENGE 3: PCI-DSS COMPLIANCE ZONE (Advanced)

### Scenario

You're securing an e-commerce company's cardholder data environment (CDE) for PCI-DSS compliance:

```
                    INTERNET
                        ↓
                   [Firewall 1]  ← You configure
                        ↓
                 DMZ (Web Tier)
                 172.16.1.0/24
                        ↓
                   [Firewall 2]  ← You configure
                        ↓
            Application Tier (Out of scope)
                 172.16.2.0/24
                        ↓
                   [Firewall 3]  ← You configure
                        ↓
          Cardholder Data Environment (CDE)
                 172.16.3.0/24
           - Payment Gateway: 172.16.3.10
           - Card Database: 172.16.3.20
           - Tokenization Service: 172.16.3.30
```

### PCI-DSS Requirements to Implement

**Requirement 1.2.1:** Restrict inbound and outbound traffic to that which is necessary for the CDE

**Requirement 1.3.1:** Implement a DMZ to limit inbound traffic to only system components that provide authorized publicly accessible services

**Requirement 1.3.4:** Do not allow unauthorized outbound traffic from the CDE to the Internet

**Requirement 1.3.5:** Permit only "established" connections into the CDE

**Requirement 1.3.6:** Place system components that store cardholder data in an internal network zone, segregated from the DMZ

**Requirement 10.2.4:** Log all invalid access attempts

### Detailed Requirements

**Firewall 1 (Internet → DMZ):**
1. Allow HTTPS (443) from internet to web servers only
2. Allow SSH from jump box (203.0.113.50) ONLY
3. Log and deny all other inbound traffic
4. DMZ web servers can initiate HTTPS to internet (updates)
5. DMZ cannot initiate connections to CDE

**Firewall 2 (DMZ ↔ Application Tier):**
1. Web servers can connect to app servers on port 8080 only
2. App servers can respond (stateful return traffic)
3. App servers can connect to CDE on port 9443 (payment API) only
4. Log all denied traffic with rate limiting

**Firewall 3 (Application Tier ↔ CDE):**
1. ONLY app servers (172.16.2.0/24) can connect to CDE
2. Payment Gateway (172.16.3.10) accepts connections on port 9443 from app tier only
3. Card Database (172.16.3.20) accepts connections on port 5432 from payment gateway only
4. Tokenization Service (172.16.3.30) accepts connections on port 8443 from app tier only
5. CDE systems CANNOT initiate outbound connections to internet
6. CDE systems can only respond to established connections
7. All connection attempts to CDE must be logged
8. No SSH into CDE except from jump box (203.0.113.50)

**Security Controls:**
1. Implement connection rate limiting to CDE (max 100 connections/min per source)
2. Drop all packets with source routing enabled
3. Drop all fragmented packets to CDE (fragment attack prevention)
4. Implement strict anti-spoofing rules
5. Log all dropped packets to CDE (with rate limiting)

### Network Topology

```
Interfaces:
eth0: Internet (WAN)
eth1: DMZ - 172.16.1.0/24
eth2: Application Tier - 172.16.2.0/24
eth3: CDE - 172.16.3.0/24

Systems:
DMZ: Web Servers 172.16.1.10-172.16.1.20
App Tier: App Servers 172.16.2.10-172.16.2.20
CDE: 
  - Payment Gateway: 172.16.3.10
  - Card Database: 172.16.3.20
  - Tokenization: 172.16.3.30
```

### Test Cases

```bash
# Test 1: Internet can reach web servers HTTPS
curl -v https://172.16.1.10

# Test 2: Web servers can reach app tier
# From 172.16.1.10: curl http://172.16.2.10:8080

# Test 3: App tier can reach CDE payment API
# From 172.16.2.10: curl https://172.16.3.10:9443/api/payment

# Test 4: Payment gateway can reach database
# From 172.16.3.10: psql -h 172.16.3.20 -p 5432

# Test 5: Internet CANNOT reach CDE directly
curl -v https://172.16.3.10  # Should FAIL/TIMEOUT

# Test 6: DMZ CANNOT reach CDE
# From 172.16.1.10: curl https://172.16.3.10  # Should FAIL

# Test 7: CDE cannot initiate outbound to internet
# From 172.16.3.10: curl http://example.com  # Should FAIL

# Test 8: Only jump box can SSH to CDE
ssh -o ConnectTimeout=5 admin@172.16.3.10  # From 203.0.113.50 works, others fail

# Test 9: Rate limiting works
# Attempt >100 connections/min to CDE - should be rate limited

# Test 10: Logging works
# All denied attempts to CDE should appear in logs
tail -f /var/log/syslog | grep "CDE-DENY"
```

### Hints

<details>
<summary>Hint 1: Multi-Zone Structure</summary>

```bash
# Define zones clearly
DMZ="172.16.1.0/24"
APP_TIER="172.16.2.0/24"
CDE="172.16.3.0/24"
JUMP_BOX="203.0.113.50"

# Payment Gateway, Database, Tokenization specific IPs
PAYMENT_GW="172.16.3.10"
CARD_DB="172.16.3.20"
TOKENIZATION="172.16.3.30"
```
</details>

<details>
<summary>Hint 2: PCI-DSS Logging</summary>

```bash
# Create custom chain for CDE logging
iptables -N LOG_CDE_DENY
iptables -A LOG_CDE_DENY -m limit --limit 5/min -j LOG --log-prefix "CDE-DENY: " --log-level 4
iptables -A LOG_CDE_DENY -j DROP

# Use this chain for denied CDE traffic
iptables -A FORWARD -d $CDE -j LOG_CDE_DENY
```
</details>

<details>
<summary>Hint 3: Strict CDE Access</summary>

```bash
# Only app tier can reach CDE, and only on specific ports
# Payment Gateway API
iptables -A FORWARD -s $APP_TIER -d $PAYMENT_GW -p tcp --dport 9443 -m conntrack --ctstate NEW -m limit --limit 100/min -j ACCEPT

# Database - only from payment gateway
iptables -A FORWARD -s $PAYMENT_GW -d $CARD_DB -p tcp --dport 5432 -j ACCEPT

# Tokenization - only from app tier
iptables -A FORWARD -s $APP_TIER -d $TOKENIZATION -p tcp --dport 8443 -j ACCEPT

# SSH to CDE - only from jump box
iptables -A FORWARD -s $JUMP_BOX -d $CDE -p tcp --dport 22 -j ACCEPT

# Everything else to CDE is denied and logged
iptables -A FORWARD -d $CDE -j LOG_CDE_DENY
```
</details>

<details>
<summary>Hint 4: Fragment and Source Routing Protection</summary>

```bash
# Drop fragmented packets to CDE (PCI-DSS security requirement)
iptables -A FORWARD -d $CDE -f -j DROP

# Drop packets with source routing enabled
iptables -A FORWARD -d $CDE -m ipv4options --ssrr -j DROP
iptables -A FORWARD -d $CDE -m ipv4options --lsrr -j DROP
```
</details>

### Grading Rubric (100 points)

**PCI-DSS Compliance (40 points):**
- [ ] 10 pts: Req 1.2.1 - Traffic restricted to necessary only
- [ ] 10 pts: Req 1.3.1 - DMZ properly implemented
- [ ] 10 pts: Req 1.3.5 - Only established connections to CDE
- [ ] 10 pts: Req 1.3.6 - CDE segregated from DMZ

**CDE Security (30 points):**
- [ ] 10 pts: CDE cannot initiate outbound to internet
- [ ] 10 pts: Only app tier can access CDE on specific ports
- [ ] 10 pts: Payment processing flow properly secured

**Advanced Security Controls (20 points):**
- [ ] 5 pts: Rate limiting to CDE (100 connections/min)
- [ ] 5 pts: Fragment attack prevention
- [ ] 5 pts: Source routing protection
- [ ] 5 pts: Comprehensive logging with rate limiting

**Architecture (10 points):**
- [ ] 5 pts: Three-tier segmentation properly implemented
- [ ] 5 pts: Jump box access properly configured

### PCI-DSS Validation Checklist

After completing your script, verify these PCI-DSS requirements:

```bash
# Requirement 1.2.1: Verify only necessary traffic allowed to CDE
sudo iptables -L FORWARD -v -n | grep "172.16.3.0/24"

# Requirement 1.3.5: Verify only ESTABLISHED connections accepted
sudo iptables -L FORWARD -v -n | grep ESTABLISHED

# Requirement 10.2.4: Verify logging of invalid access attempts
sudo tail -f /var/log/syslog | grep "CDE-DENY"

# Network segmentation: Verify CDE isolation
# From DMZ: curl https://172.16.3.10  # Should fail
# From App Tier: curl https://172.16.3.10:9443  # Should work
```

### Submit Your Work

```bash
sudo iptables-save > challenge-3-pcidss-rules.txt

# Also include your validation test results:
sudo iptables -L -v -n > challenge-3-verification.txt
```

---

## CHALLENGE 4: COMBINED SCENARIO (Expert)

### Scenario

You're the Security Engineer for a fintech startup. You must implement:
- DMZ for public-facing services
- VLAN segmentation for internal departments
- PCI-DSS compliant CDE for payment processing
- All in ONE comprehensive firewall configuration

```
                         INTERNET
                             ↓
                    [YOUR FIREWALL]
                             |
        ┌────────────────────┼────────────────────┐
        ↓                    ↓                    ↓
     DMZ Zone           Internal VLANs          CDE Zone
   10.0.1.0/24                |              172.16.100.0/24
   - Web Servers      ┌───────┼───────┐
   - Load Balancers   ↓       ↓       ↓
                  VLAN 10  VLAN 20  VLAN 30
                   Mgmt     Eng    Finance
```

### Requirements Document

You must satisfy ALL requirements from:
- Challenge 1: DMZ (web servers, HTTP/HTTPS, SSH controls)
- Challenge 2: VLAN Segmentation (3 VLANs with different trust levels)
- Challenge 3: PCI-DSS Compliance (CDE isolation, logging, rate limiting)

**Additional Requirements:**
1. Finance VLAN (VLAN 30) is the ONLY VLAN that can access CDE
2. Management VLAN can SSH to any zone for administration
3. DMZ web servers must be able to query CDE tokenization service
4. All cross-zone traffic must be logged (rate-limited)
5. Implement geo-blocking: Block traffic from known bad countries (use IP ranges)

### Network Layout

```
Interfaces:
eth0: WAN (Internet)
eth1.10: VLAN 10 (Management) - 10.10.10.0/24
eth1.20: VLAN 20 (Engineering) - 10.10.20.0/24
eth1.30: VLAN 30 (Finance) - 10.10.30.0/24
eth2: DMZ - 10.0.1.0/24
eth3: CDE - 172.16.100.0/24

Key Systems:
- Web Servers: 10.0.1.10-10.0.1.20
- Payment Gateway (CDE): 172.16.100.10
- Tokenization (CDE): 172.16.100.20
- Management Jump Box: 10.10.10.5
- Finance Workstations: 10.10.30.0/24
```

### Test Matrix (You Must Pass All)

| Test | From | To | Port | Should |
|------|------|----|----|--------|
| 1 | Internet | DMZ Web | 443 | ALLOW |
| 2 | Internet | CDE | Any | DENY |
| 3 | DMZ | CDE Tokenization | 8443 | ALLOW |
| 4 | DMZ | CDE Payment | 9443 | DENY |
| 5 | VLAN 10 (Mgmt) | CDE | 22 | ALLOW |
| 6 | VLAN 20 (Eng) | CDE | Any | DENY |
| 7 | VLAN 30 (Finance) | CDE Payment | 9443 | ALLOW |
| 8 | VLAN 30 (Finance) | CDE | 22 | DENY |
| 9 | CDE | Internet | Any | DENY |
| 10 | VLAN 20 | VLAN 30 | Any | DENY |

### Grading Rubric (100 points)

**Integration (30 points):**
- [ ] 10 pts: DMZ requirements from Challenge 1 met
- [ ] 10 pts: VLAN segmentation from Challenge 2 met
- [ ] 10 pts: PCI-DSS requirements from Challenge 3 met

**Cross-Zone Security (30 points):**
- [ ] 10 pts: Finance VLAN can access CDE, others cannot
- [ ] 10 pts: DMZ can access tokenization only (not full CDE)
- [ ] 10 pts: Management can SSH everywhere (with logging)

**Advanced Features (25 points):**
- [ ] 10 pts: Comprehensive logging across all zones
- [ ] 10 pts: Rate limiting prevents abuse
- [ ] 5 pts: Geo-blocking implemented

**Script Quality (15 points):**
- [ ] 5 pts: Well-organized with clear sections
- [ ] 5 pts: Extensive comments explaining security decisions
- [ ] 5 pts: Idempotent and production-ready

### Submit Your Work

```bash
sudo iptables-save > challenge-4-combined-rules.txt

# Include test results proving all 10 tests pass
./run-test-suite.sh > challenge-4-test-results.txt
```

---

## GRADING GUIDELINES FOR ALL CHALLENGES

### How I Will Grade Your Submissions

**When you upload your `challenge-X-rules.txt` file, I will check:**

1. **Correctness (Does it work?):**
   - Do the rules achieve the stated objectives?
   - Are there logical errors or misconfigurations?
   - Would this work in production?

2. **Security (Is it secure?):**
   - Default-deny policy?
   - Stateful tracking present?
   - Invalid packets dropped?
   - Logging implemented?
   - Protection against common attacks?

3. **Compliance (Does it meet requirements?):**
   - All specified requirements addressed?
   - PCI-DSS requirements met (Challenge 3)?
   - Test cases would pass?

4. **Best Practices (Is it maintainable?):**
   - Clear comments?
   - Organized structure?
   - Idempotent script?
   - Production-ready?

### Common Issues I'll Look For

**❌ Automatic Failures:**
- No stateful tracking (ESTABLISHED,RELATED)
- Default-allow policy in production
- Missing critical security requirements
- Would lock administrators out

**⚠️ Major Deductions:**
- Overly permissive rules (allowing more than necessary)
- Missing logging requirements
- No protection against common attacks
- Poor organization/no comments

**Minor Deductions:**
- Sub-optimal rule ordering (works but inefficient)
- Missing optional best practices
- Unclear comments

---

## EXAMPLE GRADING (Challenge 1)

**Student submission excerpt:**
```bash
iptables -F
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp --dport 80 -j ACCEPT  # Too broad!
iptables -A FORWARD -s 192.168.50.0/24 -p tcp --dport 22 -j ACCEPT  # No destination!
iptables -P FORWARD DROP
```

**My Feedback:**
```
Score: 65/100

Security Requirements (25/40):
✓ Stateful tracking present (10/10)
✓ Default-deny policy (10/10)
✗ SSH rule too broad - no destination specified (0/10)
✓ Invalid packets implicitly dropped (5/5)
- Missing loopback rule (0/5)

Functional Requirements (15/30):
✓ HTTP allowed but TOO BROAD - allows to ANY destination (5/10)
✗ HTTPS not implemented (0/5)
✓ SSH from admin network works (10/10)
✗ No outbound rules for web servers (0/5)

Best Practices (10/20):
✓ Script is idempotent (5/5)
✗ Minimal comments (1/5)
✗ No logging (0/5)
✗ No attack protection (0/5)

Issues:
1. Line 3: HTTP rule allows from ANY to ANY on port 80. Should restrict:
   iptables -A FORWARD -d 10.0.1.0/24 -p tcp --dport 80 -j ACCEPT

2. Line 4: SSH rule missing destination. Should be:
   iptables -A FORWARD -s 192.168.50.0/24 -d 10.0.1.0/24 -p tcp --dport 22 -j ACCEPT

3. Missing HTTPS (port 443) rules entirely
4. No outbound rules for web servers to reach internet
5. No logging of dropped SSH attempts

Recommendations:
- Add destination restrictions to all rules
- Implement HTTPS rules
- Add outbound rules for web server updates
- Implement logging for security events
- Add comments explaining each rule's purpose

Resubmit after fixes for full credit.
```

---

## TIPS FOR SUCCESS

### 1. Start Simple, Test Often

```bash
# Don't write entire script at once!
# Add rules incrementally and test

# Step 1: Write flush and default policy
# Step 2: Add ESTABLISHED rule and test
# Step 3: Add one service rule and test
# Step 4: Continue building...
```

### 2. Use Variables for Clarity

```bash
# Good
DMZ="10.0.1.0/24"
ADMIN_NET="192.168.50.0/24"
iptables -A FORWARD -s $ADMIN_NET -d $DMZ -p tcp --dport 22 -j ACCEPT

# Bad
iptables -A FORWARD -s 192.168.50.0/24 -d 10.0.1.0/24 -p tcp --dport 22 -j ACCEPT
```

### 3. Comment Everything

```bash
# Good
# Allow SSH from admin network to DMZ for server management
iptables -A FORWARD -s $ADMIN_NET -d $DMZ -p tcp --dport 22 -j ACCEPT

# Bad
iptables -A FORWARD -s $ADMIN_NET -d $DMZ -p tcp --dport 22 -j ACCEPT
```

### 4. Test Your Rules

```bash
# After applying rules, test each requirement
# Keep a testing checklist

# Test 1: Can I reach web server from internet?
curl -v http://10.0.1.10

# Test 2: Can I SSH from admin network?
ssh -o ConnectTimeout=5 admin@10.0.1.10

# Test 3: Is unauthorized access blocked?
ssh -o ConnectTimeout=5 admin@10.0.1.10  # From wrong IP
```

### 5. Check Your Work Before Submitting

```bash
# View your rules clearly
sudo iptables -L -v -n --line-numbers

# Save and review
sudo iptables-save > my-rules.txt
cat my-rules.txt

# Check for common mistakes:
# - Are ESTABLISHED rules first?
# - Is default policy DROP?
# - Are destinations specified?
# - Is logging present?
# - Are rate limits configured?
```

---

## RESOURCES

### iptables Reference

```bash
# Chains
-A: Append rule to end
-I: Insert rule at position
-D: Delete rule
-F: Flush all rules
-P: Set default policy

# Match Criteria
-s: Source IP/network
-d: Destination IP/network
-p: Protocol (tcp/udp/icmp)
--dport: Destination port
--sport: Source port
-i: Input interface
-o: Output interface

# Connection Tracking
-m conntrack --ctstate NEW: New connection
-m conntrack --ctstate ESTABLISHED,RELATED: Return traffic
-m conntrack --ctstate INVALID: Invalid packets

# Actions
-j ACCEPT: Allow packet
-j DROP: Silently drop packet
-j REJECT: Drop and send rejection
-j LOG: Log packet
```

### Testing Tools

```bash
# Test connectivity
curl -v http://target
nc -v target port
ping target
telnet target port

# Test from specific IP (if you have multiple IPs)
curl --interface eth1 http://target

# Check if port is open
nmap -p port target

# View logs
tail -f /var/log/syslog | grep iptables
journalctl -f | grep iptables
```

---

## READY TO START?

**Recommended Order:**
1. Challenge 1: DMZ (1 hour) - Get comfortable with basics
2. Challenge 2: VLAN (1.5 hours) - Learn inter-VLAN policies
3. Challenge 3: PCI-DSS (1.5 hours) - Master compliance requirements
4. Challenge 4: Combined (2 hours) - Integrate everything

**Total Time:** ~6 hours hands-on + grading feedback

**After completing all 4 challenges, you'll have:**
- ✅ Production-grade iptables skills
- ✅ Real-world firewall configurations in your portfolio
- ✅ Deep understanding of DMZ, VLAN, PCI-DSS zones
- ✅ Graded work samples to show employers
- ✅ Ready for SpaceX Q8 and similar interview questions

**Upload your first challenge when ready for grading!**

---

## KEY CORRECTIONS IN THIS VERSION

### Challenge 2 - VLAN 30 Access (Lines 273-278)

**Original (Contradictory):**
```
3. **VLAN 30 (Guest WiFi) - Lowest Trust:**
   - Cannot be accessed from any VLAN  ← CONTRADICTS line 281!
```

**Corrected:**
```
3. **VLAN 30 (Guest WiFi) - Lowest Trust:**
   - Cannot be accessed from VLAN 20 or other Guest WiFi devices
   - CAN be accessed from VLAN 10 Management (admins need to troubleshoot)
```

**Rationale:**
- Management (VLAN 10) MUST access guest network (VLAN 30) for troubleshooting
- Without this access, admins can't manage IoT devices, troubleshoot connectivity, or secure the guest network
- Original requirement "Cannot be accessed from any VLAN" conflicted with Inter-VLAN Rules table (line 281) which stated "VLAN 10 → VLAN 30: Allowed"
- Corrected version makes it explicit that VLAN 30 is isolated from VLAN 20 and other guests, but accessible to Management VLAN 10

This correction eliminates the contradiction and provides clear, consistent requirements!
