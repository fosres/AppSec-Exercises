# CHALLENGE 3: PCI-DSS COMPLIANCE ZONE (Advanced) - CLARIFIED

## Critical Clarification: What You're Actually Configuring

**YOU ARE CONFIGURING ONE FIREWALL WITH FOUR NETWORK INTERFACES**

This is exactly like Challenge 2 (VLAN segmentation), except with different networks and stricter security policies.

---

## Physical Architecture (What You're Building)

```
                    [ONE FIREWALL]
                (Your Linux server running iptables)
                            |
        ┌───────────────────┼───────────────────┐
        ↓                   ↓                   ↓
      eth0                eth1                eth2                eth3
   (Internet)             (DMZ)            (App Tier)            (CDE)
   WAN Port          172.16.1.0/24      172.16.2.0/24      172.16.3.0/24
        ↓                   ↓                   ↓                   ↓
   Public            Web Servers          App Servers        Payment Systems
   Internet          172.16.1.10-20      172.16.2.10-20     - Payment GW: .10
                                                             - Database: .20
                                                             - Tokenization: .30
```

**Key Point:** This is ONE firewall with FOUR network cards (interfaces), just like Challenge 2!

---

## Conceptual Architecture (Three Security Boundaries)

**The PCI-DSS documentation uses this conceptual view:**

```
                    INTERNET (Untrusted)
                        ↓
            ╔═══════════════════════╗
            ║  Security Boundary 1  ║  ← Firewall rules: Internet ↔ DMZ
            ╚═══════════════════════╝
                        ↓
                 DMZ (Web Tier)
              172.16.1.0/24
            Web Servers: .10-.20
                        ↓
            ╔═══════════════════════╗
            ║  Security Boundary 2  ║  ← Firewall rules: DMZ ↔ App Tier
            ╚═══════════════════════╝
                        ↓
            Application Tier (Internal)
              172.16.2.0/24
            App Servers: .10-.20
                        ↓
            ╔═══════════════════════╗
            ║  Security Boundary 3  ║  ← Firewall rules: App Tier ↔ CDE
            ╚═══════════════════════╝
                        ↓
          Cardholder Data Environment
                 172.16.3.0/24
           - Payment Gateway: 172.16.3.10
           - Card Database: 172.16.3.20
           - Tokenization: 172.16.3.30
```

**Important:** These three "boundaries" are all implemented in ONE iptables configuration!

---

## Why Three Boundaries? (Defense-in-Depth)

**Security principle:** Even if one zone is compromised, the attacker still can't reach the credit card data.

### **Attack Scenario Without Layered Security:**

```
Attacker → Compromises web server → Directly accesses credit card database ✗
           (One breach = total compromise)
```

### **Attack Scenario With Layered Security:**

```
Attacker → Compromises web server (Layer 1 breached)
        → Tries to reach CDE → BLOCKED by Boundary 2
        → Even if compromises App Tier (Layer 2 breached)
        → Tries to reach CDE → BLOCKED by Boundary 3
        → Must bypass THREE security layers to steal credit cards ✓
```

**Each boundary adds another checkpoint the attacker must bypass!**

---

## Network Interfaces Configuration

**Your firewall has FOUR network interfaces:**

```bash
eth0: Internet (WAN) - Public IP
eth1: DMZ - 172.16.1.1/24 (gateway for DMZ)
eth2: Application Tier - 172.16.2.1/24 (gateway for App Tier)
eth3: CDE - 172.16.3.1/24 (gateway for CDE)
```

**Your firewall is the gateway between all these networks!**

---

## What You're Actually Doing

**You're writing ONE iptables script that controls traffic between all four interfaces:**

```bash
#!/bin/bash
# ONE script configures all three security boundaries

# Boundary 1: Internet ↔ DMZ
iptables -A FORWARD -i eth0 -o eth1 ...  # Internet → DMZ
iptables -A FORWARD -i eth1 -o eth0 ...  # DMZ → Internet

# Boundary 2: DMZ ↔ App Tier  
iptables -A FORWARD -i eth1 -o eth2 ...  # DMZ → App Tier
iptables -A FORWARD -i eth2 -o eth1 ...  # App Tier → DMZ

# Boundary 3: App Tier ↔ CDE
iptables -A FORWARD -i eth2 -o eth3 ...  # App Tier → CDE
iptables -A FORWARD -i eth3 -o eth2 ...  # CDE → App Tier

# All in ONE iptables configuration!
```

---

## PCI-DSS Requirements to Implement

### **Requirement 1.2.1:** Restrict inbound and outbound traffic to that which is necessary for the CDE

**What this means:** Only allow specific ports to CDE, block everything else.

### **Requirement 1.3.1:** Implement a DMZ to limit inbound traffic to only system components that provide authorized publicly accessible services

**What this means:** Web servers in DMZ can accept public traffic, but not app/CDE servers.

### **Requirement 1.3.4:** Do not allow unauthorized outbound traffic from the CDE to the Internet

**What this means:** CDE systems cannot initiate connections to the internet (no outbound rules from eth3 to eth0).

### **Requirement 1.3.5:** Permit only "established" connections into the CDE

**What this means:** First iptables rule should be ESTABLISHED,RELATED. CDE can only reply, not initiate.

### **Requirement 1.3.6:** Place system components that store cardholder data in an internal network zone, segregated from the DMZ

**What this means:** CDE (172.16.3.0/24) is separate from DMZ (172.16.1.0/24) with firewall between them.

### **Requirement 10.2.4:** Log all invalid access attempts

**What this means:** Log denied attempts to reach CDE with rate limiting.

---

## Security Requirements Detailed

### **Boundary 1: Internet ↔ DMZ**

**Inbound (Internet → DMZ):**
```
✅ HTTPS (443) to DMZ web servers (172.16.1.10-.20)
✅ SSH from jump box (203.0.113.50) ONLY
❌ Everything else blocked and logged
```

**Outbound (DMZ → Internet):**
```
✅ HTTPS (443) for software updates
✅ DNS (53) for name resolution
❌ DMZ cannot reach CDE directly (enforced by Boundary 2)
```

---

### **Boundary 2: DMZ ↔ Application Tier**

**DMZ → App Tier:**
```
✅ HTTP (8080) to app servers (172.16.2.10-.20)
✅ Can query Tokenization service (172.16.3.30:8443) - exception!
❌ Cannot reach Payment Gateway or Database
```

**App Tier → DMZ:**
```
✅ Return traffic only (ESTABLISHED,RELATED)
❌ App Tier cannot initiate to DMZ
```

---

### **Boundary 3: Application Tier ↔ CDE**

**App Tier → CDE:**
```
✅ HTTPS to Payment Gateway (172.16.3.10:9443) - rate limited to 100/min
✅ HTTPS to Tokenization (172.16.3.30:8443)
❌ Cannot reach Card Database directly (only Payment Gateway can)
```

**CDE Internal (within eth3):**
```
✅ Payment Gateway → Card Database (172.16.3.20:5432) - PostgreSQL
✅ All CDE components can reply to established connections
❌ CDE cannot initiate ANY outbound to internet
```

**Jump Box → CDE:**
```
✅ SSH from jump box (203.0.113.50) to CDE for management
❌ SSH from anywhere else blocked
```

---

## Advanced Security Controls

### **1. Rate Limiting to CDE**
```bash
# Limit NEW connections to CDE to prevent DDoS
-A FORWARD -s 172.16.2.0/24 -d 172.16.3.10 -p tcp --dport 9443 \
  -m conntrack --ctstate NEW -m limit --limit 100/min -j ACCEPT
```

### **2. Fragment Attack Prevention**
```bash
# Drop fragmented packets to CDE (attackers use fragments to evade detection)
-A FORWARD -d 172.16.3.0/24 -f -j DROP
```

### **3. Source Routing Protection**
```bash
# Drop packets with source routing (IP spoofing technique)
-A FORWARD -d 172.16.3.0/24 -m ipv4options --ssrr -j DROP  # Strict source routing
-A FORWARD -d 172.16.3.0/24 -m ipv4options --lsrr -j DROP  # Loose source routing
```

### **4. Anti-Spoofing**
```bash
# Verify packets arrive on correct interface
-A FORWARD -i eth1 ! -s 172.16.1.0/24 -j DROP  # eth1 must have DMZ source
-A FORWARD -i eth2 ! -s 172.16.2.0/24 -j DROP  # eth2 must have App Tier source
-A FORWARD -i eth3 ! -s 172.16.3.0/24 -j DROP  # eth3 must have CDE source
```

### **5. Comprehensive Logging**
```bash
# Create custom logging chain for CDE denials
iptables -N LOG_CDE_DENY
iptables -A LOG_CDE_DENY -m limit --limit 5/min -j LOG --log-prefix "CDE-DENY: " --log-level 4
iptables -A LOG_CDE_DENY -j DROP

# Log all denied attempts to reach CDE
iptables -A FORWARD -d 172.16.3.0/24 -j LOG_CDE_DENY
```

---

## Complete Network Flow Examples

### **Example 1: Customer Places Order (Normal Flow)**

```
Step 1: Customer → Internet → DMZ Web Server (172.16.1.10:443)
  Interface: eth0 → eth1
  Rule: Allow HTTPS to DMZ web servers
  Result: ✓ Allowed

Step 2: Web Server → App Tier (172.16.2.10:8080)
  Interface: eth1 → eth2
  Rule: Allow DMZ to App Tier on port 8080
  Result: ✓ Allowed

Step 3: App Server → Payment Gateway (172.16.3.10:9443)
  Interface: eth2 → eth3
  Rule: Allow App Tier to Payment Gateway with rate limiting
  Result: ✓ Allowed (if under 100/min)

Step 4: Payment Gateway → Card Database (172.16.3.20:5432)
  Interface: eth3 → eth3 (same network, but still filtered)
  Rule: Allow Payment Gateway to Database
  Result: ✓ Allowed

Step 5: Replies flow back via ESTABLISHED rule
  All return traffic automatically allowed
  Result: ✓ Customer gets confirmation
```

**Total security checkpoints passed: 4**

---

### **Example 2: Attacker Tries to Reach CDE Directly (Blocked)**

```
Step 1: Attacker → Internet → Tries to reach Payment Gateway (172.16.3.10:9443)
  Interface: eth0 → eth3
  Firewall checks rules:
    Rule 1: ESTABLISHED? NO (new connection)
    Rule 2: INVALID? NO
    Rule 3-20: No rule allows Internet → CDE directly
    Rule 21: LOG_CDE_DENY → Logs attempt
  Result: ✗ BLOCKED and LOGGED

Security: Attack stopped at first firewall boundary!
```

---

### **Example 3: DMZ Compromised, Attacker Tries to Pivot (Blocked)**

```
Step 1: Attacker compromises DMZ web server (172.16.1.10)

Step 2: Attacker tries: DMZ → Payment Gateway (172.16.3.10:9443)
  Interface: eth1 → eth3
  Firewall checks rules:
    Rule 1: ESTABLISHED? NO
    Rule 2: INVALID? NO
    Rules 3-20: No rule allows DMZ → CDE Payment Gateway
    Rule 21: LOG_CDE_DENY → Logs attempt
  Result: ✗ BLOCKED and LOGGED

Step 3: Attacker tries: DMZ → Card Database (172.16.3.20:5432)
  Interface: eth1 → eth3
  Same result: ✗ BLOCKED and LOGGED

Security: Even with DMZ compromised, CDE is protected!
```

**Exception:** DMZ CAN reach Tokenization (172.16.3.30:8443) - this is intentional for converting credit cards to tokens.

---

### **Example 4: App Tier Compromised, Limited Access (Partially Blocked)**

```
Step 1: Attacker compromises App server (172.16.2.10)

Step 2: Attacker tries: App Tier → Payment Gateway (172.16.3.10:9443)
  Interface: eth2 → eth3
  Rule: Allow App Tier to Payment Gateway
  Result: ✓ Allowed (legitimate access path)

Step 3: Attacker tries: App Tier → Card Database (172.16.3.20:5432)
  Interface: eth2 → eth3
  Firewall checks rules:
    No rule allows App Tier → Database directly
  Result: ✗ BLOCKED

Step 4: Attacker tries: Payment Gateway → Internet
  Interface: eth3 → eth0
  Firewall checks rules:
    No outbound rules for CDE
    Only ESTABLISHED traffic allowed (PCI-DSS Req 1.3.4)
  Result: ✗ BLOCKED

Security: 
- Attacker can reach Payment Gateway (authorized path)
- But CANNOT reach Database directly
- CANNOT exfiltrate data to internet (CDE isolation works!)
- Damage limited to what Payment Gateway API allows
```

**Defense-in-depth working: Even with App Tier compromised, Database is protected!**

---

## Your Task Summary

**You're writing ONE iptables script that:**

1. ✅ Allows internet → DMZ HTTPS (public web access)
2. ✅ Allows DMZ → App Tier HTTP (internal communication)
3. ✅ Allows App Tier → CDE Payment Gateway/Tokenization (payment processing)
4. ✅ Allows Payment Gateway → Database (internal CDE communication)
5. ✅ Allows Jump Box → CDE SSH (management access)
6. ❌ Blocks internet → CDE direct access (critical!)
7. ❌ Blocks DMZ → CDE Payment Gateway (except Tokenization)
8. ❌ Blocks CDE → Internet outbound (PCI-DSS requirement)
9. ✅ Implements rate limiting (DDoS protection)
10. ✅ Drops fragmented/source-routed packets (attack prevention)
11. ✅ Logs all CDE access denials (compliance)

---

## Starter Template (Use This!)

```bash
#!/bin/bash
# Challenge 3: PCI-DSS Cardholder Data Environment
# Author: Tanveer Salim
# ONE firewall, FOUR interfaces, THREE security boundaries

# ============================================
# NETWORK DEFINITIONS
# ============================================
DMZ="172.16.1.0/24"
APP_TIER="172.16.2.0/24"
CDE="172.16.3.0/24"
PAYMENT_GW="172.16.3.10"
CARD_DB="172.16.3.20"
TOKENIZATION="172.16.3.30"
JUMP_BOX="203.0.113.50"

# ============================================
# FLUSH EXISTING RULES (IDEMPOTENT)
# ============================================
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# ============================================
# DEFAULT POLICIES
# ============================================
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# ============================================
# RULE 1: Stateful tracking (MUST BE FIRST!)
# ============================================
# Allow return traffic for all established connections
# This is critical for PCI-DSS Req 1.3.5 (only established to CDE)
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ============================================
# RULE 2: Drop invalid packets (security)
# ============================================
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

# ============================================
# RULE 3: Advanced CDE Protection
# ============================================
# Drop fragmented packets to CDE (fragment attack prevention)
iptables -A FORWARD -d $CDE -f -j DROP

# Drop source-routed packets to CDE (spoofing prevention)
iptables -A FORWARD -d $CDE -m ipv4options --ssrr -j DROP  # Strict source routing
iptables -A FORWARD -d $CDE -m ipv4options --lsrr -j DROP  # Loose source routing

# ============================================
# RULE 4: Anti-Spoofing (verify source matches interface)
# ============================================
iptables -A FORWARD -i eth1 ! -s $DMZ -j DROP       # eth1 must have DMZ source
iptables -A FORWARD -i eth2 ! -s $APP_TIER -j DROP  # eth2 must have App Tier source
iptables -A FORWARD -i eth3 ! -s $CDE -j DROP       # eth3 must have CDE source

# ============================================
# BOUNDARY 1: INTERNET ↔ DMZ
# ============================================

# Internet → DMZ: Allow HTTPS to web servers
iptables -A FORWARD -i eth0 -o eth1 -d $DMZ -p tcp --dport 443 -j ACCEPT

# Internet → DMZ: Allow SSH from jump box ONLY
iptables -A FORWARD -i eth0 -o eth1 -s $JUMP_BOX -d $DMZ -p tcp --dport 22 -j ACCEPT

# DMZ → Internet: Allow HTTPS for software updates
iptables -A FORWARD -i eth1 -o eth0 -s $DMZ -p tcp --dport 443 -j ACCEPT

# DMZ → Internet: Allow DNS
iptables -A FORWARD -i eth1 -o eth0 -s $DMZ -p tcp --dport 53 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -s $DMZ -p udp --dport 53 -j ACCEPT

# ============================================
# BOUNDARY 2: DMZ ↔ APPLICATION TIER
# ============================================

# DMZ → App Tier: Allow HTTP to app servers
iptables -A FORWARD -i eth1 -o eth2 -s $DMZ -d $APP_TIER -p tcp --dport 8080 -j ACCEPT

# DMZ → CDE: EXCEPTION - Allow access to Tokenization service ONLY
iptables -A FORWARD -i eth1 -o eth3 -s $DMZ -d $TOKENIZATION -p tcp --dport 8443 -j ACCEPT

# ============================================
# BOUNDARY 3: APPLICATION TIER ↔ CDE
# ============================================

# App Tier → Payment Gateway: Allow with rate limiting (PCI-DSS protection)
iptables -A FORWARD -i eth2 -o eth3 -s $APP_TIER -d $PAYMENT_GW -p tcp --dport 9443 \
  -m conntrack --ctstate NEW -m limit --limit 100/min -j ACCEPT

# App Tier → Tokenization: Allow
iptables -A FORWARD -i eth2 -o eth3 -s $APP_TIER -d $TOKENIZATION -p tcp --dport 8443 -j ACCEPT

# ============================================
# CDE INTERNAL COMMUNICATION (within eth3)
# ============================================

# Payment Gateway → Database: Allow PostgreSQL
iptables -A FORWARD -i eth3 -o eth3 -s $PAYMENT_GW -d $CARD_DB -p tcp --dport 5432 -j ACCEPT

# ============================================
# MANAGEMENT ACCESS
# ============================================

# Jump Box → CDE: Allow SSH for management
iptables -A FORWARD -s $JUMP_BOX -d $CDE -p tcp --dport 22 -j ACCEPT

# ============================================
# CDE LOGGING (PCI-DSS Req 10.2.4)
# ============================================

# Create custom logging chain for denied CDE access
iptables -N LOG_CDE_DENY
iptables -A LOG_CDE_DENY -m limit --limit 5/min -j LOG --log-prefix "CDE-DENY: " --log-level 4
iptables -A LOG_CDE_DENY -j DROP

# Log all other attempts to reach CDE (should all be blocked by now)
iptables -A FORWARD -d $CDE -j LOG_CDE_DENY

# ============================================
# END OF CONFIGURATION
# ============================================

echo "PCI-DSS firewall rules applied successfully!"
echo ""
echo "Security boundaries configured:"
echo "  Boundary 1: Internet ↔ DMZ"
echo "  Boundary 2: DMZ ↔ Application Tier"
echo "  Boundary 3: Application Tier ↔ CDE"
echo ""
echo "CDE protection active:"
echo "  - No direct internet access to CDE"
echo "  - CDE cannot initiate outbound connections"
echo "  - Rate limiting: 100 connections/min to Payment Gateway"
echo "  - Fragment and source-routing attacks blocked"
echo "  - All denied CDE access logged"
```

---

## Test Cases You Must Pass

### **Test 1: Internet → DMZ (Should Work)**
```bash
# From internet:
curl -v https://172.16.1.10

Expected: ✓ Connection successful (200 OK)
```

### **Test 2: Internet → CDE (Should Fail)**
```bash
# From internet:
curl -v https://172.16.3.10:9443

Expected: ✗ Connection timeout
Firewall log: "CDE-DENY: SRC=<internet-ip> DST=172.16.3.10"
```

### **Test 3: DMZ → App Tier (Should Work)**
```bash
# From DMZ web server (172.16.1.10):
curl -v http://172.16.2.10:8080

Expected: ✓ Connection successful
```

### **Test 4: DMZ → Payment Gateway (Should Fail)**
```bash
# From DMZ web server (172.16.1.10):
curl -v https://172.16.3.10:9443

Expected: ✗ Connection timeout
Firewall log: "CDE-DENY: SRC=172.16.1.10 DST=172.16.3.10"
```

### **Test 5: DMZ → Tokenization (Should Work - Exception!)**
```bash
# From DMZ web server (172.16.1.10):
curl -v https://172.16.3.30:8443

Expected: ✓ Connection successful (this is the exception)
```

### **Test 6: App Tier → Payment Gateway (Should Work)**
```bash
# From app server (172.16.2.10):
curl -v https://172.16.3.10:9443/api/payment

Expected: ✓ Connection successful (with rate limiting)
```

### **Test 7: App Tier → Database (Should Fail)**
```bash
# From app server (172.16.2.10):
psql -h 172.16.3.20 -p 5432

Expected: ✗ Connection timeout
Reason: Only Payment Gateway can access Database
```

### **Test 8: Payment Gateway → Database (Should Work)**
```bash
# From Payment Gateway (172.16.3.10):
psql -h 172.16.3.20 -p 5432

Expected: ✓ Connection successful
```

### **Test 9: CDE → Internet (Should Fail)**
```bash
# From Payment Gateway (172.16.3.10):
curl -v http://google.com

Expected: ✗ Connection timeout
Reason: PCI-DSS Req 1.3.4 - CDE cannot initiate outbound
```

### **Test 10: Jump Box → CDE SSH (Should Work)**
```bash
# From jump box (203.0.113.50):
ssh admin@172.16.3.10

Expected: ✓ SSH connection successful

# From anywhere else:
ssh admin@172.16.3.10

Expected: ✗ Connection timeout
```

### **Test 11: Rate Limiting (Should Work)**
```bash
# From app server, make >100 connections/min to Payment Gateway:
for i in {1..150}; do
  curl https://172.16.3.10:9443 &
done

Expected: 
  - First 100 connections: ✓ Success
  - Connections 101-150: ✗ Blocked
  - Firewall log: "CDE-DENY: ... (rate limit exceeded)"
```

### **Test 12: Fragment Attack (Should Fail)**
```bash
# Send fragmented packets to CDE:
hping3 -f 172.16.3.10

Expected: ✗ All fragments dropped
Reason: Fragment protection active
```

---

## Grading Rubric (100 points)

**PCI-DSS Compliance (40 points):**
- [ ] 10 pts: Req 1.2.1 - Traffic restricted to necessary only
- [ ] 10 pts: Req 1.3.1 - DMZ properly implemented
- [ ] 10 pts: Req 1.3.5 - Only established connections to CDE
- [ ] 10 pts: Req 1.3.6 - CDE segregated from DMZ

**CDE Security (30 points):**
- [ ] 10 pts: CDE cannot initiate outbound to internet
- [ ] 10 pts: Only app tier can access CDE on specific ports
- [ ] 10 pts: Payment processing flow properly secured (Payment GW → DB works)

**Advanced Security Controls (20 points):**
- [ ] 5 pts: Rate limiting to CDE (100 connections/min)
- [ ] 5 pts: Fragment attack prevention
- [ ] 5 pts: Source routing protection
- [ ] 5 pts: Comprehensive logging with rate limiting

**Architecture (10 points):**
- [ ] 5 pts: Three-tier segmentation properly implemented (all boundaries work)
- [ ] 5 pts: Jump box access properly configured

---

## Common Mistakes to Avoid

### **Mistake 1: Allowing CDE Outbound**
```bash
# WRONG:
-A FORWARD -s $CDE -j ACCEPT  # CDE can initiate outbound!

# CORRECT:
# No outbound rules for CDE!
# Only ESTABLISHED rule allows replies
```

### **Mistake 2: Too Broad CDE Access**
```bash
# WRONG:
-A FORWARD -s $APP_TIER -d $CDE -j ACCEPT  # Allows to entire CDE!

# CORRECT:
-A FORWARD -s $APP_TIER -d $PAYMENT_GW -p tcp --dport 9443 -j ACCEPT  # Specific!
```

### **Mistake 3: Forgetting Tokenization Exception**
```bash
# WRONG: Not allowing DMZ → Tokenization
# DMZ needs to tokenize credit cards before sending to CDE

# CORRECT:
-A FORWARD -s $DMZ -d $TOKENIZATION -p tcp --dport 8443 -j ACCEPT
```

### **Mistake 4: Missing Rate Limiting**
```bash
# WRONG:
-A FORWARD -s $APP_TIER -d $PAYMENT_GW -p tcp --dport 9443 -j ACCEPT

# CORRECT:
-A FORWARD -s $APP_TIER -d $PAYMENT_GW -p tcp --dport 9443 \
  -m conntrack --ctstate NEW -m limit --limit 100/min -j ACCEPT
```

### **Mistake 5: Forgetting CDE Internal Traffic**
```bash
# WRONG: Forgetting Payment Gateway → Database rule
# This is INSIDE eth3 but still needs to be allowed!

# CORRECT:
-A FORWARD -s $PAYMENT_GW -d $CARD_DB -p tcp --dport 5432 -j ACCEPT
```

---

## Summary: What You're Really Doing

**Physical Reality:**
- ✅ ONE firewall (your Linux server)
- ✅ FOUR network interfaces (eth0, eth1, eth2, eth3)
- ✅ ONE iptables configuration file

**Conceptual Security:**
- ✅ THREE security boundaries (defense-in-depth)
- ✅ FOUR security zones (Internet, DMZ, App, CDE)
- ✅ PCI-DSS compliance for credit card processing

**Comparison to Challenge 2:**
- Same structure (ONE firewall, FOUR interfaces)
- Different networks (DMZ/App/CDE instead of VLANs)
- Stricter rules (PCI-DSS compliance requirements)

---

## When You're Done

```bash
# Save your iptables configuration
sudo iptables-save > challenge-3-pcidss-rules.txt

# Upload for grading!
```

**Good luck!** This is the most complex challenge, but you have all the skills from Challenge 2. Just apply the same principles with stricter rules! 🔥

---

## Key Takeaway

**You're not configuring three separate firewalls - you're configuring ONE firewall that creates THREE security boundaries through carefully crafted iptables rules!**

This is exactly like Challenge 2, just with more zones and stricter security policies for PCI-DSS compliance.
