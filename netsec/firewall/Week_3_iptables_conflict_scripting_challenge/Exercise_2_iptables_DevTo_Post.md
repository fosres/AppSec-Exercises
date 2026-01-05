---
title: "Enterprise iptables Firewall Auditor: Kubernetes, PCI-DSS & SOC2 Compliance (Week 3) 🔥"
published: false
description: "Build a firewall auditor parsing real enterprise iptables rules from K8s clusters, compliance frameworks, and production systems"
tags: linux, cybersecurity, kubernetes, compliance
cover_image: # Add your cover image
series: 48-Week AppSec Engineering Journey
---

# Building an Enterprise iptables Auditor: Real-World Firewall Rules

**📚 PREREQUISITE:** This exercise requires understanding CIDR notation and IP address arithmetic. If you need to review these concepts, complete the exercises in [Computer Networking for Security Engineers](https://dev.to/fosres/computer-networking-for-security-engineers-4397) first.

**⭐ GITHUB REPO:** All 100 test files, solution templates, and validation scripts are available in my [AppSec Engineering Exercises Repository](https://github.com/YOUR_USERNAME/appsec-exercises). Star the repo to stay updated with new security exercises! Each exercise comes with comprehensive test suites and detailed guides.

---

Welcome to **Week 3, Exercise 2** of my 48-week journey from Intel Security Engineer to Application Security Engineer! Today's challenge: **audit production iptables configurations** from Kubernetes clusters, PCI-DSS environments, SOC2-compliant systems, and GDPR data processing infrastructure.

This isn't your simplified tutorial iptables. This is **actual enterprise firewall configuration** with state tracking, interface specifications, multiport rules, and compliance logging.

---

## 🎯 What You're Building

**Input:** iptables configuration file (one rule per line)  
**Output:** Detection report (dictionary with conflicts and duplicates)

```bash
# Run your auditor
python3 iptables_auditor.py iptables_rules_052.txt

# Output printed to console
{
  'conflicts': [{'rule_index': 1, 'rule': '...', 'conflicted_by': 0}],
  'duplicates': [{'rule_indices': [2, 3], 'rule': '...'}]
}
```

**Detection types:**
1. **Conflicts** → Earlier terminating rule makes later rule unreachable due to different terminating actions (e.g., ACCEPT vs DROP)
2. **Duplicates** → Identical rules (same traffic, same terminating action)

**Note:** See the **"Terminating vs Non-Terminating Actions"** section for critical details on why action types matter.

---

## 📋 Input/Output Specification

### Input: iptables Configuration File

**Your script takes ONE command-line argument:** the path to an iptables rules file.

```bash
python3 iptables_auditor.py iptables_rules_001.txt
```

**File format:** Plain text file with one iptables command per line.

**Example input file (`iptables_rules_001.txt`):**
```bash
# Kubernetes API server protection
iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 6443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 10250 -s 10.0.1.0/24 -j ACCEPT
iptables -A FORWARD -s 10.244.0.0/16 -d 10.244.0.0/16 -j ACCEPT
```

### Output: Dictionary Printed to Console

**Your script prints a Python dictionary to stdout** with two keys:

```python
{
  'conflicts': [
    {
      'rule_index': 1,
      'rule': 'iptables -A INPUT -s 192.168.1.50 -p tcp --dport 80 -j DROP',
      'conflicted_by': 0,
      'reason': 'Later rule unreachable - earlier ACCEPT makes this DROP ineffective'
    }
  ],
  'duplicates': [
    {
      'rule_indices': [2, 3],
      'rule': 'iptables -A INPUT -s 10.0.0.5 -p tcp --dport 443 -j ACCEPT'
    }
  ]
}
```

### Complete Example

**Input file (`iptables_rules_052.txt`):**
```bash
# Allow database from broad DMZ range
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 3306 -j ACCEPT
# Try to block from narrower range - CONFLICT (unreachable, different action)!
iptables -A INPUT -s 10.0.1.50 -p tcp --dport 3306 -j DROP
# Conflicting SSH rules (same source)
iptables -A INPUT -p tcp --dport 22 -s 192.168.100.10 -j ACCEPT
iptables -A INPUT -s 192.168.100.10 -p tcp --dport 22 -j DROP
```

**Command:**
```bash
python3 iptables_auditor.py iptables_rules_052.txt
```

**Expected output printed to console:**
```python
{
  'conflicts': [
    {
      'rule_index': 1,
      'rule': 'iptables -A INPUT -s 10.0.1.50 -p tcp --dport 3306 -j DROP',
      'conflicted_by': 0,
      'reason': 'Later DROP unreachable - earlier ACCEPT from 10.0.0.0/20 (which contains 10.0.1.50) makes this rule ineffective'
    },
    {
      'rule_index': 3,
      'rule': 'iptables -A INPUT -s 192.168.100.10 -p tcp --dport 22 -j DROP',
      'conflicted_by': 2,
      'reason': 'Later DROP unreachable - earlier ACCEPT from same source makes this rule ineffective'
    }
  ],
  'duplicates': []
}
```

### Output Field Descriptions

**`conflicts` array:**
- `rule_index`: Line number of the conflicted rule (0-indexed)
- `rule`: Full iptables command that is conflicted
- `conflicted_by`: Line number of the earlier rule that conflicts with this one
- `reason`: Human-readable explanation

**`duplicates` array:**
- `rule_indices`: List of all line numbers with identical rules
- `rule`: The duplicated iptables command

### Edge Cases

**Empty file or all comments:**
```python
{
  'conflicts': [],
  'duplicates': []
}
```

**Malformed rules:**
Skip unparseable lines and process valid ones.

**No issues found:**
```python
{
  'conflicts': [],
  'duplicates': []
}
```

---
```python
{
  'conflicts': [],
  'duplicates': []
}
```

---

## 🔍 What to Extract vs What to Ignore

### ✅ Extract These 4 Components (Required)

From each iptables rule, you MUST extract:

1. **Source IP/CIDR** (after `-s` flag)
   - Examples: `192.168.1.50`, `10.0.0.0/24`, `0.0.0.0/0`
   - Missing `-s` flag? Treat as "any source" (0.0.0.0/0)

2. **Destination Port** (after `--dport` flag)
   - Examples: `80`, `443`, `22`, `3306`
   - Missing `--dport` flag? Treat as "any port"

3. **Protocol** (after `-p` flag)
   - **Common protocols:**
     - `tcp` - Transmission Control Protocol (most common - web, SSH, databases)
     - `udp` - User Datagram Protocol (DNS, streaming, VoIP)
     - `icmp` - Internet Control Message Protocol (ping, traceroute) (`icmp` does **NOT** consider ports!)
     - `all` - Matches all protocols
   - **Protocol numbers:** Can also use numbers (e.g., `50` for ESP, `51` for AH)
   - **In our test files:** You'll see `tcp`, `udp`, and `icmp`
   - **For Week 3:** Focus on `tcp` and `udp` - these cover 95% of production rules

4. **Action** (after `-j` flag)
   - Terminating: `ACCEPT`, `DROP`, `REJECT`, `RETURN` (stop processing)
   - Non-terminating: `LOG`, `MARK`, `ULOG` (continue processing)
   - **For this exercise:** Treat `REJECT` like `DROP` (both deny traffic)
   - See **"Terminating vs Non-Terminating Actions"** section below for critical details

### ❌ Ignore These (Not Required for Week 3)

You can safely IGNORE these flags in your Week 3 solution:

**State tracking:**
```bash
-m state --state NEW,ESTABLISHED,RELATED
```
These are present in 99% of production rules but don't affect your core detection logic.

**Interface specifications:**
```bash
-i eth0          # Input interface
-o eth1          # Output interface
```

**Comments:**
```bash
-m comment --comment 'SSH from management'
```
Documentation only - doesn't change rule behavior.

**Multiport (optional):**
```bash
-m multiport --dports 80,443
```
Week 3: Can treat as matching port 80 OR 443 conceptually, or extract the list (your choice).

**Logging:**
```bash
-j LOG --log-prefix 'AUDIT: '
```
LOG rules are **non-terminating** - they execute and then processing continues to the next rule. See the **"Terminating vs Non-Terminating Actions"** section below for why this matters for conflict detection.

**Different chains:**
```bash
-A INPUT         # Incoming traffic
-A OUTPUT        # Outgoing traffic
-A FORWARD       # Routed traffic
```
All treated the same for Week 3.

**Policy rules (IGNORE these):**
```bash
# These set default actions, NOT individual rules
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
```
**Week 3:** Skip policy rules entirely - only audit rules with `-A` (append).  
**Why:** Policy rules set defaults (only 3 total), not specific traffic rules. They use `-P` not `-A`.

### 📝 Extraction Examples

**Example 1: Simple rule**
```bash
iptables -A INPUT -s 192.168.1.10 -p tcp --dport 80 -j ACCEPT
```
**Extract:** source=`192.168.1.10`, port=`80`, protocol=`tcp`, action=`ACCEPT`  
**Ignore:** `-A INPUT` (chain specification)

**Example 2: With state tracking**
```bash
iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 6443 -m state --state NEW,ESTABLISHED -j ACCEPT
```
**Extract:** source=`10.0.0.0/8`, port=`6443`, protocol=`tcp`, action=`ACCEPT`  
**Ignore:** `-m state --state NEW,ESTABLISHED` (state tracking)

**Example 3: With interface and comment**
```bash
iptables -A INPUT -i eth0 -p tcp --dport 22 -s 192.168.100.0/24 -m comment --comment 'SSH from mgmt' -j ACCEPT
```
**Extract:** source=`192.168.100.0/24`, port=`22`, protocol=`tcp`, action=`ACCEPT`  
**Ignore:** `-i eth0` (interface), `-m comment --comment 'SSH from mgmt'` (documentation)

**Example 4: Different flag order (same rule)**
```bash
# These three are DUPLICATES despite different order:
iptables -A INPUT -p tcp -s 192.168.1.10 --dport 80 -j ACCEPT
iptables -A INPUT -s 192.168.1.10 -p tcp --dport 80 -j ACCEPT
iptables -A INPUT --dport 80 -s 192.168.1.10 -p tcp -j ACCEPT
```
**Extract from all three:** source=`192.168.1.10`, port=`80`, protocol=`tcp`, action=`ACCEPT`  
**Result:** All three have identical extracted values → duplicates

**Example 5: Multiport rule**
```bash
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
```
**Extract:** source=`None` (no -s flag), port=`80,443` (multiport list), protocol=`tcp`, action=`ACCEPT`  
**Week 3 simplification:** Treat as matching both port 80 AND port 443

**Example 6: Different protocols**
```bash
# TCP - Web traffic
iptables -A INPUT -p tcp -s 10.0.0.0/24 --dport 443 -j ACCEPT

# UDP - DNS traffic
iptables -A INPUT -p udp -s 10.0.0.0/24 --dport 53 -j ACCEPT

# ICMP - Ping traffic
iptables -A INPUT -p icmp --icmp-type echo-request -s 10.0.0.0/24 -j ACCEPT
```
**Extract:**
- Rule 1: protocol=`tcp`, port=`443`
- Rule 2: protocol=`udp`, port=`53`
- Rule 3: protocol=`icmp`, port=`N/A` (ICMP doesn't use ports)

**Note:** For Week 3, focus on `tcp` and `udp`. ICMP rules may not have `--dport` flags.

**Example 7: LOG rule (special case)**
```bash
iptables -A INPUT -j LOG --log-prefix 'SOC2-AUDIT: '
iptables -A INPUT -j DROP
```
**Extract:** Action=`LOG` and Action=`DROP`  
**Important:** LOG is **non-terminating** (continues to next rule), while DROP is **terminating** (stops processing). See **"Terminating vs Non-Terminating Actions"** section for full details on why this matters.

### 🎯 Focus on Detection, Not Perfect Parsing

**Week 3 goal:** Extract the 4 core components to detect conflicts and duplicates.

**Week 10+ goal:** Handle all iptables complexity (state tracking, connection tracking, rate limiting, etc.)

For this exercise, **extracting source, port, protocol, and action is sufficient** to detect all three issue types across our 100 test files.

---

## 💣 Real-World Impact: The $300 Million Breach

**2019 Capital One Data Breach:**
- **100 million+ customer records stolen**
- **$300 million in settlements and fines**
- Root cause: **Misconfigured AWS firewall rules**

**What happened:**
```bash
# Earlier rule (too broad)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Later rule (conflicted - never reached for established connections)
iptables -A INPUT -s 203.0.113.0/24 -p tcp --dport 80 -j DROP
```

The attacker exploited an SSRF vulnerability because the DROP rule was **made ineffective by the earlier state tracking rule** for established connections. This exercise builds the tool that would have detected the misconfiguration.

**Sources:** 
- NIST SP 800-41r1: "Guidelines on Firewalls and Firewall Policy" - Section 2.2 emphasizes rule ordering and conflict detection (Pages 2-6 to 2-11)
- Capital One breach post-mortem analysis (2019)

---

## 🌐 Enterprise iptables Variations

Real production iptables rules have massive variation in format:

**Different flag orders:**
```bash
# All three are equivalent but different order
iptables -A INPUT -p tcp -s 192.168.1.10 --dport 80 -j ACCEPT
iptables -A INPUT -s 192.168.1.10 -p tcp --dport 80 -j ACCEPT
iptables -A INPUT --dport 80 -s 192.168.1.10 -p tcp -j ACCEPT
```

**State tracking (most common in production):**
```bash
# Connection state rules
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
```

**Interface specifications:**
```bash
# Interface-specific rules
iptables -A INPUT -i eth0 -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -o eth1 -j ACCEPT
```

**Different protocols:**
```bash
# TCP - Connection-oriented (web, SSH, databases)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# UDP - Connectionless (DNS, DHCP, streaming)
iptables -A INPUT -p udp --dport 53 -j ACCEPT

# ICMP - Network diagnostics (ping, traceroute)
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# All protocols
iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT

# Protocol by number (50 = ESP for IPsec)
iptables -A INPUT -p 50 -j ACCEPT
```

**Multiple ports (multiport module):**
```bash
# Single rule for HTTP and HTTPS
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
```

**Comments for documentation:**
```bash
iptables -A INPUT -p tcp --dport 22 -m comment --comment 'SSH for SRE team' -j ACCEPT
```

**Logging before action:**
```bash
# Log then drop (SOC2 requirement)
iptables -A INPUT -p tcp --dport 3306 -j LOG --log-prefix 'DB-DENY: '
iptables -A INPUT -p tcp --dport 3306 -j DROP
```

**REJECT vs DROP:**
```bash
# DROP silently discards
iptables -A INPUT -p tcp --dport 23 -j DROP

# REJECT sends ICMP response
iptables -A INPUT -p tcp --dport 23 -j REJECT --reject-with icmp-port-unreachable
```

**Different chains:**
```bash
iptables -A INPUT ...    # Incoming to host
iptables -A OUTPUT ...   # Outgoing from host
iptables -A FORWARD ...  # Routing through host
```

---

## 📋 Realistic Test Files

I generated 100 test files from actual enterprise scenarios. **All test files use `-A` (append) rules only** - no `-P` (policy) rules. You're auditing real firewall rules, not default policies.

### Kubernetes Cluster (File 001)
```bash
# Kubernetes API server protection with /12 service network
iptables -A INPUT -p tcp -s 10.0.0.0/12 --dport 6443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 10250 -s 10.0.1.0/26 -j ACCEPT
iptables -A FORWARD -s 10.244.0.0/16 -d 10.244.0.0/16 -j ACCEPT
# Single jump host (no /32 needed - implicit)
iptables -A INPUT -p tcp --dport 22 -s 192.168.100.5 -m comment --comment 'SSH from jump host' -j ACCEPT
```
**Expected output:** 
```python
{
  'conflicts': [],
  'duplicates': []
}
```
No issues (valid K8s cluster firewall with /12, /26, /16, single host)

### AWS VPC PCI-DSS Violation (File 052)
```bash
# Allow all from DMZ /20 (4096 hosts) - TOO BROAD
iptables -A INPUT -s 10.0.0.0/20 -j ACCEPT

# Try to block database access from /22 subset - CONFLICT!
iptables -A INPUT -s 10.0.4.0/22 -p tcp --dport 3306 -j DROP

# Conflicting SSH rules with single host (no /32 notation)
iptables -A INPUT -p tcp --dport 22 -s 192.168.100.10 -j ACCEPT
iptables -A INPUT -s 192.168.100.10 -p tcp --dport 22 -j DROP
```
**Expected output:**
```python
{
  'conflicts': [
    {
      'rule_index': 1,
      'rule': 'iptables -A INPUT -s 10.0.4.0/22 -p tcp --dport 3306 -j DROP',
      'conflicted_by': 0,
      'reason': 'Later DROP unreachable - earlier ACCEPT from broader 10.0.0.0/20 makes this ineffective'
    },
    {
      'rule_index': 3,
      'rule': 'iptables -A INPUT -s 192.168.100.10 -p tcp --dport 22 -j DROP',
      'conflicted_by': 2,
      'reason': 'Later DROP unreachable - earlier ACCEPT from same source makes this ineffective'
    }
  ],
  'duplicates': []
}
```
**Issues detected:**
- Conflict (broader→narrower): Rule 1 by Rule 0 (10.0.4.0/22 is inside 10.0.0.0/20, different actions)
- Conflict (exact match): Rules 2 and 3 (same host, different actions)

**CIDR Math:**
- 10.0.0.0/20 covers: 10.0.0.0 - 10.0.15.255 (4,096 IPs)
- 10.0.4.0/22 covers: 10.0.4.0 - 10.0.7.255 (1,024 IPs)
- 10.0.4.0/22 is a subset of 10.0.0.0/20 → conflict!

### Small Subnet Shadowing (File 014)
```bash
# Small /28 subnet (16 hosts: 192.168.1.128 - 192.168.1.143)
iptables -A INPUT -s 192.168.1.128/28 -p tcp --dport 3306 -j ACCEPT

# Try to block single host in that subnet - SHADOWED!
iptables -A INPUT -s 192.168.1.135 -p tcp --dport 3306 -j DROP
```
### Small Subnet Conflict (File 014)
```bash
# Small /28 subnet (16 hosts: 192.168.1.128 - 192.168.1.143)
iptables -A INPUT -s 192.168.1.128/28 -p tcp --dport 3306 -j ACCEPT

# Try to block single host in that subnet - CONFLICT!
iptables -A INPUT -s 192.168.1.135 -p tcp --dport 3306 -j DROP
```
**Expected output:** 
```python
{
  'conflicts': [
    {
      'rule_index': 1,
      'rule': 'iptables -A INPUT -s 192.168.1.135 -p tcp --dport 3306 -j DROP',
      'conflicted_by': 0,
      'reason': 'Later DROP unreachable - earlier ACCEPT from broader /28 makes this ineffective'
    }
  ],
  'duplicates': []
}
```

**CIDR Math:**
- 192.168.1.128/28 covers: 192.168.1.128 - 192.168.1.143 (16 hosts)
- 192.168.1.135 is one host inside that range → conflict!

### Point-to-Point Link Conflict (File 016)
```bash
# Point-to-point link /30 (4 hosts: .252, .253, .254, .255)
iptables -A INPUT -s 10.10.10.252/30 -p tcp --dport 179 -j ACCEPT

# Try to block one endpoint - CONFLICT!
iptables -A INPUT -s 10.10.10.253 -p tcp --dport 179 -j DROP
```
**Expected output:**
```python
{
  'conflicts': [
    {
      'rule_index': 1,
      'rule': 'iptables -A INPUT -s 10.10.10.253 -p tcp --dport 179 -j DROP',
      'conflicted_by': 0,
      'reason': 'Later DROP unreachable - earlier ACCEPT from broader /30 makes this ineffective'
    }
  ],
  'duplicates': []
}
```

**CIDR Math:**
- 10.10.10.252/30 covers: 10.10.10.252 - 10.10.10.255 (4 IPs)
- 10.10.10.253 is inside that range → conflict!

### SOC2 Compliance with Logging (File 062)
```bash
# SOC2 - Default deny with logging
# Small management subnet /27 (32 hosts)
iptables -A INPUT -p tcp --dport 22 -s 192.168.100.0/27 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Log before DROP (audit requirement)
iptables -A INPUT -j LOG --log-prefix 'SOC2-AUDIT: ' --log-level 4
iptables -A INPUT -j DROP
```
**Expected output:**
```python
{
  'conflicts': [],
  'duplicates': []
}
```
  'conflicts': []
}
```
No conflicts (LOG doesn't conflict with DROP - they work together for compliance)

---

## 💻 Parsing Strategy for Variable Rules

### Challenge: Rules Don't Follow One Format

**Problem:**
```bash
# These are all different order:
iptables -A INPUT -p tcp -s 192.168.1.10 --dport 80 -j ACCEPT
iptables -A INPUT -s 192.168.1.10 -p tcp --dport 80 -j ACCEPT
iptables -A INPUT --dport 80 -s 192.168.1.10 -p tcp -j ACCEPT
```

**Solution:** Search for flags, not positions.

### Step 1: Tokenize the Line

Split the line by spaces to get individual components:

```
line = "iptables -A INPUT -p tcp -s 192.168.1.10 --dport 80 -m state --state NEW -j ACCEPT"

After splitting: ['iptables', '-A', 'INPUT', '-p', 'tcp', '-s', '192.168.1.10', 
                 '--dport', '80', '-m', 'state', '--state', 'NEW', '-j', 'ACCEPT']
```

### Step 2: Find Flags and Extract Values

**Strategy:** Search for each flag in the token list, then grab the next token.

For example:
- Find `-s` flag → next token is the source IP
- Find `--dport` flag → next token is the port
- Find `-p` flag → next token is the protocol
- Find `-j` flag → next token is the action

### Step 3: Handle Missing Flags

Not all rules have all flags. You'll need to handle cases where a flag doesn't exist:
- No `-s` flag = rule matches any source (like 0.0.0.0/0)
- No `--dport` flag = rule matches any port

Use appropriate error handling for missing flags.

### Step 4: Ignore Complexity (For Week 3)

Skip these flags for now:
- `-m state --state NEW,ESTABLISHED` (state tracking)
- `-i eth0` (interface specifications)
- `-m comment --comment 'text'` (documentation)
- `-m multiport --dports 80,443` (multiple ports)

**Just extract:** source, port, protocol, action

---

## ⚡ CRITICAL: Terminating vs Non-Terminating Actions

**Before you start coding, you MUST understand this concept.** It's essential for conflict detection.

### Terminating Actions (Stop Processing)

These actions **terminate packet processing** - if a packet matches a rule with these actions, **no further rules are evaluated for that packet:**

| Action | Behavior | Impact on Detection |
|--------|----------|---------------------|
| **ACCEPT** | Accept packet, stop processing | Can conflict with later rules with different terminating actions |
| **DROP** | Drop packet silently, stop processing | Can conflict with later rules with different terminating actions |
| **REJECT** | Send ICMP response, stop processing | Can conflict with later rules (treat like DROP) |
| **RETURN** | Return to calling chain, stops in current chain | Can conflict with later rules |

**Example:**
```bash
# Rule 1: ACCEPT (terminates - stops processing)
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j ACCEPT

# Rule 2: NEVER EVALUATED for 10.0.1.0/24 (conflict!)
iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 22 -j DROP
```

**Why conflict?** Packets from 10.0.1.x match Rule 1 → ACCEPT (terminating) → processing stops → Rule 2 never evaluated (different terminating action = conflict).

### Non-Terminating Actions (Continue Processing)

These actions are **performed, then processing continues** to the next rule:

| Action | Behavior | Impact on Detection |
|--------|----------|---------------------|
| **LOG** | Log packet, continue to next rule | Does NOT conflict (non-terminating) |
| **MARK** | Mark packet, continue to next rule | Does NOT conflict (non-terminating) |
| **ULOG** | User-space log, continue to next rule | Does NOT conflict (non-terminating) |

**Example:**
```bash
# Rule 1: LOG (non-terminating - continues processing)
iptables -A INPUT -p tcp --dport 22 -j LOG --log-prefix 'SSH: '

# Rule 2: EVALUATED for ALL packets (not a conflict!)
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/20 -j ACCEPT
```

**Both rules execute!** LOG runs, then ACCEPT runs. This is NOT a duplicate or conflict.

### Why This Matters for Detection

#### **Conflict Detection**

Only **terminating actions with different behaviors** create conflicts:

```bash
# ✅ CONFLICT: ACCEPT vs DROP (different terminating actions)
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 22 -j DROP  # Conflict! (unreachable)

# ❌ NOT A CONFLICT: LOG + ACCEPT (LOG is non-terminating, both execute)
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j LOG
iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 22 -j ACCEPT  # Not a conflict!

# ❌ NOT A CONFLICT: DROP vs REJECT (both deny - treat REJECT like DROP)
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j DROP
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j REJECT
```

**Rule:** ACCEPT vs DROP/REJECT = conflict. DROP vs REJECT = NOT a conflict (both deny).

#### **3. Duplicate Detection**

Only **same terminating actions** are duplicates:

```bash
# ✅ DUPLICATE: Both ACCEPT (same terminating action)
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j ACCEPT

# ❌ NOT DUPLICATES: Multiple LOGs (both execute - common in production)
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j LOG --log-prefix 'SSH: '
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j LOG --log-prefix 'AUDIT: '
```

### Common Production Patterns (NOT Issues!)

These patterns appear in your test files and are **NOT conflicts or duplicates:**

**Pattern 1: LOG before DROP (SOC2/PCI-DSS compliance)**
```bash
# Audit logging before denial
iptables -A INPUT -j LOG --log-prefix 'DROP: ' --log-level 4
iptables -A INPUT -j DROP
```
**Why not a conflict?** LOG is non-terminating. Packet gets logged, THEN dropped. Both execute.

**Pattern 2: LOG before ACCEPT**
```bash
# Audit successful access
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j LOG --log-prefix 'SSH: '
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j ACCEPT
```
**Why not a duplicate?** Different actions (LOG vs ACCEPT). Both execute.

**Pattern 3: Multiple LOGs for same traffic**
```bash
# Multi-level logging (SOC2 requirement)
iptables -A INPUT -s 192.168.1.0/24 -j LOG --log-prefix 'SUBNET-AUDIT: '
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j LOG --log-prefix 'SSH-AUDIT: '
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT
```
**Why not duplicates?** All LOGs execute, then ACCEPT executes. This is normal compliance logging.

### Implementation Hints

**Check if action is terminating:**
```python
TERMINATING_ACTIONS = {'ACCEPT', 'DROP', 'REJECT', 'RETURN'}
NON_TERMINATING_ACTIONS = {'LOG', 'MARK', 'ULOG'}

def is_terminating(action):
    """Check if action terminates packet processing"""
    return action in TERMINATING_ACTIONS

# For conflicts: only terminating actions can create conflicts
if is_terminating(earlier_rule.action) and is_terminating(later_rule.action):
    # Check if this creates a conflict
    pass

# For conflicts: normalize REJECT to DROP (both deny)
def normalize_action(action):
    """Normalize actions for conflict detection"""
    if action in {'DROP', 'REJECT'}:
        return 'DENY'
    return action

# ACCEPT vs DROP/REJECT = conflict
# DROP vs REJECT = not conflict (both DENY)
```

**Skip LOG rules appropriately:**
```python
# When building list of rules for conflict detection
rules_for_conflict_detection = [
    rule for rule in all_rules 
    if rule.action in TERMINATING_ACTIONS
]

# LOG rules don't participate in conflict detection
# They execute alongside terminating actions
```

### Quick Reference

**For conflict detection:**
- ✅ Earlier terminating rule makes later rule unreachable when actions differ
- ✅ Only terminating actions (ACCEPT, DROP, REJECT) can create conflicts
- ✅ Conflict occurs when: earlier source contains/equals later source AND different terminating actions
- ✅ ACCEPT vs DROP/REJECT = conflict
- ❌ DROP vs REJECT = NOT conflict (both deny - normalize to same action)
- ❌ LOG rules cannot create conflicts (non-terminating - don't block later rules)

**For duplicate detection:**
- ✅ Only same terminating action = duplicate (ACCEPT+ACCEPT, DROP+DROP)
- ❌ Different terminating actions = conflict, not duplicate
- ❌ Multiple LOGs for same traffic = NOT duplicates (all execute)

---

## 🔍 Detection Algorithms (Same Core Logic)

Even with realistic complexity, **the core detection logic remains the same:**

### ⚠️ CRITICAL: Rules Only Collide Within the SAME Chain

**Before we dive into detection, understand this fundamental rule:**

Rules in **different chains NEVER collide** because they handle different packet flows:

```bash
# These are NOT duplicates/conflicts - different chains!
iptables -A INPUT -s 10.0.0.0/24 -p tcp --dport 22 -j ACCEPT
iptables -A FORWARD -s 10.0.0.0/24 -p tcp --dport 22 -j ACCEPT
```

**Why they don't collide:**

| Chain | Handles | Example |
|-------|---------|---------|
| **INPUT** | Packets destined **FOR this firewall** | SSH to the firewall itself |
| **FORWARD** | Packets **ROUTED THROUGH this firewall** | Traffic from client → firewall → server |
| **OUTPUT** | Packets originating **FROM this firewall** | Firewall's outbound connections |

**A packet only goes through ONE chain** - never multiple! 

**Implementation requirement:**
- Include CHAIN in your rule signature: `(chain, source, port, protocol, action)`
- Only compare rules within the SAME chain
- INPUT rules only collide with INPUT rules
- FORWARD rules only collide with FORWARD rules

**Example:**
```python
# CORRECT signature (includes chain)
signature = (rule.chain, rule.source, rule.port, rule.protocol, rule.action)

# Compare only within same chain
def find_duplicates(rules):
    # Group by chain first
    by_chain = {}
    for rule in rules:
        if rule.chain not in by_chain:
            by_chain[rule.chain] = []
        by_chain[rule.chain].append(rule)
    
    # Check for duplicates WITHIN each chain
    duplicates = []
    for chain, chain_rules in by_chain.items():
        duplicates.extend(check_duplicates_in_chain(chain_rules))
    
    return duplicates
```

### 1. Duplicate Detection

**Logic:** Two rules are duplicates if they have identical chain, source, port, protocol, and action.

**Approach:**
- Create a unique "signature" from each rule's components **(including chain!)**
- Track how many times each signature appears
- Report any signatures that appear 2+ times

**Key insight:** Rules with different flag orders are still duplicates if they match the same traffic **in the same chain**.

**Example:**
```bash
# These are duplicates (same chain, same traffic)
iptables -A INPUT -p tcp -s 10.0.0.5 --dport 53 -j DROP
iptables -A INPUT -s 10.0.0.5 -p tcp --dport 53 -j DROP
```

**NOT duplicates (different chains):**
```bash
# Different chains = different packet flows = NOT duplicates
iptables -A INPUT -p tcp -s 10.0.0.5 --dport 53 -j DROP
iptables -A FORWARD -s 10.0.0.5 -p tcp --dport 53 -j DROP
```

### 2. Conflict Detection

**Logic:** Earlier terminating rule makes later rule unreachable due to different terminating actions (e.g., ACCEPT vs DROP).

**This happens in TWO scenarios:**

**Scenario 1: Broader source contains narrower source**
```bash
# Earlier broad /20 ACCEPT makes later narrow /24 DROP unreachable
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 22 -j DROP  ← CONFLICT!
```

**Scenario 2: Exact same source**
```bash
# Earlier ACCEPT makes later DROP unreachable  
iptables -A INPUT -s 192.168.1.10 -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -s 192.168.1.10 -p tcp --dport 80 -j DROP  ← CONFLICT!
```

**Approach:**
- For each rule (call it "later rule")
- Compare against all rules that appear BEFORE it **in the same chain**
- Check if earlier rule has:
  - Same chain (INPUT, FORWARD, or OUTPUT)
  - Same port AND same protocol
  - Source IP that **contains or equals** the later rule's source
  - **Different terminating action** (ACCEPT vs DROP/REJECT)
- If yes → later rule is conflicted (unreachable)!

**Key insight:** The first terminating rule wins and makes the later rule with different action unreachable. Rules in different chains never conflict (different packet flows).

**NOT a conflict (different chains):**
```bash
# Different chains = different packet flows = NOT a conflict
iptables -A INPUT -s 192.168.1.10 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -s 192.168.1.10 -p tcp --dport 80 -j DROP
```

**NOT a conflict (same actions):**
```bash
# Both DROP - not a conflict (it's a duplicate if same source, otherwise just redundant)
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j DROP
iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 22 -j DROP
```

---
iptables -A FORWARD -s 192.168.1.50 -p tcp --dport 80 -j DROP
```

---

## 🧮 CIDR Containment - Production Reality

**This is the hardest part of the exercise.** Real iptables files use arbitrary CIDR masks, not just /8, /16, /24.

### Real Production CIDR Distribution

**In our 20 test files (matching actual enterprise usage):**

| CIDR Mask | Count | Use Case |
|-----------|-------|----------|
| Single host (implicit /32) | 16 | Most common - no /32 notation needed! |
| `/20` | 10 | AWS VPC default subnets (4,096 hosts) |
| `/22` | 8 | Private subnets (1,024 hosts) |
| `/26` | 5 | Pod subnets (64 hosts) |
| `/12` | 5 | Kubernetes service networks (1M+ IPs) |
| `/28` | 4 | Small microservice subnets (16 hosts) |
| `/23` | 4 | Database subnets (512 hosts) |
| `/27` | 3 | Management subnets (32 hosts) |
| `/25` | 3 | Application tiers (128 hosts) |
| `/30` | 1 | Point-to-point links (4 hosts) |
| `/21` | 1 | Corporate networks (2,048 hosts) |
| `/24` | 2 | Traditional Class C (only 2.7% of rules!) |
| `/16` | 2 | Large networks (only 2.7% of rules!) |

**Total: 64 CIDR rules, only 4 are /8, /16, or /24 (6.25%)**

**Note:** In real iptables rules, single host IPs never include `/32` notation - it's implicit! You write `192.168.1.10`, not `192.168.1.10/32`.

### Why This Matters for Conflict Detection

**Example 1: /20 conflicts with /24 (different actions)**
```bash
# Rule 0: Allow from AWS VPC /20 (4096 hosts: 10.0.0.0 - 10.0.15.255)
iptables -A INPUT -s 10.0.0.0/20 -p tcp --dport 22 -j ACCEPT

# Rule 1: Block from /24 subset (256 hosts: 10.0.1.0 - 10.0.1.255) - CONFLICT!
iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 22 -j DROP
```

**Analysis:**
- 10.0.1.0/24 is INSIDE 10.0.0.0/20
- Rule 0 has ACCEPT (terminating)
- Rule 1 has DROP (different terminating action)
- **Result: CONFLICT** - Rule 1 is unreachable

**Example 2: /28 conflicts with single host (different actions)**
```bash
# Rule 0: Allow from /28 subnet (16 hosts: 192.168.1.128 - 192.168.1.143)
iptables -A INPUT -s 192.168.1.128/28 -p tcp --dport 3306 -j ACCEPT

# Rule 1: Block specific host (implicit /32) - CONFLICT!
iptables -A INPUT -s 192.168.1.135 -p tcp --dport 3306 -j DROP
```

**Analysis:**
- 192.168.1.135 is INSIDE 192.168.1.128/28
- Rule 0 has ACCEPT, Rule 1 has DROP
- **Result: CONFLICT** - Rule 1 is unreachable

**Example 3: /12 conflicts with /20** (Kubernetes)
```bash
# Rule 0: K8s service network /12 (1M+ IPs: 10.96.0.0 - 10.111.255.255)
iptables -A FORWARD -s 10.96.0.0/12 -p tcp --dport 443 -j ACCEPT

# Rule 1: Block /20 range - CONFLICT!
iptables -A FORWARD -s 10.100.0.0/20 -p tcp --dport 443 -j DROP
```

**Analysis:**
- 10.100.0.0/20 is INSIDE 10.96.0.0/12
- Rule 0 has ACCEPT, Rule 1 has DROP
- **Result: CONFLICT** - Rule 1 is unreachable

**Feeling overwhelmed by CIDR complexity?** Don't worry - the [GitHub repository](https://github.com/YOUR_USERNAME/appsec-exercises) includes a solution template with starter code and hints to guide you through the implementation. **[⭐ Star it now](https://github.com/YOUR_USERNAME/appsec-exercises)** so you can access it when you're ready to start coding!

### Two Approaches for Week 3

#### **Option 1: Use Python's `ipaddress` Module (Recommended)**

```python
import ipaddress

def ip_in_cidr(specific_ip, cidr_range):
    """Check if IP is contained in CIDR range"""
    try:
        # Handle /32 notation or plain IP
        if '/' not in specific_ip:
            specific_ip = specific_ip + '/32'
        
        ip_net = ipaddress.ip_network(specific_ip, strict=False)
        cidr_net = ipaddress.ip_network(cidr_range, strict=False)
        
        # Check if specific IP's network is subnet of CIDR
        return ip_net.subnet_of(cidr_net) or ip_net == cidr_net
    except ValueError:
        return False

# Examples:
ip_in_cidr('10.0.1.50', '10.0.0.0/20')      # True (in range)
ip_in_cidr('10.0.1.0/24', '10.0.0.0/20')    # True (/24 inside /20)
ip_in_cidr('192.168.1.135', '192.168.1.128/28')  # True
ip_in_cidr('10.100.5.0/24', '10.96.0.0/12')      # True
```

**Pros:**
- ✅ Handles ALL CIDR masks correctly (/0 through /32)
- ✅ Only ~10 lines of code
- ✅ Python standard library (no external packages)
- ✅ Production-grade accuracy

**Cons:**
- ⚠️ Requires `import` statement (Week 3 skill: debatable)

#### **Option 2: Implement Bitwise CIDR Logic (Advanced)**

If you want to avoid imports, implement proper CIDR calculation:

```python
def cidr_contains(broader_cidr, specific_ip_or_cidr):
    """Check CIDR containment using bitwise operations"""
    
    # Parse broader CIDR
    broader_ip, broader_bits = broader_cidr.split('/')
    broader_mask = (0xFFFFFFFF << (32 - int(broader_bits))) & 0xFFFFFFFF
    broader_int = ip_to_int(broader_ip) & broader_mask
    
    # Parse specific IP/CIDR
    if '/' in specific_ip_or_cidr:
        specific_ip = specific_ip_or_cidr.split('/')[0]
    else:
        specific_ip = specific_ip_or_cidr
    
    specific_int = ip_to_int(specific_ip) & broader_mask
    
    return specific_int == broader_int

def ip_to_int(ip):
    """Convert IP string to integer"""
    octets = [int(x) for x in ip.split('.')]
    return (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
```

**Pros:**
- ✅ No imports needed
- ✅ Demonstrates low-level networking knowledge

**Cons:**
- ⚠️ ~30 lines of code vs 10
- ⚠️ More complex to debug
- ⚠️ Easy to get wrong (bit shifting errors)

### My Recommendation

**Use the `ipaddress` module.** It's part of Python's standard library, and production security tools use it. Demonstrating you know when to use existing libraries (instead of reinventing the wheel) is a positive interview signal.

If asked in an interview: "I chose `ipaddress` because it's battle-tested for edge cases like `/0` networks and handles all 33 possible CIDR masks correctly. For production security tools, correctness matters more than avoiding imports."

---

## ⚠️ Parsing Edge Cases

### Handle Missing Flags

Rules might not have all flags. Your parser needs to handle:
- No `-s` flag → treat as "any source" (like 0.0.0.0/0)
- No `--dport` flag → treat as "any port"

Use appropriate error handling strategies (try/except or checking if flag exists before accessing).

### Handle Comments

Comments don't affect rule matching. These two rules are duplicates:
```bash
iptables -A INPUT -s 10.0.0.5 -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -s 10.0.0.5 -p tcp --dport 80 -m comment --comment 'web' -j ACCEPT
```

Both have identical traffic patterns - the comment is just documentation.

### Handle Different Actions

REJECT and DROP both deny traffic:
```bash
iptables -A INPUT -p tcp --dport 23 -j DROP           # Silently discard
iptables -A INPUT -p tcp --dport 23 -j REJECT          # Send ICMP response
```

For conflict detection purposes, treat REJECT like DROP (both deny traffic).

### Handle Multiport (Advanced)

Multiport rules cover multiple ports in one line:
```bash
# This rule covers BOTH port 80 AND port 443
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
```

This can conflict with both port 80 rules AND port 443 rules below it if actions differ.

**Week 3 approach:** You can either extract the ports list or treat conceptually.

### Handle LOG Rules

LOG doesn't terminate processing - it just records then continues:
```bash
iptables -A INPUT -j LOG --log-prefix 'AUDIT: '
iptables -A INPUT -j DROP
```

LOG is not a conflict with DROP. LOG happens first, then DROP executes.

**Hint:** Skip rules with action = LOG for conflict detection.

---

## 🔒 Enterprise Security Context

### Kubernetes Firewall Rules

**Why this matters:**
- Kubernetes clusters have 100-1000+ iptables rules
- kube-proxy manages service networking via iptables
- Misconfigured rules can expose etcd, API server, or pod network
- CNI plugins (Calico, Cilium) generate complex rulesets

**Common K8s iptables patterns:**
```bash
# Pod network isolation
iptables -A FORWARD -s 10.244.0.0/16 -d 10.244.0.0/16 -j ACCEPT

# NodePort service access
iptables -A INPUT -p tcp --dport 30000:32767 -j ACCEPT

# API server protection
iptables -A INPUT -p tcp --dport 6443 -s 10.0.0.0/8 -m state --state NEW,ESTABLISHED -j ACCEPT
```

### PCI-DSS Requirement 1.2.1

**"Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment"**

**What this means:**
- Default-deny firewall policy
- Explicit allow rules with business justification
- Quarterly firewall rule review
- Documentation of each rule's purpose

**Example PCI-DSS violation:**
```bash
# WRONG: Too broad (allows all from DMZ)
iptables -A INPUT -s 10.0.1.0/24 -j ACCEPT

# RIGHT: Specific ports and protocols
iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -s 10.0.1.0/24 -p tcp --dport 443 -j ACCEPT
```

### SOC2 Compliance - CC6.6

**"Logical and physical access controls restrict access to information assets"**

**What this means:**
- All firewall changes must be logged
- Failed connection attempts must be auditable
- Least privilege access (specific IPs, not ranges)
- Quarterly access review

**SOC2-compliant iptables:**
```bash
# Allow specific access
iptables -A INPUT -p tcp --dport 22 -s 192.168.100.0/24 -j ACCEPT

# Log everything else (audit trail)
iptables -A INPUT -j LOG --log-prefix 'SOC2-DENY: ' --log-level 4
iptables -A INPUT -j DROP
```

### GDPR Article 32 - Security of Processing

**"Implement appropriate technical measures to ensure security"**

**What this means:**
- Personal data must be network-isolated
- Access to personal data must be logged
- Cross-border transfers require separate rules
- Breach detection through firewall logs

**GDPR-compliant database rules:**
```bash
# Allow only from application tier
iptables -A INPUT -s 10.0.2.0/24 -p tcp --dport 5432 -m state --state NEW -j ACCEPT

# Log all denied access (breach detection)
iptables -A INPUT -p tcp --dport 5432 -j LOG --log-prefix 'GDPR-DENY: '
iptables -A INPUT -p tcp --dport 5432 -j DROP
```

---

## 💡 What I Learned

### Real-World Firewall Complexity

**Before this exercise:** Thought iptables rules were uniform
**After this exercise:** Realized production firewalls are complex:
- State tracking (`-m state --state`)
- Interface specifications (`-i eth0`, `-o eth1`)
- Multiple ports (`-m multiport`)
- Logging requirements (SOC2, PCI-DSS)
- Different chains (INPUT, OUTPUT, FORWARD)
- Comments for documentation

### Parsing Variable-Format Data

**Python skills used:**
- `.split()` to tokenize lines
- `.index()` to find flags
- `try/except` for missing flags
- Dictionaries to normalize data
- Sets for deduplication

**Key insight:** Real-world data is messy. Production code must handle:
- Different flag orders
- Optional parameters
- Comments and whitespace
- Malformed rules

### Enterprise Compliance Requirements

**PCI-DSS:** Quarterly firewall reviews, explicit allow lists
**SOC2:** Comprehensive logging, least privilege
**GDPR:** Data isolation, access logging
**Kubernetes:** Complex auto-generated rules from CNI plugins

---

## 📊 Test File Breakdown (100 Comprehensive Files)

**Total: 100 test files covering all realistic enterprise scenarios**

### Valid Configurations (001-010) - 10 files
| File | Scenario | CIDR Masks | Notes |
|------|----------|------------|-------|
| 001 | Kubernetes cluster | /12, /26, /16 + single IP | API server, kubelet, pod network |
| 002 | AWS VPC subnets | /20, /22, /23 | DMZ, private, database tiers |
| 003 | Microservices | /26, /27, /28, /29 | Frontend, backend, DB, cache |
| 004 | Corporate network | /21, /22, /20 | Non-overlapping ranges |
| 005 | PCI-DSS DMZ | /25, /26, /27 | Compliant segmentation |
| 006 | GDPR data tiers | /22 + logging | PostgreSQL isolation |
| 007 | SOC2 default-deny | /27 + logging | Management subnet |
| 008 | Multi-tier web app | /24, /25, /26 | Web, app, database |
| 009 | BGP point-to-point | /30 (3 links) | Non-overlapping P2P |
| 010 | Dev environment | /24, /25, /26 | Proper isolation |

### Conflict Scenarios (011-050) - 40 files

**Systematic CIDR containment testing (broader contains narrower, different actions):**

| Broader Mask | Contains | File Range | Count |
|--------------|----------|------------|-------|
| /12 | /16, /20, /24, single IPs | 011-014 | 4 |
| /16 | /20, /24, /28, single IPs | 015-018 | 4 |
| /20 | /22, /24, /26, single IPs | 019-022 | 4 |
| /21 | /23, /24, single IPs | 023-025 | 3 |
| /22 | /24, /26, /28, single IPs | 026-029 | 4 |
| /23 | /24, /27, single IPs | 030-032 | 3 |
| /24 | /26, /28, single IPs | 033-035 | 3 |
| /25 | /27, /28, single IPs | 036-038 | 3 |
| /26 | /27, /28, single IPs | 039-041 | 3 |
| /27 | /28, /29, single IPs | 042-044 | 3 |
| /28 | /29, /30, single IPs | 045-047 | 3 |
| /29 | /30, single IPs | 048-049 | 2 |
| /30 | single IPs | 050 | 1 |

**Coverage:** All realistic CIDR combinations where earlier terminating rule makes later rule with different action unreachable. Tests AWS VPC (/20), Kubernetes (/12), microservices (/26-/28), and point-to-point (/30).

### Duplicates (051-065) - 15 files

| File | Scenario | Details |
|------|----------|---------|
| 051 | Single IP duplicates | 2 identical rules |
| 052 | /22 subnet | 3 rules, different flag order |
| 053 | With comments | Comments don't matter |
| 054 | With state tracking | State flags don't matter |
| 055 | /26 subnet | 3 identical rules |
| 056 | /28 subnet | Different flag order |
| 057 | /25 subnet | 3 rules, all orders |
| 058 | /27 subnet | 4 identical rules |
| 059 | With interfaces | Interface flags don't matter |
| 060 | /30 P2P | 2 identical rules |
| 061 | Single IP | 2 identical rules |
| 062 | /24 subnet | 5 identical rules |
| 063 | /23 subnet | 3 rules with comments |
| 064 | /21 subnet | 2 identical rules |
| 065 | /29 subnet | 2 identical rules |

### Exact Match Conflicts (066-080) - 15 files

**ACCEPT vs DROP/REJECT for exact same source (not broader/narrower):**

| File | CIDR Mask | Conflict Type |
|------|-----------|---------------|
| 066 | /20 | ACCEPT vs DROP (same source) |
| 067 | Single IP | ACCEPT vs REJECT (same source) |
| 068 | /24 | ACCEPT vs DROP (same source) |
| 069 | /22 | DROP vs ACCEPT (same source) |
| 070 | /26 | ACCEPT vs DROP (same source) |
| 071 | /28 | DROP vs ACCEPT (same source) |
| 072 | /27 | ACCEPT vs DROP (same source) |
| 073 | /25 | DROP vs ACCEPT (same source) |
| 074 | /23 | ACCEPT vs REJECT (same source) |
| 075 | /30 | ACCEPT vs DROP (same source) |
| 076 | Multiple single IPs | 2 separate conflicts |
| 077 | /21 | ACCEPT vs DROP (same source) |
| 078 | /29 | DROP vs ACCEPT (same source) |
| 079 | /20 | ACCEPT vs REJECT (tcp-reset, same source) |
| 080 | /12 K8s | ACCEPT vs DROP (same source) |

### Mixed Issues (081-100) - 20 files

**Complex real-world scenarios with multiple problem types:**

| File | Scenario | Issues |
|------|----------|--------|
| 081 | Kubernetes cluster | Conflicts + Duplicates |
| 082 | AWS VPC | Conflicts (broader→narrower) |
| 083 | Enterprise firewall | All types |
| 084 | Microservices cascade | Multi-level conflicts |
| 085 | Corporate network | Duplicates + Conflicts |
| 086 | /12 conflicts all | 3 rules conflicted |
| 087 | AWS VPC chain | 3-level conflicts |
| 088 | DMZ problems | Conflicts (broader→narrower + exact) |
| 089 | P2P cascade | 3-level conflicts |
| 090 | Database tier | Conflicts + Duplicates |
| 091 | Management network | Conflicts (broader→narrower + exact) |
| 092 | Dev environment | All types (Duplicates + Conflicts) |
| 093 | Service mesh | 4-level conflict cascade |
| 094 | Legacy + modern | /16 conflicts /22 and single IPs |
| 095 | Multi-tenant | Conflicts + Duplicates |
| 096 | Container network | Kubernetes pod conflicts |
| 097 | API gateway | Conflicts (broader→narrower + exact) |
| 098 | Load balancer | Multiple conflicts |
| 099 | Storage network | Conflicts + Duplicates |
| 100 | Production nightmare | All issues, /16 conflicts everything |

---

## 🎯 Comprehensive Testing Strategy

**100 files provide:**
- ✅ 10 valid configurations (baseline - should report no issues)
- ✅ 40 conflict scenarios (broader→narrower with different actions)
- ✅ 15 duplicate scenarios (flag order, comments, state tracking)
- ✅ 15 exact match conflict scenarios (same source, different actions)
- ✅ 20 mixed scenarios (real-world complexity)

**CIDR coverage:**
- /12: Kubernetes service networks (1M+ IPs)
- /16: Large enterprise networks
- /20: AWS VPC default subnets (4,096 hosts)
- /21-/23: Corporate subnets (512-2,048 hosts)
- /24: Traditional Class C (256 hosts)
- /25-/27: Application tiers (32-128 hosts)
- /28-/29: Microservices (8-16 hosts)
- /30: Point-to-point links (4 hosts)
- **Single IPs:** Written without /32 (implicit) - e.g., `192.168.1.10` not `192.168.1.10/32`

**Your auditor must correctly identify all issues across these 100 files** to be considered production-ready.

> **💡 Pro tip:** The 100 comprehensive test files are in the [GitHub repository](https://github.com/YOUR_USERNAME/appsec-exercises). Star the repo to bookmark it and get notified when I add more security engineering exercises! The repo includes automated validation scripts to check your solution against expected outputs.

---

## ✅ Success Criteria

### Quick Format Reminder

**Input:** 
```bash
python3 iptables_auditor.py <filepath>
```

**Output:** Dictionary with two keys: `conflicts`, `duplicates` (printed to stdout)

---

**Your solution should:**

**Parsing:**
- ✅ Extract source, port, protocol, action from variable-order rules
- ✅ Handle missing flags gracefully (`-s` not present = any source)
- ✅ Ignore state tracking, interfaces, comments (Week 3 scope)
- ✅ Skip malformed rules without crashing

**Detection:**
- ✅ Detect all conflicts (40 test files - broader→narrower and exact matches)
- ✅ Detect all duplicates (different flag order = still duplicate)
- ✅ Handle terminating vs non-terminating actions correctly

**Code Quality:**
- ✅ Clean parsing logic using `.split()` and `.index()`
- ✅ Appropriate data structures (dicts, sets, lists)
- ✅ Descriptive variable names
- ✅ Edge case handling

---

## ⭐ What's in the GitHub Repository?

**[👉 Star the AppSec Exercises Repository](https://github.com/YOUR_USERNAME/appsec-exercises)**

The GitHub repo contains everything you need to complete this exercise and future security engineering challenges:

### 🎯 For This Exercise (Week 3):

**100 Comprehensive Test Files:**
- `test_files/week3_exercise2/iptables_rules_001.txt` through `iptables_rules_100.txt`
- Systematically organized: valid configs, conflicts (broader→narrower), exact match conflicts, duplicates, mixed issues
- Production-realistic CIDR masks (/12, /20, /22, /26, /28, /30, single IPs)

**Solution Template:**
- `solutions/week3_exercise2_template.py` - Starter code with helpful hints
- Function stubs for parsing, CIDR containment, detection logic
- Comments explaining the approach

**Validation Scripts:**
- `tests/validate_week3_exercise2.py` - Automated checker for your solution
- Compares your output against expected results for all 100 files
- Provides detailed feedback on failures

**Expected Outputs:**
- `expected_outputs/week3_exercise2/` - Expected detection results for all 100 test files
- Use these to debug your solution

### 🔮 Future Exercises:

The repository will include:
- Week 4: SQL Injection Detection in Code Review
- Week 5: JWT Security Analyzer
- Week 8: Semgrep Rule Writing
- Week 11: AppSec System Design Challenges
- And 43 more security engineering exercises!

### 📊 Why Star the Repository?

✅ **Stay Updated:** Get notified when new exercises drop  
✅ **Bookmark:** Quick access to test files and validation scripts  
✅ **Support:** Show appreciation for free, high-quality security content  
✅ **Network:** Connect with other security engineers learning together  
✅ **Track Progress:** Watch your journey from 0 to 48 completed exercises

**[⭐ Star the repo now](https://github.com/YOUR_USERNAME/appsec-exercises)** — it takes 2 seconds and helps other security engineers discover these exercises!

---

## 🚀 Implementation Approach

### Before You Start

**Remember the format:**
- **Input:** Command-line argument (filepath)
- **Output:** Dictionary with two arrays printed to stdout
- **Usage:** `python3 iptables_auditor.py <filepath>`

### Day-by-Day Plan

**Day 1 (2 hours):** Parse realistic rules
- Accept filepath from command line (`sys.argv[1]`)
- Read file line by line
- Extract source, port, protocol, action (ignore state tracking, interfaces)
- Test on files 001, 002 (valid configurations)
- Print extracted data to verify parsing works

**Day 2 (1 hour):** Implement duplicate detection
- Normalize rules to same format (handle different flag orders)
- Track rule signatures using dictionaries
- Build `duplicates` array in output format
- Test on files 051, 052
- Print output dictionary

**Day 3 (2 hours):** Implement CIDR containment
- Implement `ipaddress` module for CIDR math
- Test containment logic (is /24 inside /20?)
- Verify with simple examples
- Test on files 019-022

**Day 4 (2-3 hours):** Implement conflict detection
- For each rule, check all earlier rules in same chain
- Check if earlier source contains/equals later source
- Check if actions differ (normalize DROP/REJECT)
- Build `conflicts` array in output format
- Test on files 011-015, 066-070
- Print output dictionary

**Day 5 (1 hour):** Test all 100 files, debug edge cases
- Run against all test files
- Verify output format matches specification
- Handle empty files, malformed rules
- Final output should be valid Python dictionary

---

## 📋 Quick Reference: Exact Output Format

**Your script must print this exact dictionary structure:**

```python
{
  'conflicts': [
    {
      'rule_index': <int>,           # 0-indexed line number of conflicted rule
      'rule': '<full iptables command>',
      'conflicted_by': <int>,        # 0-indexed line number of earlier conflicting rule
      'reason': '<explanation string>'
    },
    # ... more conflicted rules
  ],
  'duplicates': [
    {
      'rule_indices': [<int>, <int>, ...],  # All line numbers with this rule
      'rule': '<full iptables command>'
    },
    # ... more duplicate groups
  ],
  'conflicts': [
    {
      'rule_indices': [<int>, <int>, ...],  # Line numbers with conflicting actions
      'traffic': '<source>:<protocol>:<port>',
      'actions': ['<action1>', '<action2>']  # e.g., ['ACCEPT', 'DROP']
    },
    # ... more conflicts
  ]
}
```

**Testing tip:** Compare your output dictionary structure against the expected format for each test file.

---

## 📚 Resources

**⭐ PRIMARY RESOURCE - GitHub Repository:**  
**[github.com/YOUR_USERNAME/appsec-exercises](https://github.com/YOUR_USERNAME/appsec-exercises)**

Everything you need is in the repo:
- 📁 100 comprehensive test files (iptables_rules_001.txt through iptables_rules_100.txt)
- 📝 Solution template with starter code
- ✅ Automated validation scripts
- 📊 Expected outputs for all test cases
- 📖 Detailed implementation guide

**[👉 Star the repository](https://github.com/YOUR_USERNAME/appsec-exercises)** to bookmark these resources and get notified about future exercises!

---

**Additional Learning Resources:**

**CIDR Networking:**
- [Computer Networking for Security Engineers](https://dev.to/fosres/computer-networking-for-security-engineers-4397) (my prerequisite guide)
- [Visual Subnet Calculator](https://www.davidc.net/sites/default/subnets/subnets.html)
- RFC 4632: CIDR notation specification

**Python ipaddress module:**
- [Official Python docs](https://docs.python.org/3/library/ipaddress.html)
- [Real Python tutorial](https://realpython.com/python-ipaddress-module/)

**Enterprise Firewall Standards:**
- NIST SP 800-41r1: Guidelines on Firewalls (Section 2.2 on rule ordering)
- PCI-DSS Requirement 1.2.1: Firewall rule reviews
- CIS Benchmark: Linux firewall configuration

**Real-World References:**
- AWS VPC CIDR best practices: [AWS VPC docs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-cidr-blocks.html)
- Kubernetes networking: [K8s service networking](https://kubernetes.io/docs/concepts/services-networking/)
- Capital One breach analysis (2019): Firewall misconfiguration case study

---

## 💬 Discussion Questions

1. **State tracking complexity:** How would you handle `ESTABLISHED,RELATED` making NEW connections unreachable (conflicts)?

2. **Multiport rules:** Should `-m multiport --dports 80,443` be treated as two separate rules for conflict detection?

3. **Interface specifications:** Does `-i eth0` make a rule more or less specific than no interface specified?

4. **LOG rules:** Should LOG before DROP be flagged as a conflict or recognized as SOC2/PCI-DSS pattern?

5. **Kubernetes automation:** How would you audit auto-generated kube-proxy rules that change constantly?

**Drop your thoughts in the comments!** 👇

### 🌟 Build the Community

**[Star the repository](https://github.com/YOUR_USERNAME/appsec-exercises)** to bookmark these exercises and help others discover them! Share your solutions, discuss approaches, and learn together.

**What's included:**
- 🚀 New exercises added every week
- 📚 Growing library of production-grade security tools
- 💬 Discussions for sharing solution approaches
- ✅ Comprehensive test suites for validation

**Your star helps others discover these exercises** — it's how we build a stronger security engineering community! ⭐

---

## 🔗 Series Navigation

**Week 3 Exercises:**
- ✅ [Exercise 1: VPN Log Analyzer](https://dev.to/...) - 100/100 tests passed
- 🔄 **Exercise 2: Enterprise iptables Auditor** ← YOU ARE HERE
- 📅 Exercise 3: Network Segmentation Validator
- 📅 Exercise 4: IOC Correlator
- 📅 Exercise 5: Cipher Suite Auditor

---

## 🙏 Acknowledgments

**Inspired by:**
- **Real Kubernetes clusters** - kube-proxy iptables generation
- **PCI-DSS Requirement 1.2.1** - Cardholder data environment protection
- **SOC2 CC6.6** - Logical access controls and audit logging
- **GDPR Article 32** - Security of processing requirements
- **2019 Capital One Breach** - Real-world impact of firewall misconfigurations

**Book Citations:**
- "Secure by Design" by Dan Bergh Johnsson et al. - Chapter 6: Default-deny firewall patterns (Pages 171-175)
- NIST SP 800-41r1 - Section 2.2: Firewall policy and rule ordering (Pages 2-6 to 2-11)

---

## ⭐ Ready to Build Your Production-Grade Auditor?

### Get Everything You Need:

**[👉 Star the GitHub Repository](https://github.com/YOUR_USERNAME/appsec-exercises)**

The repo contains:
- ✅ All 100 comprehensive test files (systematically organized)
- ✅ Solution template with starter code and hints
- ✅ Automated validation scripts (check your solution instantly)
- ✅ Expected outputs for debugging
- ✅ 47 more security engineering exercises coming!

**Why star the repo?**
- 📌 Bookmark for quick access
- 🔔 Get notified when new exercises drop
- 🤝 Support free, high-quality security content
- 📈 Track your progress through all 48 weeks
- 🌟 Help other security engineers discover these exercises

**It takes 2 seconds to star, but gives you access to hundreds of hours of curated security engineering practice.**

---

## 💬 Let's Connect!

**Have questions?** Drop them in the comments below! 👇

**Found this useful?** Share it with your security engineering friends!

**Completed the exercise?** Share your solution or insights in the comments - let's learn together! 🚀

---

**Tags:** #linux #cybersecurity #kubernetes #compliance #iptables #pcidss #soc2 #gdpr #appsec #firewall

**Series:** 48-Week AppSec Engineering Journey

---

*Next up: Week 3, Exercise 3 - Network Segmentation Validator! 🌐*

**[⭐ Don't forget to star the repo](https://github.com/YOUR_USERNAME/appsec-exercises)** — see you in the next exercise!
