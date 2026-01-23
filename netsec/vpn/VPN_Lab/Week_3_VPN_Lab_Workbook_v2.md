# Week 3 VPN Mastery Lab - Workbook

**Student Name:** _________________________  
**Start Date:** _________________________  
**Completion Date:** _________________________  

**Total Time Budget: 4 hours**

---

## Lab Objectives

By completing this lab, you will be able to:
- ✅ Set up and secure a WireGuard VPN
- ✅ Compare VPN protocols (WireGuard, IPsec, OpenVPN)
- ✅ Respond to VPN security incidents
- ✅ Design secure VPN network architectures
- ✅ Answer Security Engineering interview questions about VPN security

---

## Part 1: Hands-On WireGuard Setup & Security Review (1.5 hours)

### Step 1: Install WireGuard (10 minutes)

**Commands executed:**
```bash
# Record the commands you ran here:

sudo apt-get install wireguard

# Check if wireguard is installed with below command:

wg --version


```

**WireGuard version installed:**
```
# Paste output of: wg --version

wireguard-tools v1.0.20210914 - https://git.zx2c4.com/wireguard-tools/

```

**Installation date/time:** January 19, 2026 1:05 PM PST

---

### Step 2: Generate Key Pairs (10 minutes)

**Server Keys Generated:**
```
Server Private Key: OGgAFUy/1e5DP3XRdmG07O8w7g9Wy2PohPCqCtyreVI=

Server Public Key: HiAY0m6wh+SfW5UtYIJU77SUP6Mc+5yfzDZ6pceeEWw=
```

**Client Keys Generated:**
```
Client Private Key: CEhk6dDcIHHgkR1L5cRn68Zn5J3t/S7L9vGO6W2V8Wc=

Client Public Key: LCFVziTSGrLWidiKY6Vupl+8AI6E8pGVZF3QKRcM6DI=
```

**File permissions verified:**
```bash
# Paste output of: ls -l /etc/wireguard/*_private.key


```

**Are private keys set to 600 permissions?** ☑ Yes ☐ No

Yes

---

### Step 3: Create Initial Configuration (15 minutes)

**Goal:** Create a basic (intentionally simple) WireGuard server configuration that works, but has security gaps you'll identify and fix in Steps 4-5.

#### What to Create

You'll create the file `/etc/wireguard/wg0.conf` with a basic server configuration.

#### Step-by-Step Instructions

**1. Open the configuration file:**
```bash
sudo nano /etc/wireguard/wg0.conf
```

**2. Copy this template and customize it with YOUR keys:**

```ini
[Interface]
# Server's private key (replace with YOUR server_private.key content)
PrivateKey = PASTE_YOUR_SERVER_PRIVATE_KEY_HERE
# Server's VPN IP address - this is the server's address on the VPN network
Address = 10.0.0.1/24
# Port WireGuard listens on (this is the default port - security issue!)
ListenPort = 51820
# Auto-save runtime changes to config file (convenience vs security trade-off)
SaveConfig = true

[Peer]
# Client's public key (replace with YOUR client_public.key content)
PublicKey = PASTE_YOUR_CLIENT_PUBLIC_KEY_HERE
# What IP addresses this client is allowed to use on the VPN
AllowedIPs = 10.0.0.2/32
```

**3. Replace `PASTE_YOUR_SERVER_PRIVATE_KEY_HERE` with your actual server private key:**

Your server private key is: `OGgAFUy/1e5DP3XRdmG07O8w7g9Wy2PohPCqCtyreVI=`

**4. Replace `PASTE_YOUR_CLIENT_PUBLIC_KEY_HERE` with your actual client public key:**

Your client public key is: `LCFVziTSGrLWidiKY6Vupl+8AI6E8pGVZF3QKRcM6DI=`

**5. Save the file:**
- In nano: Press `Ctrl+O` (save), then `Enter`, then `Ctrl+X` (exit)

**6. Set proper permissions:**
```bash
sudo chmod 600 /etc/wireguard/wg0.conf
```

**7. Verify your configuration:**
```bash
sudo cat /etc/wireguard/wg0.conf

# Below is my configuration:

[Interface]
# Server's private key (replace with YOUR server_private.key content)
PrivateKey = OGgAFUy/1e5DP3XRdmG07O8w7g9Wy2PohPCqCtyreVI=
# Server's VPN IP address - this is the server's address on the VPN network
Address = 10.0.0.1/24
# Port WireGuard listens on (this is the default port - security issue!)
ListenPort = 51820
# Auto-save runtime changes to config file (convenience vs security trade-off)
SaveConfig = true

[Peer]
# Client's public key (replace with YOUR client_public.key content)
PublicKey = LCFVziTSGrLWidiKY6Vupl+8AI6E8pGVZF3QKRcM6DI=
# What IP addresses this client is allowed to use on the VPN
AllowedIPs = 10.0.0.2/32
```

#### What Your Finished Config Should Look Like

Your configuration should look like this (with YOUR actual keys):

```ini
[Interface]
PrivateKey = OGgAFUy/1e5DP3XRdmG07O8w7g9Wy2PohPCqCtyreVI=
Address = 10.0.0.1/24
ListenPort = 51820
SaveConfig = true

[Peer]
PublicKey = LCFVziTSGrLWidiKY6Vupl+8AI6E8pGVZF3QKRcM6DI=
AllowedIPs = 10.0.0.2/32
```

#### What Each Field Means

| Field | What It Does | Security Notes |
|-------|-------------|----------------|
| `PrivateKey` | Server's secret key - authenticates server | MUST stay secret! 600 permissions required |
| `Address` | Server's IP on the VPN network | 10.0.0.1 is the server's VPN address |
| `ListenPort` | Port the server listens on for connections | 51820 is default - easily scanned (security issue!) |
| `SaveConfig` | Auto-saves runtime changes | Convenient but risky (security issue!) |
| `PublicKey` (Peer) | Client's public key | Allows this specific client to connect |
| `AllowedIPs` | IP addresses this client can use | Restricts client to 10.0.0.2 only |

#### Why This Config is INTENTIONALLY BASIC

This configuration is **deliberately simple** with known security gaps so you can:
- ✅ Get WireGuard working quickly
- ✅ Learn to identify security issues in Step 4
- ✅ Practice improving configurations in Step 5

**Security issues you'll find in Step 4:**
- Using default port 51820 (easily scanned)
- `SaveConfig = true` (changes persist automatically without change control)
- No firewall rules (`PostUp`/`PostDown` missing)
- No `PersistentKeepalive` configured
- Possibly other issues you'll discover during the security review

---

**Initial `/etc/wireguard/wg0.conf` created:**
```ini
# Paste your actual configuration here after creating it:

[Interface]
# Server's private key (replace with YOUR server_private.key content)
PrivateKey = OGgAFUy/1e5DP3XRdmG07O8w7g9Wy2PohPCqCtyreVI=
# Server's VPN IP address - this is the server's address on the VPN network
Address = 10.0.0.1/24
# Port WireGuard listens on (this is the default port - security issue!)
ListenPort = 51820
# Auto-save runtime changes to config file (convenience vs security trade-off)
SaveConfig = true

[Peer]
# Client's public key (replace with YOUR client_public.key content)
PublicKey = LCFVziTSGrLWidiKY6Vupl+8AI6E8pGVZF3QKRcM6DI=
# What IP addresses this client is allowed to use on the VPN
AllowedIPs = 10.0.0.2/32







```

**Configuration successfully created?** ☐ Yes ☐ No

**Verification commands run:**
```bash
# Did you verify the config?
# sudo cat /etc/wireguard/wg0.conf


# Did you set permissions?
# sudo chmod 600 /etc/wireguard/wg0.conf
# ls -l /etc/wireguard/wg0.conf

#Yes I did:

-rw------- 1 root root 647 Jan 19 14:18 /etc/wireguard/wg0.conf


```

---

### Step 4: Security Review Exercise (20 minutes)

Complete the security checklist for your WireGuard configuration:

#### CRITICAL Priority Findings

**Finding 1: Private Key Permissions**
- [ ] Checked file permissions
- Current permissions: _________________________
- **Pass/Fail:** ☐ Pass (600) ☐ Fail (explain): _________________________

**Finding 2: ListenPort Configuration**
- Current port: 51820 
- Using default 51820? ☐ Yes ☐ No

YES

- **Security improvement needed?** ☐ Yes ☐ No

YES

- If yes, what port will you use? 60000

**Finding 3: PersistentKeepalive**
- Currently configured? ☐ Yes ☐ No

NO
- If yes, value: _________________________
- **Action needed?** ☐ Add it ☐ Already configured ☐ Not needed for server

NOT needed for this exercise.

#### HIGH Priority Findings

**Finding 4: AllowedIPs Restriction**
- Current AllowedIPs value: _________________________
- Is it properly restricted to single client IP? ☐ Yes ☐ No
- **Security risk if set to 0.0.0.0/0:** _________________________

**Finding 5: Firewall Rules**
- PostUp/PostDown rules configured? ☐ Yes ☐ No
- If no, why is this a security risk? _________________________

**Finding 6: IP Forwarding**
- IP forwarding enabled? ☐ Yes ☐ No
- Command used to check: _________________________

#### MEDIUM Priority Findings

**Finding 7: SaveConfig Setting**
- Current SaveConfig value: _________________________
- Why should this be 'false' in production? _________________________

**Finding 8: Unique Keys Per Peer**
- How many peers in your config? _________________________
- Each has unique PublicKey? ☐ Yes ☐ No ☐ N/A (only 1 peer)

---

### Step 5: Create Secure Configuration (15 minutes)

Now create an **improved** configuration that fixes the security issues you identified.

**Create file:** `/etc/wireguard/wg0-secure.conf`

**Template for improved configuration:**

```ini
[Interface]
# Server's private key (same as before)
PrivateKey = OGgAFUy/1e5DP3XRdmG07O8w7g9Wy2PohPCqCtyreVI=
# Server's VPN IP address
Address = 10.0.0.1/24
# SECURITY IMPROVEMENT: Use non-standard port instead of 51820
ListenPort = 41194
# SECURITY IMPROVEMENT: Disable auto-save for production change control
SaveConfig = false

# SECURITY IMPROVEMENT: Add firewall rules (executed when VPN starts/stops)
# Adjust 'eth0' to your actual network interface name (use 'ip link' to check)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# Client's public key
PublicKey = LCFVziTSGrLWidiKY6Vupl+8AI6E8pGVZF3QKRcM6DI=
# Restrict to single client IP only
AllowedIPs = 10.0.0.2/32
# SECURITY IMPROVEMENT: Keep connection alive through NAT
PersistentKeepalive = 25
```

**Commands to create secure config:**
```bash
sudo nano /etc/wireguard/wg0-secure.conf
# Paste the improved template above
# Save with Ctrl+O, Enter, Ctrl+X

# Set permissions
sudo chmod 600 /etc/wireguard/wg0-secure.conf
```

**Improved `/etc/wireguard/wg0-secure.conf`:**
```ini
# Paste your IMPROVED configuration here:
















```

**List 3+ security improvements you made:**

1. _________________________
2. _________________________
3. _________________________

---

### Step 6: Test Configuration (15 minutes)

**Commands run:**
```bash
# Paste commands and outputs:

# Start VPN with secure config:
# sudo wg-quick up wg0-secure


# Check status:
# sudo wg show


# Output of 'sudo wg show':



```

**VPN successfully started?** ☐ Yes ☐ No

**If no, troubleshooting steps taken:**
_________________________
_________________________

**Common issues and solutions:**
- **"RTNETLINK answers: Operation not permitted"**: Run with sudo
- **"Name or service not known"**: Check that eth0 is correct interface name (use `ip link`)
- **"Cannot find device wg0-secure"**: Config file must be named exactly `/etc/wireguard/wg0-secure.conf`

**Stop the VPN when done testing:**
```bash
sudo wg-quick down wg0-secure
```

---

### Part 1 Deliverables Checklist

- [ ] WireGuard installed and version verified
- [ ] Server and client key pairs generated
- [ ] Private keys have 600 permissions
- [ ] Initial configuration created (`/etc/wireguard/wg0.conf`)
- [ ] Security review completed (8 findings documented)
- [ ] Secure configuration created (`/etc/wireguard/wg0-secure.conf`)
- [ ] VPN tested and working
- [ ] Screenshot of `sudo wg show` saved

---

## Part 2: VPN Protocol Comparison & Vendor Evaluation (1 hour)

### Exercise: VPN Protocol Comparison

**Create file:** `vpn_protocol_comparison.py`

```python
#!/usr/bin/env python3
"""
VPN Protocol Comparison for Security Engineering Evaluation
Student: _________________________
Date: _________________________
"""

# TODO: Write your comparison code here
# Hint: Compare WireGuard, IPsec, OpenVPN
# Include: encryption, key exchange, vulnerabilities, use cases




```

**Code file created and tested?** ☐ Yes ☐ No

---

### Protocol Comparison Table - Fill This Out

#### WireGuard

**Encryption algorithm:** _________________________

**Key exchange method:** _________________________

**Authentication hash:** _________________________

**Deployment complexity:** ☐ Very Low ☐ Low ☐ Medium ☐ High

**Downgrade attack risk:** ☐ Yes ☐ No  
**Why/Why not:** _________________________

**Perfect Forward Secrecy:** ☐ Yes ☐ No

**2 Common vulnerabilities:**
1. _________________________
2. _________________________

**Best use cases:**
1. _________________________
2. _________________________
3. _________________________

**Team Blind note:** _________________________

---

#### IPsec

**Encryption algorithm (recommended):** _________________________

**Key exchange protocol (prefer v1 or v2?):** _________________________

**Authentication hash (recommended):** _________________________

**Deployment complexity:** ☐ Very Low ☐ Low ☐ Medium ☐ High

**Downgrade attack risk:** ☐ Yes ☐ No  
**Explain:** _________________________

**Perfect Forward Secrecy:** ☐ Always ☐ Optional ☐ No  
**How to enable:** _________________________

**3 Common vulnerabilities:**
1. _________________________
2. _________________________
3. _________________________

**Best use cases:**
1. _________________________
2. _________________________
3. _________________________

**Team Blind note:** _________________________

---

#### OpenVPN

**Encryption algorithm:** _________________________

**Key exchange (underlying protocol):** _________________________

**Authentication hash:** _________________________

**Deployment complexity:** ☐ Very Low ☐ Low ☐ Medium ☐ High

**Downgrade attack risk:** ☐ Yes ☐ No  
**Explain:** _________________________

**Perfect Forward Secrecy:** ☐ Yes ☐ No ☐ Depends on config  
**Details:** _________________________

**3 Common vulnerabilities:**
1. _________________________
2. _________________________
3. _________________________

**Best use cases:**
1. _________________________
2. _________________________
3. _________________________

**Team Blind note:** _________________________

---

### VPN Recommendation Scenarios

**Scenario 1: Startup (50 employees), cloud-native infrastructure, no compliance requirements**

Your recommendation: ☐ WireGuard ☐ IPsec ☐ OpenVPN

**Rationale:**
_________________________
_________________________
_________________________

---

**Scenario 2: Financial company (500 employees), PCI-DSS compliance required, legacy infrastructure**

Your recommendation: ☐ WireGuard ☐ IPsec ☐ OpenVPN

**Rationale:**
_________________________
_________________________
_________________________

**NIST compliance note:**
_________________________

---

**Scenario 3: Remote-first company (200 employees), users need to bypass restrictive corporate firewalls**

Your recommendation: ☐ WireGuard ☐ IPsec ☐ OpenVPN

**Rationale:**
_________________________
_________________________
_________________________

---

### Part 2 Deliverables Checklist

- [ ] `vpn_protocol_comparison.py` created
- [ ] Protocol comparison table completed for all 3 protocols
- [ ] Can explain trade-offs between protocols
- [ ] Completed 3 recommendation scenarios
- [ ] Understand NIST compliance implications

---

## Part 3: VPN Attack Scenarios & Incident Response (1 hour)

### Exercise A: Credential Brute Force Attack Response (20 minutes)

**Scenario:** 50 failed VPN login attempts for user `admin@company.com` from IP `203.0.113.45` in 5 minutes

#### Immediate Actions (First 15 minutes)

**Action 1:**
_________________________

**Action 2:**
_________________________

**Action 3:**
_________________________

**Action 4:**
_________________________

**Action 5:**
_________________________

#### Investigation Steps (Next 30 minutes)

**What logs would you review?**
1. _________________________
2. _________________________
3. _________________________

**What patterns would indicate:**

**Username enumeration attack:**
_________________________

**Credential stuffing attack:**
_________________________

**Distributed botnet attack:**
_________________________

#### Response Actions

**List 4 response actions:**
1. _________________________
2. _________________________
3. _________________________
4. _________________________

#### Root Cause Analysis Questions

**Why wasn't MFA required?**
_________________________

**Why isn't account lockout enabled?**
_________________________

**Why isn't IP allowlisting used for admin accounts?**
_________________________

#### Long-term Improvements

1. _________________________
2. _________________________
3. _________________________
4. _________________________

---

### Exercise B: VPN Protocol Vulnerability Response (20 minutes)

**Scenario:** CVE-2024-XXXXX published for OpenVPN 2.5.x - Remote Code Execution vulnerability

#### Immediate Actions (First 30 minutes)

**How would you identify affected systems?**

Command on Ubuntu: _________________________

Command on RedHat: _________________________

**CVE Details to Review:**
1. _________________________
2. _________________________
3. _________________________
4. _________________________

#### Risk Assessment Matrix

| Factor | Your Assessment | Notes |
|--------|-----------------|-------|
| Internet-facing? | ☐ Yes ☐ No | |
| Authentication required to exploit? | ☐ Yes ☐ No | |
| PoC exploit available? | ☐ Yes ☐ No | |
| Patch available? | ☐ Yes ☐ No | |

**Overall Risk Level:** ☐ Critical ☐ High ☐ Medium ☐ Low

#### Response Decision

**Your chosen response path:** ☐ Emergency patch ☐ Temporary disable ☐ Compensating controls

**Justification:**
_________________________
_________________________

**If patching, timeline:** _________________________

**If disabling, alternative access method:** _________________________

**If compensating controls, which ones:**
1. _________________________
2. _________________________
3. _________________________

#### Communication Plan

**Who needs to be notified?**
1. _________________________
2. _________________________
3. _________________________
4. _________________________

**User communication needed?** ☐ Yes ☐ No

**If yes, what message:**
_________________________
_________________________

---

### Exercise C: Session Hijacking Detection (20 minutes)

**Create file:** `vpn_session_monitoring.py`

```python
#!/usr/bin/env python3
"""
VPN Session Hijacking Detection
Student: _________________________
Date: _________________________
"""

# TODO: Write session anomaly detection code
# Detect: concurrent sessions, impossible travel, IP changes




```

**Test Case 1: Concurrent Sessions from Different IPs**

Input:
```python
# User alice@company.com has sessions from:
# - 203.0.113.10 (New York) at 10:00 AM
# - 198.51.100.50 (Tokyo) at 10:15 AM (both active)
```

Expected detection: _________________________

Your code detected it? ☐ Yes ☐ No

---

**Test Case 2: Impossible Travel**

Input:
```python
# User bob@company.com:
# - Login from London at 2:00 PM
# - Login from Sydney at 2:30 PM
```

Expected detection: _________________________

Your code detected it? ☐ Yes ☐ No

---

**What are 3 indicators of VPN session hijacking?**

1. _________________________
2. _________________________
3. _________________________

---

### Part 3 Deliverables Checklist

- [ ] Brute force attack response plan completed
- [ ] CVE vulnerability response plan completed
- [ ] `vpn_session_monitoring.py` created
- [ ] Session hijacking test cases passed
- [ ] Can explain response steps for each attack type

---

## Part 4: VPN Security Architecture Design (30 minutes)

### Exercise: Network Segmentation with VPN

**Draw or describe your network architecture:**

```
(Use ASCII art or describe in detail)

External Users → Internet → VPN Gateway → ???












```

---

### Network Zones Documentation

#### DMZ Zone

**IP Range:** _________________________

**Purpose:** _________________________

**Firewall Rules:**
1. Allow: _________________________
2. Deny: _________________________
3. Allow: _________________________

---

#### Web/Application Zone

**IP Range:** _________________________

**Purpose:** _________________________

**Who can access:** _________________________

**Allowed protocols/ports:** _________________________

---

#### Internal Workstation Zone

**IP Range:** _________________________

**Purpose:** _________________________

**VPN users have direct access?** ☐ Yes ☐ No

**If no, how do they access?** _________________________

---

#### Database Zone

**IP Range:** _________________________

**Purpose:** _________________________

**Who can access directly:** _________________________

**VPN users have access?** ☐ Yes ☐ No  
**Why/Why not:** _________________________

---

### VPN Security Controls

#### Authentication

- [ ] Certificate-based authentication (not PSK)
- [ ] MFA required
- [ ] User certificates expire every _____ days
- [ ] Certificate revocation list (CRL) checked

**Additional notes:**
_________________________

---

#### Authorization

**How is least privilege enforced?**
_________________________

**Role-based access control (RBAC) roles:**

1. **Developers** can access: _________________________
2. **DBAs** can access: _________________________
3. **Admins** can access: _________________________

---

#### Monitoring

**What VPN events are logged?**
1. _________________________
2. _________________________
3. _________________________
4. _________________________

**Alert conditions:**
1. _________________________
2. _________________________
3. _________________________
4. _________________________

**Log retention period:** _________________________

---

#### Compliance

**Encryption in transit:** _________________________

**Perfect Forward Secrecy:** ☐ Yes ☐ No

**Session timeout:** _____ hours

**Logging retention:** _____ days

**Compliance standards met:** _________________________

---

### Threat Model

#### Threat 1: Stolen VPN Credentials

**Likelihood:** ☐ High ☐ Medium ☐ Low

**Impact:** ☐ High ☐ Medium ☐ Low

**Mitigations:**
1. _________________________
2. _________________________
3. _________________________

---

#### Threat 2: Insider Threat

**Likelihood:** ☐ High ☐ Medium ☐ Low

**Impact:** ☐ High ☐ Medium ☐ Low

**Mitigations:**
1. _________________________
2. _________________________
3. _________________________

---

#### Threat 3: VPN Gateway Compromise

**Likelihood:** ☐ High ☐ Medium ☐ Low

**Impact:** ☐ High ☐ Medium ☐ Low

**Mitigations:**
1. _________________________
2. _________________________
3. _________________________

---

#### Threat 4: Man-in-the-Middle Attack

**Likelihood:** ☐ High ☐ Medium ☐ Low

**Impact:** ☐ High ☐ Medium ☐ Low

**Mitigations:**
1. _________________________
2. _________________________
3. _________________________

---

### Part 4 Deliverables Checklist

- [ ] Network diagram created
- [ ] 4 network zones documented with IP ranges
- [ ] Firewall rules defined for each zone
- [ ] Authentication controls documented
- [ ] Authorization/RBAC roles defined
- [ ] Monitoring and alerting specified
- [ ] 4 threats modeled with mitigations

---

## Interview Preparation Questions

Practice answering these out loud. Write brief notes.

### Technical Understanding

**Q1: Explain the cryptographic primitives WireGuard uses and why they're secure.**

Your answer:
_________________________
_________________________
_________________________

---

**Q2: What's the difference between stateful and stateless firewalls in VPN context?**

Your answer:
_________________________
_________________________
_________________________

---

**Q3: How does Perfect Forward Secrecy work in VPNs?**

Your answer:
_________________________
_________________________
_________________________

---

### Practical Security Engineering

**Q4: Walk me through how you'd evaluate VPN vendors for our company.**

Your answer:
_________________________
_________________________
_________________________
_________________________

---

**Q5: How would you respond to a VPN brute force attack?**

Your answer:
_________________________
_________________________
_________________________
_________________________

---

**Q6: Design a secure VPN architecture for a remote-first company with 200 employees.**

Your answer:
_________________________
_________________________
_________________________
_________________________

---

### Attack Scenarios (Team Blind Focus)

**Q7: What are common VPN attack vectors and how do you mitigate them?**

Your answer:
1. Attack: _________________________ Mitigation: _________________________
2. Attack: _________________________ Mitigation: _________________________
3. Attack: _________________________ Mitigation: _________________________

---

**Q8: How would you detect VPN session hijacking?**

Your answer:
_________________________
_________________________
_________________________

---

**Q9: Explain protocol downgrade attacks and how WireGuard prevents them.**

Your answer:
_________________________
_________________________
_________________________

---

## Lab Completion Summary

### Time Tracking

| Part | Estimated Time | Actual Time | Notes |
|------|----------------|-------------|-------|
| Part 1: WireGuard Setup | 1.5 hours | | |
| Part 2: Protocol Comparison | 1 hour | | |
| Part 3: Incident Response | 1 hour | | |
| Part 4: Architecture Design | 30 minutes | | |
| **TOTAL** | **4 hours** | | |

---

### Key Learnings

**3 most important things you learned:**

1. _________________________
2. _________________________
3. _________________________

---

### Challenges Encountered

**What was difficult?**
_________________________
_________________________

**How did you overcome it?**
_________________________
_________________________

---

### Next Steps

**Areas needing more practice:**
1. _________________________
2. _________________________
3. _________________________

**Additional resources to review:**
1. _________________________
2. _________________________

---

## Final Checklist - Lab Complete

- [ ] All 4 parts completed
- [ ] All code files created and tested
- [ ] All interview questions practiced
- [ ] Ready to discuss VPN security in interviews
- [ ] Can explain WireGuard vs IPsec vs OpenVPN trade-offs
- [ ] Can respond to VPN security incidents
- [ ] Can design secure VPN architectures

---

## References

[1] Donenfeld, J. A., "WireGuard: Next Generation Kernel Network Tunnel", 2020  
[2] Team Blind Security Engineering Study Guide, VPN Attack Vectors section  
[3] NIST SP 800-77 Rev 1, "Guide to IPsec VPNs", June 2020  

---

**Lab completed on:** _________________________

**Self-assessment (1-10):** _____/10

**Ready for VPN security interviews?** ☐ Yes ☐ Need more practice

**Notes for review:**
_________________________
_________________________
_________________________
