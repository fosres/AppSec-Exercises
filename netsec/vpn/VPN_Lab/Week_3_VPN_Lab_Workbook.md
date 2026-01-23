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

**Are private keys set to 600 permissions?**  Yes ☐ No

Yes

---

### Step 3: Create Initial Configuration (15 minutes)

**Initial `/etc/wireguard/wg0.conf` created:**
```ini
# Paste your initial configuration here:








```

**Configuration successfully created?** ☐ Yes ☐ No

---

### Step 4: Security Review Exercise (20 minutes)

Complete the security checklist for your WireGuard configuration:

#### CRITICAL Priority Findings

**Finding 1: Private Key Permissions**
- [ ] Checked file permissions
- Current permissions: _________________________
- **Pass/Fail:** ☐ Pass (600) ☐ Fail (explain): _________________________

**Finding 2: ListenPort Configuration**
- Current port: _________________________
- Using default 51820? ☐ Yes ☐ No
- **Security improvement needed?** ☐ Yes ☐ No
- If yes, what port will you use? _________________________

**Finding 3: PersistentKeepalive**
- Currently configured? ☐ Yes ☐ No
- If yes, value: _________________________
- **Action needed?** ☐ Add it ☐ Already configured ☐ Not needed for server

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

# Start VPN:


# Check status:


# Output of 'sudo wg show':



```

**VPN successfully started?** ☐ Yes ☐ No

**If no, troubleshooting steps taken:**
_________________________
_________________________

---

### Part 1 Deliverables Checklist

- [ ] WireGuard installed and version verified
- [ ] Server and client key pairs generated
- [ ] Private keys have 600 permissions
- [ ] Initial configuration created
- [ ] Security review completed (8 findings documented)
- [ ] Secure configuration created with improvements
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
