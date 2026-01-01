# Week 3: VPN Security Study Guide

## Learning Objectives

By the end of this VPN section, you should understand:
- ✅ What VPNs are and why they're used
- ✅ Three main VPN protocols (IPsec, WireGuard, OpenVPN)
- ✅ VPN attack vectors and vulnerabilities
- ✅ Split tunneling vs full tunneling
- ✅ How VPNs relate to firewall rules

**Time Required:** 2-3 hours

---

## What is a VPN?

**VPN (Virtual Private Network):**
- Creates encrypted tunnel between two endpoints over untrusted network (Internet)
- Makes remote network appear local (extends private network)
- Hides IP address and encrypts traffic

**Common Use Cases:**
1. **Remote Work:** Employees access company network from home
2. **Site-to-Site:** Connect two office locations
3. **Privacy:** Hide browsing from ISP/government
4. **Bypass Restrictions:** Access geo-blocked content

**How it works (simple):**
```
Your Computer → Encrypted Tunnel → VPN Server → Internet
  (Client)                          (Gateway)

Without VPN:
Your Computer → ISP → Website (ISP sees everything)

With VPN:
Your Computer → ISP → VPN Server → Website
              ↑                     ↑
         Encrypted!          VPN server's IP visible,
                            not yours
```

---

## Three Main VPN Protocols

### 1. IPsec (Internet Protocol Security)

**What it is:**
- Network layer (Layer 3) protocol
- Industry standard for site-to-site VPNs
- Built into most enterprise routers

**How it works:**
```
IPsec has two modes:

Transport Mode:
  [Original IP Header][IPsec Header][Payload (encrypted)]
  - Only payload encrypted
  - Used for end-to-end encryption

Tunnel Mode:
  [New IP Header][IPsec Header][Original IP Header][Payload] (all encrypted)
  - Entire original packet encrypted
  - Used for site-to-site VPNs
```

**Components:**
- **AH (Authentication Header):** Authenticates packets (rarely used)
- **ESP (Encapsulating Security Payload):** Encrypts and authenticates
- **IKE (Internet Key Exchange):** Negotiates encryption keys

**Pros:**
- ✅ Highly secure (military-grade)
- ✅ Native OS support (Windows, macOS, Linux)
- ✅ Fast (hardware acceleration)
- ✅ Industry standard

**Cons:**
- ❌ Complex configuration
- ❌ Difficult to troubleshoot
- ❌ Can be blocked by firewalls (uses multiple ports)
- ❌ Heavy codebase (~400,000 lines)

**Common Ports:**
- UDP 500 (IKE)
- UDP 4500 (NAT traversal)
- IP Protocol 50 (ESP)

---

### 2. WireGuard

**What it is:**
- Modern VPN protocol (released 2020)
- Network layer (Layer 3)
- Designed for simplicity and speed

**How it works:**
```
WireGuard:
  [Outer IP][WireGuard Header][Encrypted Inner Packet]
  
Key features:
- Uses state-of-the-art cryptography (ChaCha20, Curve25519)
- Pre-shared keys (no complex key exchange)
- Roaming support (seamless network changes)
```

**Cryptography (fixed, no negotiation):**
- Encryption: ChaCha20
- Authentication: Poly1305
- Key exchange: Curve25519
- Hashing: BLAKE2s

**Pros:**
- ✅ Extremely fast (faster than IPsec and OpenVPN)
- ✅ Simple codebase (~4,000 lines vs IPsec's 400,000)
- ✅ Easy to configure
- ✅ Roaming support (mobile friendly)
- ✅ Low attack surface (minimal code)
- ✅ Built into Linux kernel (5.6+)

**Cons:**
- ❌ No built-in dynamic IP support (static peer IPs)
- ❌ Stores peer IPs on server (privacy concern)
- ❌ Relatively new (less battle-tested)
- ❌ No Windows/macOS native support (needs client)

**Common Port:**
- UDP 51820 (default, configurable)

**Why it's gaining popularity:**
- Used by Mullvad VPN
- Cloudflare uses it for WARP
- Much simpler than IPsec

---

### 3. OpenVPN

**What it is:**
- Application layer (Layer 5) VPN
- Uses SSL/TLS for encryption
- Open source

**How it works:**
```
OpenVPN:
  [IP Header][TCP/UDP Header][TLS Record][OpenVPN Packet]
                               ↑
                         SSL/TLS encrypted
                         
Can run over:
  - TCP port 443 (looks like HTTPS traffic)
  - UDP port 1194 (default)
```

**Authentication:**
- Uses PKI (Public Key Infrastructure)
- Client certificates
- Username/password (optional)

**Pros:**
- ✅ Runs on TCP 443 (hard to block - looks like HTTPS)
- ✅ Highly configurable
- ✅ Cross-platform (Windows, macOS, Linux, mobile)
- ✅ Open source (auditable)
- ✅ Mature (20+ years)

**Cons:**
- ❌ Slower than IPsec and WireGuard
- ❌ Complex configuration
- ❌ Larger overhead (TLS + OpenVPN headers)
- ❌ Requires third-party client

**Common Ports:**
- UDP 1194 (default)
- TCP 443 (stealth mode)

---

## Protocol Comparison

| Feature | IPsec | WireGuard | OpenVPN |
|---------|-------|-----------|---------|
| **Layer** | Layer 3 (Network) | Layer 3 (Network) | Layer 5 (Application) |
| **Speed** | Fast | Fastest | Slowest |
| **Setup** | Complex | Simple | Medium |
| **Codebase** | ~400K lines | ~4K lines | ~100K lines |
| **Ports** | UDP 500, 4500 | UDP 51820 | UDP 1194, TCP 443 |
| **Firewall-friendly** | No (multiple ports) | Medium | Yes (can use 443) |
| **Mobile** | Good | Excellent (roaming) | Good |
| **Encryption** | Negotiable | Fixed (modern) | Negotiable |
| **Use Case** | Site-to-site | Personal VPN | Bypass firewalls |

---

## Split Tunneling vs Full Tunneling

### Full Tunneling (Default)

**What it is:**
ALL traffic goes through VPN tunnel

```
Your Computer → VPN Tunnel → VPN Server → Internet
                  ↑
            EVERYTHING goes here
```

**Traffic flow:**
```
Gmail:       You → VPN → Gmail ✓
Work files:  You → VPN → Work server ✓
YouTube:     You → VPN → YouTube ✓
Local printer: You → VPN → ??? (Fails! ✗)
```

**Pros:**
- ✅ Maximum security (all traffic encrypted)
- ✅ Company can monitor/log all activity
- ✅ Consistent IP for all services

**Cons:**
- ❌ Slower (everything routes through VPN)
- ❌ Can't access local network devices
- ❌ Expensive (VPN bandwidth costs)

---

### Split Tunneling

**What it is:**
ONLY specific traffic goes through VPN

```
                  → Direct → Internet (YouTube)
Your Computer →   
                  → VPN → Work Network (files)
```

**Configuration example:**
```
Route through VPN:
  - 192.168.10.0/24 (work network)
  - 10.0.0.0/8 (internal apps)
  
Route directly:
  - 0.0.0.0/0 (everything else)
```

**Pros:**
- ✅ Faster (non-work traffic direct)
- ✅ Can access local devices
- ✅ Cheaper (less VPN bandwidth)

**Cons:**
- ❌ Security risk (partial encryption)
- ❌ Data exfiltration possible
- ❌ Malware can bypass VPN

---

## VPN Attack Vectors

### 1. Credential Attacks

**Brute Force:**
```
Attacker tries common passwords:
  - admin:password
  - user:123456
  - vpn:vpn

Defense:
  - Strong password policy
  - Account lockout after N failed attempts
  - Multi-factor authentication (MFA)
```

**Credential Stuffing:**
```
Attacker uses leaked credentials from other breaches:
  - Uses passwords from LinkedIn breach
  - Tries against company VPN
  
Defense:
  - MFA (even if password compromised)
  - Breach notification monitoring
  - Password rotation policy
```

---

### 2. Protocol Vulnerabilities

**Weak Ciphers:**
```
Old VPN configs might allow:
  - DES (broken, crackable in hours)
  - 3DES (weak, deprecated)
  - MD5 hashing (collision attacks)

Modern should use:
  - AES-256-GCM
  - ChaCha20-Poly1305
  - SHA-256 or better
```

**Downgrade Attacks:**
```
Attacker forces VPN to use weak encryption:
  1. Intercept VPN negotiation
  2. Remove strong cipher options
  3. VPN falls back to weak cipher
  4. Attacker can decrypt

Defense:
  - Disable weak ciphers
  - Enforce minimum TLS 1.2+
  - Perfect Forward Secrecy (PFS)
```

---

### 3. Session Hijacking

**Token Theft:**
```
Attacker steals VPN session token:
  1. Malware on endpoint
  2. Steals VPN cookie/token
  3. Replays token to VPN gateway
  4. Gets access without credentials

Defense:
  - Short session timeouts
  - Device posture checking
  - Certificate-based auth (not just tokens)
```

**Man-in-the-Middle (MITM):**
```
Attacker intercepts VPN connection:
  1. DNS poisoning (redirect to fake VPN server)
  2. SSL stripping (downgrade to unencrypted)
  3. Certificate spoofing (fake CA)

Defense:
  - Certificate pinning
  - DNSSEC
  - VPN server certificate validation
```

---

### 4. VPN Server Vulnerabilities

**CVE Examples:**
- CVE-2022-22954: VMware Workspace ONE RCE
- CVE-2021-22893: Pulse Secure auth bypass
- CVE-2019-11510: Pulse Secure arbitrary file read

**Defense:**
- Regular patching
- Security monitoring
- Principle of least privilege

---

## VPN and Firewall Rules

**VPN traffic needs firewall rules!**

### Allowing VPN Through Firewall

**IPsec:**
```bash
# Allow IKE (key exchange)
iptables -A INPUT -p udp --dport 500 -j ACCEPT

# Allow NAT traversal
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# Allow ESP (encrypted payload)
iptables -A INPUT -p esp -j ACCEPT
```

**WireGuard:**
```bash
# Allow WireGuard
iptables -A INPUT -p udp --dport 51820 -j ACCEPT
```

**OpenVPN:**
```bash
# Allow OpenVPN (UDP)
iptables -A INPUT -p udp --dport 1194 -j ACCEPT

# Or stealth mode (TCP 443)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

---

### VPN Interface Rules

**When VPN connected, new interface created:**
```
tun0 (OpenVPN, WireGuard)
ipsec0 (IPsec)
```

**Example firewall rules:**
```bash
# Allow traffic FROM VPN clients
iptables -A FORWARD -i tun0 -o eth1 -j ACCEPT

# Block VPN clients from accessing DMZ
iptables -A FORWARD -i tun0 -o eth1 -d 192.168.100.0/24 -j DROP

# Log VPN traffic
iptables -A FORWARD -i tun0 -j LOG --log-prefix "VPN-TRAFFIC: "
```

---

## Security Best Practices

### 1. Use Strong Protocols
- ✅ IPsec with AES-256
- ✅ WireGuard (modern cryptography)
- ✅ OpenVPN with TLS 1.3
- ❌ PPTP (broken, never use!)
- ❌ L2TP alone (no encryption)

### 2. Authentication
- ✅ Multi-factor authentication (MFA)
- ✅ Certificate-based auth
- ✅ Strong password policy
- ❌ Password-only auth

### 3. Network Segmentation
```
VPN Users → Limited Access Zone
            ↓
            Only specific servers
            NOT full network access
```

### 4. Monitoring
- Log all VPN connections
- Alert on anomalies:
  - Multiple locations simultaneously
  - Failed auth attempts
  - Unusual data transfer

### 5. Endpoint Security
- Device posture checking
- Antivirus required
- OS patching enforced
- Encrypt local disk

---

## Interview Questions You Should Answer

### Basic:
1. What is a VPN and why use it?
2. Name three VPN protocols and their differences
3. What is split tunneling?
4. What ports does IPsec use?

### Intermediate:
5. How does WireGuard differ from OpenVPN?
6. What are the security risks of split tunneling?
7. Explain a VPN credential stuffing attack
8. How would you configure a firewall to allow IPsec?

### Advanced:
9. Your company uses full tunneling VPN. Employees complain it's slow. How do you respond?
10. An attacker compromised VPN credentials. What additional security controls would prevent access?
11. Design a secure remote access architecture for 1000 employees
12. How would you detect a VPN session hijacking attack?

---

## Hands-On Exercise (Optional)

**Set up WireGuard VPN (30 minutes):**

1. Install WireGuard
2. Generate keys
3. Configure server
4. Configure client
5. Test connection
6. Add firewall rules

**This is optional - focus on understanding concepts for interviews!**

---

## Key Takeaways

**For Security Engineering interviews:**

1. **Know the three protocols:**
   - IPsec: Enterprise standard, complex, fast
   - WireGuard: Modern, simple, fastest
   - OpenVPN: Firewall-friendly (TCP 443), mature

2. **Understand attack vectors:**
   - Credential attacks (MFA is the defense)
   - Weak ciphers (enforce modern crypto)
   - Session hijacking (short timeouts, device checks)

3. **Split vs Full tunneling:**
   - Full: Secure but slow
   - Split: Fast but risky

4. **Firewall integration:**
   - VPN needs specific ports allowed
   - VPN creates new interfaces (tun0, ipsec0)
   - Apply security rules to VPN traffic

**You don't need to configure VPNs, but you MUST understand:**
- How they work
- When to use which protocol
- Common vulnerabilities
- How to secure them

---

## Study Time Breakdown

- **Reading this guide:** 45 minutes
- **Creating flashcards:** 30 minutes
- **Practice questions:** 30 minutes
- **Optional WireGuard paper (Sections 1-3):** 45 minutes

**Total: 2-3 hours**

---

## Next Steps

After completing this VPN study:
1. Create flashcards for protocols, ports, attacks
2. Practice explaining split vs full tunneling
3. Be ready to discuss VPN in firewall contexts
4. Move to Week 4 content

**You've now completed Week 3: Firewalls + VPN!** 🎉
