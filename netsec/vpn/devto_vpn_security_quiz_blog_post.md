---
title: "Master VPN Security: A Complete Quiz on Protocols, Attack Vectors & Defense Strategies"
published: true
description: "Test your VPN security knowledge with this comprehensive quiz covering IPsec, WireGuard, OpenVPN, downgrade attacks, MitM indicators, and advanced defenses like certificate pinning vs DANE."
tags: cybersecurity, networking, security, tutorial
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/placeholder.jpg
canonical_url: null
---

# Master VPN Security: A Complete Quiz on Protocols, Attack Vectors & Defense Strategies

## Introduction: Why VPN Security Matters More Than Ever

As remote work becomes permanent and zero-trust architectures dominate security discussions, understanding VPN security is no longer optional—it's essential for every security engineer, DevOps professional, and systems administrator.

I recently completed Week 3 of my intensive 48-week Security Engineering curriculum focused on transitioning from Intel hardware security to Application Security Engineering. This week covered VPN protocols, attack vectors, and network segmentation—critical knowledge for anyone serious about infrastructure security.

**What you'll learn in this post:**
- VPN protocol fundamentals (IPsec, WireGuard, OpenVPN)
- VPN attack vectors emphasized by security teams
- Downgrade attacks vs general MitM attacks
- Certificate pinning vs DANE (DNSSEC) for advanced defense
- Hands-on quiz questions to test your knowledge

> 💡 **Want more security engineering exercises like this?** I'm building a comprehensive collection of AppSec challenges and security quizzes at [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises). Star the repo to follow along with my 48-week journey from Intel to AppSec! ⭐

---

## Part 1: VPN Fundamentals & Attack Vectors Quiz

This quiz covers the core VPN security concepts you need to know for security engineering interviews and real-world infrastructure defense.

**Instructions:** Answer all 22 questions below. Don't peek at the answers! Scroll to the bottom after completing the quiz to check your responses.

### Section 1: VPN Protocol Fundamentals

**Question 1:** A company needs to deploy a VPN for remote employees accessing internal APIs. Which VPN protocol operates at the network layer and provides authenticated encryption for IP packets?

- A) OpenVPN
- B) IPsec
- C) WireGuard
- D) Both B and C

**Your Answer:** _______

---

**Question 2:** WireGuard is described as "modern, lightweight, and faster than IPsec." What are TWO primary reasons WireGuard achieves better performance than traditional IPsec implementations? (Select TWO)

- A) Uses only symmetric encryption
- B) Smaller cryptographic code base (~4,000 lines vs 400,000+)
- C) Operates at the application layer
- D) Uses modern cryptographic primitives (ChaCha20, Curve25519)
- E) Doesn't support perfect forward secrecy

**Your Answer:** _______

---

**Question 3:** According to standard VPN documentation, which VPN protocol uses SSL/TLS as its underlying transport mechanism and operates at the application layer?

- A) IPsec (operates at network layer)
- B) WireGuard (operates at network layer)
- C) OpenVPN (SSL/TLS based, application layer)
- D) All three use SSL/TLS

**Your Answer:** _______

---

### Section 2: VPN Attack Vectors

**Question 4:** An attacker captures VPN authentication credentials through phishing. What are the TWO most relevant credential-based attack types the attacker might execute? (Select TWO)

- A) Brute force attacks
- B) Buffer overflow attacks
- C) Credential stuffing
- D) DNS poisoning
- E) ARP spoofing

**Your Answer:** _______

---

**Question 5:** A security audit reveals your VPN server supports both AES-256-GCM and DES encryption. What specific protocol vulnerability attack vector does this configuration enable?

- A) Session hijacking
- B) Downgrade attacks
- C) Token theft
- D) Man-in-the-middle (general)

**Your Answer:** _______

---

**Question 6:** You're investigating a potential VPN compromise. An attacker intercepted a valid session token after successful authentication. What specific attack vector category does this represent?

- A) Credential attacks
- B) Protocol vulnerabilities
- C) Session hijacking
- D) Split tunneling exploitation

**Your Answer:** _______

---

### Section 3: Tunneling Configurations

**Question 7:** An employee's laptop is configured with split tunneling enabled. They access both internal company resources and public internet services. From a security perspective, what is the PRIMARY risk this configuration introduces?

- A) Increased bandwidth consumption
- B) Slower internet speeds
- C) Bypassed corporate security controls for non-VPN traffic
- D) Incompatibility with IPsec

**Your Answer:** _______

---

**Question 8:** Your company implements full tunneling for all VPN connections. Which statement BEST describes this configuration?

- A) Only traffic to corporate IP ranges goes through the VPN
- B) All internet traffic routes through the corporate VPN gateway
- C) DNS queries bypass the VPN for performance
- D) VPN only activates when accessing specific applications

**Your Answer:** _______

---

### Section 4: Applied Security Scenarios

**Question 9:** You're designing VPN access for contractors who need temporary access to a DMZ-hosted API server. Considering network segmentation principles, which security control would you implement?

- A) Grant full tunneling VPN access to entire corporate network
- B) Use split tunneling restricted to DMZ subnet only
- C) Disable VPN and use direct internet access
- D) Require multi-hop VPN through production network first

**Your Answer:** _______

---

**Question 10:** During a security review, you discover your organization's IPsec VPN uses 3DES encryption (168-bit effective key strength). Considering modern cryptographic standards, what should you recommend?

- A) Keep 3DES since it's still secure
- B) Upgrade to AES-256-GCM
- C) Downgrade to DES for compatibility
- D) Switch to RC4 cipher

**Your Answer:** _______

---

> 📚 **Learning Resource:** These questions are part of my comprehensive Security Engineering curriculum. Check out the full 48-week roadmap and weekly exercises at [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises) ⭐

---

## Part 2: Advanced VPN Security - Remediation Deep Dive

After mastering the fundamentals, here's a deeper dive into three critical topics: WireGuard performance, downgrade attacks, and MitM detection.

### WireGuard Performance Characteristics

**Question 11:** The WireGuard whitepaper claims the entire codebase is approximately 4,000 lines of code, compared to IPsec implementations which can exceed 400,000 lines. From a security engineering perspective, why does a smaller codebase directly improve security? (Select TWO)

- A) Smaller binaries load faster
- B) Reduced attack surface - fewer lines means fewer potential vulnerabilities
- C) Easier to audit - security researchers can review the entire codebase thoroughly
- D) Uses less memory at runtime
- E) Compatible with more operating systems

**Your Answer:** _______

---

**Question 12:** WireGuard uses ChaCha20-Poly1305 for authenticated encryption instead of AES-GCM. On processors WITHOUT dedicated AES hardware instructions (AES-NI), why does ChaCha20 perform better than AES?

- A) ChaCha20 uses a longer key (512 bits vs 256 bits)
- B) ChaCha20 is designed for efficient software implementation without requiring hardware acceleration
- C) ChaCha20 doesn't require any encryption at all
- D) ChaCha20 uses weaker encryption so it's faster

**Your Answer:** _______

---

**Question 13:** WireGuard uses Curve25519 for key exchange. Compared to traditional RSA-based key exchange (e.g., RSA-2048), what are TWO advantages of Curve25519? (Select TWO)

- A) Shorter key lengths provide equivalent security (256-bit ECC ≈ 3072-bit RSA)
- B) Faster key generation and exchange operations
- C) Works without any mathematics
- D) Doesn't require a private key
- E) Compatible with quantum computers

**Your Answer:** _______

---

### Downgrade Attacks: Deep Dive

**Question 14:** What is the ESSENTIAL characteristic that distinguishes a downgrade attack from a general man-in-the-middle attack?

- A) Downgrade attacks only work on VPNs
- B) Downgrade attacks specifically force the use of weaker cryptographic algorithms or protocol versions
- C) Downgrade attacks don't require the attacker to be in the middle
- D) Downgrade attacks are easier to detect

**Your Answer:** _______

---

**Question 15:** You're reviewing VPN server logs and notice that 95% of connections use AES-256-GCM, but 5% of connections from a specific IP range use DES encryption. Your server supports both ciphers. What should you investigate FIRST?

- A) Network bandwidth issues
- B) Possible downgrade attack - investigate why those clients negotiated weak ciphers
- C) User credential theft
- D) DNS misconfiguration

**Your Answer:** _______

---

**Question 16:** What is the MOST effective mitigation against downgrade attacks on VPN servers?

- A) Use longer passwords
- B) Disable support for weak/deprecated cipher suites entirely
- C) Increase session timeout
- D) Enable two-factor authentication

**Your Answer:** _______

---

### MitM Attack Indicators

**Question 17:** You receive a help desk ticket: "I'm getting a certificate warning when connecting to the VPN. The certificate name is 'vpn.company.com' but it says 'issued by Unknown Authority' instead of our usual CA." What type of attack does this MOST likely indicate?

- A) Downgrade attack
- B) Credential stuffing
- C) Man-in-the-middle attack with attacker-controlled certificate
- D) DDoS attack

**Your Answer:** _______

---

**Question 18:** During a VPN connection, which of the following events would be the STRONGEST cryptographic indicator of an active MitM attack?

- A) Slow connection speed
- B) Certificate chain validation failure
- C) High CPU usage on client
- D) Increased network latency

**Your Answer:** _______

---

**Question 19:** An employee reports: "My VPN connection succeeded, but I noticed the encryption changed from 'TLS 1.3 with AES-256-GCM' to 'TLS 1.0 with RC4' during the handshake." Assuming your VPN server properly supports TLS 1.3, what are the TWO most likely explanations? (Select TWO)

- A) Normal protocol negotiation based on client capabilities
- B) Active downgrade attack forcing weaker protocol
- C) Active MitM attack manipulating the handshake
- D) Network congestion
- E) DNS caching issue

**Your Answer:** _______

---

**Question 20:** You're implementing VPN monitoring. Which log events should trigger HIGH PRIORITY security alerts as potential MitM indicators? (Select TWO)

- A) Certificate validation failures from multiple clients
- B) Bandwidth usage above 1 GB per session
- C) Sudden increase in connections using deprecated TLS versions (1.0, 1.1)
- D) Users connecting from new geographic locations
- E) Sessions lasting longer than 8 hours

**Your Answer:** _______

---

## Bonus: Certificate Pinning vs DANE

**Question 21:** A sophisticated attacker has compromised a Certificate Authority that your organization trusts. They issue themselves a valid certificate for "vpn.company.com" and perform a MitM attack. Why would this attack NOT trigger certificate validation warnings on the client side?

- A) The certificate is signed by a trusted CA, so validation succeeds
- B) VPN clients don't check certificates
- C) The attacker disabled certificate checking
- D) TLS doesn't use certificates

**Your Answer:** _______

---

**Question 22:** Following the previous scenario, what additional security control could detect this sophisticated MitM attack even when the attacker has a valid certificate from a compromised CA?

- A) Certificate pinning - client expects specific certificate or public key
- B) Longer passwords
- C) Two-factor authentication
- D) Firewall rules

**Your Answer:** _______

---

## 🎯 Ready to Check Your Answers?

Before scrolling down, make sure you've answered all 22 questions! The answers and detailed explanations are below.

---
---
---

# Quiz Answers & Explanations

## Section 1: VPN Protocol Fundamentals

### Question 1: Answer - D) Both B and C

**Explanation:** Both IPsec and WireGuard operate at the network layer (Layer 3). IPsec has been the industry standard for decades, while WireGuard is a modern alternative with a much smaller codebase (~4,000 lines vs IPsec's 400,000+). OpenVPN operates at the application layer and uses SSL/TLS as its transport mechanism.

**Source:** WireGuard whitepaper, Sections 1-3

---

### Question 2: Answer - B and D

**Explanation:** 
- **B) Smaller codebase:** WireGuard's ~4,000 lines of code mean fewer bugs, easier auditing, and better performance compared to IPsec's 400,000+ lines
- **D) Modern crypto primitives:** ChaCha20 for encryption and Curve25519 for key exchange are faster than older algorithms, especially on processors without AES-NI hardware acceleration

**Why others are wrong:**
- A) WireGuard uses both symmetric and asymmetric crypto (like all VPNs)
- C) WireGuard operates at network layer, NOT application layer
- E) WireGuard DOES support perfect forward secrecy

**Source:** WireGuard: Next Generation Kernel Network Tunnel, whitepaper

---

### Question 3: Answer - C) OpenVPN

**Explanation:** OpenVPN is unique among these three in that it uses SSL/TLS as its transport and operates at Layer 7 (application layer). This makes it potentially easier to integrate with existing SSL/TLS inspection infrastructure, though both IPsec and WireGuard provide strong network-layer encryption.

---

## Section 2: VPN Attack Vectors

### Question 4: Answer - A and C

**Explanation:** Once an attacker has valid credentials, they typically execute:
- **Brute force:** Trying variations of the password
- **Credential stuffing:** Using the stolen credentials across multiple services (people reuse passwords!)

**Why others are wrong:**
- B) Buffer overflow is a software vulnerability, not a credential attack
- D) DNS poisoning is a network-level attack
- E) ARP spoofing is a Layer 2 attack

**Key takeaway:** This is why MFA (multi-factor authentication) is critical for VPN access!

---

### Question 5: Answer - B) Downgrade attacks

**Explanation:** When a server supports BOTH strong encryption (AES-256-GCM) AND weak encryption (DES), an attacker can force the connection to "downgrade" to the weaker cipher. This is a *specific type* of MitM attack called a downgrade attack.

**Real-world examples:**
- **POODLE attack (2014):** Forced TLS → SSL 3.0 downgrade
- **FREAK attack (2015):** Exploited servers supporting export-grade weak ciphers

**Mitigation:** Disable ALL weak/deprecated cipher suites entirely. Don't give attackers anything to downgrade to!

**Source:** NIST SP 800-41r1, Section 3

---

### Question 6: Answer - C) Session hijacking

**Explanation:** Session hijacking involves stealing a valid session token after authentication has succeeded. This is different from credential attacks (which target the authentication phase) and protocol vulnerabilities (which exploit cryptographic weaknesses).

**Defense:** Use short-lived session tokens, implement token rotation, and monitor for anomalous session behavior.

---

## Section 3: Tunneling Configurations

### Question 7: Answer - C) Bypassed corporate security controls

**Explanation:** Split tunneling allows direct internet access for non-corporate traffic, which means that traffic bypasses:
- Corporate firewalls
- DLP (Data Loss Prevention) systems
- Malware inspection
- Content filtering

**Trade-off:** Split tunneling improves performance but reduces security. Full tunneling routes ALL traffic through the VPN, applying corporate security controls to everything.

---

### Question 8: Answer - B) All internet traffic routes through gateway

**Explanation:** Full tunneling means 100% of network traffic (corporate AND internet) goes through the VPN tunnel. This provides maximum security but can impact performance and increases corporate bandwidth usage.

---

## Section 4: Applied Security Scenarios

### Question 9: Answer - B) Split tunneling restricted to DMZ subnet

**Explanation:** This follows the **principle of least privilege**:
- Contractors only need DMZ access (public-facing services)
- They DON'T need access to internal production systems
- Split tunneling to DMZ-only provides just enough access
- Limits blast radius if contractor credentials are compromised

**Network segmentation principle:** DMZ (Demilitarized Zone) is specifically designed for services that need external access while protecting internal networks.

---

### Question 10: Answer - B) Upgrade to AES-256-GCM

**Explanation:** 3DES is **deprecated** as of 2017 and considered a weak cipher by modern standards:
- Vulnerable to Sweet32 attack (birthday attacks on 64-bit block ciphers)
- NIST recommends against 3DES for new systems
- AES-256-GCM provides stronger security and better performance

**Why others are wrong:**
- A) 3DES is NOT secure by modern standards
- C) & D) DES and RC4 are even weaker and should NEVER be used

---

## Advanced Section: WireGuard Performance

### Question 11: Answer - B and C

**Explanation:**
- **B) Reduced attack surface:** Every line of code is a potential bug. Fewer lines = fewer places for vulnerabilities to hide
- **C) Easier to audit:** Security researchers can actually review all 4,000 lines. Auditing 400,000 lines of IPsec is practically impossible

**Real-world impact:** WireGuard's entire codebase fits in ~4,000 lines. IPsec implementations like strongSwan have 400,000+ lines. Which would you rather audit for security vulnerabilities?

**Why others are wrong:**
- A) Performance benefit, not security benefit
- D) Memory usage is important but not the primary security advantage
- E) Compatibility is not a security feature

**Source:** WireGuard whitepaper, Section 1

---

### Question 12: Answer - B) Designed for efficient software implementation

**Explanation:** Daniel J. Bernstein designed ChaCha20 specifically to be fast in pure software (no hardware acceleration needed). On processors without AES-NI:
- AES requires complex lookup tables → cache-timing attacks, slower performance
- ChaCha20 uses simple ARX operations (Add, Rotate, XOR) → constant-time, fast

**Performance comparison on ARM processors (no AES-NI):**
- ChaCha20: ~3x faster than AES
- With AES-NI: AES is faster

**This is why mobile devices and IoT often prefer ChaCha20!**

**Source:** ChaCha20 and Poly1305 for IETF Protocols, RFC 8439

---

### Question 13: Answer - A and B

**Explanation:**
- **A) Shorter keys, same security:** 256-bit Curve25519 ≈ 3072-bit RSA security (NIST recommendations)
- **B) Faster operations:** ECC operations are computationally faster than RSA for equivalent security

**Key size comparison:**

| Security Level | RSA | ECC (Curve25519) |
|---------------|-----|------------------|
| 128-bit | 3072-bit | 256-bit |
| 192-bit | 7680-bit | 384-bit |
| 256-bit | 15360-bit | 512-bit |

**Why others are wrong:**
- C) & D) Obviously wrong - all crypto uses math and private keys
- E) ECC is NOT quantum-resistant (neither is RSA)

**Source:** NIST SP 800-57, Key Management Recommendations

---

## Advanced Section: Downgrade Attacks

### Question 14: Answer - B) Force weaker cryptographic algorithms

**Explanation:** A downgrade attack is a *specific type* of MitM attack that manipulates protocol negotiation to force the use of weaker crypto:
- **General MitM:** Attacker intercepts traffic
- **Downgrade attack:** Attacker forces weaker crypto (TLS 1.3 → TLS 1.0, AES-256 → 3DES, etc.)

**Famous downgrade attacks:**
- **POODLE (2014):** TLS → SSL 3.0 downgrade
- **FREAK (2015):** Force export-grade 512-bit RSA keys
- **Logjam (2015):** Force 512-bit Diffie-Hellman

**Key insight:** Downgrade attacks exploit **backward compatibility**. The fix is to disable old/weak protocols entirely.

---

### Question 15: Answer - B) Possible downgrade attack

**Explanation:** This is a classic indicator of potential downgrade attacks:
- **Normal:** 95% of clients use strong crypto (AES-256-GCM)
- **Anomaly:** 5% from specific IP range use weak crypto (DES)

**Investigation steps:**
1. Identify the IP range (geographic location, ISP)
2. Check if legitimate clients in that range should support AES-256
3. Analyze packet captures for protocol negotiation manipulation
4. Consider if attacker is targeting specific users/locations

**Best mitigation:** Disable DES entirely so there's nothing to downgrade to!

---

### Question 16: Answer - B) Disable weak cipher suites entirely

**Explanation:** The most effective mitigation is to **eliminate the attack vector**:
- Remove all weak/deprecated ciphers from server configuration
- If only strong ciphers are available, there's nothing to downgrade to
- This is "defense by removing attack surface"

**Configuration example (OpenVPN):**
```bash
# BAD: Allows downgrades
cipher AES-256-GCM:AES-128-GCM:3DES

# GOOD: Only modern ciphers
cipher AES-256-GCM:AES-128-GCM
```

**Why others don't prevent downgrade attacks:**
- A) Password length doesn't affect cipher negotiation
- C) Session timeout is irrelevant to crypto downgrade
- D) 2FA helps with authentication, not crypto downgrade

**Source:** NIST SP 800-52r2, TLS Guidelines

---

## Advanced Section: MitM Indicators

### Question 17: Answer - C) MitM attack with attacker-controlled certificate

**Explanation:** "Issued by Unknown Authority" means:
- An attacker is presenting their own certificate
- The certificate is NOT signed by your organization's trusted CA
- This is classic MitM attack indicator

**What's happening:**
1. User tries to connect to vpn.company.com
2. Attacker intercepts the connection
3. Attacker presents their own certificate for vpn.company.com
4. Certificate validation fails → warning

**User instructions:** NEVER click through this warning! Report to security team immediately.

---

### Question 18: Answer - B) Certificate chain validation failure

**Explanation:** 
- **Cryptographic indicators** (strong evidence of MitM):
  - Certificate validation failures
  - Unexpected certificate changes
  - TLS handshake failures
  - Cipher downgrade

- **Network indicators** (could be many causes):
  - Slow speeds (could be congestion)
  - High latency (could be routing)
  - High CPU (could be legitimate processing)

**Rule of thumb:** Trust cryptographic failures over network anomalies for MitM detection.

**Source:** High Performance Browser Networking, Chapter 4: TLS

---

### Question 19: Answer - B and C

**Explanation:** These are the **same attack from different perspectives:**
- **B) Downgrade attack:** WHAT the attack does (forces weaker crypto)
- **C) MitM attack:** HOW it's accomplished (intercepts and manipulates handshake)

**Why this is suspicious:**
- TLS 1.0 is deprecated (2021)
- RC4 is broken and should NEVER be used
- If both client and server support TLS 1.3, normal negotiation would use it

**Key insight:** Downgrade attacks ARE MitM attacks. You can't manipulate a TLS handshake without being in the middle.

**Why others are wrong:**
- A) Normal negotiation would choose strongest mutually supported option
- D) Network congestion doesn't affect protocol version selection
- E) DNS caching doesn't affect TLS handshake

---

### Question 20: Answer - A and C

**Explanation:**
- **A) Multiple cert validation failures:** Strong indicator of active MitM campaign
- **C) Increase in deprecated TLS:** Suggests widespread downgrade attack

**Why others are lower priority:**
- B) High bandwidth could be legitimate file transfers
- D) New locations could be travel (verify with user)
- E) Long sessions could be legitimate remote work

**Monitoring best practice:** Prioritize cryptographic anomalies over usage patterns.

**SIEM alert rules:**
```
CRITICAL: certificate_validation_failure AND count > 5 in 10min
HIGH: tls_version IN (1.0, 1.1) AND increase > 20% over baseline
```

---

## Bonus Questions: Certificate Pinning vs DANE

### Question 21: Answer - A) Signed by trusted CA

**Explanation:** This is the **fundamental vulnerability** of the CA system:
- Your computer trusts 100+ Certificate Authorities
- If ANY one is compromised, attackers can get "valid" certificates
- Certificate validation succeeds because it's properly signed

**Real-world examples:**
- **DigiNotar breach (2011):** Fraudulent certificates for google.com used to intercept Gmail in Iran
- **Comodo breach (2011):** Fraudulent certificates for multiple major websites

**This is WHY certificate pinning and DANE exist** - to protect against compromised CAs!

---

### Question 22: Answer - A) Certificate pinning

**Explanation:** 

**Certificate Pinning:**
- Client hardcodes the expected certificate or public key
- Even if attacker has "valid" cert from compromised CA, it won't match the pin
- Connection is rejected

**Pinning example (conceptual):**
```python
EXPECTED_VPN_KEY = "sha256/abc123def456..."  # Hardcoded

def verify_certificate(server_cert):
    if hash(server_cert.public_key) != EXPECTED_VPN_KEY:
        raise SecurityError("Certificate doesn't match pin!")
```

**DANE (alternative):**
- Uses DNSSEC to publish expected certificate in DNS
- Domain owner specifies which cert to trust
- Requires DNSSEC infrastructure

**Certificate Pinning vs DANE:**

| Feature | Certificate Pinning | DANE |
|---------|-------------------|------|
| Trust Anchor | Application itself | DNS root via DNSSEC |
| Deployment | Easy (embed in app) | Complex (DNSSEC) |
| Cert Rotation | Requires app update | Update DNS record |
| Best For | Custom apps (VPN clients, mobile apps) | Email (SMTP), web services |

**Why others don't help:**
- B) Password length irrelevant to certificate validation
- C) 2FA helps authentication, not certificate trust
- D) Firewalls can't detect valid-but-malicious certificates

**Source:** RFC 6698 (DANE), Chrome HPKP deprecation notes

---

---

## Key Takeaways for Security Engineers

### VPN Protocol Selection
- **IPsec:** Industry standard, complex, well-tested, 400,000+ lines of code
- **WireGuard:** Modern, lightweight, ~4,000 lines, faster, easier to audit
- **OpenVPN:** Application-layer, SSL/TLS based, flexible, good firewall traversal

### Attack Vector Priorities
1. **Credential attacks:** MFA is mandatory for VPN access
2. **Downgrade attacks:** Disable ALL weak/deprecated ciphers
3. **Session hijacking:** Short-lived tokens, monitor for anomalies
4. **MitM attacks:** Certificate pinning for critical apps

### Monitoring & Detection
- **High priority alerts:** Certificate validation failures, deprecated TLS spikes
- **Medium priority:** Geographic anomalies, unusual bandwidth
- **Trust cryptographic indicators** over network anomalies

### Defense in Depth
- **Layer 1:** Strong authentication (MFA)
- **Layer 2:** Modern crypto only (AES-256-GCM, TLS 1.3)
- **Layer 3:** Certificate pinning (for custom clients)
- **Layer 4:** Network segmentation (DMZ, least privilege)
- **Layer 5:** Continuous monitoring (SIEM alerts)

---

## Continue Your Security Engineering Journey

This quiz is part of my comprehensive 48-week Security Engineering curriculum, documenting my transition from Intel hardware security to Application Security Engineering.

**What's covered in the full curriculum:**
- ✅ **Week 1-2:** TCP/IP fundamentals, DNS, TLS
- ✅ **Week 3:** Firewalls, VPN, network segmentation (this post!)
- 🔜 **Week 4:** Burp Suite, Web AppSec, OWASP Top 10
- 🔜 **Weeks 5-48:** SAST/DAST tools, cloud security, threat modeling, API security, and more

**Get the complete curriculum and weekly exercises:**
👉 **[github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)** ⭐

**Repository includes:**
- 48-week structured curriculum with weekly deliverables
- LeetCode-style security exercises with 60+ test cases each
- PortSwigger lab walkthroughs
- Security tool implementations in Python
- Interview preparation resources
- Weekly progress tracking

### Follow My Journey
- **GitHub:** [@fosres](https://github.com/fosres)
- **Dev.to:** [@fosres](https://dev.to/fosres)
- **Blog posts:** Security quizzes, tool tutorials, career insights

**Star the repo** if you found this quiz valuable - it helps me know this content is useful for the community! ⭐

---

## Sources & Further Reading

1. **WireGuard: Next Generation Kernel Network Tunnel** - Jason A. Donenfeld, 2017  
   https://www.wireguard.com/papers/wireguard.pdf

2. **NIST SP 800-41r1: Guidelines on Firewalls and Firewall Policy**  
   https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41r1.pdf

3. **High Performance Browser Networking** - Ilya Grigorik (O'Reilly)  
   https://hpbn.co/

4. **RFC 6698: DNS-Based Authentication of Named Entities (DANE)**  
   https://tools.ietf.org/html/rfc6698

5. **RFC 7671: The DANE Protocol: Updates and Operational Guidance**  
   https://tools.ietf.org/html/rfc7671

6. **Complete 48-Week Security Engineering Curriculum** (My GitHub repo)  
   https://github.com/fosres/AppSec-Exercises

---

## Discussion

What did you score on this quiz? What VPN security topics would you like to see covered next? Drop a comment below! 👇

**Tags:** #cybersecurity #networking #security #tutorial
