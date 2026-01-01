# Week 3 VPN Security - Remediation Quiz

**Student**: Tanveer Salim  
**Date**: January 1, 2026  
**Focus Areas**: WireGuard Performance, Downgrade Attacks, MitM Indicators

---

## Instructions

This quiz focuses on the three areas where you need more practice:
1. **WireGuard performance characteristics** (Questions 1-4)
2. **Downgrade attacks vs general MitM** (Questions 5-8)
3. **MitM attack indicators** (Questions 9-12)

Answer all questions. After completing, share your answers for detailed feedback with citations.

---

## Section 1: WireGuard Performance Characteristics

### Question 1
The WireGuard whitepaper claims the entire codebase is approximately 4,000 lines of code, compared to IPsec implementations which can exceed 400,000 lines. From a security engineering perspective, why does a smaller codebase directly improve security? (Select TWO)

- [ ] A) Smaller binaries load faster
- [ ] B) Reduced attack surface - fewer lines means fewer potential vulnerabilities
- [ ] C) Easier to audit - security researchers can review the entire codebase thoroughly
- [ ] D) Uses less memory at runtime
- [ ] E) Compatible with more operating systems

**Your Answer**: 

---

### Question 2
WireGuard uses ChaCha20-Poly1305 for authenticated encryption instead of AES-GCM. On processors WITHOUT dedicated AES hardware instructions (AES-NI), why does ChaCha20 perform better than AES?

- [ ] A) ChaCha20 uses a longer key (512 bits vs 256 bits)
- [ ] B) ChaCha20 is designed for efficient software implementation without requiring hardware acceleration
- [ ] C) ChaCha20 doesn't require any encryption at all
- [ ] D) ChaCha20 uses weaker encryption so it's faster

**Your Answer**: 

---

### Question 3
WireGuard uses Curve25519 for key exchange. Compared to traditional RSA-based key exchange (e.g., RSA-2048), what are TWO advantages of Curve25519? (Select TWO)

- [ ] A) Shorter key lengths provide equivalent security (256-bit ECC ≈ 3072-bit RSA)
- [ ] B) Faster key generation and exchange operations
- [ ] C) Works without any mathematics
- [ ] D) Doesn't require a private key
- [ ] E) Compatible with quantum computers

**Your Answer**: 

---

### Question 4
A company is choosing between IPsec and WireGuard for their VPN. The security team argues that WireGuard's "opinionated" design (fixed crypto suite: ChaCha20, Curve25519, BLAKE2s) is actually a security advantage over IPsec's flexibility (supports dozens of cipher suites). What is the BEST security argument for this position?

- [ ] A) Fewer cipher suite options means users can't choose insecure configurations
- [ ] B) WireGuard is newer so it must be better
- [ ] C) IPsec requires more memory
- [ ] D) Reducing cipher suite negotiation complexity eliminates downgrade attack vectors

**Your Answer**: 

---

## Section 2: Downgrade Attacks vs General MitM

### Question 5
What is the ESSENTIAL characteristic that distinguishes a downgrade attack from a general man-in-the-middle attack?

- [ ] A) Downgrade attacks only work on VPNs
- [ ] B) Downgrade attacks specifically force the use of weaker cryptographic algorithms or protocol versions
- [ ] C) Downgrade attacks don't require the attacker to be in the middle
- [ ] D) Downgrade attacks are easier to detect

**Your Answer**: 

---

### Question 6
A VPN server is configured to support the following TLS cipher suites in order of preference:
1. TLS_AES_256_GCM_SHA384 (strong)
2. TLS_AES_128_GCM_SHA256 (strong)
3. TLS_RSA_WITH_3DES_EDE_CBC_SHA (weak, deprecated)

An attacker performs a man-in-the-middle attack and manipulates the TLS handshake to force the connection to use cipher suite #3. What specific attack has occurred?

- [ ] A) Session hijacking
- [ ] B) Credential stuffing
- [ ] C) Downgrade attack
- [ ] D) Brute force attack

**Your Answer**: 

---

### Question 7
You're reviewing VPN server logs and notice that 95% of connections use AES-256-GCM, but 5% of connections from a specific IP range use DES encryption. Your server supports both ciphers. What should you investigate FIRST?

- [ ] A) Network bandwidth issues
- [ ] B) Possible downgrade attack - investigate why those clients negotiated weak ciphers
- [ ] C) User credential theft
- [ ] D) DNS misconfiguration

**Your Answer**: 

---

### Question 8
What is the MOST effective mitigation against downgrade attacks on VPN servers?

- [ ] A) Use longer passwords
- [ ] B) Disable support for weak/deprecated cipher suites entirely
- [ ] C) Increase session timeout
- [ ] D) Enable two-factor authentication

**Your Answer**: 

---

## Section 3: MitM Attack Indicators

### Question 9
You receive a help desk ticket: "I'm getting a certificate warning when connecting to the VPN. The certificate name is 'vpn.company.com' but it says 'issued by Unknown Authority' instead of our usual CA." What type of attack does this MOST likely indicate?

- [ ] A) Downgrade attack
- [ ] B) Credential stuffing
- [ ] C) Man-in-the-middle attack with attacker-controlled certificate
- [ ] D) DDoS attack

**Your Answer**: 

---

### Question 10
During a VPN connection, which of the following events would be the STRONGEST cryptographic indicator of an active MitM attack? (Select the MOST specific indicator)

- [ ] A) Slow connection speed
- [ ] B) Certificate chain validation failure
- [ ] C) High CPU usage on client
- [ ] D) Increased network latency

**Your Answer**: 

---

### Question 11
An employee reports: "My VPN connection succeeded, but I noticed the encryption changed from 'TLS 1.3 with AES-256-GCM' to 'TLS 1.0 with RC4' during the handshake." Assuming your VPN server properly supports TLS 1.3, what are the TWO most likely explanations? (Select TWO)

- [ ] A) Normal protocol negotiation based on client capabilities
- [ ] B) Active downgrade attack forcing weaker protocol
- [ ] C) Active MitM attack manipulating the handshake
- [ ] D) Network congestion
- [ ] E) DNS caching issue

**Your Answer**: 

---

### Question 12
You're implementing VPN monitoring. Which log events should trigger HIGH PRIORITY security alerts as potential MitM indicators? (Select TWO)

- [ ] A) Certificate validation failures from multiple clients
- [ ] B) Bandwidth usage above 1 GB per session
- [ ] C) Sudden increase in connections using deprecated TLS versions (1.0, 1.1)
- [ ] D) Users connecting from new geographic locations
- [ ] E) Sessions lasting longer than 8 hours

**Your Answer**: 

---

## Bonus Challenge Questions

### Question 13
A sophisticated attacker has compromised a Certificate Authority that your organization trusts. They issue themselves a valid certificate for "vpn.company.com" and perform a MitM attack. Why would this attack NOT trigger certificate validation warnings on the client side?

- [ ] A) The certificate is signed by a trusted CA, so validation succeeds
- [ ] B) VPN clients don't check certificates
- [ ] C) The attacker disabled certificate checking
- [ ] D) TLS doesn't use certificates

**Your Answer**: 

---

### Question 14
Following Question 13's scenario, what additional security control could detect this sophisticated MitM attack even when the attacker has a valid certificate from a compromised CA?

- [ ] A) Certificate pinning - client expects specific certificate or public key
- [ ] B) Longer passwords
- [ ] C) Two-factor authentication
- [ ] D) Firewall rules

**Your Answer**: 

---

## Submission Instructions

1. Fill in your answers using format: `**Your Answer**: A` or `**Your Answer**: B, D` (for multi-select)
2. Save this file with your answers
3. Share your completed quiz for detailed feedback

---

## Study Resources for Remediation

Before taking this quiz, consider reviewing:

1. **WireGuard Performance** (Questions 1-4):
   - WireGuard whitepaper, Section 1 (Introduction) and Section 3 (Protocol Overview)
   - Focus on: code simplicity, modern cryptographic primitives (ChaCha20, Curve25519)

2. **Downgrade Attacks** (Questions 5-8):
   - Complete 48 Week Curriculum, Week 3, page 9: "Protocol vulnerabilities: Weak ciphers, downgrade attacks"
   - Research: POODLE attack (TLS → SSL 3.0 downgrade), FREAK attack (export-grade cipher downgrade)

3. **MitM Indicators** (Questions 9-12):
   - NIST SP 800-41r1, Section 3: VPN Security Considerations
   - High Performance Browser Networking, Chapter 4: TLS handshake and certificate validation

---

## Sources Referenced

- Complete 48 Week Security Engineering Curriculum, Week 3 (pages 9-10)
- WireGuard: Next Generation Kernel Network Tunnel whitepaper (https://www.wireguard.com/papers/wireguard.pdf)
- NIST SP 800-41r1: Guidelines on Firewalls and Firewall Policy
- High Performance Browser Networking, Chapter 4: Transport Layer Security (https://hpbn.co/)
