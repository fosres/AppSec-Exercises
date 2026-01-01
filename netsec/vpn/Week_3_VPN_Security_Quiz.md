# Week 3 VPN Security Quiz

**Student**: Tanveer Salim  
**Date**: January 1, 2026  
**Topic**: VPN Security, Attack Vectors, and Tunneling Configurations

---

## Instructions

Answer all questions below. After completing, share your answers and receive detailed feedback with citations from:
- Complete 48 Week Security Engineering Curriculum (pages 9-10)
- WireGuard whitepaper (https://www.wireguard.com/papers/wireguard.pdf)
- NIST SP 800-41r1: Guidelines on Firewalls and Firewall Policy

---

## Section 1: VPN Protocol Fundamentals

### Question 1
A company needs to deploy a VPN for remote employees accessing internal APIs. Which VPN protocol operates at the network layer and provides authenticated encryption for IP packets?

- [ ] A) OpenVPN
- [ ] B) IPsec
- [ ] C) WireGuard
- [ ] D) Both B and C

**Your Answer**: 

---

### Question 2
WireGuard is described as "modern, lightweight, and faster than IPsec" in your curriculum. What are TWO primary reasons WireGuard achieves better performance than traditional IPsec implementations? (Select two)

- [ ] A) Uses only symmetric encryption
- [ ] B) Smaller cryptographic code base (~4,000 lines vs 400,000+)
- [ ] C) Operates at the application layer
- [ ] D) Uses modern cryptographic primitives (ChaCha20, Curve25519)
- [ ] E) Doesn't support perfect forward secrecy

**Your Answer**: 

---

### Question 3
Your organization needs SSL/TLS inspection on VPN traffic for compliance. Which VPN protocol would be most compatible with this requirement?

- [ ] A) IPsec
- [ ] B) WireGuard
- [ ] C) OpenVPN
- [ ] D) All are equally compatible

**Your Answer**: 

---

## Section 2: VPN Attack Vectors

### Question 4
An attacker captures VPN authentication credentials through phishing. According to your curriculum's emphasis on "VPN Attack Vectors," what are the TWO most relevant credential-based attack types the attacker might execute? (Select two)

- [ ] A) Brute force attacks
- [ ] B) Buffer overflow attacks
- [ ] C) Credential stuffing
- [ ] D) DNS poisoning
- [ ] E) ARP spoofing

**Your Answer**: 

---

### Question 5
A security audit reveals your VPN server supports both AES-256-GCM and DES encryption. What specific protocol vulnerability attack vector does this configuration enable?

- [ ] A) Session hijacking
- [ ] B) Downgrade attacks
- [ ] C) Token theft
- [ ] D) Man-in-the-middle (general)

**Your Answer**: 

---

### Question 6
You're investigating a potential VPN compromise. An attacker intercepted a valid session token after successful authentication. According to Week 3 content, what specific attack vector category does this represent?

- [ ] A) Credential attacks
- [ ] B) Protocol vulnerabilities
- [ ] C) Session hijacking
- [ ] D) Split tunneling exploitation

**Your Answer**: 

---

## Section 3: Tunneling Configurations

### Question 7
An employee's laptop is configured with split tunneling enabled. They access both internal company resources and public internet services. From a security perspective, what is the PRIMARY risk this configuration introduces?

- [ ] A) Increased bandwidth consumption
- [ ] B) Slower internet speeds
- [ ] C) Bypassed corporate security controls for non-VPN traffic
- [ ] D) Incompatibility with IPsec

**Your Answer**: 

---

### Question 8
Your company implements full tunneling for all VPN connections. Which statement BEST describes this configuration?

- [ ] A) Only traffic to corporate IP ranges goes through the VPN
- [ ] B) All internet traffic routes through the corporate VPN gateway
- [ ] C) DNS queries bypass the VPN for performance
- [ ] D) VPN only activates when accessing specific applications

**Your Answer**: 

---

### Question 9
From a "blast radius limitation" perspective (a Week 3 network segmentation concept), which tunneling configuration provides better isolation if an employee's device is compromised while connected to the VPN?

- [ ] A) Split tunneling
- [ ] B) Full tunneling
- [ ] C) Both provide equal isolation
- [ ] D) Neither provides isolation

**Your Answer**: 

---

## Section 4: Applied Security Scenarios

### Question 10
You're designing VPN access for contractors who need temporary access to a DMZ-hosted API server. Considering Week 3's network segmentation principles (DMZ for public-facing services), which security control would you implement?

- [ ] A) Grant full tunneling VPN access to entire corporate network
- [ ] B) Use split tunneling restricted to DMZ subnet only
- [ ] C) Disable VPN and use direct internet access
- [ ] D) Require multi-hop VPN through production network first

**Your Answer**: 

---

### Question 11
During a security review, you discover your organization's IPsec VPN uses 3DES encryption (168-bit effective key strength). Considering modern cryptographic standards and Week 3's focus on "weak ciphers" as a protocol vulnerability, what should you recommend?

- [ ] A) Keep 3DES since it's still secure
- [ ] B) Upgrade to AES-256-GCM
- [ ] C) Downgrade to DES for compatibility
- [ ] D) Switch to RC4 cipher

**Your Answer**: 

---

### Question 12
An incident response team suspects an active man-in-the-middle attack on VPN connections. According to Week 3's attack vector categories, which TWO indicators would most strongly suggest MitM activity? (Select two)

- [ ] A) Sudden increase in failed login attempts
- [ ] B) Certificate validation warnings on client side
- [ ] C) Unexpected TLS handshake failures or cipher downgrades
- [ ] D) High bandwidth usage
- [ ] E) Slow connection speeds

**Your Answer**: 

---

## Bonus Question (Week 3 Linux Hardening Connection)

### Question 13
Your VPN server runs Linux. Applying Week 3's "Principle of least privilege" from Linux Security Hardening Basics, what would be the MOST appropriate user permission configuration for the VPN daemon process?

- [ ] A) Run as root with full system access
- [ ] B) Run as dedicated non-root user with only necessary network capabilities
- [ ] C) Run as www-data user
- [ ] D) Run with administrator group membership

**Your Answer**: 

---

## Submission Instructions

1. Fill in your answers above using the format: `**Your Answer**: A` or `**Your Answer**: B, D` (for multi-select)
2. Save this file with your answers
3. Share your completed quiz to receive detailed feedback with explanations and source citations

---

## Sources Referenced for Quiz Creation

- Complete 48 Week Security Engineering Curriculum, Week 3 (pages 9-10)
- WireGuard Technical Whitepaper, Sections 1-3 (https://www.wireguard.com/papers/wireguard.pdf)
- NIST SP 800-41r1: Guidelines on Firewalls and Firewall Policy
- Cisco Network Segmentation Best Practices
