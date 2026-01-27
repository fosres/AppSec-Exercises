# SpaceX StarShield Take-Home Test - Question 6

**Student Name:** Tanveer Salim  
**Date:** _________________  
**Time Started:** _________________  
**Time Completed:** _________________

---

## Question 6: TLS Certificate Analysis

**Points:** 20 points total  
**Estimated Time:** 30-40 minutes  
**Curriculum Alignment:** Week 6 - Applied Crypto (TLS/Certificate Security)

---

### Scenario

The SpaceX engineering team has deployed HTTPS on their internal file server but needs your expertise to assess the certificate configuration. You've been provided with the certificate details below for security review.

### Certificate Details

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            04:50:8c:6e:7e:70:c2:ee:26:7e:9f:ea:43:92:6c:97:d4:8e:d5:68
        Signature Algorithm: md5WithRSAEncryption
        Issuer: C = US, ST = California, O = SpaceX, OU = Engineering, CN = files.spacex.com
        Validity
            Not Before: Feb  1 08:00:31 2023 GMT
            Not After : Feb  1 08:00:31 2024 GMT
        Subject: C = US, ST = California, O = SpaceX, OU = Engineering, CN = files.spacex.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:b4:e6:ed:6b:d8:9e:87:43:6e:7a:6f:2a:78:0d:
                    49:d2:63:65:c0:09:53:c3:34:18:bb:cf:54:22:65:
                    81:96:6c:c1:6f:5f:13:29:9c:2e:32:6d:15:3f:16:
                    6d:30:24:03:31:a5:24:ed:d5:be:45:e6:34:29:af:
                    90:b0:4d:03:61:16:16:12:e7:04:1b:e5:00:9c:68:
                    00:5f:93:7b:a8:b1:3a:29:ae:de:ef:e3:18:0b:56:
                    57:ba:7b:47:8c:81:e7:a3:7d:a7:ae:d9:0e:5c:72:
                    1f:3d:97:a8:63:23:51:12:c4:50:8e:8e:32:12:26:
                    f1:f6:94:30:0f:87:27:0c:8b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                39:F0:B1:8B:62:A5:4E:C9:0E:B0:59:58:82:DB:2B:FC:62:7A:01:94
            X509v3 Authority Key Identifier:
                39:F0:B1:8B:62:A5:4E:C9:0E:B0:59:58:82:DB:2B:FC:62:7A:01:94
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: md5WithRSAEncryption
    Signature Value:
        98:fd:2d:f4:86:83:93:6d:33:61:d5:9b:c0:0e:7f:e4:c0:7d:
        59:c1:61:01:fc:37:f2:0b:e8:cb:a9:18:4c:cb:54:fc:11:be:
        b1:55:ec:35:c9:f8:f5:50:e5:05:38:f2:00:56:89:1f:b7:a2:
        cd:8a:66:84:f3:df:c9:a2:bc:57:b0:f2:88:39:8b:f8:50:bd:
        69:e3:61:86:ea:05:b7:b7:f2:2b:5b:63:ee:d0:94:af:84:25:
        81:59:39:b6:61:22:00:97:b9:ab:de:12:cf:af:4c:e2:29:6e:
        b8:3f:6f:ec:4f:54:45:75:01:45:e6:88:41:13:1d:bc:a4:19:
        e3:1d
```

---

### Question 6a: Certificate Problems (10 points)

**Instructions:** Identify ALL security issues with this certificate. For each issue, explain why it's a security concern.

**Your Answer:**

The certificate is signed with md5 which is an insecure cryptographic

message digest algorithm.

The certificate uses RSA-1072 which is too small of a modulus to

be secure. 

The developers should replace this certificate with one that is

signed with a larger key size and strong message digest algorithm

such as RSA-3072-SHA256 instead.

Finally an outdated version of TLS (SSL v3) is being used. One should

use the most up-to-date TLS version possible (e.g. TLS v1.3 at the

time of this writing). SSL v3 has been criticized for several

design flaws and should NEVER be used in today's time. Up-to-date

TLS versions such as TLS version 1.3 remedies them.

_(Add as many issues as you identify - create additional sections as needed)_

---

**What's wrong:**


**Why it's a security concern:**


**Relevant standards/best practices:**


---

**What's wrong:**


**Why it's a security concern:**


**Relevant standards/best practices:**


---

**What's wrong:**


**Why it's a security concern:**


**Relevant standards/best practices:**


---

### Question 6b: Attack Scenarios (5 points)

**Instructions:** For each major vulnerability you identified, explain:
1. What specific attack does it enable?
2. What tools would an attacker use?
3. What is the likelihood of successful exploitation?

**Your Answer:**

The md5 algorithm featured in the certificate is NOT collision

resistant. An attacker can use a powerful machine to generate a fake

TLS certificate that has the same md5 digest as the original authentic

certificate!

Moreover the attacker can use a powerful machine to crack the private

key based on the RSA-1072 public key featured in the TLS certificate.

In the future there is an expectation one with a powerful quantum

computer will break RSA-1072 using Shor's Algorithm--allowing the

attacker to recover the private key. Once the private key is recovered

the attacker can forge a TLS certificate with the same md5 digest

as the authentic one and sign with the cracked private key--forging

a valid TLS certificate! This would fool any computer system that

validates TLS certificates.

_(Add as many attack vectors as you identify - create additional sections as needed)_

---

**Vulnerability exploited:**


**Attack description:**


**Tools an attacker would use:**


**Likelihood of successful exploitation (High/Medium/Low):**


**Reasoning:**


---

**Vulnerability exploited:**


**Attack description:**


**Tools an attacker would use:**


**Likelihood of successful exploitation (High/Medium/Low):**


**Reasoning:**


---

**Vulnerability exploited:**


**Attack description:**


**Tools an attacker would use:**


**Likelihood of successful exploitation (High/Medium/Low):**


**Reasoning:**


---

### Question 6c: Certificate Requirements (5 points)

**Instructions:** Specify the requirements for a secure replacement certificate that meets current industry best practices (as of 2026).

**Your Answer:**

See my answer under Question 6a

#### Minimum Key Size:


**Justification (cite NIST/industry standards):**


---

#### Acceptable Signature Algorithms:


**Why these algorithms (cite standards):**


---

#### Validity Period Best Practices:


**Reasoning:**


---

#### Proper CA/Trust Chain Configuration:


**Explanation:**


---

#### Additional Security Considerations:


---

## Resources You Should Reference

**Required Reading for this Question:**
- Complete 48 Week Security Engineering Curriculum, Week 6, pp. 21-22 (TLS Protocol Deep Dive, Certificate Validation)
- Microservices Security in Action, Chapter 6, pp. 138-156 (Building trust with certificate authorities, mTLS)
- Full Stack Python Security, Chapter 6, pp. 64-72 (TLS handshake, cipher suite negotiation)
- API Security in Action, Chapter 11, pp. 396-399 (Mutual TLS authentication, CertificateVerify messages)

**Industry Standards:**
- NIST SP 800-57 Part 1 (Key Management Recommendations)
- RFC 5280 (X.509 Certificate and CRL Profile)
- CA/Browser Forum Baseline Requirements

---

## Expected Knowledge for this Question

By Week 6 of your curriculum, you should understand:

1. **TLS Certificate Structure** (Week 2 + Week 6):
   - Certificate fields (Issuer, Subject, Validity, Extensions)
   - X.509 v3 format
   - Certificate chain validation

2. **Deprecated Cryptographic Algorithms** (Week 5 + Week 6):
   - Why MD5 is broken (collision attacks since 2004)
   - Why SHA-1 is deprecated (collision attacks since 2017)
   - Current secure algorithms (SHA-256, SHA-384, SHA-512)

3. **RSA Key Sizes** (Week 5 + Week 6):
   - NIST minimum requirements (2048-bit as of 2023)
   - Security equivalence (2048-bit RSA ≈ 112-bit symmetric security)
   - Quantum-resistant considerations (3072-bit or higher)

4. **Certificate Validation Process** (Week 6):
   - Expiration date checking (NotBefore, NotAfter)
   - CA chain verification
   - Domain name validation (CN or SAN fields)
   - Revocation status checking (OCSP, CRL)
   - Cryptographic signature verification

5. **Self-signed vs CA-signed Certificates** (Week 2 + Week 6):
   - Trust establishment mechanisms
   - Certificate pinning use cases
   - Risks of self-signed certificates

6. **Certificate Extensions** (Week 6):
   - Basic Constraints (CA:TRUE vs CA:FALSE)
   - Key Usage
   - Extended Key Usage
   - Subject Alternative Names (SANs)

---

## Grading Rubric

### Question 6a: Certificate Problems (10 points)
- **10 points:** Identified all major issues with complete explanations
- **8-9 points:** Identified most issues with good explanations
- **6-7 points:** Identified several issues with adequate explanations
- **4-5 points:** Identified some issues with basic explanations
- **0-3 points:** Identified few issues or incomplete explanations

### Question 6b: Attack Scenarios (5 points)
- **5 points:** 3+ specific attack scenarios with tools and accurate likelihood assessments
- **4 points:** 2 attack scenarios with good detail
- **3 points:** 2 attack scenarios with basic detail
- **2 points:** 1 attack scenario with good detail
- **0-1 points:** Vague or incorrect attack descriptions

### Question 6c: Certificate Requirements (5 points)
- **5 points:** All requirements specified with proper justifications and citations
- **4 points:** Most requirements with good justifications
- **3 points:** Basic requirements specified
- **2 points:** Minimal requirements specified
- **0-1 points:** Incomplete or incorrect requirements

---

## Tips for Success

1. **Be Specific:** Don't just say "weak encryption" - specify exactly which algorithm/key size is problematic
2. **Cite Standards:** Reference NIST, RFC, or industry standards when stating requirements
3. **Think Like an Attacker:** For attack scenarios, consider realistic tools (hashcat, msf, openssl)
4. **Consider Current Date:** This test is being taken in January 2026 - what was acceptable in 2023 may not be now
5. **Comprehensive Analysis:** Certificate security involves multiple layers - algorithm strength, key size, validity, trust chain, and extensions

---

## Submission Instructions

1. Complete all three parts (6a, 6b, 6c)
2. Save this file as: `spacex_q6_tanveer_salim_completed.md`
3. Re-upload to Claude for grading
4. Include your total time spent in the header

**Good luck!** 🚀🔒
