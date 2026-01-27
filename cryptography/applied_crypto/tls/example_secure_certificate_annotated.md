# Example: Properly Configured TLS Certificate (2026)

**Source:** This is based on real certificate structure from Google.com, GitHub.com, and other major sites.

---

## The Secure Certificate

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8:f9
        Signature Algorithm: sha256WithRSAEncryption  ✅ SECURE
            │
            └──> SHA-256 is collision-resistant
                 Widely supported, browsers accept it
                 No known practical attacks
                 
        Issuer: C = US, O = DigiCert Inc, CN = DigiCert TLS RSA SHA256 2020 CA1
            │
            └──> Real, trusted Certificate Authority
                 In Mozilla/Chrome/Apple/Microsoft trust stores
                 Not self-signed (different from Subject)
                 
        Validity
            Not Before: Dec  1 00:00:00 2025 GMT  ✅ Valid start date
            Not After : Feb  28 23:59:59 2026 GMT  ✅ 90-day validity
                │
                └──> 90 days = best practice for automated rotation
                     Limits damage if private key compromised
                     Forces regular certificate updates
                     
        Subject: C = US, ST = California, L = San Francisco, 
                 O = Example Corp, CN = payment-api.fintech.com
            │
            └──> CN matches one of the hostnames we'll serve
                 Includes full organization details
                 Located in same country as business
                 
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (3072 bit)  ✅ STRONG KEY SIZE
                    │
                    └──> RSA-3072 = 128-bit security strength
                         Quantum-resistant until large-scale quantum computers
                         Exceeds NIST recommendations through 2030+
                         
                Modulus:
                    00:c8:9b:e4:5f:ca:7d:6e:92:b3:d4:f5:a6:c7:e8:
                    09:1a:2b:3c:4d:5e:6f:71:82:93:a4:b5:c6:d7:e8:
                    f9:0a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:
                    e8:f9:1a:2b:3c:4d:5e:6f:80:91:a2:b3:c4:d5:e6:
                    f7:08:19:2a:3b:4c:5d:6e:7f:81:92:a3:b4:c5:d6:
                    e7:f8:09:1a:2b:3c:4d:5e:6f:80:91:a2:b3:c4:d5:
                    e6:f7:18:29:3a:4b:5c:6d:7e:8f:90:a1:b2:c3:d4:
                    e5:f6:07:18:29:3a:4b:5c:6d:7e:8f:90:a1:b2:c3:
                    d4:e5:f6:17:28:39:4a:5b:6c:7d:8e:9f:a0:b1:c2:
                    d3:e4:f5:06:17:28:39:4a:5b:6c:7d:8e:9f:a0:b1:
                    c2:d3:e4:f5:16:27:38:49:5a:6b:7c:8d:9e:af:b0:
                    c1:d2:e3:f4:05:16:27:38:49:5a:6b:7c:8d:9e:af:
                    b0:c1:d2:e3:f4:15:26:37:48:59:6a:7b:8c:9d:ae:
                    bf:c0:d1:e2:f3:04:15:26:37:48:59:6a:7b:8c:9d:
                    ae:bf:c0:d1:e2:f3:14:25:36:47:58:69:7a:8b:9c:
                    ad:be:cf:d0:e1:f2:03:14:25:36:47:58:69:7a:8b:
                    9c:ad:be:cf:d0:e1:f2:13:24:35:46:57:68:79:8a:
                    9b:ac:bd:ce:df:e0:f1:02:13:24:35:46:57:68:79:
                    8a:9b:ac:bd:ce:df:e0:f1:12:23:34:45:56:67:78:
                    89:9a:ab:bc:cd:de:ef:f0:01:12:23:34:45:56:67:
                    78:89:9a:ab:bc:cd:de:ef:f0:11:22:33:44:55:66:
                    77:88:99:aa:bb:cc:dd:ee:ff
                Exponent: 65537 (0x10001)  ✅ STANDARD EXPONENT
                    │
                    └──> 65537 is the standard RSA public exponent
                         Widely used, secure, efficient
                         
        X509v3 extensions:
            X509v3 Subject Key Identifier:  ✅ PRESENT
                A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:A1:B2:C3:D4
                │
                └──> Hash of this certificate's public key
                     Used to identify certificate in chains
                     
            X509v3 Authority Key Identifier:  ✅ PRESENT
                keyid:8D:8C:5E:C4:54:AD:8A:E1:77:E9:9B:F9:9B:05:E1:B8:01:8D:61:E1
                │
                └──> Hash of the CA's public key that signed this cert
                     DIFFERENT from Subject Key Identifier
                     Proves this is NOT self-signed
                     
            X509v3 Subject Alternative Names:  ✅ CRITICAL EXTENSION
                DNS:payment-api.fintech.com
                DNS:api.fintech.com
                DNS:www.fintech.com
                DNS:fintech.com
                │
                └──> ALL hostnames this certificate will serve
                     Modern browsers ONLY check SANs (ignore CN)
                     Multiple SANs = certificate works on multiple domains
                     MUST include the actual hostname being served
                     
            X509v3 Key Usage: critical  ✅ MARKED CRITICAL
                Digital Signature, Key Encipherment
                │
                └──> "critical" = browsers MUST check this extension
                     "Digital Signature" = can sign data
                     "Key Encipherment" = can encrypt session keys
                     Does NOT include "Certificate Sign" (not a CA)
                     
            X509v3 Extended Key Usage:  ✅ RESTRICTS PURPOSE
                TLS Web Server Authentication
                │
                └──> Explicitly states: "This cert is for TLS servers"
                     Cannot be misused for code signing, email, etc.
                     id-kp-serverAuth OID: 1.3.6.1.5.5.7.3.1
                     
            X509v3 CRL Distribution Points:  ✅ REVOCATION SUPPORT
                URI:http://crl3.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl
                URI:http://crl4.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl
                │
                └──> Two CRL endpoints for redundancy
                     Clients can check if certificate was revoked
                     HTTP URIs (not HTTPS to avoid circular dependency)
                     
            Authority Information Access:  ✅ OCSP + CA ISSUER
                OCSP - URI:http://ocsp.digicert.com
                CA Issuers - URI:http://cacerts.digicert.com/DigiCertTLSRSASHA2562020CA1-1.crt
                │
                └──> OCSP = real-time revocation checking (fast)
                     CA Issuers = where to download intermediate cert
                     Both are HTTP (not HTTPS) to avoid circular dependency
                     
            X509v3 Basic Constraints: critical  ✅ CORRECT VALUE
                CA:FALSE
                │
                └──> This is an end-entity certificate (for servers)
                     NOT a Certificate Authority certificate
                     Cannot sign other certificates
                     Marked "critical" so browsers MUST enforce this
                     
            X509v3 Certificate Policies:  ✅ POLICY INFO
                Policy: 2.23.140.1.2.2
                  CPS: https://www.digicert.com/CPS
                │
                └──> OID 2.23.140.1.2.2 = Domain Validated (DV) certificate
                     Links to Certificate Practice Statement
                     Defines validation level and warranty
                     
            CT Precertificate SCTs:  ✅ CERTIFICATE TRANSPARENCY
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : E8:3E:D0:DA:3E:F5:06:35:32:E7:57:28:BC:89:6B:C9:03:...
                    Timestamp : Dec  1 12:34:56.789 2025 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:45:02:21:00:A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:...
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 29:79:BE:F0:9E:39:39:21:F0:56:73:9F:63:A5:77:E5:BE:...
                    Timestamp : Dec  1 12:35:02.456 2025 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:44:02:20:B1:C2:D3:E4:F5:06:17:28:39:4A:5B:6C:...
                │
                └──> TWO independent CT logs for redundancy
                     Provides public audit trail of certificate issuance
                     Required by Chrome since 2018
                     Helps detect mis-issued or fraudulent certificates
                     
    Signature Algorithm: sha256WithRSAEncryption  ✅ MATCHES DATA SECTION
    Signature Value:
        9a:0b:1c:2d:3e:4f:50:61:72:83:94:a5:b6:c7:d8:e9:fa:0b:
        1c:2d:3e:4f:50:61:72:83:94:a5:b6:c7:d8:e9:fa:1c:2d:3e:
        4f:60:71:82:93:a4:b5:c6:d7:e8:f9:0a:1b:2c:3d:4e:5f:60:
        71:82:93:a4:b5:c6:d7:e8:f9:1a:2b:3c:4d:5e:6f:70:81:92:
        a3:b4:c5:d6:e7:f8:09:1a:2b:3c:4d:5e:6f:80:91:a2:b3:c4:
        d5:e6:f7:18:29:3a:4b:5c:6d:7e:8f:90:a1:b2:c3:d4:e5:f6:
        07:18:29:3a:4b:5c:6d:7e:8f:90:a1:b2:c3:d4:e5:f6:17:28:
        39:4a:5b:6c:7d:8e:9f:a0:b1:c2:d3:e4:f5:06:17:28:39:4a:
        5b:6c:7d:8e:9f:a0:b1:c2:d3:e4:f5:16:27:38:49:5a:6b:7c:
        8d:9e:af:b0:c1:d2:e3:f4:05:16:27:38:49:5a:6b:7c:8d:9e:
        af:b0:c1:d2:e3:f4:15:26:37:48:59:6a:7b:8c:9d:ae:bf:c0:
        d1:e2:f3:04:15:26:37:48:59:6a:7b:8c:9d:ae:bf:c0:d1:e2:
        f3:14:25:36:47:58:69:7a:8b:9c:ad:be:cf:d0:e1:f2:03:14:
        25:36:47:58:69:7a:8b:9c:ad:be:cf:d0:e1:f2:13:24:35:46:
        57:68:79:8a:9b:ac:bd:ce:df:e0:f1:02:13:24:35:46:57:68:
        79:8a:9b:ac:bd:ce:df:e0:f1:12:23:34:45:56:67:78:89:9a:
        ab:bc:cd:de:ef:f0:01:12:23:34:45:56:67:78:89:9a:ab:bc:
        cd:de:ef:f0
        │
        └──> SHA-256 hash of all certificate data, signed by CA's private key
             Browsers verify this signature using CA's public key
             Proves certificate was issued by trusted CA
             Proves certificate data hasn't been tampered with
```

---

## Complete Certificate Chain

A properly deployed certificate includes the **full chain**:

```
Certificate Chain:
├── End-Entity Certificate  ← The certificate above
│   Subject: CN = payment-api.fintech.com
│   Issuer: CN = DigiCert TLS RSA SHA256 2020 CA1
│   ↓
├── Intermediate CA Certificate  ✅ MUST BE INCLUDED
│   Subject: CN = DigiCert TLS RSA SHA256 2020 CA1
│   Issuer: CN = DigiCert Global Root CA
│   │
│   └──> Server must send this in TLS handshake
│        Clients need it to build trust chain
│        Links end-entity cert to trusted root
│   ↓
└── Root CA Certificate  ✅ ALREADY IN BROWSER
    Subject: CN = DigiCert Global Root CA
    Issuer: CN = DigiCert Global Root CA (self-signed root)
    │
    └──> Pre-installed in browser/OS trust store
         Self-signed (Issuer = Subject)
         CA:TRUE (this is a root CA)
         Trusted by all major browsers
```

---

## How Browsers Validate This Certificate

**Step-by-step validation process:**

```
1. ✅ Check Expiration Dates
   Not Before: Dec 1, 2025
   Not After: Feb 28, 2026
   Today: Jan 23, 2026
   → VALID (within validity window)

2. ✅ Verify Domain Name
   Hostname: payment-api.fintech.com
   SANs: DNS:payment-api.fintech.com, DNS:api.fintech.com, ...
   → MATCH FOUND in SANs

3. ✅ Build Certificate Chain
   End-Entity → Intermediate CA → Root CA
   Root CA: "DigiCert Global Root CA" found in trust store
   → CHAIN VALID

4. ✅ Verify Signatures
   End-Entity signed by Intermediate CA (verify with CA's public key)
   Intermediate CA signed by Root CA (verify with Root's public key)
   → ALL SIGNATURES VALID

5. ✅ Check Revocation Status (OCSP)
   Query: http://ocsp.digicert.com
   Response: "Good" (not revoked)
   → CERTIFICATE NOT REVOKED

6. ✅ Verify Certificate Transparency
   Check embedded SCTs
   Found 2 SCTs from independent logs
   → CT REQUIREMENT MET

7. ✅ Check Extensions
   Basic Constraints: CA:FALSE ✓ (correct for end-entity)
   Key Usage: Digital Signature, Key Encipherment ✓
   Extended Key Usage: TLS Web Server Authentication ✓
   → ALL EXTENSIONS VALID

RESULT: ✅ CERTIFICATE ACCEPTED - HTTPS connection established
```

---

## Side-by-Side Comparison

### ❌ Bad Certificate (Your Challenge)

```
Signature Algorithm: sha1WithRSAEncryption  ❌ BROKEN
Issuer: CN = TrustedCA Inc  ❌ FICTIONAL CA
Not After: Jan 15, 2027  ⚠️ 365 days (acceptable but not optimal)
Subject: CN = api.fintech.com  ❌ WRONG HOSTNAME
Public-Key: (2048 bit)  ⚠️ Minimal, not future-proof
Subject Alternative Names: DNS:api.fintech.com  ❌ DOESN'T MATCH SERVER
X509v3 Key Usage: (missing)  ❌ NOT PRESENT
X509v3 Extended Key Usage: (missing)  ❌ NOT PRESENT
CRL Distribution Points: (missing)  ❌ NO REVOCATION
Authority Information Access: (missing)  ❌ NO OCSP
CT Precertificate SCTs: (missing)  ❌ CHROME WILL REJECT
Basic Constraints: CA:FALSE  ✅ CORRECT (only thing right!)
```

**Server hostname:** payment-api.fintech.com  
**Certificate CN/SAN:** api.fintech.com  
**Result:** ❌ **BROWSER REJECTS - NET::ERR_CERT_COMMON_NAME_INVALID**

---

### ✅ Good Certificate (Example Above)

```
Signature Algorithm: sha256WithRSAEncryption  ✅ SECURE
Issuer: CN = DigiCert TLS RSA SHA256 2020 CA1  ✅ REAL, TRUSTED CA
Not After: Feb 28, 2026  ✅ 90 days (best practice)
Subject: CN = payment-api.fintech.com  ✅ MATCHES SERVER
Public-Key: (3072 bit)  ✅ STRONG, FUTURE-PROOF
Subject Alternative Names:  ✅ INCLUDES ALL HOSTNAMES
  DNS:payment-api.fintech.com
  DNS:api.fintech.com
  DNS:www.fintech.com
  DNS:fintech.com
X509v3 Key Usage: Digital Signature, Key Encipherment  ✅ PRESENT
X509v3 Extended Key Usage: TLS Web Server Auth  ✅ PRESENT
CRL Distribution Points: http://crl3.digicert.com/...  ✅ REDUNDANT URLs
Authority Information Access:
  OCSP: http://ocsp.digicert.com  ✅ REAL-TIME REVOCATION
  CA Issuers: http://cacerts.digicert.com/...  ✅ CHAIN AVAILABLE
CT Precertificate SCTs: (2 logs)  ✅ CHROME COMPLIANT
Basic Constraints: CA:FALSE  ✅ CORRECT
```

**Server hostname:** payment-api.fintech.com  
**Certificate CN/SAN:** payment-api.fintech.com (+ 3 others)  
**Result:** ✅ **BROWSER ACCEPTS - HTTPS WORKS**

---

## What You Should Notice

### 1. **Proper Domain Coverage**
```
❌ Bad:  SAN: DNS:api.fintech.com
         Server: payment-api.fintech.com
         → MISMATCH!

✅ Good: SANs: DNS:payment-api.fintech.com
              DNS:api.fintech.com
              DNS:www.fintech.com
              DNS:fintech.com
         Server: payment-api.fintech.com
         → MATCH!
```

### 2. **All Required Extensions Present**
```
❌ Bad:  Key Usage: (missing)
         Extended Key Usage: (missing)
         OCSP: (missing)
         CRL: (missing)
         CT: (missing)

✅ Good: Key Usage: ✓
         Extended Key Usage: ✓
         OCSP: ✓
         CRL: ✓
         CT: ✓
```

### 3. **Strong Cryptography**
```
❌ Bad:  sha1WithRSAEncryption + RSA-2048

✅ Good: sha256WithRSAEncryption + RSA-3072
```

### 4. **Verifiable Trust Chain**
```
❌ Bad:  Issuer: "TrustedCA Inc" (fictional, not in trust stores)

✅ Good: Issuer: "DigiCert TLS RSA SHA256 2020 CA1"
         → Chains to "DigiCert Global Root CA"
         → In all browser trust stores
```

---

## How to Inspect Real Certificates Yourself

### Check Google's Certificate:
```bash
echo | openssl s_client -connect google.com:443 -showcerts 2>/dev/null | openssl x509 -text -noout
```

### Check GitHub's Certificate:
```bash
echo | openssl s_client -connect github.com:443 -showcerts 2>/dev/null | openssl x509 -text -noout
```

### What to Look For:
```
✅ Signature Algorithm: sha256WithRSAEncryption (or sha384/sha512)
✅ Issuer: Real CA name (DigiCert, Let's Encrypt, Sectigo, etc.)
✅ Validity: 90 days (Let's Encrypt) or up to 398 days (commercial CAs)
✅ Subject Alternative Names: Multiple DNS entries
✅ Key Usage: Present and marked critical
✅ Extended Key Usage: TLS Web Server Authentication
✅ Authority Information Access: OCSP URL present
✅ CRL Distribution Points: Present
✅ CT Precertificate SCTs: 2+ logs
✅ Basic Constraints: CA:FALSE
```

---

## Checklist for Evaluating ANY Certificate

Use this every time you review a certificate:

```
□ Signature Algorithm
  ✅ SHA-256 or stronger (SHA-384, SHA-512)
  ❌ SHA-1, MD5

□ Public Key
  ✅ RSA-3072/4096 or ECDSA P-256/P-384
  ⚠️ RSA-2048 (acceptable but minimal)
  ❌ RSA-1024 or smaller

□ Validity Period
  ✅ ≤ 90 days (best practice)
  ⚠️ 91-398 days (acceptable)
  ❌ > 398 days (violates CA/Browser Forum rules)
  ❌ Expired (check current date)

□ Issuer
  ✅ Real CA in trust stores
  ❌ Self-signed (Issuer = Subject)
  ❌ Unknown/fictional CA

□ Subject / SANs
  ✅ All hostnames in SANs match where it's deployed
  ❌ Hostname mismatch

□ Key Usage (REQUIRED)
  ✅ Present with: Digital Signature, Key Encipherment
  ❌ Missing

□ Extended Key Usage (REQUIRED)
  ✅ Present with: TLS Web Server Authentication
  ❌ Missing

□ OCSP (REQUIRED)
  ✅ OCSP URL in Authority Information Access
  ❌ Missing

□ CRL (REQUIRED)
  ✅ CRL Distribution Points present
  ❌ Missing

□ Certificate Transparency (REQUIRED)
  ✅ 2+ SCTs embedded
  ❌ Missing (Chrome will reject)

□ Basic Constraints
  ✅ CA:FALSE (for end-entity certificates)
  ❌ CA:TRUE (security violation for end-entity)
```

---

## Summary: What Makes a Certificate Secure

**Cryptographic Security:**
- SHA-256+ signature algorithm
- RSA-3072+ or ECDSA P-256+ public key
- Signed by trusted CA (not self-signed)

**Operational Security:**
- Valid dates (not expired)
- Short validity (90 days ideal)
- Correct hostnames in SANs
- Complete certificate chain provided

**Revocation Infrastructure:**
- OCSP responder URL
- CRL distribution points
- Both HTTP (not HTTPS) to avoid circular dependency

**Modern Requirements:**
- Certificate Transparency (2+ SCTs)
- Proper Key Usage and Extended Key Usage
- CA:FALSE for end-entity certificates

**This is what you should compare your challenge certificates against!**

---

**References:**
- RFC 5280 (X.509 Certificate Profile)
- CA/Browser Forum Baseline Requirements v1.8.0
- NIST SP 800-57 Part 1 Rev. 5
- Chrome Certificate Transparency Policy
- Let's Encrypt Best Practices
- DigiCert Certificate Documentation

---

**Now go back and re-analyze your challenge certificate!** Compare each field against this example. You'll immediately see what's wrong.
