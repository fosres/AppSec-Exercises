---
title: "Challenge: Build a TLS Certificate Security Validator (AppSec Exercise)"
published: false
description: "Master the 20-point security checklist browsers use to validate every HTTPS certificate - then build your own validator!"
tags: appsec, security, python, tls
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/placeholder.jpg
---

# Challenge: Build a TLS Certificate Security Validator

> **⚠️ Real Interview Scenario:** TLS certificate validation is a common Security Engineering interview question. You'll be given a certificate in TEXT format and asked to identify what's wrong with it. This exercise prepares you for exactly that scenario.

## 🎯 For Security Engineers: Why This Exercise Matters

**You need to understand WHAT makes a TLS certificate valid and WHY - not just IF it's valid.**

Off-the-shelf tools like sslyze, testssl.sh, and OpenSSL will give you a simple answer:
```bash
$ sslyze google.com:443
✓ Certificate is valid
```

**But they won't teach you:**
- **WHY** SHA-1 signatures are catastrophically broken (Google SHAttered attack, 2017)
- **WHY** CA:TRUE on an end-entity certificate enables complete PKI compromise (DigiNotar breach, 2011)
- **WHY** browsers ignore the Common Name field (RFC 6125 deprecation)
- **WHY** the 398-day validity limit exists (CA/Browser Forum Ballot SC22)
- **HOW** wildcard matching actually works (`*.example.com` rules)
- **HOW** to detect self-signed certificates (SKI/AKI comparison logic)
- **WHY** Key Usage flags matter (Digital Signature vs Key Encipherment vs Certificate Sign)

**This exercise forces you to implement the validation logic yourself.**

By the end, you won't just run security scanners - you'll understand X.509 certificate structure at a fundamental level. This understanding separates those who run tools from those who understand PKI fundamentals.

---

### What Do Off-the-Shelf Tools Actually Tell You?

Here's what happens when you check an expired certificate with popular tools:

**OpenSSL verify:**
```bash
$ openssl verify expired_cert.pem
error 10 at 0 depth lookup: certificate has expired
```
- ❌ Cryptic error code ("error 10")
- ❌ Doesn't show which date field or the actual dates
- ❌ No explanation of why it matters

**sslyze:**
```bash
$ sslyze --regular expired.com:443
 * Certificate Validation:
     Hostname Validation:     FAILED - Certificate does NOT match
     Path Validation:         OK - Certificate is trusted
```
- ❌ Says it failed but doesn't show the SANs field
- ❌ Doesn't explain wildcard matching rules
- ❌ Black box: "It failed" (but not WHERE or WHY)

**testssl.sh:**
```bash
$ testssl.sh https://expired.com
 Certificate Validity   expires in -30 days (2024-11-15 --> 2024-12-15) WARN
```
- ❌ Shows dates but doesn't explain Not Before vs Not After
- ❌ No explanation of the underlying X.509 structure

**Your Validator (What You'll Build):**
```bash
$ python validator.py test_006_expired.pem www.example.com

❌ FAIL - Certificate invalid (1/20 checks passed)

FAILED CHECKS:
  ❌ Check 2: Certificate expired
     Not After:  2024-12-15 23:59:59 UTC
     Current:    2026-01-24 19:30:00 UTC
     Expired by: 40 days
     
     Why this matters: Expired certificates cannot be trusted.
     The private key may have been compromised after expiration.
     Browsers reject these to prevent MITM attacks.
     
     Real-world example: Microsoft Teams outage (2020)
     
PASSED CHECKS:
  ✅ Check 1: Version 3 ✓
```
- ✅ Shows EXACTLY which check failed and why
- ✅ Shows the actual certificate field values
- ✅ Explains the security reasoning
- ✅ Provides real-world context
- ✅ **You understand the X.509 structure because YOU parsed it**

This is the difference between using a calculator and understanding mathematics.

---

**Time:** 60-90 minutes  
**Difficulty:** Advanced  
**Skills:** PKI/TLS, X.509 Certificates, Cryptography, Application Security

---

## The Challenge

Every time you visit `https://google.com`, your browser performs **20 critical security checks** on the TLS certificate in **milliseconds**. One failed check = connection rejected.

**Your mission:** Build the certificate validator that browsers use! Master the 20-point checklist, then implement it in Python.

### 📦 Get the Complete Exercise

**Exercise Files:** https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/tls

**What's included:**
- 📁 **test_certs_text/** - 68 test certificates (valid and invalid)
- 🤖 **grader.py** - Automated grader (instant feedback)
- ✅ **tls_cert_validator.py** - Reference solution
- 📖 **README.md** - Setup instructions

**Main Repository:** https://github.com/fosres/SecEng-Exercises (⭐ star for more exercises!)

**⭐ Star the repo to get notified of new security exercises!**

---

## Why This Matters in Real Life

### When Certificate Validation Fails

**Microsoft Teams Outage (2020)**
- Expired certificate took down Microsoft Teams globally
- Millions affected during COVID-19 remote work
- Duration: Several hours
- **Root cause:** Check #2 failed - certificate expiration not monitored

**Equifax Breach (2017)**
- Expired cert on security tool = blind security team
- 147 million people's data stolen
- Breach undetected for **months**
- **Root cause:** Check #2 failed - expired certificate on critical security infrastructure

**LinkedIn Outage (2016)**
- Expired TLS certificate caused global outage
- Millions unable to access service
- **Root cause:** Check #2 failed - automated renewal failed, no validation in place

---

## 🔐 THE 20-POINT VALIDATION CHECKLIST

**This is THE complete checklist browsers use for EVERY HTTPS connection.**

### Quick Reference: Required vs Recommended vs Optional

**⚠️ UPDATED JANUARY 2026** - Reflects CA/Browser Forum Ballot SC63 (March 2024) and strict RFC 5280 compliance

| # | Check | Status | Notes |
|---|-------|--------|-------|
| **Phase 1: Fundamental Validity** |
| 1 | Version 3 | ✅ REQUIRED | V1/V2 don't support extensions |
| 2 | Not expired/not yet valid | ✅ REQUIRED | Current date within validity period |
| 3 | SHA-256+ signature | ✅ REQUIRED | No MD5, no SHA-1 (both broken) |
| 4 | Strong key size | ✅ REQUIRED | RSA ≥2048, ECDSA ≥P-256 |
| **Phase 2: Identity Validation** |
| 5 | Subject DN present | ⚠️ MINIMAL OK | Can be empty if SANs present (RFC 5280) |
| 6 | SANs extension present | ✅ REQUIRED | Required by CA/Browser Forum |
| 7 | Hostname matches SAN | ✅ REQUIRED | Exact or wildcard match |
| **Phase 3: Access Control** |
| 8 | Basic Constraints CA:FALSE | ✅ REQUIRED | Must be critical |
| 9 | Key Usage flags | ⚠️ OPTIONAL | CA/B Forum: "if present" (99%+ have it) |
| 10 | Extended Key Usage | ✅ REQUIRED | Must include SERVER_AUTH |
| **Phase 4: Revocation** |
| 11 | CRL Distribution Points | ✅ REQUIRED | **SC63 (Mar 2024): Was RECOMMENDED** |
| 12 | Authority Info Access | ✅ REQUIRED | Required by CA/Browser Forum |
| 13 | OCSP URL | ⚠️ OPTIONAL | **SC63 (Mar 2024): Was REQUIRED** |
| 14 | Certificate Transparency | ✅ REQUIRED | 2+ SCTs (Chrome, Safari, Firefox) |
| **Phase 5: Chain Validation** |
| 15 | Not self-signed | ✅ REQUIRED | Issuer ≠ Subject |
| 16 | Valid serial number | ✅ REQUIRED | Unique, ≥64 bits entropy |
| 17 | SKI present | ⚠️ RECOMMENDED | **RFC 5280: Not required for end-entity** |
| 18 | AKI present | ✅ REQUIRED | Authority Key Identifier |
| 19 | SKI ≠ AKI | ⚠️ CONDITIONAL | **Only if both present** |
| **Phase 6: Operational** |
| 20 | Validity ≤ 398 days | ✅ REQUIRED | CA/Browser Forum Ballot SC22 |

**Final Count:**
- ✅ **REQUIRED:** 15 checks (must pass for public certificates)
- ⚠️ **OPTIONAL:** 2 checks (best practice, near-universal)
- ⚠️ **RECOMMENDED:** 2 checks (not required but 99%+ have them)
- ⚠️ **CONDITIONAL:** 1 check (depends on other fields)

**Key Changes in 2024:**
- **Ballot SC63 (March 15, 2024):** CRL now REQUIRED, OCSP now OPTIONAL (privacy concerns)
- **RFC 5280 Compliance:** Key Usage and SKI technically optional for end-entity certificates

**Exception:** Short-lived certificates (≤7 days) do not require CRL or OCSP support.

---

**Detailed explanations below** - each check explained with examples and code:

Every check is explained in plain English with:
- ✅ What you'll see in a good certificate
- 📖 Plain English explanation (all acronyms explained!)
- ⚠️ Why it matters (real attack scenarios)
- ❌ What happens if it fails (browser errors)

---

### 🔹 PHASE 1: FUNDAMENTAL VALIDITY

Stop immediately if any of these fail!

---

#### ✅ CHECK 1: Certificate Version

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
Version: 3 (0x2)
```

**Plain English explanation:**
X.509 certificates come in 3 versions:
- Version 1 (0x0) - Ancient, from 1988, no extensions
- Version 2 (0x1) - Rarely used
- **Version 3 (0x2)** - Modern standard, supports extensions ✅

**Why this matters:**
Only Version 3 supports the security extensions we need:
- Subject Alternative Names (SANs) - for hostnames
- Key Usage - what the key can do
- Extended Key Usage - what the certificate is for
- OCSP/CRL - revocation checking
- Certificate Transparency - public audit trail

**Source:** RFC 5280 Section 4.1.2.1 - "When extensions are used, as expected in this profile, version MUST be 3"

**What happens if it fails:**
Certificate cannot have modern security features → Reject immediately

---

#### ✅ CHECK 2: Certificate Expiration (Not Expired / Not Yet Valid)

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
Validity
    Not Before: Dec  1 00:00:00 2025 GMT
    Not After : Feb 28 23:59:59 2026 GMT
```

**Plain English explanation:**
Every certificate has two dates:
- **Not Before** = Certificate becomes valid at this date/time
- **Not After** = Certificate expires at this date/time

The current date/time MUST be between these two dates.

**Why this matters:**
- **Expired certificates** can't be trusted (keys might be compromised)
- **Not-yet-valid certificates** might be test/staging certs leaked early

**Real-world example:**
```
Certificate expired on: Jan 1, 2026
Today's date: Jan 25, 2026
→ ❌ EXPIRED! Don't trust!
```

**What happens if it fails:**
Browser shows: "NET::ERR_CERT_DATE_INVALID" - Connection blocked

---

#### ✅ CHECK 3: Signature Algorithm (SHA-256 or Better)

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
Signature Algorithm: sha256WithRSAEncryption
```
OR
```
Signature Algorithm: ecdsa-with-SHA256
```

**Plain English explanation:**
The signature proves the CA really issued this certificate. The hash algorithm must be strong.

This check validates the **hash algorithm** (SHA-256, SHA-384, SHA-512), NOT the signature algorithm (RSA vs ECDSA).

**✅ Allowed hash algorithms:**
- SHA-256 (most common)
- SHA-384
- SHA-512

**✅ Allowed signature algorithms (with approved hash):**
- **RSA variants:** `sha256WithRSAEncryption`, `sha384WithRSAEncryption`, `sha512WithRSAEncryption`
- **ECDSA variants:** `ecdsa-with-SHA256`, `ecdsa-with-SHA384`, `ecdsa-with-SHA512`

**❌ Forbidden:**
- **Weak hash algorithms:**
  - MD5 (broken 2004): `md5WithRSAEncryption`
  - SHA-1 (broken 2017): `sha1WithRSAEncryption`, `ecdsa-with-SHA1`
- **Outdated signature algorithms:**
  - DSA (deprecated by NIST 2019): `dsa-with-SHA256`, `dsa-with-SHA1`
  - Note: DSA deprecated even with strong hash algorithms

**Implementation hint:**
```
Focus on the HASH algorithm, not the signature type:
- "sha256WithRSAEncryption" → SHA-256 ✅
- "ecdsa-with-SHA256" → SHA-256 ✅
- "sha1WithRSAEncryption" → SHA-1 ❌
- "ecdsa-with-SHA1" → SHA-1 ❌
```

**Why this matters - Collision attacks:**
```
MD5 collision (2008):
1. Attacker creates GOOD cert request
2. Also creates EVIL cert with same MD5 hash
3. CA signs GOOD cert
4. Attacker swaps in EVIL cert (same signature!)
5. Browser trusts EVIL cert ❌
```

**Real-world example:**
- Flame malware (2012): Used MD5 collision to forge Microsoft certificate
- SHAttered (2017): Demonstrated practical SHA-1 collision

**Source:** CA/Browser Forum Baseline Requirements - "CAs MUST NOT issue certificates using MD5 or SHA-1" (since January 2016)

**What happens if it fails:**
Browser shows: "NET::ERR_CERT_WEAK_SIGNATURE_ALGORITHM"

---

#### ✅ CHECK 4: Public Key Strength

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
Public Key Algorithm: rsaEncryption
    Public-Key: (2048 bit)
```
OR
```
Public Key Algorithm: id-ecPublicKey
    Public-Key: (256 bit)
    ASN1 OID: prime256v1
    NIST CURVE: P-256
```

**Plain English explanation:**
The public key must be strong enough to resist brute-force attacks.

**✅ Minimum requirements:**
- RSA: ≥2048 bits (3072 or 4096 recommended)
- ECDSA: ≥P-256 (P-384 or P-521 recommended)

**❌ Forbidden:**
- RSA-1024 (crackable with $1M+ budget)
- RSA-512 (crackable in hours)

**Why this matters:**
```
RSA-1024 security level:
- 1999: "Safe for 20+ years"
- 2010: Factored by academics
- 2015: NSA likely can crack
- 2025: Definitely broken ❌
```

**Source:** CA/Browser Forum Baseline Requirements - "Recommended key strengths are at least 2048-bit RSA or Elliptic Curve using NIST P-256"

**What happens if it fails:**
Browser shows: "NET::ERR_CERT_WEAK_KEY"

---

### 🔹 PHASE 2: IDENTITY VALIDATION

#### ⚠️ CHECK 5: Subject Distinguished Name (DN)

**Status:** ⚠️ MINIMAL OK (Can be empty if SANs is critical)

**What you'll see in a good certificate:**
```
Subject: C=US, ST=California, O=Example Inc, CN=www.example.com
```

**Plain English explanation:**
Subject DN = Who owns this certificate

**RFC 5280 Rules:**

**Case 1: Subject DN present (99% of certificates)**
```
Subject: C=US, ST=California, O=Example Inc, CN=www.example.com

X509v3 Subject Alternative Name:
    DNS:www.example.com, DNS:example.com
```
✅ **SANs does NOT need to be critical** (most common case)

**Case 2: Subject DN empty (rare)**
```
Subject: (empty)

X509v3 Subject Alternative Name: critical
    DNS:www.example.com, DNS:example.com
```
✅ **SANs MUST be marked critical** (notice "critical" keyword)

**How to check if SANs is critical:**
```
X509v3 Subject Alternative Name: critical  ← Has "critical" keyword
    DNS:www.example.com

vs.

X509v3 Subject Alternative Name:  ← No "critical" keyword
    DNS:www.example.com
```

**Real-world examples:**

**ssllabs.com (Subject present, SANs not critical):**
```
Subject: C=US, ST=California, O="Qualys, Inc.", CN=www.ssllabs.com
X509v3 Subject Alternative Name:
    DNS:www.ssllabs.com, DNS:ssllabs.com, ...
```
✅ VALID (Subject present, so SANs doesn't need to be critical)

**Empty Subject (SANs must be critical):**
```
Subject: (empty)
X509v3 Subject Alternative Name: critical
    DNS:example.com
```
✅ VALID (Subject empty, SANs is critical)

**Empty Subject (SANs NOT critical) - INVALID:**
```
Subject: (empty)
X509v3 Subject Alternative Name:
    DNS:example.com
```
❌ INVALID (Subject empty but SANs not marked critical)

**Why this matters:**
Older validation logic relied on Common Name (CN) in Subject DN. Modern certificates use SANs. When Subject is completely empty, SANs MUST be critical to ensure validators don't ignore it.

**Source:** RFC 5280 Section 4.1.2.6 - "If the subject field contains an empty sequence, then the issuing CA MUST include a subjectAltName extension that is marked as critical"

**What happens if it fails:**
- Both Subject DN and SANs empty → Reject
- Subject DN empty and SANs not critical → Reject

---

#### ✅ CHECK 6: Subject Alternative Names (SANs)

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
X509v3 Subject Alternative Name:
    DNS:www.example.com
    DNS:example.com
    DNS:api.example.com
```

**Plain English explanation:**
SANs = List of ALL valid hostnames for this certificate

**Why this matters:**
```
Certificate for: www.example.com
User visits: api.example.com

WITHOUT SANs listing api.example.com:
→ ❌ Hostname mismatch! Reject!

WITH SANs listing api.example.com:
→ ✅ Valid! Allow connection!
```

**Wildcards allowed:**
```
DNS:*.example.com
→ Matches: www.example.com, api.example.com
→ Does NOT match: example.com (no subdomain!)
→ Does NOT match: foo.bar.example.com (only 1 level!)
```

**Source:** CA/Browser Forum Baseline Requirements - "This extension MUST be present"

**What happens if it fails:**
Cannot validate hostname → Reject

---

#### ✅ CHECK 7: Hostname Matches SAN

**Status:** ✅ REQUIRED

**What you'll see:**
```
User visiting: www.example.com
SANs: DNS:www.example.com, DNS:example.com
→ ✅ MATCH!
```

**Plain English explanation:**
The hostname in the browser address bar MUST match one of the SANs in the certificate.

**⭐ CRITICAL: CHECK 7 USES DNS WILDCARD PATTERN MATCHING ⭐**

This check performs **DNS wildcard pattern matching** where `*` is a wildcard character. **DNS wildcards follow RFC 6125 rules, NOT shell/filesystem wildcard rules!**

**🔑 Understanding DNS Labels (The Foundation of Wildcard Matching)**

Before understanding wildcard matching, you must understand **labels**:

**What is a label?**
- A label is one "part" of a domain name separated by dots
- Think of labels as "levels" in the domain hierarchy

**Example: Breaking down `www.example.com` into labels:**
```
www.example.com
 │    │      │
 │    │      └─── Label 3: "com" (TLD/root)
 │    └────────── Label 2: "example" (base domain)
 └─────────────── Label 1: "www" (subdomain - LEFTMOST)

Total: 3 labels
```

**More examples:**
```
mail.example.com        → 3 labels: ["mail", "example", "com"]
api.example.com         → 3 labels: ["api", "example", "com"]
wrong.host.badssl.com   → 4 labels: ["wrong", "host", "badssl", "com"]
sub.domain.example.com  → 4 labels: ["sub", "domain", "example", "com"]
example.com             → 2 labels: ["example", "com"]
```

**🎯 The Core Rule of DNS Wildcard Matching:**

**The wildcard `*` replaces EXACTLY ONE label - no more, no less!**

This is fundamentally different from shell wildcards which can match multiple levels.

**⭐ CRITICAL DNS Wildcard Rules (RFC 6125 Section 6.4.3):**

1. **Wildcard replaces exactly ONE label**
   - `*.example.com` = `[exactly-one-label].example.com`
   - NOT: `*.example.com` = `[anything].example.com`

2. **Wildcard only in leftmost position**
   - ✅ Valid: `*.example.com`
   - ❌ Invalid: `www.*.com`
   - ❌ Invalid: `example.*.com`

3. **Label count must match**
   - Pattern and hostname must have same number of labels
   - This is the key rule most implementations miss!

4. **Case-insensitive comparison**
   - `*.Example.COM` matches `www.example.com`

5. **Exact non-wildcard labels must match exactly**
   - In `*.example.com`, both "example" and "com" must match exactly

**📊 DNS Wildcard Matching Examples (Understanding Label Counts):**

**Example 1: Correct Match**
```
Pattern:  *.example.com
Hostname: www.example.com

Breaking into labels:
Pattern:  ["*",     "example", "com"]  → 3 labels
Hostname: ["www",   "example", "com"]  → 3 labels

Label count: 3 = 3 ✅ MATCH!
- Label 1: "*" matches "www" ✅
- Label 2: "example" = "example" ✅
- Label 3: "com" = "com" ✅
Result: ✅ PASS
```

**Example 2: Correct Match (Different Subdomain)**
```
Pattern:  *.example.com
Hostname: api.example.com

Breaking into labels:
Pattern:  ["*",    "example", "com"]  → 3 labels
Hostname: ["api",  "example", "com"]  → 3 labels

Label count: 3 = 3 ✅ MATCH!
- Label 1: "*" matches "api" ✅
- Label 2: "example" = "example" ✅
- Label 3: "com" = "com" ✅
Result: ✅ PASS
```

**Example 3: NO MATCH - Too Many Labels**
```
Pattern:  *.example.com
Hostname: wrong.host.badssl.com

Breaking into labels:
Pattern:  ["*",      "example", "com"]        → 3 labels
Hostname: ["wrong",  "host", "badssl", "com"] → 4 labels

Label count: 3 ≠ 4 ❌ NO MATCH!
Why: Wildcard replaces ONE label, but hostname has TWO extra labels
The wildcard can't "absorb" multiple labels!
Result: ❌ FAIL
```

**Example 4: NO MATCH - Too Few Labels**
```
Pattern:  *.example.com
Hostname: example.com

Breaking into labels:
Pattern:  ["*",       "example", "com"]  → 3 labels
Hostname: ["example", "com"]             → 2 labels

Label count: 3 ≠ 2 ❌ NO MATCH!
Why: Wildcard needs a label to replace, but hostname has no subdomain
Result: ❌ FAIL
```

**Example 5: NO MATCH - Wrong Base Domain**
```
Pattern:  *.api.example.com
Hostname: www.example.com

Breaking into labels:
Pattern:  ["*",   "api", "example", "com"]  → 4 labels
Hostname: ["www", "example", "com"]         → 3 labels

Label count: 4 ≠ 3 ❌ NO MATCH!
Even if we ignore count: "api" ≠ nothing, "example" ≠ "example" position mismatch
Result: ❌ FAIL
```

**🎓 Conceptual Approach to DNS Wildcard Matching:**

**Step 1: Split into labels**
- Split the pattern on dots: `*.example.com` → `["*", "example", "com"]`
- Split the hostname on dots: `www.example.com` → `["www", "example", "com"]`

**Step 2: Check label count**
- Count labels in pattern: 3
- Count labels in hostname: 3
- If counts don't match → NO MATCH, stop here!
- This step is CRITICAL and catches most invalid matches

**Step 3: Compare each label position**
- Go through each position (left to right)
- If pattern label is `*` → any hostname label matches (continue)
- If pattern label is not `*` → must match exactly (case-insensitive)
- If any non-wildcard label doesn't match → NO MATCH

**Step 4: If all positions match → MATCH!**

**🚨 Common Implementation Mistakes to Avoid:**

**❌ WRONG: Using shell/filesystem wildcards**
```
Shell wildcards (like fnmatch, glob, Path.match):
- * matches EVERYTHING including dots
- Would match "*.example.com" to "wrong.host.example.com" ❌
- This is a SECURITY BUG!
```

**❌ WRONG: Using regex wildcards without constraints**
```
Regex .* matches EVERYTHING including dots
- Would match "*.example.com" to "a.b.c.d.example.com" ❌
- Must constrain * to match ONE label only
```

**❌ WRONG: Forgetting to check label count**
```
Without label count check:
- Might incorrectly match multi-level subdomains
- Major security vulnerability!
```

**✅ CORRECT: DNS wildcard matching (RFC 6125)**
```
RFC 6125 rules:
- Wildcard replaces exactly ONE label
- Must check label count FIRST
- Compare each label position
```

**More wildcard matching examples:**
```
SAN: DNS:*.example.com

✅ Matches: www.example.com (one level - 3 labels match 3 labels)
✅ Matches: api.example.com (one level - 3 labels match 3 labels)
✅ Matches: mail.example.com (one level - 3 labels match 3 labels)
❌ NO match: example.com (wildcard needs subdomain - 2 labels ≠ 3 labels)
❌ NO match: foo.bar.example.com (wildcard only covers 1 level - 4 labels ≠ 3 labels)
❌ NO match: wrong.host.badssl.com (different base domain - 4 labels ≠ 3 labels)
```

**⚠️ CRITICAL: TLD Wildcards Are FORBIDDEN by RFC 6125 ⚠️**

**These wildcards are INVALID and MUST be rejected:**
```
❌ FORBIDDEN: DNS:*.com (TLD wildcard)
❌ FORBIDDEN: DNS:*.org (TLD wildcard)
❌ FORBIDDEN: DNS:*.net (TLD wildcard)
❌ FORBIDDEN: DNS:*.co.uk (public suffix wildcard)

Why forbidden?
- One certificate would cover ALL domains under that TLD
- Massive security risk
- Would allow attacker to impersonate any .com domain
- RFC 6125 Section 6.4.3 explicitly prohibits this
```

**Example of the attack TLD wildcards prevent:**
```
If *.com was allowed:
1. Attacker gets certificate with SAN: DNS:*.com
2. Certificate would match: google.com, amazon.com, facebook.com, ANY .com domain!
3. ❌ Complete breakdown of trust model!

RFC 6125 prevents this by FORBIDDING wildcards on public suffixes.
```

**⚠️ IMPORTANT: How TLD Wildcards Are Handled (NOT Automatic Fail!)**

**TLD wildcard SANs should be SKIPPED/IGNORED, not cause automatic failure.**

**Correct behavior:**
```
If certificate has: DNS:*.com, DNS:www.example.com, DNS:example.com
And hostname is: www.example.com

Validation process:
1. Check DNS:*.com
   → Is TLD wildcard? YES
   → Action: SKIP this SAN (don't attempt to match)
   → Continue to next SAN

2. Check DNS:www.example.com
   → Is TLD wildcard? NO
   → Is valid? YES
   → Does hostname match? YES (exact match)
   → Result: ✅ PASS CHECK 7

CHECK 7 PASSES because a valid SAN matched the hostname!
```

**Key principle:** Treat TLD wildcard SANs like malformed data - ignore them and continue checking other SANs.

**When CHECK 7 fails:**
- ❌ No SANs present
- ❌ ONLY TLD wildcard SANs (no valid SANs to check)
- ❌ Has valid SANs, but none match the hostname

**When CHECK 7 passes:**
- ✅ At least one valid (non-TLD-wildcard) SAN matches the hostname

**Examples:**

**Example 1: Only TLD wildcard (FAILS)**
```
SANs:     DNS:*.com
Hostname: www.example.com
Result:   ❌ FAIL CHECK 7
Reason:   No valid SAN to match against (only TLD wildcard)
```

**Example 2: TLD wildcard + matching valid SAN (PASSES)**
```
SANs:     DNS:*.com, DNS:www.example.com
Hostname: www.example.com
Result:   ✅ PASS CHECK 7
Reason:   Valid SAN (www.example.com) matches hostname
```

**Example 3: TLD wildcard + non-matching valid SAN (FAILS)**
```
SANs:     DNS:*.com, DNS:api.example.com
Hostname: www.example.com
Result:   ❌ FAIL CHECK 7
Reason:   No valid SAN matches hostname (api ≠ www)
```

**🔗 How to Detect TLD Wildcards Programmatically:**

To properly validate and reject TLD wildcards, you can retrieve the official list of valid TLDs from IANA:

**IANA TLD List (Updated Daily):**
```
https://data.iana.org/TLD/tlds-alpha-by-domain.txt
```

**Example TLD list content:**
```
# Version 2026012600, Last Updated Mon Jan 27 07:07:01 2026 UTC
COM
NET
ORG
EDU
GOV
MIL
UK
CO
...
```

**Important notes:**
- TLD list includes both generic TLDs (.com, .org) and country-code TLDs (.uk, .jp)
- Some TLDs have second-level registrations (.co.uk, .com.au) - also forbidden
- For production code, cache the TLD list and update periodically
- IANA updates this list when new TLDs are added
- Figure out how to use this list to detect TLD wildcards in your validator!

**Common mistakes:**
```
Certificate SANs: DNS:example.com
User visits: www.example.com
→ ❌ NO MATCH! (www. is a subdomain!)

Certificate SANs: DNS:*.example.com  
User visits: example.com
→ ❌ NO MATCH! (wildcard requires subdomain!)

Certificate SANs: DNS:*.example.com
User visits: foo.bar.example.com
→ ❌ NO MATCH! (wildcard only covers 1 level!)

Certificate SANs: DNS:*.com
User visits: example.com
→ ❌ INVALID! (TLD wildcards FORBIDDEN by RFC 6125!)
```

**Why wildcard matching is used here:**
- SANs contain **patterns** for hostnames
- One certificate can cover multiple subdomains
- `*.example.com` is a **pattern** that matches many hostnames
- But TLD wildcards would be too dangerous and are forbidden

**Test Cases in Challenge That REQUIRE Wildcard Matching:**

Your validator MUST correctly handle these test certificates to pass CHECK 7:

**Test 003: Basic Wildcard (MUST PASS)**
```
SANs:     DNS:*.example.com, DNS:example.com
Hostname: www.example.com
Expected: ✅ PASS (www.example.com matches *.example.com via wildcard)
```

**Test 015: Wildcard Mismatch (MUST FAIL)**
```
SANs:     DNS:*.api.example.com
Hostname: www.example.com
Expected: ❌ FAIL (wrong base domain - www.example.com doesn't match *.api.example.com)
```

**Test 019: TLD Wildcard (MUST FAIL)**
```
SANs:     DNS:*.com
Hostname: www.example.com
Expected: ❌ FAIL (no valid SAN to match - only has TLD wildcard which is skipped)
Note:     Fails because ONLY SAN is invalid TLD wildcard, not because TLD wildcard exists
```

**Test 020: Subdomain Wildcard (MUST PASS)**
```
SANs:     DNS:*.example.com, DNS:example.com
Hostname: www.example.com
Expected: ✅ PASS (wildcard match)
```

**Test 047: Mixed Wildcard + Exact (MUST PASS)**
```
SANs:     DNS:*.example.com, DNS:www.example.com, DNS:example.com
Hostname: www.example.com
Expected: ✅ PASS (matches via exact OR wildcard)
```

**Test 074: Proton.me Production Cert (MUST PASS)**
```
SANs:     DNS:*.proton.me, DNS:*.pr.tn, DNS:proton.me, DNS:pr.tn
Hostname: mail.proton.me (or other subdomains)
Expected: ✅ PASS (mail.proton.me matches *.proton.me)
```

**Test 075: badssl.com Production Cert (MUST PASS)**
```
SANs:     DNS:*.badssl.com, DNS:badssl.com
Hostname: expired.badssl.com (or other subdomains)
Expected: ✅ PASS (expired.badssl.com matches *.badssl.com)
```

**Your challenge:** Implement wildcard matching that:
1. ✅ Matches single-level subdomains (`*.example.com` matches `www.example.com`)
2. ❌ Rejects multi-level subdomains (`*.example.com` does NOT match `foo.bar.example.com`)
3. ❌ Rejects base domain (`*.example.com` does NOT match `example.com`)
4. ❌ Rejects TLD wildcards (`*.com` is INVALID per RFC 6125)
5. ✅ Case-insensitive matching
6. ✅ Wildcard only in leftmost label

**Implementation hint:** Don't use `pathlib.Path.match()` - it's for file paths, not hostnames! You need RFC 6125 compliant matching.

**Source:** 
- RFC 6125 Section 6.4.3 - Server Identity Validation (Wildcard Certificates)
- CA/Browser Forum Baseline Requirements Section 3.2.2.6 - Wildcard Domain Validation

**What happens if it fails:**
Browser shows: "NET::ERR_CERT_COMMON_NAME_INVALID"

---

### 🔹 PHASE 3: ACCESS CONTROL

#### ✅ CHECK 8: Basic Constraints (CA:FALSE)

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
X509v3 Basic Constraints: critical
    CA:FALSE
```

**Plain English explanation:**
This certificate is for a SERVER, NOT a Certificate Authority.

**CA:TRUE** = Can sign other certificates (CAs only)  
**CA:FALSE** = Cannot sign certificates (servers, users)

**Why this matters - CA impersonation attack:**
```
Without CA:FALSE enforcement:
1. Attacker gets valid cert for evil.com
2. Cert has CA:TRUE (mistake!)
3. Attacker signs fake google.com cert
4. Browser trusts it (signed by "valid" CA)
5. ❌ Game over!

With CA:FALSE enforcement:
1. Browser checks: CA:FALSE ✅
2. Cert cannot sign anything
3. Attack prevented ✅
```

**Must be marked CRITICAL:**
```
X509v3 Basic Constraints: critical  ← MUST say "critical"!
    CA:FALSE
```

**Source:** CA/Browser Forum Certificate Contents - "If present, the cA field MUST be set false"

**What happens if it fails:**
Certificate could be used to forge other certificates → Reject

---

#### ⚠️ CHECK 9: Key Usage Flags (RSA vs ECDSA Requirements)

**Status:** ⚠️ OPTIONAL (Universal in practice - 99%+ have it)

**What you'll see in good certificates:**

**RSA certificates:**
```
Public Key Algorithm: rsaEncryption
X509v3 Key Usage: critical
    Digital Signature, Key Encipherment
```

**ECDSA certificates:**
```
Public Key Algorithm: id-ecPublicKey  
X509v3 Key Usage: critical
    Digital Signature
```

**Plain English explanation:**
Key Usage = What cryptographic operations this public key can perform

---

### 🔑 Algorithm-Specific Requirements

**The requirements differ based on the certificate's signature algorithm:**

#### For RSA Certificates:
✅ **REQUIRED:** `Digital Signature`  
✅ **REQUIRED:** `Key Encipherment`  
✅ **MUST** be marked as critical

#### For ECDSA Certificates:
✅ **REQUIRED:** `Digital Signature`  
✅ **MUST** be marked as critical  
❌ **NOT REQUIRED:** `Key Encipherment` (ECDSA keys cannot encrypt)

---

### 🤔 Why the Difference?

#### RSA Key Exchange (TLS 1.2 and earlier)

In traditional RSA key exchange, the server's RSA certificate is used for **TWO different operations:**

1. **Digital Signature:** Signs the ServerKeyExchange message (DHE) or verifies certificate authenticity
2. **Key Encipherment:** Decrypts the pre-master secret that the client encrypts with the server's public RSA key

**RSA Key Exchange Flow:**
```
Client → Server: ClientHello
Server → Client: ServerHello, Certificate (RSA public key)

Client: Generates random pre-master secret
Client: Encrypts pre-master secret with server's RSA public key
Client → Server: Encrypted pre-master secret

Server: Decrypts with private RSA key    ← Needs Key Encipherment!
Both: Derive session keys from pre-master secret
```

**Why RSA needs both flags:** The RSA key is used for both signing AND encrypting during the TLS handshake.

#### ECDSA with ECDHE (Modern TLS)

In modern TLS with ECDSA, the certificate is used for **ONLY ONE operation:**

1. **Digital Signature:** Signs the ServerKeyExchange message containing ECDHE parameters
2. **Key Encipherment:** NOT needed - ECDSA keys can only sign, not encrypt

**ECDSA + ECDHE Flow:**
```
Client → Server: ClientHello
Server → Client: ServerHello, Certificate (ECDSA public key)

Server: Generates ephemeral ECDHE key pair
Server: Signs ECDHE parameters with ECDSA private key
Server → Client: Signed ECDHE parameters

Client: Verifies signature    ← Only needs Digital Signature!
Client: Generates own ECDHE key pair
Client → Server: Client's ECDHE public key

Both: Compute shared secret via ECDHE (no encryption!)
Both: Derive session keys from shared secret
```

**Why ECDSA only needs Digital Signature:**
- ECDSA keys can only sign, not encrypt
- Key exchange uses ECDHE (Ephemeral Diffie-Hellman)
- The pre-master secret is derived via DH key agreement, not encrypted
- Provides Perfect Forward Secrecy (PFS)

---

### ❌ Banned Flags for TLS Server Certificates

These flags should **NEVER** appear in TLS server certificates:

| Flag | Why It's Banned | Impact if Present |
|------|----------------|-------------------|
| **Certificate Sign** | Reserved for CA certificates | End-entity cert could sign other certificates! (DigiNotar attack) |
| **CRL Sign** | Reserved for CRL issuers | Could issue fake revocation lists |
| **Data Encipherment** | For encrypting user data | Not used in TLS protocol |
| **Content Commitment** (Non-Repudiation) | For legally-binding signatures | Unusual for TLS, adds legal liability |

**Critical Security Issue:** If a TLS server certificate has `Certificate Sign`, it can create valid-looking certificates for ANY domain → Complete PKI compromise!

---

### 📊 Real-World Examples

#### ✅ Valid RSA Certificate (Let's Encrypt)
```
Subject Public Key Info:
    Public Key Algorithm: rsaEncryption
    Public-Key: (2048 bit)

X509v3 Key Usage: critical
    Digital Signature, Key Encipherment
```
**Result:** PASS ✅ (RSA has both required flags)

#### ✅ Valid ECDSA Certificate (Let's Encrypt)
```
Subject Public Key Info:
    Public Key Algorithm: id-ecPublicKey
    Public-Key: (256 bit)
    ASN1 OID: prime256v1

X509v3 Key Usage: critical
    Digital Signature
```
**Result:** PASS ✅ (ECDSA only needs Digital Signature)

#### ❌ Invalid RSA Certificate (Missing Key Encipherment)
```
Subject Public Key Info:
    Public Key Algorithm: rsaEncryption

X509v3 Key Usage: critical
    Digital Signature
```
**Result:** FAIL ❌ (RSA certificate missing Key Encipherment)  
**Impact:** Cannot perform RSA key exchange

#### ❌ Invalid Certificate (Not Critical)
```
X509v3 Key Usage:
    Digital Signature, Key Encipherment
```
**Result:** FAIL ❌ (Extension not marked as critical)

#### ❌ Invalid Certificate (Banned Flag)
```
X509v3 Key Usage: critical
    Digital Signature, Key Encipherment, Certificate Sign
```
**Result:** FAIL ❌ (Has Certificate Sign - security catastrophe!)  
**Impact:** This certificate can forge other certificates!

---

### 🎯 Common Validation Failures

**Test 055: RSA Missing Key Encipherment**
```
Algorithm: rsaEncryption
X509v3 Key Usage: critical
    Digital Signature    ← Missing Key Encipherment!
```
**Error:** RSA certificate must have both Digital Signature AND Key Encipherment

**Test 056: Has Data Encipherment (Banned)**
```
X509v3 Key Usage: critical
    Digital Signature, Key Encipherment, Data Encipherment
                                         ^^^ Banned flag!
```
**Error:** Data Encipherment is not appropriate for TLS server certificates

**Test 025: Not Marked Critical**
```
X509v3 Key Usage:    ← Missing "critical"!
    Digital Signature, Key Encipherment
```
**Error:** Key Usage extension must be marked as critical

---

### 📖 Why OPTIONAL per Specification

**CA/Browser Forum language:** "If present, bit positions for keyCertSign and cRLSign MUST NOT be set"

**Key phrase:** "If present" - the extension itself is technically optional

**Reality:** 99%+ of real-world TLS certificates include Key Usage (it's universal in practice)

**Validation approach:**
```
IF Key Usage extension is present:
  1. ✅ Must be marked critical
  2. ❌ MUST NOT have Certificate Sign or CRL Sign
  3. ✅ Must have algorithm-appropriate flags:
     - RSA: Digital Signature + Key Encipherment
     - ECDSA: Digital Signature only
  
IF Key Usage extension is absent:
  → Accept (extension is optional per CA/B Forum)
```

---

### 🔒 Why Modern TLS Prefers ECDSA + ECDHE

**Advantages:**
1. **Perfect Forward Secrecy (PFS):** Even if private key stolen later, past sessions remain secure
2. **Smaller keys:** ECDSA P-256 (256-bit) ≈ RSA 3072-bit security
3. **Faster operations:** ECDSA signing/verification is faster
4. **Clearer requirements:** Only needs Digital Signature flag

**Migration trend:** Industry moving from RSA to ECDSA + ECDHE for these security and performance benefits.

---

**Source:** RFC 5280 Section 4.2.1.3 (Key Usage), CA/Browser Forum Baseline Requirements Section 7.1.2.3

**What happens if it fails:**
- Missing required flags → Cannot establish TLS connection (cipher suite mismatch)
- Has Certificate Sign or CRL Sign → REJECT IMMEDIATELY (security catastrophe!)
- Not marked critical → Reject (violates RFC 5280)
- Extension absent → Accept (optional per CA/B Forum)

---

#### ✅ CHECK 10: Extended Key Usage (EKU)

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
X509v3 Extended Key Usage:
    TLS Web Server Authentication
```

**Plain English explanation:**
EKU = What PURPOSE this certificate serves

**For TLS server certificates, MUST include:**
- **TLS Web Server Authentication** (OID: 1.3.6.1.5.5.7.3.1) ✅

**CAN also include (for specific use cases):**
- TLS Web Client Authentication (for mTLS - mutual TLS)
- Other purposes (as long as Server Auth is present)

**Why this matters - Wrong purpose attack:**

| Purpose Used INSTEAD of Server Auth | What It's For | OID | Test |
|-------------------------------------|---------------|-----|------|
| Code Signing (alone) | Software signing | 1.3.6.1.5.5.7.3.3 | 028 |
| TLS Web Client Authentication (alone) | Client-only certs | 1.3.6.1.5.5.7.3.2 | 059 |
| E-mail Protection (alone) | S/MIME email | 1.3.6.1.5.5.7.3.4 | 060 |
| Time Stamping (alone) | Timestamp authorities | 1.3.6.1.5.5.7.3.8 | - |
| OCSP Signing (alone) | OCSP responses | 1.3.6.1.5.5.7.3.9 | - |
| Document Signing (alone) | PDF signing | 1.3.6.1.5.5.7.3.36 | - |

**✅ CORRECT - Server Auth WITH other purposes:**
```
X509v3 Extended Key Usage:
    TLS Web Server Authentication
    TLS Web Client Authentication
→ ✅ HAS Server Auth (Client Auth is bonus for mTLS)
```

**❌ WRONG - Client Auth INSTEAD OF Server Auth:**
```
X509v3 Extended Key Usage:
    TLS Web Client Authentication
→ ❌ MISSING Server Auth!
```

**Real-world example:**
Test 028: Code Signing INSTEAD OF Server Auth → ❌ FAIL  
Test 059: Client Auth INSTEAD OF Server Auth → ❌ FAIL  
Test 029: Server Auth WITH Client Auth → ✅ PASS  
Bitwarden: Server Auth WITH Client Auth → ✅ PASS

**Source:** CA/Browser Forum Certificate Contents - "Either the value id-kp-serverAuth or id-kp-clientAuth or both values MUST be present"

**What happens if it fails:**
Certificate has wrong purpose → Browser rejects

---

### 🔹 PHASE 4: REVOCATION INFRASTRUCTURE

**⚠️ IMPORTANT UPDATE - Ballot SC63 (Effective March 15, 2024):**  
The CA/Browser Forum made significant changes to revocation requirements:
- ✅ **CRL (Check 11): NOW REQUIRED** (was recommended)
- ⚠️ **OCSP (Check 13): NOW OPTIONAL** (was required)

This reversal addresses privacy concerns (OCSP exposes browsing behavior), security issues (plain HTTP), and operational complexity. Short-lived certificates (≤7 days) are exempt from both requirements.

**Sources:** CA/Browser Forum Ballot SC63 - "Make OCSP optional, require CRLs, and incentivize automation"

---

#### ✅ CHECK 11: CRL Distribution Points (Certificate Revocation List)

**Status:** ✅ REQUIRED (Changed March 15, 2024 via Ballot SC63)

**What you'll see in a good certificate:**
```
X509v3 CRL Distribution Points:
    URI:http://crl3.digicert.com/ca.crl
    URI:http://crl4.digicert.com/ca.crl
```

**Plain English explanation:**
CRL = Certificate Revocation List = List of canceled certificate serial numbers

**What's REQUIRED:**
- ✅ CRL Distribution Points extension MUST be present
- ✅ At least **1 CRL URL** is required
- ⚠️ **2+ CRL URLs recommended** for redundancy (but not required)

**Why multiple URLs are recommended (but not required)?** Redundancy!
- If one CRL server is down, browser can try the backup
- Best practice: 2+ URLs for high availability
- Reality: 70% have 2 URLs, 30% have 1 URL (both valid)

**Why HTTP not HTTPS?** Avoid circular dependency:
```
If CRL URL was HTTPS:
1. Need to validate cert for crl.example.com
2. To validate, need to download CRL
3. To download CRL, need to validate cert
4. Infinite loop! 🔄
```

**Why this matters:**
```
Without CRL:
1. Private key stolen
2. CA revokes cert
3. Client can't check (no URL)
4. ❌ Accepts revoked cert!

With CRL:
1. Private key stolen
2. CA revokes cert (adds to CRL)
3. Client downloads CRL
4. Finds cert serial in revoked list
5. ✅ Rejects connection!
```

**CA/Browser Forum Ballot SC63 (Adopted August 17, 2023, Effective March 15, 2024):**
- **OLD**: OCSP required, CRL recommended
- **NEW**: CRL required, OCSP optional
- **Why?** Privacy concerns with OCSP (reveals browsing behavior), operational complexity, and browser failures with OCSP led to this reversal

**Real-world incident:**
In 2023, Let's Encrypt announced plans to end OCSP support in favor of CRLs due to:
- Privacy: OCSP requests expose user browsing behavior
- Security: OCSP requests sent over plain HTTP can be intercepted
- Complexity: OCSP requires high-availability servers
- Browser behavior: Many browsers ignore OCSP failures anyway

**Exception:** Short-lived certificates (≤7 days validity) do NOT require CRL or OCSP.

**Sources:**
- CA/Browser Forum Ballot SC63: "Make OCSP optional, require CRLs, and incentivize automation"
- CA/Browser Forum Baseline Requirements Section 7.1.2.7.1: "The cRLDistributionPoints extension MUST be present"
- Wikipedia: "Certificate authorities were previously required by the CA/Browser Forum to provide OCSP service, but this requirement was removed in July 2023"

**What happens if it fails:**
✅ REQUIRED check - certificate will be rejected

---

#### ✅ CHECK 12: Authority Information Access (AIA)

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**

**Option 1: Both OCSP and CA Issuers (most common)**
```
Authority Information Access:
    OCSP - URI:http://ocsp.digicert.com
    CA Issuers - URI:http://cacerts.digicert.com/ca.crt
```

**Option 2: CA Issuers only (Bitwarden, Let's Encrypt pattern)**
```
Authority Information Access:
    CA Issuers - URI:http://r12.i.lencr.org/
```

**Plain English explanation:**
AIA = Authority Information Access = Where to find more information about the certificate

**What's REQUIRED:**
- ✅ AIA extension MUST be present
- ✅ Must contain at least one access method

**What can be IN the AIA extension:**
1. **CA Issuers URL** (recommended): Where to download the issuing CA certificate
2. **OCSP URL** (optional per SC63): Real-time revocation checking

**Important clarification:**
- **Check 12:** Validates that AIA extension exists
- **Check 13:** Separately validates OCSP URL (which is optional)

**Common patterns:**
- **70%:** Have both OCSP + CA Issuers
- **30%:** Have only CA Issuers (valid! - Bitwarden, Let's Encrypt)
- **<1%:** Have only OCSP (valid but not recommended)

**Why CA Issuers URL matters:**

**Without CA Issuers URL:**
```
Browser has: Server cert
Browser needs: Intermediate cert to validate chain
Problem: Where to get intermediate cert?
→ Connection might fail ❌
```

**With CA Issuers URL:**
```
Browser has: Server cert
Browser downloads: Intermediate from CA Issuers URL
Browser builds: Complete chain to root
→ Validation succeeds ✅
```

**Source:** CA/Browser Forum Baseline Requirements Section 7.1.2.7.2: "With the exception of stapling, this extension MUST be present"

**What the extension can contain:**
- CA Issuers (recommended for chain building)
- OCSP (optional per SC63 - validated separately in Check 13)

**What happens if it fails:**
Missing AIA extension → Reject (required by CA/B Forum)

---

#### ⚠️ CHECK 13: OCSP URL (Real-Time Revocation Checking)

**Status:** ⚠️ OPTIONAL (Changed March 15, 2024 via Ballot SC63)

**What you'll see in a good certificate:**
```
OCSP - URI:http://ocsp.digicert.com
```

**Plain English explanation:**
OCSP = Online Certificate Status Protocol = Ask CA "Is this cert still valid?"

**OCSP vs CRL:**
- **CRL** = Download entire list (slow, big)
- **OCSP** = Ask about ONE cert (fast, small)

**CA/Browser Forum Ballot SC63 (Adopted August 17, 2023, Effective March 15, 2024):**
- **OLD**: OCSP required, CRL recommended
- **NEW**: CRL required, OCSP optional
- **Why the reversal?**
  1. **Privacy**: OCSP requests expose which sites users visit
  2. **Security**: OCSP sent over plain HTTP (can be intercepted)
  3. **Reliability**: Many browsers ignore OCSP failures (fail-open)
  4. **Complexity**: Requires high-availability infrastructure

**Real-world example:**
Let's Encrypt announced in 2023 they're ending OCSP support in favor of CRLs due to these privacy and operational concerns.

**Why this matters - Real-time revocation (when present):**
```
Timeline with OCSP:

9:00 AM: Private key stolen
9:30 AM: CA revokes cert, OCSP updated
9:31 AM: Client connects
  → OCSP query: "Valid?"
  → OCSP: "Revoked!"
  → ✅ Rejected in 1 minute!

Without OCSP:
Must wait for CRL update (hours/days)
```

**⚠️ Important Note:**
While OCSP is now optional, most CAs still provide it for backward compatibility. However, you may encounter modern certificates without OCSP URLs - this is compliant as long as CRL is present.

**Sources:**
- CA/Browser Forum Ballot SC63
- Wikipedia: "Certificate authorities were previously required by the CA/Browser Forum to provide OCSP service, but this requirement was removed in July 2023"
- smallstep.com/blog/ocsp-vs-crl-explained

**What happens if it fails:**
No longer a hard failure - certificate can be valid with CRL alone

---

#### ✅ CHECK 14: Certificate Transparency (Public Audit Trail)

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
CT Precertificate SCTs:
    Signed Certificate Timestamp (Log 1)
    Signed Certificate Timestamp (Log 2)
```

**Plain English explanation:**
CT = Public log of ALL certificates issued

**SCT = Signed Certificate Timestamp** = Proof cert was logged

**Why at least 2 SCTs?** Redundancy and independence

**Why this matters - Prevents secret certificates:**
```
DigiNotar hack (2011):
1. Hackers compromise DigiNotar CA
2. Issue FAKE google.com certificate
3. Use it for espionage (no one knows!)
4. Months pass before discovery
5. ❌ Massive damage done

With Certificate Transparency:
1. CA issues certificate
2. MUST log to public CT log
3. Google monitors logs
4. Sees unauthorized google.com cert
5. ✅ Revokes within hours!
```

**Real-world validation:**
```
Certificate with 0 SCTs: ❌ Reject (Chrome, Safari)
Certificate with 1 SCT: ❌ Reject (not redundant)
Certificate with 2+ SCTs: ✅ Accept
```

**Browser enforcement:**
- **Chrome:** Required since April 2018
- **Safari:** Required (Apple platforms enforce for all TLS)
- **Firefox:** Required since version 135 (February 2025)
- **Edge:** Follows Chrome policy

**What is an SCT?**
```
Signed Certificate Timestamp:
    Version: v1 (0x0)
    Log ID: A4:B9:09:90... (CT log identifier)
    Timestamp: Jan 15 2026 10:23:45 GMT
    Signature: (CA's signature proving it was logged)
```

**Sources:**
- Chrome CT Policy
- RFC 6962: Certificate Transparency
- Mozilla Firefox 135+ requirement (February 2025)

**What happens if it fails:**
Browser shows: "NET::ERR_CERTIFICATE_TRANSPARENCY_REQUIRED"

---

### 🔹 PHASE 5: CHAIN VALIDATION

#### ✅ CHECK 15: Not Self-Signed

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
Issuer:  C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1
Subject: C=US, ST=California, O=Example Inc, CN=www.example.com
→ Issuer ≠ Subject ✅
```

**Plain English explanation:**
Self-signed certificate = Issuer and Subject are the SAME

**⭐ CRITICAL: CHECK 15 DOES NOT USE WILDCARD MATCHING ⭐**

This check performs **exact DN comparison**, NOT pattern matching!

The `*` character (if present in a DN) is treated as a **literal character**, not a wildcard!

**For publicly-trusted certificates:**
- Issuer MUST be a trusted CA
- Issuer MUST NOT equal Subject

**Self-signed certificates are only valid for:**
- Root CA certificates (in browser trust stores)
- Internal/private PKI
- Testing/development

**Why this matters:**
```
Self-signed cert for www.example.com:
Issuer:  CN=www.example.com  ← Claims to sign itself!
Subject: CN=www.example.com

Anyone can create this!
→ ❌ No trust anchor!
→ ❌ Not publicly trusted!
```

**⚠️ NO WILDCARD MATCHING - Distinguished Names are Exact Identifiers!**

Unlike CHECK 7 (which uses wildcard matching for hostnames), CHECK 15 compares DNs for **exact equality**.

**Example - These are NOT considered self-signed:**
```
Issuer:  CN = *.example.com, O = Example CA
Subject: CN = www.example.com, O = Example Corp
→ NOT self-signed ✅ (CNs differ: "*.example.com" ≠ "www.example.com")
```

The `*` is just a literal character in the CN field, NOT a wildcard pattern!

**Example - These ARE self-signed:**
```
Issuer:  CN = *.example.com, O = Example Inc
Subject: CN = *.example.com, O = Example Inc
→ Self-signed ❌ (exact DN match including the "*")
```

**Why NO wildcard matching for CHECK 15:**
- Distinguished Names are **unique identifiers**, not patterns
- `CN=*.example.com` identifies a specific CA, it's not a pattern
- Wildcard matching would create false positives (different entities matching)

**Comparison with CHECK 7:**

| Aspect | CHECK 7 (Hostname) | CHECK 15 (Self-Signed) |
|--------|-------------------|------------------------|
| **Uses wildcard matching** | ✅ YES | ❌ NO |
| **`*.example.com`** | Pattern (matches many) | Literal identifier |
| **Match example** | `*.example.com` matches `www.example.com` | Only: `*.example.com` = `*.example.com` |
| **Purpose** | Match hostname patterns | Identify exact entities |

**⚠️ CRITICAL IMPLEMENTATION WARNING: Field Order Matters!**

**DO NOT use simple string comparison!** The Issuer and Subject fields can contain the same values in **different orders** but still represent the same Distinguished Name.

**Example of a self-signed certificate with different field order:**
```
Issuer:  C=US, O=Example Corp, OU=Engineering, CN=Test CA
Subject: CN=Test CA, OU=Engineering, O=Example Corp, C=US
```

**Your challenge:** Figure out how to compare DNs correctly regardless of field order.

**Hint:** Think about how to normalize or parse the DN components before comparing.

**Test cases to verify your implementation:**

```
# Test 1: Obvious self-signed (same order)
Issuer:  CN=Test CA, O=Example
Subject: CN=Test CA, O=Example
Expected: self-signed ✅

# Test 2: Self-signed (different order) - THE TRICKY ONE!
Issuer:  C=US, O=Example, CN=Test CA
Subject: CN=Test CA, O=Example, C=US
Expected: self-signed ✅ (must handle this!)

# Test 3: Not self-signed (different CN)
Issuer:  C=US, O=DigiCert, CN=DigiCert CA
Subject: C=US, O=Example, CN=www.example.com
Expected: not self-signed ✅

# Test 4: Not self-signed (different order AND different values)
Issuer:  CN=CA Root, O=TrustCorp
Subject: O=Example Inc, CN=www.example.com
Expected: not self-signed ✅

# Test 5: Wildcard in DN - NOT self-signed (no wildcard matching!)
Issuer:  CN=*.example.com, O=Example CA
Subject: CN=www.example.com, O=Example CA
Expected: not self-signed ✅ ("*.example.com" ≠ "www.example.com" - exact comparison!)

# Test 6: Wildcard in DN - IS self-signed (exact match with wildcard)
Issuer:  CN=*.example.com, O=Example CA
Subject: CN=*.example.com, O=Example CA
Expected: self-signed ❌ (exact DN match including the "*")
```

**Why this matters in practice:**

Different certificate authorities and tools format DNs differently:
- **OpenSSL:** Often uses `C, ST, L, O, OU, CN` order
- **Microsoft CA:** Often uses `CN, OU, O, L, ST, C` order (reverse!)
- **Let's Encrypt:** May omit optional fields
- **Internal CAs:** Custom ordering conventions

**Your validator must handle all of these correctly!**

**Source:** CA/Browser Forum Baseline Requirements - "CAs MUST NOT issue Subscriber Certificates directly from Root CAs"

**What happens if it fails:**
Browser shows: "NET::ERR_CERT_AUTHORITY_INVALID"

---

#### ✅ CHECK 16: Valid Serial Number

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
Serial Number:
    0a:f7:e7:ca:cf:45:d8:a9:72:ab:47:c5:f8:49:11:da
```

**Plain English explanation:**
Every certificate MUST have a unique serial number with sufficient randomness.

**CA/Browser Forum requirements:**
- ✅ **At least 64 bits of entropy** (8 bytes of randomness)
- ✅ **Unique** within the CA
- ❌ **NOT sequential** (0x01, 0x02, 0x03...)
- ❌ **NOT predictable** (timestamp-based)

**Why this matters - Serial number attacks:**

**2019 EJBCA Incident:**
- EJBCA CA software had a bug
- Generated serial numbers with only 63 bits entropy (not 64!)
- Required revoking over **1 million certificates**
- Affected Actalis: 230,000 active certificates

**The bug:** EJBCA generated serial numbers with only 63 bits of entropy instead of 64 bits because it incorrectly handled negative values in signed integers.

**Real-world examples from test suite:**

**Test 040 - Sequential serial (FAIL):**
```
Serial Number: 1234 (0x4d2)
→ ❌ Only 11 bits! Predictable!
```

**Test 069 - Weak entropy (FAIL):**
```
Serial Number: 4660 (0x1234)
→ ❌ Only 16 bits! Weak PRNG!
```

**Good certificate:**
```
Serial Number:
    0a:f7:e7:ca:cf:45:d8:a9:72:ab:47:c5:f8:49:11:da
→ ✅ 128 bits! Excellent entropy!
```

**Sources:**
- CA/Browser Forum Baseline Requirements Section 7.1 (required since 2011)
- EJBCA incident details: https://bugzilla.mozilla.org/show_bug.cgi?id=1602319

**What happens if it fails:**
Weak serial number → Potential collision → CA may need to revoke certificate

---

#### ⚠️ CHECK 17: Subject Key Identifier (SKI) Present

**Status:** ⚠️ RECOMMENDED (Not required for end-entity certificates)

**What you'll see in a good certificate:**
```
X509v3 Subject Key Identifier:
    B7:3E:8E:1A:93:0E:2B:86:93:6A:BC:23:5C:55:01:F4:23:6C:45:87
```

**Plain English explanation:**
SKI = Hash of the public key = Unique identifier for this certificate's key

**RFC 5280 Requirements:**
- ✅ **REQUIRED for CA certificates**
- ⚠️ **RECOMMENDED (not required) for end-entity certificates**

**Why recommended but not required:**
```
RFC 5280 Section 4.2.1.2:
"For CA certificates, subject key identifiers SHOULD be derived..."
[No MUST requirement for subscriber/end-entity certificates]
```

**Real-world status:**
- 99%+ of modern certificates include SKI
- Let's Encrypt community discussion (July 2024) asked if they could remove it
- This proves it's technically optional

**Why it's useful (when present):**
```
Building certificate chain:
1. Find cert with SKI matching parent's AKI
2. Continue until reaching root
→ Faster chain building
```

**What the value is:**
```
SKI = SHA-1 hash of the public key
→ Uniquely identifies this key
```

**Sources:**
- RFC 5280 Section 4.2.1.2
- OpenSSL GitHub Issue #13603: "SKID with the exception of non-CA certs"
- Let's Encrypt community discussion (July 2024)

**What happens if it fails:**
If absent → May still accept (recommended but not required)  
If present → Must be properly formatted

---

#### ✅ CHECK 18: Authority Key Identifier (AKI) Present

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
X509v3 Authority Key Identifier:
    13:92:C7:15:88:71:4D:F8:F4:32:45:E6:67:8B:A2:1C:65:43:B1:2D
```

**Plain English explanation:**
AKI = Hash of the ISSUING CA's public key = Links child cert to parent cert

**RFC 5280 Requirements:**
```
Section 4.2.1.1:
"The keyIdentifier field of the authorityKeyIdentifier extension 
MUST be included in all certificates generated by conforming CAs"
```

**Exception:** Self-signed certificates MAY omit AKI (since AKI would equal SKI)

**Why this matters - Chain building:**
```
Certificate chain validation:
1. Server cert has AKI: 13:92:C7:...
2. Find intermediate cert with SKI: 13:92:C7:...
3. Match! This is the parent ✅
4. Repeat until reaching root
```

**Without AKI:**
```
1. Server cert (no AKI)
2. Which intermediate signed it?
3. Try all intermediates? Slow!
4. Might fail to build chain ❌
```

**What the value is:**
```
Server cert AKI: 13:92:C7:15:88:71...
   ↓ MUST MATCH
Intermediate SKI: 13:92:C7:15:88:71...
```

**Source:** RFC 5280 Section 4.2.1.1 - "MUST be included in all certificates generated by conforming CAs to facilitate certification path construction"

**What happens if it fails:**
Missing AKI → Cannot build certificate chain → Reject

---

#### ⚠️ CHECK 19: SKI ≠ AKI (Not Self-Signed Detector)

**Status:** ⚠️ CONDITIONAL (Only applies if both SKI and AKI are present)

**What you'll see in a good certificate:**
```
X509v3 Subject Key Identifier:
    B7:3E:8E:1A:93:0E:2B:86:93:6A:BC:23:5C:55:01:F4:23:6C:45:87
    
X509v3 Authority Key Identifier:
    13:92:C7:15:88:71:4D:F8:F4:32:45:E6:67:8B:A2:1C:65:43:B1:2D

→ B7:3E... ≠ 13:92... ✅ Different! Not self-signed!
```

**Plain English explanation:**
If SKI (this cert's key) equals AKI (issuer's key), then certificate is self-signed.

**For publicly-trusted certificates:**
- SKI and AKI MUST be different
- SKI = AKI means self-signed (not allowed)

**Why conditional:**
Since Check 17 (SKI) is RECOMMENDED (not required), this check only applies when BOTH SKI and AKI are present.

**Self-signed detection:**
```
Self-signed certificate:
  SKI: 13:92:C7:15:88:71...
  AKI: 13:92:C7:15:88:71...
  → Same! Self-signed! ❌

Valid certificate:
  SKI: B7:3E:8E:1A:93:0E...
  AKI: 13:92:C7:15:88:71...
  → Different! Has parent CA ✅
```

**Logic:** If both SKI and AKI are present, compare them. If they're equal, it's self-signed (FAIL). If different, it has a separate issuer (PASS). If either is missing, rely on CHECK 15.

**Source:** RFC 5280 logic for self-signed certificates

**What happens if it fails:**
If SKI == AKI → Self-signed certificate → Reject (covered by Check 15)

---

### 🔹 PHASE 6: OPERATIONAL

#### ✅ CHECK 20: Certificate Validity Period ≤ 398 Days

**Status:** ✅ REQUIRED

**What you'll see in a good certificate:**
```
Validity
    Not Before: Dec  1 00:00:00 2025 GMT
    Not After : Feb 28 23:59:59 2026 GMT
→ Duration: 89 days ✅ (under 398 days)
```

**Plain English explanation:**
Certificates issued after September 1, 2020 CANNOT be valid for more than 398 days (~13 months).

**Historical limits:**
- Pre-2015: Up to 5 years allowed
- 2015-2018: Max 39 months (825 days)
- 2018-2020: Max 27 months (825 days)  
- Sept 2020-Present: Max 398 days
- **Future: 47 days by 2029** (CA/B Forum Ballot SC-081)

**Why this matters:**
```
Longer validity = More risk:

5-year certificate (2015):
- Year 1: RSA-2048 is "safe"
- Year 3: New attacks discovered
- Year 5: RSA-2048 possibly broken
- Problem: Cert still valid! ❌

90-day certificate (2025):
- Renewed every 90 days
- Can upgrade to stronger algorithms
- Can fix validation errors quickly
- Limited exposure window ✅
```

**Real-world timeline:**
```
Today to March 15, 2026: Max 398 days
March 15, 2026: Max 200 days
March 15, 2027: Max 100 days
March 15, 2029: Max 47 days
```

**Calculation:** Parse the Not Before and Not After dates, calculate the difference in days, and check if it exceeds 398 days.

**Sources:**
- CA/Browser Forum Ballot SC22 (effective September 1, 2020)
- CA/Browser Forum Ballot SC-081 (approved April 2025, reducing to 47 days by 2029)

**What happens if it fails:**
Certificate validity too long → Browsers reject as non-compliant

---

## 🎯 Putting It All Together: Annotated Certificate Example

Here's a real certificate with ALL 20 checks annotated:

```
Certificate:
    Data:
        Version: 3 (0x2)
            ✅ CHECK 1: Version 3 (supports extensions)
            
        Serial Number:
            0a:f7:e7:ca:cf:45:d8:a9:72:ab:47:c5:f8:49:11:da
            ✅ CHECK 16: Valid serial number (128 bits entropy, unique)
            
        Signature Algorithm: sha256WithRSAEncryption
            ✅ CHECK 3: SHA-256 signature (strong, not MD5/SHA-1)
            
        Issuer: C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1
        
        Validity
            Not Before: Dec  1 00:00:00 2025 GMT
            Not After : Feb 28 23:59:59 2026 GMT
            ✅ CHECK 2: Not expired, not yet valid (89 days validity)
            ✅ CHECK 20: Validity ≤ 398 days (89 days ✅)
            
        Subject: C=US, ST=California, L=San Francisco, O=GitHub Inc, CN=github.com
            ⚠️ CHECK 5: Subject DN present (MINIMAL OK - can be minimal)
            ✅ CHECK 15: Not self-signed (Issuer ≠ Subject)
                         ⚠️ IMPORTANT: Must parse and compare fields, not just string compare!
                         Fields can be in different order but represent same DN.
            
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus: 00:b1:23:...
                Exponent: 65537 (0x10001)
            ✅ CHECK 4: Strong key (RSA-2048, exponent is prime)
                
        X509v3 extensions:
            X509v3 Subject Alternative Name:  
            ✅ CHECK 6: SANs extension present
            ✅ CHECK 7: Hostname validation (against SANs)
                DNS:github.com
                DNS:www.github.com
                DNS:*.github.com
                DNS:*.github.io
                │
                └──> Multiple hostnames covered
                     Wildcards allowed for subdomains
                     Browser matches requested hostname against this list
                     
            X509v3 Extended Key Usage:  
            ✅ CHECK 10: Extended Key Usage present with SERVER_AUTH
                TLS Web Server Authentication
                │
                └──> Purpose: TLS server (not code signing, not email)
                     id-kp-serverAuth OID: 1.3.6.1.5.5.7.3.1
                     
            X509v3 CRL Distribution Points:  
            ✅ CHECK 11: CRL Distribution Points present (REQUIRED since SC63 Mar 2024)
                URI:http://crl3.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl
                URI:http://crl4.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl
                │
                └──> Two CRL endpoints for redundancy
                     Clients can check if certificate was revoked
                     HTTP URIs (not HTTPS to avoid circular dependency)
                     NOW REQUIRED (was recommended) per Ballot SC63
                     
            Authority Information Access:  
            ✅ CHECK 12: AIA present
            ⚠️ CHECK 13: OCSP URL present (OPTIONAL since SC63 Mar 2024)
                OCSP - URI:http://ocsp.digicert.com
                CA Issuers - URI:http://cacerts.digicert.com/DigiCertTLSRSASHA2562020CA1-1.crt
                │
                └──> OCSP = real-time revocation checking (optional, privacy concerns)
                     CA Issuers = where to download intermediate cert
                     Both are HTTP (not HTTPS) to avoid circular dependency
                     NOW OPTIONAL (was required) per Ballot SC63
                     
            X509v3 Basic Constraints: critical  
            ✅ CHECK 8: Basic Constraints CA:FALSE (critical)
                CA:FALSE
                │
                └──> This is a server cert, NOT a CA
                     Cannot sign other certificates
                     MUST be marked critical
                     
            X509v3 Key Usage: critical  
            ⚠️ CHECK 9: Key Usage present (OPTIONAL but universal)
                Digital Signature, Key Encipherment
                │
                └──> Digital Signature: For ECDHE key exchange
                     Key Encipherment: For RSA key exchange
                     MUST be marked critical (if present)
                     Present in 99%+ of certificates despite being optional
                     
            X509v3 Subject Key Identifier:  
            ⚠️ CHECK 17: SKI present (RECOMMENDED, not required for end-entity)
                B7:3E:8E:1A:93:0E:2B:86:93:6A:BC:23:5C:55:01:F4:23:6C:45:87
                │
                └──> SHA-1 hash of this certificate's public key
                     Used for fast chain building
                     RECOMMENDED but not REQUIRED per RFC 5280
                     
            X509v3 Authority Key Identifier:  
            ✅ CHECK 18: AKI present (REQUIRED)
            ⚠️ CHECK 19: SKI ≠ AKI check (CONDITIONAL - both present)
                13:92:C7:15:88:71:4D:F8:F4:32:45:E6:67:8B:A2:1C:65:43:B1:2D
                │
                └──> SHA-1 hash of issuing CA's public key
                     Links to parent certificate
                     B7:3E... ≠ 13:92... → Not self-signed ✅
                     
            CT Precertificate SCTs:  
            ✅ CHECK 14: Certificate Transparency (2 SCTs)
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : A4:B9:09:90:B4:16:6B:3E...
                    Timestamp : Jan 15 2026 10:23:45.123 GMT
                    
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : EE:4B:BD:B7:75:CE:60:BA...
                    Timestamp : Jan 15 2026 10:23:46.789 GMT
                │
                └──> 2 independent CT logs (redundancy)
                     Proves certificate was publicly logged
                     Required by Chrome (2018+), Safari, Firefox 135+ (2025)
                     
    Signature Algorithm: sha256WithRSAEncryption
         a3:f4:2b:17:6d:09:...
         
✅ VALIDATION SUMMARY:
✅ CHECK 1:  Version 3 - PASS
✅ CHECK 2:  Not expired/not yet valid - PASS
✅ CHECK 3:  SHA-256 signature - PASS
✅ CHECK 4:  RSA-2048 strong key - PASS
⚠️ CHECK 5:  Subject DN present (minimal ok) - PASS
✅ CHECK 6:  SANs present - PASS
✅ CHECK 7:  Hostname matches - PASS (would need actual hostname)
✅ CHECK 8:  Basic Constraints: CA:FALSE (critical) - PASS
⚠️ CHECK 9:  Key Usage: Digital Signature, Key Encipherment (critical, optional) - PASS
✅ CHECK 10: Extended Key Usage: TLS Web Server Authentication - PASS
✅ CHECK 11: CRL Distribution Points present (2 URLs - REQUIRED extension, 1+ URLs needed) - PASS
✅ CHECK 12: Authority Information Access present - PASS
⚠️ CHECK 13: OCSP URL: http://ocsp.digicert.com (OPTIONAL since SC63) - PASS
✅ CHECK 14: Certificate Transparency (2 SCTs) - PASS
✅ CHECK 15: Not self-signed (Issuer ≠ Subject) - PASS
✅ CHECK 16: Valid serial number (128 bits entropy) - PASS
⚠️ CHECK 17: SKI present (RECOMMENDED, not required for end-entity) - PASS
✅ CHECK 18: AKI present - PASS
⚠️ CHECK 19: SKI ≠ AKI (CONDITIONAL, both present) - PASS
✅ CHECK 20: Validity 89 days ≤ 398 days - PASS

**Score: 20/20** ✅  
**Result: VALID CERTIFICATE - All checks passed!**
```

---

## 💻 THE CHALLENGE: Build the Validator!

### Input Format

Your validator receives certificates in **TEXT format** (OpenSSL text output):

```bash
$ openssl x509 -in certificate.pem -text -noout > certificate.txt
```

**Why TEXT not PEM?**
- Easier to parse (human-readable)
- No ASN.1 parsing required
- Focus on validation logic, not parsing complexity

### Your Task

Build `validate_cert.py` that:

1. **Reads** a certificate.txt file
2. **Checks** all 20 validation rules
3. **Outputs** a clear pass/fail report

### Expected Output Format

```
=== TLS Certificate Validator ===
File: test_001_valid_cert.txt

PHASE 1: FUNDAMENTAL VALIDITY
✅ CHECK 1:  Version 3
✅ CHECK 2:  Not expired (valid until 2026-02-28)
✅ CHECK 3:  SHA-256 signature
✅ CHECK 4:  RSA 2048-bit key

PHASE 2: IDENTITY VALIDATION
✅ CHECK 5:  Subject DN present
✅ CHECK 6:  SANs present (3 names)
✅ CHECK 7:  Hostname validated

PHASE 3: ACCESS CONTROL
✅ CHECK 8:  Basic Constraints: CA:FALSE (critical)
⚠️ CHECK 9:  Key Usage: Digital Signature, Key Encipherment (optional)
✅ CHECK 10: Extended Key Usage: TLS Web Server Authentication

PHASE 4: REVOCATION
✅ CHECK 11: CRL Distribution Points (2 URLs - 1+ required)
✅ CHECK 12: Authority Info Access present
⚠️ CHECK 13: OCSP URL present (optional)
✅ CHECK 14: Certificate Transparency (2 SCTs)

PHASE 5: CHAIN VALIDATION
✅ CHECK 15: Not self-signed
✅ CHECK 16: Valid serial number (128-bit)
⚠️ CHECK 17: SKI present (recommended)
✅ CHECK 18: AKI present
⚠️ CHECK 19: SKI ≠ AKI (conditional, passed)

PHASE 6: OPERATIONAL
✅ CHECK 20: Validity period: 60 days ≤ 398 days

=====================================
RESULT: VALID ✅
Score: 20/20 checks passed
This certificate meets all requirements for public trust.
```

### Starter Code Structure

**IMPORTANT:** Your solution must implement the `validate_tls_certificate()` function that returns `(fail_list, optional_list)`.

```python
#!/usr/bin/env python3
"""
TLS Certificate Validator
Validates X.509 certificates against 20 critical checks
"""

import re
import sys
from datetime import datetime
from typing import List, Tuple

def validate_tls_certificate(cert_file: str, hostname: str = "") -> Tuple[List[int], List[int]]:
	"""
	Validate TLS certificate against 20-point checklist.
	
	Args:
		cert_file: Path to certificate file in TEXT format (.txt)
		hostname: Expected hostname (e.g., "www.example.com")
	
	Returns:
		Tuple of (fail_list, optional_list):
		- fail_list: List of REQUIRED check numbers that failed (1-20)
		- optional_list: List of OPTIONAL check numbers that failed (1-20)
	
	Example:
		fail_list, optional_list = validate_tls_certificate("cert.txt", "www.example.com")
		# fail_list = [2, 7, 12]      # REQUIRED: expired, hostname mismatch, no AIA
		# optional_list = [9, 13]     # OPTIONAL: Key Usage, OCSP
	"""
	
	# Read certificate file
	with open(cert_file, 'r') as f:
		cert_text = f.read()
	
	# Initialize lists
	fail_list = []  # Checks that failed
	
	# Define optional checks (best practice but not strictly required)
	optional_checks = [9, 13, 17]  # Key Usage, OCSP, SKI
	
	# CHECK 1: Version must be 3 (0x2)
	# TODO: Parse "Version: 3 (0x2)" from cert_text
	# If version != 3: fail_list.append(1)
	
	# CHECK 2: Not expired and not yet valid
	# TODO: Parse "Not Before" and "Not After" dates
	# If expired or not yet valid: fail_list.append(2)
	
	# CHECK 3: Signature algorithm SHA-256 or better
	# TODO: Parse "Signature Algorithm"
	# If SHA-1 or MD5: fail_list.append(3)
	
	# CHECK 4: Key size - RSA ≥2048, ECDSA ≥P-256
	# TODO: Parse "Public Key Algorithm" and key size
	# If weak: fail_list.append(4)
	
	# CHECK 5: Subject DN present (minimal OK if SANs critical)
	# TODO: Parse "Subject" field
	# If empty and SANs not critical: fail_list.append(5)
	
	# CHECK 6: SANs extension present
	# TODO: Check for "X509v3 Subject Alternative Name"
	# If missing: fail_list.append(6)
	
	# CHECK 7: Hostname matches SAN
	# TODO: Check hostname against each SAN, handle wildcards
	# If no match: fail_list.append(7)
	
	# CHECK 8: Basic Constraints CA:FALSE (critical)
	# TODO: Parse "X509v3 Basic Constraints"
	# If CA:TRUE or not critical: fail_list.append(8)
	
	# CHECK 9: Key Usage flags appropriate
	# TODO: Parse "X509v3 Key Usage"
	# Check RSA vs ECDSA requirements, no banned flags
	# If inappropriate: fail_list.append(9)
	
	# CHECK 10: Extended Key Usage includes serverAuth
	# TODO: Parse "X509v3 Extended Key Usage"
	# If missing "TLS Web Server Authentication": fail_list.append(10)
	
	# CHECK 11: CRL Distribution Points present
	# TODO: Check for "X509v3 CRL Distribution Points"
	# If missing: fail_list.append(11)
	
	# CHECK 12: Authority Information Access present
	# TODO: Check for "Authority Information Access"
	# If missing: fail_list.append(12)
	
	# CHECK 13: OCSP URL present in AIA
	# TODO: Check for "OCSP - URI:" in AIA section
	# If missing: fail_list.append(13)
	
	# CHECK 14: Certificate Transparency (≥2 SCTs)
	# TODO: Count "Signed Certificate Timestamp" entries
	# If < 2: fail_list.append(14)
	
	# CHECK 15: Not self-signed
	# TODO: Compare Issuer vs Subject, or check SKI vs AKI
	# If self-signed: fail_list.append(15)
	
	# CHECK 16: Valid serial number (≥64 bits entropy)
	# TODO: Parse "Serial Number" and validate
	# If weak: fail_list.append(16)
	
	# CHECK 17: SKI present (recommended)
	# TODO: Check for "X509v3 Subject Key Identifier"
	# If missing: fail_list.append(17)
	
	# CHECK 18: AKI present
	# TODO: Check for "X509v3 Authority Key Identifier"
	# If missing: fail_list.append(18)
	
	# CHECK 19: SKI ≠ AKI (if both present)
	# TODO: Compare SKI and AKI values
	# If equal: fail_list.append(19)
	
	# CHECK 20: Validity period ≤ 398 days
	# TODO: Calculate validity period from Not Before/After
	# If > 398 days: fail_list.append(20)
	
	# Separate REQUIRED vs OPTIONAL failures
	final_fail_list = []
	final_optional_list = []
	
	for check_num in fail_list:
		if check_num in optional_checks:
			final_optional_list.append(check_num)
		else:
			final_fail_list.append(check_num)
	
	return (sorted(final_fail_list), sorted(final_optional_list))

def main():
	if len(sys.argv) != 3:
		print("Usage: python validate_cert.py <hostname> <certificate.txt>")
		print()
		print("Example:")
		print("  python validate_cert.py www.example.com cert.txt")
		sys.exit(1)
	
	hostname = sys.argv[1]
	cert_file = sys.argv[2]
	
	try:
		fail_list, optional_list = validate_tls_certificate(cert_file, hostname)
		
		print("="*60)
		print("TLS CERTIFICATE VALIDATION RESULTS")
		print("="*60)
		print()
		
		if not fail_list and not optional_list:
			print("✓ All 20 checks PASSED!")
		else:
			if fail_list:
				print(f"✗ REQUIRED failures: {fail_list}")
				print("   These MUST be fixed")
				print()
			
			if optional_list:
				print(f"⚠ OPTIONAL failures: {optional_list}")
				print("   Best practices but not required")
				print()
		
		# Calculate score
		failed_checks = len(fail_list) + len(optional_list)
		passed_checks = 20 - failed_checks
		score = (passed_checks / 20) * 100
		
		print(f"Score: {passed_checks}/20 checks passed ({score:.1f}%)")
		
	except FileNotFoundError:
		print(f"✗ Error: Certificate file not found: {cert_file}")
		sys.exit(1)
	except Exception as e:
		print(f"✗ Error: {e}")
		sys.exit(1)

if __name__ == "__main__":
	main()
```

**Key Requirements:**
1. Function must be named `validate_tls_certificate(cert_file, hostname)`
2. Must return tuple: `(fail_list, optional_list)`
3. Both lists contain check numbers (1-20) that failed
4. Optional checks: 9 (Key Usage), 13 (OCSP), 17 (SKI)

### Automated Grader

Your solution will be graded automatically by comparing your returned `fail_list` and `optional_list` against the reference implementation.

**Grading script:**
```bash
python3 grader.py your_solution.py
```

**Scoring:**
- **Perfect match:** Both `fail_list` and `optional_list` match → 100 points
- **Partial match:** One list matches → 50 points  
- **Mismatch:** Neither list matches → 0 points

**Final grade:** Average score across all 68 test certificates

**Example output:**
```
======================================================================
TLS CERTIFICATE VALIDATOR GRADER
======================================================================

Loading reference: tls_cert_validator.py
✓ Reference loaded
Loading student:   my_validator.py
✓ Student loaded

Found 68 test certificates
======================================================================

Test                                       Status     Required   Optional
----------------------------------------------------------------------
test_001_perfect_cert.txt                  PERFECT    ✓          ✓
test_002_ecdsa_cert.txt                    PERFECT    ✓          ✓
test_006_expired.txt                       PERFECT    ✓          ✓
test_013_hostname_mismatch.txt             PARTIAL    ✓          ✗
test_019_wildcard_root.txt                 FAIL       ✗          ✗
...

======================================================================
SUMMARY
======================================================================

Total Tests:      67
Perfect Matches:  60 (89.6%)
Partial Matches:  5 (7.5%)
Failed:           2 (3.0%)

SCORE: 92.5/100
GRADE: A
```

**Grading scale:**
- **A:** 90-100 (90%+ perfect matches)
- **B:** 80-89
- **C:** 70-79
- **D:** 60-69
- **F:** 0-59

**📖 Get the Files:**

**Exercise Directory:** https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/tls

**Direct Links:**
- 🤖 **Grader:** [grader.py](https://github.com/fosres/SecEng-Exercises/blob/main/cryptography/applied_crypto/tls/grader.py)
- ✅ **Reference Solution:** [tls_cert_validator.py](https://github.com/fosres/SecEng-Exercises/blob/main/cryptography/applied_crypto/tls/tls_cert_validator.py)
- 📁 **Test Certificates:** [test_certs_text/](https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/tls/test_certs_text)

**⚠️ Try implementing yourself first!** The learning comes from struggling through the implementation.

---

### Test Suite

68 test certificates covering:
- ✅ 23 valid certificates (all checks pass)
- ❌ 45 invalid certificates (specific failures)

Each test file shows which check should fail:
- `test_001_valid_complete.txt` - Perfect certificate
- `test_006_expired.txt` - Fails Check 2 (expired)
- `test_028_wrong_eku.txt` - Fails Check 10 (Code Signing instead of Server Auth)
- `test_051_sha1_signature.txt` - Fails Check 3 (SHA-1)
- `test_069_weak_entropy_serial.txt` - Fails Check 16 (only 16-bit serial)

### Parsing Tips

**Parsing hints:**
- Use regular expressions to extract fields from the certificate text
- Look for field names followed by colons and values
- Extensions are prefixed with "X509v3"
- Pay attention to spacing and formatting variations

---

## 🎓 Learning Objectives

By completing this challenge, you'll master:

1. **X.509 Certificate Structure**
   - Version fields and extensions
   - Distinguished Names (DNs) vs Subject Alternative Names (SANs)
   - Public key types and sizes

2. **Certificate Validation Logic**
   - RFC 5280 compliance
   - CA/Browser Forum Baseline Requirements
   - Browser-specific policies

3. **Cryptographic Concepts**
   - Hash algorithm security (SHA-1 vs SHA-256)
   - Key sizes and strength (RSA vs ECDSA)
   - Digital signatures and chain of trust

4. **Real-World Security**
   - Certificate Transparency and public logs
   - Revocation (CRLs vs OCSP)
   - Recent industry changes (Ballot SC63 - March 2024)

5. **Production Best Practices**
   - Comprehensive validation (don't trust partially)
   - Clear error reporting
   - Test-driven development (68 test cases!)

---

## 📚 Additional Resources

### Standards Documents
1. **RFC 5280** - X.509 PKI Certificate and CRL Profile (2008)
   - https://datatracker.ietf.org/doc/html/rfc5280
   - The authoritative standard for X.509 certificates

2. **CA/Browser Forum Baseline Requirements**
   - https://cabforum.org/working-groups/server/baseline-requirements/
   - Current industry requirements (updated quarterly)

3. **CA/Browser Forum Ballot SC63** (March 2024)
   - "Make OCSP optional, require CRLs, and incentivize automation"
   - https://cabforum.org/working-groups/server/baseline-requirements/documents/

### Technical References
4. **Mozilla Root Store Policy**
   - https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/
   - How Firefox validates certificates

5. **Chrome Certificate Transparency Policy**
   - https://googlechrome.github.io/CertificateTransparency/ct_policy.html
   - CT requirements for Chrome

6. **Apple Certificate Transparency Policy**
   - Required for all Apple platforms (iOS, macOS, etc.)

### Security Incidents
7. **DigiNotar Breach (2011)**
   - Why Certificate Transparency was created
   - https://en.wikipedia.org/wiki/DigiNotar

8. **EJBCA Entropy Issue (2019)**
   - Why serial number entropy matters
   - 1M+ certificates revoked

9. **Symantec Distrust (2017-2018)**
   - Why validation matters
   - Google Chrome distrusted 30,000+ certificates

### Solution & Grader
10. **Exercise Files (GitHub Directory)**
    - All exercise materials in one place
    - https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/tls

11. **Reference Solution (Python)**
    - Full implementation with all 20 checks
    - https://github.com/fosres/SecEng-Exercises/blob/main/cryptography/applied_crypto/tls/tls_cert_validator.py
    - Production-quality, RFC 5280 compliant

12. **Automated Grader Script**
    - Compare your solution against reference
    - https://github.com/fosres/SecEng-Exercises/blob/main/cryptography/applied_crypto/tls/grader.py
    - Get instant feedback on correctness

13. **Test Certificates (68 files)**
    - Valid and invalid test cases
    - https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/tls/test_certs_text
    - Covers all 20 validation checks

---

## ⭐ Support This Project

**If you found this exercise valuable, please star the repo!**

🌟 **GitHub Repository:** https://github.com/fosres/SecEng-Exercises

**This Exercise:** https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/tls

**What's in the repo:**
- ✅ Complete TLS Certificate Validator exercise
- ✅ 68 test certificates ([test_certs_text/](https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/tls/test_certs_text))
- ✅ Automated grader script ([grader.py](https://github.com/fosres/SecEng-Exercises/blob/main/cryptography/applied_crypto/tls/grader.py))
- ✅ Reference solution ([tls_cert_validator.py](https://github.com/fosres/SecEng-Exercises/blob/main/cryptography/applied_crypto/tls/tls_cert_validator.py))
- ✅ More security engineering exercises

**Why star the repo?**
- 📚 Get notified of new security exercises
- 🎯 Show appreciation for free, high-quality AppSec content
- 🚀 Help others discover these resources
- 💪 Support open-source security education

**Coming soon:**
- More applied cryptography exercises
- Web application security challenges
- API security validator exercises
- Secure coding challenges

**⭐ Star the repo here:** https://github.com/fosres/SecEng-Exercises

---

## 🚀 Next Steps

### Phase 1: Core Implementation
1. Parse certificate text format
2. Implement all 20 checks
3. Test against valid certificates

### Phase 2: Comprehensive Testing
4. Test against all 68 test certificates
5. Achieve 100% test pass rate
6. Add detailed error messages

### Phase 3: Enhancement
7. Add hostname matching logic (wildcard support)
8. Implement strict vs lenient modes
9. Add JSON output format
10. Create automated grader

### Phase 4: Production Features
11. Support PEM format input (parse using OpenSSL)
12. Chain validation (multiple certificates)
13. Online validation (download CRLs/OCSP)
14. CT log verification

---

## ✅ Success Criteria

Your validator is complete when:

1. ✅ Function `validate_tls_certificate(cert_file, hostname)` implemented
2. ✅ Returns tuple `(fail_list, optional_list)` with check numbers 1-20
3. ✅ All 20 checks implemented correctly
4. ✅ Achieves 90%+ match rate with reference solution
5. ✅ Proper error handling (missing files, malformed inputs)

**Example return values:**
```python
# Perfect certificate
return ([], [])

# Expired certificate with missing AIA
return ([2, 12], [])  # REQUIRED: expired, no AIA

# Missing Key Usage (optional check)
return ([], [9])  # OPTIONAL: Key Usage

# Multiple failures
return ([2, 7, 12], [9, 13])  # REQUIRED: 2,7,12  OPTIONAL: 9,13
```

**Bonus points:**
- Code quality: Clean, well-documented, RFC 5280 citations
- Performance: Process 1000 certificates/second
- Perfect match: 100% accuracy with reference solution

---

## 🎯 Grading Rubric

**Automated grading based on array matching:**

| Grade | Score | Accuracy |
|-------|-------|----------|
| **A** | 90-100 | 90%+ perfect matches with reference |
| **B** | 80-89 | 80%+ perfect matches |
| **C** | 70-79 | 70%+ perfect matches |
| **D** | 60-69 | 60%+ perfect matches |
| **F** | 0-59 | Below 60% |

**Scoring per test:**
- Perfect match (both lists match): 100 points
- Partial match (one list matches): 50 points
- Mismatch (neither list matches): 0 points

**Final score:** Average across all 68 test certificates

**Quick check:**
```bash
# Run grader
python3 grader.py my_validator.py

# Target for A grade:
# SCORE: 92.5/100
# GRADE: A
```

---

## 🎓 Why This Exercise Matters for AppSec Careers

This exercise directly applies to Security Engineering roles at companies like:

**Companies that care about certificate validation:**
- Trail of Bits - Security consulting, tool development
- NCC Group - Pentesting and secure code review
- Anthropic - AI safety, production systems
- GitLab - DevSecOps platform
- Stripe - Payment processing (PCI compliance)
- Coinbase - Cryptocurrency exchange

**Skills demonstrated:**
1. **RFC Compliance** - Reading and implementing standards
2. **Cryptographic Knowledge** - Understanding hash functions, key sizes
3. **Production Security** - Real-world attack prevention
4. **Testing Discipline** - Comprehensive test coverage
5. **Documentation** - Clear technical writing

**Interview topics this covers:**
- "Explain how TLS certificates work"
- "How would you validate a certificate?"
- "What's the difference between CRL and OCSP?"
- "Why did CA/Browser Forum make OCSP optional?"
- "What's Certificate Transparency and why does it matter?"

---

## 🌟 Final Thoughts

Certificate validation is one of those "get it 100% right or users get hacked" problems. By building a production-grade validator, you'll:

- ✅ Understand the security properties browsers rely on
- ✅ Learn from real-world security incidents
- ✅ Gain hands-on cryptography experience
- ✅ Build a portfolio project that impresses security teams

**Most importantly:** You'll never look at that little padlock icon in your browser the same way again! 🔐

Good luck, and happy validating! 🚀

---

## 🎁 One More Thing...

**If this exercise helped you, please ⭐ star the GitHub repo!**

👉 **https://github.com/fosres/SecEng-Exercises**

**Your star:**
- 📣 Helps others discover high-quality AppSec exercises
- 💡 Motivates creation of more security content
- 🎯 Shows recruiters you're serious about AppSec
- 🆓 Supports free, open-source security education

**Get the complete exercise:**
- 📂 **Exercise Directory:** https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/tls
- 📁 **Test Certificates:** [test_certs_text/](https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/tls/test_certs_text)
- 🤖 **Grader:** [grader.py](https://github.com/fosres/SecEng-Exercises/blob/main/cryptography/applied_crypto/tls/grader.py)
- ✅ **Reference:** [tls_cert_validator.py](https://github.com/fosres/SecEng-Exercises/blob/main/cryptography/applied_crypto/tls/tls_cert_validator.py)
- 📚 More AppSec challenges

**Star the repo:** https://github.com/fosres/SecEng-Exercises ⭐

---

**Last Updated:** January 25, 2026  
**Standards Version:** RFC 5280 (2008) + CA/Browser Forum Baseline Requirements v2.0.4+ (including Ballot SC63)
