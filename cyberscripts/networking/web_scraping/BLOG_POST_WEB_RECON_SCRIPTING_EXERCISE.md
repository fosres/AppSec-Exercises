---
title: "Week 4 Scripting Exercise: Build a Web Reconnaissance Report Generator"
published: false
description: "Build a Python tool to scrape security-relevant information from websites - HTTP headers, cookies, server versions, security configurations. A practical exercise from Grace Nolan's Security Engineering Interview Notes."
tags: appsec, security, python, scripting
---

# Week 4 Scripting Exercise: Build a Web Reconnaissance Report Generator

**Time:** 2-4 hours  
**Type:** Free-response scripting project  
**Skills:** HTTP Protocol, Python requests/parsing, Security Headers, Cookie Analysis  

---

## 🎯 The Challenge

From **Grace Nolan's Security Engineering Interview Notes**:

> "**Web scrapers** - Write a script to scrape information from a website."

Your task: Build a Python script that performs passive reconnaissance on a target URL and generates a security-focused report.

This is the **discovery phase** of security assessments - understanding what you're looking at before testing anything.

---

> ⭐ **This exercise is part of my open-source Security Engineering curriculum.**
> 
> If you find this helpful, **[star the repo on GitHub](https://github.com/fosres)** to support the project and get notified when new exercises drop!

---

## Background Reading

Before you start coding, review these concepts:

### From Grace Nolan's Notes (Networking Section)

**HTTP Response Headers contain:**
- Status codes (1xx informational, 2xx success, 3xx redirect, 4xx client error, 5xx server error)
- Content type and encoding
- Server identification

**Cookies:**
- `HttpOnly` - cannot be accessed by JavaScript (XSS mitigation)
- `Secure` - only sent over HTTPS
- `SameSite` - CSRF protection (Strict, Lax, None)

### From Hacking APIs, Chapter 6: Discovery (pp. 125-147)

The passive reconnaissance process has three phases:

1. **Cast a Wide Net** - Gather general information about the target
2. **Adapt and Focus** - Refine based on findings
3. **Document the Attack Surface** - Record everything useful

Key quote:
> "Taking notes is crucial to performing an effective attack. Document and take screen captures of all interesting findings."

### From Full Stack Python Security

**Chapter 7 (pp. 86-89)** - HTTP Cookies:
- Cookies are sent via `Set-Cookie` response header
- Session IDs are commonly stored in cookies
- The `Secure` directive prevents transmission over HTTP
- The `Domain` directive controls which domains receive the cookie

**Chapter 14 (pp. 222-224)** - Security Response Headers:
- `HttpOnly` hides cookies from JavaScript (`document.cookie`)
- `X-Content-Type-Options: nosniff` prevents MIME sniffing attacks
- Missing security headers are common findings in assessments

### From API Security in Action, Chapter 5 (pp. 151-153)

**CORS Headers:**
- `Access-Control-Allow-Origin` - Which origins can access resources
- `Access-Control-Allow-Credentials` - Whether cookies are sent
- Wildcard (`*`) with credentials is a security misconfiguration

---

## Your Assignment

Build a Python script called `web_recon.py` that:

1. **Takes a URL as input** (command line argument or user prompt)
2. **Makes an HTTP request** to the target
3. **Extracts and displays** the following information:

---

### Part 1: Basic Response Information

Extract and display:

```
═══ RESPONSE STATUS ═══
Status Code: 200
Status Message: OK
HTTP Version: HTTP/1.1
Response Time: 0.234 seconds
```

**Why this matters:** Status codes reveal application behavior. A 403 vs 404 can indicate whether a resource exists.

---

### Part 2: Server Information (Technology Fingerprinting)

Look for headers that reveal server technology and **display their values**:

```
═══ SERVER INFORMATION ═══
Server: nginx/1.18.0
X-Powered-By: PHP/7.4.3
X-AspNet-Version: (not present)
X-Generator: WordPress 5.8
X-Drupal-Cache: (not present)
```

**Headers to check:**
- `Server`
- `X-Powered-By`
- `X-AspNet-Version`
- `X-Generator`
- `X-Drupal-Cache`
- `X-Varnish`

**Why this matters:** These headers reveal what software is running. Security analysts can then search for CVEs affecting those versions.

> **Note:** Just report if these headers exist and show their values. Let the human analyst assess the risk - that's what real recon tools do.

---

### Part 3: Security Headers Analysis

Check for presence/absence of security headers:

```
═══ SECURITY HEADERS ═══
X-Frame-Options: DENY ✓
X-Content-Type-Options: nosniff ✓
X-XSS-Protection: (not present) ⚠️
Strict-Transport-Security: max-age=31536000; includeSubDomains ✓
Content-Security-Policy: (not present) ⚠️
Referrer-Policy: strict-origin-when-cross-origin ✓
Permissions-Policy: (not present) ⚠️

Security Header Score: 4/7
```

**Headers to check:**

| Header | Purpose | Risk if Missing |
|--------|---------|-----------------|
| `X-Frame-Options` | Prevents clickjacking | Clickjacking attacks |
| `X-Content-Type-Options` | Prevents MIME sniffing | Content type attacks |
| `X-XSS-Protection` | Browser XSS filter | XSS (legacy browsers) |
| `Strict-Transport-Security` | Enforces HTTPS | Downgrade attacks |
| `Content-Security-Policy` | Controls resource loading | XSS, injection |
| `Referrer-Policy` | Controls referrer info | Information leakage |
| `Permissions-Policy` | Controls browser features | Privacy issues |

---

### Part 4: Cookie Analysis

Parse all `Set-Cookie` headers and analyze security attributes:

```
═══ COOKIES ═══
Cookie 1: session
  Value: abc123...def (truncated)
  HttpOnly: ✓ Yes
  Secure: ✓ Yes
  SameSite: Strict
  Domain: .example.com
  Path: /
  Max-Age: 86400 (1 day)

Cookie 2: tracking_id
  Value: xyz789
  HttpOnly: ✗ No ⚠️
  Secure: ✗ No ⚠️
  SameSite: (not set) ⚠️
  
⚠️  FINDING: Cookie 'tracking_id' missing HttpOnly - vulnerable to XSS theft
⚠️  FINDING: Cookie 'tracking_id' missing Secure - sent over HTTP
⚠️  FINDING: Cookie 'tracking_id' missing SameSite - CSRF risk
```

**Cookie attributes to extract:**
- Name and value (truncate long values)
- `HttpOnly` flag (boolean)
- `Secure` flag (boolean)
- `SameSite` value (Strict/Lax/None or not set)
- `Domain` scope
- `Path` scope
- `Max-Age` or `Expires`

---

### Part 5: CORS Configuration

Check for CORS headers and potential misconfigurations:

```
═══ CORS CONFIGURATION ═══
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization

🚨 CRITICAL: Wildcard origin (*) with Allow-Credentials is a security vulnerability!
```

**CORS security rules:**
- `*` origin with `credentials: true` = **CRITICAL vulnerability**
- Overly permissive methods (DELETE, PUT) = **note for testing**

---

### Part 6: Additional Reconnaissance

Extract any other useful information:

```
═══ ADDITIONAL INFORMATION ═══
Content-Type: text/html; charset=utf-8
Content-Length: 45678
Content-Encoding: gzip
Cache-Control: no-cache, no-store
ETag: "abc123"

Interesting Headers Found:
- X-Request-ID: req-12345 (useful for log correlation)
- X-RateLimit-Remaining: 99 (rate limiting detected)
- Via: 1.1 proxy.example.com (proxy detected)
```

---

### Part 7: Generate Summary Report

End with an executive summary:

```
═══════════════════════════════════════════════════════════════
                    RECONNAISSANCE SUMMARY
═══════════════════════════════════════════════════════════════
Target: https://example.com
Scan Time: 2026-01-03 10:30:00 UTC

FINDINGS:
🚨 CRITICAL (1):
   - CORS misconfiguration: wildcard with credentials

⚠️  MEDIUM (3):
   - Missing Content-Security-Policy header
   - Cookie 'tracking_id' missing HttpOnly
   - Missing X-Frame-Options header

ℹ️  INFO (4):
   - Server: nginx/1.18.0
   - X-Powered-By: PHP/7.4.3
   - Rate limiting detected
   - Proxy detected in request path

SECURITY HEADER SCORE: 4/7 (57%)
COOKIE SECURITY SCORE: 1/2 cookies properly secured (50%)

RECOMMENDED NEXT STEPS:
1. Search for CVEs: nginx 1.18.0, PHP 7.4.3
2. Test for clickjacking (X-Frame-Options present)
3. Test XSS vectors (no CSP)
4. Test CSRF on state-changing operations
═══════════════════════════════════════════════════════════════
```

---

## Example Output

When run against a target, your script should produce output similar to:

```
$ python3 web_recon.py https://example.com

[*] Starting reconnaissance on: https://example.com
[*] Time: 2026-01-03T10:30:00Z

═══ RESPONSE STATUS ═══
Status Code: 200
Status Message: OK
Response Time: 0.342s

═══ SERVER INFORMATION ═══
Server: ECS (dcb/7F84)
X-Powered-By: (not present)

═══ SECURITY HEADERS ═══
X-Frame-Options: (not present) ⚠️
X-Content-Type-Options: (not present) ⚠️
Strict-Transport-Security: (not present) ⚠️
Content-Security-Policy: (not present) ⚠️

Security Header Score: 0/7

═══ COOKIES ═══
No cookies set.

═══ CORS CONFIGURATION ═══
No CORS headers present.

═══ RECONNAISSANCE SUMMARY ═══
Target: https://example.com
Findings: 4 missing security headers
Recommendation: Review security header configuration
```

---

## Scoring Rules

### Cookie Security Score

Each cookie is scored out of **3 points**:

| Attribute | Points | Rule |
|-----------|--------|------|
| `HttpOnly` | 1 | Present = 1 point, Missing = 0 |
| `Secure` | 1 | Present = 1 point, Missing = 0 |
| `SameSite` | 1 | `Strict` or `Lax` = 1 point, `None` or missing = 0 |

**Cookie Security Score** = (Total points earned) / (Total possible points) × 100%

**Example:**
```
Cookie 1: session    → HttpOnly ✓, Secure ✓, SameSite=Strict ✓  → 3/3
Cookie 2: tracking   → HttpOnly ✗, Secure ✓, SameSite ✗         → 1/3
Cookie 3: preference → HttpOnly ✗, Secure ✗, SameSite=Lax ✓     → 1/3

Total: 5/9 = 55.6%
Cookie Security Score: 55.6%
```

---

### Security Header Score

Score out of **7 points** (1 point per header present):

| Header | Points |
|--------|--------|
| `X-Frame-Options` | 1 |
| `X-Content-Type-Options` | 1 |
| `X-XSS-Protection` | 1 |
| `Strict-Transport-Security` | 1 |
| `Content-Security-Policy` | 1 |
| `Referrer-Policy` | 1 |
| `Permissions-Policy` | 1 |

**Security Header Score** = Headers present / 7 × 100%

---

### Finding Severity Levels

Use these rules to categorize each finding:

#### 🚨 CRITICAL

| Finding | Condition |
|---------|-----------|
| CORS misconfiguration | `Access-Control-Allow-Origin: *` AND `Access-Control-Allow-Credentials: true` both present |

#### ⚠️ MEDIUM

| Finding | Condition |
|---------|-----------|
| Missing Content-Security-Policy | `Content-Security-Policy` header not present |
| Missing HSTS | `Strict-Transport-Security` header not present (HTTPS sites only) |
| Missing X-Frame-Options | `X-Frame-Options` header not present |
| Missing X-Content-Type-Options | `X-Content-Type-Options` header not present |
| Cookie missing HttpOnly | Any cookie where `HttpOnly` is not set |
| Cookie missing Secure | Any cookie where `Secure` is not set (HTTPS sites only) |
| Cookie missing SameSite | Any cookie without `SameSite` attribute or with `SameSite=None` |

#### ℹ️ INFO

| Finding | Condition |
|---------|-----------|
| Server header present | `Server` header exists - display its value |
| X-Powered-By present | `X-Powered-By` header exists - display its value |
| Technology fingerprint | `X-Generator`, `X-AspNet-Version`, `X-Drupal-Cache`, etc. present |
| Rate limiting detected | `X-RateLimit-*` or `RateLimit-*` headers present |
| Proxy detected | `Via` or `X-Forwarded-*` headers present |
| CDN detected | `X-Cache`, `CF-Ray`, `X-Served-By`, or similar headers present |
| Missing X-XSS-Protection | `X-XSS-Protection` header not present (deprecated header) |
| Missing Permissions-Policy | `Permissions-Policy` header not present |
| Missing Referrer-Policy | `Referrer-Policy` header not present |

> **Why is server version INFO and not HIGH?**
> 
> Detecting version numbers like `nginx/1.18.0` vs `nginx` requires regex pattern matching. We're keeping this exercise focused on HTTP fundamentals and string parsing. Just report what you find - security analysts know to look up CVEs for any versions shown.

---

### Example Severity Classification

```
Target: https://example.com

🚨 CRITICAL (0):
   (none)

⚠️  MEDIUM (5):
   - Missing Content-Security-Policy header
   - Missing Strict-Transport-Security header
   - Cookie 'tracking' missing HttpOnly
   - Cookie 'tracking' missing SameSite attribute
   - Missing X-Frame-Options header

ℹ️  INFO (4):
   - Server: nginx/1.18.0
   - X-Powered-By: PHP/7.4.3
   - CDN detected: Cloudflare (CF-Ray header)
   - Missing Permissions-Policy header
```

---

## Grading Criteria

Your script will be evaluated on:

| Criteria | Points |
|----------|--------|
| Successfully fetches URL and handles errors | 10 |
| Extracts status code, message, response time | 10 |
| Reports server information headers | 15 |
| Checks all 7 security headers | 15 |
| Parses cookies with all attributes | 20 |
| Detects CORS misconfigurations | 15 |
| Generates clear, readable summary | 10 |
| Code quality and error handling | 5 |
| **Total** | **100** |

---

## Bonus Challenges

Once your basic script works:

1. **Add robots.txt fetching** - Check for `/robots.txt` and list disallowed paths
2. **Check multiple URLs** - Accept a file of URLs to scan
3. **Export to JSON** - Save findings in structured format
4. **Compare to baseline** - Load a "known good" config and diff against it

---

## Submission

When complete, your deliverables should include:

1. `web_recon.py` - Your Python script
2. Sample output from running against 2-3 real websites
3. Brief notes on any interesting findings

---

## Resources

### Primary Sources
- **Grace Nolan's Notes**: https://github.com/gracenolan/Notes
- **Hacking APIs** (Corey Ball) - Chapter 6: Discovery
- **Full Stack Python Security** - Chapters 7 and 14
- **API Security in Action** - Chapter 5

### Reference Documentation
- [MDN: HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Python requests library](https://docs.python-requests.org/)

### Tools to Compare Against
- [SecurityHeaders.com](https://securityheaders.com/) - Online header scanner
- [Mozilla Observatory](https://observatory.mozilla.org/) - Comprehensive scanner

---

## Why This Matters

This exercise builds skills directly applicable to:

- **Bug Bounty Hunting**: Reconnaissance is the first step in finding vulnerabilities
- **Penetration Testing**: Discovery phase of every engagement
- **Security Auditing**: Automated header/cookie policy checking
- **Security Engineering Interviews**: Grace Nolan specifically lists this as a coding challenge

As noted in Hacking APIs:
> "Taking notes is crucial to performing an effective attack. Document and take screen captures of all interesting findings."

Your script automates this documentation process.

---

## 🌟 Found This Helpful?

This exercise is part of my **48-Week Security Engineering Curriculum** - a complete roadmap from networking fundamentals to landing a Security Engineering role.

**[⭐ Star the repo on GitHub](https://github.com/fosres)** to:
- Support the project
- Get notified when new exercises drop
- Help others discover these resources

The curriculum includes:
- 📚 Weekly study guides with page-by-page reading assignments
- 🛠️ Hands-on scripting exercises (like this one!)
- 🎯 PortSwigger lab progressions
- 📝 Interview prep from Grace Nolan's notes

**[Check it out →](https://github.com/fosres)**

---

## Share Your Results!

Built your recon tool? I'd love to see it!

- Tweet your output with **#SecurityEngineering** and tag me
- Open a PR to add your solution to the community solutions folder
- Post interesting findings (from authorized testing only!) in the discussions

---

*Week 4 of the 48-Week Security Engineering Curriculum: Linux Security + Python Files*
