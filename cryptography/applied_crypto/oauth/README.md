# OAuth 2.0 Security Testing Lab - Complete Package
**6 Vulnerable OAuth Servers + Comprehensive Testing Framework**

## 📦 What You Have

This package contains everything needed for comprehensive OAuth 2.0 security testing practice based on **OAuth 2 in Action** by Justin Richer and Antonio Sanso.

### 🎯 Core Components

1. **6 OAuth Servers** (A through F) - Each with multiple mixed vulnerabilities
2. **Complete Coverage Matrix** - 100% of OAuth 2 in Action principles
3. **Testing Guide** - How to discover vulnerabilities systematically
4. **OAuth Security Principles** - Reference document you provided

---

## 📊 Coverage Statistics

- **Total Servers**: 6 (non-obvious names for discovery-based testing)
- **Total Vulnerabilities**: 77+ distinct security issues
- **OAuth 2 in Action Coverage**: 100% (22/22 core principles)
- **Advanced Features**: Dynamic Client Registration (RFC 7591)
- **Average Vulnerabilities per Server**: 12.8
- **Unique Vulnerability Combinations**: Realistic production scenarios

---

## 🚀 Quick Start

### Step 1: Run All Servers

```bash
# Terminal 1
python3 oauth_server_a.py    # Port 5001

# Terminal 2
python3 oauth_server_b.py    # Port 5002

# Terminal 3
python3 oauth_server_c.py    # Port 5003

# Terminal 4
python3 oauth_server_d.py    # Port 5004

# Terminal 5
python3 oauth_server_e.py    # Port 5005

# Terminal 6
python3 oauth_server_f.py    # Port 5006
```

### Step 2: Read Testing Guide

Open `TESTING_GUIDE.md` - it shows you HOW to test without revealing WHAT you'll find.

### Step 3: Start Testing

Use the methodology in the testing guide to systematically discover vulnerabilities.

### Step 4: Build Your Scanner

Create automated tools to detect all 77+ vulnerabilities across the 6 servers.

---

## 📁 File Descriptions

### OAuth Servers

| File | Port | Description | Vulnerabilities |
|------|------|-------------|-----------------|
| `oauth_server_a.py` | 5001 | Authorization flow, redirect URI issues | 13 issues |
| `oauth_server_b.py` | 5002 | PKCE, public clients, refresh tokens | 14 issues |
| `oauth_server_c.py` | 5003 | Scope enforcement, error handling | 10 issues |
| `oauth_server_d.py` | 5004 | Token storage, timing attacks | 9 issues |
| `oauth_server_e.py` | 5005 | TLS enforcement, transport security | 12 issues |
| `oauth_server_f.py` | 5006 | Dynamic client registration | 19 issues |

**IMPORTANT**: Filenames do NOT reveal the vulnerabilities. You must discover them through testing.

### Documentation

| File | Purpose |
|------|---------|
| `TESTING_GUIDE.md` | How to test servers systematically (no spoilers) |
| `COMPLETE_COVERAGE_MATRIX.md` | Maps all servers to OAuth 2 in Action principles |
| `OAuth_Security_Testing_Principles.md` | Your reference document (OAuth 2 in Action excerpts) |

---

## 🎯 Learning Objectives

By completing this lab, you will:

### Technical Skills

✅ Master OAuth 2.0 security principles from OAuth 2 in Action  
✅ Identify 77+ distinct vulnerability patterns  
✅ Build production-quality automated security scanners  
✅ Perform manual security testing with Burp Suite (Week 18)  
✅ Map findings to industry standards (RFC 6749, 7636, 7591)  
✅ Write professional security reports with citations  

### Interview Preparation

✅ Trail of Bits: Security engineering methodology  
✅ GitLab: AppSec code review and vulnerability analysis  
✅ Stripe: OAuth security and API protection  
✅ Anthropic: Security tooling and automation  
✅ General Security Engineer roles: Comprehensive OAuth knowledge  

---

## 📚 OAuth 2 in Action Principles Covered

### ✅ 100% Coverage Achieved

1. **Authorization Code Security** (Chapter 9, page 167)
   - Single-use enforcement
   - Expiration (60 seconds max)
   - Immediate invalidation after exchange

2. **Redirect URI Validation** (Chapter 9, pages 158-167)
   - Exact matching only
   - Subdirectory attack prevention
   - No partial matching algorithms
   - Domain validation
   - redirect_uri binding

3. **Error Handling Security** (Chapter 9, pages 166-167)
   - HTTP 400 vs 30x redirects
   - Invalid scope handling
   - Invalid client_id handling
   - Fragment leakage prevention
   - Referer header protection

4. **Token Protection** (Chapter 10, page 183)
   - **Transmission**: TLS/HTTPS enforcement
   - **Scopes**: Minimum privilege, validation, enforcement
   - **Storage**: Hashed at auth server, transient at resource server
   - **Lifetimes**: Short tokens, expiration enforcement, refresh rotation

5. **PKCE** (Chapter 10, pages 177-183)
   - Required for public clients
   - S256 method enforcement
   - code_verifier validation
   - Mismatch rejection

6. **Client Authentication** (Chapter 7, page 79)
   - client_secret validation
   - Public vs confidential separation
   - Rate limiting
   - Timing attack resistance

7. **Open Redirector Prevention** (Chapter 9, page 167)
   - Registered URIs only
   - No user input in redirect targets
   - No dangerous URI schemes (javascript:, data:)

8. **Dynamic Client Registration** (Chapter 7, pages 126-127)
   - Registration authentication
   - Redirect URI validation at registration
   - Metadata sanitization
   - Rate limiting

---

## 🛠️ Recommended Workflow

### Week 6 (Current) - Automated Testing

**Day 1-2: Exploration**
- Run all 6 servers
- Document normal OAuth flows
- Identify endpoints and parameters
- Read OAuth 2 in Action chapters 7, 9, 10

**Day 3-4: Discovery**
- Use TESTING_GUIDE.md methodology
- Test each category systematically
- Document findings with citations
- Map to OAuth 2 in Action principles

**Day 5-6: Automation**
- Build comprehensive security scanner
- Detect all 77+ vulnerabilities automatically
- Generate professional security reports
- Create test suite with 60+ test cases

**Day 7: Documentation**
- Write blog post (dev.to)
- Create GitHub repository
- Document findings with OAuth 2 in Action citations
- Share with OWASP LA community

### Week 7 - CSRF Deep Dive

Continue OAuth work, focus on state parameter and CSRF protection patterns.

### Week 13 - Threat Modeling

Apply STRIDE methodology to these OAuth servers:
- Spoofing: Client impersonation
- Tampering: Code/token modification
- Repudiation: Audit log analysis
- Information Disclosure: Error messages, debug endpoints
- Denial of Service: Rate limiting
- Elevation of Privilege: Scope escalation

### Week 18 - Manual Exploitation

Use Burp Suite to:
- Intercept OAuth flows
- Modify authorization codes
- Test timing attacks manually
- Perform PortSwigger OAuth labs
- Compare automated vs manual testing

---

## 🎓 Interview Story Template

> "I built a comprehensive OAuth security testing lab with 6 servers containing 77+ distinct vulnerabilities covering 100% of OAuth 2 in Action security principles. Each server has 10-19 mixed vulnerabilities including authorization code reuse, weak redirect URI validation, PKCE bypasses, scope escalation, timing attacks, and TLS enforcement issues.
> 
> I created automated scanners to detect all 22 core OAuth security principles plus dynamic client registration vulnerabilities. The project demonstrates:
> 
> - **Security Testing**: Systematic vulnerability discovery methodology
> - **Automation**: Production-quality Python security tools
> - **Standards Knowledge**: Deep understanding of RFC 6749, 7636, 7591
> - **Documentation**: Professional security reports with OAuth 2 in Action citations
> - **Threat Modeling**: STRIDE analysis applied to OAuth implementations
> 
> This directly prepared me for security engineering work at Trail of Bits, GitLab, Stripe, and similar companies requiring OAuth expertise."

---

## 📊 Competitive Advantage

### What Makes This Lab Unique

**Compared to PortSwigger Labs**:
- ✅ Multiple vulnerabilities per server (realistic)
- ✅ Mixed security issues (not one-topic-per-lab)
- ✅ Automated testing focus (Week 6 appropriate)
- ✅ Complete local control (modify servers, experiment)

**Compared to Single Vulnerable Server**:
- ✅ 6 different implementations (real-world variety)
- ✅ 77+ vulnerabilities vs 6-10
- ✅ Non-obvious naming (discovery-based learning)
- ✅ Production-like scenarios

**Compared to Secure Implementations**:
- ✅ Hands-on vulnerability exploitation
- ✅ Understanding what goes wrong (not just what's right)
- ✅ Building security mindset through attack techniques

---

## ⚠️ Important Notes

### Legal & Ethical

**ONLY test against**:
- ✅ These local OAuth servers (localhost)
- ✅ Your own deployments
- ✅ Systems with explicit written permission

**NEVER test against**:
- ❌ Google OAuth (or any production OAuth server)
- ❌ GitHub OAuth
- ❌ Any system without permission
- ❌ Company systems without authorization

**Unauthorized testing is illegal** (Computer Fraud and Abuse Act).

### TLS Testing Note

The servers run on HTTP (localhost) for development. Server E demonstrates TLS checking logic even though actual HTTPS requires deployment. This is acceptable for learning - in production, OAuth MUST use HTTPS.

---

## 🚀 Next Steps

1. **Immediate** (Week 6):
   - Run all servers
   - Complete TESTING_GUIDE.md exercises
   - Build automated scanner
   - Document findings

2. **Short-term** (Weeks 7-10):
   - Fix vulnerabilities in one server
   - Create secure reference implementation
   - Write dev.to blog series
   - Share on GitHub

3. **Medium-term** (Weeks 11-18):
   - System design: Design secure OAuth at scale
   - Manual testing: Burp Suite + PortSwigger labs
   - Threat modeling: STRIDE analysis

4. **Long-term** (Weeks 19-24):
   - Mock interviews covering OAuth security
   - Contribute to open source OAuth projects
   - Apply OAuth knowledge to job applications

---

## 📧 Using This in Job Applications

### Resume Bullet Point

> "Built comprehensive OAuth 2.0 security testing lab with 6 servers containing 77+ vulnerabilities; created automated scanner detecting 100% of OAuth 2 in Action security principles including authorization code reuse, redirect URI validation, PKCE bypasses, scope enforcement, and timing attacks."

### GitHub Repository Description

> "Production OAuth 2.0 security testing lab for discovering and exploiting vulnerabilities based on OAuth 2 in Action. Includes 6 intentionally vulnerable servers, comprehensive testing framework, and automated security scanner. Covers all 22 core security principles plus dynamic client registration."

### Blog Post Title Ideas

1. "Building an OAuth Security Testing Lab: 100% Coverage of OAuth 2 in Action"
2. "I Found 77 OAuth Vulnerabilities in 6 Servers - Here's How"
3. "From Zero to OAuth Security Expert: A Hands-On Journey"
4. "Automated OAuth Security Testing: Detecting 22 Vulnerability Patterns"

---

## ✅ Success Metrics

You've mastered this lab when you can:

- [ ] Run all 6 servers simultaneously
- [ ] Discover all 77+ vulnerabilities through testing
- [ ] Map each finding to OAuth 2 in Action chapter/page
- [ ] Build automated scanner with 60+ test cases
- [ ] Explain why each vulnerability matters
- [ ] Provide proof-of-concept exploits
- [ ] Write remediation recommendations
- [ ] Apply STRIDE threat modeling
- [ ] Perform manual exploitation with Burp Suite
- [ ] Confidently discuss OAuth security in interviews

---

## 🎯 Final Thoughts

This lab represents **100% coverage of OAuth 2 in Action security principles**. It's designed to be:

- **Realistic**: Multiple vulnerabilities per server (like production)
- **Educational**: Discovery-based learning (not cookbook answers)
- **Comprehensive**: All 22 core principles + advanced features
- **Practical**: Builds automation skills employers value
- **Interview-Ready**: Demonstrates security engineering competency

**You now have everything needed to become an OAuth security expert.** 🚀

Good luck with your Week 6 security testing practice!

---

*Package Version: 1.0*  
*Created: February 5, 2026*  
*OAuth 2 in Action Coverage: 100%*  
*Total Vulnerabilities: 77+*
