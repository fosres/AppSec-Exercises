# OAuth Security Testing Guide
**How to Discover Vulnerabilities in OAuth Servers A-F**

## 🎯 Purpose

This guide teaches you HOW to test OAuth servers for security vulnerabilities based on OAuth 2 in Action principles. It does NOT tell you what vulnerabilities exist - you must discover them yourself.

---

## 📚 Required Reading FIRST

Before testing, read these sections in your OAuth 2 in Action book:

1. **Chapter 7**: Client registration and authentication
2. **Chapter 9**: Authorization code security (pages 158-167)
3. **Chapter 10**: Token protection (page 183)
4. **RFC 7636**: PKCE specification

Also review the `OAuth_Security_Testing_Principles.md` file you provided.

---

## 🧪 TESTING METHODOLOGY

### Step 1: Understand Normal Flow

For each server, first understand the **correct** OAuth flow:

```bash
# 1. Start server
python3 oauth_server_a.py

# 2. Make normal authorization request
curl "http://localhost:5001/oauth/authorize?client_id=...&redirect_uri=...&response_type=code&scope=profile"

# 3. Exchange code for token
curl -X POST http://localhost:5001/oauth/token \
  -d "code=...&client_id=...&client_secret=..."

# 4. Use token to access resource
curl http://localhost:5001/api/userinfo \
  -H "Authorization: Bearer ..."
```

Document what SHOULD happen at each step.

### Step 2: Test Boundary Conditions

Based on OAuth 2 in Action principles, test these categories:

---

## 🔍 TEST CATEGORIES

### Category 1: Authorization Code Security

**What to test** (Chapter 9, page 167):

1. **Code Reuse**:
   ```bash
   # Get authorization code once
   CODE="abc123"
   
   # Exchange for token (first time)
   curl -X POST .../token -d "code=$CODE&..."
   
   # Try to reuse SAME code
   curl -X POST .../token -d "code=$CODE&..."
   # Question: Does it work? Should it?
   ```

2. **Code Expiration**:
   ```bash
   # Get code
   CODE="abc123"
   
   # Wait 10 minutes
   sleep 600
   
   # Try to exchange
   curl -X POST .../token -d "code=$CODE&..."
   # Question: Does it still work? Should it?
   ```

3. **Code Binding**:
   ```bash
   # Get code with redirect_uri=A
   curl ".../authorize?redirect_uri=A&..."
   
   # Exchange with redirect_uri=B
   curl -X POST .../token -d "code=$CODE&redirect_uri=B&..."
   # Question: Does it work? Should it?
   ```

---

### Category 2: Redirect URI Validation

**What to test** (Chapter 9, pages 158-167):

1. **Exact Matching**:
   ```bash
   # Registered: https://app.example.com/callback
   
   # Test: Subdirectory traversal
   curl ".../authorize?redirect_uri=https://app.example.com/callback/../../evil"
   
   # Test: Subdomain
   curl ".../authorize?redirect_uri=https://evil.app.example.com/callback"
   
   # Test: @ symbol
   curl ".../authorize?redirect_uri=https://app.example.com@attacker.com"
   
   # Question: Which are accepted? Which should be?
   ```

2. **Error Handling**:
   ```bash
   # Test invalid redirect_uri
   curl ".../authorize?client_id=valid&redirect_uri=http://attacker.com"
   
   # Question: Does it return HTTP 400 or 30x redirect?
   # What SHOULD happen per OAuth 2 in Action Chapter 9, page 167?
   ```

---

### Category 3: PKCE Implementation

**What to test** (Chapter 10, pages 177-183):

1. **Requirement Enforcement**:
   ```bash
   # For public client, try without PKCE
   curl ".../authorize?client_id=public-client&..." # No code_challenge
   
   # Question: Does it work? Should public clients require PKCE?
   ```

2. **Method Validation**:
   ```bash
   # Test 'plain' method
   curl ".../authorize?code_challenge=mysecret&code_challenge_method=plain"
   
   # Question: Is 'plain' accepted? Should it be per RFC 7636?
   ```

3. **Verifier Validation**:
   ```bash
   # Get code with code_challenge=ABC
   
   # Exchange with WRONG code_verifier
   curl -X POST .../token -d "code_verifier=WRONG&..."
   
   # Question: Does it work? Should it?
   ```

---

### Category 4: Scope Enforcement

**What to test** (Chapter 10, page 183):

1. **Authorization Server Validation**:
   ```bash
   # Client registered for scopes: ['read', 'write']
   
   # Request unauthorized scope
   curl ".../authorize?scope=admin+delete+superuser"
   
   # Question: Are unregistered scopes accepted?
   ```

2. **Scope Escalation**:
   ```bash
   # Get code with scope=read
   CODE="..."
   
   # Exchange requesting scope=write+admin
   curl -X POST .../token -d "code=$CODE&scope=write+admin&..."
   
   # Question: Can you escalate scope at token endpoint?
   ```

3. **Resource Server Enforcement**:
   ```bash
   # Get token with scope=read
   TOKEN="..."
   
   # Try DELETE operation (requires scope=delete)
   curl -X DELETE .../api/data -H "Authorization: Bearer $TOKEN"
   
   # Question: Is the operation allowed? Should it be?
   ```

---

### Category 5: Error Handling

**What to test** (Chapter 9, pages 166-167):

1. **Invalid Client**:
   ```bash
   curl ".../authorize?client_id=DOESNOTEXIST&redirect_uri=http://attacker.com"
   
   # Question: HTTP 400 or 30x redirect? What's the security implication?
   ```

2. **Information Disclosure**:
   ```bash
   # Make various error requests
   curl ".../token" -d "code=invalid"
   
   # Question: Do error messages reveal:
   # - Server version?
   # - Database info?
   # - Internal paths?
   # - Stack traces?
   ```

3. **Fragment Leakage**:
   ```bash
   # Check redirect responses
   curl -I ".../authorize?..."
   
   # Question: Are sensitive params in URL fragment (#)?
   # Why does this matter per Chapter 9?
   ```

---

### Category 6: Token Security

**What to test** (Chapter 10, page 183):

1. **Transmission Security**:
   ```bash
   # Try token in URL parameter
   curl ".../api/resource?access_token=TOKEN123"
   
   # Question: Is this accepted? Why is this dangerous?
   ```

2. **Token Lifetime**:
   ```bash
   # Get token
   TOKEN="..."
   
   # Wait 2 hours
   sleep 7200
   
   # Use token
   curl .../api/resource -H "Authorization: Bearer $TOKEN"
   
   # Question: Does it still work? What's the risk?
   ```

3. **Token Storage**:
   ```bash
   # This requires code inspection
   # Open oauth_server_X.py and look at token storage
   
   # Question: Are tokens stored:
   # - In plain text or hashed?
   # - In memory or on disk?
   # - With or without expiration timestamps?
   ```

---

### Category 7: Client Authentication

**What to test** (Chapter 7, page 79):

1. **Authentication Required**:
   ```bash
   # For confidential client, try without secret
   curl -X POST .../token -d "code=...&client_id=...&client_secret="
   
   # Question: Does it work? Should confidential clients require secret?
   ```

2. **Timing Attacks**:
   ```bash
   # Test with different wrong secrets
   for secret in "a" "aa" "aaa" "aaaa"; do
       time curl -X POST .../token -d "client_secret=$secret&..."
   done
   
   # Question: Are response times consistent?
   # Why does this matter?
   ```

3. **Rate Limiting**:
   ```bash
   # Try 100 wrong passwords
   for i in {1..100}; do
       curl -X POST .../token -d "client_secret=wrong$i&..."
   done
   
   # Question: Are you blocked after N attempts?
   ```

---

### Category 8: TLS/HTTPS Enforcement

**What to test** (Chapter 10, page 183):

1. **Endpoint Requirements**:
   ```bash
   # Try HTTP instead of HTTPS
   curl "http://localhost:5006/oauth/token" # Note: HTTP not HTTPS
   
   # Question: Is TLS enforced? Should it be for token endpoint?
   ```

2. **Token Transmission**:
   ```bash
   # Check if server validates request is over TLS
   
   # Question: Does server reject non-TLS token requests?
   # (Local testing uses HTTP, but code should CHECK for TLS)
   ```

---

### Category 9: Dynamic Client Registration

**What to test** (Chapter 7, pages 126-127):

**Only applicable to Server F**

1. **Registration Authentication**:
   ```bash
   # Try to register without credentials
   curl -X POST http://localhost:5006/register \
     -H "Content-Type: application/json" \
     -d '{"redirect_uris":["http://evil.com"]}'
   
   # Question: Is authentication required?
   ```

2. **Redirect URI Validation**:
   ```bash
   # Try to register dangerous URIs
   curl -X POST .../register -d '{
     "redirect_uris": [
       "javascript:alert(1)",
       "data:text/html,<script>...</script>",
       "http://attacker.com"
     ]
   }'
   
   # Question: Are these rejected? Should they be?
   ```

3. **Metadata Sanitization**:
   ```bash
   # Try XSS in client_name
   curl -X POST .../register -d '{
     "client_name": "<script>alert(1)</script>"
   }'
   
   # Question: Is input sanitized?
   ```

---

## 🛠️ BUILDING YOUR SCANNER

### Test Script Template

```python
#!/usr/bin/env python3
"""
OAuth Security Scanner
Tests servers against OAuth 2 in Action principles
"""

import requests
import time

class OAuthScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.results = []
    
    def test_code_reuse(self, code):
        """Test if authorization codes can be reused"""
        # Make token request
        r1 = requests.post(f"{self.base_url}/token", data={
            'code': code,
            # ... other params
        })
        
        # Try SAME code again
        r2 = requests.post(f"{self.base_url}/token", data={
            'code': code,
            # ... same params
        })
        
        if r2.status_code == 200:
            self.results.append({
                'test': 'code_reuse',
                'status': 'VULNERABLE',
                'severity': 'HIGH',
                'principle': 'Authorization Code Security (Ch 9, p.167)',
                'description': 'Authorization code can be reused'
            })
    
    def test_redirect_uri_validation(self, client_id):
        """Test redirect_uri validation strength"""
        test_uris = [
            'http://registered@attacker.com',
            'http://evil.registered.com',
            'http://registered.com/../../evil'
        ]
        
        for uri in test_uris:
            r = requests.get(f"{self.base_url}/authorize", params={
                'client_id': client_id,
                'redirect_uri': uri
            })
            
            if r.status_code == 200 or (r.status_code in [301, 302] and uri in r.headers.get('Location', '')):
                self.results.append({
                    'test': 'redirect_uri_validation',
                    'status': 'VULNERABLE',
                    'severity': 'CRITICAL',
                    'principle': 'Redirect URI Validation (Ch 9, p.158-167)',
                    'description': f'Weak redirect_uri validation: {uri} accepted'
                })
    
    # Add more test methods...
    
    def run_all_tests(self):
        """Run complete security test suite"""
        print(f"Testing {self.base_url}...")
        
        # Run each test category
        self.test_code_reuse()
        self.test_redirect_uri_validation()
        # ... more tests
        
        # Report results
        self.print_report()
    
    def print_report(self):
        """Print test results"""
        print("\n" + "="*70)
        print("OAUTH SECURITY SCAN RESULTS")
        print("="*70)
        
        for result in self.results:
            print(f"\n[{result['severity']}] {result['test']}")
            print(f"  Status: {result['status']}")
            print(f"  Principle: {result['principle']}")
            print(f"  Description: {result['description']}")

# Test all servers
servers = [
    'http://localhost:5001',
    'http://localhost:5002',
    'http://localhost:5003',
    'http://localhost:5004',
    'http://localhost:5005',
    'http://localhost:5006'
]

for server in servers:
    scanner = OAuthScanner(server)
    scanner.run_all_tests()
```

---

## 📝 DOCUMENTATION REQUIREMENTS

For each vulnerability you discover:

1. **Vulnerability Name**: Clear, concise name
2. **Affected Server**: Which server (A-F)
3. **Severity**: CRITICAL / HIGH / MEDIUM / LOW
4. **OAuth 2 in Action Reference**: Chapter and page number
5. **Description**: What the vulnerability is
6. **Proof of Concept**: Command/code to reproduce
7. **Impact**: What an attacker could do
8. **Remediation**: How to fix it

### Example Finding

```markdown
## Vulnerability: Authorization Code Reuse

**Server**: A  
**Severity**: HIGH  
**Reference**: OAuth 2 in Action, Chapter 9, page 167

**Description**:
The server does not delete authorization codes after they are exchanged
for access tokens, allowing codes to be reused multiple times.

**Proof of Concept**:
```bash
# Get code
CODE="abc123"

# Exchange once
curl -X POST http://localhost:5001/oauth/token -d "code=$CODE&..."
# Returns: {"access_token": "token1"}

# Reuse same code
curl -X POST http://localhost:5001/oauth/token -d "code=$CODE&..."
# Returns: {"access_token": "token2"}  ← SHOULD FAIL!
```

**Impact**:
An attacker who intercepts an authorization code can exchange it for
an access token even after the legitimate client has already used it.

**Remediation**:
```python
# Delete code immediately after first use
codes_used = codes.get(code)
if codes_used:
    del codes[code]  # Mark as used
    # ... generate token
```

**Citation**: "Burn the authorization code once it's been used" 
(OAuth 2 in Action, Chapter 9, page 167)
```

---

## ✅ SUCCESS CRITERIA

You've successfully completed testing when you can:

1. ✅ Identify all vulnerabilities in each server
2. ✅ Map each finding to OAuth 2 in Action chapter/page
3. ✅ Explain WHY each is a vulnerability
4. ✅ Provide proof-of-concept exploits
5. ✅ Write remediation recommendations
6. ✅ Build automated scanner detecting all issues

---

## 🎯 LEARNING OBJECTIVES

By testing these 6 servers, you will:

- Master OAuth 2.0 security principles
- Understand real-world vulnerability patterns
- Practice security testing methodology
- Learn to cite security standards
- Build production-quality security tools
- Develop security researcher mindset

**This directly prepares you for:**
- Trail of Bits security engineering interviews
- GitLab AppSec roles
- Stripe security positions
- Anthropic security work
- General Security Engineer roles

---

## 📚 ADDITIONAL RESOURCES

- OAuth 2 in Action (Richer & Sanso)
- RFC 6749 - OAuth 2.0 Framework
- RFC 7636 - PKCE
- RFC 7591 - Dynamic Client Registration
- OWASP API Security Top 10
- PortSwigger OAuth labs (Week 18)

---

**Remember**: The goal is to DISCOVER vulnerabilities yourself using the
OAuth 2 in Action principles. This guide shows you HOW to test, not WHAT
you'll find. Good luck! 🚀
