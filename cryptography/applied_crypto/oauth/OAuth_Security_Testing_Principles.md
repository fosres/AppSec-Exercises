# OAuth 2.0 Security Testing Principles
*Source: OAuth 2 in Action by Justin Richer and Antonio Sanso*

## Core Security Principles

### 1. Authorization Code Security (Chapter 9)

#### Single-Use Authorization Codes
**Principle**: Burn the authorization code once it's been used.

**Testing Requirements**:
- ✅ Verify authorization codes can only be exchanged for tokens once
- ✅ Test that reusing an authorization code results in error
- ✅ Validate proper code expiration mechanisms
- ✅ Ensure used codes are immediately invalidated

**Citation**: OAuth 2 in Action, Chapter 9, page 167

---

### 2. Redirect URI Validation (Chapter 9)

#### Exact Matching Only
**Principle**: Exact matching is the ONLY safe validation method for redirect_uri that the authorization server should adopt.

**Testing Requirements**:
- ✅ Test that authorization server rejects redirect URIs that don't exactly match registered URIs
- ✅ Verify rejection of subdirectory navigation attacks (e.g., `../../attacker.html`)
- ✅ Ensure partial matching algorithms are disabled
- ✅ Test against domain variations and typosquatting

**Example Vulnerable Pattern to Test Against**:
```
Registered URI: https://theoauthclient.com/oauth/oauthprovider/callback
Attack URI: https://theoauthclient.com/oauth/oauthprovider/callback/../../usergeneratedcontent/attackerpage.html
```

**Result**: Must reject the attack URI even though it contains the registered path.

**Citation**: OAuth 2 in Action, Chapter 9, pages 158-167

---

### 3. Error Handling Security (Chapter 9)

#### Preventing Open Redirector Vulnerabilities
**Principle**: Respond with HTTP 400 (Bad Request) rather than redirecting to unvalidated URIs.

**Testing Requirements**:
- ✅ Test invalid scope requests return HTTP 400, not 30x redirect
- ✅ Verify invalid client_id returns HTTP 400, not 30x redirect
- ✅ Ensure malformed redirect_uri returns HTTP 400, not 30x redirect
- ✅ Validate that errors don't leak through URL fragments
- ✅ Test that sensitive info doesn't leak through Referer headers

**Mitigation Tests**:
1. Redirect to intermediate URI under authorization server control to clear Referer information
2. Append '#' to error redirect URI to prevent browser fragment reattachment
3. Return HTTP 400 for suspicious requests

**Citation**: OAuth 2 in Action, Chapter 9, pages 166-167

---

### 4. Token Protection (Chapter 10)

#### Transmission Security
**Principle**: Transmission of access tokens must be protected using secure transport layer mechanisms such as TLS.

**Testing Requirements**:
- ✅ Verify all token endpoints require HTTPS/TLS
- ✅ Test that tokens are rejected over non-TLS connections
- ✅ Validate proper TLS certificate verification
- ✅ Ensure no tokens in URL query parameters (use headers/body only)

**Citation**: OAuth 2 in Action, Chapter 10, page 183

---

#### Minimum Privilege (Conservative Scopes)
**Principle**: The client should ask for the minimum information needed (be conservative with the scope set).

**Testing Requirements**:
- ✅ Verify clients cannot request more scopes than registered
- ✅ Test scope validation at authorization server
- ✅ Ensure resource server enforces scope restrictions
- ✅ Validate scope downscoping works correctly

**Citation**: OAuth 2 in Action, Chapter 10, page 183

---

#### Token Storage at Authorization Server
**Principle**: The authorization server should store hashes of the access token instead of clear text.

**Testing Requirements**:
- ✅ Verify tokens are hashed before database storage
- ✅ Test token introspection uses hash comparison
- ✅ Validate proper hashing algorithms (e.g., SHA-256 minimum)
- ✅ Ensure database compromise doesn't expose usable tokens

**Citation**: OAuth 2 in Action, Chapter 10, page 183

---

#### Short Token Lifetimes
**Principle**: The authorization server should keep access token lifetime short in order to minimize the risk associated with the leak of a single access token.

**Testing Requirements**:
- ✅ Verify token expiration is enforced
- ✅ Test expired tokens are rejected by resource server
- ✅ Validate refresh token rotation mechanisms
- ✅ Ensure reasonable token lifetimes (e.g., 15 minutes for access tokens)

**Citation**: OAuth 2 in Action, Chapter 10, page 183

---

#### Token Storage at Resource Server
**Principle**: The resource server should keep access tokens in transient memory.

**Testing Requirements**:
- ✅ Verify tokens are not persisted to disk by resource server
- ✅ Test tokens are not logged in clear text
- ✅ Validate tokens are cleared from memory after validation
- ✅ Ensure no token caching beyond request scope

**Citation**: OAuth 2 in Action, Chapter 10, page 183

---

### 5. PKCE (Proof Key for Code Exchange) (Chapter 10)

#### Authorization Code Protection
**Principle**: PKCE may be used to increase the safety of authorization codes.

**Testing Requirements**:
- ✅ Verify code_challenge is required for public clients
- ✅ Test both 'plain' and 'S256' code_challenge_method
- ✅ Validate code_verifier matches original code_challenge
- ✅ Ensure mismatched verifier/challenge pairs are rejected

**Implementation Test**:
```python
# Test S256 PKCE validation
if code.request.code_challenge_method == 'S256':
	code_challenge = base64url.fromBase64(
		crypto.createHash('sha256')
		.update(req.body.code_verifier)
		.digest('base64')
	)
	
	if code.request.code_challenge != code_challenge:
		# Must return error
		res.status(400).json({error: 'invalid_request'})
```

**Citation**: OAuth 2 in Action, Chapter 10, pages 177-183

---

### 6. Client Authentication (Chapter 7)

#### Client ID and Secret Validation
**Principle**: Invalid client credentials should be detected and handled securely.

**Testing Requirements**:
- ✅ Test invalid client_id returns appropriate error (no redirect)
- ✅ Verify client_secret validation for confidential clients
- ✅ Ensure public clients cannot use confidential client credentials
- ✅ Test rate limiting on authentication attempts

**Citation**: OAuth 2 in Action, Chapter 7, page 79

---

### 7. Open Redirector Prevention (Chapter 9)

#### Monitored Redirects Only
**Principle**: Implementing the OAuth core specification verbatim might lead to the authorization server acting as an open redirector. If this is a properly monitored redirector, this is fine, but it might pose threats if implemented naively.

**Testing Requirements**:
- ✅ Verify all redirects are to registered URIs only
- ✅ Test monitoring/logging of redirect destinations
- ✅ Validate no unvalidated user input in redirect targets
- ✅ Ensure no redirects to data: or javascript: URIs

**Citation**: OAuth 2 in Action, Chapter 9, page 167

---

## Security Testing Workflow

### Phase 1: Pre-Authorization Testing
1. Test client registration validation
2. Verify redirect URI exact matching
3. Test invalid client_id handling
4. Validate scope request limits

### Phase 2: Authorization Flow Testing
1. Test authorization code generation
2. Verify PKCE implementation (if applicable)
3. Test authorization code single-use enforcement
4. Validate proper error responses (HTTP 400 vs redirects)

### Phase 3: Token Exchange Testing
1. Test authorization code validation
2. Verify PKCE verifier validation (if applicable)
3. Test client authentication
4. Validate token generation and storage (hashed)

### Phase 4: Token Usage Testing
1. Test TLS enforcement at resource server
2. Verify token expiration enforcement
3. Test scope enforcement at resource server
4. Validate token introspection accuracy

### Phase 5: Security Attack Testing
1. Test authorization code replay attacks
2. Verify redirect URI manipulation resistance
3. Test token replay attacks
4. Validate against known OAuth vulnerabilities (OWASP API Top 10)

---

## Common Vulnerabilities to Test Against

### 1. Redirect URI Manipulation (Chapter 9, pages 158-167)
- Directory traversal in redirect URI
- Subdomain takeover attacks
- Open redirect via partial matching

### 2. Authorization Code Reuse (Chapter 9)
- Code replay attacks
- Stolen code usage
- Race conditions in code validation

### 3. Token Leakage
- Tokens in URL query parameters
- Tokens in logs or error messages
- Tokens transmitted over non-TLS connections

### 4. Information Disclosure
- Fragment leakage of tokens/codes
- Referer header leakage
- Error messages revealing system details

---

## Additional Security Recommendations

### Dynamic Client Registration (Chapter 7)
**Testing Requirements**:
- ✅ Verify registration endpoint authentication
- ✅ Test redirect URI validation at registration
- ✅ Validate client metadata sanitization
- ✅ Ensure rate limiting on registration attempts

**Citation**: OAuth 2 in Action, Chapter 7, pages 126-127

---

### Proof of Possession Tokens (Chapter 15)
**Advanced Security Testing**:
- ✅ Verify client key pair generation
- ✅ Test JWT signature validation
- ✅ Validate token binding to client
- ✅ Ensure token introspection returns public key

**Citation**: OAuth 2 in Action, Chapter 15, pages 264-280

---

## Testing Tools and Approaches

### Automated Testing
- Unit tests for token validation logic
- Integration tests for complete OAuth flows
- Security regression tests in CI/CD pipeline

### Manual Testing
- Penetration testing with tools like Burp Suite
- jwt_tool for JWT/token analysis
- Custom scripts for flow validation

### Continuous Monitoring
- Log analysis for suspicious patterns
- Rate limiting effectiveness validation
- Token lifetime and usage pattern analysis

---

## Summary: Critical Security Principles

From OAuth 2 in Action, Chapter 10, page 183:

> **The Five Pillars of OAuth Token Security:**
> 1. TLS for all token transmission
> 2. Conservative scope requests (minimum necessary)
> 3. Hashed token storage at authorization server
> 4. Short token lifetimes
> 5. Transient token storage at resource server
>
> **Plus:** PKCE for authorization code protection in public clients

These principles form the foundation of secure OAuth 2.0 implementations and should be validated through comprehensive automated and manual testing.

---

*Document Version: 1.0*  
*Last Updated: February 5, 2026*  
*Compiled for Week 6 OAuth Security Curriculum*
