# OAuth 2.0 Authorization Code + PKCE Flow Diagram
## Secure System Design Interview Ready

Based on OAuth 2 in Action Listings 1-6 (Richer & Sanso, 2017)

---

## The Complete Flow: All 4 Actors

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐
│             │     │              │     │                  │     │                  │
│    USER     │     │    CLIENT    │     │   AUTH SERVER    │     │   RESOURCE       │
│ (Resource   │     │   (Mobile    │     │   (Okta, Auth0,  │     │   SERVER         │
│  Owner)     │     │    App/SPA)  │     │    Google)       │     │   (Your API)     │
│             │     │              │     │                  │     │                  │
└──────┬──────┘     └──────┬───────┘     └────────┬─────────┘     └────────┬─────────┘
       │                   │                      │                        │
       │                   │                      │                        │
       │  1. Click         │                      │                        │
       │     "Login"       │                      │                        │
       ├──────────────────>│                      │                        │
       │                   │                      │                        │
       │                   │                      │                        │
       │              ┌────┴──────────────────────────────────────┐        │
       │              │ 2. Generate PKCE Parameters (Listing 1)   │        │
       │              │                                            │        │
       │              │    code_verifier = secrets.token_urlsafe(32)       │
       │              │    # Example: "dBjftJeZ4CVP-mB92K27uhbUJ..."       │
       │              │                                            │        │
       │              │    code_challenge = base64url(            │        │
       │              │        sha256(code_verifier)              │        │
       │              │    )                                      │        │
       │              │    # Example: "E9Melhoa2OwvFrEMTJguCHa..."│        │
       │              │                                            │        │
       │              │    state = secrets.token_urlsafe(32)      │        │
       │              │    # CSRF protection token                │        │
       │              │                                            │        │
       │              │    STORE code_verifier & state in memory  │        │
       │              └────────────────────────────────────────────┘        │
       │                   │                      │                        │
       │                   │                      │                        │
       │              3. Redirect to Authorization Endpoint                │
       │                   │                      │                        │
       │                   │  GET /authorize?     │                        │
       │                   │    response_type=code                         │
       │                   │    client_id=myapp_123                        │
       │                   │    redirect_uri=https://myapp.com/callback    │
       │                   │    scope=read write                           │
       │                   │    state=xyz789...                            │
       │                   │    code_challenge=E9Melhoa2Owv...             │
       │                   │    code_challenge_method=S256                 │
       │                   ├─────────────────────>│                        │
       │                   │                      │                        │
       │                   │                      │                        │
       │                   │              ┌───────┴──────────────────┐     │
       │                   │              │ 4. Store code_challenge  │     │
       │                   │              │    with session          │     │
       │                   │              │                          │     │
       │                   │              │    session_data = {      │     │
       │                   │              │      client_id,          │     │
       │                   │              │      redirect_uri,       │     │
       │                   │              │      code_challenge,     │     │
       │                   │              │      code_challenge_method│     │
       │                   │              │    }                     │     │
       │                   │              └──────────────────────────┘     │
       │                   │                      │                        │
       │                   │                      │                        │
       │  5. Show Login Page (if not authenticated)                        │
       │<─────────────────────────────────────────┤                        │
       │                   │                      │                        │
       │                   │                      │                        │
       │  6. Enter Username/Password               │                        │
       ├──────────────────────────────────────────>│                        │
       │                   │                      │                        │
       │                   │              ┌───────┴──────────────────┐     │
       │                   │              │ 7. Authenticate User     │     │
       │                   │              │    - Verify credentials  │     │
       │                   │              │    - Check MFA if needed │     │
       │                   │              └──────────────────────────┘     │
       │                   │                      │                        │
       │                   │                      │                        │
       │  8. Show Authorization Page:             │                        │
       │     "MyApp wants to access your data"    │                        │
       │     Scopes: read, write                  │                        │
       │     [Allow] [Deny]                       │                        │
       │<─────────────────────────────────────────┤                        │
       │                   │                      │                        │
       │                   │                      │                        │
       │  9. Click "Allow" │                      │                        │
       ├──────────────────────────────────────────>│                        │
       │                   │                      │                        │
       │                   │              ┌───────┴──────────────────┐     │
       │                   │              │ 10. Generate Auth Code   │     │
       │                   │              │                          │     │
       │                   │              │     code = random()      │     │
       │                   │              │     # Single-use, 60s TTL│     │
       │                   │              │                          │     │
       │                   │              │     Store mapping:       │     │
       │                   │              │     code → {             │     │
       │                   │              │       user_id,           │     │
       │                   │              │       client_id,         │     │
       │                   │              │       redirect_uri,      │     │
       │                   │              │       code_challenge,    │     │
       │                   │              │       scope,             │     │
       │                   │              │       expires_at         │     │
       │                   │              │     }                    │     │
       │                   │              └──────────────────────────┘     │
       │                   │                      │                        │
       │                   │                      │                        │
       │  11. Redirect to callback with code & state                       │
       │                   │                      │                        │
       │     302 Found     │                      │                        │
       │     Location: https://myapp.com/callback?code=AUTH_CODE_ABC&state=xyz789
       │<──────────────────────────────────────────┤                        │
       │                   │                      │                        │
       │                   │                      │                        │
       │  12. Browser follows redirect             │                        │
       │                   │                      │                        │
       │     GET /callback?code=AUTH_CODE_ABC&state=xyz789                 │
       ├──────────────────>│                      │                        │
       │                   │                      │                        │
       │                   │                      │                        │
       │              ┌────┴──────────────────────────────────────┐        │
       │              │ 13. Validate State (Listing 2)            │        │
       │              │                                            │        │
       │              │     received_state = req.query.state      │        │
       │              │     stored_state = get_from_session()     │        │
       │              │                                            │        │
       │              │     if not secrets.compare_digest(        │        │
       │              │         received_state, stored_state      │        │
       │              │     ):                                    │        │
       │              │         return ERROR("CSRF attack!")      │        │
       │              │                                            │        │
       │              │     # State matches ✓                     │        │
       │              └────────────────────────────────────────────┘        │
       │                   │                      │                        │
       │                   │                      │                        │
       │              ┌────┴──────────────────────────────────────┐        │
       │              │ 14. Exchange Code for Token (Listing 2)   │        │
       │              │                                            │        │
       │              │     POST /token                            │        │
       │              │     Content-Type: application/x-www-form-urlencoded
       │              │                                            │        │
       │              │     Body:                                  │        │
       │              │       grant_type=authorization_code        │        │
       │              │       code=AUTH_CODE_ABC                   │        │
       │              │       redirect_uri=https://myapp.com/callback       │
       │              │       client_id=myapp_123                  │        │
       │              │       code_verifier=dBjftJeZ4CVP...        │        │
       │              │       (NO client_secret - public client)   │        │
       │              └────┬───────────────────────────────────────┘        │
       │                   │                      │                        │
       │                   ├─────────────────────>│                        │
       │                   │                      │                        │
       │                   │              ┌───────┴──────────────────┐     │
       │                   │              │ 15. Verify PKCE          │     │
       │                   │              │                          │     │
       │                   │              │     stored = lookup(code)│     │
       │                   │              │                          │     │
       │                   │              │     computed_challenge = │     │
       │                   │              │       base64url(         │     │
       │                   │              │         sha256(          │     │
       │                   │              │           code_verifier  │     │
       │                   │              │         )                │     │
       │                   │              │       )                  │     │
       │                   │              │                          │     │
       │                   │              │     if computed_challenge│     │
       │                   │              │        != stored.code_challenge:
       │                   │              │         return ERROR      │     │
       │                   │              │                          │     │
       │                   │              │     # PKCE verified ✓    │     │
       │                   │              └──────────────────────────┘     │
       │                   │                      │                        │
       │                   │              ┌───────┴──────────────────┐     │
       │                   │              │ 16. Validate Request     │     │
       │                   │              │                          │     │
       │                   │              │  - Code not expired? ✓   │     │
       │                   │              │  - Code not used before?✓│     │
       │                   │              │  - redirect_uri matches?✓│     │
       │                   │              │  - client_id matches? ✓  │     │
       │                   │              │                          │     │
       │                   │              │  Mark code as USED       │     │
       │                   │              └──────────────────────────┘     │
       │                   │                      │                        │
       │                   │              ┌───────┴──────────────────┐     │
       │                   │              │ 17. Generate Tokens      │     │
       │                   │              │                          │     │
       │                   │              │  access_token = JWT {    │     │
       │                   │              │    sub: user_123,        │     │
       │                   │              │    scope: "read write",  │     │
       │                   │              │    exp: now + 3600,      │     │
       │                   │              │    iat: now              │     │
       │                   │              │  }                       │     │
       │                   │              │                          │     │
       │                   │              │  refresh_token = random()│     │
       │                   │              │  # Long-lived, opaque    │     │
       │                   │              │                          │     │
       │                   │              │  Store refresh_token:    │     │
       │                   │              │    token → {user_id,     │     │
       │                   │              │            client_id,    │     │
       │                   │              │            scope}        │     │
       │                   │              └──────────────────────────┘     │
       │                   │                      │                        │
       │                   │                      │                        │
       │                   │  18. Return Tokens   │                        │
       │                   │                      │                        │
       │                   │  200 OK              │                        │
       │                   │  {                   │                        │
       │                   │    "access_token": "eyJhbGciOiJIUzI1NiIs...",│
       │                   │    "token_type": "Bearer",                    │
       │                   │    "expires_in": 3600,                        │
       │                   │    "refresh_token": "tGzv3JOkF0XG5Qx2TlKW",  │
       │                   │    "scope": "read write"                      │
       │                   │  }                   │                        │
       │                   │<─────────────────────┤                        │
       │                   │                      │                        │
       │              ┌────┴──────────────────────────────────────┐        │
       │              │ 19. Store Tokens Securely                 │        │
       │              │                                            │        │
       │              │     Mobile (iOS): Keychain                │        │
       │              │     Mobile (Android): Keystore            │        │
       │              │     Web (SPA): Memory (NOT localStorage!) │        │
       │              │                                            │        │
       │              │     access_token_expires_at = now + 3600  │        │
       │              └────────────────────────────────────────────┘        │
       │                   │                      │                        │
       │                   │                      │                        │
       │  20. Show Success │                      │                        │
       │<──────────────────┤                      │                        │
       │                   │                      │                        │
       │                   │                      │                        │
       │                   │                      │                        │
       │ ═══════════════════════════════════════════════════════════════════
       │ USER IS NOW AUTHENTICATED - TOKEN USAGE BEGINS
       │ ═══════════════════════════════════════════════════════════════════
       │                   │                      │                        │
       │                   │                      │                        │
       │  21. "Load my data"                      │                        │
       ├──────────────────>│                      │                        │
       │                   │                      │                        │
       │              ┌────┴──────────────────────────────────────┐        │
       │              │ 22. Make API Request (Listing 3)          │        │
       │              │                                            │        │
       │              │     GET /api/user/data                     │        │
       │              │     Authorization: Bearer eyJhbGciOiJIUzI1...       │
       │              └────┬───────────────────────────────────────┘        │
       │                   │                      │                        │
       │                   ├────────────────────────────────────────────────>│
       │                   │                      │                        │
       │                   │                      │                        │
       │                   │                      │              ┌─────────┴────────────┐
       │                   │                      │              │ 23. Extract Token    │
       │                   │                      │              │     (Listing 5)      │
       │                   │                      │              │                      │
       │                   │                      │              │  auth_header =       │
       │                   │                      │              │    req.headers[      │
       │                   │                      │              │      'authorization' │
       │                   │                      │              │    ]                 │
       │                   │                      │              │                      │
       │                   │                      │              │  if not auth_header: │
       │                   │                      │              │    return 401        │
       │                   │                      │              │                      │
       │                   │                      │              │  if not starts_with( │
       │                   │                      │              │      'bearer'        │
       │                   │                      │              │  ):                  │
       │                   │                      │              │    return 401        │
       │                   │                      │              │                      │
       │                   │                      │              │  token = auth_header │
       │                   │                      │              │    .slice('bearer '.len)
       │                   │                      │              │                      │
       │                   │                      │              │  # token = "eyJhbGc..."
       │                   │                      │              └──────────────────────┘
       │                   │                      │                        │
       │                   │                      │                        │
       │                   │                      │              ┌─────────┴────────────┐
       │                   │                      │              │ 24. Validate Token   │
       │                   │                      │              │     (Listing 6)      │
       │                   │                      │              │                      │
       │                   │                      │              │  Option A: JWT       │
       │                   │                      │              │    - Verify signature│
       │                   │                      │              │    - Check expiration│
       │                   │                      │              │    - Check audience  │
       │                   │                      │              │                      │
       │                   │                      │              │  Option B: Opaque    │
       │                   │                      │              │    - Lookup in DB    │
       │                   │                      │              │    - Check expiry    │
       │                   │                      │              │                      │
       │                   │                      │              │  Extract claims:     │
       │                   │                      │              │    user_id = 123     │
       │                   │                      │              │    scopes = [read,   │
       │                   │                      │              │             write]   │
       │                   │                      │              └──────────────────────┘
       │                   │                      │                        │
       │                   │                      │                        │
       │                   │                      │              ┌─────────┴────────────┐
       │                   │                      │              │ 25. Check Scopes     │
       │                   │                      │              │                      │
       │                   │                      │              │  required = "read"   │
       │                   │                      │              │  if required not in  │
       │                   │                      │              │     token.scopes:    │
       │                   │                      │              │    return 403        │
       │                   │                      │              │                      │
       │                   │                      │              │  # Authorized ✓      │
       │                   │                      │              └──────────────────────┘
       │                   │                      │                        │
       │                   │                      │                        │
       │                   │                      │              ┌─────────┴────────────┐
       │                   │                      │              │ 26. Fetch User Data  │
       │                   │                      │              │                      │
       │                   │                      │              │  data = database     │
       │                   │                      │              │    .get_user_data(   │
       │                   │                      │              │      user_id=123     │
       │                   │                      │              │    )                 │
       │                   │                      │              └──────────────────────┘
       │                   │                      │                        │
       │                   │                      │                        │
       │                   │  27. Return Protected Resource                │
       │                   │                      │                        │
       │                   │  200 OK              │                        │
       │                   │  {                   │                        │
       │                   │    "user": {         │                        │
       │                   │      "id": 123,      │                        │
       │                   │      "name": "Alice",│                        │
       │                   │      "email": "alice@example.com"             │
       │                   │    }                 │                        │
       │                   │  }                   │                        │
       │                   │<─────────────────────────────────────────────┤
       │                   │                      │                        │
       │                   │                      │                        │
       │  28. Display data │                      │                        │
       │<──────────────────┤                      │                        │
       │                   │                      │                        │
       │                   │                      │                        │
       │                   │                      │                        │
       │ ═══════════════════════════════════════════════════════════════════
       │ TOKEN REFRESH (When access_token expires)
       │ ═══════════════════════════════════════════════════════════════════
       │                   │                      │                        │
       │  [1 hour later - access_token expired]   │                        │
       │                   │                      │                        │
       │  29. "Load data"  │                      │                        │
       ├──────────────────>│                      │                        │
       │                   │                      │                        │
       │              ┌────┴──────────────────────────────────────┐        │
       │              │ 30. Attempt API Call                      │        │
       │              │     (access_token expired)                │        │
       │              └────┬───────────────────────────────────────┘        │
       │                   │                      │                        │
       │                   ├────────────────────────────────────────────────>│
       │                   │                      │                        │
       │                   │                      │                        │
       │                   │  31. Token Expired   │                        │
       │                   │  401 Unauthorized    │                        │
       │                   │<─────────────────────────────────────────────┤
       │                   │                      │                        │
       │                   │                      │                        │
       │              ┌────┴──────────────────────────────────────┐        │
       │              │ 32. Refresh Token (Listing 4)             │        │
       │              │                                            │        │
       │              │     POST /token                            │        │
       │              │     Content-Type: application/x-www-form-urlencoded
       │              │                                            │        │
       │              │     Body:                                  │        │
       │              │       grant_type=refresh_token             │        │
       │              │       refresh_token=tGzv3JOkF0XG5Qx2TlKW   │        │
       │              │       client_id=myapp_123                  │        │
       │              └────┬───────────────────────────────────────┘        │
       │                   │                      │                        │
       │                   ├─────────────────────>│                        │
       │                   │                      │                        │
       │                   │              ┌───────┴──────────────────┐     │
       │              │              │ 33. Validate Refresh Token   │     │
       │                   │              │                          │     │
       │                   │              │  - Lookup refresh_token  │     │
       │                   │              │  - Check not expired     │     │
       │                   │              │  - Check not revoked     │     │
       │                   │              │  - client_id matches     │     │
       │                   │              └──────────────────────────┘     │
       │                   │                      │                        │
       │                   │              ┌───────┴──────────────────┐     │
       │                   │              │ 34. Issue New Tokens     │     │
       │                   │              │     (Token Rotation)     │     │
       │                   │              │                          │     │
       │                   │              │  new_access_token = JWT  │     │
       │                   │              │  new_refresh_token =     │     │
       │                   │              │    random()              │     │
       │                   │              │                          │     │
       │                   │              │  INVALIDATE old          │     │
       │                   │              │    refresh_token         │     │
       │                   │              │                          │     │
       │                   │              │  Store new refresh_token │     │
       │                   │              └──────────────────────────┘     │
       │                   │                      │                        │
       │                   │                      │                        │
       │                   │  35. Return New Tokens                        │
       │                   │                      │                        │
       │                   │  200 OK              │                        │
       │                   │  {                   │                        │
       │                   │    "access_token": "eyJhbGc...",             │
       │                   │    "token_type": "Bearer",                    │
       │                   │    "expires_in": 3600,                        │
       │                   │    "refresh_token": "RjY2NjM5NzA2OWJjuE7c"   │
       │                   │  }                   │                        │
       │                   │<─────────────────────┤                        │
       │                   │                      │                        │
       │                   │                      │                        │
       │              ┌────┴──────────────────────────────────────┐        │
       │              │ 36. Store New Tokens                      │        │
       │              └────────────────────────────────────────────┘        │
       │                   │                      │                        │
       │                   │                      │                        │
       │              ┌────┴──────────────────────────────────────┐        │
       │              │ 37. Retry API Call with New Token         │        │
       │              └────┬───────────────────────────────────────┘        │
       │                   │                      │                        │
       │                   ├────────────────────────────────────────────────>│
       │                   │                      │                        │
       │                   │  38. Success         │                        │
       │                   │  200 OK              │                        │
       │                   │  { data }            │                        │
       │                   │<─────────────────────────────────────────────┤
       │                   │                      │                        │
       │  39. Display data │                      │                        │
       │<──────────────────┤                      │                        │
       │                   │                      │                        │
```

---

## Key Security Features (OAuth 2 in Action References)

### 1. PKCE (Proof Key for Code Exchange) - Listing 1 & 2
**Prevents**: Authorization code interception attacks

**How it works**:
```
Client generates:
  code_verifier = random(43-128 chars)
  code_challenge = base64url(sha256(code_verifier))

Authorization request includes:
  code_challenge + code_challenge_method=S256

Token exchange includes:
  code_verifier

Auth server verifies:
  sha256(received_verifier) == stored_challenge
```

**Why it matters**: Even if attacker intercepts authorization code, they can't exchange it without code_verifier.

**Source**: OAuth 2 in Action, Listing 1-2; RFC 7636

---

### 2. State Parameter - Listing 2
**Prevents**: CSRF attacks on OAuth callback

**How it works**:
```python
# Client generates
state = secrets.token_urlsafe(32)
store_in_session(state)

# Client includes in authorization request
auth_url = f"{auth_server}/authorize?...&state={state}"

# Client validates in callback
if not secrets.compare_digest(received_state, stored_state):
    raise Exception("CSRF attack detected!")
```

**Why it matters**: Attacker can't trick victim into authorizing attacker's OAuth request.

**Source**: OAuth 2 in Action, Listing 2, pages 119-138

---

### 3. Authorization Code Properties
**Security requirements**:
- ✅ Single-use (used twice = error)
- ✅ Short-lived (60 seconds typical)
- ✅ Bound to client_id and redirect_uri
- ✅ Bound to code_challenge (PKCE)

**Why it matters**: Limits damage if code is intercepted.

**Source**: OAuth 2 in Action, Chapter 9, pages 149-167

---

### 4. Bearer Token Transmission - Listing 3 & 5
**Best practice**: `Authorization: Bearer {token}` header

**Bad practices**:
```
❌ Query parameter: GET /api/data?access_token=xyz
   (Tokens leak in server logs, browser history)

❌ Request body for GET: Not allowed by HTTP spec

✅ Authorization header: Authorization: Bearer xyz
   (Proper, doesn't leak in logs)
```

**Source**: OAuth 2 in Action, Listing 3 (client) & Listing 5 (server)

---

### 5. Token Validation - Listing 6
**Two approaches**:

**Option A: JWT (Stateless)**
```python
# Resource server validates locally
def validate_jwt(token):
    # 1. Verify signature (using auth server's public key)
    # 2. Check expiration (exp claim)
    # 3. Check audience (aud claim)
    # 4. Check issuer (iss claim)
    return claims
```
**Pros**: No database lookup, scales to millions of requests/sec
**Cons**: Can't revoke until expiration

**Option B: Opaque Token (Stateful)**
```python
# Resource server calls auth server or database
def validate_opaque(token):
    token_data = database.lookup(token)
    if not token_data or token_data.expired:
        return None
    return token_data
```
**Pros**: Can revoke immediately
**Cons**: Database lookup on every request

**Source**: OAuth 2 in Action, Listing 6; Chapter 11

---

### 6. Token Refresh with Rotation - Listing 4
**Security requirement**: Issue new refresh token on each use

```python
# OLD (vulnerable)
def refresh_access_token(refresh_token):
    new_access = generate_token()
    # ❌ Reuse same refresh_token (can be replayed if stolen)
    return new_access, refresh_token

# NEW (secure)
def refresh_access_token(refresh_token):
    new_access = generate_token()
    new_refresh = generate_token()
    
    # ✅ Invalidate old refresh token
    database.revoke(refresh_token)
    database.store(new_refresh)
    
    return new_access, new_refresh
```

**Why it matters**: Stolen refresh token becomes useless after one use.

**Source**: OAuth 2 in Action, Listing 4 & Listing 10

---

## Interview Discussion Points (Week 21 System Design)

When asked **"Design authentication for 100M users with OAuth support"**, reference this diagram:

### Architecture Decisions:

**1. Token Format**: JWT vs Opaque
- JWT: Stateless validation, scales better
- Opaque: Can revoke immediately, requires database

**2. Token Storage** (Client-side):
- Mobile: Keychain (iOS), Keystore (Android)
- Web: Memory only (NOT localStorage - XSS vulnerable)

**3. Token Lifetime**:
- Access token: 15 min - 1 hour (short-lived)
- Refresh token: 30-90 days (long-lived)
- Refresh token rotation: ALWAYS issue new refresh token

**4. Validation Strategy** (Resource Server):
```
100M users, 500K API requests/sec

Option A: JWT validation
- No database lookup
- Cached public keys (1 hour TTL)
- Can handle 500K/sec easily

Option B: Token introspection
- Database lookup on every request
- Need caching layer (Redis)
- Harder to scale
```

**5. Security Measures**:
- PKCE mandatory for public clients
- State parameter for CSRF protection
- Rate limiting: 100 auth attempts/IP/hour
- Suspicious login detection (new device/location)

---

## What Listings 1-6 Taught You

| Listing | What You Learned | Interview Value |
|---------|------------------|-----------------|
| **1** | How to build authorization URLs with PKCE | "I'd generate code_challenge from code_verifier..." |
| **2** | State validation + token exchange | "State parameter prevents CSRF on callback..." |
| **3** | How clients send Bearer tokens | "Access tokens go in Authorization header..." |
| **4** | Token refresh with rotation | "Refresh tokens should rotate on each use..." |
| **5** | How APIs extract tokens | "First extract from Authorization header..." |
| **6** | How APIs validate tokens | "For JWT, verify signature and check expiration..." |

---

## Next Steps

**For Week 6**:
1. ✅ Study this diagram (understand all 39 steps)
2. ✅ Draw your own version in Excalidraw
3. ✅ Read Listings 1-6 in OAuth 2 in Action
4. ✅ Implement Python OAuth client with PKCE

**For Week 21** (System Design):
- Design auth systems at scale using this flow
- Make architectural decisions (JWT vs opaque, caching, etc.)
- Handle edge cases (token revocation, account takeover)

---

## Sources

1. **OAuth 2 in Action** by Richer & Sanso, Manning Publications, 2017
   - Listing 1: Authorization request (page 312)
   - Listing 2: Callback and token request (pages 312-313)
   - Listing 3: Fetching protected resource (page 313)
   - Listing 4: Refreshing access token (pages 313-314)
   - Listing 5: Extracting access token (page 315)
   - Listing 6: Looking up token (pages 315-316)
   - Chapter 7: Common client vulnerabilities (pages 119-138)
   - Chapter 9: Common authorization server vulnerabilities (pages 149-167)
   - Chapter 10: Common token vulnerabilities (pages 168-177)

2. **RFC 7636**: Proof Key for Code Exchange (PKCE)

3. **Complete 48-Week Security Engineering Curriculum**, Week 6, page 26
