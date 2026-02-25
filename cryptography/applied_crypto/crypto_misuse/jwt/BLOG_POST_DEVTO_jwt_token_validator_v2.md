---
title: "Challenge: Build a Production-Grade JWT Token Validator (AppSec Exercise)"
published: false
description: "A hands-on security engineering challenge: implement a JWT validator using PyJWT and the cryptography library, then discover which five of the twelve required security checks the library doesn't cover — and implement them yourself. 100 test cases."
tags: appsec, security, python, challenge
---

# Challenge: Build a Production-Grade JWT Token Validator

**Time:** 90–150 minutes
**Difficulty:** Intermediate–Advanced
**Skills:** Application Security, Cryptography, Defensive Programming, API Security
**Requires:** `pip install cryptography PyJWT`

---

## The Challenge

Every major API on the internet uses JSON Web Tokens. Stripe uses them for
OAuth access tokens. GitHub uses them for App authentication. AWS Cognito uses
them as identity tokens in every call your application makes. Implemented
correctly, JWTs are a powerful authentication primitive. Implemented
incorrectly, they hand attackers the keys to your kingdom — with no log entry
and no error message.

Your challenge: write `validate_jwt()` — a function that correctly validates
JWTs signed with any of the nine common algorithms, enforces constant-time
comparison on every security-sensitive string comparison in the function, and
returns claims only when all twelve security checks pass.

---

## Why This Matters in Real Life

### The $0 JWT bypass that worked on thousands of APIs

In 2015, researchers discovered that many JWT libraries accepted tokens signed
with the algorithm `"none"` — meaning *no signature at all*. An attacker could
take any valid token, change the `alg` field in the header to `"none"`, strip
the signature, rewrite any claim they wanted (say, `"role": "admin"`), and the
server would accept it.

This was not a theoretical attack. Libraries in Node.js, Python, PHP, Ruby, and
Java were all vulnerable. The fix sounds trivial — reject `alg=none` — but
production systems were still being found vulnerable years later.

**Hacking APIs** (Corey Ball, Ch. 8, p. 194) captures it bluntly:

> "If the algorithm value is 'none', the token has not been signed with any
> hashing algorithm."

### The algorithm confusion attack

A more sophisticated variant: an API is deployed with RS256 (asymmetric, RSA)
JWTs. An attacker discovers the RSA public key — as intended, it is public and
often published at a JWKS endpoint. They craft a new token and sign it with
HS256, using the public key bytes as the HMAC secret. A naive library that
trusts the `alg` field in the header will verify this as a valid HS256 token.
The attacker wins using publicly available material.

**API Security in Action** (Neil Madden, p. 191) is unambiguous on the fix:

> "The algorithm header can't be trusted and should be ignored. You should
> associate the algorithm with each key instead."

This exercise enforces that principle in the function signature: the **caller**
passes `expected_algorithm`. The header value is only checked to confirm it
agrees — it is never used to select the verification logic.

### The timing oracle

Comparing two strings with `==` in Python exits on the first mismatched byte.
An attacker sending thousands of requests and measuring response time
distributions can statistically recover the correct HMAC signature byte by
byte. This applies to the HMAC signature comparison — the place where key
material can actually leak through timing.

`aud` and `iss` are delegated to `jwt.decode()` / `jwt.decode_complete()` in
this exercise, which handles them using standard Python equality internally.
That is acceptable here because knowing your audience or issuer string gives an
attacker nothing useful — those values do not enable token forgery on their own.
The signing key is what must be protected, and that comparison happens inside
the HMAC step where `hmac.compare_digest` is mandatory.

---

## The Security Implications

### What happens when validation fails?

**Scenario 1 — alg=none bypass:** Attacker rewrites `sub: "attacker"` to
`sub: "admin"`, strips the signature, sets `alg: "none"`. Your API
authenticates them as an administrator.

**Scenario 2 — Algorithm confusion (RS256 → HS256):** Attacker obtains the
public key from your JWKS endpoint. Signs a crafted token with HS256 using the
public key bytes as the secret. Your API accepts it if it trusts the header.

**Scenario 3 — Cross-service token replay:** Your payment service issues tokens
with `aud: "https://payments.example.com"`. Your profile service also validates
JWTs. If the profile service does not check `aud`, a token stolen from a
phishing attack against the payments service works on the profile service too.

**Scenario 4 — Issuer confusion:** Two microservices share a JWT library. One
issues tokens for internal consumers; another issues tokens for external users.
Without `iss` validation, a low-privilege external token is accepted by internal
services.

**Scenario 5 — Token replay after logout:** A user logs out. The session token
is long-lived. Without a `jti` revocation check, the stolen or logged token
continues to work until expiry.

**Scenario 6 — kid path traversal:** The `kid` (Key ID) header field is meant
to be a lookup key in a key store. A PortSwigger lab demonstrates what happens
if the validator uses `kid` as a filename — an attacker sets `kid` to
`../../../../dev/null`, causing the validator to load an empty file as the
secret and sign a forgery with an empty HMAC key.

**Scenario 7 — Timing oracle on audience list:** An `aud` list is iterated
with a short-circuit `in` operator. The response time reveals which position
in the list contained the match, leaking information about the token's intended
recipients. Always iterate all entries.

---

## JWT Structure: What You Are Actually Parsing

Before writing a single line of validation code, you need to know what a JWT
physically looks like. A JWT is three base64url-encoded segments separated by
dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwiYXVkIjoiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20iLCJleHAiOjE3MDAwMDM2MDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Breaking that apart:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9          <- segment 1: HEADER
.
eyJzdWIiOiJ1c2VyLTQyIiwiYXVkIjoiaHR0cH...      <- segment 2: PAYLOAD
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c   <- segment 3: SIGNATURE
```

Each segment is base64url-encoded — standard Base64 with `+` replaced by `-`,
`/` replaced by `_`, and padding `=` stripped. This means you cannot read the
content directly — you must decode each segment first.

---

### The Header (Segment 1)

Decode segment 1 from base64url and you get a JSON object. For the token above:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

The header describes the token itself — how it was signed, what type it is, and
which key was used. It is metadata *about* the token, not the user's claims.
Those live in the payload.

Here are every field the header can legally contain, per RFC 7515 (JWS) and
RFC 7518 (JWA):

| Field | Name | Required? | What it means |
|---|---|---|---|
| `alg` | Algorithm | **Yes** | Which signing algorithm was used. Examples: `"HS256"`, `"RS256"`, `"ES256"`. This is the field your validator checks against `expected_algorithm` and the field attackers manipulate in algorithm confusion attacks. |
| `typ` | Type | No | Declares the token type. For JWTs this is usually `"JWT"`. Optional to validate in most implementations. |
| `kid` | Key ID | No | A string identifier for the signing key. Used when a server rotates keys and needs to tell receivers which key to use for verification. Your validator checks this against the `key_store` allowlist. Never use it as a filename or path component. |
| `cty` | Content Type | No | Used in nested JWTs where the payload is itself a JWT. Rare in practice. |
| `jku` | JWK Set URL | No | A URL pointing to a JSON Web Key Set for fetching the public key. **Dangerous if trusted blindly** — an attacker can point this at their own server (SSRF). Not supported in this exercise. |
| `jwk` | JSON Web Key | No | The public key embedded directly in the header. **Dangerous if trusted blindly** — an attacker can embed their own key and sign a token with it. Not supported in this exercise. |
| `x5u` | X.509 URL | No | A URL pointing to an X.509 certificate chain. Same SSRF risk as `jku`. Not supported in this exercise. |
| `x5c` | X.509 Cert Chain | No | The certificate chain embedded directly in the header. Not supported in this exercise. |
| `x5t` | X.509 Thumbprint | No | SHA-1 thumbprint of the X.509 certificate. Rarely used. |
| `crit` | Critical | No | List of header fields the receiver MUST understand. If your validator does not understand a listed field, it must reject the token. |

The three fields your validator actually reads are `alg` and `kid`. Every other
field is either irrelevant to this exercise or actively dangerous to act on
without additional safeguards (`jku`, `jwk`, `x5u`).

Unknown fields not in the table above must be **ignored, not rejected**. Test
172 verifies this: a token with `"cty": "JWT"` and `"x-foo": "bar"` in the
header is still valid as long as `alg` is correct and the signature verifies.

---

### The Payload (Segment 2)

Decode segment 2 and you get another JSON object. In JWT terminology this
object is called the **claims set**, and its individual key-value pairs are
called **claims**.

The word "claim" is intentional: the token is *asserting* facts about an
identity. `"sub": "user-42"` is a claim that this token represents user 42.
`"exp": 1700003600` is a claim that the token expires at that Unix timestamp.
Your job as the validator is to decide whether you trust those claims — and
you can only do that after verifying the signature, because an unsigned or
forged token can claim anything.

In Python, the JSON object decodes directly to a `dict`. That is what the
function signature means by `-> Optional[dict]`: on success, return the claims
set as a Python dictionary; on any validation failure, return `None`. The
caller then reads specific keys from that dict — `claims["sub"]`,
`claims["role"]`, and so on — to make authorization decisions.

This is where `nbf`, `exp`, `aud`, `iss`, and every other piece of identity
information lives. The header contains metadata *about* the token; the payload
contains the token's actual content.

```json
{
  "sub":  "user-42",
  "aud":  "https://api.example.com",
  "iss":  "https://auth.example.com",
  "iat":  1699999700,
  "nbf":  1699999700,
  "exp":  1700003600,
  "jti":  "550e8400-e29b-41d4-a716-446655440000"
}
```

RFC 7519 defines the following standard payload claims:

| Field | Name | What it means |
|---|---|---|
| `sub` | Subject | Who the token is about — usually a user ID or service account name. |
| `iss` | Issuer | Which authorization server issued the token. Your validator checks this against `expected_issuer`. |
| `aud` | Audience | Which service(s) the token is intended for. Your validator checks this against `expected_audience`. May be a single string or a JSON array of strings (RFC 7519 §4.1.3). |
| `exp` | Expiration Time | Unix timestamp after which the token must be rejected. Validation is strict: `current_time < exp` (a token where `exp == now` is already expired). |
| `nbf` | Not Before | Unix timestamp before which the token must be rejected. Validation is inclusive: `current_time >= nbf` (a token where `nbf == now` is valid). |
| `iat` | Issued At | Unix timestamp when the token was issued. Used with `max_age_seconds` to reject stale tokens even if `exp` is far in the future. |
| `jti` | JWT ID | A unique identifier for this specific token. Used for revocation — your validator checks it against `revoked_jti_set`. |

All other fields in the payload are **application-defined claims** — `role`,
`scope`, `plan`, `email`, and so on. Your validator must pass them through
unchanged in the returned dict. It must not reject a token for containing
unknown claims.

This is what your validator returns on success. Steps 7–12 all operate on this
object. The payload must not be read until after the signature passes — any
claims extracted from an unverified payload must be treated as untrusted.

---

### The Signature (Segment 3)

The third segment is raw bytes, base64url-encoded. It is computed over exactly
the string `base64url(header) + "." + base64url(payload)` — called the
**signing input**. The algorithm family determines how to verify it, which is
the focus of the "Algorithm Families" section below.

---

## The Challenge: `validate_jwt`

```python
from typing import Optional, Any

def validate_jwt(
    token: str,
    key: Any,                              # bytes for HMAC; RSA/EC public key for asymmetric
    expected_algorithm: str,               # "HS256", "RS256", "PS256", "ES256", etc.
    expected_audience: str,
    current_time: Optional[float] = None,
    expected_issuer: Optional[str] = None,
    revoked_jti_set: Optional[set] = None,
    key_store: Optional[set] = None,
    max_age_seconds: Optional[float] = None,
    max_token_bytes: int = 8192,
) -> Optional[dict]:
    """
    Validate a JWT and return its claims (the payload) if every check passes.

    A JWT has three base64url-encoded segments separated by dots:
        segment 1 — header:    metadata (alg, kid, typ)
        segment 2 — payload:   the claims set (sub, exp, aud, iss, nbf, iat, jti, ...)
        segment 3 — signature: cryptographic proof over header + payload

    "Claims" and "payload" refer to the same thing: the decoded JSON object
    from segment 2. This function returns that object as a Python dict on
    success, or None on any validation failure.

    Validation order (implement in this exact sequence):
      1.  Byte length   — reject if len(token.encode()) > max_token_bytes
      2.  Structure     — exactly 3 dot-separated segments
      3.  Header        — segment 1 must be valid JSON dict; alg MUST equal
                          expected_algorithm (exact, case-sensitive match)
      4.  kid           — if key_store is not None AND header has 'kid',
                          kid MUST be in key_store
      5.  Signature     — recompute and verify using the correct algorithm
      6.  Payload       — segment 2 must be valid JSON dict (the claims set)
      7.  exp           — payload MUST have exp; current_time < exp (strict)
      8.  nbf           — if payload has nbf: current_time >= nbf (inclusive)
      9.  iat           — if max_age_seconds is not None: payload MUST have iat
                          and (current_time - iat) <= max_age_seconds
      10. aud           — handled by jwt.decode_complete() via the audience= param
                          aud may be a string or a list (RFC 7519 §4.1.3)
      11. iss           — handled by jwt.decode_complete() via the issuer= param
                          (pass None to skip the check)
      12. jti revoke    — if revoked_jti_set is not None: payload MUST have jti
                          and jti MUST NOT be in revoked_jti_set

    Returns the payload dict (claims set) on success. None on any failure.
    Never raises exceptions to the caller.
    """
    pass
```

Two dependencies:

```bash
pip install cryptography PyJWT
```

---

## `jwt.decode()` Is Allowed — and Still Not Enough

In production Python, `PyJWT` is the right tool for JWT validation. You are
free to use it in this exercise.

`jwt.decode()` handles signature verification, `exp`, `nbf`, `aud`, and `iss`
automatically when you pass the right options. For asymmetric algorithms you
pass the public key object directly and it dispatches to PKCS#1, PSS, or ECDSA
internally. **You should absolutely use it in this exercise if you want to.**

Here is the catch: `jwt.decode()` alone will not pass this test suite. Five of
the twelve required checks are not handled by the library at all. After
`jwt.decode()` returns successfully, you still have to implement all of the
following yourself:

Here is the precise breakdown of every validation check in this exercise,
what PyJWT's `jwt.types.Options` actually does for each one, and what remains
yours to implement. Every row marked "Yes" or "Partially" applies equally to
both `jwt.decode()` and `jwt.decode_complete()` — they share identical
validation logic; the only difference is that `decode_complete()` also returns
the raw header and signature alongside the payload.

| Check | `jwt.decode()` handles it? | What PyJWT actually does |
|---|---|---|
| Signature verification | **Yes** | Verifies cryptographic signature for all algorithm families |
| `exp` (expiration) | **Yes** | Rejects if `current_time >= exp`; raises `ExpiredSignatureError` |
| `nbf` (not before) | **Yes** | Rejects if `current_time < nbf`; raises `ImmatureSignatureError` |
| `aud` (audience) | **Yes** | Checks claim matches `audience` parameter |
| `iss` (issuer) | **Yes** | Checks claim matches `issuer` parameter |
| `iat` type check | **Partially** (`verify_iat`) | Rejects if `iat` is not an integer, or if `iat > now` (issued in the future). Does **not** enforce a max age window. |
| `jti` type check | **Partially** (`verify_jti`) | Rejects if `jti` is not a string. Has **no** concept of a revocation blocklist. |
| **Token byte length** | **No** | PyJWT never checks the raw size of the token string — a 50 MB token parses just fine |
| **`kid` allowlist** | **No** | PyJWT passes `kid` to your key function if you provide one, but does not enforce an allowlist or block path traversal strings |
| **`jti` revocation** | **No** | `verify_jti` only enforces the type. Checking a token's `jti` against a blocklist is entirely yours. |
| **`iat` max age** | **No** | `verify_iat` only guards against future-issued tokens. The `max_age_seconds` window check is entirely yours. |
| **Constant-time `aud` / `iss` comparison** | **Delegated** | PyJWT uses standard Python equality for these — acceptable because `aud` and `iss` are not secret values; knowing them does not enable token forgery. The signing key is what requires constant-time protection. |

This means that even with `jwt.decode()` doing the heavy lifting, a reader who
passes all 175 tests has demonstrated that they understand what a JWT library
handles and — critically — what it does not. That boundary is exactly what a
security engineer needs to know when evaluating whether a given library
configuration is sufficient for their threat model, or when auditing a
codebase that uses PyJWT without any of these supplementary checks.

The recommended approach is a layered one — use the library for the
cryptographic core, then write manual code for the checks the library does not
fully cover. Figuring out exactly how to structure that is part of the exercise.

---

## Algorithm Families You Must Support

The `key` parameter is `bytes`. The signing input is
`base64url(header) + "." + base64url(payload)` encoded as ASCII. Compute
`HMAC-SHA{N}(key, signing_input)` and compare with `hmac.compare_digest`.

```python
import hmac, hashlib
# key: bytes, signing_input: bytes
mac = hmac.new(key, signing_input, hashlib.sha256).digest()
```

### RSA PKCS#1 v1.5 (RS256, RS384, RS512)

The `key` parameter is an RSA public key from the `cryptography` library. The
signature in the JWT is raw bytes, base64url-encoded.

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
# Raises InvalidSignature on failure
public_key.verify(sig_bytes, signing_input, padding.PKCS1v15(), hashes.SHA256())
```

### RSA-PSS (PS256, PS384, PS512)

Same RSA public key, but PSS padding. RFC 7518 §3.5 specifies the salt length
must equal the hash digest length. Use `PSS.AUTO` for verification to accept
any valid salt.

```python
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
public_key.verify(
    sig_bytes, signing_input,
    PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.AUTO),
    hashes.SHA256()
)
```

### ECDSA (ES256, ES384, ES512)

This is where most implementations trip up. **JWT signatures are raw `r ∥ s`
concatenation, not DER-encoded.** The `cryptography` library's `verify()`
expects DER format, so you must convert.

RFC 7518 §3.4 defines the coordinate byte lengths: ES256 = 32 bytes each,
ES384 = 48 bytes each, ES512 = 66 bytes each.

```python
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric import ec

coord_size = 32  # for ES256
r = int.from_bytes(raw_sig[:coord_size], "big")
s = int.from_bytes(raw_sig[coord_size:], "big")
der_sig = encode_dss_signature(r, s)
public_key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
```

---

## Why This Is Harder Than It Looks

### Edge Case 1: Base64URL padding

Base64URL (used in JWTs) strips the `=` padding characters that standard Base64
adds. You must restore them before decoding:

```python
# Breaks on many real tokens
base64.urlsafe_b64decode(segment)

# Correct
pad = 4 - len(segment) % 4
if pad != 4:
    segment += "=" * pad
base64.urlsafe_b64decode(segment)
```

### Edge Case 2: exp == now is expired

`exp` validation uses a strict less-than. `current_time == exp` means the token
has expired. Test 45 verifies this boundary.

### Edge Case 3: nbf == now is valid

`nbf` validation is inclusive. `current_time == nbf` means the token is now
valid. Test 50 verifies this boundary. It is the mirror image of `exp` and they
are easy to confuse.

### Edge Case 4: aud can be a string or a list

RFC 7519 §4.1.3 allows `aud` to be either a single string or a JSON array. A
validator that only handles the string case will reject valid multi-audience
tokens (Test 57). More dangerously, one that handles the list case with a
short-circuit comparison leaks timing information about the list contents.

### Edge Case 5: Constant-time for the HMAC signature comparison

`hmac.compare_digest` is mandatory when comparing the HMAC signature. Standard
Python `==` short-circuits on the first mismatched byte — a timing oracle on
the signature comparison could leak information about the HMAC output, which in
turn could leak information about the signing key itself. That is the real
threat.

`aud` and `iss` are delegated to `jwt.decode_complete()` in this exercise.
Those values are not secret — an attacker learning your audience string cannot
forge a token without the signing key — so PyJWT's standard equality comparison
for them is acceptable here.

Category 15 of the test suite probes constant-time discipline on the HMAC
secret itself: tokens signed with a secret that shares a prefix with the real
secret must be rejected correctly regardless of how many bytes matched.

### Edge Case 6: kid must be an allowlist lookup, never a path

If the JWT header contains a `kid` (Key ID) field, your validator must look it
up in a caller-provided `key_store` set. It must never use `kid` as a filename
or path component of any kind. An attacker who sets `kid` to
`../../../../dev/null` on a naive implementation can force your validator to
load an empty file as the signing key, then forge tokens signed with an empty
HMAC secret. Test 77 submits exactly this path traversal attempt.

**API Security in Action** (p. 191, Table 6.2) is explicit: `kid` "can be
safely looked up in a server-side set of keys" but other key-embedding headers
like `jwk` and `jku` "lose all security properties" — treat them as untrusted.

### Edge Case 7: jti must be required when a revocation set is given

It is tempting to skip the `jti` check when the claim is absent: after all, you
cannot revoke something that has no ID. But the correct fail-secure behaviour
is the opposite: if the caller provides a `revoked_jti_set`, they are asserting
that all valid tokens must carry a `jti`. A token without one cannot be verified
as non-revoked, so it must be rejected. Test 69 verifies this.

**API Security in Action** (p. 213) describes this pattern using a database
allowlist: "If the entry exists in the database, then the token is still valid.
But if the database returns an empty result, the token has been revoked."

---

## The Testing Gauntlet — 175 Tests in 27 Categories

| Category | Tests | What Is Checked |
|---|---|---|
| 1. Valid HMAC | 1–8 | HS256/384/512, nbf, numeric sub, many claims |
| 2. Valid Asymmetric | 9–16 | RS256/384/512, PS256/384/512, ES256/384 |
| 3. Structural | 17–24 | Empty, plain text, wrong segment counts, invalid base64 |
| 4. Algorithm Confusion | 25–34 | alg=none (3 casings), cross-family mismatches, trailing space, wrong case |
| 5. Signature Forgery | 35–42 | Wrong HMAC key, empty key, truncated sig, tampered payload/header, wrong RSA/EC key |
| 6. Expiration | 43–48 | Expired, boundary (exp==now is expired), missing exp |
| 7. Not-Before | 49–54 | Past nbf, boundary (nbf==now is valid), future nbf |
| 8. Audience | 55–60 | Wrong aud, missing aud, list aud, exact match |
| 9. Issuer | 61–66 | Match, mismatch, missing, skip when None, empty-matches-empty |
| 10. JTI Revocation | 67–72 | Not revoked, revoked, missing jti when set required, empty revocation set |
| 11. kid Allowlist | 73–78 | In store, not in store, path traversal attempt, empty store, no key_store |
| 12. Max Age (iat) | 79–84 | Within limit, over limit, missing iat when required, boundary |
| 13. Token Size | 85–88 | Default 8192 limit, tiny custom limit, large custom limit |
| 14. Claims Extraction | 89–94 | All claim types returned in dict correctly |
| 15. Constant-Time | 95–97 | Same-prefix HMAC secret, same-prefix audience, same-prefix issuer |
| 16. Combined | 98–100 | Multiple simultaneous failures, single iss failure, perfect token (all 8 optional checks) |
| 17. Payload/Header JSON Corruption | 101–108 | Bad JSON in header/payload, JSON arrays/primitives, exp/aud/nbf wrong types |
| 18. ES512 + Cross-Family Mismatches | 109–116 | ES512 (P-521), PS256 vs RS256, ES256 vs ES384, HS256 vs HS512, PS384/RS512 forgery |
| 19. Audience Edge Cases | 117–123 | Empty list, integer aud, non-string list entries, expected last/middle/duplicate in list |
| 20. kid Edge Cases | 124–129 | No kid + non-None store, integer kid, null kid, shell injection kid, OTHER_KID match |
| 21. jti Edge Cases | 130–134 | Empty jti, jti not in set, integer jti, case sensitivity, empty set + absent jti |
| 22. Float Timestamps | 135–140 | Float exp/nbf/iat, boolean exp, integer iss, iat==now with max_age=0 |
| 23. Structural Edge Cases | 141–145 | Empty signature, all-empty segments, JSON string/number as payload |
| 24. Asymmetric + All Optional Combined | 146–150 | RS256/ES256/ES512/PS256 each with iss+jti+kid+max_age simultaneously |
| 25. Algorithm Confusion — Canonical Attack | 151–157 | RS256→HS256 public-key-as-secret, EC/RSA key type mismatch, Unicode alg, null-byte alg, PS384 forgery |
| 26. Constant-Time Completeness | 158–163 | iss/aud suffix attacks, iss/aud case mismatch, jti=null, aud=boolean |
| 27. Boundary Conditions + Robustness | 164–175 | exp=0/1/year-2500, nbf=0, iat in future, truncated sig, leading dot, newline injection, unknown headers, negative exp, HS512 combined, aud suffix list |

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════════════════╗
║                   JWT TOKEN VALIDATOR — ALL ALGORITHMS                   ║
║                     100 Comprehensive Security Tests                     ║
║         Sources: API Security in Action Ch.6 · Hacking APIs Ch.8         ║
║                     RFC 7519 (JWT) · RFC 7518 (JWA)                      ║
╚══════════════════════════════════════════════════════════════════════════╝

  Cat 1
  ✅ PASS   Test  1: HS256 — minimal valid token
  ✅ PASS   Test  2: HS256 — with role claim
  ...
  Cat 2
  ✅ PASS   Test  9: RS256 — valid
  ✅ PASS   Test 12: PS256 — valid (RSA-PSS)
  ✅ PASS   Test 15: ES256 — valid (ECDSA P-256)
  ...
  Cat 4
  ✅ PASS   Test 25: alg=none (lowercase) — unsigned token bypass
  ✅ PASS   Test 28: Header alg=RS256 when HS256 expected — reject mismatch
  ...
  Cat 15
  ✅ PASS   Test 95: Same-length wrong HMAC secret (same prefix) — must reject
  ✅ PASS   Test 96: Audience prefix match (shorter) — must reject
  ✅ PASS   Test 97: Issuer prefix match (shorter) — must reject

════════════════════════════════════════════════════════════════════════════
  RESULTS: 175/175 tests passed (100%)
════════════════════════════════════════════════════════════════════════════
🎉  PERFECT — ALL 175 TESTS PASSED! 🎉
```

---

## Why This Builds Real Security Engineering Skills

**1. Algorithm agility done correctly.** The caller owns the algorithm decision;
the header only confirms it. This directly implements the principle from
*API Security in Action* (p. 191): the algorithm header cannot be trusted and
must not be used to select verification logic.

**2. Cryptographic discipline where it counts.** Most engineers know to use
`hmac.compare_digest` for MAC comparison. This exercise reinforces that the
signing key comparison is the critical one — `aud` and `iss` are not secret
values and are safely handled by `jwt.decode_complete()`. Knowing which
comparisons require constant-time discipline and which do not is itself a
security engineering skill.

**3. Understanding what the library buys you — and what it doesn't.** Using
`jwt.decode()` correctly is necessary but not sufficient. The exercise makes
the gap concrete: five checks remain entirely your responsibility regardless of
which JWT library you choose. Knowing where a library's guarantees end and your
code's responsibilities begin is a core security engineering competency,
especially when reviewing third-party implementations or responding to a JWT-
related CVE in a dependency.

**4. Fail-secure optional checks.** The `jti` revocation check, `iss`
validation, `kid` allowlist, and `iat` max-age checks are all designed around
the fail-secure principle: if the caller enables a check and the token lacks the
required data, the validator rejects the token. Absence of evidence is not
evidence of absence.

**5. Dependency injection for deterministic testing.** Passing `current_time`
as a parameter instead of calling `time.time()` inside the function makes every
time-sensitive test completely deterministic. This is a direct application of
the *Effective Python* (Brett Slatkin) principle of making functions testable by
injecting their external dependencies.

**6. Defence-in-depth ordering.** Byte size before parsing. Structure before
header decoding. Header before signature. Signature before claims. Each step
prevents the next step from operating on untrusted data. This is the *Secure by
Design* (Johnsson, Deogun & Sawano) principle of validating at the boundary in
depth.

---

## Common Mistakes

### ❌ Mistake 1: Trusting the header algorithm field

```python
# Vulnerable — attacker controls alg
alg = json.loads(decode(header))["alg"]
if alg == "HS256":
    verify_hmac(...)
elif alg == "RS256":
    verify_rsa(...)
```

The `expected_algorithm` parameter exists precisely to prevent this. Check that
the header agrees with what the caller expects — never use the header value to
decide which verification path to take.

### ❌ Mistake 2: Using `==` for audience or issuer comparison

```python
# Leaks timing information
if claims["aud"] == expected_audience:
    ...

# Correct
if hmac.compare_digest(claims["aud"], expected_audience):
    ...
```

### ❌ Mistake 3: Short-circuiting the audience list

```python
# Leaks position of matching entry
if expected_audience in aud_list:
    ...

# Correct: check all entries in constant time
matched = False
for entry in aud_list:
    if hmac.compare_digest(entry, expected_audience):
        matched = True
```

### ❌ Mistake 4: Converting ECDSA raw → DER incorrectly

The raw ES256 signature is exactly 64 bytes: `r` (32 bytes) followed by `s`
(32 bytes). For ES384 it is 96 bytes (48 + 48). For ES512 it is 132 bytes
(66 + 66). A validator that uses the wrong coordinate size will reject all
valid ES384/ES512 tokens, or misconstruct `r` and `s` for ES256.

### ❌ Mistake 5: Accepting tokens without jti when revocation is enabled

```python
# Wrong — lets unsigned tokens slip through
jti = claims.get("jti")
if revoked_jti_set and jti in revoked_jti_set:
    return None

# Correct — if revocation is configured, jti is required
if revoked_jti_set is not None:
    jti = claims.get("jti")
    if jti is None or jti in revoked_jti_set:
        return None
```

### ❌ Mistake 6: Any string operation on the kid field

```python
# Never do this
key_path = f"keys/{header['kid']}.pem"
with open(key_path) as f: ...

# Correct — allowlist lookup only
if key_store is not None and "kid" in header:
    if header["kid"] not in key_store:
        return None
```

---

## Take the Challenge

```bash
# 1. Install dependencies
pip install cryptography PyJWT

# 2. Download the challenge file
curl -O https://raw.githubusercontent.com/fosres/SecEng-Exercises/main/jwt_token_validator_v2_175_tests.py

# 3. Run the tests (expect ~56/175 before you implement anything)
python3 jwt_token_validator_v2_175_tests.py

# 4. Implement validate_jwt() and iterate
```

The stub returns `None` for everything. The tests that pass before you write
a single line are all "must reject" cases — they confirm the test infrastructure
is correct. Every test you need to unlock requires a real implementation.

`jwt.decode()` will unlock most of Categories 1–9. It will not unlock any of
the checks in Categories 10–13 (jti revocation, kid allowlist, max age, token
size), nor the edge-case and robustness categories 17–27. Those you must write
yourself on top of whatever the library returns.

If this exercise is useful to you, ⭐ starring the repo takes three seconds and
helps other security engineers find it. More exercises covering SQL injection,
SSRF, XXE, IDOR, and API authentication patterns are already in progress:

**[github.com/fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)**

---

---

## Quick Poll: Why Are You Here?

I'm curious who is actually reading these exercises — job seeker, student,
seasoned engineer brushing up, hiring manager evaluating candidates?

**[Take the 30-second poll (no login required)](https://strawpoll.com/wby5QoKAkyA/results)**

Results are public. Knowing your background helps me pitch the difficulty and
depth of future exercises at the right level.

---

## What You'll Learn

- ✅ JWT structure: three base64url segments, what each contains
- ✅ Why `alg=none` is dangerous and how to block all capitalisations
- ✅ Why the header algorithm field must never drive verification logic
- ✅ HMAC-SHA256/384/512 from scratch using only the standard library
- ✅ RSA PKCS#1 v1.5 and PSS signature verification via `cryptography`
- ✅ ECDSA raw `r ∥ s` encoding (RFC 7518 §3.4) and why it differs from DER
- ✅ Constant-time comparison discipline focused on where key material can actually leak
- ✅ RFC 7519 audience semantics: string vs. list
- ✅ Issuer validation and why it prevents cross-service replay attacks
- ✅ `jti` revocation: the fail-secure design when the claim is absent
- ✅ `kid` allowlist lookup and the path traversal risk of naive implementations
- ✅ Token age limits via `iat` as defence against stolen long-lived tokens
- ✅ Defensive ordering: each validation step guards the next

---

## For Hiring Managers

This exercise evaluates a candidate's ability to:

- Use `jwt.decode()` correctly — passing an algorithm allowlist, requiring `exp`
  and `aud`, never letting the token's header drive library behaviour
- Identify precisely which checks a JWT library does and does not perform, and
  implement the missing ones correctly on top of it
- Apply constant-time discipline to the HMAC signature comparison where key
  list iteration, `iss` comparison)
- Reason about fail-secure defaults for optional parameters (`jti` revocation,
  `kid` allowlist, `iat` max age, token byte limit)
- Write clean, type-annotated, keyword-argument-driven Python that handles every
  error case without raising exceptions to the caller

A candidate who passes all 100 tests understands JWT security at the depth
needed to design authentication middleware, evaluate third-party JWT library
configurations, and write security architecture documentation for cross-service
token flows — not just "I've called `jwt.decode()` before."

---

## Level Up: After You Pass

1. **Add JWE support** — encrypted JWTs keep sensitive claims off the wire even
   if the token is logged or cached. Read *API Security in Action* Ch. 6 §6.3
   on `A128CBC-HS256` and the Cryptographic Doom Principle.

2. **Implement a JWKS endpoint fetcher** — extend your validator to fetch
   public keys from a `/.well-known/jwks.json` endpoint. Add in-memory caching
   with a TTL and a fallback for key rotation. This is how AWS Cognito, Auth0,
   and Google validate tokens in production.

3. **Benchmark constant-time discipline** — write a script that sends your
   validator 50,000 requests with signatures that differ in the first byte,
   middle byte, and last byte, then plots the response time distributions.
   A correct implementation is statistically indistinguishable across all three.

4. **Fuzz it** — use `hypothesis` to generate arbitrary byte strings as tokens
   and verify your validator never raises an unhandled exception. A validator
   that panics on malformed input is itself a denial-of-service vector.

5. **Try PortSwigger JWT labs 4–6** — `jwk` header injection (lab 4), `jku`
   header injection leading to SSRF (lab 5), and `kid` path traversal (lab 6).
   You will recognise every attack because this exercise already defends against
   them. These labs are on your Week 15 curriculum.

---

## References

- **PyJWT documentation** — https://pyjwt.readthedocs.io/en/stable/
  Pay particular attention to the `algorithms` allowlist parameter and the
  `options={"require": [...]}` dict for enforcing required claims
- **API Security in Action** — Neil Madden (Manning, 2020)
  Ch. 6, pp. 187–195: JWT structure, standard claims, JOSE header security
  Ch. 6, p. 191 Table 6.2: kid allowlist vs. jwk/jku header risks
  Ch. 6, p. 213: jti allowlist/blocklist revocation pattern
  Ch. 11, p. 394: jti replay prevention for service-to-service JWTs
- **Hacking APIs** — Corey Ball (No Starch Press, 2022)
  Ch. 8, pp. 194, 200: alg=none bypass, algorithm confusion, JWT recon decoding
- **Secure by Design** — Johnsson, Deogun & Sawano (Manning, 2019)
  Domain Primitive pattern; fail-secure defaults; validate at the boundary
- **Effective Python** — Brett Slatkin (Addison-Wesley, 3rd ed.)
  Keyword-only arguments, type annotations, dependency injection for testability
- **Python Workout** — Reuven M. Lerner (Manning, 2020)
  Exercise-driven incremental learning philosophy
- **RFC 7519** — JSON Web Token:
  https://datatracker.ietf.org/doc/html/rfc7519
- **RFC 7518** — JSON Web Algorithms (JWA):
  https://datatracker.ietf.org/doc/html/rfc7518
- **OWASP JWT Security Cheat Sheet**:
  https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- **PortSwigger JWT Labs** (Week 15 curriculum):
  https://portswigger.net/web-security/jwt

---

Found this useful? ⭐ **[Star the repo](https://github.com/fosres/SecEng-Exercises)** and
**[vote on the next exercise](https://strawpoll.com/wby5QoKAkyA/results)**.

---

## Template Code for Challenge

| File | Description |
|---|---|
| [jwt_token_validator_v2_200_tests.py](https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/crypto_misuse/jwt/jwt_token_validator_v2_200_tests.py) | Challenge file — 200 test cases, stub only |
| [jwt_token_validator_v2_200_tests_solution.py](https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/crypto_misuse/jwt/jwt_token_validator_v2_200_tests_solution.py) | Reference solution — attempt the challenge before opening this |

Both files live in the
[SecEng-Exercises cryptography/applied_crypto/crypto_misuse/jwt](https://github.com/fosres/SecEng-Exercises/tree/main/cryptography/applied_crypto/crypto_misuse/jwt)
directory. If you find a bug or want to contribute additional test cases, pull
requests are welcome.
