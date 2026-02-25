"""
Exercise: JWT Token Validator — ALL ALGORITHMS, 100 COMPREHENSIVE TESTS
========================================================================

Implement validate_jwt() — a production-grade validator that correctly
handles every common JWT algorithm family and every realistic security
check a real API server performs before trusting a token.

INSTRUCTIONS:
	1. pip install cryptography
	2. Implement validate_jwt() in the section below
	3. Run: python3 jwt_token_validator_v2_100_tests.py
	4. Pass all 100 tests.

DEPENDENCIES (reader must install):
	pip install cryptography

Inspired By:
	• "API Security in Action" — Neil Madden (Manning, 2020)
	  Ch. 6, pp. 187–195: JWT structure, standard claims, JOSE header
	  Ch. 6, p. 191 Table 6.2: kid header — allowlist only, never filesystem
	  Ch. 6, p. 213: jti allowlist/blocklist revocation pattern
	  Ch. 11, p. 394: jti replay prevention for service-to-service JWTs
	• "Hacking APIs" — Corey Ball (No Starch, 2022)
	  Ch. 8, pp. 194, 200: alg=none, algorithm confusion, JWT decoding recon
	• "Secure by Design" — Johnsson, Deogun & Sawano (Manning, 2019)
	  Domain Primitive pattern: validate at the boundary, fail secure
	• "Effective Python" — Brett Slatkin (Addison-Wesley, 3rd ed.)
	  Items on keyword-only args, type annotations, dependency injection
	• "Python Workout" — Reuven M. Lerner (Manning, 2020)
	  Exercise-driven incremental learning philosophy
	• RFC 7519 — JSON Web Token: https://datatracker.ietf.org/doc/html/rfc7519
	• RFC 7518 — JSON Web Algorithms: https://datatracker.ietf.org/doc/html/rfc7518

Security Context:
	JWT validation is one of the most attack-prone operations in API security.
	The alg=none bypass (Hacking APIs, p. 194) and algorithm confusion attacks
	(RS256 → HS256 using public key as HMAC secret) have been found in
	production libraries for Node.js, Python, PHP, Ruby, and Java.

	API Security in Action (p. 191): "The algorithm header can't be trusted
	and should be ignored. You should associate the algorithm with each key."

	This exercise enforces that principle: the CALLER declares the expected
	algorithm; the header is only checked to confirm it agrees.

Validation Order (implement in this exact sequence):
	 1. Byte length   — reject if len(token.encode()) > max_token_bytes
	 2. Structure     — exactly 3 dot-separated segments
	 3. Header        — valid JSON; alg MUST equal expected_algorithm (exact, case-sensitive)
	 4. kid           — if key_store is not None AND header has 'kid', kid MUST be in key_store
	 5. Signature     — recompute and verify (see algorithm notes below)
	 6. Payload       — valid JSON
	 7. exp           — MUST be present; current_time < exp  (strict less-than)
	 8. nbf           — if present: current_time >= nbf      (inclusive)
	 9. iat           — if max_age_seconds is not None: iat MUST be present and
	                    (current_time - iat) <= max_age_seconds
	10. aud           — MUST be present; expected_audience must be in aud
	                    aud may be a string or a list of strings (RFC 7519 §4.1.3)
	                    ALL comparisons MUST use hmac.compare_digest (constant-time)
	11. iss           — if expected_issuer is not None: token MUST have iss and
	                    hmac.compare_digest(token_iss, expected_issuer) must be True
	12. jti revoke    — if revoked_jti_set is not None: jti MUST be present and
	                    MUST NOT be in revoked_jti_set

Algorithm Notes:
	HS256/384/512:
	  key   = bytes (the HMAC secret UTF-8 encoded)
	  sign  = HMAC-SHA{N}(key, signing_input)
	  verify= hmac.compare_digest(expected, actual)   ← constant-time mandatory

	RS256/384/512 (PKCS#1 v1.5):
	  key   = RSA public key (cryptography.hazmat.primitives.asymmetric.rsa)
	  verify= public_key.verify(sig, signing_input, PKCS1v15(), SHA{N}())
	          raises InvalidSignature on failure

	PS256/384/512 (RSA-PSS):
	  key   = RSA public key
	  salt  = hash digest size (RFC 7518 §3.5: "same size as the hash output")
	  verify= public_key.verify(sig, signing_input, PSS(MGF1(SHA{N}), AUTO), SHA{N}())

	ES256/384/512 (ECDSA):
	  key   = EC public key (P-256, P-384, P-521 respectively)
	  sig   = raw (r || s) concatenation, NOT DER format (RFC 7518 §3.4)
	  coord sizes: ES256=32B, ES384=48B, ES512=66B
	  verify= convert raw→DER via encode_dss_signature, then public_key.verify(...)
"""

import hmac
import hashlib
import base64
import json
import time
from typing import Optional, Any


# ===========================================================================
# YOUR IMPLEMENTATION GOES HERE
# ===========================================================================

def validate_jwt(
	token: str,
	key: Any,
	expected_algorithm: str,
	expected_audience: str,
	current_time: Optional[float] = None,
	expected_issuer: Optional[str] = None,
	revoked_jti_set: Optional[set] = None,
	key_store: Optional[set] = None,
	max_age_seconds: Optional[float] = None,
	max_token_bytes: int = 8192,
) -> Optional[dict]:
	"""
	Validate a JWT and return its claims if every security check passes.

	Args:
		token:             Raw JWT string (header.payload.signature)
		key:               bytes for HMAC algorithms; RSA/EC public key object
		                   for asymmetric algorithms. The caller decides which
		                   key type to pass based on expected_algorithm.
		expected_algorithm: Exact algorithm string the validator accepts.
		                   MUST match the token header's 'alg' field exactly
		                   (case-sensitive). Examples: "HS256", "RS256",
		                   "PS256", "ES256". Never read from the header alone.
		expected_audience: The 'aud' value this service expects.
		current_time:      Unix timestamp used as "now". Defaults to
		                   time.time(). Override in tests for determinism.
		expected_issuer:   If not None, the token's 'iss' must match this
		                   value via constant-time comparison.
		revoked_jti_set:   If not None, the token MUST contain a 'jti' claim
		                   and that jti MUST NOT appear in this set.
		key_store:         If not None, and the token header contains a 'kid'
		                   field, the kid MUST be present in this set.
		                   Never use kid as a file path. Allowlist only.
		                   (API Security in Action, p. 191, Table 6.2)
		max_age_seconds:   If not None, the token MUST contain an 'iat' claim
		                   and (current_time - iat) must be <= max_age_seconds.
		max_token_bytes:   Maximum token byte length (default 8192).
		                   Rejects tokens larger than this to prevent DoS.

	Returns:
		The decoded claims dict on success.
		None on ANY validation failure — never raises exceptions to caller.

	Example:
		>>> claims = validate_jwt(token, b"secret", "HS256",
		...                       "https://api.example.com")
		>>> claims["sub"]
		'user-42'

	Critical Requirements:
	╔═══════════════════════════════════════════════════════════════╗
	║ 1. The CALLER's expected_algorithm is authoritative — NEVER   ║
	║    accept whatever alg the token header declares on its own   ║
	║ 2. Reject alg=none in ALL capitalisations                     ║
	║ 3. Verify signature BEFORE reading any claims                 ║
	║ 4. HMAC: use hmac.compare_digest — not ==                     ║
	║ 5. aud + iss comparisons: also use hmac.compare_digest        ║
	║ 6. aud list: iterate ALL entries, never short-circuit         ║
	║ 7. kid: allowlist check only, never filesystem ops            ║
	║ 8. Return None on every error; never raise to the caller      ║
	╚═══════════════════════════════════════════════════════════════╝
	"""
	# TODO: Implement your solution here
	pass


# ===========================================================================
# TEST INFRASTRUCTURE  (DO NOT MODIFY)
# ===========================================================================

import struct
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
	decode_dss_signature,
	encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature

# ── Generate key pairs once (module-level, deterministic within a session) ──

# RSA-2048 — used for RS256/384/512 and PS256/384/512
_RSA_PRIV      = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_RSA_PUB       = _RSA_PRIV.public_key()
_RSA_PRIV_ALT  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_RSA_PUB_ALT   = _RSA_PRIV_ALT.public_key()   # "wrong" RSA key for forgery tests

# EC keys — P-256 for ES256, P-384 for ES384
_EC256_PRIV     = ec.generate_private_key(ec.SECP256R1())
_EC256_PUB      = _EC256_PRIV.public_key()
_EC384_PRIV     = ec.generate_private_key(ec.SECP384R1())
_EC384_PUB      = _EC384_PRIV.public_key()
_EC256_PRIV_ALT = ec.generate_private_key(ec.SECP256R1())
_EC256_PUB_ALT  = _EC256_PRIV_ALT.public_key()  # "wrong" EC key for forgery tests

# ── Algorithm dispatch tables (for _make_jwt test helper) ───────────────────

_HMAC_HASHES = {
	"HS256": hashlib.sha256,
	"HS384": hashlib.sha384,
	"HS512": hashlib.sha512,
}
_RSA_PKCS_HASHES = {
	"RS256": hashes.SHA256,
	"RS384": hashes.SHA384,
	"RS512": hashes.SHA512,
}
_RSA_PSS_HASHES = {
	"PS256": hashes.SHA256,
	"PS384": hashes.SHA384,
	"PS512": hashes.SHA512,
}
_EC_PARAMS = {
	# algorithm: (hash_cls, coord_size_bytes)
	"ES256": (hashes.SHA256, 32),
	"ES384": (hashes.SHA384, 48),
	"ES512": (hashes.SHA512, 66),
}


def _b64url_encode(data: bytes) -> str:
	return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
	pad = 4 - len(segment) % 4
	if pad != 4:
		segment += "=" * pad
	return base64.urlsafe_b64decode(segment)


def _make_jwt(header: dict, payload: dict, private_key_or_secret, algorithm: str) -> str:
	"""
	Build a correctly signed JWT for any supported algorithm family.
	Used ONLY by the test suite — not part of the challenge.
	"""
	h_b64 = _b64url_encode(json.dumps(header,  separators=(",", ":")).encode())
	p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
	signing_input = f"{h_b64}.{p_b64}".encode("ascii")

	if algorithm in _HMAC_HASHES:
		secret = (
			private_key_or_secret if isinstance(private_key_or_secret, bytes)
			else private_key_or_secret.encode("utf-8")
		)
		sig = hmac.new(secret, signing_input, _HMAC_HASHES[algorithm]).digest()

	elif algorithm in _RSA_PKCS_HASHES:
		h_cls = _RSA_PKCS_HASHES[algorithm]
		sig = private_key_or_secret.sign(
			signing_input, asym_padding.PKCS1v15(), h_cls()
		)

	elif algorithm in _RSA_PSS_HASHES:
		h_cls = _RSA_PSS_HASHES[algorithm]
		sig = private_key_or_secret.sign(
			signing_input,
			asym_padding.PSS(
				mgf=asym_padding.MGF1(h_cls()),
				salt_length=asym_padding.PSS.DIGEST_LENGTH,
			),
			h_cls(),
		)

	elif algorithm in _EC_PARAMS:
		h_cls, coord_size = _EC_PARAMS[algorithm]
		der_sig = private_key_or_secret.sign(signing_input, ec.ECDSA(h_cls()))
		r, s = decode_dss_signature(der_sig)
		sig = r.to_bytes(coord_size, "big") + s.to_bytes(coord_size, "big")

	else:
		raise ValueError(f"Unsupported algorithm in test infra: {algorithm}")

	return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def _tamper_payload(token: str, new_payload: dict) -> str:
	"""Replace payload without re-signing."""
	h, _, sig = token.split(".")
	return f"{h}.{_b64url_encode(json.dumps(new_payload, separators=(',',':')).encode())}.{sig}"


def _tamper_header(token: str, new_header: dict) -> str:
	"""Replace header without re-signing."""
	_, p, sig = token.split(".")
	return f"{_b64url_encode(json.dumps(new_header, separators=(',',':')).encode())}.{p}.{sig}"


# ── Shared fixtures ──────────────────────────────────────────────────────────

SECRET        = b"super-secret-key-for-testing-only"
WRONG_SECRET  = b"completely-wrong-secret"
EMPTY_SECRET  = b""
PREFIX_SECRET = b"super-secret-key-for-testing-ZZZZ"  # same length, different suffix

AUDIENCE  = "https://api.example.com"
OTHER_AUD = "https://api.other.com"
ISSUER    = "https://auth.example.com"
BAD_ISS   = "https://evil.example.com"
PREFIX_ISS = "https://auth.example.co"  # same prefix as ISSUER, shorter (different)

FIXED_NOW   = 1_700_000_000.0
PAST        = FIXED_NOW - 3_600.0
FAR_PAST    = FIXED_NOW - 86_400.0
FUTURE      = FIXED_NOW + 3_600.0
FAR_FUTURE  = FIXED_NOW + 86_400.0
JUST_EXPIRED = FIXED_NOW - 1.0
NEAR_FUTURE = FIXED_NOW + 1.0

VALID_KID   = "hmac-key-2024-01"
OTHER_KID   = "hmac-key-2023-01"
EVIL_KID    = "../../../../etc/passwd"
KEY_STORE   = {VALID_KID, OTHER_KID}

JTI_GOOD    = "550e8400-e29b-41d4-a716-446655440000"
JTI_BAD     = "revoked-token-id-00000000"
REVOKED_SET = {JTI_BAD, "other-revoked-jti"}

HS256_HDR = {"alg": "HS256", "typ": "JWT"}
RS256_HDR = {"alg": "RS256", "typ": "JWT"}
RS384_HDR = {"alg": "RS384", "typ": "JWT"}
RS512_HDR = {"alg": "RS512", "typ": "JWT"}
PS256_HDR = {"alg": "PS256", "typ": "JWT"}
PS384_HDR = {"alg": "PS384", "typ": "JWT"}
PS512_HDR = {"alg": "PS512", "typ": "JWT"}
ES256_HDR = {"alg": "ES256", "typ": "JWT"}
ES384_HDR = {"alg": "ES384", "typ": "JWT"}


def _vp(sub="user-42", extra: Optional[dict] = None) -> dict:
	"""Build a valid baseline payload, optionally extending it."""
	p = {
		"sub": sub,
		"aud": AUDIENCE,
		"iss": ISSUER,
		"iat": int(FIXED_NOW) - 300,
		"exp": int(FUTURE),
	}
	if extra:
		p.update(extra)
	return p


# ===========================================================================
# TEST RUNNER
# ===========================================================================

from typing import NamedTuple

class TC(NamedTuple):
	"""A single test case."""
	label:            str
	token:            str
	key:              Any          # bytes or RSA/EC public key
	algorithm:        str
	audience:         str
	current_time:     float
	expected_issuer:  Optional[str]
	revoked_jti_set:  Optional[set]
	key_store:        Optional[set]
	max_age_seconds:  Optional[float]
	max_token_bytes:  int
	expected:         Optional[dict]


class Colors:
	GREEN  = "\033[92m"
	RED    = "\033[91m"
	YELLOW = "\033[93m"
	CYAN   = "\033[96m"
	BOLD   = "\033[1m"
	DIM    = "\033[2m"
	END    = "\033[0m"


def _ok(result, expected) -> bool:
	if expected is None:
		return result is None
	if isinstance(expected, dict):
		return isinstance(result, dict) and all(
			result.get(k) == v for k, v in expected.items()
		)
	return result == expected


def _build_tests() -> list:
	"""Construct all 100 test cases. Returns list of TC namedtuples."""

	# ─── Shorthand helpers ────────────────────────────────────────────────────
	def _hs(payload, *, hdr=None, secret=SECRET) -> str:
		return _make_jwt(hdr or HS256_HDR, payload, secret, "HS256")

	def _hs384(payload) -> str:
		return _make_jwt({"alg": "RS384", "typ": "JWT"}, payload, _RSA_PRIV, "RS384")

	def _tc(label, token, key, alg, *, exp,
	        aud=AUDIENCE, now=FIXED_NOW, iss=None, rev=None,
	        store=None, age=None, maxb=8192) -> TC:
		return TC(label, token, key, alg, aud, now, iss, rev, store, age, maxb, exp)

	tests = []

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 1: Valid HMAC JWTs (Tests 1–8)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(_tc(
		"Cat 1 | Test  1: HS256 — minimal valid token",
		_hs(_vp()), SECRET, "HS256", exp={"sub": "user-42"},
	))
	tests.append(_tc(
		"Cat 1 | Test  2: HS256 — with role claim",
		_hs(_vp("alice", {"role": "admin"})), SECRET, "HS256",
		exp={"sub": "alice", "role": "admin"},
	))
	tests.append(_tc(
		"Cat 1 | Test  3: HS256 — with scope claim",
		_hs(_vp("bob", {"scope": "read write"})), SECRET, "HS256",
		exp={"sub": "bob", "scope": "read write"},
	))
	tests.append(_tc(
		"Cat 1 | Test  4: HS384 — valid",
		_make_jwt({"alg": "HS384", "typ": "JWT"}, _vp(), SECRET, "HS384"),
		SECRET, "HS384", exp={"sub": "user-42"},
	))
	tests.append(_tc(
		"Cat 1 | Test  5: HS512 — valid",
		_make_jwt({"alg": "HS512", "typ": "JWT"}, _vp(), SECRET, "HS512"),
		SECRET, "HS512", exp={"sub": "user-42"},
	))
	tests.append(_tc(
		"Cat 1 | Test  6: HS256 — with nbf in the past",
		_hs(_vp(extra={"nbf": int(PAST)})), SECRET, "HS256",
		exp={"sub": "user-42"},
	))
	tests.append(_tc(
		"Cat 1 | Test  7: HS256 — numeric sub",
		_hs(_vp(extra={"sub": 99999})), SECRET, "HS256",
		exp={"sub": 99999},
	))
	tests.append(_tc(
		"Cat 1 | Test  8: HS256 — many custom claims",
		_hs(_vp("power-user", {"plan": "enterprise", "seats": 50, "beta": True})),
		SECRET, "HS256", exp={"plan": "enterprise", "seats": 50},
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 2: Valid Asymmetric JWTs (Tests 9–16)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(_tc(
		"Cat 2 | Test  9: RS256 — valid",
		_make_jwt(RS256_HDR, _vp("svc-rsa"), _RSA_PRIV, "RS256"),
		_RSA_PUB, "RS256", exp={"sub": "svc-rsa"},
	))
	tests.append(_tc(
		"Cat 2 | Test 10: RS384 — valid",
		_make_jwt(RS384_HDR, _vp("svc-rsa"), _RSA_PRIV, "RS384"),
		_RSA_PUB, "RS384", exp={"sub": "svc-rsa"},
	))
	tests.append(_tc(
		"Cat 2 | Test 11: RS512 — valid",
		_make_jwt(RS512_HDR, _vp("svc-rsa"), _RSA_PRIV, "RS512"),
		_RSA_PUB, "RS512", exp={"sub": "svc-rsa"},
	))
	tests.append(_tc(
		"Cat 2 | Test 12: PS256 — valid (RSA-PSS)",
		_make_jwt(PS256_HDR, _vp("svc-pss"), _RSA_PRIV, "PS256"),
		_RSA_PUB, "PS256", exp={"sub": "svc-pss"},
	))
	tests.append(_tc(
		"Cat 2 | Test 13: PS384 — valid (RSA-PSS)",
		_make_jwt(PS384_HDR, _vp("svc-pss"), _RSA_PRIV, "PS384"),
		_RSA_PUB, "PS384", exp={"sub": "svc-pss"},
	))
	tests.append(_tc(
		"Cat 2 | Test 14: PS512 — valid (RSA-PSS)",
		_make_jwt(PS512_HDR, _vp("svc-pss"), _RSA_PRIV, "PS512"),
		_RSA_PUB, "PS512", exp={"sub": "svc-pss"},
	))
	tests.append(_tc(
		"Cat 2 | Test 15: ES256 — valid (ECDSA P-256)",
		_make_jwt(ES256_HDR, _vp("svc-ec"), _EC256_PRIV, "ES256"),
		_EC256_PUB, "ES256", exp={"sub": "svc-ec"},
	))
	tests.append(_tc(
		"Cat 2 | Test 16: ES384 — valid (ECDSA P-384)",
		_make_jwt(ES384_HDR, _vp("svc-ec"), _EC384_PRIV, "ES384"),
		_EC384_PUB, "ES384", exp={"sub": "svc-ec"},
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 3: Structural / Malformed (Tests 17–24)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(_tc("Cat 3 | Test 17: Empty string",
		"", SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 3 | Test 18: Plain English text (not a JWT)",
		"hello world", SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 3 | Test 19: Only one segment",
		"onlyone", SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 3 | Test 20: Only two segments",
		"two.parts", SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 3 | Test 21: Four segments",
		"too.many.parts.here", SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 3 | Test 22: Header is invalid base64",
		"!!!NOT-B64!!!.dGVzdA.dGVzdA", SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 3 | Test 23: String 'null'",
		"null", SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 3 | Test 24: Whitespace-only string",
		"   ", SECRET, "HS256", exp=None))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 4: Algorithm Confusion Attacks (Tests 25–34)
	# ═══════════════════════════════════════════════════════════════════════════

	_none_payload = _vp()

	tests.append(_tc(
		"Cat 4 | Test 25: alg=none (lowercase) — unsigned token bypass",
		_make_jwt({"alg": "none", "typ": "JWT"}, _none_payload, SECRET, "HS256"),
		SECRET, "HS256", exp=None,
	))
	tests.append(_tc(
		"Cat 4 | Test 26: alg=None (title-case) — must reject all casings",
		_make_jwt({"alg": "None", "typ": "JWT"}, _none_payload, SECRET, "HS256"),
		SECRET, "HS256", exp=None,
	))
	tests.append(_tc(
		"Cat 4 | Test 27: alg=NONE (uppercase) — must reject all casings",
		_make_jwt({"alg": "NONE", "typ": "JWT"}, _none_payload, SECRET, "HS256"),
		SECRET, "HS256", exp=None,
	))
	# Header claims RS256 but expected_algorithm is HS256
	tests.append(_tc(
		"Cat 4 | Test 28: Header alg=RS256 when HS256 expected — reject mismatch",
		_make_jwt(RS256_HDR, _vp(), _RSA_PRIV, "RS256"),
		SECRET, "HS256", exp=None,
	))
	# Header claims HS256 but expected_algorithm is RS256
	tests.append(_tc(
		"Cat 4 | Test 29: Header alg=HS256 when RS256 expected — reject mismatch",
		_hs(_vp()), _RSA_PUB, "RS256", exp=None,
	))
	# Header claims ES256 but expected_algorithm is HS256
	tests.append(_tc(
		"Cat 4 | Test 30: Header alg=ES256 when HS256 expected — reject mismatch",
		_make_jwt(ES256_HDR, _vp(), _EC256_PRIV, "ES256"),
		SECRET, "HS256", exp=None,
	))
	# Empty alg string
	tests.append(_tc(
		"Cat 4 | Test 31: alg='' (empty string) — reject",
		_make_jwt({"alg": "", "typ": "JWT"}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", exp=None,
	))
	# Missing alg field
	tests.append(_tc(
		"Cat 4 | Test 32: alg field missing entirely from header — reject",
		_make_jwt({"typ": "JWT"}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", exp=None,
	))
	# Trailing space in alg — not an exact match to "HS256"
	tests.append(_tc(
		"Cat 4 | Test 33: alg='HS256 ' (trailing space) — reject",
		_make_jwt({"alg": "HS256 ", "typ": "JWT"}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", exp=None,
	))
	# Wrong case in alg
	tests.append(_tc(
		"Cat 4 | Test 34: alg='hs256' (wrong case) — reject",
		_make_jwt({"alg": "hs256", "typ": "JWT"}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", exp=None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 5: Signature Forgery (Tests 35–42)
	# ═══════════════════════════════════════════════════════════════════════════

	_base_hs = _hs(_vp())
	_base_rs = _make_jwt(RS256_HDR, _vp("svc-rsa"), _RSA_PRIV, "RS256")
	_base_es = _make_jwt(ES256_HDR, _vp("svc-ec"), _EC256_PRIV, "ES256")

	tests.append(_tc("Cat 5 | Test 35: HS256 signed with wrong secret — must reject",
		_hs(_vp(), secret=WRONG_SECRET), SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 5 | Test 36: HS256 signed with empty secret — must reject",
		_hs(_vp(), secret=EMPTY_SECRET), SECRET, "HS256", exp=None))

	# Corrupt last 4 chars of signature
	_corrupted = _base_hs[:-4] + "XXXX"
	tests.append(_tc("Cat 5 | Test 37: HS256 signature truncated/corrupted — must reject",
		_corrupted, SECRET, "HS256", exp=None))

	# All-zero 32-byte signature
	_zero_sig = _base_hs.rsplit(".", 1)[0] + "." + _b64url_encode(b"\x00" * 32)
	tests.append(_tc("Cat 5 | Test 38: HS256 all-zero signature — must reject",
		_zero_sig, SECRET, "HS256", exp=None))

	tests.append(_tc("Cat 5 | Test 39: HS256 payload tampered post-signing — must reject",
		_tamper_payload(_base_hs, _vp("evil-admin")), SECRET, "HS256", exp=None))

	tests.append(_tc("Cat 5 | Test 40: HS256 header tampered post-signing — must reject",
		_tamper_header(_base_hs, {**HS256_HDR, "kid": "injected"}),
		SECRET, "HS256", exp=None))

	tests.append(_tc("Cat 5 | Test 41: RS256 signed with different RSA key — must reject",
		_make_jwt(RS256_HDR, _vp("svc-rsa"), _RSA_PRIV_ALT, "RS256"),
		_RSA_PUB, "RS256", exp=None))

	tests.append(_tc("Cat 5 | Test 42: ES256 signed with different EC key — must reject",
		_make_jwt(ES256_HDR, _vp("svc-ec"), _EC256_PRIV_ALT, "ES256"),
		_EC256_PUB, "ES256", exp=None))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 6: Expiration (Tests 43–48)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(_tc("Cat 6 | Test 43: exp = 1 second ago — must reject",
		_hs({**_vp(), "exp": int(JUST_EXPIRED)}), SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 6 | Test 44: exp = 1 hour ago — must reject",
		_hs({**_vp(), "exp": int(PAST)}), SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 6 | Test 45: exp == now (boundary, strict) — must reject",
		_hs({**_vp(), "exp": int(FIXED_NOW)}), SECRET, "HS256", exp=None))

	_no_exp = dict(_vp())
	del _no_exp["exp"]
	tests.append(_tc("Cat 6 | Test 46: exp claim missing entirely — must reject",
		_hs(_no_exp), SECRET, "HS256", exp=None))

	tests.append(_tc("Cat 6 | Test 47: exp = 1 hour from now — must accept",
		_hs({**_vp(), "exp": int(FUTURE)}), SECRET, "HS256",
		exp={"sub": "user-42"}))
	tests.append(_tc("Cat 6 | Test 48: exp = 24 hours from now — must accept",
		_hs({**_vp(), "exp": int(FAR_FUTURE)}), SECRET, "HS256",
		exp={"sub": "user-42"}))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 7: Not-Before / nbf (Tests 49–54)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(_tc("Cat 7 | Test 49: nbf = 1 hour ago — must accept (inclusive)",
		_hs({**_vp(), "nbf": int(PAST)}), SECRET, "HS256",
		exp={"sub": "user-42"}))
	tests.append(_tc("Cat 7 | Test 50: nbf == now (boundary) — must accept (inclusive)",
		_hs({**_vp(), "nbf": int(FIXED_NOW)}), SECRET, "HS256",
		exp={"sub": "user-42"}))
	tests.append(_tc("Cat 7 | Test 51: nbf = 1 second in the future — must reject",
		_hs({**_vp(), "nbf": int(NEAR_FUTURE)}), SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 7 | Test 52: nbf = 24 hours in the future — must reject",
		_hs({**_vp(), "nbf": int(FAR_FUTURE)}), SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 7 | Test 53: nbf past + exp future — both valid — must accept",
		_hs({"sub": "u", "aud": AUDIENCE, "iss": ISSUER,
		     "exp": int(FAR_FUTURE), "nbf": int(PAST), "iat": int(PAST)}),
		SECRET, "HS256", exp={"sub": "u"}))
	tests.append(_tc("Cat 7 | Test 54: nbf 1 sec future + exp valid — must reject",
		_hs({**_vp(), "nbf": int(NEAR_FUTURE)}), SECRET, "HS256", exp=None))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 8: Audience Validation (Tests 55–60)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(_tc("Cat 8 | Test 55: Wrong audience string — must reject",
		_hs({**_vp(), "aud": OTHER_AUD}), SECRET, "HS256", exp=None))

	_no_aud = dict(_vp())
	del _no_aud["aud"]
	tests.append(_tc("Cat 8 | Test 56: aud claim missing — must reject",
		_hs(_no_aud), SECRET, "HS256", exp=None))

	tests.append(_tc("Cat 8 | Test 57: aud is list containing expected — must accept",
		_hs({**_vp(), "aud": [AUDIENCE, OTHER_AUD]}), SECRET, "HS256",
		exp={"sub": "user-42"}))
	tests.append(_tc("Cat 8 | Test 58: aud is list NOT containing expected — must reject",
		_hs({**_vp(), "aud": [OTHER_AUD]}), SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 8 | Test 59: aud is empty string — must reject",
		_hs({**_vp(), "aud": ""}), SECRET, "HS256", exp=None))
	tests.append(_tc("Cat 8 | Test 60: aud exact match (string) — must accept",
		_hs({**_vp(), "aud": AUDIENCE}), SECRET, "HS256",
		exp={"sub": "user-42"}))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 9: Issuer Validation (Tests 61–66)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(TC(
		"Cat 9 | Test 61: iss matches expected_issuer — must accept",
		_hs(_vp()), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, None, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 9 | Test 62: iss wrong, expected_issuer set — must reject",
		_hs({**_vp(), "iss": BAD_ISS}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, None, None, None, 8192, None,
	))
	_no_iss = dict(_vp())
	del _no_iss["iss"]
	tests.append(TC(
		"Cat 9 | Test 63: iss missing, expected_issuer set — must reject",
		_hs(_no_iss), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, None, None, None, 8192, None,
	))
	tests.append(TC(
		"Cat 9 | Test 64: expected_issuer=None — iss check skipped, accept even if iss wrong",
		_hs({**_vp(), "iss": BAD_ISS}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 9 | Test 65: iss='' and expected_issuer='' — empty matches empty, accept",
		_hs({**_vp(), "iss": ""}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		"", None, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 9 | Test 66: iss is prefix of ISSUER (same prefix, shorter) — must reject",
		_hs({**_vp(), "iss": PREFIX_ISS}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, None, None, None, 8192, None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 10: JTI Revocation (Tests 67–72)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(TC(
		"Cat 10 | Test 67: jti not in revoked set — must accept",
		_hs(_vp(extra={"jti": JTI_GOOD})), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, REVOKED_SET, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 10 | Test 68: jti IS in revoked set — must reject",
		_hs(_vp(extra={"jti": JTI_BAD})), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, REVOKED_SET, None, None, 8192, None,
	))
	tests.append(TC(
		"Cat 10 | Test 69: jti missing, revoked_jti_set set — must reject",
		_hs(_vp()), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, REVOKED_SET, None, None, 8192, None,
	))
	tests.append(TC(
		"Cat 10 | Test 70: revoked_jti_set=None — jti check skipped, accept",
		_hs(_vp(extra={"jti": JTI_BAD})), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 10 | Test 71: revoked_jti_set=set() (empty) — not revoked, must accept",
		_hs(_vp(extra={"jti": JTI_GOOD})), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, set(), None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 10 | Test 72: jti in larger revoked set — must reject",
		_hs(_vp(extra={"jti": JTI_BAD})), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, {"unrelated-1", "unrelated-2", JTI_BAD, "unrelated-3"}, None, None, 8192, None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 11: kid Allowlist (Tests 73–78)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(TC(
		"Cat 11 | Test 73: kid in key_store — must accept",
		_make_jwt({**HS256_HDR, "kid": VALID_KID}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, KEY_STORE, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 11 | Test 74: kid NOT in key_store — must reject",
		_make_jwt({**HS256_HDR, "kid": "unknown-key-99"}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, KEY_STORE, None, 8192, None,
	))
	tests.append(TC(
		"Cat 11 | Test 75: no kid in token + key_store=None — must accept",
		_hs(_vp()), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 11 | Test 76: kid in token + key_store=None — allowlist not enforced, accept",
		_make_jwt({**HS256_HDR, "kid": VALID_KID}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 11 | Test 77: kid = path traversal string — not in store, must reject",
		_make_jwt({**HS256_HDR, "kid": EVIL_KID}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, KEY_STORE, None, 8192, None,
	))
	tests.append(TC(
		"Cat 11 | Test 78: key_store is empty set, token has kid — must reject",
		_make_jwt({**HS256_HDR, "kid": VALID_KID}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, set(), None, 8192, None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 12: Max Age via iat (Tests 79–84)
	# ═══════════════════════════════════════════════════════════════════════════

	_iat_30min = {**_vp(), "iat": int(FIXED_NOW) - 1800}   # 30 min old
	_iat_2hr   = {**_vp(), "iat": int(FIXED_NOW) - 7200}   # 2 hr old
	_iat_1hr   = {**_vp(), "iat": int(FIXED_NOW) - 3600}   # exactly 1 hr old

	tests.append(TC(
		"Cat 12 | Test 79: iat 30 min ago, max_age=3600 — within limit, accept",
		_hs(_iat_30min), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, 3600.0, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 12 | Test 80: iat 2 hrs ago, max_age=3600 — exceeds limit, reject",
		_hs(_iat_2hr), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, 3600.0, 8192, None,
	))

	_no_iat = dict(_vp())
	del _no_iat["iat"]
	tests.append(TC(
		"Cat 12 | Test 81: iat missing + max_age set — cannot verify age, reject",
		_hs(_no_iat), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, 3600.0, 8192, None,
	))
	tests.append(TC(
		"Cat 12 | Test 82: iat very old + max_age=None — age check skipped, accept",
		_hs({**_vp(), "iat": int(FAR_PAST)}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 12 | Test 83: iat exactly at boundary (age == max_age) — must accept",
		_hs(_iat_1hr), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, 3600.0, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 12 | Test 84: max_age=0 + iat 1 sec ago — any age fails, reject",
		_hs({**_vp(), "iat": int(FIXED_NOW) - 1}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, 0.0, 8192, None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 13: Token Size Limit (Tests 85–88)
	# ═══════════════════════════════════════════════════════════════════════════

	_normal_tok = _hs(_vp())
	_big_payload = {**_vp(), "data": "A" * 8000}
	_big_tok = _hs(_big_payload)
	_huge_payload = {**_vp(), "data": "B" * 60000}
	_huge_tok = _hs(_huge_payload)

	tests.append(TC(
		"Cat 13 | Test 85: Normal ~400B token, default 8192 limit — must accept",
		_normal_tok, SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 13 | Test 86: Token > 8192 bytes with default limit — must reject",
		_big_tok, SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 8192, None,
	))
	tests.append(TC(
		"Cat 13 | Test 87: Normal token, max_token_bytes=10 (tiny limit) — must reject",
		_normal_tok, SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 10, None,
	))
	tests.append(TC(
		"Cat 13 | Test 88: Large token, max_token_bytes=100000 — must accept",
		_huge_tok, SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 100_000, {"sub": "user-42"},
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 14: Claims Extraction (Tests 89–94)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(_tc("Cat 14 | Test 89: sub claim extracted correctly",
		_hs(_vp("extract-me")), SECRET, "HS256", exp={"sub": "extract-me"}))
	tests.append(_tc("Cat 14 | Test 90: custom role claim in returned dict",
		_hs(_vp("role-user", {"role": "moderator"})), SECRET, "HS256",
		exp={"role": "moderator"}))
	tests.append(_tc("Cat 14 | Test 91: iss present in returned claims dict",
		_hs(_vp()), SECRET, "HS256", exp={"iss": ISSUER}))
	tests.append(_tc("Cat 14 | Test 92: aud present in returned claims dict",
		_hs(_vp()), SECRET, "HS256", exp={"aud": AUDIENCE}))
	tests.append(_tc("Cat 14 | Test 93: numeric claims returned correctly",
		_hs(_vp("nums", {"a": 1, "b": 2, "c": 3})), SECRET, "HS256",
		exp={"a": 1, "b": 2, "c": 3}))
	tests.append(_tc("Cat 14 | Test 94: nested dict claim preserved in returned dict",
		_hs(_vp("nested", {"meta": {"env": "prod", "v": 2}})), SECRET, "HS256",
		exp={"meta": {"env": "prod", "v": 2}}))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 15: Constant-Time Correctness (Tests 95–97)
	# Tests correctness properties that constant-time code must satisfy:
	# a shared prefix must NOT cause a false acceptance.
	# ═══════════════════════════════════════════════════════════════════════════

	# Secret with same prefix as real SECRET but different suffix — must still fail
	tests.append(_tc(
		"Cat 15 | Test 95: Same-length wrong HMAC secret (same prefix) — must reject",
		_make_jwt(HS256_HDR, _vp(), PREFIX_SECRET, "HS256"),
		SECRET, "HS256", exp=None,
	))
	# Audience with same prefix as AUDIENCE but truncated (different) — must reject
	_prefix_aud = AUDIENCE[:-3]   # "https://api.example.c"
	tests.append(TC(
		"Cat 15 | Test 96: Audience prefix match (shorter) — must reject",
		_hs({**_vp(), "aud": _prefix_aud}), SECRET, "HS256",
		AUDIENCE, FIXED_NOW, None, None, None, None, 8192, None,
	))
	# Issuer with same prefix but shorter — must reject
	tests.append(TC(
		"Cat 15 | Test 97: Issuer prefix match (shorter) — must reject",
		_hs({**_vp(), "iss": PREFIX_ISS}), SECRET, "HS256",
		AUDIENCE, FIXED_NOW, ISSUER, None, None, None, 8192, None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 16: Combined / Complex (Tests 98–100)
	# ═══════════════════════════════════════════════════════════════════════════

	# Test 98: Multiple simultaneous failures — all checks must independently fail
	tests.append(TC(
		"Cat 16 | Test 98: Expired + wrong aud + revoked jti — all fail, must reject",
		_hs({**_vp(), "exp": int(PAST), "aud": OTHER_AUD, "jti": JTI_BAD}),
		SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, REVOKED_SET, None, None, 8192, None,
	))
	# Test 99: Everything valid except iss
	tests.append(TC(
		"Cat 16 | Test 99: All valid except wrong iss — must reject",
		_hs({**_vp(), "iss": BAD_ISS, "jti": JTI_GOOD}), SECRET, "HS256",
		AUDIENCE, FIXED_NOW,
		ISSUER, {JTI_BAD}, KEY_STORE | {"hmac-key-2024-01"}, 7200.0, 8192, None,
	))
	# Test 100: Perfect token — every optional check passes
	_perfect = {
		"sub": "perfect",
		"aud": AUDIENCE,
		"iss": ISSUER,
		"exp": int(FAR_FUTURE),
		"nbf": int(PAST),
		"iat": int(FIXED_NOW) - 600,
		"jti": "unique-perfect-jti-99999",
	}
	tests.append(TC(
		"Cat 16 | Test 100: Perfect token — all 8 optional checks pass",
		_make_jwt({**HS256_HDR, "kid": VALID_KID}, _perfect, SECRET, "HS256"),
		SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, {"other-revoked"}, KEY_STORE, 3600.0, 8192, {"sub": "perfect"},
	))

	return tests


def run_all_tests() -> None:
	tests = _build_tests()
	assert len(tests) == 100, f"Expected 100 tests, built {len(tests)}"

	print()
	print("╔" + "═" * 74 + "╗")
	print("║" + f"{'JWT TOKEN VALIDATOR — ALL ALGORITHMS':^74}" + "║")
	print("║" + f"{'100 Comprehensive Security Tests':^74}" + "║")
	print("║" + f"{'Sources: API Security in Action Ch.6 · Hacking APIs Ch.8':^74}" + "║")
	print("║" + f"{'RFC 7519 (JWT) · RFC 7518 (JWA)':^74}" + "║")
	print("╚" + "═" * 74 + "╝")
	print()

	passed = 0
	failed = 0
	last_cat = None

	for tc in tests:
		cat = tc.label.split("|")[0].strip()
		if cat != last_cat:
			print(f"  {Colors.CYAN}{Colors.BOLD}{cat}{Colors.END}")
			last_cat = cat

		try:
			result = validate_jwt(
				tc.token,
				tc.key,
				tc.algorithm,
				tc.audience,
				tc.current_time,
				tc.expected_issuer,
				tc.revoked_jti_set,
				tc.key_store,
				tc.max_age_seconds,
				tc.max_token_bytes,
			)
		except Exception as exc:
			label = tc.label.split("|")[1].strip()
			print(f"  {Colors.RED}❌ ERROR  {Colors.END}{label}")
			print(f"       {Colors.DIM}Raised {type(exc).__name__}: {exc}{Colors.END}")
			failed += 1
			continue

		ok = _ok(result, tc.expected)
		label = tc.label.split("|")[1].strip()

		if ok:
			print(f"  {Colors.GREEN}✅ PASS   {Colors.END}{label}")
			passed += 1
		else:
			print(f"  {Colors.RED}❌ FAIL   {Colors.END}{label}")
			if tc.expected is None:
				print(f"       {Colors.DIM}Expected: None  |  Got: {result}{Colors.END}")
			else:
				print(f"       {Colors.DIM}Expected dict with {tc.expected}  |  Got: {result}{Colors.END}")
			failed += 1

	total = passed + failed
	pct   = int(passed / total * 100)

	print()
	print("═" * 76)
	print(f"{Colors.BOLD}  RESULTS: {passed}/{total} tests passed ({pct}%){Colors.END}")
	print("═" * 76)

	if passed == 100:
		print("╔" + "═" * 74 + "╗")
		print("║" + f"{Colors.GREEN}{Colors.BOLD}{'🎉  PERFECT — ALL 100 TESTS PASSED! 🎉':^84}{Colors.END}" + "║")
		print("╚" + "═" * 74 + "╝")
		print()
		print(f"  {Colors.GREEN}▶ Next steps (API Security in Action Ch.6 §6.3):{Colors.END}")
		print("    1. Add JWE (encrypted JWT) support — keep sensitive claims off the wire")
		print("    2. Implement a JWKS endpoint + key rotation logic")
		print("    3. Benchmark aud list iteration: verify no short-circuit on match")
		print("    4. Try PortSwigger JWT labs 4-6 (kid injection, jku SSRF) — Week 15")
		print("    5. Write the Dev.to blog post for your portfolio")

	elif passed >= 85:
		print(f"  {Colors.YELLOW}⚡ Almost there! {failed} tests failing.{Colors.END}")
		print("    • Review Cat 15: constant-time comparisons must check ALL bytes")
		print("    • Review Cat 12: iat missing when max_age is set → reject (fail secure)")
		print("    • Review Cat 10: jti missing when revoked_jti_set is set → reject")

	elif passed >= 70:
		print(f"  {Colors.YELLOW}📈 Good progress! Areas to focus on:{Colors.END}")
		print("    • Cat 2: For ES256/384/512 convert raw (r||s) → DER before verify()")
		print("      ES256=32B/coord, ES384=48B/coord, ES512=66B/coord (RFC 7518 §3.4)")
		print("    • Cat 2: PS256/384/512 uses PSS padding with salt = hash digest size")
		print("    • Cat 9: Use hmac.compare_digest for iss (not ==)")

	elif passed >= 45:
		print(f"  {Colors.YELLOW}🔧 Keep going! Key hints:{Colors.END}")
		print("    1. Structure first: exactly 3 segments split by '.'")
		print("    2. Header alg must equal expected_algorithm exactly (case-sensitive)")
		print("    3. HMAC: hmac.new(key, signing_input, hash_fn).digest()")
		print("    4. Verify signature BEFORE parsing any claims")
		print("    5. exp: current_time < exp (strict — exp==now is expired)")
		print("    6. nbf: current_time >= nbf (inclusive — nbf==now is valid)")

	else:
		print(f"  {Colors.RED}🔑 Getting started — fundamentals:{Colors.END}")
		print("    1. A JWT is: base64url(header) + '.' + base64url(payload) + '.' + sig")
		print("    2. Imports: hmac, hashlib, base64, json; from cryptography import ...")
		print("    3. Only accept algorithm in header if it matches expected_algorithm")
		print("    4. Reference: API Security in Action Ch.6 pp.187-195")
		print("    5. Reference: RFC 7518 §3 for algorithm identifiers")

	print()


if __name__ == "__main__":
	run_all_tests()
