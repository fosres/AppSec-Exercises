"""
Exercise: JWT Token Validator — ALL ALGORITHMS, 175 COMPREHENSIVE TESTS
========================================================================

Implement validate_jwt() — a production-grade validator that correctly
handles every common JWT algorithm family and every realistic security
check a real API server performs before trusting a token.

INSTRUCTIONS:
	1. pip install cryptography
	2. Implement validate_jwt() in the section below
	3. Run: python3 jwt_token_validator_v2_175_tests.py
	4. Pass all 175 tests.

DEPENDENCIES (reader must install):
	pip install cryptography "PyJWT>=2.8"

	NOTE: PyJWT 2.8+ is required. jwt.decode_complete() was not exposed at the
	module level until PyJWT 2.8. Earlier versions only expose it on PyJWT()
	instances. The test suite verifies the version at startup.

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
import jwt
import time
from typing import Optional, Any

import logging

logger = logging.getLogger(__name__)

# ── PyJWT compatibility shim ─────────────────────────────────────────────────
# jwt.decode_complete() was not exposed at module level until PyJWT 2.8.
# On PyJWT 2.7.x it only exists on the PyJWT() instance.
# This shim makes it available as jwt.decode_complete on all supported versions
# so the test suite and solution work identically on 2.7 and 2.8+.
if not hasattr(jwt, "decode_complete"):
	jwt.decode_complete = jwt.PyJWT().decode_complete

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
	
	if len(token.encode()) > max_token_bytes:

		logger.debug("token length larger than max bytesize of 8192")

		return None

	structure = token.split(".")

	if len(structure) != 3:
		
		logger.debug("token structure does not have 3 arguments exactly")

		return None		

	# jwt.decode_complete() 

	# The above function verifies (3.) header, (6.) payload,

	# and (5.) signature

	# (11.) issuer, and (10.) audience

	try:

		jwt_decode = jwt.decode_complete(

				token,

				key,

				algorithms = [expected_algorithm],

				audience = expected_audience,

				issuer = expected_issuer,			
		)

	except jwt.InvalidSignatureError:

		logger.debug("Invalid Signature")

		return None
	
	except jwt.InvalidKeyError:

		logger.debug("Invalid Key")

		return None
	
	except jwt.ExpiredSignatureError:
		
		logger.debug(f"Expired Signature")
		
		return None
	
	except jwt.ImmatureSignatureError:
		
		logger.debug(f"Token issued too early")
		
		return None
	
	except jwt.InvalidTokenError:
		
		logger.debug(f"Invalid Token")

		return None

	except Exception as e:
		
		logger.debug(f"Exception: {e}")

		return None	

	# Header can contain the following relevant fields:

	'''
		1. alg

		2. type

		3. kid
	'''

	jwt_decode_header = jwt_decode['header']

	if	(

			'kid' in jwt_decode_header

			and

			key_store is not None

			and

			jwt_decode_header['kid'] not in key_store
		):

		return None
		

	# Payload can contain the following relevant fields:

	'''
		1. "sub"

  		2. "aud"

  		3. "iss"

		4. "nbf"

  		5. "iat"

  		6. "exp"
	'''

	jwt_decode_payload = jwt_decode['payload']

	jwt_decode_signature = jwt_decode['signature']
	

	if	(
			max_age_seconds is not None	

			and
			
			'iat' not in jwt_decode_payload

		):

		return None

	if	(
			'iat' in jwt_decode_payload

			and

			max_age_seconds is not None	
		):

		if current_time is None:

			current_time = time.time()

		age = current_time - jwt_decode_payload['iat']

		if age > max_age_seconds:

			return None		

	if	(
			revoked_jti_set is not None

			and

			'jti' not in jwt_decode_payload
		):

		return None
	
	if	(
			revoked_jti_set is not None

			and

			'jti' in jwt_decode_payload

			and

			not isinstance(jwt_decode_payload['jti'],str)
		):

		return None

	if	(
			revoked_jti_set is not None

			and

			'jti' in jwt_decode_payload

			and

			jwt_decode_payload['jti'] in revoked_jti_set
		):

		return None

	return jwt_decode_payload
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
_EC521_PRIV     = ec.generate_private_key(ec.SECP521R1())
_EC521_PUB      = _EC521_PRIV.public_key()       # ES512 (P-521)
_EC521_PRIV_ALT = ec.generate_private_key(ec.SECP521R1())
_EC521_PUB_ALT  = _EC521_PRIV_ALT.public_key()  # "wrong" ES512 key

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

FIXED_NOW   = float(int(time.time()))  # real clock, truncated so int(FIXED_NOW)==FIXED_NOW
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
REVOKED_SET    = {JTI_BAD, "other-revoked-jti"}
JTI_GOOD_ALT   = "jti-good-alt-aabbccdd-1234"
EVIL_KID2      = ";rm -rf /tmp/;"
JTI_UPPER      = "ABC-CASE-SENSITIVE-JTI"
JTI_LOWER      = "abc-case-sensitive-jti"   # differs only by case from JTI_UPPER

# For the RS256→HS256 algorithm confusion attack (Hacking APIs p.200):
# Attacker uses the RSA public key DER bytes as the HMAC secret.
# This fixture is computed at module load time.
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
_RSA_PUB_DER   = _RSA_PUB.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

# Suffix-attack fixtures (longer strings that share expected as a prefix)
ISS_SUFFIX_ATK = ISSUER  + ".evil.com"   # "https://auth.example.com.evil.com"
AUD_SUFFIX_ATK = AUDIENCE + ".evil.com"  # "https://api.example.com.evil.com"
AUD_UPPER      = AUDIENCE.upper()        # "HTTPS://API.EXAMPLE.COM"
ISS_UPPER      = ISSUER.upper()          # "HTTPS://AUTH.EXAMPLE.COM"

HS256_HDR = {"alg": "HS256", "typ": "JWT"}
RS256_HDR = {"alg": "RS256", "typ": "JWT"}
RS384_HDR = {"alg": "RS384", "typ": "JWT"}
RS512_HDR = {"alg": "RS512", "typ": "JWT"}
PS256_HDR = {"alg": "PS256", "typ": "JWT"}
PS384_HDR = {"alg": "PS384", "typ": "JWT"}
PS512_HDR = {"alg": "PS512", "typ": "JWT"}
ES256_HDR = {"alg": "ES256", "typ": "JWT"}
ES384_HDR = {"alg": "ES384", "typ": "JWT"}
ES512_HDR = {"alg": "ES512", "typ": "JWT"}


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
	"""Construct all 175 test cases. Returns list of TC namedtuples."""

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
		"Cat 1 | Test  7: HS256 — string sub that looks numeric",
		_hs(_vp(extra={"sub": "99999"})), SECRET, "HS256",
		exp={"sub": "99999"},
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

	tests.append(_tc("Cat 6 | Test 46: aud is integer (not string or list) — type error, must reject",
		_hs({**_vp(), "aud": 99}), SECRET, "HS256", exp=None))

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


	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 17: Payload / Header JSON Corruption (Tests 101–108)
	# Structural: base64 decodes fine but the JSON inside is invalid or wrong type
	# ═══════════════════════════════════════════════════════════════════════════

	# Build a token where payload base64 is valid but JSON is garbage
	_h101 = _b64url_encode(json.dumps(HS256_HDR, separators=(",",":")).encode())
	_p101 = _b64url_encode(b"not-json-at-all!!!")
	_si101 = f"{_h101}.{_p101}".encode()
	_s101 = _b64url_encode(hmac.new(SECRET, _si101, hashlib.sha256).digest())
	tests.append(_tc(
		"Cat 17 | Test 101: Payload is valid base64 but not JSON — must reject",
		f"{_h101}.{_p101}.{_s101}", SECRET, "HS256", exp=None,
	))

	# Header decodes from base64 but is not valid JSON
	_h102 = _b64url_encode(b"[not-json]")
	_p102 = _b64url_encode(json.dumps(_vp(), separators=(",",":")).encode())
	_si102 = f"{_h102}.{_p102}".encode()
	_s102 = _b64url_encode(hmac.new(SECRET, _si102, hashlib.sha256).digest())
	tests.append(_tc(
		"Cat 17 | Test 102: Header is valid base64 but not JSON — must reject",
		f"{_h102}.{_p102}.{_s102}", SECRET, "HS256", exp=None,
	))

	# Payload is a JSON array, not an object
	_arr_payload = [1, 2, 3]
	_h103 = _b64url_encode(json.dumps(HS256_HDR, separators=(",",":")).encode())
	_p103 = _b64url_encode(json.dumps(_arr_payload, separators=(",",":")).encode())
	_si103 = f"{_h103}.{_p103}".encode()
	_s103 = _b64url_encode(hmac.new(SECRET, _si103, hashlib.sha256).digest())
	tests.append(_tc(
		"Cat 17 | Test 103: Payload is a JSON array (not object) — must reject",
		f"{_h103}.{_p103}.{_s103}", SECRET, "HS256", exp=None,
	))

	# Header is a JSON array, not an object
	_h104 = _b64url_encode(json.dumps(["alg", "HS256"], separators=(",",":")).encode())
	_p104 = _b64url_encode(json.dumps(_vp(), separators=(",",":")).encode())
	_si104 = f"{_h104}.{_p104}".encode()
	_s104 = _b64url_encode(hmac.new(SECRET, _si104, hashlib.sha256).digest())
	tests.append(_tc(
		"Cat 17 | Test 104: Header is a JSON array (not object) — must reject",
		f"{_h104}.{_p104}.{_s104}", SECRET, "HS256", exp=None,
	))

	# iss is an integer — PyJWT 2.11.0 raises InvalidIssuerError on type mismatch
	tests.append(TC(
		"Cat 17 | Test 105: iss is integer (not string) when expected_issuer is set — must reject",
		_hs({**_vp(), "iss": 99999}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, None, None, None, 8192, None,
	))

	# exp is JSON null
	tests.append(_tc(
		"Cat 17 | Test 106: exp is null (JSON null) — must reject",
		_hs({**_vp(), "exp": None}), SECRET, "HS256", exp=None,
	))

	# aud is JSON null
	tests.append(_tc(
		"Cat 17 | Test 107: aud is null (JSON null) — must reject",
		_hs({**_vp(), "aud": None}), SECRET, "HS256", exp=None,
	))

	# aud list mixing string entries with an integer — type error, reject
	tests.append(_tc(
		"Cat 17 | Test 108: aud list contains integer alongside valid string — must reject",
		_hs({**_vp(), "aud": [AUDIENCE, 42]}), SECRET, "HS256", exp=None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 18: ES512 + Cross-Family Algorithm Mismatches (Tests 109–116)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(_tc(
		"Cat 18 | Test 109: ES512 — valid (ECDSA P-521)",
		_make_jwt(ES512_HDR, _vp("svc-ec512"), _EC521_PRIV, "ES512"),
		_EC521_PUB, "ES512", exp={"sub": "svc-ec512"},
	))
	tests.append(_tc(
		"Cat 18 | Test 110: ES512 — signed with wrong P-521 key — must reject",
		_make_jwt(ES512_HDR, _vp("svc-ec512"), _EC521_PRIV_ALT, "ES512"),
		_EC521_PUB, "ES512", exp=None,
	))
	# PS256 token when RS256 expected (same RSA key, different padding)
	tests.append(_tc(
		"Cat 18 | Test 111: PS256 token when RS256 expected — sibling mismatch, reject",
		_make_jwt(PS256_HDR, _vp("svc-pss"), _RSA_PRIV, "PS256"),
		_RSA_PUB, "RS256", exp=None,
	))
	# RS256 token when PS256 expected
	tests.append(_tc(
		"Cat 18 | Test 112: RS256 token when PS256 expected — sibling mismatch, reject",
		_make_jwt(RS256_HDR, _vp("svc-rsa"), _RSA_PRIV, "RS256"),
		_RSA_PUB, "PS256", exp=None,
	))
	# ES256 token when ES384 expected (same family, different hash)
	tests.append(_tc(
		"Cat 18 | Test 113: ES256 token when ES384 expected — same family, reject",
		_make_jwt(ES256_HDR, _vp("svc-ec"), _EC256_PRIV, "ES256"),
		_EC256_PUB, "ES384", exp=None,
	))
	# HS256 token when HS512 expected (same family, different hash)
	tests.append(_tc(
		"Cat 18 | Test 114: HS256 token when HS512 expected — same family, reject",
		_hs(_vp()), SECRET, "HS512", exp=None,
	))
	# RS512 signed with different RSA key
	tests.append(_tc(
		"Cat 18 | Test 115: RS512 signed with wrong RSA key — must reject",
		_make_jwt(RS512_HDR, _vp("svc-rsa"), _RSA_PRIV_ALT, "RS512"),
		_RSA_PUB, "RS512", exp=None,
	))
	# PS512 signed with wrong key
	tests.append(_tc(
		"Cat 18 | Test 116: PS512 signed with wrong RSA key — must reject",
		_make_jwt(PS512_HDR, _vp("svc-pss"), _RSA_PRIV_ALT, "PS512"),
		_RSA_PUB, "PS512", exp=None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 19: Audience Edge Cases (Tests 117–123)
	# ═══════════════════════════════════════════════════════════════════════════

	tests.append(_tc(
		"Cat 19 | Test 117: aud is empty list [] — must reject",
		_hs({**_vp(), "aud": []}), SECRET, "HS256", exp=None,
	))
	tests.append(_tc(
		"Cat 19 | Test 118: aud is an integer, not a string — must reject",
		_hs({**_vp(), "aud": 42}), SECRET, "HS256", exp=None,
	))
	tests.append(_tc(
		"Cat 19 | Test 119: aud list with non-string entries [123, 456] — must reject",
		_hs({**_vp(), "aud": [123, 456]}), SECRET, "HS256", exp=None,
	))
	# Expected audience is the LAST entry in a long list — tests full iteration
	_big_aud_list = [f"https://service-{i}.example.com" for i in range(18)] + [AUDIENCE]
	tests.append(_tc(
		"Cat 19 | Test 120: aud list with expected as last of 19 entries — must accept",
		_hs({**_vp(), "aud": _big_aud_list}), SECRET, "HS256",
		exp={"sub": "user-42"},
	))
	# aud list with duplicates
	tests.append(_tc(
		"Cat 19 | Test 121: aud list with duplicate expected entries — must accept",
		_hs({**_vp(), "aud": [AUDIENCE, AUDIENCE]}), SECRET, "HS256",
		exp={"sub": "user-42"},
	))
	# aud list where expected is neither first nor last (middle)
	_mid_aud_list = [OTHER_AUD, OTHER_AUD, AUDIENCE, OTHER_AUD, OTHER_AUD]
	tests.append(_tc(
		"Cat 19 | Test 122: aud list with expected in middle — must accept",
		_hs({**_vp(), "aud": _mid_aud_list}), SECRET, "HS256",
		exp={"sub": "user-42"},
	))
	# aud list contains only non-matching strings
	tests.append(_tc(
		"Cat 19 | Test 123: aud list with multiple wrong string entries — must reject",
		_hs({**_vp(), "aud": [OTHER_AUD, "https://third.example.com"]}),
		SECRET, "HS256", exp=None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 20: kid Edge Cases (Tests 124–129)
	# ═══════════════════════════════════════════════════════════════════════════

	# Token has no kid, but key_store is non-None — no kid to validate, must accept
	tests.append(TC(
		"Cat 20 | Test 124: no kid in token, key_store non-empty — accept (nothing to check)",
		_hs(_vp()), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, KEY_STORE, None, 8192, {"sub": "user-42"},
	))
	# kid is an integer in the header (type safety: kid must be a string)
	tests.append(TC(
		"Cat 20 | Test 125: kid is integer (123) in header — must reject",
		_make_jwt({**HS256_HDR, "kid": 123}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, KEY_STORE, None, 8192, None,
	))
	# kid is null in the header when key_store is set
	tests.append(TC(
		"Cat 20 | Test 126: kid is null in header, key_store set — must reject",
		_make_jwt({**HS256_HDR, "kid": None}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, KEY_STORE, None, 8192, None,
	))
	# kid with shell-injection characters — not in store, must reject
	tests.append(TC(
		"Cat 20 | Test 127: kid with shell-injection chars — not in store, must reject",
		_make_jwt({**HS256_HDR, "kid": EVIL_KID2}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, KEY_STORE, None, 8192, None,
	))
	# No kid in token, key_store is empty set — no kid to check, must accept
	tests.append(TC(
		"Cat 20 | Test 128: no kid in token, key_store=set() (empty) — accept (nothing to check)",
		_hs(_vp()), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, set(), None, 8192, {"sub": "user-42"},
	))
	# kid matches the OTHER_KID (second entry in KEY_STORE), not VALID_KID
	tests.append(TC(
		"Cat 20 | Test 129: kid matches second key in store (OTHER_KID) — must accept",
		_make_jwt({**HS256_HDR, "kid": OTHER_KID}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, KEY_STORE, None, 8192, {"sub": "user-42"},
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 21: jti Edge Cases (Tests 130–134)
	# ═══════════════════════════════════════════════════════════════════════════

	# jti is empty string, revoked_jti_set contains ""
	tests.append(TC(
		"Cat 21 | Test 130: jti='' and revoked set contains '' — must reject (revoked)",
		_hs(_vp(extra={"jti": ""})), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, {""}, None, None, 8192, None,
	))
	# jti is empty string, revoked_jti_set does NOT contain "" — jti present, not revoked
	tests.append(TC(
		"Cat 21 | Test 131: jti='' not in revoked set — must accept",
		_hs(_vp(extra={"jti": ""})), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, {JTI_BAD}, None, None, 8192, {"sub": "user-42"},
	))
	# jti is an integer (not string) when revocation check is enabled
	tests.append(TC(
		"Cat 21 | Test 132: jti is integer (not string) when revoked_jti_set set — must reject",
		_hs(_vp(extra={"jti": 99999})), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, REVOKED_SET, None, None, 8192, None,
	))
	# jti case sensitivity: "ABC..." not same as "abc..."
	tests.append(TC(
		"Cat 21 | Test 133: jti case differs from revoked entry — must accept (not revoked)",
		_hs(_vp(extra={"jti": JTI_UPPER})), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, {JTI_LOWER}, None, None, 8192, {"sub": "user-42"},
	))
	# revoked_jti_set=set() (empty), token has NO jti — jti required when check enabled
	tests.append(TC(
		"Cat 21 | Test 134: revoked_jti_set=set() and jti absent — must reject (jti required)",
		_hs(_vp()), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, set(), None, None, 8192, None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 22: Float Timestamps + Time Edge Cases (Tests 135–140)
	# RFC 7519 §2 defines NumericDate as a JSON numeric value — floats are valid
	# ═══════════════════════════════════════════════════════════════════════════

	# exp as float (non-integer numeric — RFC 7519 allows this)
	tests.append(_tc(
		"Cat 22 | Test 135: exp is float (FUTURE + 0.9) — must accept",
		_hs({**_vp(), "exp": FUTURE + 0.9}), SECRET, "HS256",
		exp={"sub": "user-42"},
	))
	# nbf as float
	tests.append(_tc(
		"Cat 22 | Test 136: nbf is float (PAST + 0.5) — must accept",
		_hs({**_vp(), "nbf": PAST + 0.5}), SECRET, "HS256",
		exp={"sub": "user-42"},
	))
	# iat as float with max_age set
	tests.append(TC(
		"Cat 22 | Test 137: iat is float, within max_age — must accept",
		_hs({**_vp(), "iat": FIXED_NOW - 1799.9}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, 3600.0, 8192, {"sub": "user-42"},
	))
	# exp is a boolean — wrong type, reject
	tests.append(_tc(
		"Cat 22 | Test 138: exp is boolean True — wrong type, must reject",
		_hs({**_vp(), "exp": True}), SECRET, "HS256", exp=None,
	))
	# iss is an integer, not a string, when expected_issuer is set
	tests.append(TC(
		"Cat 22 | Test 139: iss is integer (not string) when expected_issuer set — must reject",
		_hs({**_vp(), "iss": 12345}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, None, None, None, 8192, None,
	))
	# iat exactly == current_time with max_age=0 — age is 0, 0 <= 0, must accept
	tests.append(TC(
		"Cat 22 | Test 140: iat == current_time, max_age=0 — age=0 <= 0, must accept",
		_hs({**_vp(), "iat": int(FIXED_NOW)}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, 0.0, 8192, {"sub": "user-42"},
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 23: Structural Edge Cases (Tests 141–145)
	# ═══════════════════════════════════════════════════════════════════════════

	# Signature segment is empty string (header.payload.)
	_base_for_143 = _hs(_vp())
	_hdr_seg, _pay_seg, _ = _base_for_143.split(".")
	tests.append(_tc(
		"Cat 23 | Test 141: Third segment (signature) is empty — must reject",
		f"{_hdr_seg}.{_pay_seg}.", SECRET, "HS256", exp=None,
	))
	# All three segments are empty ("..")
	tests.append(_tc(
		"Cat 23 | Test 142: All segments empty ('..') — must reject",
		"..", SECRET, "HS256", exp=None,
	))
	# Token is just dots with no content ("...")
	tests.append(_tc(
		"Cat 23 | Test 143: Four dots (five empty segments) — must reject",
		"....", SECRET, "HS256", exp=None,
	))
	# Payload is a JSON primitive (a bare string, not an object)
	_h144 = _b64url_encode(json.dumps(HS256_HDR, separators=(",",":")).encode())
	_p144 = _b64url_encode(json.dumps("just-a-string", separators=(",",":")).encode())
	_si144 = f"{_h144}.{_p144}".encode()
	_s144 = _b64url_encode(hmac.new(SECRET, _si144, hashlib.sha256).digest())
	tests.append(_tc(
		"Cat 23 | Test 144: Payload is a JSON string primitive (not object) — must reject",
		f"{_h144}.{_p144}.{_s144}", SECRET, "HS256", exp=None,
	))
	# Payload is JSON number 42
	_h145 = _b64url_encode(json.dumps(HS256_HDR, separators=(",",":")).encode())
	_p145 = _b64url_encode(json.dumps(42, separators=(",",":")).encode())
	_si145 = f"{_h145}.{_p145}".encode()
	_s145 = _b64url_encode(hmac.new(SECRET, _si145, hashlib.sha256).digest())
	tests.append(_tc(
		"Cat 23 | Test 145: Payload is JSON number 42 (not object) — must reject",
		f"{_h145}.{_p145}.{_s145}", SECRET, "HS256", exp=None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 24: Combined Asymmetric + All Optional Checks (Tests 146–150)
	# Verifies optional checks work correctly with asymmetric algorithm families
	# ═══════════════════════════════════════════════════════════════════════════

	_perfect_asym = {
		"sub":  "asym-perfect",
		"aud":  AUDIENCE,
		"iss":  ISSUER,
		"exp":  int(FAR_FUTURE),
		"nbf":  int(PAST),
		"iat":  int(FIXED_NOW) - 600,
		"jti":  JTI_GOOD_ALT,
	}

	tests.append(TC(
		"Cat 24 | Test 146: RS256 + iss + jti + kid + max_age — all valid, must accept",
		_make_jwt({**RS256_HDR, "kid": VALID_KID}, _perfect_asym, _RSA_PRIV, "RS256"),
		_RSA_PUB, "RS256", AUDIENCE, FIXED_NOW,
		ISSUER, {"other-revoked"}, KEY_STORE, 3600.0, 8192, {"sub": "asym-perfect"},
	))
	tests.append(TC(
		"Cat 24 | Test 147: ES256 + iss + jti + kid + max_age — all valid, must accept",
		_make_jwt({**ES256_HDR, "kid": VALID_KID}, _perfect_asym, _EC256_PRIV, "ES256"),
		_EC256_PUB, "ES256", AUDIENCE, FIXED_NOW,
		ISSUER, {"other-revoked"}, KEY_STORE, 3600.0, 8192, {"sub": "asym-perfect"},
	))
	tests.append(TC(
		"Cat 24 | Test 148: RS256 + all checks enabled, jti revoked — must reject",
		_make_jwt(RS256_HDR, {**_perfect_asym, "jti": JTI_BAD}, _RSA_PRIV, "RS256"),
		_RSA_PUB, "RS256", AUDIENCE, FIXED_NOW,
		ISSUER, REVOKED_SET, None, 3600.0, 8192, None,
	))
	tests.append(TC(
		"Cat 24 | Test 149: ES512 + all checks enabled — valid, must accept",
		_make_jwt({**ES512_HDR, "kid": VALID_KID}, _perfect_asym, _EC521_PRIV, "ES512"),
		_EC521_PUB, "ES512", AUDIENCE, FIXED_NOW,
		ISSUER, {"other-revoked"}, KEY_STORE, 3600.0, 8192, {"sub": "asym-perfect"},
	))
	tests.append(TC(
		"Cat 24 | Test 150: PS256 + all checks enabled — valid, must accept",
		_make_jwt({**PS256_HDR, "kid": VALID_KID}, _perfect_asym, _RSA_PRIV, "PS256"),
		_RSA_PUB, "PS256", AUDIENCE, FIXED_NOW,
		ISSUER, {"other-revoked"}, KEY_STORE, 3600.0, 8192, {"sub": "asym-perfect"},
	))


	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 25: Algorithm Confusion — The Canonical Attack + Key Type Safety
	# (Tests 151–157)
	# Source: Hacking APIs Ch.8 p.200; API Security in Action p.191
	# ═══════════════════════════════════════════════════════════════════════════

	# THE canonical RS256→HS256 attack: token signed HS256 using RSA public key
	# DER bytes as HMAC secret. Expected_algorithm is RS256. Header says HS256.
	# Rejected because header alg (HS256) != expected_algorithm (RS256).
	_rs256_hs256_attack = _make_jwt(
		{"alg": "HS256", "typ": "JWT"}, _vp("attacker"),
		_RSA_PUB_DER, "HS256",
	)
	tests.append(_tc(
		"Cat 25 | Test 151: RS256→HS256 confusion (pub key as HMAC secret) — must reject",
		_rs256_hs256_attack, _RSA_PUB, "RS256", exp=None,
	))

	# Same attack but we correctly expect HS256 — the signature is wrong for our SECRET
	tests.append(_tc(
		"Cat 25 | Test 152: HS256 signed with RSA pub-key bytes (not our HMAC secret) — must reject",
		_rs256_hs256_attack, SECRET, "HS256", exp=None,
	))

	# EC key passed where RSA algorithm expected — must not raise, must return None
	tests.append(_tc(
		"Cat 25 | Test 153: EC public key passed for RS256 (wrong key type) — must reject gracefully",
		_make_jwt(RS256_HDR, _vp("svc-rsa"), _RSA_PRIV, "RS256"),
		_EC256_PUB, "RS256", exp=None,
	))

	# RSA key passed where EC algorithm expected — must not raise, must return None
	tests.append(_tc(
		"Cat 25 | Test 154: RSA public key passed for ES256 (wrong key type) — must reject gracefully",
		_make_jwt(ES256_HDR, _vp("svc-ec"), _EC256_PRIV, "ES256"),
		_RSA_PUB, "ES256", exp=None,
	))

	# alg with Unicode fullwidth digits — must not match "HS256" exactly
	tests.append(_tc(
		"Cat 25 | Test 155: alg='HS\uff12\uff15\uff16' (Unicode fullwidth) — must reject",
		_make_jwt({"alg": "HS\uff12\uff15\uff16", "typ": "JWT"}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", exp=None,
	))

	# alg with embedded null byte — must not match "HS256"
	tests.append(_tc(
		"Cat 25 | Test 156: alg='HS256\x00' (null byte suffix) — must reject",
		_make_jwt({"alg": "HS256\x00", "typ": "JWT"}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", exp=None,
	))

	# PS384 signed with wrong RSA key — must reject (not yet tested for PS384)
	tests.append(_tc(
		"Cat 25 | Test 157: PS384 signed with wrong RSA key — must reject",
		_make_jwt(PS384_HDR, _vp("svc-pss"), _RSA_PRIV_ALT, "PS384"),
		_RSA_PUB, "PS384", exp=None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 26: Constant-Time / String Comparison Completeness (Tests 158–163)
	# These test correctness properties that constant-time code must satisfy:
	# a shared prefix or suffix must NOT cause a false acceptance or rejection.
	# ═══════════════════════════════════════════════════════════════════════════

	# iss LONGER than expected — suffix attack (ISSUER is a prefix of iss claim)
	tests.append(TC(
		"Cat 26 | Test 158: iss longer than expected (suffix attack) — must reject",
		_hs({**_vp(), "iss": ISS_SUFFIX_ATK}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, None, None, None, 8192, None,
	))

	# aud LONGER than expected — suffix attack (AUDIENCE is a prefix of aud claim)
	tests.append(TC(
		"Cat 26 | Test 159: aud longer than expected (suffix attack) — must reject",
		_hs({**_vp(), "aud": AUD_SUFFIX_ATK}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 8192, None,
	))

	# aud uppercased — case sensitivity: "HTTPS://API.EXAMPLE.COM" != "https://api.example.com"
	tests.append(TC(
		"Cat 26 | Test 160: aud uppercased — case-sensitive comparison must reject",
		_hs({**_vp(), "aud": AUD_UPPER}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 8192, None,
	))

	# iss uppercased — case sensitivity
	tests.append(TC(
		"Cat 26 | Test 161: iss uppercased — case-sensitive comparison must reject",
		_hs({**_vp(), "iss": ISS_UPPER}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, None, None, None, 8192, None,
	))

	# jti=null (JSON null, not absent) when revocation check enabled — must reject
	tests.append(TC(
		"Cat 26 | Test 162: jti=null (JSON null) when revoked_jti_set set — must reject",
		_hs(_vp(extra={"jti": None})), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, REVOKED_SET, None, None, 8192, None,
	))

	# aud=boolean True — not a string or list, must reject
	tests.append(_tc(
		"Cat 26 | Test 163: aud=True (boolean) — wrong type, must reject",
		_hs({**_vp(), "aud": True}), SECRET, "HS256", exp=None,
	))

	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 27: Boundary Conditions and Robustness (Tests 164–175)
	# ═══════════════════════════════════════════════════════════════════════════

	# exp = 0 (Unix epoch 1970-01-01T00:00:00Z) — definitely expired
	tests.append(_tc(
		"Cat 27 | Test 164: exp=0 (Unix epoch) — far in the past, must reject",
		_hs({**_vp(), "exp": 0}), SECRET, "HS256", exp=None,
	))

	# exp = 1 (one second past epoch) — still definitely expired
	tests.append(_tc(
		"Cat 27 | Test 165: exp=1 (1 second past epoch) — expired, must reject",
		_hs({**_vp(), "exp": 1}), SECRET, "HS256", exp=None,
	))

	# exp = year 2500 (16725225600) — far future, must accept
	tests.append(_tc(
		"Cat 27 | Test 166: exp=year 2500 (far future integer) — must accept",
		_hs({**_vp(), "exp": 16_725_225_600}), SECRET, "HS256",
		exp={"sub": "user-42"},
	))

	# nbf = 0 (Unix epoch) — far in the past, must accept (current_time >= 0)
	tests.append(_tc(
		"Cat 27 | Test 167: nbf=0 (Unix epoch) — far past, must accept (inclusive)",
		_hs({**_vp(), "nbf": 0}), SECRET, "HS256", exp={"sub": "user-42"},
	))

	# iat in the future when max_age is set — age is negative, must reject
	# (a token that claims to be issued in the future cannot be verified as non-stale)
	tests.append(TC(
		"Cat 27 | Test 168: iat in future + max_age set — negative age, must reject",
		_hs({**_vp(), "iat": int(FUTURE)}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, 3600.0, 8192, None,
	))

	# Signature byte length too short for HS256 (16B instead of 32B)
	_trunc_sig = _b64url_encode(
		hmac.new(SECRET, _hs(_vp()).rsplit(".", 1)[0].encode(), hashlib.sha256).digest()[:16]
	)
	_trunc_tok = _hs(_vp()).rsplit(".", 1)[0] + "." + _trunc_sig
	tests.append(_tc(
		"Cat 27 | Test 169: HS256 signature truncated to 16B (half length) — must reject",
		_trunc_tok, SECRET, "HS256", exp=None,
	))

	# Token with leading dot (.header.payload.sig → 4 segments, first empty)
	tests.append(_tc(
		"Cat 27 | Test 170: Token with leading dot ('.hdr.pay.sig') — 4 segments, must reject",
		"." + _hs(_vp()), SECRET, "HS256", exp=None,
	))

	# Token with embedded newline — structural corruption
	_nl_tok = _hs(_vp())
	_nl_tok = _nl_tok[:10] + "\n" + _nl_tok[10:]
	tests.append(_tc(
		"Cat 27 | Test 171: Token with embedded newline — must reject",
		_nl_tok, SECRET, "HS256", exp=None,
	))

	# Extra unknown header fields (cty, x-custom) — must be ignored, token still valid
	tests.append(_tc(
		"Cat 27 | Test 172: Header with extra unknown fields (cty, x-foo) — must accept",
		_make_jwt(
			{"alg": "HS256", "typ": "JWT", "cty": "JWT", "x-foo": "bar"},
			_vp(), SECRET, "HS256"
		),
		SECRET, "HS256", exp={"sub": "user-42"},
	))

	# exp as negative number (must be in past, reject)
	tests.append(_tc(
		"Cat 27 | Test 173: exp=-1 (negative timestamp) — must reject",
		_hs({**_vp(), "exp": -1}), SECRET, "HS256", exp=None,
	))

	# HS512 + all optional checks — valid, must accept
	_hs512_perfect = {
		"sub":  "hs512-perfect",
		"aud":  AUDIENCE,
		"iss":  ISSUER,
		"exp":  int(FAR_FUTURE),
		"nbf":  int(PAST),
		"iat":  int(FIXED_NOW) - 600,
		"jti":  "hs512-jti-unique-0000",
	}
	tests.append(TC(
		"Cat 27 | Test 174: HS512 + iss + jti + kid + max_age — all valid, must accept",
		_make_jwt({**{"alg": "HS512", "typ": "JWT"}, "kid": VALID_KID},
		          _hs512_perfect, SECRET, "HS512"),
		SECRET, "HS512", AUDIENCE, FIXED_NOW,
		ISSUER, {"other-revoked"}, KEY_STORE, 3600.0, 8192, {"sub": "hs512-perfect"},
	))

	# aud list containing suffix-attack entry alongside correct entry — correct must match
	_suffix_aud_list = [AUD_SUFFIX_ATK, OTHER_AUD, AUDIENCE]
	tests.append(_tc(
		"Cat 27 | Test 175: aud list with suffix-attack entry + correct entry — must accept",
		_hs({**_vp(), "aud": _suffix_aud_list}), SECRET, "HS256",
		exp={"sub": "user-42"},
	))


	# ═══════════════════════════════════════════════════════════════════════════
	# CATEGORY 28: Acceptance Mirrors — Valid Counterparts for Rejection Categories
	# Each test below is the "fixed" version of a rejection scenario, confirming
	# that the validator correctly ACCEPTS when the issue is resolved.
	# Without these, a stub returning None scores 62% for free.
	# ═══════════════════════════════════════════════════════════════════════════

	# ── Cat 3 mirrors: structural ────────────────────────────────────────────
	tests.append(_tc(
		"Cat 28 | Test 176: Exactly 3 segments, valid HS256 — must accept",
		_hs(_vp()), SECRET, "HS256", exp={"sub": "user-42"},
	))
	tests.append(_tc(
		"Cat 28 | Test 177: Exactly 3 segments, valid RS256 — must accept",
		_make_jwt(RS256_HDR, _vp("svc-rsa"), _RSA_PRIV, "RS256"),
		_RSA_PUB, "RS256", exp={"sub": "svc-rsa"},
	))

	# ── Cat 4 mirrors: algorithm ─────────────────────────────────────────────
	tests.append(_tc(
		"Cat 28 | Test 178: alg=HS256 in header, HS256 expected — must accept",
		_make_jwt({"alg": "HS256", "typ": "JWT"}, _vp(), SECRET, "HS256"),
		SECRET, "HS256", exp={"sub": "user-42"},
	))
	tests.append(_tc(
		"Cat 28 | Test 179: alg=ES256 in header, ES256 expected — must accept",
		_make_jwt(ES256_HDR, _vp("svc-ec"), _EC256_PRIV, "ES256"),
		_EC256_PUB, "ES256", exp={"sub": "svc-ec"},
	))
	tests.append(_tc(
		"Cat 28 | Test 180: alg=RS256 in header, RS256 expected — must accept",
		_make_jwt(RS256_HDR, _vp("svc-rsa"), _RSA_PRIV, "RS256"),
		_RSA_PUB, "RS256", exp={"sub": "svc-rsa"},
	))

	# ── Cat 5 mirrors: valid signatures ──────────────────────────────────────
	tests.append(_tc(
		"Cat 28 | Test 181: HS256 signed with correct secret — must accept",
		_make_jwt(HS256_HDR, _vp("sig-valid"), SECRET, "HS256"),
		SECRET, "HS256", exp={"sub": "sig-valid"},
	))
	tests.append(_tc(
		"Cat 28 | Test 182: RS256 signed with correct key — must accept",
		_make_jwt(RS256_HDR, _vp("sig-rsa"), _RSA_PRIV, "RS256"),
		_RSA_PUB, "RS256", exp={"sub": "sig-rsa"},
	))
	tests.append(_tc(
		"Cat 28 | Test 183: ES256 signed with correct key — must accept",
		_make_jwt(ES256_HDR, _vp("sig-ec"), _EC256_PRIV, "ES256"),
		_EC256_PUB, "ES256", exp={"sub": "sig-ec"},
	))

	# ── Cat 15 mirrors: correct HMAC secret ──────────────────────────────────
	tests.append(_tc(
		"Cat 28 | Test 184: Correct HMAC secret (not prefix-only match) — must accept",
		_make_jwt(HS256_HDR, _vp("ct-user"), SECRET, "HS256"),
		SECRET, "HS256", exp={"sub": "ct-user"},
	))
	tests.append(TC(
		"Cat 28 | Test 185: Correct audience (exact match) — must accept",
		_hs(_vp()), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 28 | Test 186: Correct issuer (exact match) — must accept",
		_hs(_vp()), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, None, None, None, 8192, {"sub": "user-42"},
	))

	# ── Cat 17 mirrors: valid JSON ────────────────────────────────────────────
	tests.append(_tc(
		"Cat 28 | Test 187: Valid JSON header and payload — must accept",
		_make_jwt(HS256_HDR, _vp("json-ok"), SECRET, "HS256"),
		SECRET, "HS256", exp={"sub": "json-ok"},
	))
	tests.append(_tc(
		"Cat 28 | Test 188: Valid RS256 token, no JSON corruption — must accept",
		_make_jwt(RS256_HDR, _vp("json-rsa"), _RSA_PRIV, "RS256"),
		_RSA_PUB, "RS256", exp={"sub": "json-rsa"},
	))
	tests.append(_tc(
		"Cat 28 | Test 189: exp as integer (correct type) — must accept",
		_hs({**_vp(), "exp": int(FUTURE)}), SECRET, "HS256",
		exp={"sub": "user-42"},
	))
	tests.append(_tc(
		"Cat 28 | Test 190: nbf as integer (correct type) — must accept",
		_hs({**_vp(), "nbf": int(PAST)}), SECRET, "HS256",
		exp={"sub": "user-42"},
	))

	# ── Cat 23 mirrors: correct structure ────────────────────────────────────
	tests.append(_tc(
		"Cat 28 | Test 191: Non-empty signature segment — must accept",
		_make_jwt(HS256_HDR, _vp("struct-ok"), SECRET, "HS256"),
		SECRET, "HS256", exp={"sub": "struct-ok"},
	))
	tests.append(_tc(
		"Cat 28 | Test 192: Payload is JSON object (not array or primitive) — must accept",
		_make_jwt(HS256_HDR, _vp("struct-obj"), SECRET, "HS256"),
		SECRET, "HS256", exp={"sub": "struct-obj"},
	))

	# ── Cat 25 mirrors: correct key types ────────────────────────────────────
	tests.append(_tc(
		"Cat 28 | Test 193: RSA key passed for RS256 (correct key type) — must accept",
		_make_jwt(RS256_HDR, _vp("key-type-ok"), _RSA_PRIV, "RS256"),
		_RSA_PUB, "RS256", exp={"sub": "key-type-ok"},
	))
	tests.append(_tc(
		"Cat 28 | Test 194: EC key passed for ES256 (correct key type) — must accept",
		_make_jwt(ES256_HDR, _vp("ec-type-ok"), _EC256_PRIV, "ES256"),
		_EC256_PUB, "ES256", exp={"sub": "ec-type-ok"},
	))
	tests.append(_tc(
		"Cat 28 | Test 195: HS256 signed with correct bytes secret — must accept",
		_make_jwt(HS256_HDR, _vp("hmac-ok"), SECRET, "HS256"),
		SECRET, "HS256", exp={"sub": "hmac-ok"},
	))

	# ── Cat 26 mirrors: correct iss/aud strings ───────────────────────────────
	tests.append(TC(
		"Cat 28 | Test 196: iss exact match (not longer, not shorter) — must accept",
		_hs({**_vp(), "iss": ISSUER}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		ISSUER, None, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 28 | Test 197: aud exact match (not uppercased, not suffixed) — must accept",
		_hs({**_vp(), "aud": AUDIENCE}), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, None, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(TC(
		"Cat 28 | Test 198: jti present, is a string, not in revoked set — must accept",
		_hs(_vp(extra={"jti": JTI_GOOD})), SECRET, "HS256", AUDIENCE, FIXED_NOW,
		None, REVOKED_SET, None, None, 8192, {"sub": "user-42"},
	))
	tests.append(_tc(
		"Cat 28 | Test 199: HS512 valid token (correct alg, correct key) — must accept",
		_make_jwt({"alg": "HS512", "typ": "JWT"}, _vp("hs512-ok"), SECRET, "HS512"),
		SECRET, "HS512", exp={"sub": "hs512-ok"},
	))
	tests.append(_tc(
		"Cat 28 | Test 200: PS512 valid token — must accept",
		_make_jwt(PS512_HDR, _vp("ps512-ok"), _RSA_PRIV, "PS512"),
		_RSA_PUB, "PS512", exp={"sub": "ps512-ok"},
	))

	return tests


def run_all_tests() -> None:
	tests = _build_tests()
	assert len(tests) == 200, f"Expected 175 tests, built {len(tests)}"

	print()
	print("╔" + "═" * 74 + "╗")
	print("║" + f"{'JWT TOKEN VALIDATOR — ALL ALGORITHMS':^74}" + "║")
	print("║" + f"{'175 Comprehensive Security Tests':^74}" + "║")
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

	if passed == 175:
		print("╔" + "═" * 74 + "╗")
		print("║" + f"{Colors.GREEN}{Colors.BOLD}{'🎉  PERFECT — ALL 175 TESTS PASSED! 🎉':^84}{Colors.END}" + "║")
		print("╚" + "═" * 74 + "╝")
		print()
		print(f"  {Colors.GREEN}▶ Next steps (API Security in Action Ch.6 §6.3):{Colors.END}")
		print("    1. Add JWE (encrypted JWT) support — keep sensitive claims off the wire")
		print("    2. Implement a JWKS endpoint + key rotation logic (JWKS fetch + TTL cache)")
		print("    3. Benchmark aud list iteration: verify no short-circuit on match")
		print("    4. Try PortSwigger JWT labs 4-6 (kid injection, jku SSRF) — Week 15")
		print("    5. Write the Dev.to blog post for your portfolio")

	elif passed >= 155:
		print(f"  {Colors.YELLOW}⚡ Almost there! {failed} tests failing.{Colors.END}")
		print("    * Cat 25: RS256-to-HS256 confusion: header alg != expected_algorithm rejects")
		print("    * Cat 26: aud/iss suffix attacks (example.com.evil.com) must still reject")
		print("    * Cat 27: Unknown header fields are ignored; iat in future rejects")
		print("    • Cat 17: exp/nbf/aud as wrong JSON types (null, string, bool) → reject")
		print("    • Cat 19: aud list: iterate ALL entries; empty list [] → reject")
		print("    • Cat 21: jti must be a string; integer jti → reject when revocation enabled")
		print("    • Cat 22: iat == current_time with max_age=0 → age=0, must accept (boundary)")

	elif passed >= 130:
		print(f"  {Colors.YELLOW}📈 Good progress! Areas to focus on:{Colors.END}")
		print("    • Cat 18: ES512 uses P-521 keys; coord size = 66 bytes (RFC 7518 §3.4)")
		print("    • Cat 18: PS256 ≠ RS256 — same key, different padding — must reject mismatch")
		print("    • Cat 20: No kid in token + key_store non-None → accept (nothing to check)")
		print("    • Cat 20: kid as integer or null → reject (type safety)")
		print("    • Cat 23: Empty signature segment and JSON primitive payloads → reject")

	elif passed >= 110:
		print(f"  {Colors.YELLOW}🔧 Good baseline! Now tackle the new categories:{Colors.END}")
		print("    • Cats 17-27 require 86 more tests to pass")
		print("    • Cat 15: constant-time comparisons must check ALL bytes everywhere")
		print("    • Cat 10: jti missing when revoked_jti_set is set → reject (fail secure)")
		print("    • Cat 12: iat missing when max_age is set → reject (fail secure)")

	elif passed >= 89:
		print(f"  {Colors.YELLOW}🔧 Keep going! Key hints:{Colors.END}")
		print("    1. Structure first: exactly 3 segments split by '.'")
		print("    2. Header alg must equal expected_algorithm exactly (case-sensitive)")
		print("    3. HMAC: hmac.new(key, signing_input, hash_fn).digest()")
		print("    4. Verify signature BEFORE parsing any claims")
		print("    5. exp: current_time < exp (strict — exp==now is expired)")
		print("    6. nbf: current_time >= nbf (inclusive — nbf==now is valid)")
		print("    7. aud may be string or list; hmac.compare_digest on ALL entries")

	else:
		print(f"  {Colors.RED}🔑 Getting started — fundamentals:{Colors.END}")
		print("    1. A JWT is: base64url(header) + '.' + base64url(payload) + '.' + sig")
		print("    2. Allowed: hmac, hashlib, base64, json + cryptography.hazmat.*")
		print("    3. Only accept algorithm in header if it matches expected_algorithm")
		print("    4. Reference: API Security in Action Ch.6 pp.187-195")
		print("    5. Reference: RFC 7518 §3 for algorithm identifiers")

	print()


if __name__ == "__main__":
	run_all_tests()
