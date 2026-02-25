from dotenv import load_dotenv
import os
from fastapi import FastAPI, Depends, HTTPException, Request,Response, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette_csrf import CSRFMiddleware
import jwt
import secrets
import hashlib
import time,datetime
from datetime import timezone
from datetime import datetime, timedelta
from pydantic import BaseModel

load_dotenv()

limiter = Limiter(key_func=get_remote_address)

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
security = HTTPBearer()

app.add_middleware(CSRFMiddleware, secret=os.getenv("CSRF_SECRET"))
# Initialize CsrfProtect with a secret key

# Configuration

# Do NOT hardcode secrets!


JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"


# Do NOT hardcode API keys

# No attempt at rate-limiting!

# No attempt at API Key Rotation

API_KEYS = {
	"client_abc": os.getenv("client_abc"),
	"client_xyz": os.getenv("client_xyz")
}

# In-memory storage (production would use database)
sessions = {}
refresh_tokens = {}

class LoginRequest(BaseModel):
	username: str
	
	# Bad idea to store password plain!

	# Store hash of password in database.

	password: str 

def create_jwt_token(user_id: str):
	"""Create JWT access token"""

	payload = {
		"user_id": user_id,
		"exp": datetime.utcnow() + timedelta(hours=24),

		"aud": "audience_here",

		"iss": "issuer_here"

		# Best practice to have issuer and audience arguments

		# though not required
	}


	token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

	return token

def create_session(user_id: str):
	"""Create session for web users"""
	session_id = secrets.token_hex(16)

	# Do not store session_id in memory!

	# Store a hash of session_id instead

	session_id_hash = hashlib.sha256(session_id.encode()).hexdigest()

	sessions[session_id_hash] = {
		"user_id": user_id,
		"created_at": datetime.utcnow()
	}
	return session_id

def create_refresh_token(user_id: str):
	"""Create refresh token"""
	token = secrets.token_hex(32)

	# Do not index with raw token

	# Index with hash instead

	token_hash = hashlib.sha512(token.encode()).hexdigest()


	refresh_tokens[token_hash] = user_id

	return token

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: LoginRequest, response: Response):
	"""Login endpoint for web and API users"""
	# Authenticate user (simplified)

	# Once again do NOT store password in plaintext
	user_id = authenticate_user(request.username, request.password)
	
	if not user_id:
		raise HTTPException(401, "Invalid credentials")
	
	# Create tokens
	access_token = create_jwt_token(user_id)
	refresh_token = create_refresh_token(user_id)
	session_id = create_session(user_id)
	
	# Set session cookie
	response.set_cookie(
		key="session_id",
		value=session_id,
		max_age=86400,
		expires=datetime.now() + datetime.timedelta(hours=24),
		secure=True,
		httponly=True,
		samesite='Strict'
	)
	
	return {
		"access_token": access_token,
		"refresh_token": refresh_token,
		"token_type": "bearer"
	}

@app.post("/refresh")
@limiter.limit("5/minute")
async def refresh(request: Request,refresh_token: str):
	"""Refresh access token"""

	# The line below must be edited to retrieve token by hashing

	# token as index.

	token_hash = hashlib.sha512(refresh_token.encode()).hexdigest()

	user_id = refresh_tokens.get(token_hash)
	
	if not user_id:
		raise HTTPException(401, "Invalid refresh token")
	
	new_access_token = create_jwt_token(user_id)

	del refresh_tokens[token_hash]
	
	return {
		"access_token": new_access_token,
		"token_type": "bearer"
	}

@app.get("/api/profile")
@limiter.limit("5/minute")
async def get_profile_api(request: Request,credentials: HTTPAuthorizationCredentials = Depends(security)):
	"""Get user profile via JWT (for API clients)"""
	token = credentials.credentials
	
	try:
		# Remember the extra traits recommended such as

		# audience,issuer, etc, exp
		payload = jwt.decode(
					token,
					JWT_SECRET,
					algorithms=[JWT_ALGORITHM],
					issuer="issuer_here",
					audience="audience_here"
		)

		user_id = payload["user_id"]
		return {"user_id": user_id, "profile": "data"}
	except jwt.InvalidTokenError:
		raise HTTPException(401, "Invalid token")

@app.get("/web/profile")
@limiter.limit("5/minute")
async def get_profile_web(request: Request,session_id: str = Cookie(None)):
	"""Get user profile via session (for web users)"""
	
	session_id_hash = hashlib.sha256(session_id.encode()).hexdigest()

	session = sessions.get(session_id_hash)
	
	if not session:
		raise HTTPException(401, "Not authenticated")
	
	user_id = session["user_id"]
	return {"user_id": user_id, "profile": "data"}

@app.post("/admin/users")
@limiter.limit("5/minute")
async def create_user(request: Request,api_key: str, user_data: dict):
	"""Admin endpoint - create user (service-to-service)"""
	# Check API key
	valid_key = None
	
	# Do not store API keys in plaintext in memory!

	for client, key in API_KEYS.items():
		if api_key == key:
			valid_key = client
			break
	
	if not valid_key:
		raise HTTPException(403, "Invalid API key")
	
	# Create user
	return {"status": "created", "client": valid_key}

@app.delete("/web/account")
@limiter.limit("5/minute")
async def delete_account(request: Request,session_id: str = Cookie(None)):
	"""Delete user account (destructive action)"""
	
	# The user must pass password authentication

	# first. Then check if session Cookie is valid.

	# Third check if Anti-CSRF Token is valid.

	# Then finally delete.

	session = sessions.get(session_id)

	# The user must pass password authentication

	# first before proceeding with deletion

	# Simply checking with Session Cookie insufficient.	
	if not session:
		raise HTTPException(401, "Not authenticated")
	
	user_id = session["user_id"]
	
	# Delete account
	return {"status": "deleted", "user_id": user_id}

def authenticate_user(username: str, password: str):
	"""Authenticate user (simplified)"""
	# In real app: check against database with Argon2

	# Developer failed to hash password and check against

	# stored hash of password


	if username and password:
		return f"user_{username}"
	return None

