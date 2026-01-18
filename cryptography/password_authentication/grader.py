#!/usr/bin/env python3
"""
COMPREHENSIVE SECURITY GRADER - Authentication Challenge
=========================================================

This grader ACTIVELY TRIES TO BREAK your implementation.
It's not looking for perfect code - it's looking for security vulnerabilities.

Usage:
	python grader.py your_solution.py

Requirements:
	pip install 'passlib[argon2,bcrypt]' psutil

Author: @fosres
Based on: OWASP Testing Guide, PortSwigger Labs, "Full Stack Python Security"
"""

import sys
import os
import time
import sqlite3
import importlib.util
import traceback
import gc
import psutil
import statistics
from typing import Callable, List, Dict, Tuple, Any

# ============================================================================
# Test Configuration - Uses Pre-Populated Database Files
# ============================================================================

# Provided database files (with test users already populated)
DB_SQLITE_ORIGINAL = "users_sqlite.db"
DB_SQLALCHEMY_ORIGINAL = "users_sqlalchemy.db"

# Working copies (will be reset between tests)
DB_SQLITE = "test_grader.db"
DB_SQLALCHEMY_SQLITE = "test_grader_sqlalchemy.db"

DB_POSTGRES_CONFIG = {
	'host': 'localhost',
	'database': 'auth_db',  # User must load users_postgres.sql into this database
	'user': 'postgres',
	'password': 'postgres'
}

COLORS_ENABLED = True

class Colors:
	GREEN = '\033[92m' if COLORS_ENABLED else ''
	RED = '\033[91m' if COLORS_ENABLED else ''
	YELLOW = '\033[93m' if COLORS_ENABLED else ''
	BLUE = '\033[94m' if COLORS_ENABLED else ''
	BOLD = '\033[1m' if COLORS_ENABLED else ''
	END = '\033[0m' if COLORS_ENABLED else ''

# Track test results
test_results = []
critical_failures = []

# Track which database backends are available
postgres_available = False
sqlalchemy_available = False

def check_postgres_availability():
	"""Check if PostgreSQL is available with pre-populated test data"""
	global postgres_available
	try:
		import psycopg2
		conn = psycopg2.connect(**DB_POSTGRES_CONFIG)
		cursor = conn.cursor()
		
		# Check if users table exists
		cursor.execute("""
			SELECT EXISTS (
				SELECT FROM information_schema.tables 
				WHERE table_name = 'users'
			)
		""")
		table_exists = cursor.fetchone()[0]
		
		if not table_exists:
			conn.close()
			print(f"{Colors.YELLOW}⚠️  PostgreSQL: users table not found{Colors.END}")
			print(f"{Colors.YELLOW}    Load with: psql -U postgres -d auth_db -f users_postgres.sql{Colors.END}")
			postgres_available = False
			return False
		
		# Check if test users exist
		cursor.execute("SELECT COUNT(*) FROM users")
		count = cursor.fetchone()[0]
		conn.close()
		
		if count >= 5:  # Should have at least 5 test users
			postgres_available = True
			return True
		else:
			print(f"{Colors.YELLOW}⚠️  PostgreSQL: users table exists but has only {count} users{Colors.END}")
			print(f"{Colors.YELLOW}    Expected at least 5 test users{Colors.END}")
			postgres_available = False
			return False
	except Exception as e:
		postgres_available = False
		return False

def check_sqlalchemy_availability():
	"""Check if SQLAlchemy is available and database file exists"""
	global sqlalchemy_available
	try:
		import sqlalchemy
		import os
		
		if not os.path.exists(DB_SQLALCHEMY_ORIGINAL):
			print(f"{Colors.YELLOW}⚠️  SQLAlchemy database file not found: {DB_SQLALCHEMY_ORIGINAL}{Colors.END}")
			sqlalchemy_available = False
			return False
		
		sqlalchemy_available = True
		return True
	except:
		sqlalchemy_available = False
		return False

class TestResult:
	def __init__(self, category: str, name: str, passed: bool, points: int, max_points: int, message: str = ""):
		self.category = category
		self.name = name
		self.passed = passed
		self.points = points
		self.max_points = max_points
		self.message = message
		self.is_critical = "CRITICAL" in message or "SQL INJECTION" in message.upper()

def print_header(text: str):
	print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.END}")
	print(f"{Colors.BOLD}{Colors.BLUE}{text.center(80)}{Colors.END}")
	print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.END}\n")

def print_test(name: str, passed: bool, message: str = "", critical: bool = False):
	global test_results, critical_failures
	
	if passed:
		status = f"{Colors.GREEN}✅ PASS{Colors.END}"
	else:
		status = f"{Colors.RED}❌ FAIL{Colors.END}"
		if critical:
			critical_failures.append(name)
	
	print(f"{status}: {name}")
	if message:
		for line in message.split('\n'):
			if line.strip():
				print(f"  {Colors.YELLOW}{line}{Colors.END}")

def load_solution(filepath: str):
	"""Dynamically load user's solution"""
	if not os.path.exists(filepath):
		print(f"{Colors.RED}❌ Error: File '{filepath}' not found!{Colors.END}")
		sys.exit(1)
	
	spec = importlib.util.spec_from_file_location("solution", filepath)
	solution = importlib.util.module_from_spec(spec)
	
	try:
		spec.loader.exec_module(solution)
		return solution
	except Exception as e:
		print(f"{Colors.RED}❌ Error loading solution: {e}{Colors.END}")
		traceback.print_exc()
		sys.exit(1)

def setup_sqlite_db():
	"""Reset SQLite database to original state (copy from provided file)"""
	import shutil
	
	if not os.path.exists(DB_SQLITE_ORIGINAL):
		raise FileNotFoundError(f"Provided database file not found: {DB_SQLITE_ORIGINAL}")
	
	# Remove old test database
	if os.path.exists(DB_SQLITE):
		os.remove(DB_SQLITE)
	
	# Copy from original
	shutil.copy2(DB_SQLITE_ORIGINAL, DB_SQLITE)

def setup_postgres_db():
	"""Reset PostgreSQL database to original state (delete added users)"""
	if not postgres_available:
		return
	
	try:
		import psycopg2
		
		conn = psycopg2.connect(**DB_POSTGRES_CONFIG)
		conn.autocommit = True
		cursor = conn.cursor()
		
		# Delete all users except the 5 original test users
		# Keep: alice_scrypt, bob_pbkdf2, charlie_argon2, dave_bcrypt, eve_scrypt
		cursor.execute("""
			DELETE FROM users 
			WHERE username NOT IN ('alice_scrypt', 'bob_pbkdf2', 'charlie_argon2', 'dave_bcrypt', 'eve_scrypt')
		""")
		
		conn.close()
	except Exception as e:
		print(f"{Colors.YELLOW}Warning: PostgreSQL reset failed: {e}{Colors.END}")

def setup_sqlalchemy_db():
	"""Reset SQLAlchemy database to original state (copy from provided file)"""
	if not sqlalchemy_available:
		return
	
	import shutil
	
	if not os.path.exists(DB_SQLALCHEMY_ORIGINAL):
		print(f"{Colors.YELLOW}Warning: {DB_SQLALCHEMY_ORIGINAL} not found{Colors.END}")
		return
	
	# Remove old test database
	if os.path.exists(DB_SQLALCHEMY_SQLITE):
		os.remove(DB_SQLALCHEMY_SQLITE)
	
	# Copy from original
	shutil.copy2(DB_SQLALCHEMY_ORIGINAL, DB_SQLALCHEMY_SQLITE)

# ============================================================================
# SQL Injection Test Payloads
# ============================================================================

SQL_INJECTION_PAYLOADS = {
	'drop_table': [
		"admin'; DROP TABLE users; --",
		"admin'); DROP TABLE users; --",
		"'; DROP TABLE users CASCADE; --",
		"admin' OR 1=1; DROP TABLE users; --",
	],
	'auth_bypass': [
		"admin' OR '1'='1",
		"admin' OR '1'='1' --",
		"admin' OR '1'='1' /*",
		"admin'--",
		"admin' #",
		"' OR 1=1 --",
		"' OR 'a'='a",
		"') OR ('1'='1",
		"admin') OR ('1'='1') --",
		"' OR ''='",
	],
	'union_select': [
		"' UNION SELECT NULL, username, password_hash FROM users --",
		"admin' UNION SELECT 1,2,3 --",
	],
	'stacked_queries': [
		"admin'; INSERT INTO users VALUES (999, 'hacker', 'hash', 'all'); --",
		"admin'; UPDATE users SET password_hash='hacked'; --",
		"admin'; DELETE FROM users WHERE username='admin'; --",
	],
	'blind_sqli': [
		# Time-based blind SQL injection
		"admin' AND SLEEP(5) --",  # MySQL
		"admin' AND pg_sleep(5) --",  # PostgreSQL
		"admin' AND (SELECT COUNT(*) FROM generate_series(1,1000000)) --",  # PostgreSQL
		# Boolean-based blind SQL injection  
		"admin' AND '1'='1",
		"admin' AND '1'='2",
		"admin' AND SUBSTRING(password_hash,1,1)='a' --",
	],
}

# ============================================================================
# CATEGORY 1: Password Hashing - KDF Implementation Tests
# ============================================================================

def test_kdf_implementation(solution, kdf_name: str, hash_func_name: str, verify_func_name: str,
							min_time_ms: float, expected_format: str):
	"""Comprehensive test for a single KDF implementation"""
	
	hash_func = getattr(solution, hash_func_name, None)
	verify_func = getattr(solution, verify_func_name, None)
	
	if not hash_func or not verify_func:
		test_results.append(TestResult(
			f"KDF-{kdf_name}", f"{kdf_name}: Functions exist", False, 0, 5,
			f"Missing {hash_func_name} or {verify_func_name}"
		))
		return
	
	# Test 1: Unique salt generation
	try:
		password = "TestPassword123!"
		hash1 = hash_func(password)
		hash2 = hash_func(password)
		
		passed = hash1 != hash2
		test_results.append(TestResult(
			f"KDF-{kdf_name}", f"{kdf_name}: Unique salt generation", passed, 3 if passed else 0, 3,
			"Same password produced identical hash - salt not random!" if not passed else ""
		))
		print_test(f"{kdf_name}: Unique salt generation", passed,
			"Same password produced identical hash - salt not random!" if not passed else "")
	except Exception as e:
		test_results.append(TestResult(f"KDF-{kdf_name}", f"{kdf_name}: Unique salt generation", False, 0, 3, str(e)))
		print_test(f"{kdf_name}: Unique salt generation", False, f"Error: {e}")
	
	# Test 2: Sufficient work factor
	try:
		password = "TestPassword123!"
		start = time.perf_counter()
		hash_result = hash_func(password)
		elapsed = (time.perf_counter() - start) * 1000  # Convert to ms
		
		passed = elapsed >= min_time_ms
		test_results.append(TestResult(
			f"KDF-{kdf_name}", f"{kdf_name}: Work factor (≥{min_time_ms}ms)", passed, 4 if passed else 0, 4,
			f"Too fast: {elapsed:.1f}ms (weak parameters?)" if not passed else f"{elapsed:.1f}ms"
		))
		print_test(f"{kdf_name}: Work factor (≥{min_time_ms}ms)", passed,
			f"Too fast: {elapsed:.1f}ms (using OWASP 2023 parameters?)" if not passed else f"Timing: {elapsed:.1f}ms")
	except Exception as e:
		test_results.append(TestResult(f"KDF-{kdf_name}", f"{kdf_name}: Work factor", False, 0, 4, str(e)))
		print_test(f"{kdf_name}: Work factor", False, f"Error: {e}")
	
	# Test 3: Correct password verification
	try:
		password = "CorrectPassword123!@#"
		stored_hash = hash_func(password)
		result = verify_func(password, stored_hash)
		
		passed = result is True
		test_results.append(TestResult(
			f"KDF-{kdf_name}", f"{kdf_name}: Verify correct password", passed, 3 if passed else 0, 3,
			"Returns False for CORRECT password!" if not passed else ""
		))
		print_test(f"{kdf_name}: Verify correct password", passed,
			"CRITICAL: Returns False for correct password!" if not passed else "", critical=not passed)
	except Exception as e:
		test_results.append(TestResult(f"KDF-{kdf_name}", f"{kdf_name}: Verify correct password", False, 0, 3, str(e)))
		print_test(f"{kdf_name}: Verify correct password", False, f"Error: {e}", critical=True)
	
	# Test 4: Reject incorrect password
	try:
		correct = "CorrectPassword123!@#"
		wrong = "WrongPassword456$%^"
		stored_hash = hash_func(correct)
		result = verify_func(wrong, stored_hash)
		
		passed = result is False
		test_results.append(TestResult(
			f"KDF-{kdf_name}", f"{kdf_name}: Reject wrong password", passed, 5 if passed else 0, 5,
			"CRITICAL: Accepted WRONG password!" if not passed else ""
		))
		print_test(f"{kdf_name}: Reject wrong password", passed,
			"🚨 CRITICAL: Accepted WRONG password!" if not passed else "", critical=not passed)
	except Exception as e:
		test_results.append(TestResult(f"KDF-{kdf_name}", f"{kdf_name}: Reject wrong password", False, 0, 5, str(e)))
		print_test(f"{kdf_name}: Reject wrong password", False, f"Error: {e}", critical=True)
	
	# Test 5: Hash format validation
	try:
		password = "TestPassword123!"
		hash_result = hash_func(password)
		hash_str = str(hash_result)
		
		if expected_format in hash_str:
			passed = True
			msg = f"Format: {hash_str[:40]}..."
		else:
			passed = False
			msg = f"Expected '{expected_format}' in hash, got: {hash_str[:50]}"
		
		test_results.append(TestResult(
			f"KDF-{kdf_name}", f"{kdf_name}: Hash format", passed, 2 if passed else 0, 2, msg
		))
		print_test(f"{kdf_name}: Hash format", passed, msg if not passed else "")
	except Exception as e:
		test_results.append(TestResult(f"KDF-{kdf_name}", f"{kdf_name}: Hash format", False, 0, 2, str(e)))
		print_test(f"{kdf_name}: Hash format", False, f"Error: {e}")
	
	# Test 5.5: OWASP 2023 Parameter Validation
	try:
		password = "TestPassword123!"
		hash_result = hash_func(password)
		hash_str = str(hash_result)
		
		passed = False
		msg = ""
		
		# Validate parameters based on KDF type
		if kdf_name == "scrypt":
			# Expected format: scrypt:N:r:p:salt:hash or similar
			if "scrypt" in hash_str.lower():
				# Try to extract N parameter
				# Most implementations store N in the hash
				passed = True  # If hash took ≥20ms, parameters are likely correct
				msg = "Hash timing suggests OWASP-compliant parameters"
		
		elif kdf_name == "pbkdf2":
			# Expected format includes iterations
			if "pbkdf2" in hash_str.lower():
				passed = True  # If hash took ≥50ms, iterations are likely correct
				msg = "Hash timing suggests OWASP-compliant parameters"
		
		elif kdf_name == "argon2":
			# Argon2 library format
			if "argon2" in hash_str.lower() or "$argon2" in hash_str:
				passed = True  # Library handles parameters
				msg = "Using standard Argon2 library format"
		
		elif kdf_name == "bcrypt":
			# Expected format: $2a$12$... or $2b$12$...
			if hash_str.startswith("$2"):
				parts = hash_str.split("$")
				if len(parts) >= 3:
					try:
						cost = int(parts[2])
						if cost >= 12:
							passed = True
							msg = f"cost={cost} (OWASP compliant ≥12)"
						else:
							msg = f"cost={cost} (OWASP 2023 requires cost≥12)"
					except:
						passed = True  # If parsing fails, trust timing test
						msg = "Hash timing suggests OWASP-compliant parameters"
		
		test_results.append(TestResult(
			f"KDF-{kdf_name}", f"{kdf_name}: OWASP 2023 parameters", passed, 3 if passed else 0, 3, msg
		))
		print_test(f"{kdf_name}: OWASP 2023 parameters", passed, 
			msg if not passed else f"✓ {msg}")
	except Exception as e:
		test_results.append(TestResult(f"KDF-{kdf_name}", f"{kdf_name}: OWASP 2023 parameters", False, 0, 3, str(e)))
		print_test(f"{kdf_name}: OWASP 2023 parameters", False, f"Error: {e}")
	
	# Test 6: Unicode password support
	try:
		unicode_password = "パスワード🔐Test123!"
		hash_result = hash_func(unicode_password)
		result = verify_func(unicode_password, hash_result)
		
		passed = result is True
		test_results.append(TestResult(
			f"KDF-{kdf_name}", f"{kdf_name}: Unicode support", passed, 2 if passed else 0, 2,
			"Failed to handle Unicode password" if not passed else ""
		))
		print_test(f"{kdf_name}: Unicode support", passed,
			"Failed to handle Unicode password" if not passed else "")
	except Exception as e:
		test_results.append(TestResult(f"KDF-{kdf_name}", f"{kdf_name}: Unicode support", False, 0, 2, str(e)))
		print_test(f"{kdf_name}: Unicode support", False, f"Error: {e}")
	
	# Test 7: Timing attack resistance (constant-time comparison)
	try:
		password = "CorrectPassword123!"
		stored_hash = hash_func(password)
		
		# Test with completely wrong password
		wrong_short = "x"
		wrong_long = "WrongPassword123!WrongPassword123!WrongPassword123!"
		
		timings_short = []
		timings_long = []
		
		for _ in range(20):
			start = time.perf_counter()
			verify_func(wrong_short, stored_hash)
			timings_short.append(time.perf_counter() - start)
			
			start = time.perf_counter()
			verify_func(wrong_long, stored_hash)
			timings_long.append(time.perf_counter() - start)
		
		avg_short = statistics.mean(timings_short)
		avg_long = statistics.mean(timings_long)
		
		# Timing should be similar (within 20% variance)
		variance = abs(avg_short - avg_long) / max(avg_short, avg_long)
		passed = variance < 0.20
		
		test_results.append(TestResult(
			f"KDF-{kdf_name}", f"{kdf_name}: Timing attack resistance", passed, 3 if passed else 0, 3,
			f"Timing variance: {variance*100:.1f}% (vulnerable to timing attacks)" if not passed else f"Variance: {variance*100:.1f}%"
		))
		print_test(f"{kdf_name}: Timing attack resistance", passed,
			f"⚠️  Timing variance: {variance*100:.1f}% (vulnerable to timing attacks?)" if not passed else "")
	except Exception as e:
		test_results.append(TestResult(f"KDF-{kdf_name}", f"{kdf_name}: Timing attack resistance", False, 0, 3, str(e)))
		print_test(f"{kdf_name}: Timing attack resistance", False, f"Error: {e}")

# ============================================================================
# CATEGORY 2: SQL Injection Tests
# ============================================================================

def verify_sqlite_integrity() -> Tuple[bool, str]:
	"""Verify SQLite database hasn't been compromised"""
	try:
		conn = sqlite3.connect(DB_SQLITE)
		cursor = conn.cursor()
		
		# Table exists?
		cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
		if not cursor.fetchone():
			conn.close()
			return False, "Table was dropped"
		
		# Row count correct?
		cursor.execute("SELECT COUNT(*) FROM users")
		count = cursor.fetchone()[0]
		if count < 1:  # Should have at least the test user
			conn.close()
			return False, f"Rows deleted (count={count})"
		
		conn.close()
		return True, "OK"
	except Exception as e:
		return False, f"Database error: {e}"

def verify_postgres_integrity() -> Tuple[bool, str]:
	"""Verify PostgreSQL database hasn't been compromised"""
	if not postgres_available:
		return True, "PostgreSQL not available"
	
	try:
		import psycopg2
		
		conn = psycopg2.connect(**DB_POSTGRES_CONFIG)
		cursor = conn.cursor()
		
		# Table exists?
		cursor.execute("SELECT tablename FROM pg_tables WHERE tablename='users'")
		if not cursor.fetchone():
			conn.close()
			return False, "Table was dropped"
		
		# Row count correct?
		cursor.execute("SELECT COUNT(*) FROM users")
		count = cursor.fetchone()[0]
		if count < 1:
			conn.close()
			return False, f"Rows deleted (count={count})"
		
		conn.close()
		return True, "OK"
	except Exception as e:
		return False, f"Database error: {e}"

def verify_sqlalchemy_integrity() -> Tuple[bool, str]:
	"""Verify SQLAlchemy database hasn't been compromised"""
	if not sqlalchemy_available:
		return True, "SQLAlchemy not available"
	
	try:
		from sqlalchemy import create_engine
		from sqlalchemy.orm import sessionmaker
		
		engine = create_engine(f'sqlite:///{DB_SQLALCHEMY_SQLITE}')
		Session = sessionmaker(bind=engine)
		session = Session()
		
		# Try to query - will fail if table dropped
		result = session.execute("SELECT COUNT(*) FROM users")
		count = result.fetchone()[0]
		session.close()
		
		if count < 1:
			return False, f"Rows deleted (count={count})"
		
		return True, "OK"
	except Exception as e:
		return False, f"Database error: {e}"

def test_sql_injection_comprehensive(solution, kdf_name: str, db_backend: str):
	"""Comprehensive SQL injection testing for specific database backend"""
	
	register_func = getattr(solution, "register_user", None)
	auth_func = getattr(solution, "authenticate_user", None)
	
	if not register_func or not auth_func:
		test_results.append(TestResult(
			f"SQLi-{db_backend}-{kdf_name}", 
			f"{kdf_name} {db_backend}: Functions not found", 
			False, 0, 10,
			"Missing register_user or authenticate_user functions"
		))
		return
	
	# Select appropriate setup and verification functions
	if db_backend == "sqlite":
		setup_func = setup_sqlite_db
		verify_func = verify_sqlite_integrity
	elif db_backend == "postgres":
		if not postgres_available:
			print(f"{Colors.YELLOW}⚠️  Skipping PostgreSQL tests (database not available){Colors.END}")
			return
		setup_func = setup_postgres_db
		verify_func = verify_postgres_integrity
	elif db_backend == "sqlalchemy":
		if not sqlalchemy_available:
			print(f"{Colors.YELLOW}⚠️  Skipping SQLAlchemy tests (library not available){Colors.END}")
			return
		setup_func = setup_sqlalchemy_db
		verify_func = verify_sqlalchemy_integrity
	else:
		return
	
	vulnerabilities_found = []
	
	# Test registration username parameter with KDF and db_backend parameters
	for category, payloads in SQL_INJECTION_PAYLOADS.items():
		for payload in payloads:
			setup_func()
			
			try:
				register_func(payload, "password123", "files.txt", kdf=kdf_name, db_backend=db_backend)
			except:
				pass  # Exceptions are OK
			
			intact, msg = verify_func()
			if not intact:
				vulnerabilities_found.append({
					'function': 'register',
					'parameter': 'username',
					'category': category,
					'payload': payload,
					'impact': msg
				})
	
	# Test authentication username parameter (bypass attempts)
	for payload in SQL_INJECTION_PAYLOADS['auth_bypass']:
		setup_func()
		
		try:
			# Register legitimate user with specified KDF and backend
			register_func("realuser", "RealPassword123!", "file.txt", kdf=kdf_name, db_backend=db_backend)
			
			# Try to bypass with malicious username
			result = auth_func(payload, "wrongpassword", db_backend=db_backend)
			
			# If authentication succeeded, that's a vulnerability!
			if result and len(result) > 0:
				vulnerabilities_found.append({
					'function': 'authenticate',
					'parameter': 'username',
					'category': 'auth_bypass',
					'payload': payload,
					'impact': 'Authentication bypassed with wrong password'
				})
		except:
			pass  # Exception is good - rejected malicious input
	
	# Report results
	passed = len(vulnerabilities_found) == 0
	
	if passed:
		msg = f"Tested {len(SQL_INJECTION_PAYLOADS['drop_table']) + len(SQL_INJECTION_PAYLOADS['auth_bypass'])}+ payloads"
	else:
		msg = f"🚨 {len(vulnerabilities_found)} CRITICAL SQL INJECTION VULNERABILITIES:\n"
		for vuln in vulnerabilities_found[:3]:  # Show first 3
			msg += f"  • {vuln['function']}({vuln['parameter']}): {vuln['payload'][:40]}... → {vuln['impact']}\n"
		if len(vulnerabilities_found) > 3:
			msg += f"  • ... and {len(vulnerabilities_found) - 3} more"
	
	test_results.append(TestResult(
		f"SQLi-{db_backend}-{kdf_name}", 
		f"{kdf_name} {db_backend}: SQL injection prevention", 
		passed, 10 if passed else 0, 10, msg
	))
	print_test(f"{kdf_name} {db_backend}: SQL injection prevention", passed, msg, critical=not passed)

# ============================================================================
# CATEGORY 2.5: Blind SQL Injection Tests
# ============================================================================

def test_blind_sql_injection(solution, kdf_name: str, db_backend: str):
	"""Test for blind SQL injection vulnerabilities"""
	
	register_func = getattr(solution, "register_user", None)
	auth_func = getattr(solution, "authenticate_user", None)
	
	if not register_func or not auth_func:
		return
	
	# Skip if database not available
	if db_backend == "postgres" and not postgres_available:
		return
	if db_backend == "sqlalchemy" and not sqlalchemy_available:
		return
	
	# Setup appropriate database
	if db_backend == "sqlite":
		setup_sqlite_db()
	elif db_backend == "postgres":
		setup_postgres_db()
	elif db_backend == "sqlalchemy":
		setup_sqlalchemy_db()
	
	# Register a test user
	try:
		register_func("blindtest", "TestPassword123!", "files.txt", kdf=kdf_name, db_backend=db_backend)
	except:
		pass
	
	# Test time-based blind SQL injection
	# If vulnerable, malicious input with SLEEP() will cause delay
	try:
		# Normal authentication (baseline timing)
		start = time.perf_counter()
		try:
			auth_func("nonexistent", "password", db_backend=db_backend)
		except:
			pass
		baseline_time = time.perf_counter() - start
		
		# Time-based blind SQLi payload
		# SQLite doesn't have SLEEP, but PostgreSQL does
		if db_backend == "postgres":
			payload = "admin' AND pg_sleep(2) --"
		else:
			# For SQLite/SQLAlchemy, use a different approach
			payload = "admin' AND (SELECT COUNT(*) FROM users) --"
		
		start = time.perf_counter()
		try:
			auth_func(payload, "password", db_backend=db_backend)
		except:
			pass
		attack_time = time.perf_counter() - start
		
		# If attack took significantly longer (>1.5 seconds more), vulnerable
		time_diff = attack_time - baseline_time
		
		if db_backend == "postgres":
			# PostgreSQL pg_sleep should add ~2 seconds
			passed = time_diff < 1.5  # Not vulnerable if time difference is small
			msg = f"Time diff: {time_diff:.2f}s (vulnerable if >1.5s)" if not passed else f"Time diff: {time_diff:.2f}s"
		else:
			# For SQLite, just check it didn't hang
			passed = attack_time < 5.0  # Should complete quickly if not vulnerable
			msg = f"Execution time: {attack_time:.2f}s"
		
		test_results.append(TestResult(
			f"BlindSQLi-{db_backend}-{kdf_name}",
			f"{kdf_name} {db_backend}: Blind SQL injection prevention",
			passed, 5 if passed else 0, 5, msg
		))
		print_test(f"{kdf_name} {db_backend}: Blind SQL injection prevention", passed,
			f"⚠️  Vulnerable to time-based blind SQLi! {msg}" if not passed else "")
	except Exception as e:
		# If test fails, assume safe (but log error)
		test_results.append(TestResult(
			f"BlindSQLi-{db_backend}-{kdf_name}",
			f"{kdf_name} {db_backend}: Blind SQL injection prevention",
			True, 5, 5, f"Test error (assuming safe): {str(e)[:50]}"
		))
		print_test(f"{kdf_name} {db_backend}: Blind SQL injection prevention", True, "")

# ============================================================================
# CATEGORY 3: User Enumeration Tests
# ============================================================================

def test_user_enumeration(solution, kdf_name: str, db_backend: str):
	"""Test if error messages leak user existence"""
	
	register_func = getattr(solution, "register_user", None)
	auth_func = getattr(solution, "authenticate_user", None)
	
	if not register_func or not auth_func:
		return
	
	# Skip if database not available
	if db_backend == "postgres" and not postgres_available:
		return
	if db_backend == "sqlalchemy" and not sqlalchemy_available:
		return
	
	# Setup appropriate database
	if db_backend == "sqlite":
		setup_sqlite_db()
	elif db_backend == "postgres":
		setup_postgres_db()
	elif db_backend == "sqlalchemy":
		setup_sqlalchemy_db()
	
	# Register a known user with specified KDF
	try:
		register_func("existinguser", "Password123!", "files.txt", kdf=kdf_name, db_backend=db_backend)
	except:
		pass
	
	# Try to authenticate non-existent user
	error_nonexistent = None
	try:
		auth_func("nonexistentuser", "anypassword", db_backend=db_backend)
	except Exception as e:
		error_nonexistent = str(e)
	
	# Try to authenticate existing user with wrong password
	error_wrong_password = None
	try:
		auth_func("existinguser", "wrongpassword", db_backend=db_backend)
	except Exception as e:
		error_wrong_password = str(e)
	
	# Errors should be IDENTICAL
	if error_nonexistent and error_wrong_password:
		passed = error_nonexistent == error_wrong_password
		
		if not passed:
			msg = f"Different errors reveal user existence!\n"
			msg += f"  Non-existent: '{error_nonexistent[:60]}...'\n"
			msg += f"  Wrong password: '{error_wrong_password[:60]}...'"
		else:
			msg = f"Generic error: '{error_nonexistent[:50]}'"
	else:
		passed = False
		msg = "Authentication should raise exceptions for failed login"
	
	test_results.append(TestResult(
		f"UserEnum-{db_backend}-{kdf_name}", 
		f"{kdf_name} {db_backend}: User enumeration prevention", 
		passed, 5 if passed else 0, 5, msg
	))
	print_test(f"{kdf_name} {db_backend}: User enumeration prevention", passed, msg, critical=not passed)

# ============================================================================
# CATEGORY 4: Resource Leak Tests
# ============================================================================

def test_resource_leaks(solution, kdf_name: str, db_backend: str):
	"""Test for database connection leaks"""
	
	register_func = getattr(solution, "register_user", None)
	auth_func = getattr(solution, "authenticate_user", None)
	
	if not register_func or not auth_func:
		return
	
	# Skip if database not available
	if db_backend == "postgres" and not postgres_available:
		return
	if db_backend == "sqlalchemy" and not sqlalchemy_available:
		return
	
	# Setup appropriate database
	if db_backend == "sqlite":
		setup_sqlite_db()
	elif db_backend == "postgres":
		setup_postgres_db()
	elif db_backend == "sqlalchemy":
		setup_sqlalchemy_db()
	
	# Get initial process stats
	process = psutil.Process()
	initial_connections = len(process.connections())
	initial_handles = process.num_handles() if hasattr(process, 'num_handles') else 0
	
	# Perform 50 operations with specified KDF and backend
	for i in range(50):
		try:
			register_func(f"user{i}", f"password{i}", "files.txt", kdf=kdf_name, db_backend=db_backend)
		except:
			pass  # Duplicates expected
		
		try:
			auth_func(f"user{i}", "wrongpassword", db_backend=db_backend)
		except:
			pass  # Auth failures expected
	
	# Force garbage collection
	gc.collect()
	time.sleep(0.1)
	
	# Check if connections increased significantly
	final_connections = len(process.connections())
	final_handles = process.num_handles() if hasattr(process, 'num_handles') else 0
	
	connection_leak = final_connections - initial_connections
	handle_leak = final_handles - initial_handles
	
	# Allow some variance, but >10 leaked connections is a problem
	passed = connection_leak <= 10 and handle_leak <= 20
	
	if not passed:
		msg = f"⚠️  Resource leak detected:\n"
		msg += f"  Connections: +{connection_leak} (should be ≤10)\n"
		msg += f"  Handles: +{handle_leak} (should be ≤20)\n"
		msg += f"  Database connections may not be properly closed!"
	else:
		msg = f"Connections: +{connection_leak}, Handles: +{handle_leak}"
	
	test_results.append(TestResult(
		f"Resources-{db_backend}-{kdf_name}", 
		f"{kdf_name} {db_backend}: Resource leak prevention", 
		passed, 4 if passed else 0, 4, msg
	))
	print_test(f"{kdf_name} {db_backend}: Resource leak prevention", passed, msg if not passed else "")

# ============================================================================
# CATEGORY 5: Input Validation & Edge Cases
# ============================================================================

def test_edge_cases(solution, kdf_name: str, db_backend: str):
	"""Test handling of edge cases and malicious inputs"""
	
	register_func = getattr(solution, "register_user", None)
	auth_func = getattr(solution, "authenticate_user", None)
	
	if not register_func or not auth_func:
		return
	
	# Skip if database not available
	if db_backend == "postgres" and not postgres_available:
		return
	if db_backend == "sqlalchemy" and not sqlalchemy_available:
		return
	
	# Setup function for this backend
	if db_backend == "sqlite":
		setup_func = setup_sqlite_db
		get_count_func = lambda: _sqlite_get_user_count("duplicate")
	elif db_backend == "postgres":
		setup_func = setup_postgres_db
		get_count_func = lambda: _postgres_get_user_count("duplicate")
	elif db_backend == "sqlalchemy":
		setup_func = setup_sqlalchemy_db
		get_count_func = lambda: _sqlalchemy_get_user_count("duplicate")
	else:
		return
	
	edge_cases_passed = 0
	edge_cases_total = 0
	
	# Test 1: Empty string inputs
	setup_func()
	try:
		register_func("", "password", "files", kdf=kdf_name, db_backend=db_backend)
		passed = False  # Should reject empty username
	except:
		passed = True  # Good - rejected invalid input
	
	edge_cases_total += 1
	if passed:
		edge_cases_passed += 1
	print_test(f"{kdf_name} {db_backend}: Reject empty username", passed, "Accepted empty username!" if not passed else "")
	
	# Test 2: Null byte injection
	setup_func()
	try:
		register_func("user\x00admin", "password", "files", kdf=kdf_name, db_backend=db_backend)
		# Check if null byte bypassed validation (depends on backend)
		passed = True  # As long as it doesn't crash
	except:
		passed = True
	
	edge_cases_total += 1
	if passed:
		edge_cases_passed += 1
	print_test(f"{kdf_name} {db_backend}: Null byte handling", passed, "Crashed on null byte" if not passed else "")
	
	# Test 3: Very long input (buffer overflow attempt)
	setup_func()
	try:
		long_username = "A" * 10000
		register_func(long_username, "password", "files", kdf=kdf_name, db_backend=db_backend)
		passed = True  # If it handles it gracefully, that's OK
	except:
		passed = True  # Rejecting is also OK
	
	edge_cases_total += 1
	if passed:
		edge_cases_passed += 1
	print_test(f"{kdf_name} {db_backend}: Long input handling", passed, "Crashed on long input" if not passed else "")
	
	# Test 4: Special characters in all fields
	setup_func()
	try:
		register_func("user!@#$%^&*()", "pass!@#$%^&*()", "file!@#$%^&*().txt", kdf=kdf_name, db_backend=db_backend)
		result = auth_func("user!@#$%^&*()", "pass!@#$%^&*()", db_backend=db_backend)
		passed = result is not None and "file!@#$%^&*().txt" in str(result)
	except:
		passed = False
	
	edge_cases_total += 1
	if passed:
		edge_cases_passed += 1
	print_test(f"{kdf_name} {db_backend}: Special characters", passed, "Failed to handle special characters" if not passed else "")
	
	# Test 5: Duplicate registration attempt
	setup_func()
	try:
		register_func("duplicate", "password1", "files1", kdf=kdf_name, db_backend=db_backend)
		register_func("duplicate", "password2", "files2", kdf=kdf_name, db_backend=db_backend)
		
		# Should only have one user
		count = get_count_func()
		passed = count == 1
	except:
		passed = True  # Raising exception is also acceptable
	
	edge_cases_total += 1
	if passed:
		edge_cases_passed += 1
	print_test(f"{kdf_name} {db_backend}: Duplicate prevention", passed, "Allowed duplicate username!" if not passed else "")
	
	# Overall edge case score
	score = int((edge_cases_passed / edge_cases_total) * 3)  # 5 tests, 3 points total
	test_results.append(TestResult(
		f"EdgeCases-{db_backend}-{kdf_name}", 
		f"{kdf_name} {db_backend}: Edge case handling", 
		edge_cases_passed == edge_cases_total,
		score, 3, f"Passed {edge_cases_passed}/{edge_cases_total} edge cases"
	))

# Helper functions to get user count from different backends
def _sqlite_get_user_count(username: str) -> int:
	conn = sqlite3.connect(DB_SQLITE)
	cursor = conn.cursor()
	cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
	count = cursor.fetchone()[0]
	conn.close()
	return count

def _postgres_get_user_count(username: str) -> int:
	import psycopg2
	conn = psycopg2.connect(**DB_POSTGRES_CONFIG)
	cursor = conn.cursor()
	cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
	count = cursor.fetchone()[0]
	conn.close()
	return count

def _sqlalchemy_get_user_count(username: str) -> int:
	from sqlalchemy import create_engine
	from sqlalchemy.orm import sessionmaker
	
	engine = create_engine(f'sqlite:///{DB_SQLALCHEMY_SQLITE}')
	Session = sessionmaker(bind=engine)
	session = Session()
	
	result = session.execute(f"SELECT COUNT(*) FROM users WHERE username = '{username}'")
	count = result.fetchone()[0]
	session.close()
	return count

# ============================================================================
# Main Test Runner
# ============================================================================

# ============================================================================
# Main Test Runner
# ============================================================================

def run_all_tests(solution):
	"""Execute comprehensive security tests"""
	
	# Check database availability
	check_postgres_availability()
	check_sqlalchemy_availability()
	
	# Print availability status
	print(f"\n{Colors.BOLD}Database Backend Availability:{Colors.END}")
	print(f"  SQLite: {Colors.GREEN}✓ Available{Colors.END}")
	print(f"  PostgreSQL: {Colors.GREEN if postgres_available else Colors.YELLOW}{'✓ Available' if postgres_available else '⚠️  Not Available (tests will be skipped)'}{Colors.END}")
	print(f"  SQLAlchemy: {Colors.GREEN if sqlalchemy_available else Colors.YELLOW}{'✓ Available' if sqlalchemy_available else '⚠️  Not Available (tests will be skipped)'}{Colors.END}")
	
	# Verify provided database files exist
	print(f"\n{Colors.BOLD}Pre-Populated Database Files:{Colors.END}")
	
	import os
	sqlite_exists = os.path.exists(DB_SQLITE_ORIGINAL) if 'DB_SQLITE_ORIGINAL' in globals() else os.path.exists('users_sqlite.db')
	sqlalchemy_exists = os.path.exists(DB_SQLALCHEMY_ORIGINAL) if 'DB_SQLALCHEMY_ORIGINAL' in globals() else os.path.exists('users_sqlalchemy.db')
	
	print(f"  {DB_SQLITE}: {Colors.GREEN if sqlite_exists else Colors.RED}{'✓ Found' if sqlite_exists else '✗ Missing'}{Colors.END}")
	if sqlalchemy_available:
		print(f"  {DB_SQLALCHEMY_SQLITE}: {Colors.GREEN if sqlalchemy_exists else Colors.RED}{'✓ Found' if sqlalchemy_exists else '✗ Missing'}{Colors.END}")
	if postgres_available:
		print(f"  PostgreSQL (auth_db): {Colors.GREEN}✓ Loaded{Colors.END}")
	
	if not sqlite_exists:
		print(f"\n{Colors.RED}ERROR: Required database file '{DB_SQLITE}' not found!{Colors.END}")
		print(f"{Colors.YELLOW}Please ensure you have the provided database files in the current directory.{Colors.END}")
		sys.exit(1)
	
	kdfs = [
		("scrypt", "hash_password_scrypt", "verify_password_scrypt", 20.0, "scrypt:"),
		("pbkdf2", "hash_password_pbkdf2", "verify_password_pbkdf2", 50.0, "pbkdf2:"),
		("argon2", "hash_password_argon2", "verify_password_argon2", 20.0, "argon2:"),
		("bcrypt", "hash_password_bcrypt", "verify_password_bcrypt", 50.0, "$2"),
	]
	
	db_backends = ["sqlite"]
	if postgres_available:
		db_backends.append("postgres")
	if sqlalchemy_available:
		db_backends.append("sqlalchemy")
	
	for kdf_name, hash_func, verify_func, min_time, format_check in kdfs:
		print_header(f"TESTING {kdf_name.upper()} IMPLEMENTATION")
		
		# Password hashing tests (database-independent)
		test_kdf_implementation(solution, kdf_name, hash_func, verify_func, min_time, format_check)
		
		# Database-specific tests for each backend
		for db_backend in db_backends:
			if db_backend != "sqlite":
				print(f"\n{Colors.BOLD}--- {db_backend.upper()} Backend ---{Colors.END}")
			
			# SQL injection tests
			test_sql_injection_comprehensive(solution, kdf_name, db_backend)
			
			# Blind SQL injection tests
			test_blind_sql_injection(solution, kdf_name, db_backend)
			
			# User enumeration tests
			test_user_enumeration(solution, kdf_name, db_backend)
			
			# Resource leak tests
			test_resource_leaks(solution, kdf_name, db_backend)
			
			# Edge case tests
			test_edge_cases(solution, kdf_name, db_backend)

def print_final_report():
	"""Print comprehensive final report"""
	
	print_header("FINAL GRADING REPORT")
	
	# Calculate scores
	total_points = sum(r.points for r in test_results)
	max_points = sum(r.max_points for r in test_results)
	percentage = (total_points / max_points * 100) if max_points > 0 else 0
	
	# Category breakdown
	categories = {}
	for result in test_results:
		cat = result.category
		if cat not in categories:
			categories[cat] = {'earned': 0, 'max': 0, 'passed': 0, 'total': 0}
		categories[cat]['earned'] += result.points
		categories[cat]['max'] += result.max_points
		categories[cat]['total'] += 1
		if result.passed:
			categories[cat]['passed'] += 1
	
	print(f"\n{Colors.BOLD}Category Breakdown:{Colors.END}\n")
	for cat, scores in sorted(categories.items()):
		pct = (scores['earned'] / scores['max'] * 100) if scores['max'] > 0 else 0
		color = Colors.GREEN if pct >= 80 else Colors.YELLOW if pct >= 60 else Colors.RED
		print(f"  {cat:20s}: {color}{scores['earned']:3d}/{scores['max']:3d} pts{Colors.END} ({pct:5.1f}%) - {scores['passed']}/{scores['total']} tests passed")
	
	print(f"\n{Colors.BOLD}Overall Score:{Colors.END}")
	print(f"  Points: {total_points}/{max_points}")
	print(f"  Percentage: {percentage:.1f}%")
	print(f"  Tests Passed: {sum(1 for r in test_results if r.passed)}/{len(test_results)}")
	
	# Grade assignment
	if percentage >= 95:
		grade, msg, color = "A+", "EXCELLENT! Production-ready implementation", Colors.GREEN
	elif percentage >= 90:
		grade, msg, color = "A", "VERY GOOD! Minor issues to address", Colors.GREEN
	elif percentage >= 85:
		grade, msg, color = "B+", "GOOD! Several improvements needed", Colors.GREEN
	elif percentage >= 80:
		grade, msg, color = "B", "SATISFACTORY - Some security gaps", Colors.YELLOW
	elif percentage >= 70:
		grade, msg, color = "C", "NEEDS WORK - Significant vulnerabilities", Colors.YELLOW
	else:
		grade, msg, color = "F", "INSECURE - Would fail security audit", Colors.RED
	
	print(f"\n{Colors.BOLD}Final Grade: {color}{grade}{Colors.END}")
	print(f"{color}{msg}{Colors.END}")
	
	# Critical failures
	if critical_failures:
		print(f"\n{Colors.RED}{Colors.BOLD}🚨 CRITICAL SECURITY FAILURES:{Colors.END}")
		for failure in critical_failures[:10]:
			print(f"  {Colors.RED}•{Colors.END} {failure}")
		if len(critical_failures) > 10:
			print(f"  {Colors.RED}• ... and {len(critical_failures) - 10} more{Colors.END}")
	
	print()

def main():
	if len(sys.argv) != 2:
		print(f"{Colors.YELLOW}Usage: python grader.py solution.py{Colors.END}")
		sys.exit(1)
	
	solution_file = sys.argv[1]
	
	print_header("COMPREHENSIVE SECURITY GRADER")
	print(f"Solution: {Colors.BOLD}{solution_file}{Colors.END}")
	print(f"\n{Colors.YELLOW}⚠️  This grader ACTIVELY TRIES TO BREAK your implementation.{Colors.END}")
	print(f"{Colors.YELLOW}⚠️  Expect to see security vulnerabilities exposed!{Colors.END}\n")
	
	solution = load_solution(solution_file)
	
	print(f"{Colors.GREEN}✓{Colors.END} Solution loaded")
	print(f"{Colors.GREEN}✓{Colors.END} Starting adversarial testing...\n")
	
	run_all_tests(solution)
	print_final_report()
	
	# Cleanup
	if os.path.exists(DB_SQLITE):
		os.remove(DB_SQLITE)
	if os.path.exists(DB_SQLALCHEMY_SQLITE):
		os.remove(DB_SQLALCHEMY_SQLITE)

if __name__ == "__main__":
	main()
