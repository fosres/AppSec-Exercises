#!/usr/bin/env python3
"""
Security Log Correlator Grader
Tests student solutions against 101 realistic test cases

Usage:
	python3 grader.py student_solution.py
	python3 grader.py student_solution.py --verbose
	python3 grader.py student_solution.py --test 031
	python3 grader.py student_solution.py --category brute_force

Required Function Signatures:
	
	def parse_auth_log(filepath, table_events):
		# Parse CSV auth log and populate table_events in-place
		# table_events[user_id]["auth_events"] = [...]
	
	def parse_security_log(filepath, table_events):
		# Parse JSON security log and populate table_events in-place
		# table_events[user_id]["security_events"] = [...]
	
	Expected table_events structure after both functions:
		{
			"user123": {
				"auth_events": [{...}, {...}],
				"security_events": [{...}, {...}]
			},
			"user456": {
				"auth_events": [{...}],
				"security_events": [{...}]
			}
		}

Detection Criteria:
	
	BRUTE FORCE:
	- 5+ failed logins within 5-minute window
	- Successful login MUST occur within the SAME 5-minute window
	- Returns: dict with attack details or None
	- DETECTION: Only detects COMPLETED attacks (success within window)
	  * If success within window: Return attack dict with success_event
	  * If success outside window OR no success: Return None (don't detect)
	- IMPORTANT: The time window is from first failure to last failure.
	  Success must be within this same window to be detected.
	- MULTIPLE ATTACKS: If a user experiences multiple separate brute force attacks
	  (each with 5+ failures + success within their own window), return ALL attacks
	  in an "attacks" array with "total_attacks" count.
	  See return type options below.
	
	PRIVILEGE ESCALATION:
	- Successful login (any IP address)
	- Privilege change event within 10 minutes
	- event_type == "privilege_change"
	- resource contains: "sudo_access", "admin_role", "root_access", etc.
	- NOTE: Does NOT require IP address change (simplified criteria)
	- Rationale: Rapid escalation is suspicious regardless of IP
	- Returns: dict with attack details or None
	- MULTIPLE ESCALATIONS: Multiple escalations can occur after the SAME login
	  (e.g., escalate to sudo, then root, then admin). They are grouped by login_event.
	  A user may also have multiple logins throughout the day, each with escalations.
	  Return escalations grouped in "login_sessions" array.
	  See return type options below.
	
	ANOMALOUS FILE ACCESS:
	- event_type == "file_access"
	- resource contains sensitive file paths:
	  * /etc/passwd, /etc/shadow, /etc/sudoers
	  * /root/.ssh/authorized_keys, /.ssh/id_rsa
	  * /var/log/auth.log, /var/log/secure
	  * /etc/crontab, /var/spool/cron/*
	- Returns: dict with attack details or None

Detection Function Return Types:
	Functions can return EITHER:
	1. dict with attack details (recommended - includes full information)
	2. boolean True/False (simple detection)
	3. None (no attack detected - equivalent to False)
	
	Example dict return (SINGLE attack):
	{
		"user_id": "user123",
		"failure_count": 7,
		"failure_chain": [...],  # Full event details of all failures
		"success_event": {...},  # The exact successful login event within the window
		                         # that proves the brute force attack succeeded
		"attack_duration_seconds": 245.5
	}
	
	Example dict return (MULTIPLE attacks):
	{
		"user_id": "user123",
		"attacks": [
			{
				"failure_count": 5,
				"failure_chain": [...],
				"success_event": {...},  # Success within window
				"attack_duration_seconds": 300
			},
			{
				"failure_count": 8,
				"failure_chain": [...],
				"success_event": {...},  # Success within window
				"attack_duration_seconds": 240
			}
		],
		"total_attacks": 2
	}
	
	Example dict return (privilege escalation - ALWAYS grouped):
	{
		"user_id": "admin",
		"login_sessions": [
			{
				"login_event": {            # Full auth event from auth.log
					"timestamp": "2024-01-15T10:00:00Z",
					"user_id": "admin",
					"action": "login",
					"ip_address": "192.168.1.100",
					"status": "success",
					"session_id": "sess_123"
				},
				"privilege_escalations": [
					{
						"privilege_event": {    # Full security event from security.log
							"timestamp": "2024-01-15T10:02:00Z",
							"user_id": "admin",
							"event_type": "privilege_change",
							"resource": "sudo_access",
							"session_id": "sess_123",
							"ip_address": "192.168.1.100"
						},
						"time_to_escalation_seconds": 120
					},
					{
						"privilege_event": {
							"timestamp": "2024-01-15T10:05:00Z",
							"user_id": "admin",
							"event_type": "privilege_change",
							"resource": "root_access",
							"session_id": "sess_123",
							"ip_address": "192.168.1.100"
						},
						"time_to_escalation_seconds": 300
					}
				],
				"escalation_count": 2
			},
			{
				"login_event": {            # Different login session
					"timestamp": "2024-01-15T14:00:00Z",
					"user_id": "admin",
					"action": "login",
					"ip_address": "192.168.1.100",
					"status": "success",
					"session_id": "sess_456"
				},
				"privilege_escalations": [
					{
						"privilege_event": {
							"timestamp": "2024-01-15T14:03:00Z",
							"user_id": "admin",
							"event_type": "privilege_change",
							"resource": "admin_role",
							"session_id": "sess_456",
							"ip_address": "192.168.1.100"
						},
						"time_to_escalation_seconds": 180
					}
				],
				"escalation_count": 1
			}
		],
		"total_login_sessions": 2,
		"total_escalations": 3
	}
	
	Note: login_event contains the FULL auth event from auth.log
	(timestamp, user_id, action, ip_address, status, session_id, etc.)
	privilege_event contains the FULL security event from security.log
	(timestamp, user_id, event_type, resource, session_id, ip_address, etc.)
	Even single login with single escalation uses this structure
	(login_sessions array with 1 session, privilege_escalations array with 1 item)
"""

import sys
import os
import argparse
import importlib.util
import tempfile
import zipfile
import signal
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import time


# ==================== TIMEOUT HANDLER ====================

class TimeoutError(Exception):
	"""Raised when a test times out"""
	pass

def timeout_handler(signum, frame):
	"""Signal handler for timeout"""
	raise TimeoutError("Test exceeded time limit")


# ==================== TEST SPECIFICATIONS ====================

class TestSpec:
	"""Specification for what a test should detect"""
	def __init__(self, test_num: int, category: str, 
	             should_detect_brute_force: bool = False,
	             should_detect_privilege_escalation: bool = False,
	             should_detect_anomalous_access: bool = False,
	             min_users: int = 0,
	             max_users: int = 10000,
	             description: str = ""):
		self.test_num = test_num
		self.category = category
		self.should_detect_brute_force = should_detect_brute_force
		self.should_detect_privilege_escalation = should_detect_privilege_escalation
		self.should_detect_anomalous_access = should_detect_anomalous_access
		self.min_users = min_users
		self.max_users = max_users
		self.description = description


# Test specifications based on test data generation
TEST_SPECS = {
	# Parsing tests (001-015) - Should parse without errors
	**{i: TestSpec(i, "parsing", description=f"Parsing test {i}") 
	   for i in range(1, 16)},
	
	# Correlation tests (016-030) - Should correlate correctly
	**{i: TestSpec(i, "correlation", min_users=10, description=f"Correlation test {i}") 
	   for i in range(16, 31)},
	
	# Brute force tests (031-045)
	31: TestSpec(31, "brute_force", should_detect_brute_force=True, 
	            description="Exactly 5 failures then success"),
	32: TestSpec(32, "brute_force", should_detect_brute_force=False,
	            description="Below threshold (4 failures)"),
	33: TestSpec(33, "brute_force", should_detect_brute_force=False,
	            description="Failures outside time window"),
	34: TestSpec(34, "brute_force", should_detect_brute_force=True,
	            description="6+ failures then success"),
	35: TestSpec(35, "brute_force", should_detect_brute_force=True,
	            description="Rapid failures then success"),
	36: TestSpec(36, "brute_force", should_detect_brute_force=True,
	            description="Multiple users under attack"),
	37: TestSpec(37, "brute_force", should_detect_brute_force=True,
	            description="Distributed attack pattern"),
	38: TestSpec(38, "brute_force", should_detect_brute_force=True,
	            description="Slow brute force"),
	39: TestSpec(39, "brute_force", should_detect_brute_force=True,
	            description="Mixed attack patterns"),
	40: TestSpec(40, "brute_force", should_detect_brute_force=False,
	            description="Legitimate user typos"),
	41: TestSpec(41, "brute_force", should_detect_brute_force=True,
	            description="Brute force with multiple IPs"),
	42: TestSpec(42, "brute_force", should_detect_brute_force=True,
	            description="Fast brute force"),
	43: TestSpec(43, "brute_force", should_detect_brute_force=True,
	            description="Large scale distributed attack"),
	44: TestSpec(44, "brute_force", should_detect_brute_force=True,
	            description="Brute force on multiple accounts"),
	45: TestSpec(45, "brute_force", should_detect_brute_force=False,
	            description="Normal authentication pattern"),
	
	# Privilege escalation tests (046-055)
	# Detection criteria: Successful login followed by privilege_change within 10 minutes
	# NOTE: Does NOT require different IP addresses - simplified from original spec
	# Rationale: Rapid privilege escalation is suspicious regardless of IP
	#   - Misses attacks if requiring IP change (insider threats, session hijacking)
	#   - Creates false positives (VPN usage, normal admin workflows)
	#   - Real security principle: TIMING matters more than IP for privilege escalation
	46: TestSpec(46, "privilege_escalation", should_detect_privilege_escalation=True,
	            description="Rapid privilege escalation after login"),
	47: TestSpec(47, "privilege_escalation", should_detect_privilege_escalation=False,
	            description="No privilege change event"),
	48: TestSpec(48, "privilege_escalation", should_detect_privilege_escalation=False,
	            description="Privilege change outside time window"),
	49: TestSpec(49, "privilege_escalation", should_detect_privilege_escalation=False,
	            description="No privilege change after login"),
	50: TestSpec(50, "privilege_escalation", should_detect_privilege_escalation=True,
	            description="Privilege escalation within 10 minutes"),
	51: TestSpec(51, "privilege_escalation", should_detect_privilege_escalation=True,
	            description="Multiple rapid privilege escalations"),
	52: TestSpec(52, "privilege_escalation", should_detect_privilege_escalation=True,
	            description="Very rapid privilege escalation"),
	53: TestSpec(53, "privilege_escalation", should_detect_privilege_escalation=False,
	            description="Normal delayed privilege usage"),
	54: TestSpec(54, "privilege_escalation", should_detect_privilege_escalation=True,
	            description="Privilege escalation with subsequent actions"),
	55: TestSpec(55, "privilege_escalation", should_detect_privilege_escalation=False,
	            description="Normal admin workflow pattern"),
	
	# Security analysis tests (056-065)
	56: TestSpec(56, "security_analysis", should_detect_anomalous_access=True,
	            description="Access to /etc/passwd"),
	57: TestSpec(57, "security_analysis", should_detect_anomalous_access=True,
	            description="Access to /etc/shadow"),
	58: TestSpec(58, "security_analysis", should_detect_anomalous_access=True,
	            description="Log file access (tampering attempt)"),
	59: TestSpec(59, "security_analysis", should_detect_anomalous_access=True,
	            description="Multiple sensitive files"),
	60: TestSpec(60, "security_analysis", should_detect_anomalous_access=True,
	            description="Mixed activity with log access"),
	61: TestSpec(61, "security_analysis", should_detect_anomalous_access=True,
	            description="SSH key access"),
	62: TestSpec(62, "security_analysis", should_detect_anomalous_access=True,
	            description="Log file access (tampering attempt)"),
	63: TestSpec(63, "security_analysis", should_detect_anomalous_access=True,
	            description="Root directory access"),
	64: TestSpec(64, "security_analysis", should_detect_anomalous_access=True,
	            description="SSH key access in home directory"),
	65: TestSpec(65, "security_analysis", should_detect_anomalous_access=True,
	            description="System configuration access")
}


# ==================== GRADER CLASS ====================

class LogCorrelatorGrader:
	"""Grades student log correlator implementations"""
	
	def __init__(self, solution_path: str, test_data_zip: str, verbose: bool = False):
		self.solution_path = Path(solution_path)
		self.test_data_zip = Path(test_data_zip)
		self.verbose = verbose
		self.student_module = None
		self.test_dir = None
		self.is_temp_dir = False  # Track if we created a temporary directory
		self.results = []
		
	def load_student_solution(self):
		"""Dynamically import student's solution"""
		if not self.solution_path.exists():
			print(f"❌ Error: Solution file not found: {self.solution_path}")
			sys.exit(1)
		
		try:
			spec = importlib.util.spec_from_file_location("student_solution", self.solution_path)
			self.student_module = importlib.util.module_from_spec(spec)
			spec.loader.exec_module(self.student_module)
			
			# Verify required functions exist
			required_functions = [
				'parse_auth_log',
				'parse_security_log'
			]
			
			optional_functions = [
				'detect_brute_force',
				'detect_privilege_escalation',
				'detect_anomalous_access'
			]
			
			missing = [f for f in required_functions if not hasattr(self.student_module, f)]
			if missing:
				print(f"❌ Error: Missing required functions: {', '.join(missing)}")
				sys.exit(1)
			
			available_optional = [f for f in optional_functions if hasattr(self.student_module, f)]
			
			if self.verbose:
				print("✅ Loaded student solution")
				print(f"   Required functions: {', '.join(required_functions)}")
				print(f"   Optional functions: {', '.join(available_optional)}")
			
		except Exception as e:
			print(f"❌ Error loading solution: {e}")
			import traceback
			traceback.print_exc()
			sys.exit(1)
	
	def extract_test_data(self):
		"""Extract test data to temporary directory, or use existing directory"""
		# Check if it's already a directory
		if self.test_data_zip.is_dir():
			self.test_dir = str(self.test_data_zip)
			self.is_temp_dir = False  # Don't delete user-provided directory
			if self.verbose:
				print(f"✅ Using test data directory: {self.test_dir}")
			return
		
		# Otherwise treat it as a zip file
		if not self.test_data_zip.exists():
			print(f"❌ Error: Test data not found: {self.test_data_zip}")
			sys.exit(1)
		
		try:
			self.test_dir = tempfile.mkdtemp()
			self.is_temp_dir = True  # We created this, so clean it up later
			with zipfile.ZipFile(self.test_data_zip, 'r') as zip_ref:
				zip_ref.extractall(self.test_dir)
			
			if self.verbose:
				print(f"✅ Extracted test data to {self.test_dir}")
			
		except Exception as e:
			print(f"❌ Error extracting test data: {e}")
			sys.exit(1)
	
	def run_single_test(self, test_num: int, category: str) -> Dict:
		"""Run a single test case"""
		# Find test directory
		test_name = f"test_{test_num:03d}_{category}"
		category_dir = f"{test_num//1:02d}_{category}".split("_")[0] + "_" + category
		
		# Handle category mapping
		category_map = {
			"parsing": "01_parsing",
			"correlation": "02_correlation",
			"brute_force": "03_brute_force",
			"privilege_escalation": "04_privilege_escalation",
			"security_analysis": "05_security_analysis",
			"edge_cases": "06_edge_cases"
		}
		
		category_dir = category_map.get(category, category)
		
		# Handle path construction based on whether test_dir already contains test_data_complete
		test_dir_path = Path(self.test_dir)
		if test_dir_path.name == "test_data_complete":
			# User provided test_data_complete directory directly
			test_path = test_dir_path / category_dir / test_name
		else:
			# Extracted from zip (temp dir contains test_data_complete folder)
			test_path = test_dir_path / "test_data_complete" / category_dir / test_name
		
		if not test_path.exists():
			return {
				"test_num": test_num,
				"category": category,
				"status": "SKIP",
				"message": f"Test directory not found: {test_path}",
				"time": 0
			}
		
		auth_log = test_path / "auth.log"
		security_log = test_path / "security.log"
		
		if not auth_log.exists() or not security_log.exists():
			return {
				"test_num": test_num,
				"category": category,
				"status": "SKIP",
				"message": "Missing log files",
				"time": 0
			}
		
		spec = TEST_SPECS.get(test_num)
		if not spec:
			spec = TestSpec(test_num, category)
		
		result = {
			"test_num": test_num,
			"category": category,
			"description": spec.description,
			"status": "PASS",
			"message": "",
			"time": 0,
			"details": {}
		}
		
		try:
			start_time = time.time()
			
			# Set 30-second timeout for this test
			signal.signal(signal.SIGALRM, timeout_handler)
			signal.alarm(30)
			
			# Step 1 & 2: Parse logs and correlate (user's approach combines these)
			# User's functions modify table_events in-place
			table_events = {}
			
			try:
				self.student_module.parse_auth_log(str(auth_log), table_events)
				auth_events_count = sum(len(user_data.get("auth_events", [])) for user_data in table_events.values())
			except Exception as e:
				result["status"] = "ERROR"
				result["message"] = f"parse_auth_log failed: {e}"
				result["time"] = time.time() - start_time
				return result
			
			try:
				self.student_module.parse_security_log(str(security_log), table_events)
				security_events_count = sum(len(user_data.get("security_events", [])) for user_data in table_events.values())
			except Exception as e:
				result["status"] = "ERROR"
				result["message"] = f"parse_security_log failed: {e}"
				result["time"] = time.time() - start_time
				return result
			
			result["details"]["auth_events_parsed"] = auth_events_count
			result["details"]["security_events_parsed"] = security_events_count
			
			# table_events is now the correlated user_events
			user_events = table_events
			
			num_users = len(user_events) if user_events else 0
			result["details"]["users_correlated"] = num_users
			
			# Validate user count is reasonable
			if spec.min_users > 0 and num_users < spec.min_users:
				result["status"] = "FAIL"
				result["message"] = f"Too few users correlated: {num_users} < {spec.min_users}"
			elif num_users > spec.max_users:
				result["status"] = "FAIL"
				result["message"] = f"Too many users correlated: {num_users} > {spec.max_users}"
			
			# Step 3: Test detection functions (if they exist and test requires them)
			# NOTE: Detection functions can return:
			#   - dict with "detected" key (returns attack details)
			#   - boolean True/False (simple detection)
			#   - None (no attack detected)
			
			if hasattr(self.student_module, 'detect_brute_force') and user_events:
				# Test brute force detection on first 10 users
				brute_force_detected = False
				brute_force_details = None
				for user_id in list(user_events.keys())[:10]:
					try:
						result_val = self.student_module.detect_brute_force(user_id, user_events)
						
						# Handle dict return (Option 1: rich details)
						if isinstance(result_val, dict) and result_val:
							# Check if it's an empty detection (no attacks found)
							if "attacks" in result_val:
								# Multiple attacks structure - check if array is empty
								if len(result_val.get("attacks", [])) > 0:
									brute_force_detected = True
									brute_force_details = result_val
									break
								# else: Empty attacks array - no detection
							elif "failure_count" in result_val or "failure_chain" in result_val:
								# Single attack structure - verify it has actual attack data
								# Not just an empty dict with only user_id
								brute_force_detected = True
								brute_force_details = result_val
								break
							# else: Empty dict (only user_id) - no detection
					except:
						pass
				
				result["details"]["brute_force_detected"] = brute_force_detected
				if brute_force_details:
					# Handle both single attack and multiple attacks structures
					if "attacks" in brute_force_details:
						# Multiple attacks structure
						result["details"]["brute_force_details"] = {
							"user_id": brute_force_details.get("user_id"),
							"total_attacks": brute_force_details.get("total_attacks"),
							"attack_count": len(brute_force_details.get("attacks", []))
						}
					else:
						# Single attack structure (backward compatible)
						result["details"]["brute_force_details"] = {
							"user_id": brute_force_details.get("user_id"),
							"failure_count": brute_force_details.get("failure_count")
						}
				# Only validate for brute_force category tests
				if category == "brute_force":
					if spec.should_detect_brute_force and not brute_force_detected:
						result["status"] = "FAIL"
						result["message"] = "Should detect brute force but didn't"
					elif not spec.should_detect_brute_force and brute_force_detected:
						result["status"] = "FAIL"
						result["message"] = "Should NOT detect brute force but did (false positive)"
			
			if hasattr(self.student_module, 'detect_privilege_escalation') and user_events:
				priv_esc_detected = False
				priv_esc_details = None
				for user_id in list(user_events.keys())[:10]:
					try:
						result_val = self.student_module.detect_privilege_escalation(user_id, user_events)
						
						# Handle dict return (Option 1: rich details)
						if isinstance(result_val, dict) and result_val:
							# Check if it's an empty detection (no escalations found)
							if result_val.get("total_escalations", 0) > 0:
								priv_esc_detected = True
								priv_esc_details = result_val
								break
					except:
						pass
				
				result["details"]["privilege_escalation_detected"] = priv_esc_detected
				if priv_esc_details:
					# Always expect grouped login_sessions structure
					if "login_sessions" in priv_esc_details:
						result["details"]["priv_esc_details"] = {
							"user_id": priv_esc_details.get("user_id"),
							"total_login_sessions": priv_esc_details.get("total_login_sessions"),
							"total_escalations": priv_esc_details.get("total_escalations"),
							"sessions_count": len(priv_esc_details.get("login_sessions", []))
						}
					else:
						# Fallback for boolean or unexpected format
						result["details"]["priv_esc_details"] = {
							"user_id": priv_esc_details.get("user_id", "unknown"),
							"detected": True
						}
				
				# Only validate for privilege_escalation category tests
				# Detection: Login + privilege_change within 10 min (NO IP requirement)
				if category == "privilege_escalation":
					if spec.should_detect_privilege_escalation and not priv_esc_detected:
						result["status"] = "FAIL"
						result["message"] = "Should detect privilege escalation but didn't"
					elif not spec.should_detect_privilege_escalation and priv_esc_detected:
						result["status"] = "FAIL"
						result["message"] = "Should NOT detect privilege escalation but did (false positive)"
			
			if hasattr(self.student_module, 'detect_anomalous_access') and user_events:
				anomalous_detected = False
				anomalous_details = None
				for user_id in list(user_events.keys())[:10]:
					try:
						result_val = self.student_module.detect_anomalous_access(user_id, user_events)
						
						# Handle dict return (Option 1: rich details)
						if isinstance(result_val, dict) and result_val:
							# Check if it's an empty detection (no sensitive files accessed)
							if result_val.get("access_count", 0) > 0:
								anomalous_detected = True
								anomalous_details = result_val
								break
					except:
						pass
				
				result["details"]["anomalous_access_detected"] = anomalous_detected
				if anomalous_details:
					result["details"]["anomalous_details"] = {
						"user_id": anomalous_details.get("user_id"),
						"access_count": anomalous_details.get("access_count")
					}
				
				# Only validate for security_analysis category tests
				if category == "security_analysis":
					if spec.should_detect_anomalous_access and not anomalous_detected:
						result["status"] = "FAIL"
						result["message"] = "Should detect anomalous access but didn't"
					elif not spec.should_detect_anomalous_access and anomalous_detected:
						result["status"] = "FAIL"
						result["message"] = "Should NOT detect anomalous access but did (false positive)"
			
			result["time"] = time.time() - start_time
			signal.alarm(0)  # Cancel the alarm
			
		except TimeoutError:
			signal.alarm(0)  # Cancel the alarm
			result["status"] = "ERROR"
			result["message"] = "Test timed out after 30 seconds (likely infinite loop)"
			result["time"] = 30.0
		except Exception as e:
			signal.alarm(0)  # Cancel the alarm
			result["status"] = "ERROR"
			result["message"] = str(e)
			result["time"] = time.time() - start_time
			
			if self.verbose:
				import traceback
				result["traceback"] = traceback.format_exc()
		
		return result
	
	def run_all_tests(self, test_filter: Optional[int] = None, 
	                  category_filter: Optional[str] = None):
		"""Run all tests or filtered subset"""
		tests_to_run = []
		
		for test_num, spec in TEST_SPECS.items():
			if test_filter and test_num != test_filter:
				continue
			if category_filter and spec.category != category_filter:
				continue
			tests_to_run.append((test_num, spec.category))
		
		print(f"\n🧪 Running {len(tests_to_run)} tests...")
		print("=" * 80)
		
		for test_num, category in sorted(tests_to_run):
			result = self.run_single_test(test_num, category)
			self.results.append(result)
			
			# Print result
			status_icon = {
				"PASS": "✅",
				"FAIL": "❌",
				"ERROR": "💥",
				"SKIP": "⏭️"
			}.get(result["status"], "❓")
			
			test_id = f"Test {result['test_num']:03d}"
			
			if self.verbose or result["status"] != "PASS":
				print(f"\n{status_icon} {test_id} ({result['category']}): {result['status']}")
				if result.get("description"):
					print(f"   {result['description']}")
				if result.get("message"):
					print(f"   Message: {result['message']}")
				if self.verbose and result.get("details"):
					print(f"   Details: {result['details']}")
				if result.get("time"):
					print(f"   Time: {result['time']:.3f}s")
				if result.get("traceback"):
					print(f"   Traceback:\n{result['traceback']}")
			else:
				# Compact output for passing tests
				print(f"{status_icon} {test_id}", end=" ", flush=True)
				if (test_num % 10 == 0):
					print()  # New line every 10 tests
		
		print("\n" + "=" * 80)
	
	def print_summary(self):
		"""Print test summary"""
		total = len(self.results)
		passed = sum(1 for r in self.results if r["status"] == "PASS")
		failed = sum(1 for r in self.results if r["status"] == "FAIL")
		errors = sum(1 for r in self.results if r["status"] == "ERROR")
		skipped = sum(1 for r in self.results if r["status"] == "SKIP")
		
		total_time = sum(r["time"] for r in self.results)
		
		print("\n📊 SUMMARY")
		print("=" * 80)
		print(f"Total Tests:   {total}")
		print(f"✅ Passed:     {passed} ({passed/total*100:.1f}%)")
		print(f"❌ Failed:     {failed} ({failed/total*100:.1f}%)")
		print(f"💥 Errors:     {errors} ({errors/total*100:.1f}%)")
		print(f"⏭️  Skipped:    {skipped}")
		print(f"⏱️  Total Time: {total_time:.2f}s")
		print("=" * 80)
		
		# Category breakdown
		categories = {}
		for result in self.results:
			cat = result.get("category", "unknown")
			if cat not in categories:
				categories[cat] = {"pass": 0, "fail": 0, "error": 0}
			
			if result["status"] == "PASS":
				categories[cat]["pass"] += 1
			elif result["status"] == "FAIL":
				categories[cat]["fail"] += 1
			elif result["status"] == "ERROR":
				categories[cat]["error"] += 1
		
		if categories:
			print("\n📁 BY CATEGORY:")
			for cat, counts in sorted(categories.items()):
				total_cat = counts["pass"] + counts["fail"] + counts["error"]
				print(f"  {cat:20s}: {counts['pass']}/{total_cat} passed")
		
		# Failed tests details
		failed_tests = [r for r in self.results if r["status"] in ["FAIL", "ERROR"]]
		if failed_tests:
			print(f"\n❌ FAILED/ERROR TESTS ({len(failed_tests)}):")
			for result in failed_tests:
				print(f"  Test {result['test_num']:03d} ({result['category']}): {result['message']}")
		
		print("=" * 80)
		
		# Final score
		if total > 0:
			score = (passed / total) * 100
			if score == 100:
				print("🎉 PERFECT SCORE! All tests passed!")
			elif score >= 90:
				print(f"🌟 EXCELLENT! {score:.1f}% tests passed")
			elif score >= 70:
				print(f"👍 GOOD! {score:.1f}% tests passed")
			elif score >= 50:
				print(f"📚 NEEDS WORK: {score:.1f}% tests passed")
			else:
				print(f"⚠️  NEEDS SIGNIFICANT WORK: {score:.1f}% tests passed")
	
	def cleanup(self):
		"""Clean up temporary test directory if one was created"""
		if self.is_temp_dir and self.test_dir:
			try:
				import shutil
				shutil.rmtree(self.test_dir)
				if self.verbose:
					print(f"🧹 Cleaned up temporary directory: {self.test_dir}")
			except Exception as e:
				if self.verbose:
					print(f"⚠️  Warning: Could not clean up temp directory: {e}")


# ==================== MAIN ====================

def main():
	parser = argparse.ArgumentParser(
		description="Grade Security Log Correlator implementations",
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""
Examples:
  python3 grader.py my_solution.py
  python3 grader.py my_solution.py --verbose
  python3 grader.py my_solution.py --test 031
  python3 grader.py my_solution.py --category brute_force
		"""
	)
	
	parser.add_argument("solution", help="Path to student's solution script")
	parser.add_argument("--test", type=int, help="Run only specific test number")
	parser.add_argument("--category", choices=["parsing", "correlation", "brute_force", 
	                                           "privilege_escalation", "security_analysis", 
	                                           "edge_cases"],
	                   help="Run only tests in this category")
	parser.add_argument("--verbose", "-v", action="store_true", 
	                   help="Verbose output with details")
	parser.add_argument("--test-data", default="test_data_complete",
	                   help="Path to test data directory or zip file (default: test_data_complete)")
	
	args = parser.parse_args()
	
	print("=" * 80)
	print("🔒 SECURITY LOG CORRELATOR GRADER")
	print("=" * 80)
	print(f"Solution: {args.solution}")
	if args.test:
		print(f"Filter: Test {args.test}")
	if args.category:
		print(f"Filter: Category '{args.category}'")
	
	grader = LogCorrelatorGrader(args.solution, args.test_data, args.verbose)
	grader.load_student_solution()
	grader.extract_test_data()
	grader.run_all_tests(test_filter=args.test, category_filter=args.category)
	grader.print_summary()
	grader.cleanup()  # Clean up temporary directory if one was created


if __name__ == "__main__":
	main()
