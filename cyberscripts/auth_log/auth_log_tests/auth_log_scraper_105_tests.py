#!/usr/bin/env python3
"""
Auth Log Failed Authentication Scraper - 105 Test Cases

This exercise tests your ability to parse Linux auth.log files and detect
ALL failed SSH authentication attempts - both password and publickey failures.

Security Rationale:
- Password failures: Credential stuffing, brute force attacks
- Publickey failures: Key enumeration, stolen key testing, lateral movement

A comprehensive security tool must track BOTH types.

Real-World Output Fields:
- first_failure: When did the attack start? (incident response)
- last_failure: Is the attack still happening? (active threat detection)

Inspired by:
- Python Workout, Second Edition (Lerner) - Chapter 6: Files, pp. 113-128
- Hacking APIs (Ball) - Log analysis patterns, pp. 89-102
- API Security in Action (Madden) - Authentication monitoring
- Secure by Design (Johnsson et al.) - Defense in depth

"""

import json
import os
import re
from pathlib import Path


def parse_auth_log(filepath: str) -> dict:
	"""
	Parse a Linux auth.log file and analyze failed authentication attempts.
	
	Tracks BOTH 'Failed password' AND 'Failed publickey' as security events.
	
	Args:
		filepath: Path to the auth.log file
	
	Returns:
		A dictionary with the following structure:
		{
			"total_failed": int,           # Total failed auth attempts (password + publickey)
			"unique_ips": list[str],       # Unique source IPs (sorted alphabetically)
			"unique_users": list[str],     # Unique usernames attempted (sorted alphabetically)
			"attempts_by_ip": dict,        # {ip: count} for each IP
			"attempts_by_user": dict,      # {username: count} for each user
			"top_offender_ips": list[str], # All IPs tied for most failures (sorted)
			"top_targeted_users": list[str], # All users tied for most targeted (sorted)
			"first_failure": str | None,   # Timestamp of first failure e.g. "Jan 5 14:22:01"
			"last_failure": str | None,    # Timestamp of last/most recent failure
			"potential_brute_force": list[str], # IPs with 5+ failures (sorted alphabetically)
		}
	
	Log Formats to MATCH (signal):
		Password failures:
			"Jan  5 14:22:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"
			"Jan  5 14:22:02 server sshd[12346]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2"
		
		Publickey failures:
			"Jan  5 14:22:03 server sshd[12347]: Failed publickey for root from 192.168.1.100 port 22 ssh2: RSA SHA256:..."
			"Jan  5 14:22:04 server sshd[12348]: Failed publickey for invalid user git from 10.0.0.1 port 22 ssh2: ED25519 SHA256:..."
	
	Lines to IGNORE (noise):
		- Successful logins ("Accepted password", "Accepted publickey")
		- Connection closed/reset messages
		- Session opened/closed messages
		- CRON, sudo, systemd entries
		- Any line not matching the Failed password/publickey patterns
	
	Timestamp format:
		"Mon DD HH:MM:SS" where DD may have leading space for single digits
		Examples: "Jan  5 14:22:01" or "Jan 15 14:22:01"
	
	Regex hint:
		r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port'
	"""
	pass  # YOUR IMPLEMENTATION HERE


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_tests(test_dir: str = "auth_log_tests") -> None:
	"""Run all 105 tests and report results."""
	
	# Load expected results
	expected_path = Path(test_dir) / "expected_results.json"
	if not expected_path.exists():
		print(f"ERROR: Expected results not found at {expected_path}")
		return
	
	with open(expected_path) as f:
		expected = json.load(f)
	
	passed = 0
	failed = 0
	errors = []
	
	for test_name, expected_result in sorted(expected.items()):
		# Determine category from test name (e.g., "test_1_01..." -> category1)
		parts = test_name.split("_")
		category_num = parts[1]
		
		# Find the log file
		category_dirs = {
			"1": "category1_basic",
			"2": "category2_edge_cases",
			"3": "category3_ip_handling",
			"4": "category4_brute_force",
			"5": "category5_timeline",
			"6": "category6_top_offender",
			"7": "category7_username_edge",
		}
		
		category_dir = category_dirs.get(category_num)
		if not category_dir:
			errors.append(f"{test_name}: Unknown category")
			failed += 1
			continue
		
		log_path = Path(test_dir) / category_dir / f"{test_name}.log"
		if not log_path.exists():
			errors.append(f"{test_name}: Log file not found at {log_path}")
			failed += 1
			continue
		
		try:
			result = parse_auth_log(str(log_path))
			
			if result == expected_result:
				passed += 1
			else:
				failed += 1
				# Find first difference
				for key in expected_result:
					if key not in result:
						errors.append(f"{test_name}: Missing key '{key}'")
						break
					elif result[key] != expected_result[key]:
						errors.append(
							f"{test_name}: Key '{key}' differs\n"
							f"  Expected: {expected_result[key]}\n"
							f"  Got:      {result[key]}"
						)
						break
				else:
					# Check for extra keys
					extra = set(result.keys()) - set(expected_result.keys())
					if extra:
						errors.append(f"{test_name}: Extra keys: {extra}")
					else:
						errors.append(f"{test_name}: Unknown difference")
		
		except Exception as e:
			failed += 1
			errors.append(f"{test_name}: Exception - {type(e).__name__}: {e}")
	
	# Report results
	total = passed + failed
	print(f"\n{'='*60}")
	print(f"AUTH LOG SCRAPER TEST RESULTS")
	print(f"{'='*60}")
	print(f"Passed: {passed}/{total} ({100*passed/total:.1f}%)")
	print(f"Failed: {failed}/{total}")
	
	if errors:
		print(f"\n{'='*60}")
		print(f"FAILURES (first 10):")
		print(f"{'='*60}")
		for error in errors[:10]:
			print(f"\n{error}")
		
		if len(errors) > 10:
			print(f"\n... and {len(errors) - 10} more failures")
	
	# Category breakdown
	print(f"\n{'='*60}")
	print(f"CATEGORY BREAKDOWN")
	print(f"{'='*60}")
	
	categories = {
		"1": ("Basic Parsing", 0, 0),
		"2": ("Edge Cases", 0, 0),
		"3": ("IP Handling", 0, 0),
		"4": ("Brute Force", 0, 0),
		"5": ("Timeline", 0, 0),
		"6": ("Top Offender", 0, 0),
		"7": ("Username Edge", 0, 0),
	}
	
	for test_name in expected:
		cat = test_name.split("_")[1]
		name, p, f = categories[cat]
		# Check if this test passed
		test_passed = test_name not in [e.split(":")[0] for e in errors]
		if test_passed:
			categories[cat] = (name, p + 1, f)
		else:
			categories[cat] = (name, p, f + 1)
	
	for cat in sorted(categories.keys()):
		name, p, f = categories[cat]
		total_cat = p + f
		print(f"  Category {cat} ({name}): {p}/{total_cat}")


# ============================================================================
# INDIVIDUAL TEST FUNCTIONS (for pytest compatibility)
# ============================================================================

def _load_expected():
	"""Load expected results (cached)."""
	if not hasattr(_load_expected, "cache"):
		with open("auth_log_tests/expected_results.json") as f:
			_load_expected.cache = json.load(f)
	return _load_expected.cache


def _run_single_test(test_name: str) -> bool:
	"""Run a single test, return True if passed."""
	expected = _load_expected()
	if test_name not in expected:
		raise ValueError(f"Unknown test: {test_name}")
	
	cat = test_name.split("_")[1]
	category_dirs = {
		"1": "category1_basic",
		"2": "category2_edge_cases",
		"3": "category3_ip_handling",
		"4": "category4_brute_force",
		"5": "category5_timeline",
		"6": "category6_top_offender",
		"7": "category7_username_edge",
	}
	
	log_path = f"auth_log_tests/{category_dirs[cat]}/{test_name}.log"
	result = parse_auth_log(log_path)
	
	return result == expected[test_name]


# Generate individual test functions for pytest
def test_1_01_single_password_failure():
	assert _run_single_test("test_1_01_single_password_failure")

def test_1_02_single_publickey_failure():
	assert _run_single_test("test_1_02_single_publickey_failure")

def test_1_03_mixed_auth_same_ip():
	assert _run_single_test("test_1_03_mixed_auth_same_ip")

def test_2_08_key_enumeration():
	assert _run_single_test("test_2_08_key_enumeration")

def test_2_09_password_brute_force():
	assert _run_single_test("test_2_09_password_brute_force")

def test_5_04_all_day():
	assert _run_single_test("test_5_04_all_day")

def test_5_05_burst_attack():
	assert _run_single_test("test_5_05_burst_attack")

# ... (remaining 98 test functions would follow the same pattern)


if __name__ == "__main__":
	run_tests()
