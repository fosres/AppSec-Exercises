#!/usr/bin/env python3
"""
VPN Log Analyzer Grader - Simplified Single-File Version
=========================================================

Usage:
	python3 vpn_grader.py student_solution.py

That's it! The grader automatically:
- Finds the test_logs/ directory
- Calculates expected results using reference implementation
- Runs student solution against all test files
- Reports detailed results with colored output

Inspired by:
- "Python Workout, 2nd Edition" by Reuven M. Lerner (Manning, 2024)
  Chapter 5: Dictionaries and Sets (Pages 143-147)
- "Effective Python, 3rd Edition" by Brett Slatkin (Addison-Wesley, 2024)
  Item 76: Testing patterns (Pages 301-308)
- "Secure by Design" by Dan Bergh Johnsson et al. (Manning, 2019)
  Chapter 8: Input validation (Pages 179-195)
"""

import sys
import os
import subprocess
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
import time


class Colors:
	"""ANSI color codes for terminal output"""
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	BLUE = '\033[94m'
	BOLD = '\033[1m'
	RESET = '\033[0m'


def calculate_expected_result(log_file: Path) -> Dict[str, List[str]]:
	"""
	Reference implementation to calculate expected results.
	
	Detection Rules (from challenge specification):
	1. Brute Force: Username with ≥5 failed login attempts
	2. Session Hijacking: Username with successful logins from ≥3 different IPs
	3. Credential Stuffing: IP address attempting ≥5 different usernames
	
	Based on "Python Workout" Exercise 15 patterns (Pages 143-147)
	"""
	failed_attempts = defaultdict(int)
	user_ips = defaultdict(set)
	ip_users = defaultdict(set)
	
	try:
		with open(log_file, 'r') as f:
			for line in f:
				line = line.strip()
				if not line:
					continue
				
				try:
					# Parse: "2026-01-02 14:14:20 | user:admin | IP:10.0.0.5 | status:failed"
					fields = line.split('|')
					if len(fields) != 4:
						continue
					
					username = fields[1].split(':')[1].strip()
					ip = fields[2].split(':')[1].strip()
					status = fields[3].split(':')[1].strip()
					
					if status == 'failed':
						failed_attempts[username] += 1
						ip_users[ip].add(username)
					elif status == 'success':
						user_ips[username].add(ip)
				
				except (IndexError, ValueError):
					continue
	
	except FileNotFoundError:
		return {'brute_force': [], 'session_hijacking': [], 'credential_stuffing': []}
	
	# Apply thresholds
	brute_force = sorted([user for user, count in failed_attempts.items() if count >= 5])
	session_hijacking = sorted([user for user, ips in user_ips.items() if len(ips) >= 3])
	credential_stuffing = sorted([ip for ip, users in ip_users.items() if len(users) >= 5])
	
	return {
		'brute_force': brute_force,
		'session_hijacking': session_hijacking,
		'credential_stuffing': credential_stuffing
	}


def run_student_solution(solution_path: Path, log_file: Path) -> Tuple[Optional[Dict], Optional[str], float]:
	"""
	Execute student solution and capture output.
	
	Following "Effective Python" Item 52: subprocess isolation (Pages 195-201)
	"""
	start_time = time.time()
	
	try:
		result = subprocess.run(
			[sys.executable, str(solution_path), str(log_file)],
			capture_output=True,
			text=True,
			timeout=10
		)
		
		runtime_ms = (time.time() - start_time) * 1000
		
		if result.returncode != 0:
			return None, f"Exit code {result.returncode}: {result.stderr[:200]}", runtime_ms
		
		# Parse output
		output = result.stdout.strip()
		if not (output.startswith('{') and output.endswith('}')):
			return None, f"Invalid format: {output[:100]}", runtime_ms
		
		result_dict = eval(output)
		
		# Validate structure
		required_keys = {'brute_force', 'session_hijacking', 'credential_stuffing'}
		if set(result_dict.keys()) != required_keys:
			return None, f"Wrong keys: {set(result_dict.keys())}", runtime_ms
		
		for key in required_keys:
			if not isinstance(result_dict[key], list):
				return None, f"'{key}' must be list", runtime_ms
			if not all(isinstance(x, str) for x in result_dict[key]):
				return None, f"'{key}' contains non-strings", runtime_ms
		
		return result_dict, None, runtime_ms
	
	except subprocess.TimeoutExpired:
		return None, "Timeout (>10s)", (time.time() - start_time) * 1000
	except Exception as e:
		return None, str(e)[:200], (time.time() - start_time) * 1000


def compare_results(expected: Dict, actual: Dict) -> Tuple[bool, List[str]]:
	"""Compare expected vs actual with detailed diff"""
	mismatches = []
	all_match = True
	
	for category in ['brute_force', 'session_hijacking', 'credential_stuffing']:
		exp_set = set(expected[category])
		act_set = set(actual[category])
		
		if exp_set != act_set:
			all_match = False
			missing = exp_set - act_set
			extra = act_set - exp_set
			
			if missing:
				mismatches.append(f"    {category}: Missing {missing}")
			if extra:
				mismatches.append(f"    {category}: Extra {extra}")
	
	return all_match, mismatches


def find_test_logs_dir() -> Optional[Path]:
	"""Auto-discover test_logs directory"""
	# Check current directory
	current = Path.cwd() / 'test_logs'
	if current.exists() and current.is_dir():
		return current
	
	# Check same directory as grader script
	script_dir = Path(__file__).parent / 'test_logs'
	if script_dir.exists() and script_dir.is_dir():
		return script_dir
	
	# Check parent directory
	parent = Path.cwd().parent / 'test_logs'
	if parent.exists() and parent.is_dir():
		return parent
	
	return None


def categorize_file(file_num: int) -> str:
	"""Determine test category from file number"""
	if 1 <= file_num <= 20:
		return 'normal'
	elif 21 <= file_num <= 40:
		return 'brute_force'
	elif 41 <= file_num <= 60:
		return 'session_hijack'
	elif 61 <= file_num <= 80:
		return 'cred_stuffing'
	elif 81 <= file_num <= 95:
		return 'mixed'
	else:
		return 'edge_cases'


def print_summary(stats: Dict, total_runtime: float) -> None:
	"""Print colored summary statistics"""
	c = Colors
	
	print(f"\n{c.BOLD}{'='*70}{c.RESET}")
	print(f"{c.BOLD}Test Summary{c.RESET}")
	print(f"{c.BOLD}{'='*70}{c.RESET}\n")
	
	# Category breakdown
	print(f"{c.BOLD}Results by Category:{c.RESET}")
	for category, data in stats.items():
		passed = data['passed']
		total = data['total']
		if total == 0:
			continue
		pct = (passed / total * 100)
		
		color = c.GREEN if passed == total else (c.YELLOW if pct >= 80 else c.RED)
		print(f"  {category:20s}: {color}{passed:2d}/{total:2d}{c.RESET} ({pct:5.1f}%)")
	
	# Overall score
	total_passed = sum(d['passed'] for d in stats.values())
	total_tests = sum(d['total'] for d in stats.values())
	overall_pct = (total_passed / total_tests * 100) if total_tests > 0 else 0
	
	print(f"\n{c.BOLD}Overall Score:{c.RESET}")
	if total_passed == total_tests:
		print(f"  {c.GREEN}{c.BOLD}PERFECT: {total_passed}/{total_tests} (100%){c.RESET} ⭐⭐⭐")
	elif overall_pct >= 90:
		print(f"  {c.GREEN}EXCELLENT: {total_passed}/{total_tests} ({overall_pct:.1f}%){c.RESET} 🌟🌟")
	elif overall_pct >= 70:
		print(f"  {c.YELLOW}GOOD: {total_passed}/{total_tests} ({overall_pct:.1f}%){c.RESET} 🌟")
	else:
		print(f"  {c.RED}NEEDS WORK: {total_passed}/{total_tests} ({overall_pct:.1f}%){c.RESET} ⚠️")
	
	print(f"\n{c.BOLD}Performance:{c.RESET}")
	print(f"  Total time: {total_runtime:.1f}s")
	avg_time = (total_runtime / total_tests * 1000) if total_tests > 0 else 0
	print(f"  Average: {avg_time:.1f}ms per test")
	
	if avg_time > 100:
		print(f"  {c.YELLOW}⚠ Consider optimization (target: <100ms per test){c.RESET}")


def main():
	"""Main entry point"""
	c = Colors
	
	print(f"{c.BOLD}{c.BLUE}")
	print("VPN Log Analyzer Grader")
	print("=" * 70)
	print(f"{c.RESET}")
	
	# Check arguments
	if len(sys.argv) != 2:
		print(f"{c.RED}Usage:{c.RESET} python3 {sys.argv[0]} <student_solution.py>\n")
		print("Example:")
		print(f"  python3 {sys.argv[0]} vpn_log_analyzer.py\n")
		sys.exit(1)
	
	solution_path = Path(sys.argv[1])
	if not solution_path.exists():
		print(f"{c.RED}✗{c.RESET} Solution file not found: {solution_path}\n")
		sys.exit(1)
	
	# Find test logs directory
	test_logs_dir = find_test_logs_dir()
	if not test_logs_dir:
		print(f"{c.RED}✗{c.RESET} Could not find test_logs/ directory")
		print("\nSearched in:")
		print(f"  - {Path.cwd() / 'test_logs'}")
		print(f"  - {Path(__file__).parent / 'test_logs'}")
		print(f"  - {Path.cwd().parent / 'test_logs'}")
		print("\nPlease extract test files: tar -xzf vpn_test_logs.tar.gz\n")
		sys.exit(1)
	
	# Find test files
	test_files = sorted(test_logs_dir.glob("vpn_auth_*.log"))
	if not test_files:
		print(f"{c.RED}✗{c.RESET} No test files found in {test_logs_dir}\n")
		sys.exit(1)
	
	print(f"{c.GREEN}✓{c.RESET} Found {len(test_files)} test files in {test_logs_dir}")
	print(f"{c.GREEN}✓{c.RESET} Testing solution: {solution_path}\n")
	
	# Initialize statistics
	stats = {
		'normal': {'passed': 0, 'total': 0},
		'brute_force': {'passed': 0, 'total': 0},
		'session_hijack': {'passed': 0, 'total': 0},
		'cred_stuffing': {'passed': 0, 'total': 0},
		'mixed': {'passed': 0, 'total': 0},
		'edge_cases': {'passed': 0, 'total': 0}
	}
	
	failed_tests = []
	total_start = time.time()
	
	# Run tests
	print(f"{c.BOLD}Running Tests{c.RESET}")
	print("=" * 70)
	
	for test_file in test_files:
		filename = test_file.name
		file_num = int(filename.split('_')[2].split('.')[0])
		category = categorize_file(file_num)
		
		stats[category]['total'] += 1
		
		# Calculate expected result
		expected = calculate_expected_result(test_file)
		
		# Run student solution
		actual, error, runtime_ms = run_student_solution(solution_path, test_file)
		
		if error:
			print(f"{c.RED}✗{c.RESET} {filename:25s} - {error}")
			failed_tests.append((filename, error, None))
		else:
			match, mismatches = compare_results(expected, actual)
			
			if match:
				stats[category]['passed'] += 1
				print(f"{c.GREEN}✓{c.RESET} {filename:25s} ({runtime_ms:.1f}ms)")
			else:
				print(f"{c.RED}✗{c.RESET} {filename:25s} - Mismatches:")
				for mismatch in mismatches:
					print(f"  {mismatch}")
				failed_tests.append((filename, "Logic error", mismatches))
	
	total_runtime = time.time() - total_start
	
	# Print summary
	print_summary(stats, total_runtime)
	
	# Show first few failures in detail
	if failed_tests and len(failed_tests) <= 10:
		print(f"\n{c.BOLD}Failed Tests Detail:{c.RESET}")
		for filename, error, mismatches in failed_tests:
			print(f"\n  {c.RED}✗{c.RESET} {filename}")
			print(f"    {error}")
			if mismatches:
				for m in mismatches:
					print(f"    {m}")
	elif len(failed_tests) > 10:
		print(f"\n{c.BOLD}Failed Tests:{c.RESET}")
		print(f"  {len(failed_tests)} tests failed")
		print(f"  First 5 failures shown above")
	
	print(f"\n{c.BOLD}{'='*70}{c.RESET}\n")
	
	# Exit with status
	total_passed = sum(d['passed'] for d in stats.values())
	total_tests = sum(d['total'] for d in stats.values())
	sys.exit(0 if total_passed == total_tests else 1)


if __name__ == '__main__':
	main()
