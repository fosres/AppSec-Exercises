#!/usr/bin/env python3
"""
TLS Certificate Validator Grader (Improved Version)
Grades based on Validation Summary output format

Output format expected:
	CHECK N: ... - PASS/FAIL
	...
	The following CHECKS FAILED and are REQUIRED:[list]
	The following CHECKS FAILED and are OPTIONAL:[list]

Usage: python3 grader_v2.py <path_to_validator> <test_directory>
"""

import sys
import os
import subprocess
import re
from pathlib import Path
from collections import defaultdict
import json

class Colors:
	"""ANSI color codes for terminal output"""
	GREEN = '\033[92m'
	RED = '\033[91m'
	YELLOW = '\033[93m'
	BLUE = '\033[94m'
	MAGENTA = '\033[95m'
	CYAN = '\033[96m'
	BOLD = '\033[1m'
	END = '\033[0m'

class TestResult:
	"""Stores results for a single test case"""
	def __init__(self, test_num, test_name, hostname, expected):
		self.test_num = test_num
		self.test_name = test_name
		self.hostname = hostname
		self.expected = expected
		self.output = ""
		self.error = ""
		self.passed = False
		
		# Parsed from validation summary
		self.required_failures = []
		self.optional_failures = []
		
		# Individual check results
		self.checks_passed = []
		self.checks_failed = []
		self.warnings = []
		
		self.score = 0
		self.detailed_feedback = []

def extract_test_metadata(test_file):
	"""
	Extract test number, hostname, and expected results from test file header.
	
	Format:
		# Test N: Description
		# Expected: PASS/FAIL/WARNING - Check X
		# Hostname: domain.com
	"""
	with open(test_file, 'r') as f:
		lines = f.readlines()
	
	test_num = None
	test_name = ""
	hostname = "www.example.com"  # Default
	expected = {}
	
	for line in lines[:10]:  # Check first 10 lines for metadata
		line = line.strip()
		
		# Extract test number and name
		if line.startswith("# Test "):
			match = re.search(r'# Test (\d+): (.+)', line)
			if match:
				test_num = int(match.group(1))
				test_name = match.group(2)
		
		# Extract hostname
		if line.startswith("# Hostname:"):
			hostname = line.split(":", 1)[1].strip()
		
		# Extract expected results
		if line.startswith("# Expected:"):
			expected_str = line.split(":", 1)[1].strip()
			expected = parse_expected_results(expected_str)
	
	return test_num, test_name, hostname, expected

def parse_expected_results(expected_str):
	"""
	Parse expected results string.
	
	Examples:
		"PASS (20/20 or close)"
		"FAIL - Check 7"
		"WARNING - Check 17"
		"FAIL - Checks 2, 4, 15"
	"""
	expected = {
		'overall': 'UNKNOWN',
		'failing_checks': [],
		'warning_checks': [],
		'notes': ''
	}
	
	# Determine overall status
	if 'PASS' in expected_str.upper():
		expected['overall'] = 'PASS'
	elif 'FAIL' in expected_str.upper():
		expected['overall'] = 'FAIL'
	elif 'WARNING' in expected_str.upper():
		expected['overall'] = 'WARNING'
	
	# Extract check numbers
	check_pattern = r'Check[s]?\s+(\d+(?:\s*,\s*\d+)*)'
	match = re.search(check_pattern, expected_str, re.IGNORECASE)
	if match:
		check_str = match.group(1)
		checks = [int(x.strip()) for x in check_str.split(',')]
		
		if 'FAIL' in expected_str.upper():
			expected['failing_checks'] = checks
		elif 'WARNING' in expected_str.upper():
			expected['warning_checks'] = checks
	
	# Store full notes
	expected['notes'] = expected_str
	
	return expected

def run_validator(validator_path, test_file, hostname):
	"""
	Run the validator on a test file and capture output.
	
	Returns: (stdout, stderr, returncode)
	"""
	try:
		result = subprocess.run(
			[sys.executable, validator_path, hostname, test_file],
			capture_output=True,
			text=True,
			timeout=10
		)
		return result.stdout, result.stderr, result.returncode
	except subprocess.TimeoutExpired:
		return "", "TIMEOUT: Validator took >10 seconds", -1
	except Exception as e:
		return "", f"ERROR: {str(e)}", -1

def parse_validation_summary(output):
	"""
	Parse the validation summary to extract failed checks.
	
	Expected format:
		The following CHECKS FAILED and are REQUIRED:[14, 15, 19]
		The following CHECKS FAILED and are OPTIONAL:[17]
	
	Returns: (required_failures, optional_failures)
	"""
	required_failures = []
	optional_failures = []
	
	# Parse REQUIRED failures
	required_pattern = r'CHECKS FAILED and are REQUIRED:\s*\[([^\]]*)\]'
	required_match = re.search(required_pattern, output)
	if required_match:
		checks_str = required_match.group(1).strip()
		if checks_str:
			required_failures = [int(x.strip()) for x in checks_str.split(',')]
	
	# Parse OPTIONAL failures
	optional_pattern = r'CHECKS FAILED and are OPTIONAL:\s*\[([^\]]*)\]'
	optional_match = re.search(optional_pattern, output)
	if optional_match:
		checks_str = optional_match.group(1).strip()
		if checks_str:
			optional_failures = [int(x.strip()) for x in checks_str.split(',')]
	
	return required_failures, optional_failures

def parse_individual_checks(output):
	"""
	Parse individual CHECK lines to see detailed results.
	
	Pattern: CHECK N: ... - PASS/FAIL/WARNING
	
	Returns: dict with check numbers as keys and 'PASS'/'FAIL'/'WARNING' as values
	"""
	results = {}
	
	pattern = r'CHECK\s+(\d+):\s+.*?\s+-\s+(PASS|FAIL|WARNING)'
	
	for match in re.finditer(pattern, output, re.IGNORECASE):
		check_num = int(match.group(1))
		status = match.group(2).upper()
		results[check_num] = status
	
	return results

def grade_test(validator_path, test_file):
	"""
	Grade a single test case based on validation summary.
	
	Returns: TestResult object
	"""
	# Extract metadata
	test_num, test_name, hostname, expected = extract_test_metadata(test_file)
	
	if test_num is None:
		print(f"{Colors.RED}ERROR: Could not parse test file: {test_file}{Colors.END}")
		return None
	
	result = TestResult(test_num, test_name, hostname, expected)
	
	# Run validator
	stdout, stderr, returncode = run_validator(validator_path, test_file, hostname)
	result.output = stdout
	result.error = stderr
	
	# Handle errors
	if stderr and "TIMEOUT" in stderr:
		result.passed = False
		result.detailed_feedback.append("Validator timed out (>10 seconds)")
		return result
	
	if stderr and "ERROR" in stderr:
		result.passed = False
		result.detailed_feedback.append(f"Validator error: {stderr}")
		return result
	
	# Parse validation summary
	required_failures, optional_failures = parse_validation_summary(stdout)
	result.required_failures = required_failures
	result.optional_failures = optional_failures
	
	# Parse individual checks for detailed analysis
	check_results = parse_individual_checks(stdout)
	
	for check_num, status in check_results.items():
		if status == 'PASS':
			result.checks_passed.append(check_num)
		elif status == 'FAIL':
			result.checks_failed.append(check_num)
		elif status == 'WARNING':
			result.warnings.append(check_num)
	
	# Grade based on validation summary
	result.passed, result.score, feedback = grade_against_expected(
		result, expected, required_failures, optional_failures, check_results
	)
	result.detailed_feedback = feedback
	
	return result

def grade_against_expected(result, expected, required_failures, optional_failures, check_results):
	"""
	Determine if test passed based on validation summary.
	
	Grading criteria:
	1. Did validator correctly identify which checks failed?
	2. Did validator correctly categorize failures as REQUIRED vs OPTIONAL?
	3. Did validator miss any expected failures?
	4. Did validator report false positives?
	
	Returns: (passed, score, feedback_list)
	"""
	feedback = []
	score = 0
	
	overall_expected = expected['overall']
	failing_checks_expected = set(expected['failing_checks'])
	warning_checks_expected = set(expected['warning_checks'])
	
	# All failures reported by validator
	all_failures = set(required_failures + optional_failures)
	
	# For PASS tests: Should have no (or very few) failures
	if overall_expected == 'PASS':
		if len(all_failures) == 0:
			score = 100
			feedback.append("✅ Correctly identified as passing (no failures)")
			passed = True
		elif len(all_failures) <= 2:
			score = 85
			feedback.append(f"⚠️ Mostly correct, but flagged {len(all_failures)} false positives: {sorted(all_failures)}")
			passed = True
		else:
			score = max(0, 70 - len(all_failures) * 5)
			feedback.append(f"❌ Too many false positives: {sorted(all_failures)}")
			passed = False
		
		return passed, score, feedback
	
	# For FAIL tests: Should catch the expected failures
	if overall_expected == 'FAIL':
		if not failing_checks_expected:
			# General failure test - should have at least one failure
			if len(all_failures) > 0:
				score = 90
				feedback.append(f"✅ Correctly identified failures: {sorted(all_failures)}")
				passed = True
			else:
				score = 0
				feedback.append("❌ Failed to detect any problems")
				passed = False
		else:
			# Specific checks should fail
			caught = failing_checks_expected & all_failures
			missed = failing_checks_expected - all_failures
			extra = all_failures - failing_checks_expected
			
			# Base score: catching expected failures (70 points)
			if caught:
				catch_score = int(70 * (len(caught) / len(failing_checks_expected)))
				score += catch_score
				feedback.append(f"✅ Caught {len(caught)}/{len(failing_checks_expected)} expected failures: {sorted(caught)}")
			else:
				feedback.append(f"❌ Missed all expected failures: {sorted(failing_checks_expected)}")
			
			# Penalty for missed failures (up to -20)
			if missed:
				miss_penalty = min(20, len(missed) * 10)
				score -= miss_penalty
				feedback.append(f"❌ Missed {len(missed)} expected failure(s): {sorted(missed)}")
			
			# Penalty for false positives (up to -10)
			if extra:
				extra_penalty = min(10, len(extra) * 5)
				score -= extra_penalty
				feedback.append(f"⚠️ {len(extra)} unexpected failure(s): {sorted(extra)}")
			
			# Bonus for correct categorization (REQUIRED vs OPTIONAL) (+20)
			categorization_score = grade_categorization(
				required_failures, optional_failures, 
				failing_checks_expected, warning_checks_expected
			)
			score += categorization_score
			
			if categorization_score > 15:
				feedback.append(f"✅ Good categorization (REQUIRED vs OPTIONAL)")
			elif categorization_score > 0:
				feedback.append(f"⚠️ Partial categorization accuracy")
			else:
				feedback.append(f"❌ Poor categorization (REQUIRED vs OPTIONAL)")
			
			# Ensure score is in valid range
			score = max(0, min(100, score))
			
			# Pass if caught at least one expected failure and score >= 60
			passed = (len(caught) > 0 and score >= 60)
	
	# For WARNING tests: Should flag the expected warnings
	elif overall_expected == 'WARNING':
		if not warning_checks_expected:
			# General warning test
			if len(optional_failures) > 0:
				score = 90
				feedback.append(f"✅ Correctly identified warnings: {sorted(optional_failures)}")
				passed = True
			else:
				score = 50
				feedback.append("⚠️ No warnings reported")
				passed = False
		else:
			# Specific warnings expected
			warned = warning_checks_expected & set(optional_failures)
			
			if warned:
				score = int(100 * (len(warned) / len(warning_checks_expected)))
				feedback.append(f"✅ Caught {len(warned)}/{len(warning_checks_expected)} expected warnings")
				passed = True
			else:
				score = 30
				feedback.append(f"❌ Missed expected warnings: {sorted(warning_checks_expected)}")
				passed = False
	else:
		# Unknown expected result
		score = 50
		feedback.append("⚠️ Unknown expected result type")
		passed = False
	
	return passed, score, feedback

def grade_categorization(required_failures, optional_failures, 
						 expected_required, expected_optional):
	"""
	Grade how well the validator categorized failures as REQUIRED vs OPTIONAL.
	
	Returns: score (0-20 points)
	"""
	score = 0
	
	required_set = set(required_failures)
	optional_set = set(optional_failures)
	
	# Check if required failures are correctly categorized
	# (They should be in required_failures, not optional_failures)
	correctly_required = expected_required & required_set
	incorrectly_optional = expected_required & optional_set
	
	# Check if optional failures are correctly categorized
	correctly_optional = expected_optional & optional_set
	incorrectly_required = expected_optional & required_set
	
	total_to_categorize = len(expected_required) + len(expected_optional)
	
	if total_to_categorize == 0:
		# No categorization needed
		return 0
	
	correct_categorizations = len(correctly_required) + len(correctly_optional)
	incorrect_categorizations = len(incorrectly_optional) + len(incorrectly_required)
	
	# Score based on categorization accuracy
	if total_to_categorize > 0:
		accuracy = correct_categorizations / total_to_categorize
		score = int(20 * accuracy)
	
	return score

def print_test_result(result, verbose=False):
	"""Print results for a single test"""
	# Status indicator
	if result.passed:
		status = f"{Colors.GREEN}✓ PASS{Colors.END}"
	else:
		status = f"{Colors.RED}✗ FAIL{Colors.END}"
	
	# Test header
	print(f"\n{Colors.BOLD}Test {result.test_num:03d}: {result.test_name}{Colors.END}")
	print(f"  Status: {status} (Score: {result.score}/100)")
	print(f"  Hostname: {result.hostname}")
	
	if result.expected['notes']:
		print(f"  Expected: {result.expected['notes']}")
	
	# Validation Summary
	print(f"\n  {Colors.BOLD}Validation Summary:{Colors.END}")
	if result.required_failures:
		print(f"    REQUIRED failures: {sorted(result.required_failures)}")
	else:
		print(f"    REQUIRED failures: None")
	
	if result.optional_failures:
		print(f"    OPTIONAL failures: {sorted(result.optional_failures)}")
	else:
		print(f"    OPTIONAL failures: None")
	
	# Detailed feedback
	if result.detailed_feedback:
		print(f"\n  {Colors.BOLD}Feedback:{Colors.END}")
		for feedback_item in result.detailed_feedback:
			print(f"    {feedback_item}")
	
	# Show errors
	if result.error:
		print(f"  {Colors.RED}Error: {result.error}{Colors.END}")
	
	# Verbose output
	if verbose and result.output:
		print(f"\n{Colors.CYAN}--- Full Output ---{Colors.END}")
		print(result.output)
		print(f"{Colors.CYAN}--- End Output ---{Colors.END}")

def print_summary(results):
	"""Print overall summary statistics"""
	print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
	print(f"{Colors.BOLD}GRADING SUMMARY{Colors.END}")
	print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")
	
	# Overall statistics
	total_tests = len(results)
	passed_tests = sum(1 for r in results if r.passed)
	failed_tests = total_tests - passed_tests
	
	avg_score = sum(r.score for r in results) / total_tests if total_tests > 0 else 0
	
	print(f"Total Tests: {total_tests}")
	print(f"{Colors.GREEN}Passed: {passed_tests} ({100*passed_tests/total_tests:.1f}%){Colors.END}")
	print(f"{Colors.RED}Failed: {failed_tests} ({100*failed_tests/total_tests:.1f}%){Colors.END}")
	print(f"Average Score: {avg_score:.1f}/100")
	
	# Categorization accuracy
	print(f"\n{Colors.BOLD}Categorization Accuracy (REQUIRED vs OPTIONAL):{Colors.END}")
	
	categorization_correct = 0
	categorization_total = 0
	
	for result in results:
		if result.expected['failing_checks'] or result.expected['warning_checks']:
			expected_req = set(result.expected['failing_checks'])
			expected_opt = set(result.expected['warning_checks'])
			actual_req = set(result.required_failures)
			actual_opt = set(result.optional_failures)
			
			correct = len(expected_req & actual_req) + len(expected_opt & actual_opt)
			total = len(expected_req) + len(expected_opt)
			
			if total > 0:
				categorization_correct += correct
				categorization_total += total
	
	if categorization_total > 0:
		cat_accuracy = 100 * categorization_correct / categorization_total
		print(f"  {cat_accuracy:.1f}% correct ({categorization_correct}/{categorization_total} checks)")
	else:
		print(f"  N/A (no categorization tests)")
	
	# Check-level statistics
	all_required_failures = []
	all_optional_failures = []
	
	for result in results:
		all_required_failures.extend(result.required_failures)
		all_optional_failures.extend(result.optional_failures)
	
	# Count frequency of each check failing
	required_counts = defaultdict(int)
	optional_counts = defaultdict(int)
	
	for check in all_required_failures:
		required_counts[check] += 1
	
	for check in all_optional_failures:
		optional_counts[check] += 1
	
	print(f"\n{Colors.BOLD}Most Commonly Failing Checks:{Colors.END}")
	print(f"{'Check':<10} {'Required':<12} {'Optional':<12} {'Total':<10}")
	print("-" * 50)
	
	all_checks = sorted(set(list(required_counts.keys()) + list(optional_counts.keys())))
	
	for check in all_checks[:10]:  # Top 10
		req_count = required_counts.get(check, 0)
		opt_count = optional_counts.get(check, 0)
		total_count = req_count + opt_count
		print(f"CHECK {check:<3}  {req_count:<12} {opt_count:<12} {total_count:<10}")
	
	# Score distribution
	print(f"\n{Colors.BOLD}Score Distribution:{Colors.END}")
	score_ranges = {
		'90-100': 0,
		'80-89': 0,
		'70-79': 0,
		'60-69': 0,
		'0-59': 0
	}
	
	for result in results:
		if result.score >= 90:
			score_ranges['90-100'] += 1
		elif result.score >= 80:
			score_ranges['80-89'] += 1
		elif result.score >= 70:
			score_ranges['70-79'] += 1
		elif result.score >= 60:
			score_ranges['60-69'] += 1
		else:
			score_ranges['0-59'] += 1
	
	for range_name, count in score_ranges.items():
		pct = 100 * count / total_tests if total_tests > 0 else 0
		bar = '█' * int(pct / 2)
		print(f"  {range_name}: {count:3d} tests ({pct:5.1f}%) {bar}")
	
	# Final grade
	print(f"\n{Colors.BOLD}FINAL GRADE:{Colors.END}")
	if avg_score >= 90:
		grade = 'A'
		color = Colors.GREEN
	elif avg_score >= 80:
		grade = 'B'
		color = Colors.CYAN
	elif avg_score >= 70:
		grade = 'C'
		color = Colors.YELLOW
	elif avg_score >= 60:
		grade = 'D'
		color = Colors.YELLOW
	else:
		grade = 'F'
		color = Colors.RED
	
	print(f"{color}{Colors.BOLD}{grade} ({avg_score:.1f}/100){Colors.END}")
	print(f"\n{Colors.BOLD}{'='*80}{Colors.END}\n")

def save_report(results, output_file):
	"""Save detailed JSON report"""
	report = {
		'total_tests': len(results),
		'passed_tests': sum(1 for r in results if r.passed),
		'average_score': sum(r.score for r in results) / len(results) if results else 0,
		'tests': []
	}
	
	for result in results:
		test_data = {
			'test_num': result.test_num,
			'test_name': result.test_name,
			'hostname': result.hostname,
			'expected': result.expected,
			'passed': result.passed,
			'score': result.score,
			'required_failures': result.required_failures,
			'optional_failures': result.optional_failures,
			'checks_passed': result.checks_passed,
			'checks_failed': result.checks_failed,
			'warnings': result.warnings,
			'feedback': result.detailed_feedback,
			'error': result.error
		}
		report['tests'].append(test_data)
	
	with open(output_file, 'w') as f:
		json.dump(report, f, indent=2)
	
	print(f"Detailed report saved to: {output_file}")

def main():
	"""Main grader function"""
	print(f"{Colors.BOLD}{Colors.CYAN}")
	print("=" * 80)
	print("TLS Certificate Validator - Automated Grader v2.0")
	print("(Grades based on Validation Summary)")
	print("=" * 80)
	print(f"{Colors.END}\n")
	
	# Parse arguments
	if len(sys.argv) < 3:
		print("Usage: python3 grader_v2.py <validator_script> <test_directory>")
		print("\nExample:")
		print("  python3 grader_v2.py tls_cert_validator.py test_certs_text/")
		sys.exit(1)
	
	validator_path = sys.argv[1]
	test_dir = sys.argv[2]
	
	verbose = '--verbose' in sys.argv or '-v' in sys.argv
	save_json = '--json' in sys.argv
	
	# Validate inputs
	if not os.path.isfile(validator_path):
		print(f"{Colors.RED}ERROR: Validator not found: {validator_path}{Colors.END}")
		sys.exit(1)
	
	if not os.path.isdir(test_dir):
		print(f"{Colors.RED}ERROR: Test directory not found: {test_dir}{Colors.END}")
		sys.exit(1)
	
	# Find all test files
	test_files = sorted(Path(test_dir).glob("test_*.txt"))
	# Exclude swap files
	test_files = [f for f in test_files if not f.name.startswith('.')]
	
	if not test_files:
		print(f"{Colors.RED}ERROR: No test files found in {test_dir}{Colors.END}")
		sys.exit(1)
	
	print(f"Validator: {validator_path}")
	print(f"Test Directory: {test_dir}")
	print(f"Test Files: {len(test_files)}")
	print(f"Verbose: {verbose}")
	print()
	
	# Grade all tests
	results = []
	
	print(f"{Colors.BOLD}Running tests...{Colors.END}\n")
	
	for i, test_file in enumerate(test_files, 1):
		print(f"[{i}/{len(test_files)}] Testing: {test_file.name}...", end=' ')
		sys.stdout.flush()
		
		result = grade_test(validator_path, str(test_file))
		
		if result:
			results.append(result)
			if result.passed:
				print(f"{Colors.GREEN}✓{Colors.END} ({result.score}/100)")
			else:
				print(f"{Colors.RED}✗{Colors.END} ({result.score}/100)")
		else:
			print(f"{Colors.RED}ERROR{Colors.END}")
	
	# Print individual results if verbose
	if verbose:
		print(f"\n{Colors.BOLD}Individual Test Results:{Colors.END}")
		for result in results:
			print_test_result(result, verbose=True)
	
	# Print summary
	print_summary(results)
	
	# Save JSON report if requested
	if save_json:
		output_file = "grader_report_v2.json"
		save_report(results, output_file)

if __name__ == "__main__":
	main()
