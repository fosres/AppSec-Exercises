#!/usr/bin/env python3
"""
TLS Certificate Validator Grader
Grades student solutions against 67 test cases

Usage:
	python grade_validator.py path/to/student_solution.py
"""

import sys
import os
import importlib.util
from pathlib import Path

# Expected results for all 67 test cases
# Format: test_number: (should_pass, expected_failing_checks, description)
EXPECTED_RESULTS = {
	# Valid/Secure Certificates (should pass all 20 checks)
	1: (True, [], "Perfect certificate"),
	2: (True, [], "ECDSA P-256"),
	3: (True, [], "Wildcard *.example.com"),
	4: (True, [], "Multi-SAN (5 domains)"),
	5: (True, [], "350-day validity"),
	11: (True, [], "ECDSA P-384"),
	12: (True, [], "RSA-4096 with SHA-384"),
	16: (True, [], "CN mismatch but SAN matches"),
	18: (True, [], "IP address in SAN"),
	20: (True, [], "Subdomain wildcard"),
	29: (True, [], "Multiple EKU (Server + Client)"),
	41: (True, [], "RSA-2048 minimum"),
	42: (True, [], "7-day validity"),
	43: (True, [], "398-day validity maximum"),
	44: (True, [], "SHA-512 signature"),
	45: (True, [], "Single SAN only"),
	46: (True, [], "10 SANs"),
	47: (True, [], "Mixed wildcard + specific"),
	48: (True, [], "Very long organization name"),
	49: (True, [], "Minimal valid certificate"),
	65: (True, [], "BEST PRACTICE: RSA-3072, 90 days"),
	66: (True, [], "BEST PRACTICE: ECDSA P-384"),
	67: (True, [], "BEST PRACTICE: 30-day validity"),
	
	# Invalid Certificates (should fail specific checks)
	6: (False, [2], "Expired certificate"),
	7: (False, [2], "Not yet valid"),
	8: (False, [20], "400-day validity (>398)"),
	9: (False, [20], "5-year validity"),
	10: (False, [2], "Expires in 1 hour"),
	13: (False, [7], "Hostname mismatch"),
	14: (False, [6], "Missing SANs"),
	15: (False, [7], "Wildcard mismatch"),
	17: (False, [5], "Empty Subject DN"),
	19: (False, [7], "Wildcard on root domain"),
	21: (False, [8], "CA:TRUE catastrophic"),
	22: (False, [8], "Missing Basic Constraints"),
	23: (False, [8], "Basic Constraints not critical"),
	24: (False, [9], "Missing Key Usage"),
	25: (False, [9], "Key Usage not critical"),
	26: (False, [9], "Has Certificate Sign"),
	27: (False, [10], "Missing Extended Key Usage"),
	28: (False, [10], "Wrong EKU (Code Signing)"),
	30: (False, [9], "Has CRL Sign"),
	31: (False, [11], "Missing CRL Distribution Points"),
	32: (False, [13], "Missing OCSP URL"),
	33: (False, [11, 13], "Missing CRL and OCSP"),
	34: (False, [12, 13], "Missing AIA"),
	35: (False, [11], "CRL over HTTPS"),
	36: (False, [13], "OCSP over HTTPS"),
	37: (False, [15], "Self-signed"),
	38: (False, [17], "Missing SKI"),
	39: (False, [18], "Missing AKI"),
	40: (False, [16], "Sequential serial number"),
	50: (False, [2], "Expires in 1 day"),
	51: (False, [3], "SHA-1 signature"),
	52: (False, [3], "MD5 signature"),
	53: (False, [4], "RSA-1024 weak"),
	54: (False, [4], "RSA-512 broken"),
	55: (False, [9], "Missing Key Encipherment"),
	56: (False, [9], "Has Data Encipherment"),
	57: (False, [9], "Has Content Commitment"),
	58: (False, [9], "Missing Digital Signature"),
	59: (False, [10], "Client Auth instead of Server"),
	60: (False, [10], "Email Protection EKU"),
	61: (False, [6], "SANs marked critical"),
	62: (False, [6], "Very long hostname"),
	63: (False, [8], "CA:TRUE with path_length=0"),
	64: (False, [13], "Only CRL, no OCSP"),
}

DEFAULT_HOSTNAME = "www.example.com"

def load_student_solution(solution_path):
	"""Dynamically load student's solution module"""
	if not os.path.exists(solution_path):
		print(f"❌ Error: File not found: {solution_path}")
		sys.exit(1)
	
	spec = importlib.util.spec_from_file_location("student_solution", solution_path)
	if spec is None or spec.loader is None:
		print(f"❌ Error: Could not load {solution_path}")
		sys.exit(1)
	
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	
	return module

def find_test_certs_directory():
	"""Find the test_certs_text directory"""
	# Try current directory
	if os.path.exists("test_certs_text"):
		return "test_certs_text"
	
	# Try parent directory
	if os.path.exists("../test_certs_text"):
		return "../test_certs_text"
	
	# Try looking for extracted archive
	for root, dirs, files in os.walk("."):
		if "test_certs_text" in dirs:
			return os.path.join(root, "test_certs_text")
	
	print("❌ Error: Could not find test_certs_text directory")
	print("   Please extract TLS_Certificate_Test_Suite_TEXT_ONLY.tar.gz first")
	sys.exit(1)

def grade_solution(solution_path):
	"""Grade the student's validator solution"""
	print("=" * 80)
	print("TLS CERTIFICATE VALIDATOR GRADER")
	print("=" * 80)
	print()
	
	# Load student solution
	print(f"Loading solution: {solution_path}")
	student_module = load_student_solution(solution_path)
	
	# Check if validate_tls_certificate function exists
	if not hasattr(student_module, 'validate_tls_certificate'):
		print("❌ Error: Solution must define validate_tls_certificate(text_file, hostname)")
		sys.exit(1)
	
	validate_func = student_module.validate_tls_certificate
	print("✅ Found validate_tls_certificate function")
	print()
	
	# Find test certificates
	test_dir = find_test_certs_directory()
	print(f"Using test certificates from: {test_dir}")
	print()
	
	# Grade each test case
	results = {
		'passed': 0,
		'failed': 0,
		'errors': 0,
		'details': []
	}
	
	print("=" * 80)
	print("GRADING IN PROGRESS...")
	print("=" * 80)
	print()
	
	for test_num, (should_pass, expected_fails, description) in sorted(EXPECTED_RESULTS.items()):
		test_file = f"{test_dir}/test_{test_num:03d}_*.txt"
		
		# Find the actual test file
		import glob
		matches = glob.glob(test_file)
		if not matches:
			print(f"⚠️  Test {test_num:03d}: File not found")
			results['errors'] += 1
			continue
		
		test_file = matches[0]
		
		try:
			# Call student's validator
			result = validate_func(test_file, DEFAULT_HOSTNAME)
			
			# Check if result is a dict with 'valid' key
			if not isinstance(result, dict) or 'valid' not in result:
				print(f"❌ Test {test_num:03d}: Invalid return format (must return dict with 'valid' key)")
				results['failed'] += 1
				results['details'].append({
					'test': test_num,
					'description': description,
					'status': 'FAIL',
					'reason': 'Invalid return format'
				})
				continue
			
			student_valid = result['valid']
			
			# Check if result matches expected
			if student_valid == should_pass:
				print(f"✅ Test {test_num:03d}: PASS - {description}")
				results['passed'] += 1
				results['details'].append({
					'test': test_num,
					'description': description,
					'status': 'PASS',
					'reason': None
				})
			else:
				expected_str = "valid" if should_pass else "invalid"
				got_str = "valid" if student_valid else "invalid"
				print(f"❌ Test {test_num:03d}: FAIL - {description}")
				print(f"   Expected: {expected_str}, Got: {got_str}")
				results['failed'] += 1
				results['details'].append({
					'test': test_num,
					'description': description,
					'status': 'FAIL',
					'reason': f"Expected {expected_str}, got {got_str}"
				})
		
		except Exception as e:
			print(f"💥 Test {test_num:03d}: ERROR - {description}")
			print(f"   Exception: {str(e)}")
			results['errors'] += 1
			results['details'].append({
				'test': test_num,
				'description': description,
				'status': 'ERROR',
				'reason': str(e)
			})
	
	# Print final report
	print()
	print("=" * 80)
	print("GRADING COMPLETE")
	print("=" * 80)
	print()
	
	total_tests = results['passed'] + results['failed'] + results['errors']
	percentage = (results['passed'] / total_tests * 100) if total_tests > 0 else 0
	
	print(f"Total Tests:  {total_tests}")
	print(f"Passed:       {results['passed']} ✅")
	print(f"Failed:       {results['failed']} ❌")
	print(f"Errors:       {results['errors']} 💥")
	print()
	print(f"Score:        {results['passed']}/{total_tests} ({percentage:.1f}%)")
	print()
	
	# Grade assignment
	if percentage >= 95:
		grade = "A+ (Excellent!)"
	elif percentage >= 90:
		grade = "A (Great work!)"
	elif percentage >= 85:
		grade = "B+ (Good!)"
	elif percentage >= 80:
		grade = "B (Solid)"
	elif percentage >= 75:
		grade = "C+ (Needs improvement)"
	elif percentage >= 70:
		grade = "C (Keep working)"
	else:
		grade = "F (More work needed)"
	
	print(f"Grade:        {grade}")
	print()
	
	# Show failed tests
	if results['failed'] > 0:
		print("=" * 80)
		print("FAILED TESTS (Review these)")
		print("=" * 80)
		print()
		for detail in results['details']:
			if detail['status'] == 'FAIL':
				print(f"Test {detail['test']:03d}: {detail['description']}")
				print(f"  Reason: {detail['reason']}")
				print()
	
	# Show errors
	if results['errors'] > 0:
		print("=" * 80)
		print("ERRORS (Fix these)")
		print("=" * 80)
		print()
		for detail in results['details']:
			if detail['status'] == 'ERROR':
				print(f"Test {detail['test']:03d}: {detail['description']}")
				print(f"  Error: {detail['reason']}")
				print()
	
	return results

def main():
	if len(sys.argv) != 2:
		print("Usage: python grade_validator.py path/to/student_solution.py")
		print()
		print("Example:")
		print("  python grade_validator.py my_validator.py")
		sys.exit(1)
	
	solution_path = sys.argv[1]
	results = grade_solution(solution_path)
	
	# Exit code based on results
	if results['passed'] == (results['passed'] + results['failed'] + results['errors']):
		sys.exit(0)  # All passed
	else:
		sys.exit(1)  # Some failed

if __name__ == "__main__":
	main()
