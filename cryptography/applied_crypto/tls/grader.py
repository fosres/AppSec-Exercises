#!/usr/bin/env python3
"""
TLS Certificate Validator Grader
Compares student solution against reference solution.

Usage: python3 grader.py student_solution.py
"""

import sys
import os
import importlib.util
from pathlib import Path
import contextlib
import io

def load_module(filepath):
	"""Load Python module from filepath."""
	spec = importlib.util.spec_from_file_location("module", filepath)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module

def run_validator(module, cert_file, hostname):
	"""Run validator and capture return values."""
	try:
		# Suppress print statements
		with contextlib.redirect_stdout(io.StringIO()):
			fail_list, optional_list = module.validate_tls_certificate(cert_file, hostname)
		return (sorted(fail_list), sorted(optional_list))
	except Exception as e:
		return (None, None)

def main():
	if len(sys.argv) != 2:
		print("Usage: python3 grader.py <student_solution.py>")
		print()
		print("Example:")
		print("  python3 grader.py my_validator.py")
		sys.exit(1)
	
	student_file = sys.argv[1]
	reference_file = "tls_cert_validator.py"
	test_dir = "test_certs_text"
	hostname = "www.example.com"
	
	# Validate files exist
	if not os.path.exists(student_file):
		print(f"✗ Student solution not found: {student_file}")
		sys.exit(1)
	
	if not os.path.exists(reference_file):
		print(f"✗ Reference solution not found: {reference_file}")
		print(f"  Place tls_cert_validator.py in current directory")
		sys.exit(1)
	
	if not os.path.exists(test_dir):
		print(f"✗ Test directory not found: {test_dir}/")
		sys.exit(1)
	
	# Load modules
	print("="*70)
	print("TLS CERTIFICATE VALIDATOR GRADER")
	print("="*70)
	print()
	
	try:
		print(f"Loading reference: {reference_file}")
		reference = load_module(reference_file)
		print("✓ Reference loaded")
	except Exception as e:
		print(f"✗ Failed to load reference: {e}")
		sys.exit(1)
	
	try:
		print(f"Loading student:   {student_file}")
		student = load_module(student_file)
		print("✓ Student loaded")
	except Exception as e:
		print(f"✗ Failed to load student solution: {e}")
		sys.exit(1)
	
	# Get test files
	test_files = sorted(Path(test_dir).glob("test_*.txt"))
	if not test_files:
		print(f"✗ No test files found in {test_dir}/")
		sys.exit(1)
	
	print(f"\nFound {len(test_files)} test certificates")
	print("="*70)
	print()
	
	# Run tests
	perfect = 0
	partial = 0
	failed = 0
	errors = 0
	
	results = []
	
	for test_file in test_files:
		test_name = test_file.name
		
		# Run reference
		ref_fail, ref_opt = run_validator(reference, str(test_file), hostname)
		
		# Run student
		stu_fail, stu_opt = run_validator(student, str(test_file), hostname)
		
		# Check for errors
		if ref_fail is None or stu_fail is None:
			results.append({
				'name': test_name,
				'status': 'ERROR',
				'ref_fail': ref_fail,
				'ref_opt': ref_opt,
				'stu_fail': stu_fail,
				'stu_opt': stu_opt
			})
			errors += 1
			continue
		
		# Compare
		fail_match = (ref_fail == stu_fail)
		opt_match = (ref_opt == stu_opt)
		
		if fail_match and opt_match:
			status = 'PERFECT'
			perfect += 1
		elif fail_match or opt_match:
			status = 'PARTIAL'
			partial += 1
		else:
			status = 'FAIL'
			failed += 1
		
		results.append({
			'name': test_name,
			'status': status,
			'fail_match': fail_match,
			'opt_match': opt_match,
			'ref_fail': ref_fail,
			'ref_opt': ref_opt,
			'stu_fail': stu_fail,
			'stu_opt': stu_opt
		})
	
	# Print results table
	print(f"{'Test':<42} {'Status':<10} {'Required':<10} {'Optional':<10}")
	print("-"*70)
	
	for r in results:
		if r['status'] == 'ERROR':
			print(f"{r['name']:<42} ERROR      N/A        N/A")
			continue
		
		fail_icon = '✓' if r['fail_match'] else '✗'
		opt_icon = '✓' if r['opt_match'] else '✗'
		
		# Color codes
		if r['status'] == 'PERFECT':
			color = '\033[92m'  # Green
		elif r['status'] == 'PARTIAL':
			color = '\033[93m'  # Yellow
		else:
			color = '\033[91m'  # Red
		reset = '\033[0m'
		
		print(f"{r['name']:<42} {color}{r['status']:<10}{reset} {fail_icon:<10} {opt_icon:<10}")
	
	# Print summary
	total = len(results) - errors
	print()
	print("="*70)
	print("SUMMARY")
	print("="*70)
	print()
	print(f"Total Tests:      {total}")
	print(f"Perfect Matches:  {perfect} ({perfect/total*100:.1f}%)")
	print(f"Partial Matches:  {partial} ({partial/total*100:.1f}%)")
	print(f"Failed:           {failed} ({failed/total*100:.1f}%)")
	if errors > 0:
		print(f"Errors:           {errors}")
	print()
	
	# Calculate grade
	score = (perfect * 100 + partial * 50) / total if total > 0 else 0
	
	if score >= 90:
		grade = "A"
	elif score >= 80:
		grade = "B"
	elif score >= 70:
		grade = "C"
	elif score >= 60:
		grade = "D"
	else:
		grade = "F"
	
	print(f"SCORE: {score:.1f}/100")
	print(f"GRADE: {grade}")
	print()
	
	# Show mismatches
	mismatches = [r for r in results if r['status'] != 'PERFECT' and r['status'] != 'ERROR']
	if mismatches:
		print("="*70)
		print(f"MISMATCHES (showing first 5 of {len(mismatches)})")
		print("="*70)
		print()
		
		for r in mismatches[:5]:
			print(f"{r['name']}")
			if not r['fail_match']:
				print(f"  Required checks:")
				print(f"    Reference: {r['ref_fail']}")
				print(f"    Student:   {r['stu_fail']}")
			if not r['opt_match']:
				print(f"  Optional checks:")
				print(f"    Reference: {r['ref_opt']}")
				print(f"    Student:   {r['stu_opt']}")
			print()

if __name__ == "__main__":
	main()
