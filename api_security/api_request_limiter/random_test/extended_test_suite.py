"""
Exercise 2.X: API Request Rate Limiter - EXTENDED TEST SUITE
=============================================================

This file includes:
  • 15 standard test cases
  • 30 randomized test cases (generated each run)

Your solution is compared against a reference implementation.
Yes, you can see the reference implementation below - that's OK for learning!

INSTRUCTIONS:
-------------
1. Implement your check_rate_limit() function in the USER IMPLEMENTATION section
2. Run this file: python3 extended_test_suite.py
3. Pass all 45 tests (15 standard + 30 random)
"""

from typing import List, Tuple
import random


# ============================================================================
# REFERENCE IMPLEMENTATION (used for comparison in random tests)
# ============================================================================

'''
So first identify the sublist of request_times that took place

within the last 60 seconds.

If size of sublist is less than max_requests --> (True,0.0)

Else if size of sublist is greater than or equal to max_requests

--> False
'''
def reference_check_rate_limit(request_times: List[float], 
							   current_time: float, 
							   max_requests: int) -> Tuple[bool, float]:
	"""
	Reference implementation - you can see this!
	
	This is used to verify your solution against random test cases.
	In a real testing scenario, this would be hidden, but for learning
	purposes, you can study this to understand the expected behavior.
	"""
	# Filter to last 60 seconds
	window_start = current_time - 60.0
	recent_requests = [t for t in request_times if t >= window_start]
	
	# Check if under limit
	if len(recent_requests) < max_requests:
		return (True, 0.0)
	
	# Calculate retry time
	oldest_request = recent_requests[0]
	retry_after = (oldest_request + 60.0) - current_time
	retry_after = max(0.0, retry_after)
	
	return (False, retry_after)


# ============================================================================
# YOUR IMPLEMENTATION GOES HERE
# ============================================================================


'''
So first identify the sublist of request_times that took place

within the last 60 seconds.

If size of sublist is less than max_requests --> (True,0.0)

Else if size of sublist is greater than or equal to max_requests

--> False
'''
def check_rate_limit(request_times: List[float], 
					 current_time: float, 
					 max_requests: int) -> Tuple[bool, float]:
	"""
	YOUR SOLUTION - implement this function!
	
	Args:
		request_times: List of timestamps (floats) for previous requests
		current_time: Timestamp (float) of the current request
		max_requests: Maximum requests allowed per 60-second window
	
	Returns:
		Tuple of (allowed: bool, retry_after: float)
		- allowed: True if request allowed, False if rate limited
		- retry_after: 0.0 if allowed, otherwise seconds until client can retry
	"""
	
	# TODO: Implement your solution here
	# Replace 'pass' with your code
	
	# Edge case: Empty request history
	if len(request_times) == 0:
		return (True, 0)
	
	# Step 1: Filter to only requests within last 60 seconds
	j = 0
	
	if current_time > 60.0:
		time_min = current_time - 60.0
		j = len(request_times) - 1
		
		# Binary search backwards to find first request >= time_min
		while j >= 0 and request_times[j] >= time_min:
			j -= 1
		
		j += 1  # Move forward to first request within window
	
	# Only consider requests within the last 60 seconds
	request_times = request_times[j:len(request_times)]

	if len(request_times) == 0:

		return (True,0.0)

	elif len(request_times) < max_requests:

		return (True,0.0)

	else:

		return (False,request_times[0] + 60.0 - current_time)



# ============================================================================
# TEST SUITE
# ============================================================================

class Colors:
	"""ANSI color codes for terminal output."""
	GREEN = '\033[92m'
	RED = '\033[91m'
	YELLOW = '\033[93m'
	BLUE = '\033[94m'
	CYAN = '\033[96m'
	MAGENTA = '\033[95m'
	BOLD = '\033[1m'
	END = '\033[0m'


def generate_random_test_case():
	"""Generate a random test case with valid parameters."""
	
	# Random max_requests (1 to 100)
	max_requests = random.choice([1, 2, 3, 5, 10, 20, 50, 100])
	
	# Random current_time (between 60 and 500 for variety)
	current_time = random.uniform(100.0, 500.0)
	
	# Generate random request_times
	num_requests = random.randint(0, max_requests + 5)  # Sometimes over limit
	request_times = []
	
	if num_requests > 0:
		# Mix of old and recent requests
		for _ in range(num_requests):
			# 70% chance of being in the recent window
			if random.random() < 0.7:
				# Recent request (within last 60 seconds)
				timestamp = random.uniform(current_time - 60.0, current_time - 0.1)
			else:
				# Old request (outside window)
				timestamp = random.uniform(1.0, current_time - 60.1)
			request_times.append(timestamp)
		
		# Sort chronologically
		request_times.sort()
	
	return request_times, current_time, max_requests


def compare_results(result1: Tuple[bool, float], 
				   result2: Tuple[bool, float]) -> bool:
	"""
	Compare two results with epsilon for floating point.
	
	Returns True if results match (within tolerance).
	"""
	if not isinstance(result1, tuple) or not isinstance(result2, tuple):
		return False
	
	if len(result1) != 2 or len(result2) != 2:
		return False
	
	# Compare bool values
	bool_match = result1[0] == result2[0]
	
	# Compare float values with epsilon
	retry_match = abs(float(result1[1]) - float(result2[1])) < 0.01
	
	return bool_match and retry_match


def run_standard_tests():
	"""Run the 15 standard test cases."""
	
	test_cases = [
		("Test 1: Under limit (3/5 requests)", 
		 [100.0, 110.0, 120.0], 121.0, 5, (True, 0)),
		("Test 2: At limit (5/5 requests within window)", 
		 [100.0, 110.0, 120.0, 121.0, 121.5], 122.0, 5, (False, 38)),
		("Test 3: Old requests ignored", 
		 [1.0, 2.0, 3.0, 60.0, 61.0, 62.0, 63.0, 64.0], 120.0, 5, (False, 0)),
		("Test 4: Empty request history", 
		 [], 122.0, 5, (True, 0)),
		("Test 5: Single request in history", 
		 [121.0], 122.0, 5, (True, 0)),
		("Test 6: All requests old (>60 seconds)", 
		 [1.0, 2.0, 3.0, 4.0, 5.0], 122.0, 5, (True, 0)),
		("Test 7: Exactly at window boundary", 
		 [1.0, 2.0, 3.0, 4.0, 5.0, 6.0], 7.0, 5, (False, 54)),
		("Test 8: Mixed old and new requests", 
		 [1.0, 2.0, 3.0, 60.0, 61.0, 62.0, 63.0, 64.0], 120.1, 5, (True, 0)),
		("Test 9: Requests at exact 60-second boundary", 
		 [60.0, 61.0, 62.0, 63.0, 64.0], 120.0, 5, (False, 0)),
		("Test 10: Very recent burst (all within 1 second)", 
		 [121.0, 121.2, 121.4, 121.6, 121.8], 122.0, 5, (False, 59)),
		("Test 11: Custom max_requests (limit of 2)", 
		 [100.0, 110.0], 120.0, 2, (False, 40)),
		("Test 12: Custom max_requests (limit of 10)", 
		 [100.0, 110.0, 120.0], 121.0, 10, (True, 0)),
		("Test 13: Custom max_requests (limit of 1)", 
		 [119.5], 120.0, 1, (False, 59.5)),
		("Test 14: Custom max_requests (limit of 3)", 
		 [100.0, 110.0, 119.0], 120.0, 3, (False, 40)),
		("Test 15: Custom max_requests (limit of 100)", 
		 [100.0, 110.0, 120.0], 121.0, 100, (True, 0)),
	]
	
	print()
	print("=" * 80)
	print(f"{Colors.BOLD}PART 1: STANDARD TEST CASES (15 tests){Colors.END}")
	print("=" * 80)
	print()
	
	passed = 0
	failed = 0
	errors = 0
	
	for test_name, times, current, max_req, expected in test_cases:
		try:
			result = check_rate_limit(times.copy(), current, max_req)
			
			# Validate result type
			if not isinstance(result, tuple) or len(result) != 2:
				print(f"{Colors.RED}❌ FAIL{Colors.END} - {test_name}")
				print(f"   {Colors.RED}Must return tuple (bool, float){Colors.END}")
				print()
				failed += 1
				continue
			
			# Compare with expected
			if compare_results(result, expected):
				print(f"{Colors.GREEN}✅ PASS{Colors.END} - {test_name}")
				passed += 1
			else:
				print(f"{Colors.RED}❌ FAIL{Colors.END} - {test_name}")
				print(f"   Input: times={times[:3]}{'...' if len(times) > 3 else ''}, "
					  f"current={current}, max={max_req}")
				print(f"   Expected: {expected}")
				print(f"   Got:      {result}")
				failed += 1
			
		except Exception as e:
			print(f"{Colors.RED}❌ ERROR{Colors.END} - {test_name}")
			print(f"   {Colors.RED}{type(e).__name__}: {e}{Colors.END}")
			errors += 1
	
	print()
	print(f"{Colors.BOLD}Standard Tests Summary:{Colors.END}")
	print(f"  Passed: {Colors.GREEN}{passed}/15{Colors.END}")
	if failed > 0:
		print(f"  Failed: {Colors.RED}{failed}/15{Colors.END}")
	if errors > 0:
		print(f"  Errors: {Colors.RED}{errors}/15{Colors.END}")
	print()
	
	return passed, failed, errors


def run_random_tests(num_tests=30):
	"""Run randomized test cases against reference implementation."""
	
	print("=" * 80)
	print(f"{Colors.BOLD}PART 2: RANDOMIZED TEST CASES (30 tests){Colors.END}")
	print("=" * 80)
	print()
	print(f"{Colors.CYAN}Generating {num_tests} random test cases...{Colors.END}")
	print(f"{Colors.CYAN}Comparing your solution vs reference implementation...{Colors.END}")
	print()
	
	passed = 0
	failed = 0
	errors = 0
	failed_cases = []
	
	# Set seed for reproducibility (remove this for truly random tests each run)
	random.seed(42)
	
	for i in range(1, num_tests + 1):
		try:
			# Generate random test case
			request_times, current_time, max_requests = generate_random_test_case()
			
			# Get results from both implementations
			user_result = check_rate_limit(request_times.copy(), current_time, max_requests)
			reference_result = reference_check_rate_limit(request_times.copy(), current_time, max_requests)
			
			# Validate user result type
			if not isinstance(user_result, tuple) or len(user_result) != 2:
				print(f"{Colors.RED}❌ FAIL{Colors.END} Random Test {i:2d}: Invalid return type")
				failed += 1
				failed_cases.append((i, request_times, current_time, max_requests, 
								   reference_result, user_result, "Invalid return type"))
				continue
			
			# Compare results
			if compare_results(user_result, reference_result):
				print(f"{Colors.GREEN}✅ PASS{Colors.END} Random Test {i:2d}: "
					  f"max={max_requests:3d}, {len(request_times):2d} requests → {user_result}")
				passed += 1
			else:
				print(f"{Colors.RED}❌ FAIL{Colors.END} Random Test {i:2d}: Results don't match")
				failed += 1
				failed_cases.append((i, request_times, current_time, max_requests, 
								   reference_result, user_result, "Results mismatch"))
				
		except Exception as e:
			print(f"{Colors.RED}❌ ERROR{Colors.END} Random Test {i:2d}: {type(e).__name__}: {e}")
			errors += 1
	
	print()
	print(f"{Colors.BOLD}Random Tests Summary:{Colors.END}")
	print(f"  Passed: {Colors.GREEN}{passed}/{num_tests}{Colors.END}")
	if failed > 0:
		print(f"  Failed: {Colors.RED}{failed}/{num_tests}{Colors.END}")
	if errors > 0:
		print(f"  Errors: {Colors.RED}{errors}/{num_tests}{Colors.END}")
	print()
	
	# Show details of failed random tests
	if failed_cases:
		print("=" * 80)
		print(f"{Colors.YELLOW}{Colors.BOLD}FAILED RANDOM TEST DETAILS:{Colors.END}")
		print("=" * 80)
		print()
		
		for test_num, times, current, max_req, expected, got, reason in failed_cases[:5]:  # Show first 5
			print(f"{Colors.YELLOW}Random Test {test_num}:{Colors.END} {reason}")
			print(f"  request_times: {times}")
			print(f"  current_time:  {current:.2f}")
			print(f"  max_requests:  {max_req}")
			print(f"  Expected (reference): {expected}")
			print(f"  Got (your code):      {got}")
			
			# Explain the difference
			if isinstance(got, tuple) and len(got) == 2:
				if expected[0] != got[0]:
					print(f"  {Colors.RED}→ Wrong allowed/blocked decision{Colors.END}")
				if abs(float(expected[1]) - float(got[1])) >= 0.01:
					diff = float(got[1]) - float(expected[1])
					print(f"  {Colors.RED}→ retry_after off by {diff:.2f} seconds{Colors.END}")
			print()
		
		if len(failed_cases) > 5:
			print(f"{Colors.YELLOW}... and {len(failed_cases) - 5} more failed tests{Colors.END}")
			print()
	
	return passed, failed, errors


def run_all_tests():
	"""Run all tests and display final summary."""
	
	print()
	print("╔" + "═" * 78 + "╗")
	print("║" + " " * 20 + "EXTENDED TEST SUITE" + " " * 39 + "║")
	print("║" + " " * 15 + "15 Standard + 30 Random = 45 Total Tests" + " " * 22 + "║")
	print("╚" + "═" * 78 + "╝")
	
	# Run standard tests
	std_passed, std_failed, std_errors = run_standard_tests()
	
	# Run random tests
	rand_passed, rand_failed, rand_errors = run_random_tests(30)
	
	# Final summary
	total_passed = std_passed + rand_passed
	total_failed = std_failed + rand_failed
	total_errors = std_errors + rand_errors
	total_tests = 45
	
	print()
	print("=" * 80)
	print(f"{Colors.BOLD}FINAL SUMMARY{Colors.END}")
	print("=" * 80)
	
	print(f"\nStandard Tests: {Colors.GREEN if std_failed == 0 else Colors.RED}"
		  f"{std_passed}/15{Colors.END}")
	print(f"Random Tests:   {Colors.GREEN if rand_failed == 0 else Colors.RED}"
		  f"{rand_passed}/30{Colors.END}")
	print(f"\n{Colors.BOLD}TOTAL: {Colors.GREEN if total_passed == total_tests else Colors.RED}"
		  f"{total_passed}/{total_tests}{Colors.END} tests passed")
	
	if total_errors > 0:
		print(f"\n{Colors.RED}Errors encountered: {total_errors}{Colors.END}")
	
	print()
	
	if total_passed == total_tests:
		print("╔" + "═" * 78 + "╗")
		print("║" + f"{Colors.GREEN}{Colors.BOLD}{'🎉 PERFECT! ALL 45 TESTS PASSED! 🎉':^88s}{Colors.END}" + "║")
		print("╚" + "═" * 78 + "╝")
		print()
		print("Your solution is rock-solid and handles all edge cases!")
		print()
		print("Next steps:")
		print("  ✅ Add to GitHub portfolio")
		print("  ✅ Write blog post about rate limiting")
		print("  ✅ Move to Week 3 project")
		print()
	elif total_passed >= 40:
		print(f"{Colors.YELLOW}Almost there! You passed {total_passed}/45 tests.{Colors.END}")
		print("Review the failed test cases above and debug your solution.")
		print()
	elif total_passed >= 30:
		print(f"{Colors.YELLOW}Good progress! You passed {total_passed}/45 tests.{Colors.END}")
		print("Focus on the standard tests first, then tackle the random tests.")
		print()
	else:
		print(f"{Colors.RED}Keep working! You passed {total_passed}/45 tests.{Colors.END}")
		print()
		print("Hints:")
		print("  1. Make sure you return Tuple[bool, float]")
		print("  2. Filter to last 60 seconds: recent = [t for t in times if t >= window_start]")
		print("  3. Use max_requests parameter (don't hardcode!)")
		print("  4. Calculate retry_after: (oldest + 60.0) - current_time")
		print()
	
	print("=" * 80)
	print()


# ============================================================================
# MAIN - Run all tests when file is executed
# ============================================================================

if __name__ == "__main__":
	run_all_tests()
