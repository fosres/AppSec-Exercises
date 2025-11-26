"""
Exercise 2.X: API Request Rate Limiter - 30 COMPREHENSIVE TESTS
================================================================

This file includes 30 carefully designed standard test cases.
No reference implementation - figure it out yourself!

INSTRUCTIONS:
-------------
1. Implement your check_rate_limit() function below
2. Run this file: python3 rate_limiter_30_tests.py
3. Pass all 30 tests!

Inspired by: "API Security in Action" (Chapter 3, pp. 67-69) 
			 "Hacking APIs" (Chapter 13, pp. 276-280)
"""

from typing import List, Tuple


# ============================================================================
# YOUR IMPLEMENTATION GOES HERE
# ============================================================================

def check_rate_limit(request_times: List[float], 
					 current_time: float, 
					 max_requests: int) -> Tuple[bool, float]:
	"""
	Implement a 60-second sliding window rate limiter.
	
	Args:
		request_times: List of timestamps (floats) for previous requests
		current_time: Timestamp (float) of the current request
		max_requests: Maximum requests allowed per 60-second window
	
	Returns:
		Tuple of (allowed: bool, retry_after: float)
		- allowed: True if request allowed, False if rate limited
		- retry_after: 0.0 if allowed, otherwise seconds until client can retry
	
	Example:
		>>> check_rate_limit([100.0, 110.0, 120.0], 121.0, 5)
		(True, 0.0)  # Only 3 requests in window, limit is 5
		
		>>> check_rate_limit([100.0, 110.0, 120.0, 121.0, 121.5], 122.0, 5)
		(False, 38.0)  # 5 requests in window, must wait 38 seconds
	
	Critical Requirements:
	╔═══════════════════════════════════════════════════════════════════════╗
	║ 1. MUST return a tuple: (bool, float)                                ║
	║ 2. Only count requests within last 60 seconds from current_time      ║
	║ 3. Use >= for boundary check (NOT >)                                 ║
	║ 4. max_requests is CONFIGURABLE - never hardcode!                    ║
	║ 5. retry_after must be 0.0 if allowed                                ║
	║ 6. retry_after = (oldest_request + 60.0) - current_time if blocked   ║
	╚═══════════════════════════════════════════════════════════════════════╝
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


def compare_results(result: Tuple[bool, float], 
				   expected: Tuple[bool, float]) -> bool:
	"""
	Compare result with expected value.
	
	Returns True if results match (within tolerance).
	"""
	if not isinstance(result, tuple):
		return False
	
	if len(result) != 2:
		return False
	
	# Compare bool values
	bool_match = result[0] == expected[0]
	
	# Compare float values with epsilon (0.01 seconds tolerance)
	try:
		retry_match = abs(float(result[1]) - float(expected[1])) < 0.01
	except (TypeError, ValueError):
		return False
	
	return bool_match and retry_match


def run_all_tests():
	"""Run all 30 test cases."""
	
	# ========================================================================
	# 30 STANDARD TEST CASES
	# ========================================================================
	
	test_cases = [
		# BASIC FUNCTIONALITY (Tests 1-5)
		("Test 1: Under limit (3/5 requests)", 
		 [100.0, 110.0, 120.0], 121.0, 5, (True, 0.0)),
		
		("Test 2: At limit (5/5 requests within window)", 
		 [100.0, 110.0, 120.0, 121.0, 121.5], 122.0, 5, (False, 38.0)),
		
		("Test 3: Empty request history", 
		 [], 122.0, 5, (True, 0.0)),
		
		("Test 4: Single request in history", 
		 [121.0], 122.0, 5, (True, 0.0)),
		
		("Test 5: All requests old (>60 seconds)", 
		 [1.0, 2.0, 3.0, 4.0, 5.0], 122.0, 5, (True, 0.0)),
		
		# BOUNDARY CONDITIONS (Tests 6-10)
		("Test 6: Exactly at window boundary", 
		 [1.0, 2.0, 3.0, 4.0, 5.0, 6.0], 7.0, 5, (False, 54.0)),
		
		("Test 7: Old requests ignored", 
		 [1.0, 2.0, 3.0, 60.0, 61.0, 62.0, 63.0, 64.0], 120.0, 5, (False, 0.0)),
		
		("Test 8: Mixed old and new requests", 
		 [1.0, 2.0, 3.0, 60.0, 61.0, 62.0, 63.0, 64.0], 120.1, 5, (True, 0.0)),
		
		("Test 9: Requests at exact 60-second boundary", 
		 [60.0, 61.0, 62.0, 63.0, 64.0], 120.0, 5, (False, 0.0)),
		
		("Test 10: Just after 60-second boundary", 
		 [60.0, 61.0, 62.0, 63.0, 64.0], 120.1, 5, (True, 0.0)),
		
		# TIMING SCENARIOS (Tests 11-15)
		("Test 11: Very recent burst (all within 1 second)", 
		 [121.0, 121.2, 121.4, 121.6, 121.8], 122.0, 5, (False, 59.0)),
		
		("Test 12: Spread across full window", 
		 [60.0, 70.0, 80.0, 90.0, 100.0], 120.0, 5, (False, 0.0)),
		
		("Test 13: One request just inside window", 
		 [60.1, 70.0, 80.0, 90.0, 100.0], 120.0, 5, (False, 0.1)),
		
		("Test 14: Multiple old, one recent", 
		 [1.0, 2.0, 3.0, 4.0, 119.0], 120.0, 5, (True, 0.0)),
		
		("Test 15: Gradual spacing", 
		 [100.0, 105.0, 110.0, 115.0], 120.0, 5, (True, 0.0)),
		
		# VARIABLE max_requests (Tests 16-20)
		("Test 16: Strict limit (max=2)", 
		 [100.0, 110.0], 120.0, 2, (False, 40.0)),
		
		("Test 17: Very strict limit (max=1)", 
		 [119.5], 120.0, 1, (False, 59.5)),
		
		("Test 18: Lenient limit (max=10)", 
		 [100.0, 110.0, 120.0], 121.0, 10, (True, 0.0)),
		
		("Test 19: High volume limit (max=100)", 
		 [100.0, 110.0, 120.0], 121.0, 100, (True, 0.0)),
		
		("Test 20: Strict limit (max=3)", 
		 [100.0, 110.0, 119.0], 120.0, 3, (False, 40.0)),
		
		# FRACTIONAL SECONDS (Tests 21-25)
		("Test 21: Fractional timestamps (under limit)", 
		 [100.5, 110.3, 120.7], 121.2, 5, (True, 0.0)),
		
		("Test 22: Fractional retry_after", 
		 [119.3], 120.0, 1, (False, 59.3)),
		
		("Test 23: Precise boundary with fractions", 
		 [60.5, 70.5, 80.5, 90.5, 100.5], 120.5, 5, (False, 0.0)),
		
		("Test 24: Just outside window with fractions", 
		 [59.9, 70.0, 80.0, 90.0, 100.0], 120.0, 5, (True, 0.0)),
		
		("Test 25: Microsecond precision", 
		 [119.999], 120.0, 1, (False, 59.999)),
		
		# EDGE CASES (Tests 26-30)
		("Test 26: Exactly at limit with old requests", 
		 [1.0, 2.0, 100.0, 110.0, 120.0, 121.0, 121.5], 122.0, 5, (False, 38.0)),
		
		("Test 27: Empty list with strict limit", 
		 [], 120.0, 1, (True, 0.0)),
		
		("Test 28: Single recent request at boundary", 
		 [60.0], 120.0, 1, (False, 0.0)),
		
		("Test 29: All requests at same timestamp", 
		 [100.0, 100.0, 100.0], 120.0, 5, (True, 0.0)),
		
		("Test 30: High volume at limit", 
		 [61.0, 62.0, 63.0, 64.0, 65.0, 66.0, 67.0, 68.0, 69.0, 70.0], 120.0, 10, (False, 1.0)),
	]
	
	# ========================================================================
	# RUN TESTS
	# ========================================================================
	
	print()
	print("╔" + "═" * 78 + "╗")
	print("║" + " " * 20 + "RATE LIMITER CHALLENGE" + " " * 36 + "║")
	print("║" + " " * 25 + "30 TEST CASES" + " " * 40 + "║")
	print("╚" + "═" * 78 + "╝")
	print()
	
	passed = 0
	failed = 0
	errors = 0
	failed_tests = []
	
	for test_name, times, current, max_req, expected in test_cases:
		try:
			result = check_rate_limit(times.copy(), current, max_req)
			
			# Validate result type
			if not isinstance(result, tuple) or len(result) != 2:
				print(f"{Colors.RED}❌ FAIL{Colors.END} - {test_name}")
				print(f"   {Colors.RED}ERROR: Must return tuple (bool, float), got {type(result).__name__}{Colors.END}")
				print()
				failed += 1
				failed_tests.append((test_name, times, current, max_req, expected, result, "Invalid return type"))
				continue
			
			# Compare with expected
			if compare_results(result, expected):
				print(f"{Colors.GREEN}✅ PASS{Colors.END} - {test_name}")
				passed += 1
			else:
				print(f"{Colors.RED}❌ FAIL{Colors.END} - {test_name}")
				print(f"   Input: times={times[:5]}{'...' if len(times) > 5 else ''}, "
					  f"current={current}, max={max_req}")
				print(f"   Expected: {expected}")
				print(f"   Got:      {result}")
				
				# Show specific differences
				if result[0] != expected[0]:
					print(f"   {Colors.RED}→ Wrong allowed/blocked decision{Colors.END}")
				if abs(float(result[1]) - float(expected[1])) >= 0.01:
					diff = float(result[1]) - float(expected[1])
					print(f"   {Colors.RED}→ retry_after off by {diff:.2f} seconds{Colors.END}")
				print()
				
				failed += 1
				failed_tests.append((test_name, times, current, max_req, expected, result, "Results mismatch"))
			
		except Exception as e:
			print(f"{Colors.RED}❌ ERROR{Colors.END} - {test_name}")
			print(f"   {Colors.RED}{type(e).__name__}: {e}{Colors.END}")
			print()
			errors += 1
			failed_tests.append((test_name, times, current, max_req, expected, None, f"Exception: {e}"))
	
	# ========================================================================
	# SUMMARY
	# ========================================================================
	
	print()
	print("=" * 80)
	print(f"{Colors.BOLD}SUMMARY{Colors.END}")
	print("=" * 80)
	
	total_tests = 30
	print(f"\n{Colors.BOLD}Tests Passed: {Colors.GREEN if passed == total_tests else Colors.YELLOW}"
		  f"{passed}/{total_tests}{Colors.END}")
	
	if failed > 0:
		print(f"Tests Failed: {Colors.RED}{failed}/{total_tests}{Colors.END}")
	if errors > 0:
		print(f"Errors:       {Colors.RED}{errors}/{total_tests}{Colors.END}")
	
	print()
	
	# ========================================================================
	# RESULTS
	# ========================================================================
	
	if passed == total_tests:
		print("╔" + "═" * 78 + "╗")
		print("║" + f"{Colors.GREEN}{Colors.BOLD}{'🎉 PERFECT! ALL 30 TESTS PASSED! 🎉':^88s}{Colors.END}" + "║")
		print("╚" + "═" * 78 + "╝")
		print()
		print("Your solution is production-ready! 💪")
		print()
		print("Next steps:")
		print("  ✅ Add to GitHub portfolio")
		print("  ✅ Write blog post about your approach")
		print("  ✅ Share your completion time!")
		print("  ✅ Move to Week 3 project")
		print()
	elif passed >= 25:
		print(f"{Colors.YELLOW}Almost there! You passed {passed}/30 tests.{Colors.END}")
		print("Review the failed test cases above and debug your solution.")
		print()
		if failed_tests:
			print(f"{Colors.BOLD}Failed tests:{Colors.END}")
			for test_name, _, _, _, _, _, _ in failed_tests[:3]:
				print(f"  • {test_name}")
			if len(failed_tests) > 3:
				print(f"  ... and {len(failed_tests) - 3} more")
		print()
	elif passed >= 20:
		print(f"{Colors.YELLOW}Good progress! You passed {passed}/30 tests.{Colors.END}")
		print("Focus on the edge cases and boundary conditions.")
		print()
	elif passed >= 10:
		print(f"{Colors.YELLOW}Keep going! You passed {passed}/30 tests.{Colors.END}")
		print()
		print("Hints:")
		print("  1. Filter to last 60 seconds: recent = [t for t in times if t >= window_start]")
		print("  2. Use >= not > for the boundary check")
		print("  3. Don't hardcode max_requests=5")
		print()
	else:
		print(f"{Colors.RED}Keep working! You passed {passed}/30 tests.{Colors.END}")
		print()
		print("Key hints:")
		print("  1. Return Tuple[bool, float]")
		print("  2. window_start = current_time - 60.0")
		print("  3. Filter: recent = [t for t in request_times if t >= window_start]")
		print("  4. If len(recent) < max_requests: return (True, 0.0)")
		print("  5. Else: retry_after = (recent[0] + 60.0) - current_time")
		print("  6. Return (False, max(0.0, retry_after))")
		print()
	
	print("=" * 80)
	print()


# ============================================================================
# MAIN - Run all tests when file is executed
# ============================================================================

if __name__ == "__main__":
	run_all_tests()
