"""
Week 1 Port Scanner - 60 COMPREHENSIVE TESTS
==============================================

Grading suite for your port scanner implementation.
Tests your actual code structure and validates all edge cases.

USAGE:
1. Place your port_scan.py in the same directory
2. Run: python3 grade_port_scanner.py
3. See your grade out of 60 tests!
"""

import sys
import os

# Import the student's scanner
try:
	sys.path.insert(0, '/mnt/user-data/uploads')
	from port_scan import scan_port
	print("✅ Successfully imported scan_port from port_scan.py\n")
except ImportError as e:
	print(f"❌ ERROR: Could not import scan_port from port_scan.py")
	print(f"   {e}")
	sys.exit(1)


# ==========================================================
# TEST SUITE
# ==========================================================

class Colors:
	"""ANSI color codes for terminal output"""
	GREEN = '\033[92m'
	RED = '\033[91m'
	YELLOW = '\033[93m'
	BLUE = '\033[94m'
	BOLD = '\033[1m'
	END = '\033[0m'


def run_all_tests():
	"""Execute all 60 test cases"""
	
	test_cases = [
		# ========================================
		# CATEGORY 1: Port Validation (Tests 1-15)
		# ========================================
		("Test 1: Invalid port - negative number (-1)", "localhost", -1, 1.0, "ERROR"),
		("Test 2: Invalid port - negative (-999)", "localhost", -999, 1.0, "ERROR"),
		("Test 3: Invalid port - zero (0)", "localhost", 0, 1.0, "ERROR"),
		("Test 4: Invalid port - just over max (65536)", "localhost", 65536, 1.0, "ERROR"),
		("Test 5: Invalid port - way over max (100000)", "localhost", 100000, 1.0, "ERROR"),
		("Test 6: Valid port - minimum (1)", "localhost", 1, 1.0, None),  # Any result OK
		("Test 7: Valid port - low range (22)", "localhost", 22, 1.0, None),
		("Test 8: Valid port - HTTP (80)", "localhost", 80, 1.0, None),
		("Test 9: Valid port - HTTPS (443)", "localhost", 443, 1.0, None),
		("Test 10: Valid port - mid range (8080)", "localhost", 8080, 1.0, None),
		("Test 11: Valid port - high range (50000)", "localhost", 50000, 1.0, None),
		("Test 12: Valid port - very high (60000)", "localhost", 60000, 1.0, None),
		("Test 13: Valid port - maximum (65535)", "localhost", 65535, 1.0, None),
		("Test 14: Valid port - privilege boundary (1024)", "localhost", 1024, 1.0, None),
		("Test 15: Valid port - common dev (3000)", "localhost", 3000, 1.0, None),
		
		# ========================================
		# CATEGORY 2: Timeout Validation (Tests 16-25)
		# ========================================
		("Test 16: Invalid timeout - below range (0.9)", "localhost", 80, 0.9, "ERROR"),
		("Test 17: Invalid timeout - zero (0.0)", "localhost", 80, 0.0, "ERROR"),
		("Test 18: Invalid timeout - negative (-1.0)", "localhost", 80, -1.0, "ERROR"),
		("Test 19: Invalid timeout - above range (2.1)", "localhost", 80, 2.1, "ERROR"),
		("Test 20: Invalid timeout - way above (5.0)", "localhost", 80, 5.0, "ERROR"),
		("Test 21: Valid timeout - minimum (1.0)", "localhost", 80, 1.0, None),
		("Test 22: Valid timeout - mid range (1.5)", "localhost", 80, 1.5, None),
		("Test 23: Valid timeout - maximum (2.0)", "localhost", 80, 2.0, None),
		("Test 24: Valid timeout - low end (1.1)", "localhost", 80, 1.1, None),
		("Test 25: Valid timeout - high end (1.9)", "localhost", 80, 1.9, None),
		
		# ========================================
		# CATEGORY 3: DNS & Host Resolution (Tests 26-35)
		# ========================================
		("Test 26: DNS failure - nonexistent domain", "thisdomaindoesnotexist12345.com", 80, 1.0, "ERROR"),
		("Test 27: DNS failure - invalid characters", "invalid..domain...com", 80, 1.0, "ERROR"),
		("Test 28: DNS failure - very long domain", "a" * 300 + ".com", 80, 1.0, "ERROR"),
		("Test 29: Valid host - localhost", "localhost", 12345, 1.0, None),
		("Test 30: Valid host - IPv4 loopback (127.0.0.1)", "127.0.0.1", 12345, 1.0, None),
		("Test 31: Valid host - IPv6 loopback (::1)", "::1", 12345, 1.0, None),
		("Test 32: Valid host - another loopback (127.0.0.2)", "127.0.0.2", 12345, 1.0, None),
		("Test 33: Localhost - common port", "localhost", 80, 1.0, None),
		("Test 34: IPv4 - high port", "127.0.0.1", 54321, 1.0, None),
		("Test 35: IPv6 - mid port", "::1", 8080, 1.0, None),
		
		# ========================================
		# CATEGORY 4: Port States - Closed Ports (Tests 36-45)
		# ========================================
		("Test 36: Closed port - high number", "localhost", 54321, 1.0, "CLOSED"),
		("Test 37: Closed port - another high", "localhost", 55555, 1.0, "CLOSED"),
		("Test 38: Closed port - random mid", "localhost", 12345, 1.0, "CLOSED"),
		("Test 39: Closed port - another random", "localhost", 23456, 1.0, "CLOSED"),
		("Test 40: Closed port - ephemeral range", "localhost", 49999, 1.0, "CLOSED"),
		("Test 41: Closed port - on IPv4", "127.0.0.1", 34567, 1.0, "CLOSED"),
		("Test 42: Closed port - on IPv6", "::1", 45678, 1.0, "CLOSED"),
		("Test 43: Closed port - low number", "localhost", 999, 1.0, "CLOSED"),
		("Test 44: Closed port - mid range", "localhost", 32000, 1.0, "CLOSED"),
		("Test 45: Closed port - unusual", "localhost", 31337, 1.0, "CLOSED"),
		
		# ========================================
		# CATEGORY 5: Return Value Validation (Tests 46-55)
		# ========================================
		("Test 46: Returns string not None - closed port", "localhost", 11111, 1.0, "MUST_RETURN_STRING"),
		("Test 47: Returns string not None - invalid port", "localhost", -10, 1.0, "MUST_RETURN_STRING"),
		("Test 48: Returns string not None - invalid timeout", "localhost", 80, 0.5, "MUST_RETURN_STRING"),
		("Test 49: Returns string not None - DNS error", "badhost999.invalid", 80, 1.0, "MUST_RETURN_STRING"),
		("Test 50: Returns string not None - another closed", "localhost", 22222, 1.0, "MUST_RETURN_STRING"),
		("Test 51: Status is uppercase or consistent", "localhost", 33333, 1.0, "CHECK_CASE"),
		("Test 52: Error status contains ERROR", "localhost", 100000, 1.0, "CHECK_ERROR_STRING"),
		("Test 53: Closed status indicates closed", "localhost", 44444, 1.0, "CHECK_CLOSED_STRING"),
		("Test 54: Return value is useful", "localhost", 80, 1.0, "CHECK_USEFUL"),
		("Test 55: Multiple calls work", "localhost", 80, 1.0, "CHECK_MULTIPLE"),
		
		# ========================================
		# CATEGORY 6: Edge Cases & Combined Conditions (Tests 56-60)
		# ========================================
		("Test 56: Combined - invalid port + valid timeout", "localhost", -5, 1.5, "ERROR"),
		("Test 57: Combined - valid port + invalid timeout", "localhost", 80, 3.0, "ERROR"),
		("Test 58: Combined - boundary port (1) + boundary timeout (1.0)", "localhost", 1, 1.0, None),
		("Test 59: Combined - boundary port (65535) + boundary timeout (2.0)", "localhost", 65535, 2.0, None),
		("Test 60: Combined - IPv6 + high port + mid timeout", "::1", 50000, 1.5, None),
	]
	
	print("╔" + "═" * 78 + "╗")
	print("║" + f"{Colors.BOLD}{'WEEK 1 PORT SCANNER - COMPREHENSIVE GRADING':^78s}{Colors.END}" + "║")
	print("║" + f"{'60 TEST CASES':^78s}" + "║")
	print("║" + f"{'Networking Fundamentals Assessment':^78s}" + "║")
	print("╚" + "═" * 78 + "╝")
	print()
	
	passed = 0
	failed = 0
	category_results = {}
	
	# Define test categories
	categories = {
		range(1, 16): "Port Validation (15 tests)",
		range(16, 26): "Timeout Validation (10 tests)",
		range(26, 36): "DNS & Host Resolution (10 tests)",
		range(36, 46): "Port States - Closed Ports (10 tests)",
		range(46, 56): "Return Value Validation (10 tests)",
		range(56, 61): "Edge Cases & Combined (5 tests)"
	}
	
	# Track for multi-call test
	multi_call_results = []
	
	for idx, test_data in enumerate(test_cases, 1):
		test_name = test_data[0]
		host = test_data[1]
		port = test_data[2]
		timeout = test_data[3]
		expected = test_data[4]
		
		# Determine category
		category = next((name for range_obj, name in categories.items() if idx in range_obj), "Other")
		
		if category not in category_results:
			category_results[category] = {'passed': 0, 'failed': 0}
		
		try:
			# Capture stdout to suppress function's print statements during testing
			import io
			import contextlib
			
			f = io.StringIO()
			with contextlib.redirect_stdout(f):
				result = scan_port(host, port, timeout)
			
			# Store for multi-call test
			if idx <= 5:
				multi_call_results.append(result)
			
			# Validate based on expected type
			test_passed = False
			failure_reason = None
			
			if expected == "MUST_RETURN_STRING":
				# Test that it returns a string, not None
				if result is not None and isinstance(result, str):
					test_passed = True
				else:
					test_passed = False
					failure_reason = f"Expected string return, got {type(result).__name__}: {result}"
			
			elif expected == "CHECK_CASE":
				# Check status is consistent (all uppercase or all lowercase)
				if result and isinstance(result, str):
					if result.isupper() or result.islower():
						test_passed = True
					else:
						test_passed = False
						failure_reason = f"Status should be consistent case: {result}"
				else:
					test_passed = False
					failure_reason = f"Expected string, got {type(result)}"
			
			elif expected == "CHECK_ERROR_STRING":
				# Check that error returns contain "ERROR" or similar
				if result and isinstance(result, str) and "ERROR" in result.upper():
					test_passed = True
				else:
					test_passed = False
					failure_reason = f"Error status should contain 'ERROR': {result}"
			
			elif expected == "CHECK_CLOSED_STRING":
				# Check that closed returns indicate closed state
				if result and isinstance(result, str) and "CLOSED" in result.upper():
					test_passed = True
				else:
					test_passed = False
					failure_reason = f"Closed status should indicate 'CLOSED': {result}"
			
			elif expected == "CHECK_USEFUL":
				# Check return is not empty or useless
				if result and isinstance(result, str) and len(result) > 0:
					test_passed = True
				else:
					test_passed = False
					failure_reason = f"Return value not useful: {result}"
			
			elif expected == "CHECK_MULTIPLE":
				# Check that we successfully called function multiple times
				if len(multi_call_results) >= 5:
					test_passed = True
				else:
					test_passed = False
					failure_reason = f"Function should be callable multiple times"
			
			elif expected == "ERROR":
				# Expecting an error status
				if result and isinstance(result, str) and "ERROR" in result.upper():
					test_passed = True
				else:
					test_passed = False
					failure_reason = f"Expected ERROR status, got: {result}"
			
			elif expected == "CLOSED":
				# Expecting closed status
				if result and isinstance(result, str) and "CLOSED" in result.upper():
					test_passed = True
				else:
					test_passed = False
					failure_reason = f"Expected CLOSED status, got: {result}"
			
			elif expected is None:
				# Any valid return is acceptable (as long as it's not None)
				if result is not None and isinstance(result, str):
					test_passed = True
				else:
					test_passed = False
					failure_reason = f"Expected valid string return, got {type(result).__name__}: {result}"
			
			if test_passed:
				print(f"{Colors.GREEN}✅ PASS{Colors.END} - {test_name}")
				passed += 1
				category_results[category]['passed'] += 1
			else:
				print(f"{Colors.RED}❌ FAIL{Colors.END} - {test_name}")
				if failure_reason:
					print(f"   {failure_reason}")
				failed += 1
				category_results[category]['failed'] += 1
				
		except Exception as e:
			print(f"{Colors.RED}❌ ERROR{Colors.END} - {test_name}")
			print(f"   {type(e).__name__}: {e}")
			failed += 1
			category_results[category]['failed'] += 1
	
	# Print category breakdown
	print()
	print("=" * 80)
	print(f"{Colors.BOLD}CATEGORY BREAKDOWN{Colors.END}")
	print("=" * 80)
	
	for category, results in category_results.items():
		total = results['passed'] + results['failed']
		percentage = (results['passed'] / total * 100) if total > 0 else 0
		status_color = Colors.GREEN if percentage == 100 else Colors.YELLOW if percentage >= 70 else Colors.RED
		print(f"{status_color}{category:.<60s} {results['passed']}/{total} ({percentage:.0f}%){Colors.END}")
	
	# Overall summary
	print()
	print("=" * 80)
	print(f"{Colors.BOLD}FINAL GRADE{Colors.END}")
	print("=" * 80)
	percentage = (passed / 60 * 100)
	
	if percentage >= 90:
		grade = "A"
		grade_color = Colors.GREEN
	elif percentage >= 80:
		grade = "B"
		grade_color = Colors.GREEN
	elif percentage >= 70:
		grade = "C"
		grade_color = Colors.YELLOW
	elif percentage >= 60:
		grade = "D"
		grade_color = Colors.YELLOW
	else:
		grade = "F"
		grade_color = Colors.RED
	
	print(f"Tests Passed: {passed}/60 ({percentage:.1f}%)")
	print(f"Tests Failed: {failed}/60")
	print(f"{grade_color}Letter Grade: {grade}{Colors.END}")
	print()
	
	if passed == 60:
		print("╔" + "═" * 78 + "╗")
		print("║" + f"{Colors.GREEN}{Colors.BOLD}{'🎉 PERFECT SCORE! ALL 60 TESTS PASSED! 🎉':^88s}{Colors.END}" + "║")
		print("║" + " " * 78 + "║")
		print("║" + f"{'You have mastered Week 1 port scanning fundamentals!':^78s}" + "║")
		print("║" + f"{'Ready to move on to Week 2! ✓':^78s}" + "║")
		print("╚" + "═" * 78 + "╝")
		print()
		print(f"{Colors.BOLD}What You Demonstrated:{Colors.END}")
		print("  ✅ Input validation (port range, timeout range)")
		print("  ✅ Socket programming (TCP connections)")
		print("  ✅ Exception handling (timeout, refused, DNS errors)")
		print("  ✅ Resource management (socket cleanup)")
		print("  ✅ Function design (returns values, reusable)")
		print()
		print(f"{Colors.BOLD}Next Steps:{Colors.END}")
		print("  1. Add service name detection (port 80 → 'http')")
		print("  2. Add banner grabbing from open ports")
		print("  3. Support IPv6 explicitly")
		print("  4. Week 2: Build concurrent scanner with threading")
		
	elif passed >= 50:
		print(f"{Colors.YELLOW}Good work! You passed {passed}/60 tests.{Colors.END}")
		print()
		print("Areas to improve:")
		for category, results in category_results.items():
			if results['failed'] > 0:
				print(f"  • {category}: {results['failed']} test(s) failing")
		print()
		print("Common issues to check:")
		print("  1. Are you returning strings (not None)?")
		print("  2. Are error cases returning 'ERROR'?")
		print("  3. Are closed ports returning 'CLOSED'?")
		print("  4. Does your function work when called multiple times?")
		
	elif passed >= 30:
		print(f"{Colors.YELLOW}You're making progress - {passed}/60 tests passing.{Colors.END}")
		print()
		print("Focus on these fundamentals:")
		print("  1. Validate port range: 1-65535 (not 0-65535)")
		print("  2. Validate timeout range: 1.0-2.0 seconds")
		print("  3. Return status strings: 'OPEN', 'CLOSED', 'FILTERED', 'ERROR'")
		print("  4. Handle exceptions: socket.timeout, ConnectionRefusedError, socket.gaierror")
		print("  5. Always close sockets in finally block")
		print()
		print(f"{Colors.BOLD}Review these concepts:{Colors.END}")
		print("  • Python socket module documentation")
		print("  • Exception handling with try/except")
		print("  • TCP 3-way handshake")
		
	else:
		print(f"{Colors.RED}Keep working - {passed}/60 tests passing.{Colors.END}")
		print()
		print(f"{Colors.BOLD}Essential fixes needed:{Colors.END}")
		print("  1. Function MUST return a value (not use sys.exit())")
		print("  2. Return should be a status string: 'OPEN', 'CLOSED', 'FILTERED', 'ERROR'")
		print("  3. Validate inputs BEFORE creating socket")
		print("  4. Catch specific exceptions, not bare 'except:'")
		print("  5. Close socket in 'finally' block")
		print()
		print(f"{Colors.BOLD}Recommended resources:{Colors.END}")
		print("  • Python socket module: https://docs.python.org/3/library/socket.html")
		print("  • Beej's Guide: https://beej.us/guide/bgnet/")
		print("  • HPBN Chapter 2: https://hpbn.co/building-blocks-of-tcp/")
	
	print()
	print("=" * 80)
	print(f"{Colors.BLUE}Week 1 Port Scanner Assessment Complete{Colors.END}")
	print("=" * 80)


if __name__ == "__main__":
	run_all_tests()
