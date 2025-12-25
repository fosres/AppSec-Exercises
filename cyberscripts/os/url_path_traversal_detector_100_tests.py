#!/usr/bin/env python3
"""
URL Path Traversal Pattern Detector - Week 2 Exercise
======================================================

Learning Objective:
------------------
Learn to RECOGNIZE common path traversal attack patterns in URLs.
This builds your security awareness and prepares you for later work
where you'll learn how to PREVENT these attacks properly.

Context:
--------
You're doing a security code review at a startup. The previous developer
left behind a file upload API with thousands of logged requests. Your manager
asks you to write a quick script to identify which requests might be 
path traversal attempts so the security team can investigate.

Your Task:
----------
Write a function that examines URL paths and returns True if the path
contains common path traversal patterns, False otherwise.

This is NOT production security code - this is a learning exercise to help
you recognize what path traversal attacks look like in the wild.

Real-World Patterns to Detect:
------------------------------
From "Hacking APIs" by Corey Ball (Chapter 9, pp. 218-219):

1. Classic traversal sequences:
   - ../ (Unix parent directory)
   - ..\\ (Windows parent directory)
   
2. Sensitive file paths:
   - /etc/passwd (Unix password file)
   - /etc/shadow (Unix shadow passwords)
   - /root/.ssh/ (SSH keys)
   - C:\\Windows\\System32 (Windows system files)
   - \\windows\\win.ini (Windows config)

3. URL encoding variants:
   - %2e%2e%2f (encoded ../)
   - %2e%2e%5c (encoded ..\\)

4. Log file access:
   - /var/log/ (system logs)
   - /proc/ (process information)

Note: You'll learn proper PREVENTION techniques in Week 8 when you study
pathlib and path canonicalization. For now, focus on RECOGNITION.


def contains_path_traversal(url_path: str) -> bool:
	\"\"\"
	Detect if a URL path contains common path traversal patterns.
	
	This is a LEARNING EXERCISE for pattern recognition, not production code.
	Real prevention requires path canonicalization (you'll learn that in Week 8).
	
	Args:
		url_path: A URL path string (e.g., "/api/download?file=report.pdf")
	
	Returns:
		True if path traversal patterns detected, False otherwise
	
	Examples:
		>>> contains_path_traversal("/api/files/report.pdf")
		False  # Normal path
		
		>>> contains_path_traversal("/download?file=../../etc/passwd")
		True  # Contains ../
		
		>>> contains_path_traversal("/files/%2e%2e%2fetc%2fpasswd")
		True  # URL encoded traversal
	
	Hints:
		- Use the 'in' operator to check for substrings
		- Check for both ../ and ..\\
		- Look for sensitive paths like /etc/, /root/, C:\\Windows
		- URL encoding: %2e = '.' and %2f = '/'
		- Use .lower() to handle case variations
		- You can check multiple conditions with 'or'
	\"\"\"
	pass


# ============================================================================
# TEST SUITE - 30 Test Cases (Week 2 Appropriate)
# ============================================================================

def run_tests():
	\"\"\"Run all 30 test cases with detailed feedback.\"\"\"
	
	tests_passed = 0
	tests_failed = 0
	failed_tests = []
	
	# ANSI color codes
	GREEN = '\033[92m'
	RED = '\033[91m'
	YELLOW = '\033[93m'
	BLUE = '\033[94m'
	RESET = '\033[0m'
	BOLD = '\033[1m'
	
	print(f"\n{BOLD}{BLUE}╔═══════════════════════════════════════════════════════════════╗{RESET}")
	print(f"{BOLD}{BLUE}║   URL PATH TRAVERSAL PATTERN DETECTOR - Week 2 Exercise      ║{RESET}")
	print(f"{BOLD}{BLUE}║                    100 Test Cases                             ║{RESET}")
	print(f"{BOLD}{BLUE}╚═══════════════════════════════════════════════════════════════╝{RESET}\n")
	
	test_cases = [
		# ═══════════════════════════════════════════════════════════
		# CATEGORY 1: Safe Paths (Tests 1-20)
		# Expected: False (no traversal detected)
		# These are legitimate paths that should NOT be flagged
		# ═══════════════════════════════════════════════════════════
		("/api/v1/users", False, "Normal API endpoint"),
		("/files/reports/2024/annual.pdf", False, "Deep legitimate path"),
		("/download?file=document.docx", False, "Simple query parameter"),
		("/images/logo.png", False, "Image file"),
		("/api/search?q=python", False, "Search query"),
		("/data/exports/report.csv", False, "Data export"),
		("/public/index.html", False, "Public resource"),
		("/assets/css/style.css", False, "CSS asset"),
		("/blog/2024/security-tips", False, "Blog post URL"),
		("/user/profile/settings", False, "User settings"),
		("/api/products/123/reviews", False, "Nested resource"),
		("/static/js/app.bundle.js", False, "JavaScript bundle"),
		("/media/videos/tutorial.mp4", False, "Video file"),
		("/docs/api/reference/v2", False, "API documentation"),
		("/webhooks/stripe/payment/success", False, "Webhook endpoint"),
		("/graphql?query=users", False, "GraphQL endpoint"),
		("/files/archive/2023/Q4/report.xlsx", False, "Deep archive path"),
		("/cdn/fonts/roboto-regular.woff2", False, "Font file"),
		("/api/v2/organizations/acme/projects", False, "Multi-level API"),
		("/admin/dashboard/analytics", False, "Admin interface"),
		
		# ═══════════════════════════════════════════════════════════
		# CATEGORY 2: Classic Unix Traversal (Tests 21-35)
		# Expected: True (traversal detected)
		# Standard ../ patterns on Unix/Linux systems
		# ═══════════════════════════════════════════════════════════
		("/files/../../../etc/passwd", True, "Classic Unix traversal"),
		("/api/files/../../../../root/.ssh/id_rsa", True, "SSH key access"),
		("/docs/../../var/log/auth.log", True, "Log file access"),
		("/reports/../../../etc/shadow", True, "Shadow file access"),
		("/download?file=../../../../../etc/hosts", True, "Hosts file access"),
		("/api/load?path=../../proc/self/environ", True, "Process environment"),
		("/files/reports/../../../root/.bash_history", True, "Bash history"),
		("/data/../../../var/www/html/.htaccess", True, "Apache config"),
		("/upload/../../../etc/crontab", True, "Cron jobs"),
		("/api/read?file=../../../home/user/.ssh/authorized_keys", True, "SSH authorized keys"),
		("/static/../../etc/mysql/my.cnf", True, "MySQL config"),
		("/download?path=../../../var/lib/mysql/", True, "MySQL data directory"),
		("/files/../../../opt/secrets/api_keys.txt", True, "API keys file"),
		("/docs/../../usr/local/etc/nginx.conf", True, "Nginx config"),
		("/api/load?file=../../../sys/class/net/eth0/address", True, "Network MAC address"),
		
		# ═══════════════════════════════════════════════════════════
		# CATEGORY 3: Classic Windows Traversal (Tests 36-50)
		# Expected: True (traversal detected)
		# Standard ..\ patterns on Windows systems
		# ═══════════════════════════════════════════════════════════
		("/download?file=..\\..\\windows\\system32\\config\\sam", True, "Windows SAM file"),
		("/files/..\\..\\..\\windows\\win.ini", True, "Windows INI file"),
		("/api/load?path=..\\..\\windows\\system32\\drivers\\etc\\hosts", True, "Windows hosts file"),
		("/download?file=..\\..\\..\\boot.ini", True, "Boot configuration"),
		("/files/..\\..\\windows\\system32\\config\\system", True, "System registry"),
		("/api/read?path=..\\..\\..\\windows\\system32\\config\\software", True, "Software registry"),
		("/load?file=..\\..\\program files\\app\\config.xml", True, "Program Files config"),
		("/download?path=..\\..\\users\\administrator\\.ssh\\id_rsa", True, "Windows SSH keys"),
		("/files/..\\..\\..\\windows\\system32\\drivers\\etc\\networks", True, "Network config"),
		("/api/load?file=..\\..\\inetpub\\wwwroot\\web.config", True, "IIS web config"),
		("/download?path=..\\..\\windows\\system32\\inetsrv\\config\\applicationHost.config", True, "IIS app config"),
		("/files/..\\..\\..\\windows\\panther\\unattend.xml", True, "Windows unattend"),
		("/api/read?file=..\\..\\windows\\repair\\sam", True, "Windows repair SAM"),
		("/load?path=..\\..\\..\\programdata\\microsoft\\crypto\\rsa\\machinekeys", True, "Machine crypto keys"),
		("/download?file=..\\..\\windows\\system32\\config\\security", True, "Security registry"),
		
		# ═══════════════════════════════════════════════════════════
		# CATEGORY 4: Absolute Paths - Unix (Tests 51-60)
		# Expected: True (sensitive path detected)
		# Direct absolute path references on Unix/Linux
		# ═══════════════════════════════════════════════════════════
		("/api/load?file=/etc/passwd", True, "Direct /etc/passwd"),
		("/download?file=/root/.bashrc", True, "Root bashrc"),
		("/api/read?path=/var/log/syslog", True, "System log"),
		("/files/path=/etc/shadow", True, "Shadow file direct"),
		("/load?file=/proc/version", True, "Kernel version"),
		("/download?path=/etc/ssh/sshd_config", True, "SSH daemon config"),
		("/api/read?file=/home/user/.aws/credentials", True, "AWS credentials"),
		("/files/path=/var/spool/cron/crontabs/root", True, "Root crontab"),
		("/load?file=/etc/sudoers", True, "Sudoers file"),
		("/download?path=/var/log/apache2/access.log", True, "Apache access log"),
		
		# ═══════════════════════════════════════════════════════════
		# CATEGORY 5: Absolute Paths - Windows (Tests 61-70)
		# Expected: True (sensitive path detected)
		# Direct absolute path references on Windows
		# ═══════════════════════════════════════════════════════════
		("/files/C:\\Windows\\System32\\config\\SAM", True, "Windows SAM absolute"),
		("/download?file=C:\\Users\\Administrator\\.ssh\\id_rsa", True, "Admin SSH key"),
		("/api/load?path=C:\\Windows\\System32\\drivers\\etc\\hosts", True, "Windows hosts absolute"),
		("/files/path=C:\\inetpub\\wwwroot\\web.config", True, "IIS web config absolute"),
		("/load?file=D:\\backup\\database\\users.sql", True, "Database backup"),
		("/download?path=C:\\Program Files\\App\\secrets.json", True, "App secrets"),
		("/api/read?file=C:\\Windows\\Panther\\Unattend.xml", True, "Unattend absolute"),
		("/files/path=C:\\ProgramData\\MySQL\\my.ini", True, "MySQL config absolute"),
		("/load?file=E:\\shares\\confidential\\data.xlsx", True, "Network share"),
		("/download?path=C:\\Windows\\System32\\config\\SYSTEM", True, "System registry absolute"),
		
		# ═══════════════════════════════════════════════════════════
		# CATEGORY 6: URL Encoded Traversal (Tests 71-80)
		# Expected: True (encoded traversal detected)
		# URL encoded versions of traversal sequences
		# ═══════════════════════════════════════════════════════════
		("/files/%2e%2e/%2e%2e/etc/passwd", True, "URL encoded ../"),
		("/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", True, "Fully encoded"),
		("/api/load?path=..%2f..%2fetc%2fpasswd", True, "Partially encoded"),
		("/files/%2e%2e%5c%2e%2e%5cwindows", True, "Encoded backslashes"),
		("/download?file=%2e%2e%2froot%2f.ssh", True, "Encoded SSH path"),
		("/api/read?path=%2e%2e%2f%2e%2e%2fvar%2flog", True, "Encoded var log"),
		("/files/%2e%2e/%2e%2e/%2e%2e/etc/shadow", True, "Triple encoded traversal"),
		("/load?file=%2e%2e%5c%2e%2e%5cwindows%5csystem32", True, "Windows encoded"),
		("/download?path=..%2f..%2f..%2fproc%2fself%2fenviron", True, "Proc environ encoded"),
		("/api/load?file=%2e%2e%2f%2e%2e%2fopt%2fsecrets", True, "Opt secrets encoded"),
		
		# ═══════════════════════════════════════════════════════════
		# CATEGORY 7: Case Variations (Tests 81-90)
		# Expected: True (case-insensitive detection)
		# Mixed case attempts to bypass filters
		# ═══════════════════════════════════════════════════════════
		("/files/../../ETC/passwd", True, "Uppercase /ETC/"),
		("/download?file=..\\..\\WINDOWS\\system32", True, "Uppercase WINDOWS"),
		("/api/load?path=/Root/.ssh/id_rsa", True, "Mixed case Root"),
		("/files/../../Var/Log/auth.log", True, "Mixed case Var"),
		("/download?file=C:\\WINDOWS\\System32\\config", True, "Uppercase drive"),
		("/api/read?path=../../../ETC/SHADOW", True, "All caps shadow"),
		("/load?file=/PROC/version", True, "Uppercase proc"),
		("/files/path=..\\..\\Windows\\Win.Ini", True, "Mixed case win.ini"),
		("/download?file=/VAR/WWW/html/.htaccess", True, "Uppercase var www"),
		("/api/load?path=C:\\Program Files\\APP\\Config.xml", True, "Mixed case Program Files"),
		
		# ═══════════════════════════════════════════════════════════
		# CATEGORY 8: Advanced Evasion Techniques (Tests 91-100)
		# Expected: True (evasion attempts detected)
		# Sophisticated bypass attempts
		# ═══════════════════════════════════════════════════════════
		("/files/....//....//etc/passwd", True, "Double dot slash evasion"),
		("/download?file=..;/..;/etc/passwd", True, "Semicolon separator"),
		("/api/load?path=..//..//..//etc/passwd", True, "Extra slashes"),
		("/files/..%00/..%00/etc/passwd", True, "Null byte injection"),
		("/download?file=..\\x00\\..\\x00\\windows", True, "Hex null byte"),
		("/api/read?path=.%2e/.%2e/etc/passwd", True, "Mixed encoding dots"),
		("/load?file=/etc/./passwd", True, "Current directory in absolute"),
		("/files/..//../../etc/passwd", True, "Double slash traversal"),
		("/download?path=..\\\\..\\\\windows\\\\system32", True, "Double backslash"),
		("/api/load?file=%252e%252e%252fetc%252fpasswd", True, "Double URL encoding"),
	]
	
	print(f"{BOLD}Running 100 comprehensive pattern recognition tests...{RESET}\n")
	
	for i, (url_path, expected, description) in enumerate(test_cases, 1):
		try:
			result = contains_path_traversal(url_path)
			
			# Validate return type
			if not isinstance(result, bool):
				print(f"{RED}✗ Test {i} FAILED{RESET}: {description}")
				print(f"  Path: {url_path}")
				print(f"  Expected: bool, Got: {type(result).__name__}")
				print(f"  {YELLOW}⚠ Function must return True or False{RESET}\n")
				tests_failed += 1
				failed_tests.append((i, description, "Type error"))
				continue
			
			if result == expected:
				print(f"{GREEN}✓ Test {i} PASSED{RESET}: {description}")
				print(f"  Path: {url_path}")
				print(f"  Result: {result} (expected {expected})")
				tests_passed += 1
			else:
				print(f"{RED}✗ Test {i} FAILED{RESET}: {description}")
				print(f"  Path: {url_path}")
				print(f"  Got: {result}, Expected: {expected}")
				if expected:
					print(f"  {YELLOW}⚠ Should detect traversal but didn't{RESET}")
				else:
					print(f"  {YELLOW}⚠ False positive - flagged safe path{RESET}")
				tests_failed += 1
				failed_tests.append((i, description, f"Got {result}, expected {expected}"))
			print()
			
		except Exception as e:
			print(f"{RED}✗ Test {i} CRASHED{RESET}: {description}")
			print(f"  Path: {url_path}")
			print(f"  Error: {str(e)}")
			print(f"  {YELLOW}⚠ Function raised an exception{RESET}\n")
			tests_failed += 1
			failed_tests.append((i, description, f"Exception: {str(e)}"))
	
	# Print summary
	total = tests_passed + tests_failed
	percentage = (tests_passed / total * 100) if total > 0 else 0
	
	print(f"\n{BOLD}{BLUE}{'='*65}{RESET}")
	print(f"{BOLD}TEST SUMMARY{RESET}")
	print(f"{BOLD}{BLUE}{'='*65}{RESET}")
	print(f"Total Tests: {total}")
	print(f"{GREEN}Passed: {tests_passed}{RESET}")
	print(f"{RED}Failed: {tests_failed}{RESET}")
	print(f"Success Rate: {percentage:.1f}%\n")
	
	# Performance feedback
	if percentage == 100:
		print(f"{GREEN}{BOLD}🎉 PERFECT SCORE! 🎉{RESET}")
		print(f"{GREEN}Excellent work! You can now recognize path traversal patterns.{RESET}")
		print(f"\n{BOLD}What you've learned:{RESET}")
		print("  ✓ Classic traversal sequences (../, ..\\)")
		print("  ✓ Sensitive file paths (/etc/, /root/, C:\\Windows)")
		print("  ✓ URL encoding detection (%2e, %2f, %5c)")
		print("  ✓ Case-insensitive pattern matching")
		print("  ✓ Advanced evasion techniques (null bytes, double encoding)")
		print(f"\n{BOLD}Next steps:{RESET}")
		print("  • Practice PortSwigger Directory Traversal labs")
		print("  • Add this to your GitHub portfolio")
		print("  • In Week 8, you'll learn proper PREVENTION with pathlib")
		print("  • Review 'Hacking APIs' Chapter 9 for more attack patterns")
		
	elif percentage >= 80:
		print(f"{GREEN}{BOLD}GREAT WORK!{RESET}")
		print(f"{GREEN}You're recognizing most patterns correctly.{RESET}")
		print(f"\n{BOLD}Review:{RESET}")
		if failed_tests:
			print(f"  Failed tests: {[t[0] for t in failed_tests[:10]]}")
		print(f"\n{YELLOW}Tips:{RESET}")
		print("  • Don't forget to check for ..\\  (Windows)")
		print("  • Use .lower() for case-insensitive matching")
		print("  • URL encoding: %2e = dot, %2f = slash, %5c = backslash")
	
	elif percentage >= 60:
		print(f"{YELLOW}{BOLD}GOOD START!{RESET}")
		print(f"{YELLOW}You're catching basic patterns but missing some variations.{RESET}")
		print(f"\n{BOLD}Focus on:{RESET}")
		print("  1. Check for both ../ AND ..\\ (Unix and Windows)")
		print("  2. Look for sensitive paths: /etc/, /root/, /var/")
		print("  3. Check for URL encoding: %2e%2e%2f")
		print("  4. Use .lower() to handle case variations")
		print(f"\n{YELLOW}Pattern Checklist:{RESET}")
		print("  • '../' in url_path")
		print("  • '..\\\\' in url_path  (need double backslash in Python)")
		print("  • '/etc/' in url_path.lower()")
		print("  • '%2e%2e' in url_path.lower()")
	
	else:
		print(f"{RED}{BOLD}KEEP WORKING!{RESET}")
		print(f"{RED}You're not detecting most traversal patterns yet.{RESET}")
		print(f"\n{BOLD}Start with these patterns:{RESET}")
		print()
		print("  1. Classic traversal:")
		print("     if '../' in url_path:")
		print("         return True")
		print()
		print("  2. Windows traversal:")
		print("     if '..\\\\' in url_path:")
		print("         return True")
		print()
		print("  3. Sensitive paths:")
		print("     if '/etc/' in url_path.lower():")
		print("         return True")
		print()
		print("  4. Combine with 'or':")
		print("     return ('../' in url_path or")
		print("            '..\\\\' in url_path or")
		print("            '/etc/' in url_path.lower())")
		print()
		print(f"{YELLOW}Remember:{RESET}")
		print("  • Use 'in' to check for substrings")
		print("  • Use .lower() for case-insensitive checks")
		print("  • Return True if ANY pattern matches")
	
	print(f"\n{BOLD}{BLUE}{'='*65}{RESET}\n")
	
	if failed_tests and percentage < 100:
		print(f"{BOLD}Failed Test Details:{RESET}")
		for test_num, desc, error in failed_tests[:10]:
			print(f"  • Test {test_num}: {desc}")
			print(f"    {error}")
		if len(failed_tests) > 10:
			print(f"  ... and {len(failed_tests) - 10} more")
		print()


if __name__ == "__main__":
	run_tests()
