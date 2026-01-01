#!/usr/bin/env python3
"""
OS Path Traversal Validator - Production-Grade Challenge
=========================================================

Based on real-world CVEs and attack patterns:
- CVE-2019-3396 (Atlassian Confluence) - $10M+ in damages
- CVE-2022-24765 (Git Path Traversal)
- Zip Slip Vulnerability (Snyk Research, 2018)

References:
- "API Security in Action" by Neil Madden (Chapter 8, pp. 251-254)
- "Full Stack Python Security" by Dennis Byrne (Chapter 6, pp. 123-127)
- "Secure by Design" by Johnsson, Deogun, Sawano (Chapter 7, pp. 189-193)
- "Hacking APIs" by Corey J. Ball (Chapter 4: Common API Vulnerabilities)

Challenge:
----------
Implement is_safe_path() that validates if a requested path stays within
the base directory after canonicalization.

This is NOT pattern matching. This is proper path validation using OS-level
canonicalization to determine where the path ACTUALLY points.

Key Concept:
------------
The OS resolves paths like ../../../etc/passwd into their canonical form.
Your job is to check if that canonical path is still within base_dir.

Example:
--------
base_dir = "/var/www/uploads"
requested_path = "../../etc/passwd"

# After joining and canonicalizing:
# /var/www/uploads/../../etc/passwd → /var/etc/passwd

# /var/etc/passwd is NOT within /var/www/uploads
# Therefore: return False (UNSAFE)
"""

from pathlib import Path
import urllib.parse
import re

def parse_linux(base_dir: str,requested_path: str) -> bool:

	base_stack = []

	request_stack = []

	parsed_request_path = ""

	parsed_base_path = ""

	i = 0

	arg = ""
	
	while i < len(base_dir):

		if base_dir[i] == '/':

			arg = ""

			i += 1

		else:

			while i < len(base_dir) and base_dir[i] != '/':

				arg += base_dir[i]

				i += 1

			if arg == "..":
			
				if len(request_stack) > 0:
					request_stack.pop()
			
			elif arg == "\x2e\x2e":

				if len(request_stack) > 0:
					request_stack.pop()

			elif arg == ".":

				pass

			elif arg == "\x2e":
				
				pass

			else:
				request_stack.append(arg)

		i += 1


	i = 0

	arg = ""

	while i < len(requested_path):

		if requested_path[i] == '/':

			arg = ""

			i += 1

		else:

			while i < len(requested_path) and requested_path[i] != '/':

				arg += requested_path[i]

				i += 1

			if arg == "..":
			
				if len(request_stack) > 0:
					request_stack.pop()
			
			elif arg == "\x2e\x2e":

				if len(request_stack) > 0:
					request_stack.pop()

			elif arg == ".":

				pass

			elif arg == "\x2e":

				pass
			else:
				request_stack.append(arg)

		i += 1

	parsed_request_path += "/"

	for arg in request_stack:

		parsed_request_path += arg

		parsed_request_path += "/"

	print(f"parsed_request_path: {parsed_request_path}")

	return parsed_request_path.find(base_dir) == 0

def parse_windows(base_dir: str,requested_path: str) -> bool:

	base_stack = []

	request_stack = []

	parsed_request_path = ""

	parsed_base_path = ""

	i = 0

	arg = ""
	
	while i < len(base_dir):

		if base_dir[i] == '\\':

			arg = ""

			i += 1

		else:

			while i < len(base_dir) and base_dir[i] != '\\':

				arg += base_dir[i]

				i += 1

			if arg == "..":
			
				if len(request_stack) > 0:
					request_stack.pop()
			
			elif arg == "\x2e\x2e":

				if len(request_stack) > 0:
					request_stack.pop()

			elif arg == ".":

				i += 1

				continue

			elif arg == "\x2e":

				i += 1

				continue

			else:
				request_stack.append(arg)

		i += 1


	i = 0

	arg = ""

	while i < len(requested_path):

		if requested_path[i] == '\\':

			arg = ""

			i += 1

		else:

			while i < len(requested_path) and requested_path[i] != '\\':

				arg += requested_path[i]

				i += 1

			if arg == "..":
			
				if len(request_stack) > 0:
					request_stack.pop()
			
			elif arg == "\x2e\x2e":

				if len(request_stack) > 0:
					request_stack.pop()

			elif arg == ".":

				i += 1

				continue

			elif arg == "\x2e":

				i += 1

				continue

			else:
				request_stack.append(arg)

		i += 1


	for arg in request_stack:

		parsed_request_path += arg

		parsed_request_path += "/"

	return parsed_request_path.find(base_dir) == 0


def is_safe_path(base_dir: str, requested_path: str) -> bool:
	"""Validate if requested_path stays within base_dir after canonicalization.

	This uses OS-level path resolution to determine the actual destination,
	then checks if it's still within the allowed base directory.

	Args:
		base_dir: The root directory (e.g., "/var/www/uploads")
		requested_path: User-provided path (may contain ../, absolute paths, etc.)

	Returns:
		True if the path is safe (stays within base_dir)
		False if it's a path traversal attack (escapes base_dir)

	Security Properties:
		- Immune to ../ traversal (handled by canonicalization)
		- Immune to URL encoding (OS decodes)
		- Immune to symlink attacks (resolve() follows symlinks)
		- Works on both Unix and Windows
		- Handles absolute paths correctly

	Examples:
		>>> is_safe_path("/var/www/uploads", "images/logo.png")
		True  # Safe: /var/www/uploads/images/logo.png

		>>> is_safe_path("/var/www/uploads", "../../etc/passwd")
		False  # Attack: /var/etc/passwd (escapes base_dir)

		>>> is_safe_path("/var/www/uploads", "/etc/passwd")
		False  # Attack: /etc/passwd (absolute path escape)

	Implementation Hints:
		- Use Path.resolve() to canonicalize paths
		- Path.resolve() converts to absolute, resolves ../, follows symlinks
		- Check if canonical path starts with canonical base_dir
		- Handle edge cases: empty paths, null bytes, etc.
	"""
	expanded_path = urllib.parse.unquote(requested_path)

	while re.search(r'%[0-9a-fA-F][0-9a-fA-F]',expanded_path) != None:

		expanded_path = urllib.parse.unquote(expanded_path)

	if ":\\" in base_dir:

		return parse_windows(base_dir,expanded_path)

	else:
		return parse_linux(base_dir,expanded_path)


# ============================================================================
# TEST SUITE - 100 Real-World Attack Patterns
# ============================================================================

def run_tests():
	"""Execute all 100 test cases with detailed feedback."""

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
	print(f"{BOLD}{BLUE}║     OS PATH TRAVERSAL VALIDATOR - 100 Production Tests      ║{RESET}")
	print(f"{BOLD}{BLUE}║   Based on CVE-2019-3396, CVE-2022-24765, and Zip Slip       ║{RESET}")
	print(f"{BOLD}{BLUE}╚═══════════════════════════════════════════════════════════════╝{RESET}\n")

	test_cases = [
		# ═══════════════════════════════════════════════════════════
		# CATEGORY 1: Safe Paths (Tests 1-25)
		# Expected: True (these should be ALLOWED)
		# Normal legitimate file access within base directory
		# Various base paths to test different scenarios
		# ═══════════════════════════════════════════════════════════
		("/var/www/uploads", "images/logo.png", True, "Normal file access"),
		("/home/alice/documents", "projects/proposal.docx", True, "User home directory"),
		("/opt/application/data", "reports/2024/Q1/sales.pdf", True, "Deep nested path"),
		("/app/static", "css/bootstrap.min.css", True, "Static resource"),
		("/tmp/processing", "batch_123/results.json", True, "Temp processing"),
		("/mnt/storage/backups", "database/daily/backup.sql", True, "Backup storage"),
		("/usr/local/webapp/cache", "thumbnails/user_456.png", True, "Cache directory"),
		("/home/bob/projects/myapp", "src/main.py", True, "Source code"),
		("/data/uploads", "2024/12/invoice_001.pdf", True, "Date-organized uploads"),
		("/srv/www/public", "media/videos/tutorial.mp4", True, "Public media"),
		("/var/lib/app/files", "exports/monthly_report.xlsx", True, "Application files"),
		("/home/charlie/Downloads", "software/installer.exe", True, "Downloads folder"),
		("/opt/myapp/assets", "fonts/roboto/regular.woff2", True, "Application assets"),
		("/var/spool/app/queue", "jobs/pending/task_789.json", True, "Job queue"),
		("/mnt/shared/documents", "legal/contracts/NDA.pdf", True, "Shared storage"),
		("/home/dave/workspace", "project/README.md", True, "Workspace directory"),
		("/app/user_data", "profiles/alice/avatar.jpg", True, "User profiles"),
		("/var/cache/webapp", "sessions/active/sess_xyz.dat", True, "Session cache"),
		("/usr/share/app/templates", "email/welcome.html", True, "Template directory"),
		("/data/archives", "2023/yearly/archive.tar.gz", True, "Archive storage"),
		("/home/eve/Pictures", "vacation/2024/beach.jpg", True, "Personal pictures"),
		("/opt/service/logs", "application/2024-12-22.log", True, "Service logs"),
		("/var/tmp/uploads", "processing/image_resize_queue.tmp", True, "Temp uploads"),
		("/mnt/backup/hourly", "databases/postgres/dump.sql", True, "Hourly backups"),
		("/srv/ftp/public", "releases/v2.0.1/package.zip", True, "FTP public directory"),

		# ═══════════════════════════════════════════════════════════
		# CATEGORY 2: Classic Unix Traversal (Tests 26-40)
		# Expected: False (path traversal attacks)
		# Standard ../ sequences attempting to escape base_dir
		# Varying base paths and attack targets
		# ═══════════════════════════════════════════════════════════
		("/var/www/uploads", "../../../etc/passwd", False, "Classic triple traversal"),
		("/home/alice/documents", "../../bob/.ssh/id_rsa", False, "Access other user's SSH key"),
		("/app/data", "../../../../etc/shadow", False, "Shadow file from /app"),
		("/opt/webapp/files", "../../../var/log/auth.log", False, "Auth log from /opt"),
		("/tmp/uploads", "../../etc/hosts", False, "Hosts file from /tmp"),
		("/usr/local/app/data", "../../../../proc/self/environ", False, "Proc environ from /usr/local"),
		("/mnt/storage/files", "../../../etc/crontab", False, "Cron from mounted storage"),
		("/home/charlie/projects", "../../dave/.bash_history", False, "Access neighbor's bash history"),
		("/var/lib/app", "../../../etc/mysql/my.cnf", False, "MySQL config from /var/lib"),
		("/srv/ftp/uploads", "../../../../root/.ssh/authorized_keys", False, "Root SSH keys from FTP"),
		("/data/temp", "../../../etc/ssh/sshd_config", False, "SSH config from /data"),
		("/home/eve/uploads", "../../frank/.aws/credentials", False, "AWS creds from home"),
		("/opt/service/logs", "../../../var/lib/mysql/ibdata1", False, "MySQL data from service"),
		("/var/cache/app", "../../../../opt/secrets/api_keys.txt", False, "API keys from cache"),
		("/usr/share/nginx/html", "../../../etc/nginx/nginx.conf", False, "Nginx config from webroot"),

		# ═══════════════════════════════════════════════════════════
		# CATEGORY 3: Absolute Path Attacks (Tests 41-60)
		# Expected: False (direct absolute paths)
		# Bypassing base_dir entirely with absolute paths
		# Different base directories being bypassed
		# Mix of Unix and Windows absolute paths
		# ═══════════════════════════════════════════════════════════
		("/var/www/uploads", "/etc/passwd", False, "Direct /etc/passwd from webroot"),
		("/home/alice/docs", "/etc/shadow", False, "Direct shadow from home"),
		("/app/files", "/root/.ssh/id_rsa", False, "Direct SSH key from /app"),
		("/opt/webapp/data", "/var/log/syslog", False, "Direct syslog from /opt"),
		("/tmp/processing", "/proc/version", False, "Kernel version from /tmp"),
		("/mnt/storage/files", "/etc/ssh/sshd_config", False, "SSH config from mount"),
		("/usr/local/app/uploads", "/home/bob/.aws/credentials", False, "AWS creds from /usr/local"),
		("/var/lib/service/data", "/var/spool/cron/crontabs/root", False, "Root cron from /var/lib"),
		("/srv/www/files", "/etc/sudoers", False, "Sudoers from /srv"),
		("/home/charlie/projects", "/var/log/apache2/access.log", False, "Apache log from home"),
		# Windows absolute paths
		("C:\\inetpub\\wwwroot", "C:\\Windows\\System32\\config\\SAM", False, "Absolute SAM path"),
		("C:\\Users\\Alice\\uploads", "C:\\Windows\\win.ini", False, "Absolute Windows INI"),
		("D:\\app\\data", "C:\\Users\\Administrator\\.ssh\\id_rsa", False, "Absolute admin SSH"),
		("C:\\Program Files\\MyApp", "C:\\Windows\\Panther\\Unattend.xml", False, "Absolute Unattend"),
		("E:\\temp\\files", "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys", False, "Absolute machine keys"),
		("/data/uploads", "/etc/mysql/my.cnf", False, "MySQL config from /data"),
		("/var/cache/webapp", "/root/.bashrc", False, "Root bashrc from cache"),
		("/opt/service/files", "/proc/self/cmdline", False, "Process cmdline from service"),
		("/usr/share/app/data", "/sys/class/net/eth0/address", False, "MAC from /usr/share"),
		("/home/dave/workspace", "/var/lib/postgresql/data/", False, "PostgreSQL from workspace"),

		# ═══════════════════════════════════════════════════════════
		# CATEGORY 4: Relative Traversal from Subdirectory (Tests 61-65)
		# Expected: False (traversal from within valid subdirectory)
		# Attackers start in a valid subdirectory, then traverse out
		# ═══════════════════════════════════════════════════════════
		("/var/www/html", "images/../../etc/passwd", False, "Traversal from images/"),
		("/home/alice/projects", "myapp/src/../../../bob/.ssh/id_rsa", False, "Deep traversal from src/"),
		("/opt/application/data", "reports/Q4/../../../../etc/shadow", False, "Quarterly report traversal"),
		("/app/user_files", "uploads/temp/../../../../../../var/log/auth.log", False, "Multi-level escape"),
		("C:\\inetpub\\wwwroot", "images\\..\\..\\..\\Windows\\System32\\config", False, "Windows IIS traversal"),

		# ═══════════════════════════════════════════════════════════
		# CATEGORY 5: URL-Encoded Traversal (Tests 66-75)
		# Expected: True (Path treats encoded chars as literals)
		# Note: Python's Path handles these as literal characters
		# In production, framework decodes BEFORE calling your validator
		# Various base paths testing encoded inputs
		# ═══════════════════════════════════════════════════════════
		("/var/www/uploads", "images/logo%2Epng", True, "Literal %2E in filename"),
		("/home/alice/files", "document%2Fpdf", True, "Literal %2F in filename"),
		("/app/data", "report%5Cxlsx", True, "Literal %5C in filename"),
		("/opt/webapp/files", "%2e%2e%2fetc%2fpasswd", True, "Fully encoded (literal)"),
		("/tmp/uploads", "..%2f..%2fetc%2fpasswd", True, "Mixed encoding (literal)"),
		("/data/processing", "%252e%252e%252fetc%252fpasswd", True, "Double encoded (literal)"),
		("/usr/local/app/files", "images%2flogo%2epng", True, "Path with encoded separators"),
		("/mnt/storage/data", "%2e%2e%5cetc%5cpasswd", True, "Windows encoded (literal)"),
		("/srv/ftp/public", "file%00%2etxt", True, "Null byte encoded (literal)"),
		("/var/lib/app/files", "%2e%2e%2f%2e%2e%2fvar%2flog", True, "Log path encoded"),

		# ═══════════════════════════════════════════════════════════
		# CATEGORY 6: Null Byte Injection (Tests 76-80)
		# Expected: False (invalid paths)
		# Null bytes should be rejected
		# Testing from different base directories
		# ═══════════════════════════════════════════════════════════
		("/var/www/uploads", "image.png\x00../../etc/passwd", False, "Null byte traversal"),
		("/home/alice/files", "report.pdf\x00../../etc/shadow", False, "Null byte in home dir"),
		("/app/data", "file.txt\x00.php", False, "Null byte extension bypass"),
		("/opt/webapp/uploads", "document\x00../../root/.ssh/id_rsa", False, "Null byte SSH attack"),
		("/tmp/files", "\x00../../var/log/auth.log", False, "Leading null byte attack"),

		# ═══════════════════════════════════════════════════════════
		# CATEGORY 7: Linux System Files (Tests 81-85)
		# Expected: False (sensitive system paths)
		# Real targets from actual attacks
		# Testing from various application directories
		# ═══════════════════════════════════════════════════════════
		("/var/www/html", "../../../../proc/self/environ", False, "Env vars from webroot"),
		("/home/alice/uploads", "../../../../sys/class/net/eth0/address", False, "MAC from home"),
		("/opt/application/files", "../../../../../root/.ssh/id_rsa", False, "Root SSH from /opt"),
		("/app/user_data", "../../../../proc/self/cmdline", False, "Process cmdline from /app"),
		("/data/processing", "../../../dev/urandom", False, "Random device from /data"),

		# ═══════════════════════════════════════════════════════════
		# CATEGORY 8: Windows System Files (Tests 86-95)
		# Expected: False (Windows sensitive paths)
		# Windows-specific attack targets from various directories
		# Using proper Windows paths with backslashes for base_dir
		# ═══════════════════════════════════════════════════════════
		("C:\\inetpub\\wwwroot\\uploads", "..\\..\\..\\Windows\\System32\\config\\SAM", False, "SAM from IIS webroot"),
		("C:\\Users\\Alice\\Documents", "..\\..\\..\\Windows\\win.ini", False, "Win.ini from user docs"),
		("D:\\app\\files", "..\\..\\boot.ini", False, "Boot.ini from D: drive"),
		("C:\\Program Files\\MyApp\\data", "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts", False, "Hosts from Program Files"),
		("E:\\uploads\\temp", "..\\..\\..\\Windows\\Panther\\Unattend.xml", False, "Unattend from E: drive"),
		("C:\\xampp\\htdocs\\uploads", "..\\..\\..\\Windows\\System32\\config\\SYSTEM", False, "SYSTEM registry from XAMPP"),
		("C:\\Users\\Bob\\Desktop\\files", "..\\..\\..\\Users\\Administrator\\.ssh\\id_rsa", False, "Admin SSH from Desktop"),
		("D:\\websites\\public", "..\\..\\ProgramData\\MySQL\\my.ini", False, "MySQL config from D: drive"),
		("C:\\temp\\processing", "..\\..\\Windows\\repair\\SAM", False, "Repair SAM from temp"),
		("C:\\webapp\\user_uploads", "..\\..\\..\\Windows\\System32\\inetsrv\\config\\applicationHost.config", False, "IIS config from webapp"),

		# ═══════════════════════════════════════════════════════════
		# CATEGORY 9: CVE-Inspired Patterns (Tests 96-100)
		# Expected: False (real CVE patterns)
		# From actual disclosed vulnerabilities
		# Testing from various application directories
		# ═══════════════════════════════════════════════════════════
		("/var/www/html", "..;/..;/etc/passwd", False, "CVE-2019-3396 (Confluence)"),
		("/home/alice/repo", ".git/../../../etc/shadow", False, "CVE-2022-24765 (Git)"),
		("/opt/application/temp", "../../../../tmp/malicious.sh", False, "Zip Slip attack"),
		("/app/uploads", "....//....//etc/passwd", False, "Confluence double dot slash"),
		("/data/files", "..//..//..//var/log/auth.log", False, "Double slash traversal"),
	]

	print(f"{BOLD}Running 100 production-grade security tests...{RESET}\n")

	for i, (base, requested, expected, description) in enumerate(test_cases, 1):
		try:
			result = is_safe_path(base, requested)

			# Validate return type
			if not isinstance(result, bool):
				print(f"{RED}✗ Test {i} FAILED{RESET}: {description}")
				print(f"  Base: {base}")
				print(f"  Requested: {requested}")
				print(f"  Expected: bool, Got: {type(result).__name__}")
				print(f"  {YELLOW}⚠ Function must return True or False{RESET}\n")
				tests_failed += 1
				failed_tests.append((i, description, "Type error"))
				continue

			if result == expected:
				print(f"{GREEN}✓ Test {i} PASSED{RESET}: {description}")
				print(f"  Requested: {requested}")
				print(f"  Result: {result} (expected {expected})")
				tests_passed += 1
			else:
				print(f"{RED}✗ Test {i} FAILED{RESET}: {description}")
				print(f"  Base: {base}")
				print(f"  Requested: {requested}")
				print(f"  Got: {result}, Expected: {expected}")
				if expected:
					print(f"  {YELLOW}⚠ Should be safe but flagged as attack{RESET}")
				else:
					print(f"  {YELLOW}⚠ Should block attack but allowed access!{RESET}")
				tests_failed += 1
				failed_tests.append((i, description, f"Got {result}, expected {expected}"))
			print()

		except Exception as e:
			print(f"{RED}✗ Test {i} CRASHED{RESET}: {description}")
			print(f"  Base: {base}")
			print(f"  Requested: {requested}")
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
		print(f"{GREEN}{BOLD}🎉 PERFECT! ALL 100 TESTS PASSED! 🎉{RESET}")
		print(f"\n{GREEN}Your path validator is PRODUCTION-READY! 🛡️{RESET}\n")
		print(f"{BOLD}You've successfully defended against:{RESET}")
		print(f"  ✅ Classic path traversal attacks (../, /etc/passwd)")
		print(f"  ✅ Absolute path bypasses")
		print(f"  ✅ Null byte injection attempts")
		print(f"  ✅ Linux system file access (/proc, /sys, /dev)")
		print(f"  ✅ Windows system file access (SAM, win.ini, etc.)")
		print(f"  ✅ Real-world CVE patterns (Git, Confluence, Zip Slip)")
		print(f"\n{BOLD}Next steps:{RESET}")
		print(f"  • Add this to your GitHub portfolio")
		print(f"  • Review the CVEs: CVE-2019-3396, CVE-2022-24765")
		print(f"  • Practice on PortSwigger Directory Traversal labs")
		print(f"  • Apply this technique in production code reviews")

	elif percentage >= 80:
		print(f"{GREEN}{BOLD}EXCELLENT WORK!{RESET}")
		print(f"{GREEN}You're handling most attack patterns correctly.{RESET}")
		print(f"\n{BOLD}Minor issues to fix:{RESET}")
		if failed_tests:
			print(f"  Failed tests: {[t[0] for t in failed_tests[:10]]}")
		print(f"\n{YELLOW}Common mistakes:{RESET}")
		print(f"  • Are you canonicalizing BOTH base_dir and requested_path?")
		print(f"  • Are you handling null bytes (\\x00)?")
		print(f"  • Are you checking if canonical path starts with canonical base?")

	elif percentage >= 60:
		print(f"{YELLOW}{BOLD}GOOD PROGRESS!{RESET}")
		print(f"{YELLOW}You understand the basics but missing key security checks.{RESET}")
		print(f"\n{BOLD}Core algorithm:{RESET}")
		print(f"  1. Canonicalize base_dir: Path(base_dir).resolve()")
		print(f"  2. Join paths: base / requested_path")
		print(f"  3. Canonicalize result: (base / requested).resolve()")
		print(f"  4. Check if result is still within base")
		print(f"\n{YELLOW}Key insight:{RESET}")
		print(f"  Use Path.resolve() - it handles:")
		print(f"  • Converting to absolute paths")
		print(f"  • Resolving ../ and ./ sequences")
		print(f"  • Following symlinks")
		print(f"  • Normalizing path separators")

	else:
		print(f"{RED}{BOLD}NEEDS SIGNIFICANT WORK{RESET}")
		print(f"{RED}The implementation is missing core security logic.{RESET}")
		print(f"\n{BOLD}Start with this algorithm:{RESET}")
		print()
		print(f"  from pathlib import Path")
		print()
		print(f"  def is_safe_path(base_dir, requested_path):")
		print(f"      # Step 1: Canonicalize base directory")
		print(f"      base = Path(base_dir).resolve()")
		print()
		print(f"      # Step 2: Join with requested path and canonicalize")
		print(f"      target = (base / requested_path).resolve()")
		print()
		print(f"      # Step 3: Check if target is still within base")
		print(f"      try:")
		print(f"          target.relative_to(base)")
		print(f"          return True  # Safe")
		print(f"      except ValueError:")
		print(f"          return False  # Escaped base_dir")
		print()
		print(f"\n{YELLOW}Study:{RESET}")
		print(f"  • Python pathlib documentation")
		print(f"  • 'API Security in Action' Chapter 8")
		print(f"  • OWASP Path Traversal guide")

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
