#!/usr/bin/env python3
"""
Secure File Access - Path Traversal PREVENTION Exercise
========================================================

Inspired by:
- "API Security in Action" by Neil Madden, Chapter 2, page 50
  ("PRINCIPLE: Always define acceptable inputs rather than unacceptable ones 
  when validating untrusted input. An allow list describes exactly which inputs 
  are considered valid and rejects anything else.")
  
- "Full Stack Python Security" by Dennis Byrne, Chapter 14, page 218
  ("Input sanitization is always a bad idea because it is too difficult to 
  implement... Blocklists can lead to security flaws if you fail to anticipate 
  every possible malicious input.")
  
- "Secure by Design" by Johnsson, Deogun, Sawano, Chapter 5
  (Domain primitives and validation principles)

Challenge:
----------
Implement secure file access that PREVENTS path traversal attacks using
industry-standard techniques:

1. PATH CANONICALIZATION - Convert paths to absolute canonical form
2. DIRECTORY CONFINEMENT - Verify paths stay within allowed directory
3. ALLOWLIST VALIDATION - Optional whitelist of permitted files

This is what production AppSec code actually looks like - NOT pattern matching!

Real-World Context:
-------------------
When developers write code like this:

    def download_file(filename):
        path = f"/var/app/data/{filename}"
        return open(path, 'rb').read()  # ❌ VULNERABLE!

Attackers can exploit it:
    
    filename = "../../etc/passwd"
    → Opens: /var/app/data/../../etc/passwd
    → Resolves to: /etc/passwd
    → Result: Password file leaked!

Your mission is to implement the SECURE version using path canonicalization.

Key Concepts:
-------------
1. **Canonicalization** - Converting paths to their "canonical" (standard) form:
   - Resolves relative references (../, ./)
   - Converts to absolute paths
   - Resolves symlinks
   - Removes redundant separators
   
   Example:
   /var/app/../etc/./passwd → /etc/passwd (canonical form)

2. **Directory Confinement** - Ensuring the canonical path is within allowed directory:
   - Base directory: /var/app/data
   - User input: reports/2024.pdf
   - Canonical path: /var/app/data/reports/2024.pdf ✓
   - Is within base? YES → Allow
   
   - User input: ../../etc/passwd  
   - Canonical path: /etc/passwd ✓
   - Is within base? NO → Block!

3. **Allowlist (Optional)** - Explicitly list permitted files:
   - Allowed: {"report.pdf", "invoice.xlsx", "summary.csv"}
   - Request: "report.pdf" → Allow
   - Request: "secrets.txt" → Block (not in allowlist)

Defense in Depth:
-----------------
This implements multiple security layers:
- Layer 1: Allowlist (if provided) - Blocks unknown files
- Layer 2: Canonicalization - Resolves actual path
- Layer 3: Confinement check - Verifies within base directory
- Layer 4: Existence check - Verifies file exists

Even if one layer fails, others protect the system.

from pathlib import Path
from typing import Optional, Set


def secure_file_access(
	base_directory: str,
	user_provided_path: str,
	allowed_files: Optional[Set[str]] = None
) -> Path:
	\"\"\"
	Securely resolve a user-provided file path within a base directory.
	
	This function implements defense-in-depth against path traversal:
	1. Allowlist validation (if provided) - Rejects unlisted files
	2. Path canonicalization - Resolves to absolute path
	3. Directory confinement - Ensures path stays within base_directory
	4. Existence verification - Confirms file actually exists
	
	Args:
		base_directory: Root directory for file access (e.g., "/var/app/data")
		user_provided_path: User input that may contain traversal attempts
		allowed_files: Optional set of explicitly permitted filenames
	
	Returns:
		Canonical Path object pointing to the safe file
	
	Raises:
		ValueError: If path traversal detected or file not in allowlist
		FileNotFoundError: If the resolved path doesn't exist
	
	Security Properties:
		- Immune to ../ traversal attacks
		- Immune to absolute path attacks (/etc/passwd)
		- Immune to symlink attacks (if symlink points outside base_directory)
		- Immune to URL-encoded attacks (%2e%2e%2f)
		- Immune to null byte attacks (path%00.txt)
		- Works on both Unix and Windows
	
	Examples:
		>>> secure_file_access("/var/app/data", "reports/2024.pdf")
		Path('/var/app/data/reports/2024.pdf')
		
		>>> secure_file_access("/var/app/data", "../../etc/passwd")
		ValueError: Path traversal attempt detected
		
		>>> secure_file_access("/var/app/data", "report.pdf", {"report.pdf"})
		Path('/var/app/data/report.pdf')
		
		>>> secure_file_access("/var/app/data", "secret.txt", {"report.pdf"})
		ValueError: File not in allowlist
	\"\"\"
	pass


# ============================================================================
# TEST SUITE - 60 Comprehensive Tests
# ============================================================================

def run_all_tests():
	\"\"\"Execute all 60 test cases with detailed feedback.\"\"\"
	
	import tempfile
	import os
	from pathlib import Path
	
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
	print(f"{BOLD}{BLUE}║     SECURE FILE ACCESS - PATH TRAVERSAL PREVENTION           ║{RESET}")
	print(f"{BOLD}{BLUE}║                     60 Test Cases                             ║{RESET}")
	print(f"{BOLD}{BLUE}╚═══════════════════════════════════════════════════════════════╝{RESET}\n")
	
	# Create temporary test directory structure
	with tempfile.TemporaryDirectory() as tmpdir:
		base_dir = Path(tmpdir) / "app_data"
		base_dir.mkdir()
		
		# Create test files and directories
		(base_dir / "reports").mkdir()
		(base_dir / "reports" / "2024.pdf").touch()
		(base_dir / "reports" / "summary.csv").touch()
		(base_dir / "exports").mkdir()
		(base_dir / "exports" / "data.xlsx").touch()
		(base_dir / "public").mkdir()
		(base_dir / "public" / "index.html").touch()
		(base_dir / "readme.txt").touch()
		(base_dir / "config.ini").touch()
		
		# Create a file outside base_dir for testing
		outside_file = Path(tmpdir) / "etc" / "passwd"
		outside_file.parent.mkdir(parents=True, exist_ok=True)
		outside_file.touch()
		
		# Create a symlink attack scenario (if platform supports it)
		try:
			symlink_path = base_dir / "link_to_etc"
			symlink_path.symlink_to(outside_file.parent)
		except (OSError, NotImplementedError):
			symlink_path = None
		
		base_dir_str = str(base_dir)
		
		test_cases = [
			# ═══════════════════════════════════════════════════════════
			# CATEGORY 1: Normal File Access (Tests 1-10)
			# Expected: SUCCESS - These should all work
			# ═══════════════════════════════════════════════════════════
			(base_dir_str, "readme.txt", None, True, "Normal file in root"),
			(base_dir_str, "reports/2024.pdf", None, True, "File in subdirectory"),
			(base_dir_str, "reports/summary.csv", None, True, "Another subdirectory file"),
			(base_dir_str, "exports/data.xlsx", None, True, "File in different subdirectory"),
			(base_dir_str, "public/index.html", None, True, "Public resource"),
			(base_dir_str, "./readme.txt", None, True, "Current directory reference"),
			(base_dir_str, "reports/../readme.txt", None, True, "Relative path that stays inside"),
			(base_dir_str, "reports/./2024.pdf", None, True, "Current directory in path"),
			(base_dir_str, "reports/../reports/2024.pdf", None, True, "Redundant navigation"),
			(base_dir_str, "reports//2024.pdf", None, True, "Extra slashes (should normalize)"),
			
			# ═══════════════════════════════════════════════════════════
			# CATEGORY 2: Classic Path Traversal Attacks (Tests 11-20)
			# Expected: BLOCKED - All should raise ValueError
			# ═══════════════════════════════════════════════════════════
			(base_dir_str, "../etc/passwd", None, False, "Classic Unix traversal"),
			(base_dir_str, "../../etc/passwd", None, False, "Multiple traversal"),
			(base_dir_str, "../../../etc/passwd", None, False, "Deep traversal"),
			(base_dir_str, "reports/../../etc/passwd", None, False, "Traversal after valid path"),
			(base_dir_str, "reports/../../../etc/passwd", None, False, "Deep traversal from subdir"),
			(base_dir_str, "..\\..\\etc\\passwd", None, False, "Windows-style traversal"),
			(base_dir_str, "reports\\..\\..\\etc\\passwd", None, False, "Windows mixed traversal"),
			(base_dir_str, "./../etc/passwd", None, False, "Current dir then traversal"),
			(base_dir_str, "reports/.././../etc/passwd", None, False, "Complex traversal"),
			(base_dir_str, "../" * 10 + "etc/passwd", None, False, "Excessive traversal"),
			
			# ═══════════════════════════════════════════════════════════
			# CATEGORY 3: Absolute Path Attacks (Tests 21-30)
			# Expected: BLOCKED - Absolute paths should be rejected
			# ═══════════════════════════════════════════════════════════
			(base_dir_str, "/etc/passwd", None, False, "Absolute Unix path"),
			(base_dir_str, "/var/log/auth.log", None, False, "Absolute path to logs"),
			(base_dir_str, "/root/.ssh/id_rsa", None, False, "Absolute path to SSH keys"),
			(base_dir_str, str(outside_file), None, False, "Absolute path to known external file"),
			(base_dir_str, "C:\\Windows\\System32\\config\\SAM", None, False, "Absolute Windows path"),
			(base_dir_str, "C:\\Users\\Administrator\\.ssh\\id_rsa", None, False, "Windows SSH key path"),
			(base_dir_str, "/proc/self/environ", None, False, "Linux process environment"),
			(base_dir_str, "/sys/class/net/eth0/address", None, False, "System info path"),
			(base_dir_str, "//etc/passwd", None, False, "Double slash absolute"),
			(base_dir_str, "\\\\server\\share\\file.txt", None, False, "UNC path attempt"),
			
			# ═══════════════════════════════════════════════════════════
			# CATEGORY 4: Allowlist Validation (Tests 31-40)
			# Expected: Mixed - Only allowlisted files should succeed
			# ═══════════════════════════════════════════════════════════
			(base_dir_str, "readme.txt", {"readme.txt", "config.ini"}, True, "File in allowlist"),
			(base_dir_str, "config.ini", {"readme.txt", "config.ini"}, True, "Another allowlisted file"),
			(base_dir_str, "reports/2024.pdf", {"readme.txt"}, False, "File not in allowlist"),
			(base_dir_str, "exports/data.xlsx", {"readme.txt", "config.ini"}, False, "Subdirectory file not allowlisted"),
			(base_dir_str, "readme.txt", set(), False, "Empty allowlist blocks everything"),
			(base_dir_str, "reports/2024.pdf", {"reports/2024.pdf"}, True, "Full path in allowlist"),
			(base_dir_str, "public/index.html", {"public/index.html"}, True, "Nested file allowlisted"),
			(base_dir_str, "../etc/passwd", {"readme.txt"}, False, "Traversal blocked even with allowlist"),
			(base_dir_str, "reports/2024.pdf", {"2024.pdf"}, False, "Basename match shouldn't work"),
			(base_dir_str, "README.TXT", {"readme.txt"}, False, "Case sensitivity in allowlist"),
			
			# ═══════════════════════════════════════════════════════════
			# CATEGORY 5: URL Encoding & Special Characters (Tests 41-50)
			# Expected: Mixed - Depends on implementation
			# Note: Path() handles URL encoding implicitly through OS
			# ═══════════════════════════════════════════════════════════
			(base_dir_str, "readme.txt%00.pdf", None, False, "Null byte in filename"),
			(base_dir_str, "reports%2F2024.pdf", None, False, "URL encoded slash (literal %)"),
			(base_dir_str, "../etc/passwd%00", None, False, "Null byte after traversal"),
			(base_dir_str, "readme\x00.txt", None, False, "Actual null byte character"),
			(base_dir_str, "reports/../readme.txt", None, True, "Clean traversal within bounds"),
			(base_dir_str, "reports/./2024.pdf", None, True, "Current dir reference"),
			(base_dir_str, "reports\\2024.pdf", None, True, "Backslash on Unix (literal char)"),
			(base_dir_str, "readme\ttab.txt", None, False, "Tab character in filename"),
			(base_dir_str, "readme\nnewline.txt", None, False, "Newline in filename"),
			(base_dir_str, "readme<script>.txt", None, False, "Special HTML chars in filename"),
			
			# ═══════════════════════════════════════════════════════════
			# CATEGORY 6: Edge Cases & Platform Differences (Tests 51-60)
			# Expected: Mixed - Testing boundary conditions
			# ═══════════════════════════════════════════════════════════
			(base_dir_str, "", None, False, "Empty path"),
			(base_dir_str, ".", None, False, "Current directory only"),
			(base_dir_str, "..", None, False, "Parent directory only"),
			(base_dir_str, "nonexistent.txt", None, False, "File doesn't exist"),
			(base_dir_str, "reports/nonexistent.pdf", None, False, "Nonexistent in subdir"),
			(base_dir_str, "reports", None, False, "Directory instead of file"),
			(base_dir_str, "readme.txt/", None, False, "Trailing slash on file"),
			(base_dir_str, "/readme.txt", None, False, "Leading slash (absolute)"),
			(base_dir_str, "reports/../exports/../readme.txt", None, True, "Complex but valid path"),
			(base_dir_str, " readme.txt", None, False, "Leading whitespace in filename"),
		]
		
		# Add symlink test if platform supports it
		if symlink_path:
			test_cases.insert(25, (
				base_dir_str,
				"link_to_etc/passwd",
				None,
				False,
				"Symlink escape attempt"
			))
		
		print(f"{BOLD}Running 60 comprehensive security tests...{RESET}\n")
		
		for i, (base, user_path, allowlist, should_succeed, description) in enumerate(test_cases[:60], 1):
			try:
				result = secure_file_access(base, user_path, allowlist)
				
				# Validate return type
				if not isinstance(result, Path):
					print(f"{RED}✗ Test {i} FAILED{RESET}: {description}")
					print(f"  Base: {base}")
					print(f"  User path: {user_path}")
					print(f"  Expected: Path object, Got: {type(result).__name__}")
					print(f"  {YELLOW}⚠ Function must return a Path object{RESET}\n")
					tests_failed += 1
					failed_tests.append((i, description, "Wrong return type"))
					continue
				
				if should_succeed:
					# Should have succeeded and did
					print(f"{GREEN}✓ Test {i} PASSED{RESET}: {description}")
					print(f"  User path: {user_path}")
					print(f"  Resolved to: {result}")
					print(f"  {GREEN}Correctly allowed safe access{RESET}")
					tests_passed += 1
				else:
					# Should have blocked but didn't
					print(f"{RED}✗ Test {i} FAILED{RESET}: {description}")
					print(f"  User path: {user_path}")
					print(f"  Resolved to: {result}")
					print(f"  {YELLOW}⚠ Should have raised ValueError but allowed access!{RESET}")
					tests_failed += 1
					failed_tests.append((i, description, f"Should block but returned {result}"))
				print()
				
			except (ValueError, FileNotFoundError) as e:
				if not should_succeed:
					# Should have blocked and did
					print(f"{GREEN}✓ Test {i} PASSED{RESET}: {description}")
					print(f"  User path: {user_path}")
					print(f"  {GREEN}Correctly blocked: {type(e).__name__}{RESET}")
					tests_passed += 1
				else:
					# Should have succeeded but blocked
					print(f"{RED}✗ Test {i} FAILED{RESET}: {description}")
					print(f"  User path: {user_path}")
					print(f"  {YELLOW}⚠ Should allow but raised: {e}{RESET}")
					tests_failed += 1
					failed_tests.append((i, description, f"Should allow but raised {type(e).__name__}"))
				print()
				
			except Exception as e:
				print(f"{RED}✗ Test {i} CRASHED{RESET}: {description}")
				print(f"  User path: {user_path}")
				print(f"  Error: {str(e)}")
				print(f"  {YELLOW}⚠ Unexpected exception: {type(e).__name__}{RESET}\n")
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
	
	# Performance feedback with progressive hints
	if percentage == 100:
		print(f"{GREEN}{BOLD}🎉 PERFECT SCORE! 🎉{RESET}")
		print(f"{GREEN}Outstanding! You've implemented production-grade path security.{RESET}")
		print(f"\n{BOLD}You now understand:{RESET}")
		print("  ✓ Path canonicalization with resolve()")
		print("  ✓ Directory confinement checking")
		print("  ✓ Allowlist validation")
		print("  ✓ Defense in depth")
		print(f"\n{BOLD}Next Steps:{RESET}")
		print("  1. Add this to your portfolio as a code sample")
		print("  2. Review OWASP Secure Coding guidelines")
		print("  3. Practice explaining your approach in mock interviews")
		print("  4. Apply this pattern to other input validation scenarios")
		
	elif percentage >= 80:
		print(f"{GREEN}{BOLD}EXCELLENT WORK!{RESET}")
		print(f"{GREEN}You understand the core concepts.{RESET}")
		print(f"\n{BOLD}Minor improvements needed:{RESET}")
		if failed_tests:
			print(f"  Failed tests: {[t[0] for t in failed_tests[:5]]}")
		print(f"\n{YELLOW}Check:{RESET}")
		print("  • Are you handling empty paths?")
		print("  • Are you checking file existence?")
		print("  • Is your allowlist validation case-sensitive?")
	
	elif percentage >= 60:
		print(f"{YELLOW}{BOLD}GOOD PROGRESS!{RESET}")
		print(f"{YELLOW}You're on the right track but missing key security checks.{RESET}")
		print(f"\n{BOLD}Focus on:{RESET}")
		print("  1. Use Path.resolve() to canonicalize paths")
		print("  2. Check if resolved path starts with base directory")
		print("  3. Validate against allowlist BEFORE checking filesystem")
		print("  4. Verify the file actually exists")
		print(f"\n{YELLOW}Algorithm Skeleton:{RESET}")
		print("  base = Path(base_directory).resolve()")
		print("  target = (base / user_provided_path).resolve()")
		print("  if not str(target).startswith(str(base)):")
		print("      raise ValueError('Path traversal detected')")
	
	elif percentage >= 40:
		print(f"{YELLOW}{BOLD}KEEP WORKING!{RESET}")
		print(f"{YELLOW}You need to implement the core security logic.{RESET}")
		print(f"\n{BOLD}Required Steps:{RESET}")
		print("  1. Import Path from pathlib")
		print("  2. Convert base_directory to absolute: Path(base_directory).resolve()")
		print("  3. Join with user input: base / user_provided_path")
		print("  4. Resolve the result: (base / user_path).resolve()")
		print("  5. Check if result starts with base directory")
		print("  6. Raise ValueError if not")
		print(f"\n{YELLOW}Key Insight:{RESET}")
		print("  resolve() does ALL the hard work:")
		print("  • Converts to absolute path")
		print("  • Resolves ../ and ./ references")
		print("  • Follows symlinks")
		print("  • Normalizes separators")
	
	else:
		print(f"{RED}{BOLD}NEEDS SIGNIFICANT WORK{RESET}")
		print(f"{RED}The implementation is missing core security logic.{RESET}")
		print(f"\n{BOLD}Start Here:{RESET}")
		print("  1. Read Python pathlib documentation")
		print("  2. Understand what Path.resolve() does")
		print("  3. Implement basic canonicalization:")
		print()
		print("     from pathlib import Path")
		print("     base = Path(base_directory).resolve()")
		print("     target = (base / user_provided_path).resolve()")
		print()
		print("  4. Check containment:")
		print()
		print("     if not str(target).startswith(str(base) + os.sep):")
		print("         raise ValueError('Path traversal')")
		print()
		print(f"\n{YELLOW}Study:{RESET}")
		print("  • Python pathlib tutorial")
		print("  • OWASP Path Traversal prevention")
		print("  • 'API Security in Action' Chapter 2")
	
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
	run_all_tests()
