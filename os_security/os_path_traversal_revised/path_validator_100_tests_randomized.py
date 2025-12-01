"""
Exercise 2.Y: Secure Path Validator - 100 RANDOMIZED REALISTIC TESTS
=====================================================================

Prevent path traversal attacks by validating file paths on GNU/Linux systems.

Path traversal (directory traversal) is a web security vulnerability that allows
attackers to read arbitrary files on the server. Attackers use "../" sequences
to escape the intended directory and access sensitive files like /etc/passwd,
configuration files, or source code.

TARGET PLATFORM: GNU/Linux (Unix-style paths with forward slashes)

🎲 RANDOMIZED VERSION: Test cases are shuffled randomly on each run!
This prevents you from gaming the system or memorizing test order.
Real security testing requires handling attacks in any order.

INSTRUCTIONS:
-------------
1. Implement your is_safe_path() function below
2. Run this file: python3 path_validator_100_tests_randomized.py
3. Pass all 100 realistic, production-grade tests!

These tests simulate REAL attacks seen in penetration tests, bug bounty reports,
and CVE disclosures. Every test case reflects actual attack patterns documented
in security research and production incidents.

Inspired by: "API Security in Action" (Chapter 8, pp. 251-254)
             "Full Stack Python Security" (Chapter 6, pp. 123-127)
             "Secure by Design" (Chapter 7, pp. 189-193)
             "Hacking APIs" (Chapter 4: Common API Vulnerabilities)
             "Python Workout" (Chapter 2: Strings)
             
Real-world CVE references: CVE-2019-3396 (Atlassian), CVE-2022-24765 (Git),
                          Zip Slip vulnerability (Snyk Research 2018)
"""

from typing import List, Tuple
import os
import random


# ============================================================================
# YOUR IMPLEMENTATION GOES HERE
# ============================================================================

def is_safe_path(base_dir: str, requested_path: str) -> bool:
    """
    Validate that requested_path stays within base_dir (no path traversal).
    
    Path traversal attacks use "../" to escape the intended directory:
        is_safe_path("/var/www", "../../etc/passwd") → False (attack!)
        is_safe_path("/var/www", "images/logo.png")   → True  (safe)
    
    Args:
        base_dir: The base directory that files must stay within
        requested_path: The file path requested by the user
    
    Returns:
        True if requested_path is safe (stays within base_dir)
        False if requested_path tries to escape base_dir (attack!)
    
    Examples:
        >>> is_safe_path("/var/www/html", "images/photo.jpg")
        True  # Safe: /var/www/html/images/photo.jpg
        
        >>> is_safe_path("/var/www/html", "../../../etc/passwd")
        False  # Attack! Tries to access /etc/passwd
        
        >>> is_safe_path("/uploads", "user123/document.pdf")
        True  # Safe: /uploads/user123/document.pdf
        
        >>> is_safe_path("/uploads", "/etc/passwd")
        False  # Attack! Absolute path escapes base_dir
    
    Critical Requirements:
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║ 1. MUST return bool (True for safe, False for attack)                ║
    ║ 2. Block "../" sequences that escape base_dir                        ║
    ║ 3. Block absolute paths (starting with /)                            ║
    ║ 4. Handle edge cases: empty strings, ".", "..", trailing slashes     ║
    ║ 5. Use os.path functions for proper path handling                    ║
    ║ 6. Normalize paths before comparison (resolve .., ., //)             ║
    ║ 7. GNU/Linux only - forward slashes (/) as path separator            ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    
    Security Notes:
    • This is ONE layer of defense - always combine with other controls
    • Real systems should also use chroot, containers, or filesystem ACLs
    • Always validate BEFORE accessing the filesystem
    • Log all rejected paths for security monitoring
    
    Hints:
    • Use os.path.normpath() to normalize paths
    • Use os.path.abspath() to get absolute paths
    • Use os.path.commonpath() to check if paths share a base
    • Consider: what if requested_path is empty? Contains only ".."?
    """
    
    # TODO: Implement your solution here
    # Replace 'pass' with your code
    
    pass  # Remove this line and add your implementation


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
    BOLD = '\033[1m'
    END = '\033[0m'


def run_all_tests():
    """Run all 100 test cases."""
    
    # ========================================================================
    # 100 REALISTIC PRODUCTION TEST CASES
    # ========================================================================
    
    test_cases = [
        # BASIC FUNCTIONALITY (Tests 1-5)
        ("Test 1: Simple safe file in subdirectory", 
         "/var/www/html", "images/logo.png", True),
        
        ("Test 2: Safe nested directory structure", 
         "/uploads", "user123/documents/report.pdf", True),
        
        ("Test 3: File in base directory itself", 
         "/data", "file.txt", True),
        
        ("Test 4: Deep nested safe path", 
         "/var/app", "static/css/themes/dark/main.css", True),
        
        ("Test 5: Safe path with multiple segments", 
         "/home/user", "projects/webapp/src/main.py", True),
        
        # BOUNDARY CONDITIONS (Tests 6-10)
        ("Test 6: Empty requested path", 
         "/var/www", "", False),
        
        ("Test 7: Current directory reference", 
         "/var/www", ".", True),
        
        ("Test 8: Requested path same as base", 
         "/var/www", "/var/www", True),
        
        ("Test 9: Trailing slash in base_dir", 
         "/var/www/", "images/photo.jpg", True),
        
        ("Test 10: Trailing slash in requested_path", 
         "/var/www", "images/", True),
        
        # ATTACK SCENARIOS - Path Traversal (Tests 11-15)
        ("Test 11: Single parent directory escape", 
         "/var/www/html", "../config.php", False),
        
        ("Test 12: Multiple parent directory escapes", 
         "/var/www/html", "../../../etc/passwd", False),
        
        ("Test 13: Escape then descend (classic attack)", 
         "/var/www/html", "../../var/log/apache.log", False),
        
        ("Test 14: Parent directory at start", 
         "/uploads", "../../etc/shadow", False),
        
        ("Test 15: Many parent directories", 
         "/app", "../../../../../root/.ssh/id_rsa", False),
        
        # NORMALIZATION TESTS (Tests 16-20)
        ("Test 16: Current directory in middle", 
         "/var/www", "images/./photos/pic.jpg", True),
        
        ("Test 17: Multiple current directories", 
         "/var/www", "./././images/logo.png", True),
        
        ("Test 18: Redundant slashes", 
         "/var/www", "images//photos///pic.jpg", True),
        
        ("Test 19: Parent then child (should stay safe)", 
         "/var/www", "images/../images/logo.png", True),
        
        ("Test 20: Complex but safe normalization", 
         "/var/www", "a/b/../c/./d/../e/file.txt", True),
        
        # ADVANCED ATTACK SCENARIOS (Tests 21-25)
        ("Test 21: Absolute path attack", 
         "/var/www", "/etc/passwd", False),
        
        ("Test 22: Absolute path to different directory", 
         "/uploads", "/var/log/auth.log", False),
        
        ("Test 23: Double dot without slash", 
         "/var/www", "..", False),
        
        ("Test 24: Triple dots (not standard but test)", 
         "/var/www", "...", True),
        
        ("Test 25: Parent directory as entire path", 
         "/var/www/html", "..", False),
        
        # EDGE CASES & COMPLEX SCENARIOS (Tests 26-30)
        ("Test 26: Deep nested escape attempt", 
         "/var/www", "a/b/c/../../../../../../../../etc/passwd", False),
        
        ("Test 27: Encoded slash attempt (%2F)", 
         "/var/www", "images%2F..%2F..%2Fetc%2Fpasswd", True),
        
        ("Test 28: Safe path with dots in filename", 
         "/var/www", "images/logo.v2.final.png", True),
        
        ("Test 29: Hidden file (starts with dot)", 
         "/home/user", ".config/settings.json", True),
        
        ("Test 30: Path with spaces and special chars", 
         "/var/www", "user_uploads/my document (2024).pdf", True),
        
        # BASE DIRECTORY VARIATIONS (Tests 31-35)
        ("Test 31: Different base - /home/user with safe path", 
         "/home/user", "projects/python/main.py", True),
        
        ("Test 32: Different base - /opt/app with attack", 
         "/opt/app", "../../../etc/passwd", False),
        
        ("Test 33: Different base - /tmp with nested safe path", 
         "/tmp", "uploads/session_abc123/data.json", True),
        
        ("Test 34: Different base - /srv/data with absolute attack", 
         "/srv/data", "/root/.ssh/id_rsa", False),
        
        ("Test 35: Different base - /usr/local/share with escape", 
         "/usr/local/share", "../../bin/sudo", False),
        
        # MULTIPLE DOT FILENAMES (Tests 36-40)
        ("Test 36: Three dots as filename (valid in Linux!)", 
         "/var/www", "...", True),
        
        ("Test 37: Four dots as filename (valid in Linux!)", 
         "/var/www", "....", True),
        
        ("Test 38: Five dots in path (valid filename)", 
         "/var/www", "data/.....", True),
        
        ("Test 39: Mix of .. and ... (tricky but safe)", 
         "/var/www", "files/.../data/../archive/..../file.txt", True),
        
        ("Test 40: Three dots with parent directory (attack!)", 
         "/var/www", ".../../../etc/passwd", False),
        
        # ADVANCED LINUX EDGE CASES (Tests 41-45)
        ("Test 41: Unicode filename (valid in Linux)", 
         "/var/www", "uploads/文档.pdf", True),
        
        ("Test 42: Filename with emoji (valid in Linux)", 
         "/var/www", "images/photo_🔒_secure.jpg", True),
        
        ("Test 43: Very long path component", 
         "/var/www", "a" * 255 + "/file.txt", True),
        
        ("Test 44: Special chars - dash, underscore, tilde", 
         "/home/user", "my-project_v2.0/~backup/data.db", True),
        
        ("Test 45: Symlink-named file with parent escape attempt", 
         "/var/www", "link/../../../etc/hostname", False),
        
        # ROOT AND SYSTEM DIRECTORIES (Tests 46-50)
        ("Test 46: Root directory as base with safe file", 
         "/", "var/www/html/index.html", True),
        
        ("Test 47: Root directory as base - parent of root is still root", 
         "/", "../etc/passwd", True),
        
        ("Test 48: System config directory as base", 
         "/etc", "nginx/nginx.conf", True),
        
        ("Test 49: System config with parent escape", 
         "/etc/nginx", "../../shadow", False),
        
        ("Test 50: Proc filesystem access attempt", 
         "/var/www", "../../../../proc/self/environ", False),
        
        # COMPLEX ATTACK COMBINATIONS (Tests 51-55)
        ("Test 51: Multiple escape sequences in single component", 
         "/var/www", "images/../../../../../../etc/passwd", False),
        
        ("Test 52: Mixed dots with normalization trickery", 
         "/var/www", "files/..././..././etc/passwd", True),
        
        ("Test 53: Escape using only current directory refs (safe)", 
         "/var/www", "./././././images/logo.png", True),
        
        ("Test 54: Parent escape hidden in long path", 
         "/var/www", "uploads/user/documents/files/../../../../../../../../etc/shadow", False),
        
        ("Test 55: Alternating parent/child navigation (safe)", 
         "/var/www", "a/b/../c/d/../e/f/file.txt", True),
        
        # EXTREME EDGE CASES (Tests 56-60)
        ("Test 56: Path with null-like name (null is invalid char but test string)", 
         "/var/www", "files/null/data.txt", True),
        
        ("Test 57: All special chars safe path", 
         "/var/www", "files/@#$%^&()_+-=[]{}file.txt", True),
        
        ("Test 58: Multiple consecutive slashes with escape", 
         "/var/www", "images///../../etc/passwd", False),
        
        ("Test 59: Hidden file with parent escape", 
         "/var/www", ".hidden/../../etc/hostname", False),
        
        ("Test 60: Complex normalization that stays safe", 
         "/var/www", "files/.../data/..././file.txt", True),
        
        # URL-ENCODED ATTACKS - Single Encoding (Tests 61-70)
        # Reference: "API Security in Action" Ch 8, pp. 251-254
        # Reference: "Hacking APIs" Ch 4 (Input Validation Attacks)
        ("Test 61: URL-encoded dots %2e%2e%2f", 
         "/var/www", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", True),
        
        ("Test 62: URL-encoded forward slash only", 
         "/var/www", "images%2f..%2f..%2fetc%2fpasswd", True),
        
        ("Test 63: Mixed URL encoding - some encoded, some not", 
         "/var/www", "..%2f..%2f..%2fetc/passwd", True),
        
        ("Test 64: URL-encoded absolute path", 
         "/var/www", "%2fetc%2fpasswd", True),
        
        ("Test 65: Capital hex in URL encoding %2E%2E%2F", 
         "/var/www", "%2E%2E%2F%2E%2E%2Fetc%2Fpasswd", True),
        
        ("Test 66: Lowercase hex URL encoding mixed with real path", 
         "/var/www", "images/%2e%2e/%2e%2e/etc/passwd", True),
        
        ("Test 67: URL-encoded with safe path", 
         "/var/www", "images%2flogo.png", True),
        
        ("Test 68: Partial URL encoding of parent directory", 
         "/var/www", ".%2e/..%2fetc/passwd", True),
        
        ("Test 69: URL-encoded root access attempt", 
         "/var/www", "%2fvar%2flog%2fauth.log", True),
        
        ("Test 70: Mixed case and URL encoding", 
         "/var/www", "%2E%2e%2F%2e%2E%2fetc%2Fpasswd", True),
        
        # DOUBLE URL-ENCODED ATTACKS (Tests 71-75)
        # Reference: "Full Stack Python Security" Ch 6, pp. 123-127
        ("Test 71: Double URL-encoded dots %252e", 
         "/var/www", "%252e%252e%252f%252e%252e%252fetc%252fpasswd", True),
        
        ("Test 72: Double URL-encoded forward slash", 
         "/var/www", "images%252f..%252f..%252fetc%252fpasswd", True),
        
        ("Test 73: Triple URL-encoded attack", 
         "/var/www", "%25252e%25252e%25252fetc%25252fpasswd", True),
        
        ("Test 74: Double encoding with absolute path", 
         "/var/www", "%252fetc%252fpasswd", True),
        
        ("Test 75: Mixed single and double encoding", 
         "/var/www", "%2e%2e%252f%2e%2e/etc/passwd", True),
        
        # NULL BYTE INJECTION ATTACKS (Tests 76-80)
        # Reference: "Hacking APIs" (Null byte termination attacks)
        # Note: Python 3 blocks null bytes in paths, but testing defense-in-depth
        ("Test 76: Null byte after safe filename", 
         "/var/www", "images/logo.png\x00../../etc/passwd", False),
        
        ("Test 77: Null byte in middle of path", 
         "/var/www", "images\x00/../../etc/passwd", False),
        
        ("Test 78: Null byte before extension", 
         "/var/www", "file.txt\x00.php", False),
        
        ("Test 79: Multiple null bytes", 
         "/var/www", "images\x00\x00/../../etc/passwd", False),
        
        ("Test 80: Null byte with URL encoding attempt", 
         "/var/www", "file%00.txt", True),
        
        # LINUX-SPECIFIC SYSTEM PATHS (Tests 81-85)
        # Reference: "Hacking APIs" (Linux system file access attempts)
        ("Test 81: /proc filesystem environment variables", 
         "/var/www", "../../../../proc/self/environ", False),
        
        ("Test 82: /proc filesystem command line", 
         "/var/www", "../../../proc/self/cmdline", False),
        
        ("Test 83: /sys filesystem access attempt", 
         "/var/www", "../../../../sys/class/net/eth0/address", False),
        
        ("Test 84: /dev/random access attempt", 
         "/var/www", "../../../dev/random", False),
        
        ("Test 85: Root SSH private key access", 
         "/var/www", "../../../../root/.ssh/id_rsa", False),
        
        # DOUBLE-DOT VARIATIONS (Tests 86-90)
        # Reference: CVE-2019-3396 (Atlassian Confluence)
        ("Test 86: Four dots in sequence ....//", 
         "/var/www", "....//....//etc/passwd", True),
        
        ("Test 87: Mixed double-dots and slashes", 
         "/var/www", "....//..///etc/passwd", True),
        
        ("Test 88: Excessive dots with parent escape", 
         "/var/www", "......//////etc/passwd", True),
        
        ("Test 89: Double-dot with URL encoding combo", 
         "/var/www", "....%2f%2f....%2f%2fetc%2fpasswd", True),
        
        ("Test 90: Alternating dots and slashes", 
         "/var/www", "./.././.././etc/passwd", True),
        
        # REAL-WORLD CVE PATTERNS (Tests 91-100)
        # Reference: CVE-2022-24765 (Git), Zip Slip (Snyk 2018)
        ("Test 91: Git CVE-2022-24765 pattern", 
         "/var/www", ".git/../../../etc/passwd", False),
        
        ("Test 92: Zip Slip pattern - archive extraction", 
         "/var/www/uploads", "../../../../tmp/malicious.sh", False),
        
        ("Test 93: Confluence CVE-2019-3396 pattern", 
         "/var/www", "..;/..;/etc/passwd", True),
        
        ("Test 94: Path with semicolon separator", 
         "/var/www", "images;../../etc/passwd", True),
        
        ("Test 95: Question mark in path (query string confusion)", 
         "/var/www", "../../etc/passwd?file=safe.txt", True),
        
        ("Test 96: Hash/fragment in path", 
         "/var/www", "../../etc/passwd#section", True),
        
        ("Test 97: Encoded newline in path %0a", 
         "/var/www", "images%0a../../etc/passwd", True),
        
        ("Test 98: Encoded carriage return %0d", 
         "/var/www", "images%0d../../etc/passwd", True),
        
        ("Test 99: Tab character in path", 
         "/var/www", "images\t../../etc/passwd", True),
        
        ("Test 100: Vertical tab and form feed characters", 
         "/var/www", "images\v\f../../etc/passwd", True),
    ]
    
    # ========================================================================
    # RANDOMIZE TEST ORDER
    # ========================================================================
    
    # Shuffle test cases randomly to prevent gaming the system
    # Security testing requires handling attacks in any order
    # Set seed to None for true randomness (different on each run)
    random.shuffle(test_cases)
    
    # ========================================================================
    # RUN TESTS
    # ========================================================================
    
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 18 + "SECURE PATH VALIDATOR CHALLENGE" + " " * 29 + "║")
    print("║" + " " * 17 + "🎲 100 RANDOMIZED TEST CASES 🎲" + " " * 30 + "║")
    print("╚" + "═" * 78 + "╝")
    print()
    print(f"{Colors.YELLOW}⚠️  Test order is randomized on each run!{Colors.END}")
    print()
    
    passed = 0
    failed = 0
    errors = 0
    failed_tests = []
    
    for test_name, base, requested, expected in test_cases:
        try:
            result = is_safe_path(base, requested)
            
            # Validate result type
            if not isinstance(result, bool):
                print(f"{Colors.RED}❌ FAIL{Colors.END} - {test_name}")
                print(f"   {Colors.RED}ERROR: Must return bool, got {type(result).__name__}{Colors.END}")
                print()
                failed += 1
                failed_tests.append((test_name, base, requested, expected, result))
                continue
            
            # Compare with expected
            if result == expected:
                status = "SAFE" if result else "BLOCKED"
                print(f"{Colors.GREEN}✅ PASS{Colors.END} - {test_name} → {status}")
                passed += 1
            else:
                print(f"{Colors.RED}❌ FAIL{Colors.END} - {test_name}")
                print(f"   Base: {base}")
                print(f"   Requested: {requested}")
                print(f"   Expected: {'SAFE' if expected else 'BLOCKED'}")
                print(f"   Got:      {'SAFE' if result else 'BLOCKED'}")
                
                if expected and not result:
                    print(f"   {Colors.RED}→ False positive: Blocked a safe path!{Colors.END}")
                else:
                    print(f"   {Colors.RED}→ FALSE NEGATIVE: Allowed an attack!{Colors.END}")
                print()
                
                failed += 1
                failed_tests.append((test_name, base, requested, expected, result))
            
        except Exception as e:
            print(f"{Colors.RED}❌ ERROR{Colors.END} - {test_name}")
            print(f"   {Colors.RED}{type(e).__name__}: {e}{Colors.END}")
            print()
            errors += 1
            failed_tests.append((test_name, base, requested, expected, None))
    
    # ========================================================================
    # SUMMARY
    # ========================================================================
    
    print()
    print("=" * 80)
    print(f"{Colors.BOLD}SUMMARY{Colors.END}")
    print("=" * 80)
    
    total_tests = 100
    print(f"\n{Colors.BOLD}Tests Passed: {Colors.GREEN if passed == total_tests else Colors.YELLOW}"
          f"{passed}/{total_tests}{Colors.END}")
    
    if failed > 0:
        print(f"Tests Failed: {Colors.RED}{failed}/{total_tests}{Colors.END}")
        
        # Count false negatives (security bugs!)
        false_negatives = sum(1 for _, _, _, expected, result in failed_tests 
                             if expected == False and result == True)
        if false_negatives > 0:
            print(f"{Colors.RED}⚠️  WARNING: {false_negatives} false negatives (attacks allowed!){Colors.END}")
    
    if errors > 0:
        print(f"Errors:       {Colors.RED}{errors}/{total_tests}{Colors.END}")
    
    print()
    
    # ========================================================================
    # RESULTS & HINTS
    # ========================================================================
    
    if passed == total_tests:
        print("╔" + "═" * 78 + "╗")
        print("║" + f"{Colors.GREEN}{Colors.BOLD}{'🎉 PERFECT! ALL 100 TESTS PASSED! 🎉':^88s}{Colors.END}" + "║")
        print("╚" + "═" * 78 + "╝")
        print()
        print("Your path validator is PRODUCTION-READY! 🛡️")
        print()
        print("You've successfully defended against:")
        print("  ✅ Classic path traversal attacks (../, /etc/passwd)")
        print("  ✅ URL-encoded bypasses (single, double, triple encoding)")
        print("  ✅ Null byte injection attempts")
        print("  ✅ Linux system file access (/proc, /sys, /dev)")
        print("  ✅ Real-world CVE patterns (Git, Confluence, Zip Slip)")
        print()
        print("Next steps:")
        print("  → Add to GitHub portfolio")
        print("  → Write dev.to blog post about your solution")
        print("  → Test against OWASP ZAP and Burp Suite")
        print("  → Deploy in production with monitoring")
        print()
    elif passed >= 95:
        print(f"{Colors.YELLOW}Almost there! You passed {passed}/100 tests.{Colors.END}")
        print("You're very close! Review the failed test cases carefully.")
        print()
        if failed_tests:
            print(f"{Colors.BOLD}Failed tests:{Colors.END}")
            for test_name, _, _, _, _ in failed_tests[:5]:
                print(f"  • {test_name}")
        print()
    elif passed >= 85:
        print(f"{Colors.YELLOW}Excellent progress! You passed {passed}/100 tests.{Colors.END}")
        print("Focus on URL-encoded attacks and real-world CVE patterns.")
        print()
        print("Key areas to review:")
        print("  • URL encoding (%2e%2e%2f)")
        print("  • Double/triple URL encoding")
        print("  • Null byte injection")
        print("  • CVE-inspired attack patterns")
        print()
    elif passed >= 70:
        print(f"{Colors.YELLOW}Good progress! You passed {passed}/100 tests.{Colors.END}")
        print("You're handling basic attacks well. Focus on encoding bypasses.")
        print()
        print("Key hints:")
        print("  • URL-encoded attacks won't work at OS level (treat as literal chars)")
        print("  • Null bytes should be rejected (defense-in-depth)")
        print("  • Linux system files (/proc, /sys) are common targets")
        print()
    elif passed >= 50:
        print(f"{Colors.YELLOW}Keep going! You passed {passed}/100 tests.{Colors.END}")
        print()
        print("Key implementation approach:")
        print("  1. Reject empty and absolute paths first")
        print("  2. Reject paths containing null bytes")
        print("  3. Use os.path.normpath() to normalize")
        print("  4. Use os.path.join() to combine base + requested")
        print("  5. Use os.path.abspath() to get absolute paths")
        print("  6. Check if final path starts with base directory")
        print()
    else:
        print(f"{Colors.RED}Keep working! You passed {passed}/100 tests.{Colors.END}")
        print()
        print("Implementation approach:")
        print("  1. Normalize both base_dir and requested_path")
        print("  2. Combine: full_path = os.path.join(base_dir, requested_path)")
        print("  3. Get absolute: abs_path = os.path.abspath(full_path)")
        print("  4. Get absolute base: abs_base = os.path.abspath(base_dir)")
        print("  5. Check if abs_path starts with abs_base + os.sep")
        print()
        print("Example structure:")
        print("  def is_safe_path(base_dir, requested_path):")
        print("      if not requested_path:  # Empty check")
        print("          return False")
        print("      if '\\x00' in requested_path:  # Null byte check")
        print("          return False")
        print("      # Normalize and combine paths...")
        print("      # Compare to ensure it stays in base_dir")
        print()
    
    print("=" * 80)
    print()


# ============================================================================
# MAIN - Run all tests when file is executed
# ============================================================================

if __name__ == "__main__":
    run_all_tests()
