"""
SOLUTION EXAMPLE: Secure Path Validator (GNU/Linux)
====================================================

⚠️  SPOILER ALERT! Only look at this after completing the challenge!

This is a minimal, production-ready solution that passes all 30 tests.
Target platform: GNU/Linux (Unix-style paths with forward slashes)
"""

import os


def is_safe_path(base_dir: str, requested_path: str) -> bool:
    """
    Validate that requested_path stays within base_dir (no path traversal).
    
    This solution uses Python's os.path functions to properly normalize
    and compare paths, which handles all edge cases correctly including
    root directory as base.
    """
    
    # Edge case: Empty requested path is not safe
    if not requested_path:
        return False
    
    # Combine base_dir and requested_path
    # os.path.join() handles absolute paths in requested_path correctly
    full_path = os.path.join(base_dir, requested_path)
    
    # Normalize both paths (resolve .., ., redundant slashes)
    normalized_full = os.path.normpath(full_path)
    normalized_base = os.path.normpath(base_dir)
    
    # Get absolute paths (in case base_dir or requested_path are relative)
    abs_full = os.path.abspath(normalized_full)
    abs_base = os.path.abspath(normalized_base)
    
    # Check if the full path is within the base directory
    # Special case: if base is root ("/"), just check if path starts with "/"
    if abs_base == os.sep:
        return abs_full.startswith(os.sep)
    
    # For non-root bases: check if abs_full starts with abs_base followed by separator
    # OR is exactly equal to abs_base (for cases like ".")
    return abs_full == abs_base or abs_full.startswith(abs_base + os.sep)


# ============================================================================
# ALTERNATIVE SOLUTIONS
# ============================================================================

def is_safe_path_alternative1(base_dir: str, requested_path: str) -> bool:
    """
    Alternative using os.path.commonpath().
    
    This checks if base_dir and full_path share the same base directory.
    """
    if not requested_path:
        return False
    
    full_path = os.path.join(base_dir, requested_path)
    abs_full = os.path.abspath(full_path)
    abs_base = os.path.abspath(base_dir)
    
    # If they share the same common path, and it's the base, then safe
    common = os.path.commonpath([abs_base, abs_full])
    return common == abs_base


def is_safe_path_alternative2(base_dir: str, requested_path: str) -> bool:
    """
    Alternative using os.path.relpath().
    
    This checks if the relative path from base to full doesn't start with "..".
    """
    if not requested_path:
        return False
    
    full_path = os.path.join(base_dir, requested_path)
    abs_full = os.path.abspath(full_path)
    abs_base = os.path.abspath(base_dir)
    
    # Get relative path from base to full
    rel_path = os.path.relpath(abs_full, abs_base)
    # If it starts with "..", it's outside the base
    return not rel_path.startswith("..")


# ============================================================================
# WHAT MAKES THE SOLUTION SECURE
# ============================================================================

"""
KEY SECURITY PRINCIPLES (GNU/Linux):

1. NORMALIZATION FIRST
   • os.path.normpath() resolves .., ., and redundant slashes
   • Example: "images/../../../etc/passwd" → "../../etc/passwd"
   
2. ABSOLUTE PATHS
   • os.path.abspath() converts relative paths to absolute
   • Prevents confusion about what "base" means
   • Example: "./var/www" → "/home/user/var/www"
   
3. PROPER COMPARISON
   • Check if path STARTS WITH base + separator
   • Not just startswith(base) - that would allow "/var/www-backup"
   • Example: "/var/www/file" vs "/var/www-backup/file"
   
4. EMPTY PATH HANDLING
   • Empty string is invalid - must be explicit
   • Prevents confusion about default behavior
   
5. USING os.path MODULE
   • Don't reinvent the wheel with string operations
   • os.path handles Linux path conventions correctly
   • os.path handles edge cases we might not think of

WHAT IT BLOCKS:

✅ ../../../etc/passwd       (parent directory escapes)
✅ /etc/passwd              (absolute paths)
✅ images/../../../etc      (escape after safe prefix)
✅ ..                       (parent directory as entire path)
✅ images//../../etc        (redundant slashes)

WHAT IT ALLOWS:

✅ images/logo.png          (normal file)
✅ user/docs/report.pdf     (nested directories)
✅ .                        (current directory reference)
✅ images/./logo.png        (current dir in middle)
✅ images/../images/logo    (normalizes to images/logo)
"""


# ============================================================================
# TESTING THE SOLUTION
# ============================================================================

if __name__ == "__main__":
    # Quick verification
    tests = [
        ("/var/www", "images/logo.png", True),
        ("/var/www", "../../../etc/passwd", False),
        ("/var/www", "/etc/passwd", False),
        ("/var/www", "..", False),
        ("/var/www", "", False),
        ("/var/www", ".", True),
    ]
    
    print("Quick Solution Test:")
    print("=" * 50)
    for base, requested, expected in tests:
        result = is_safe_path(base, requested)
        status = "✅" if result == expected else "❌"
        print(f"{status} is_safe_path('{base}', '{requested}') → {result}")
    
    print("\nRun path_validator_30_tests.py for full test suite!")
