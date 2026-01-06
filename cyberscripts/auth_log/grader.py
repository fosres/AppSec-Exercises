#!/usr/bin/env python3
"""
Auth Log Scraper Grader
=======================

Grades your parse_auth_log() implementation against 105 test cases.

Usage:
    python grader.py <your_solution.py>

Example:
    python grader.py my_solution.py

Your solution file must contain a function:
    def parse_auth_log(filepath: str) -> dict
"""

import sys
import json
import importlib.util
from pathlib import Path


def load_solution(filepath: str):
	"""Dynamically load the user's solution module."""
	path = Path(filepath)
	if not path.exists():
		print(f"❌ Error: File not found: {filepath}")
		sys.exit(1)
	
	if not path.suffix == '.py':
		print(f"❌ Error: Expected a .py file, got: {filepath}")
		sys.exit(1)
	
	spec = importlib.util.spec_from_file_location("user_solution", path)
	module = importlib.util.module_from_spec(spec)
	
	try:
		spec.loader.exec_module(module)
	except Exception as e:
		print(f"❌ Error loading your solution: {e}")
		sys.exit(1)
	
	if not hasattr(module, 'parse_auth_log'):
		print("❌ Error: Your solution must define a function called 'parse_auth_log'")
		sys.exit(1)
	
	return module.parse_auth_log


def run_tests(parse_auth_log, test_dir: Path) -> tuple[int, int, list]:
	"""Run all tests and return (passed, failed, failure_details)."""
	
	expected_path = test_dir / "expected_results.json"
	if not expected_path.exists():
		print(f"❌ Error: Expected results not found at {expected_path}")
		print("Make sure you're running from the test directory or provide the correct path.")
		sys.exit(1)
	
	with open(expected_path) as f:
		expected = json.load(f)
	
	category_dirs = {
		"1": "category1_basic",
		"2": "category2_edge_cases",
		"3": "category3_ip_handling",
		"4": "category4_brute_force",
		"5": "category5_timeline",
		"6": "category6_top_offender",
		"7": "category7_username_edge",
	}
	
	passed = 0
	failed = 0
	failures = []
	
	for test_name, exp in sorted(expected.items()):
		cat = test_name.split("_")[1]
		log_path = test_dir / category_dirs[cat] / f"{test_name}.log"
		
		if not log_path.exists():
			failures.append(f"{test_name}: Log file not found at {log_path}")
			failed += 1
			continue
		
		try:
			result = parse_auth_log(str(log_path))
			
			if result == exp:
				passed += 1
			else:
				failed += 1
				# Find first difference
				for key in exp:
					if key not in result:
						failures.append(f"{test_name}: Missing key '{key}'")
						break
					elif result[key] != exp[key]:
						failures.append(
							f"{test_name}: '{key}'\n"
							f"    Expected: {exp[key]}\n"
							f"    Got:      {result[key]}"
						)
						break
				else:
					extra = set(result.keys()) - set(exp.keys())
					if extra:
						failures.append(f"{test_name}: Extra keys: {extra}")
					else:
						failures.append(f"{test_name}: Unknown difference")
		
		except Exception as e:
			failed += 1
			failures.append(f"{test_name}: {type(e).__name__}: {e}")
	
	return passed, failed, failures


def get_category_breakdown(failures: list, total_per_cat: int = 15) -> dict:
	"""Calculate pass/fail per category."""
	categories = {
		"1": ("Basic Parsing", 0),
		"2": ("Edge Cases", 0),
		"3": ("IP Handling", 0),
		"4": ("Brute Force", 0),
		"5": ("Timeline", 0),
		"6": ("Top Offender", 0),
		"7": ("Username Edge", 0),
	}
	
	# Count failures per category
	failed_tests = set(f.split(":")[0] for f in failures)
	for test_name in failed_tests:
		cat = test_name.split("_")[1]
		if cat in categories:
			name, fails = categories[cat]
			categories[cat] = (name, fails + 1)
	
	return categories


def print_results(passed: int, failed: int, failures: list, total: int = 105):
	"""Print formatted results."""
	score = (passed / total) * 100
	
	print()
	print("╔═════════════════════════════════════════════╗")
	print("║          AUTH LOG SCRAPER                   ║")
	print("║             RESULTS                         ║")
	print("╠═════════════════════════════════════════════╣")
	print(f"║  Tests Passed: {passed:3d} / {total}                    ║")
	print(f"║  Score: {score:5.1f}%                               ║")
	print("╠═════════════════════════════════════════════╣")
	
	if score < 30:
		print("║  📚 Keep reading Python Workout            ║")
	elif score < 60:
		print("║  📈 Making progress                        ║")
	elif score < 75:
		print("║  ✅ Solid foundation                       ║")
	elif score < 90:
		print("║  🔧 Production-ready                       ║")
	elif score < 100:
		print("║  ⭐ Excellent! Almost perfect              ║")
	else:
		print("║  🎉 Ready for Security Engineering!        ║")
	
	print("╚═════════════════════════════════════════════╝")
	
	# Category breakdown
	categories = get_category_breakdown(failures)
	print("\n📊 Category Breakdown:")
	print("-" * 45)
	for cat in sorted(categories.keys()):
		name, fails = categories[cat]
		cat_passed = 15 - fails
		status = "✅" if fails == 0 else "❌" if cat_passed < 8 else "⚠️"
		print(f"  {status} Category {cat} ({name}): {cat_passed}/15")
	
	# Show failures
	if failures:
		print(f"\n❌ Failures ({len(failures)} total):")
		print("-" * 45)
		for f in failures[:10]:
			print(f"\n{f}")
		
		if len(failures) > 10:
			print(f"\n... and {len(failures) - 10} more failures")
			print("Fix the above issues first, then re-run.")
	
	print()


def main():
	if len(sys.argv) < 2:
		print(__doc__)
		print("❌ Error: Please provide your solution file as an argument.")
		print("\nExample:")
		print("    python grader.py my_solution.py")
		sys.exit(1)
	
	solution_file = sys.argv[1]
	
	# Find test directory
	script_dir = Path(__file__).parent
	test_dir = script_dir
	
	# Check if we're in the right directory
	if not (test_dir / "expected_results.json").exists():
		# Try looking in auth_log_tests subdirectory
		test_dir = script_dir / "auth_log_tests"
		if not (test_dir / "expected_results.json").exists():
			print("❌ Error: Cannot find test files.")
			print("Make sure grader.py is in the same directory as expected_results.json")
			sys.exit(1)
	
	print(f"📝 Loading solution from: {solution_file}")
	parse_auth_log = load_solution(solution_file)
	
	print(f"🧪 Running 105 tests...")
	passed, failed, failures = run_tests(parse_auth_log, test_dir)
	
	print_results(passed, failed, failures)
	
	# Exit with appropriate code
	sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
	main()
