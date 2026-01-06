#!/usr/bin/env python3
"""
Apache/Nginx Log Parser Grader
Week 2 - AppSec Exercise

Tests log_parser.py against sample log files and validates output.
Total Points: 100

Usage:
	python3 grader.py

Requirements:
	- log_parser.py in current directory
	- sample_logs/ directory with test files
"""

import json
import subprocess
import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple, Any


class Colors:
	"""ANSI color codes for terminal output"""
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKCYAN = '\033[96m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'


class LogParserGrader:
	"""Grader for Apache/Nginx log parser exercise"""
	
	def __init__(self):
		self.total_points = 0
		self.max_points = 100
		self.test_results = []
		self.sample_logs_dir = Path("sample_logs")
		self.parser_script = Path("/tmp/claude_log_parser.py")
		
	def print_header(self, text: str):
		"""Print section header"""
		print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
		print(f"{Colors.HEADER}{Colors.BOLD}{text.center(70)}{Colors.ENDC}")
		print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
	
	def print_success(self, text: str):
		"""Print success message"""
		print(f"{Colors.OKGREEN}✅ {text}{Colors.ENDC}")
	
	def print_fail(self, text: str):
		"""Print failure message"""
		print(f"{Colors.FAIL}❌ {text}{Colors.ENDC}")
	
	def print_warning(self, text: str):
		"""Print warning message"""
		print(f"{Colors.WARNING}⚠️  {text}{Colors.ENDC}")
	
	def print_info(self, text: str):
		"""Print info message"""
		print(f"{Colors.OKCYAN}ℹ️  {text}{Colors.ENDC}")
	
	def award_points(self, points: int, max_pts: int, test_name: str):
		"""Award points for a test"""
		self.total_points += points
		self.test_results.append((test_name, points, max_pts))
		
		if points == max_pts:
			self.print_success(f"{test_name}: {points}/{max_pts} points")
		elif points > 0:
			self.print_warning(f"{test_name}: {points}/{max_pts} points")
		else:
			self.print_fail(f"{test_name}: {points}/{max_pts} points")
	
	def check_files_exist(self) -> bool:
		"""Check if required files exist"""
		self.print_header("Checking Required Files")
		
		if not self.parser_script.exists():
			self.print_fail(f"log_parser.py not found in current directory")
			return False
		self.print_success("Found log_parser.py")
		
		if not self.sample_logs_dir.exists():
			self.print_fail(f"sample_logs/ directory not found")
			return False
		self.print_success("Found sample_logs/ directory")
		
		# Count log files
		log_files = list(self.sample_logs_dir.glob("*.log"))
		if len(log_files) < 11:
			self.print_warning(f"Found {len(log_files)} log files (expected 11+)")
		else:
			self.print_success(f"Found {len(log_files)} log files")
		
		return True
	
	def run_parser(self, log_file: Path) -> Tuple[bool, Dict[str, Any], str]:
		"""
		Run log_parser.py on a log file
		Returns: (success, parsed_json, error_message)
		"""
		try:
			result = subprocess.run(
				[sys.executable, str(self.parser_script), str(log_file)],
				capture_output=True,
				text=True,
				timeout=10
			)
			
			if result.returncode != 0:
				return False, {}, f"Non-zero exit code: {result.returncode}\n{result.stderr}"
			
			# Parse JSON output
			try:
				output = json.loads(result.stdout)
				return True, output, ""
			except json.JSONDecodeError as e:
				return False, {}, f"Invalid JSON output: {e}\nOutput: {result.stdout[:200]}"
				
		except subprocess.TimeoutExpired:
			return False, {}, "Parser timed out (>10 seconds)"
		except Exception as e:
			return False, {}, f"Unexpected error: {e}"
	
	def validate_json_structure(self, output: Dict[str, Any], test_name: str) -> int:
		"""
		Validate JSON structure (30 points)
		Returns: points earned
		"""
		points = 0
		max_points = 30
		
		# Check top-level keys (10 points)
		required_keys = ["summary", "top_ips", "security_findings", "suspicious_user_agents"]
		missing_keys = [k for k in required_keys if k not in output]
		
		if not missing_keys:
			points += 10
		else:
			self.print_fail(f"  Missing top-level keys: {missing_keys}")
		
		# Check summary structure (10 points)
		if "summary" in output:
			summary = output["summary"]
			summary_keys = ["total_requests", "unique_ips", "failed_requests", 
			               "total_bytes_transferred", "most_common_status_codes"]
			missing_summary = [k for k in summary_keys if k not in summary]
			
			if not missing_summary:
				# Check data types
				if (isinstance(summary["total_requests"], int) and
					isinstance(summary["unique_ips"], int) and
					isinstance(summary["failed_requests"], int) and
					isinstance(summary["total_bytes_transferred"], int) and
					isinstance(summary["most_common_status_codes"], dict)):
					points += 10
				else:
					self.print_fail(f"  Summary fields have wrong data types")
					points += 5
			else:
				self.print_fail(f"  Missing summary keys: {missing_summary}")
		
		# Check array structures (10 points)
		if "top_ips" in output and isinstance(output["top_ips"], list):
			points += 3
			# Check if top_ips has correct structure
			if output["top_ips"] and all(isinstance(item, dict) and "ip" in item and "requests" in item 
			                             for item in output["top_ips"]):
				points += 2
		
		if "security_findings" in output and isinstance(output["security_findings"], list):
			points += 3
		
		if "suspicious_user_agents" in output and isinstance(output["suspicious_user_agents"], list):
			points += 2
		
		return points
	
	def test_access_log(self) -> int:
		"""
		Test against access.log (original blog post example)
		30 points total
		"""
		self.print_header("Test 1: access.log (Original Example)")
		
		log_file = self.sample_logs_dir / "access.log"
		if not log_file.exists():
			self.print_fail("access.log not found in sample_logs/")
			return 0
		
		success, output, error = self.run_parser(log_file)
		
		if not success:
			self.print_fail(f"Parser failed: {error}")
			return 0
		
		points = 0
		
		# JSON structure (10 points)
		struct_points = self.validate_json_structure(output, "access.log")
		points += min(10, struct_points // 3)  # Scale to 10 points
		
		# Check expected values (20 points)
		summary = output.get("summary", {})
		
		# Total requests should be 11
		if summary.get("total_requests") == 11:
			points += 3
			self.print_success("  Correct total_requests: 11")
		else:
			self.print_fail(f"  Wrong total_requests: {summary.get('total_requests')} (expected 11)")
		
		# Unique IPs should be 5
		if summary.get("unique_ips") == 5:
			points += 3
			self.print_success("  Correct unique_ips: 5")
		else:
			self.print_fail(f"  Wrong unique_ips: {summary.get('unique_ips')} (expected 5)")
		
		# Security findings
		findings = output.get("security_findings", [])
		sqli_count = sum(1 for f in findings if f.get("finding_type") == "SQL_INJECTION")
		path_count = sum(1 for f in findings if f.get("finding_type") == "PATH_TRAVERSAL")
		bf_count = sum(1 for f in findings if f.get("finding_type") == "BRUTE_FORCE")
		
		# Should have 2 SQLi
		if sqli_count == 2:
			points += 5
			self.print_success("  Correct SQL_INJECTION detections: 2")
		else:
			self.print_fail(f"  Wrong SQL_INJECTION count: {sqli_count} (expected 2)")
		
		# Should have 2 Path Traversal
		if path_count == 2:
			points += 5
			self.print_success("  Correct PATH_TRAVERSAL detections: 2")
		else:
			self.print_fail(f"  Wrong PATH_TRAVERSAL count: {path_count} (expected 2)")
		
		# Should have 0 Brute Force (only 2 failed logins)
		if bf_count == 0:
			points += 4
			self.print_success("  Correct BRUTE_FORCE detections: 0 (only 2 failed attempts)")
		else:
			self.print_fail(f"  Wrong BRUTE_FORCE count: {bf_count} (expected 0)")
		
		return points
	
	def test_normal_traffic(self) -> int:
		"""
		Test against normal traffic (no attacks)
		10 points - should have zero detections
		"""
		self.print_header("Test 2: Normal Traffic (No False Positives)")
		
		log_file = self.sample_logs_dir / "01_normal_traffic_only.log"
		if not log_file.exists():
			self.print_fail("01_normal_traffic_only.log not found")
			return 0
		
		success, output, error = self.run_parser(log_file)
		
		if not success:
			self.print_fail(f"Parser failed: {error}")
			return 0
		
		points = 0
		findings = output.get("security_findings", [])
		
		if len(findings) == 0:
			points = 10
			self.print_success("  Zero false positives! Perfect!")
		else:
			self.print_fail(f"  Found {len(findings)} false positive(s)")
			for f in findings:
				self.print_fail(f"    - {f.get('finding_type')}: {f.get('path')}")
		
		return points
	
	def test_sql_injection(self) -> int:
		"""
		Test SQL injection detection
		15 points
		"""
		self.print_header("Test 3: SQL Injection Detection")
		
		log_file = self.sample_logs_dir / "02_sql_injection_heavy.log"
		if not log_file.exists():
			self.print_fail("02_sql_injection_heavy.log not found")
			return 0
		
		success, output, error = self.run_parser(log_file)
		
		if not success:
			self.print_fail(f"Parser failed: {error}")
			return 0
		
		points = 0
		findings = output.get("security_findings", [])
		sqli_findings = [f for f in findings if f.get("finding_type") == "SQL_INJECTION"]
		
		# Should detect 8 SQL injection attacks
		detection_rate = len(sqli_findings) / 8
		points = int(15 * detection_rate)
		
		if len(sqli_findings) == 8:
			self.print_success(f"  Detected all 8 SQL injection attacks!")
		elif len(sqli_findings) > 5:
			self.print_warning(f"  Detected {len(sqli_findings)}/8 SQL injection attacks")
		else:
			self.print_fail(f"  Only detected {len(sqli_findings)}/8 SQL injection attacks")
		
		# Check severity
		if sqli_findings and all(f.get("severity") == "HIGH" for f in sqli_findings):
			self.print_success("  All SQLi marked as HIGH severity")
		else:
			self.print_warning("  Some SQLi not marked as HIGH severity")
		
		return points
	
	def test_path_traversal(self) -> int:
		"""
		Test path traversal detection
		10 points
		"""
		self.print_header("Test 4: Path Traversal Detection")
		
		log_file = self.sample_logs_dir / "03_path_traversal_heavy.log"
		if not log_file.exists():
			self.print_fail("03_path_traversal_heavy.log not found")
			return 0
		
		success, output, error = self.run_parser(log_file)
		
		if not success:
			self.print_fail(f"Parser failed: {error}")
			return 0
		
		points = 0
		findings = output.get("security_findings", [])
		path_findings = [f for f in findings if f.get("finding_type") == "PATH_TRAVERSAL"]
		
		# Should detect 7-8 path traversal attacks (8 if URL decoding implemented)
		if len(path_findings) >= 7:
			detection_rate = min(len(path_findings) / 8, 1.0)
			points = int(10 * detection_rate)
			self.print_success(f"  Detected {len(path_findings)}/8 path traversal attacks")
		else:
			self.print_fail(f"  Only detected {len(path_findings)}/8 path traversal attacks")
		
		# Check severity
		if path_findings and all(f.get("severity") == "MEDIUM" for f in path_findings):
			self.print_success("  All path traversal marked as MEDIUM severity")
		else:
			self.print_warning("  Some path traversal not marked as MEDIUM severity")
		
		return points
	
	def test_brute_force(self) -> int:
		"""
		Test brute force detection
		10 points
		"""
		self.print_header("Test 5: Brute Force Detection")
		
		log_file = self.sample_logs_dir / "05_brute_force_multi_ip.log"
		if not log_file.exists():
			self.print_fail("05_brute_force_multi_ip.log not found")
			return 0
		
		success, output, error = self.run_parser(log_file)
		
		if not success:
			self.print_fail(f"Parser failed: {error}")
			return 0
		
		points = 0
		findings = output.get("security_findings", [])
		bf_findings = [f for f in findings if f.get("finding_type") == "BRUTE_FORCE"]
		
		# Should detect exactly 1 brute force (10.0.0.100)
		if len(bf_findings) == 1:
			points = 10
			self.print_success("  Correct! Detected 1 brute force attack")
			
			# Check details
			bf = bf_findings[0]
			if bf.get("ip") == "10.0.0.100":
				self.print_success("  Correct IP: 10.0.0.100")
			if bf.get("failed_request_count") == 3:
				self.print_success("  Correct count: 3 failed attempts")
			if bf.get("severity") == "LOW":
				self.print_success("  Correct severity: LOW")
				
		elif len(bf_findings) == 0:
			self.print_fail("  No brute force detected (expected 1)")
		else:
			points = 5
			self.print_warning(f"  Detected {len(bf_findings)} brute force patterns (expected 1)")
			self.print_info("  Only 10.0.0.100 has 3+ failures to a 'login' endpoint")
		
		return points
	
	def test_edge_cases(self) -> int:
		"""
		Test edge case handling
		5 points
		"""
		self.print_header("Test 6: Edge Cases")
		
		log_file = self.sample_logs_dir / "06_edge_cases.log"
		if not log_file.exists():
			self.print_fail("06_edge_cases.log not found")
			return 0
		
		success, output, error = self.run_parser(log_file)
		
		if not success:
			self.print_fail(f"Parser failed: {error}")
			return 0
		
		points = 0
		
		# Should not crash (2 points)
		points += 2
		self.print_success("  Parser did not crash on edge cases")
		
		# Should have zero false positives (3 points)
		findings = output.get("security_findings", [])
		if len(findings) == 0:
			points += 3
			self.print_success("  Zero false positives on edge cases!")
		else:
			self.print_fail(f"  Found {len(findings)} false positive(s)")
			# Check specifically for /temporary false positive
			temp_fps = [f for f in findings if "/temporary" in f.get("path", "")]
			if temp_fps:
				self.print_fail("  FALSE POSITIVE: /temporary detected as SQL injection")
				self.print_info("  Fix: Use ' OR ', not 'OR', to avoid matching 'temp-OR-ary'")
		
		return points
	
	def test_suspicious_agents(self) -> int:
		"""
		Test suspicious user agent detection
		5 points
		"""
		self.print_header("Test 7: Suspicious User Agents")
		
		log_file = self.sample_logs_dir / "access.log"
		if not log_file.exists():
			return 0
		
		success, output, error = self.run_parser(log_file)
		
		if not success:
			return 0
		
		points = 0
		agents = output.get("suspicious_user_agents", [])
		
		# Should detect curl, sqlmap, python-requests
		agent_names = [a.get("user_agent") for a in agents]
		
		if "sqlmap" in agent_names:
			points += 2
			self.print_success("  Detected sqlmap")
		
		if "curl" in agent_names:
			points += 2
			self.print_success("  Detected curl")
		
		if "python-requests" in agent_names:
			points += 1
			self.print_success("  Detected python-requests")
		
		if points < 5:
			self.print_warning(f"  Detected {len(agent_names)}/3 expected agents")
		
		return points
	
	def run_all_tests(self):
		"""Run all grading tests"""
		# Check files exist
		if not self.check_files_exist():
			print(f"\n{Colors.FAIL}Cannot proceed without required files{Colors.ENDC}")
			sys.exit(1)
		
		# Run tests
		self.award_points(self.test_access_log(), 30, "Test 1: access.log")
		self.award_points(self.test_normal_traffic(), 10, "Test 2: Normal Traffic")
		self.award_points(self.test_sql_injection(), 15, "Test 3: SQL Injection")
		self.award_points(self.test_path_traversal(), 10, "Test 4: Path Traversal")
		self.award_points(self.test_brute_force(), 10, "Test 5: Brute Force")
		self.award_points(self.test_edge_cases(), 5, "Test 6: Edge Cases")
		self.award_points(self.test_suspicious_agents(), 5, "Test 7: User Agents")
		
		# Bonus: Test all remaining files for crashes (15 points)
		self.test_all_files_no_crash()
		
	def test_all_files_no_crash(self):
		"""Test that parser doesn't crash on any file"""
		self.print_header("Bonus: All Files Parse Without Crashing")
		
		log_files = sorted(self.sample_logs_dir.glob("*.log"))
		crash_count = 0
		
		for log_file in log_files:
			success, output, error = self.run_parser(log_file)
			if not success:
				crash_count += 1
				self.print_fail(f"  {log_file.name}: CRASHED")
				self.print_info(f"    Error: {error[:100]}")
			else:
				self.print_success(f"  {log_file.name}: OK")
		
		# Award points: 15 points if all pass, proportional otherwise
		success_count = len(log_files) - crash_count
		points = int((success_count / max(len(log_files), 1)) * 15)
		
		self.award_points(points, 15, "Bonus: No Crashes")
	
	def print_final_score(self):
		"""Print final grade report"""
		self.print_header("FINAL GRADE REPORT")
		
		print(f"\n{Colors.BOLD}Test Results:{Colors.ENDC}")
		print("-" * 60)
		
		for test_name, points, max_pts in self.test_results:
			percentage = (points / max_pts * 100) if max_pts > 0 else 0
			
			if percentage == 100:
				color = Colors.OKGREEN
			elif percentage >= 70:
				color = Colors.WARNING
			else:
				color = Colors.FAIL
			
			print(f"{color}{test_name:.<50} {points:>2}/{max_pts:>2} ({percentage:>5.1f}%){Colors.ENDC}")
		
		print("-" * 60)
		
		final_percentage = (self.total_points / self.max_points * 100)
		
		# Determine letter grade
		if final_percentage >= 90:
			grade = "A+"
			color = Colors.OKGREEN
		elif final_percentage >= 80:
			grade = "A"
			color = Colors.OKGREEN
		elif final_percentage >= 70:
			grade = "B"
			color = Colors.WARNING
		elif final_percentage >= 60:
			grade = "C"
			color = Colors.WARNING
		else:
			grade = "F"
			color = Colors.FAIL
		
		print(f"\n{Colors.BOLD}TOTAL SCORE: {color}{self.total_points}/{self.max_points} ({final_percentage:.1f}%){Colors.ENDC}")
		print(f"{Colors.BOLD}LETTER GRADE: {color}{grade}{Colors.ENDC}\n")
		
		# Feedback
		if final_percentage >= 90:
			print(f"{Colors.OKGREEN}{Colors.BOLD}🎉 EXCELLENT WORK!{Colors.ENDC}")
			print(f"{Colors.OKGREEN}Your parser is production-ready!{Colors.ENDC}")
		elif final_percentage >= 70:
			print(f"{Colors.WARNING}{Colors.BOLD}Good work, but there's room for improvement.{Colors.ENDC}")
			print(f"{Colors.WARNING}Review the failed tests above.{Colors.ENDC}")
		else:
			print(f"{Colors.FAIL}{Colors.BOLD}Needs significant improvement.{Colors.ENDC}")
			print(f"{Colors.FAIL}Review the requirements and test cases carefully.{Colors.ENDC}")


def main():
	"""Main grader function"""
	print(f"{Colors.BOLD}{Colors.HEADER}")
	print("╔════════════════════════════════════════════════════════════════════╗")
	print("║                                                                    ║")
	print("║          Apache/Nginx Log Parser - Automated Grader               ║")
	print("║                   Week 2 AppSec Exercise                           ║")
	print("║                                                                    ║")
	print("╚════════════════════════════════════════════════════════════════════╝")
	print(f"{Colors.ENDC}\n")
	
	grader = LogParserGrader()
	grader.run_all_tests()
	grader.print_final_score()


if __name__ == "__main__":
	main()
