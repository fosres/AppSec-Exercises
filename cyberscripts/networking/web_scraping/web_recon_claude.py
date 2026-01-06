#!/usr/bin/env python3
"""
Web Reconnaissance Report Generator
Week 4 Security Engineering Exercise

A passive reconnaissance tool that analyzes HTTP response headers,
cookies, and security configurations.

Usage:
	python3 web_recon_claude.py https://example.com
	python3 web_recon_claude.py urls.txt

Sources:
	- Grace Nolan's Security Engineering Interview Notes
	- Hacking APIs, Chapter 6: Discovery (pp. 125-147)
	- Full Stack Python Security, Chapters 7 and 14
	- API Security in Action, Chapter 5 (pp. 151-153)
"""

import requests
import sys
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

# =============================================================================
# CONFIGURATION
# =============================================================================

SECURITY_HEADERS = [
	'X-Frame-Options',
	'X-Content-Type-Options',
	'X-XSS-Protection',
	'Strict-Transport-Security',
	'Content-Security-Policy',
	'Referrer-Policy',
	'Permissions-Policy'
]

SERVER_INFO_HEADERS = [
	'Server',
	'X-Powered-By',
	'X-AspNet-Version',
	'X-Generator',
	'X-Drupal-Cache',
	'X-Varnish'
]

CORS_HEADERS = [
	'Access-Control-Allow-Origin',
	'Access-Control-Allow-Credentials',
	'Access-Control-Allow-Methods',
	'Access-Control-Allow-Headers'
]

ADDITIONAL_HEADERS = [
	'Content-Type',
	'Content-Length',
	'Content-Encoding',
	'Cache-Control',
	'ETag'
]

INTERESTING_HEADERS = [
	'X-Request-ID',
	'X-RateLimit-Remaining',
	'X-RateLimit-Limit',
	'Via',
	'X-Cache',
	'CF-Ray',
	'X-Served-By'
]

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def print_section(title):
	"""Print a section header."""
	print(f"\n{'═' * 3} {title} {'═' * 3}\n")

def print_header_status(name, value):
	"""Print a header with its value or 'not present'."""
	if value:
		print(f"{name}: {value}")
	else:
		print(f"{name}: (not present)")

def is_url(string):
	"""Check if a string is a valid URL."""
	try:
		result = urlparse(string)
		return all([result.scheme, result.netloc])
	except:
		return False

def get_http_version(raw_version):
	"""Convert raw HTTP version number to string."""
	if raw_version:
		return f"HTTP/{raw_version / 10}"
	return "Unknown"

# =============================================================================
# ANALYSIS FUNCTIONS
# =============================================================================

def analyze_cookies(response):
	"""
	Analyze cookies for security attributes.
	Returns: (cookie_data, cookie_score, cookie_total, findings)
	"""
	cookie_data = []
	findings = []
	cookie_score = 0
	cookie_total = 0
	
	if 'Set-Cookie' not in response.headers:
		return cookie_data, 0, 0, findings
	
	raw_cookies = response.raw.headers.getlist('Set-Cookie')
	
	for i, cookie in enumerate(response.cookies):
		cookie_total += 3
		cookie_info = {
			'name': cookie.name,
			'value': cookie.value[:40] + '...' if len(cookie.value) > 40 else cookie.value,
			'domain': cookie.domain,
			'path': cookie.path,
			'expires': cookie.expires,
			'httponly': False,
			'secure': cookie.secure,
			'samesite': None
		}
		
		# Check HttpOnly
		if cookie.has_nonstandard_attr('HttpOnly'):
			cookie_info['httponly'] = True
			cookie_score += 1
		else:
			findings.append(f"Cookie '{cookie.name}' missing HttpOnly")
		
		# Check Secure
		if cookie.secure:
			cookie_score += 1
		else:
			findings.append(f"Cookie '{cookie.name}' missing Secure")
		
		# Check SameSite (parse from raw header)
		if i < len(raw_cookies):
			raw_cookie = raw_cookies[i]
			if 'SameSite=' in raw_cookie:
				idx = raw_cookie.find('SameSite=') + len('SameSite=')
				samesite_val = ''
				while idx < len(raw_cookie) and raw_cookie[idx].isalpha():
					samesite_val += raw_cookie[idx]
					idx += 1
				cookie_info['samesite'] = samesite_val
				if samesite_val.lower() in ['strict', 'lax']:
					cookie_score += 1
				else:
					findings.append(f"Cookie '{cookie.name}' has SameSite=None")
			else:
				findings.append(f"Cookie '{cookie.name}' missing SameSite")
		
		cookie_data.append(cookie_info)
	
	return cookie_data, cookie_score, cookie_total, findings

def analyze_security_headers(headers):
	"""
	Check for presence of security headers.
	Returns: (present_headers, missing_headers, score)
	"""
	present = {}
	missing = []
	
	for header in SECURITY_HEADERS:
		value = headers.get(header)
		if value:
			present[header] = value
		else:
			missing.append(header)
	
	return present, missing, len(present)

def analyze_cors(headers):
	"""
	Analyze CORS configuration.
	Returns: (cors_headers, is_critical)
	"""
	cors_data = {}
	is_critical = False
	
	for header in CORS_HEADERS:
		value = headers.get(header)
		if value:
			cors_data[header] = value
	
	# Check for critical misconfiguration
	origin = cors_data.get('Access-Control-Allow-Origin')
	credentials = cors_data.get('Access-Control-Allow-Credentials')
	
	if origin == '*' and credentials and credentials.lower() == 'true':
		is_critical = True
	
	return cors_data, is_critical

def analyze_server_info(headers):
	"""
	Extract server information headers.
	Returns: dict of present headers
	"""
	info = {}
	for header in SERVER_INFO_HEADERS:
		value = headers.get(header)
		if value:
			info[header] = value
	return info

# =============================================================================
# MAIN SCAN FUNCTION
# =============================================================================

def scan_url(url):
	"""Perform reconnaissance on a single URL."""
	
	# Ensure URL has scheme
	if not url.startswith(('http://', 'https://')):
		url = 'https://' + url
	
	print(f"\n{'=' * 65}")
	print(f"[*] Starting reconnaissance on: {url}")
	print(f"[*] Time: {datetime.now(timezone.utc).isoformat()}Z")
	print('=' * 65)
	
	# Initialize findings
	critical_findings = []
	medium_findings = []
	info_findings = []
	
	try:
		# Make request
		response = requests.get(
			url,
			timeout=15,
			allow_redirects=True,
			headers={'User-Agent': 'Mozilla/5.0 (Security Research)'}
		)
		headers = response.headers
		
		# =================================================================
		# PART 1: Response Status
		# =================================================================
		print_section("RESPONSE STATUS")
		print(f"Status Code: {response.status_code}")
		print(f"Status Message: {response.reason}")
		print(f"HTTP Version: {get_http_version(response.raw.version)}")
		print(f"Response Time: {response.elapsed.total_seconds():.3f}s")
		
		# =================================================================
		# PART 2: Server Information
		# =================================================================
		print_section("SERVER INFORMATION")
		server_info = analyze_server_info(headers)
		
		for header in SERVER_INFO_HEADERS:
			value = server_info.get(header)
			print_header_status(header, value)
			if value:
				info_findings.append(f"{header}: {value}")
		
		# =================================================================
		# PART 3: Security Headers
		# =================================================================
		print_section("SECURITY HEADERS")
		present_headers, missing_headers, security_score = analyze_security_headers(headers)
		
		for header in SECURITY_HEADERS:
			value = present_headers.get(header)
			if value:
				# Truncate long CSP values
				display_value = value[:60] + '...' if len(value) > 60 else value
				print(f"{header}: {display_value} ✓")
			else:
				print(f"{header}: (not present) ⚠️")
				# Categorize severity
				if header in ['Content-Security-Policy', 'Strict-Transport-Security', 
							  'X-Frame-Options', 'X-Content-Type-Options']:
					medium_findings.append(f"Missing {header}")
				else:
					info_findings.append(f"Missing {header}")
		
		print(f"\nSecurity Header Score: {security_score}/7")
		
		# =================================================================
		# PART 4: Cookie Analysis
		# =================================================================
		print_section("COOKIES")
		cookie_data, cookie_score, cookie_total, cookie_findings = analyze_cookies(response)
		
		if cookie_data:
			for i, cookie in enumerate(cookie_data, 1):
				print(f"Cookie {i}: {cookie['name']}")
				print(f"  Value: {cookie['value']}")
				print(f"  HttpOnly: {cookie['httponly']}")
				print(f"  Secure: {cookie['secure']}")
				print(f"  SameSite: {cookie['samesite'] or '(not set)'}")
				print(f"  Domain: {cookie['domain']}")
				print(f"  Path: {cookie['path']}")
				print(f"  Expires: {cookie['expires']}")
				print()
			
			medium_findings.extend(cookie_findings)
			
			percentage = (cookie_score / cookie_total * 100) if cookie_total > 0 else 0
			print(f"Cookie Security Score: {cookie_score}/{cookie_total} ({percentage:.1f}%)")
		else:
			print("No cookies set.")
		
		# =================================================================
		# PART 5: CORS Configuration
		# =================================================================
		print_section("CORS CONFIGURATION")
		cors_data, cors_critical = analyze_cors(headers)
		
		if cors_data:
			for header, value in cors_data.items():
				print(f"{header}: {value}")
			
			if cors_critical:
				print("\n🚨 CRITICAL: Wildcard origin (*) with Allow-Credentials is a security vulnerability!")
				critical_findings.append("CORS misconfiguration: wildcard with credentials")
		else:
			print("No CORS headers present.")
		
		# =================================================================
		# PART 6: Additional Information
		# =================================================================
		print_section("ADDITIONAL INFORMATION")
		
		for header in ADDITIONAL_HEADERS:
			value = headers.get(header)
			print_header_status(header, value)
		
		print("\nInteresting Headers Found:")
		interesting_found = False
		for header in INTERESTING_HEADERS:
			value = headers.get(header)
			if value:
				print(f"  - {header}: {value}")
				interesting_found = True
				if 'RateLimit' in header:
					info_findings.append("Rate limiting detected")
				elif header == 'Via':
					info_findings.append("Proxy detected")
				elif header in ['X-Cache', 'CF-Ray', 'X-Served-By']:
					info_findings.append(f"CDN detected ({header})")
		
		if not interesting_found:
			print("  (none)")
		
		# =================================================================
		# PART 7: Summary Report
		# =================================================================
		print(f"\n{'═' * 65}")
		print("                    RECONNAISSANCE SUMMARY")
		print('═' * 65)
		print(f"Target: {url}")
		print(f"Scan Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
		
		print(f"\n🚨 CRITICAL ({len(critical_findings)}):")
		if critical_findings:
			for finding in critical_findings:
				print(f"   - {finding}")
		else:
			print("   (none)")
		
		print(f"\n⚠️  MEDIUM ({len(medium_findings)}):")
		if medium_findings:
			for finding in medium_findings:
				print(f"   - {finding}")
		else:
			print("   (none)")
		
		print(f"\nℹ️  INFO ({len(info_findings)}):")
		if info_findings:
			# Deduplicate info findings
			for finding in list(dict.fromkeys(info_findings)):
				print(f"   - {finding}")
		else:
			print("   (none)")
		
		print(f"\nSECURITY HEADER SCORE: {security_score}/7 ({security_score/7*100:.0f}%)")
		if cookie_total > 0:
			print(f"COOKIE SECURITY SCORE: {cookie_score}/{cookie_total} ({cookie_score/cookie_total*100:.0f}%)")
		
		print('═' * 65)
		
	except requests.exceptions.Timeout:
		print(f"[!] Timeout: Could not connect to {url}")
	except requests.exceptions.ConnectionError as e:
		print(f"[!] Connection Error: {url} - {e}")
	except requests.exceptions.RequestException as e:
		print(f"[!] Request Error: {url} - {e}")
	except Exception as e:
		print(f"[!] Unexpected Error: {url} - {e}")

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
	if len(sys.argv) != 2:
		print("Usage:")
		print("  python3 web_recon_claude.py https://example.com")
		print("  python3 web_recon_claude.py urls.txt")
		sys.exit(1)
	
	arg = sys.argv[1]
	
	# Check if argument is a URL or a file
	if is_url(arg):
		# Single URL mode
		scan_url(arg)
	elif os.path.isfile(arg):
		# File mode - read URLs from file
		with open(arg, 'r') as f:
			for line in f:
				line = line.strip()
				# Skip empty lines and comments
				if not line or line.startswith('#'):
					continue
				if is_url(line):
					scan_url(line)
				else:
					print(f"[!] Skipping invalid URL: {line}")
	else:
		# Try adding https:// and treating as URL
		if '.' in arg:
			scan_url(arg)
		else:
			print(f"[!] '{arg}' is not a valid URL or file")
			sys.exit(1)

if __name__ == "__main__":
	main()
