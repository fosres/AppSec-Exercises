#!/usr/bin/env python3
"""
TLS Certificate Security Validator
Implements the 20-point validation checklist used by modern browsers.

References:
- RFC 5280: Internet X.509 Public Key Infrastructure Certificate
- RFC 6125: Representation and Verification of Domain-Based Application Service Identity
- CA/Browser Forum Baseline Requirements
- CA/Browser Forum Ballot SC63 (March 2024): CRL required, OCSP optional
- CA/Browser Forum Ballot SC22 (September 2020): 398-day validity limit

Author: Tanveer Salim
"""

import re
import sys
from datetime import datetime, timezone
from typing import List, Tuple, Set, Dict, Optional
from pathlib import Path


class TLSValidator:
	"""Validates TLS certificates against the 20-point security checklist."""
	
	# Required checks (must pass for certificate to be valid)
	REQUIRED_CHECKS = {1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 14, 15, 16, 18, 20}
	
	# Optional checks (best practice but not strictly required)
	OPTIONAL_CHECKS = {9, 13, 17}
	
	# Conditional check (only applies if both SKI and AKI present)
	CONDITIONAL_CHECKS = {19}
	
	def __init__(self, cert_text: str, hostname: str = ""):
		"""
		Initialize validator with certificate text and target hostname.
		
		Args:
			cert_text: Certificate in OpenSSL text format
			hostname: Expected hostname for validation (e.g., "www.example.com")
		"""
		self.cert_text = cert_text
		self.hostname = hostname.lower()
		self.fail_list: List[int] = []
		self.optional_fail: List[int] = []
		
	def validate(self) -> Tuple[List[int], List[int]]:
		"""
		Run all 20 validation checks.
		
		Returns:
			Tuple of (fail_list, optional_fail):
			- fail_list: REQUIRED checks that failed
			- optional_fail: OPTIONAL checks that failed
		"""
		# Phase 1: Fundamental Validity
		self._check_01_version()
		self._check_02_expiration()
		self._check_03_signature_algorithm()
		self._check_04_key_strength()
		
		# Phase 2: Identity Validation
		self._check_05_subject_dn()
		self._check_06_sans_present()
		self._check_07_hostname_match()
		
		# Phase 3: Access Control
		self._check_08_basic_constraints()
		self._check_09_key_usage()
		self._check_10_extended_key_usage()
		
		# Phase 4: Revocation
		self._check_11_crl_distribution()
		self._check_12_authority_info_access()
		self._check_13_ocsp_url()
		self._check_14_certificate_transparency()
		
		# Phase 5: Chain Validation
		self._check_15_not_self_signed()
		self._check_16_serial_number()
		self._check_17_ski_present()
		self._check_18_aki_present()
		self._check_19_ski_not_equal_aki()
		
		# Phase 6: Operational
		self._check_20_validity_period()
		
		return (self.fail_list, self.optional_fail)
	
	def _fail_check(self, check_num: int) -> None:
		"""Record a failed check in the appropriate list."""
		if check_num in self.OPTIONAL_CHECKS:
			self.optional_fail.append(check_num)
		else:
			self.fail_list.append(check_num)
	
	# ========================================================================
	# PHASE 1: FUNDAMENTAL VALIDITY
	# ========================================================================
	
	def _check_01_version(self) -> None:
		"""
		CHECK 1: Certificate must be Version 3
		Status: REQUIRED
		Source: RFC 5280 Section 4.1.2.1
		"""
		match = re.search(r'Version:\s*3\s*\(0x2\)', self.cert_text)
		if not match:
			self._fail_check(1)
	
	def _check_02_expiration(self) -> None:
		"""
		CHECK 2: Certificate must not be expired or not-yet-valid
		Status: REQUIRED
		Source: RFC 5280 Section 4.1.2.5
		"""
		# Parse Not Before and Not After dates
		not_before_match = re.search(r'Not Before\s*:\s*(.+)', self.cert_text)
		not_after_match = re.search(r'Not After\s*:\s*(.+)', self.cert_text)
		
		if not (not_before_match and not_after_match):
			self._fail_check(2)
			return
		
		try:
			# Parse dates - handle multiple formats
			not_before = self._parse_cert_date(not_before_match.group(1))
			not_after = self._parse_cert_date(not_after_match.group(1))
			current = datetime.now(timezone.utc)
			
			# Check if expired or not yet valid
			if current < not_before or current > not_after:
				self._fail_check(2)
		except (ValueError, AttributeError):
			self._fail_check(2)
	
	def _parse_cert_date(self, date_str: str) -> datetime:
		"""Parse certificate date from various formats."""
		date_str = date_str.strip()
		
		# Common formats in OpenSSL output
		formats = [
			'%b %d %H:%M:%S %Y %Z',  # Dec 1 00:00:00 2025 GMT
			'%b %d %H:%M:%S %Y',     # Dec 1 00:00:00 2025
			'%Y-%m-%d %H:%M:%S %Z',  # 2025-12-01 00:00:00 GMT
		]
		
		for fmt in formats:
			try:
				dt = datetime.strptime(date_str, fmt)
				# Make timezone-aware (assume UTC)
				if dt.tzinfo is None:
					dt = dt.replace(tzinfo=timezone.utc)
				return dt
			except ValueError:
				continue
		
		raise ValueError(f"Unable to parse date: {date_str}")
	
	def _check_03_signature_algorithm(self) -> None:
		"""
		CHECK 3: Signature algorithm must be SHA-256 or better
		Status: REQUIRED
		Source: CA/Browser Forum Baseline Requirements
		
		Allowed: SHA-256, SHA-384, SHA-512
		Forbidden: MD5, SHA-1
		"""
		match = re.search(r'Signature Algorithm:\s*(\S+)', self.cert_text)
		if not match:
			self._fail_check(3)
			return
		
		sig_alg = match.group(1).lower()
		
		# Check for forbidden algorithms
		forbidden = ['md5', 'sha1', 'sha-1']
		if any(f in sig_alg for f in forbidden):
			self._fail_check(3)
			return
		
		# Check for allowed algorithms
		allowed = ['sha256', 'sha-256', 'sha384', 'sha-384', 'sha512', 'sha-512']
		if not any(a in sig_alg for a in allowed):
			self._fail_check(3)
	
	def _check_04_key_strength(self) -> None:
		"""
		CHECK 4: Public key must meet minimum strength requirements
		Status: REQUIRED
		Source: CA/Browser Forum Baseline Requirements
		
		RSA: ≥2048 bits
		ECDSA: ≥P-256 (256 bits)
		"""
		# Find public key algorithm
		alg_match = re.search(r'Public Key Algorithm:\s*(\S+)', self.cert_text)
		if not alg_match:
			self._fail_check(4)
			return
		
		alg = alg_match.group(1).lower()
		
		if 'rsa' in alg:
			# RSA: Need at least 2048 bits
			key_match = re.search(r'Public-Key:\s*\((\d+)\s*bit\)', self.cert_text)
			if not key_match:
				self._fail_check(4)
				return
			
			key_size = int(key_match.group(1))
			if key_size < 2048:
				self._fail_check(4)
		
		elif 'ec' in alg or 'ecdsa' in alg:
			# ECDSA: Need at least P-256 (256 bits)
			key_match = re.search(r'Public-Key:\s*\((\d+)\s*bit\)', self.cert_text)
			if not key_match:
				self._fail_check(4)
				return
			
			key_size = int(key_match.group(1))
			if key_size < 256:
				self._fail_check(4)
		else:
			# Unknown algorithm - fail safe
			self._fail_check(4)
	
	# ========================================================================
	# PHASE 2: IDENTITY VALIDATION
	# ========================================================================
	
	def _check_05_subject_dn(self) -> None:
		"""
		CHECK 5: Subject DN present (minimal OK if SANs critical)
		Status: MINIMAL OK
		Source: RFC 5280 Section 4.1.2.6
		
		Rules:
		- If Subject has no meaningful DN components, SANs must be marked critical
		- If Subject present, SANs doesn't need to be critical
		"""
		# Find subject line
		subject_match = re.search(r'Subject:\s*(.*)$', self.cert_text, re.MULTILINE)
		
		if not subject_match:
			# No subject line found
			self._fail_check(5)
			return
		
		subject_line = subject_match.group(1).strip()
		
		# Try to parse DN components
		has_components = False
		if subject_line:
			# Check if there are any valid DN components (key=value pairs)
			components = re.findall(r'([A-Z]+)\s*=\s*([^,]+)', subject_line)
			# Filter to only count components with non-empty values
			has_components = any(value.strip() for _, value in components)
		
		if not has_components:
			# Subject has no meaningful components - SANs must be critical
			sans_critical = self._is_sans_critical()
			if not sans_critical:
				self._fail_check(5)
	
	def _is_sans_critical(self) -> bool:
		"""Check if SANs extension is marked as critical."""
		# Look for "X509v3 Subject Alternative Name: critical"
		pattern = r'X509v3 Subject Alternative Name:\s*critical'
		return bool(re.search(pattern, self.cert_text))
	
	def _check_06_sans_present(self) -> None:
		"""
		CHECK 6: Subject Alternative Names (SANs) must be present with DNS entries
		Status: REQUIRED
		Source: CA/Browser Forum Baseline Requirements
		
		Must have:
		- SANs extension present
		- At least one DNS: entry with an actual hostname value
		"""
		# Find the SANs extension section
		sans_section_match = re.search(
			r'X509v3 Subject Alternative Name:([^\n]*)\n(.*?)(?=\n\s{0,4}X509v3|\nSignature Algorithm:|\Z)',
			self.cert_text,
			re.DOTALL
		)
		
		if not sans_section_match:
			# No SANs extension at all
			self._fail_check(6)
			return
		
		# Get the SANs section content (header line + content)
		sans_header = sans_section_match.group(1)
		sans_content = sans_section_match.group(2)
		
		# Search for DNS entries ONLY in the SANs section content
		dns_entries = re.findall(r'DNS:\s*([a-zA-Z0-9*][^\s,]*)', sans_content)
		
		# Filter to valid entries (non-empty after stripping)
		valid_entries = [entry.strip() for entry in dns_entries if entry.strip()]
		
		if len(valid_entries) == 0:
			# SANs section exists but no valid DNS entries
			self._fail_check(6)
	
	def _get_sans(self) -> List[str]:
		"""Extract all DNS names from SANs extension."""
		sans = []
		
		# Find the SANs extension - match until next major section
		# Look for next extension (X509v3) or next major section (Signature Algorithm, etc.)
		sans_match = re.search(
			r'X509v3 Subject Alternative Name:.*?\n(.*?)(?=\n(?:X509v3|Signature Algorithm|$))',
			self.cert_text,
			re.DOTALL | re.MULTILINE
		)
		
		if sans_match:
			sans_content = sans_match.group(1)
			# Extract DNS entries - strict pattern for valid hostnames
			# Allows: letters, digits, dots, hyphens, underscores, asterisks (for wildcards)
			dns_matches = re.findall(r'DNS:\s*([a-zA-Z0-9*][a-zA-Z0-9.*_-]*)', sans_content)
			# Normalize and filter out empty entries
			sans = [dns.strip().lower() for dns in dns_matches if dns and dns.strip()]
		
		return sans
	
	def _check_07_hostname_match(self) -> None:
		"""
		CHECK 7: Hostname must match one of the SANs
		Status: REQUIRED
		Source: RFC 6125 Section 6.4.3
		
		Implements DNS wildcard matching:
		- Wildcard (*) replaces exactly ONE label
		- Wildcard only in leftmost position
		- Label count must match
		- Case-insensitive
		- TLD wildcards (*.com) are FORBIDDEN
		"""
		if not self.hostname:
			# No hostname provided to validate
			return
		
		sans = self._get_sans()
		if not sans:
			self._fail_check(7)
			return
		
		# Try to match hostname against each SAN
		for san in sans:
			if self._dns_wildcard_match(san, self.hostname):
				return  # Match found!
		
		# No match found
		self._fail_check(7)
	
	def _dns_wildcard_match(self, pattern: str, hostname: str) -> bool:
		"""
		Implement RFC 6125 DNS wildcard matching.
		
		Rules:
		1. Wildcard (*) replaces exactly ONE label
		2. Wildcard only in leftmost position
		3. Label count must match
		4. Case-insensitive
		5. TLD wildcards (*.com, *.org) are FORBIDDEN
		
		Args:
			pattern: SAN pattern (e.g., "*.example.com")
			hostname: Hostname to match (e.g., "www.example.com")
		
		Returns:
			True if hostname matches pattern
		"""
		pattern = pattern.lower()
		hostname = hostname.lower()
		
		# Check for TLD wildcard (FORBIDDEN by RFC 6125)
		if self._is_tld_wildcard(pattern):
			return False  # Skip invalid TLD wildcards
		
		# Exact match (no wildcard)
		if pattern == hostname:
			return True
		
		# No wildcard in pattern
		if '*' not in pattern:
			return False
		
		# Wildcard must be in leftmost label only
		if not pattern.startswith('*.'):
			return False  # Wildcard not in leftmost position
		
		# Split into labels
		pattern_labels = pattern.split('.')
		hostname_labels = hostname.split('.')
		
		# Label count must match (wildcard replaces ONE label)
		if len(pattern_labels) != len(hostname_labels):
			return False
		
		# Compare each label position
		for i, (p_label, h_label) in enumerate(zip(pattern_labels, hostname_labels)):
			if p_label == '*':
				# Wildcard matches any single label
				continue
			elif p_label != h_label:
				# Non-wildcard labels must match exactly
				return False
		
		return True
	
	def _is_tld_wildcard(self, pattern: str) -> bool:
		"""
		Check if pattern is a TLD wildcard (forbidden by RFC 6125).
		
		Examples:
		- *.com -> True (FORBIDDEN)
		- *.org -> True (FORBIDDEN)
		- *.co.uk -> True (FORBIDDEN)
		- *.example.com -> False (allowed)
		"""
		if not pattern.startswith('*.'):
			return False
		
		# Get the part after "*."
		suffix = pattern[2:]
		
		# Load IANA TLD list (simplified - in production, cache this)
		known_tlds = self._get_known_tlds()
		
		# Check if suffix is a known TLD
		return suffix.lower() in known_tlds
	
	def _get_known_tlds(self) -> Set[str]:
		"""
		Get set of known TLDs.
		
		In production: Download from https://data.iana.org/TLD/tlds-alpha-by-domain.txt
		For this exercise: Include common TLDs
		"""
		return {
			'com', 'org', 'net', 'edu', 'gov', 'mil',
			'uk', 'us', 'ca', 'de', 'fr', 'jp', 'cn',
			'co.uk', 'com.au', 'co.jp', 'co.nz',
			'io', 'dev', 'app', 'me', 'tv',
		}
	
	# ========================================================================
	# PHASE 3: ACCESS CONTROL
	# ========================================================================
	
	def _check_08_basic_constraints(self) -> None:
		"""
		CHECK 8: Basic Constraints must have CA:FALSE and be critical
		Status: REQUIRED
		Source: CA/Browser Forum Certificate Contents
		"""
		# Must be marked critical
		pattern = r'X509v3 Basic Constraints:\s*critical\s+CA:FALSE'
		if not re.search(pattern, self.cert_text):
			self._fail_check(8)
	
	def _check_09_key_usage(self) -> None:
		"""
		CHECK 9: Key Usage flags (if present)
		Status: OPTIONAL (Universal in practice - 99%+)
		Source: RFC 5280 Section 4.2.1.3
		
		If present:
		- RSA: Must have Digital Signature + Key Encipherment
		- ECDSA: Must have Digital Signature only
		- Must be marked critical
		- Must NOT have Certificate Sign, CRL Sign, Data Encipherment, Content Commitment
		
		If missing:
		- Report as optional check failure (extension is optional but recommended)
		"""
		# Check if Key Usage extension exists
		ku_match = re.search(
			r'X509v3 Key Usage:\s*(critical)?\s*\n\s+(.+)',
			self.cert_text
		)
		
		if not ku_match:
			# Extension not present - report as optional failure
			self._fail_check(9)
			return
		
		is_critical = bool(ku_match.group(1))
		key_usage = ku_match.group(2)
		
		# Must be marked critical if present
		if not is_critical:
			self._fail_check(9)
			return
		
		# Check for banned flags
		banned = [
			'Certificate Sign',
			'CRL Sign',
			'Data Encipherment',
			'Content Commitment',
			'Non-Repudiation',  # Alternative name for Content Commitment
			'Non Repudiation'
		]
		if any(flag in key_usage for flag in banned):
			self._fail_check(9)
			return
		
		# Get algorithm type
		alg_match = re.search(r'Public Key Algorithm:\s*(\S+)', self.cert_text)
		if not alg_match:
			return
		
		alg = alg_match.group(1).lower()
		
		if 'rsa' in alg:
			# RSA: Must have both Digital Signature and Key Encipherment
			required = ['Digital Signature', 'Key Encipherment']
			if not all(flag in key_usage for flag in required):
				self._fail_check(9)
		
		elif 'ec' in alg or 'ecdsa' in alg:
			# ECDSA: Must have Digital Signature (Key Encipherment not applicable)
			if 'Digital Signature' not in key_usage:
				self._fail_check(9)
	
	def _check_10_extended_key_usage(self) -> None:
		"""
		CHECK 10: Extended Key Usage must include TLS Web Server Authentication
		Status: REQUIRED
		Source: CA/Browser Forum Certificate Contents
		"""
		# Look for EKU section
		eku_match = re.search(
			r'X509v3 Extended Key Usage:(.*?)(?=\n\s{0,4}[A-Z]|\Z)',
			self.cert_text,
			re.DOTALL
		)
		
		if not eku_match:
			self._fail_check(10)
			return
		
		eku = eku_match.group(1)
		
		# Must include "TLS Web Server Authentication"
		if 'TLS Web Server Authentication' not in eku:
			self._fail_check(10)
	
	# ========================================================================
	# PHASE 4: REVOCATION INFRASTRUCTURE
	# ========================================================================
	
	def _check_11_crl_distribution(self) -> None:
		"""
		CHECK 11: CRL Distribution Points must be present
		Status: REQUIRED (Changed March 2024 via Ballot SC63)
		Source: CA/Browser Forum Ballot SC63
		
		Must have at least 1 CRL URL (2+ recommended for redundancy)
		"""
		# Look for CRL Distribution Points section (match until next extension or end)
		crl_match = re.search(
			r'X509v3 CRL Distribution Points:(.*?)(?=\n\s{0,4}[A-Z]|\Z)',
			self.cert_text,
			re.DOTALL
		)
		
		if not crl_match:
			self._fail_check(11)
			return
		
		# Extract URIs from the section
		crl_section = crl_match.group(1)
		crl_uris = re.findall(r'URI:\s*(\S+)', crl_section)
		
		# Must have at least 1 URI
		if not crl_uris:
			self._fail_check(11)
	
	def _check_12_authority_info_access(self) -> None:
		"""
		CHECK 12: Authority Information Access must be present
		Status: REQUIRED
		Source: CA/Browser Forum Baseline Requirements Section 7.1.2.7.2
		
		Must contain at least one access method:
		- CA Issuers (recommended)
		- OCSP (optional per SC63)
		"""
		# Look for AIA section
		aia_match = re.search(
			r'Authority Information Access:(.*?)(?=\n\s{0,4}[A-Z]|\Z)',
			self.cert_text,
			re.DOTALL
		)
		
		if not aia_match:
			self._fail_check(12)
	
	def _check_13_ocsp_url(self) -> None:
		"""
		CHECK 13: OCSP URL (Real-time revocation checking)
		Status: OPTIONAL (Changed March 2024 via Ballot SC63)
		Source: CA/Browser Forum Ballot SC63
		
		Was REQUIRED before March 2024, now OPTIONAL due to:
		- Privacy concerns (exposes browsing behavior)
		- Security issues (plain HTTP)
		- Operational complexity
		"""
		# Look for OCSP URL in AIA section
		ocsp_match = re.search(
			r'OCSP\s*-\s*URI:\s*(\S+)',
			self.cert_text
		)
		
		if not ocsp_match:
			self._fail_check(13)  # Will go to optional_fail list
	
	def _check_14_certificate_transparency(self) -> None:
		"""
		CHECK 14: Certificate Transparency (Public audit trail)
		Status: REQUIRED
		Source: Chrome CT Policy, RFC 6962
		
		Must have at least 2 SCTs (Signed Certificate Timestamps)
		"""
		# Look for CT Precertificate SCTs section
		ct_match = re.search(
			r'CT Precertificate SCTs:(.*?)(?=\n\s{0,4}[A-Z]|\Z)',
			self.cert_text,
			re.DOTALL
		)
		
		if not ct_match:
			self._fail_check(14)
			return
		
		ct_text = ct_match.group(1)
		
		# Count SCTs (each has "Signed Certificate Timestamp:")
		sct_count = len(re.findall(r'Signed Certificate Timestamp:', ct_text))
		
		# Must have at least 2 SCTs
		if sct_count < 2:
			self._fail_check(14)
	
	# ========================================================================
	# PHASE 5: CHAIN VALIDATION
	# ========================================================================
	
	def _check_15_not_self_signed(self) -> None:
		"""
		CHECK 15: Certificate must not be self-signed
		Status: REQUIRED
		Source: CA/Browser Forum Baseline Requirements
		
		CRITICAL: No wildcard matching - exact DN comparison!
		Field order matters - must parse and normalize DNs.
		"""
		issuer = self._parse_dn('Issuer')
		subject = self._parse_dn('Subject')
		
		# If either DN is missing/empty, cannot determine self-signed status reliably
		# This is not necessarily self-signed, just malformed
		if not issuer or not subject:
			# Empty DN is handled by Check 5, not a self-signed issue
			return
		
		# Compare normalized DNs
		if issuer == subject:
			self._fail_check(15)
	
	def _parse_dn(self, field_name: str) -> Optional[Dict[str, str]]:
		"""
		Parse Distinguished Name into normalized dictionary.
		
		Handles different field orders:
		- "C=US, O=Example, CN=Test" vs "CN=Test, O=Example, C=US"
		
		Returns:
			Dict mapping field types to values (case-insensitive)
			None if DN is missing or completely empty
		"""
		match = re.search(rf'{field_name}:\s*(.*)$', self.cert_text, re.MULTILINE)
		if not match:
			return None
		
		dn_str = match.group(1).strip()
		
		# If DN string is empty, return None
		if not dn_str:
			return None
		
		# Parse DN components
		dn_dict = {}
		
		# Split by commas (handle escaped commas)
		components = re.split(r',\s*(?![^=]*\s)', dn_str)
		
		for component in components:
			component = component.strip()
			if '=' in component:
				key, value = component.split('=', 1)
				key = key.strip().upper()  # Normalize key
				value = value.strip()
				if key and value:  # Only add if both key and value are non-empty
					dn_dict[key] = value
		
		# If no valid components found, return None
		return dn_dict if dn_dict else None
	
	def _check_16_serial_number(self) -> None:
		"""
		CHECK 16: Valid serial number
		Status: REQUIRED
		Source: CA/Browser Forum Baseline Requirements Section 7.1
		
		Must have at least 64 bits of entropy (8 bytes)
		"""
		# Find serial number
		serial_match = re.search(
			r'Serial Number:\s*\n?\s*([0-9a-fA-F:]+)',
			self.cert_text
		)
		
		if not serial_match:
			self._fail_check(16)
			return
		
		serial = serial_match.group(1).strip()
		
		# Remove colons and spaces
		serial = serial.replace(':', '').replace(' ', '')
		
		# Must have at least 16 hex digits (64 bits = 8 bytes = 16 hex chars)
		if len(serial) < 16:
			self._fail_check(16)
	
	def _check_17_ski_present(self) -> None:
		"""
		CHECK 17: Subject Key Identifier present
		Status: RECOMMENDED (Not required for end-entity certificates)
		Source: RFC 5280 Section 4.2.1.2
		"""
		ski_match = re.search(
			r'X509v3 Subject Key Identifier:(.*?)(?=\n\s{0,4}[A-Z]|\Z)',
			self.cert_text,
			re.DOTALL
		)
		
		if not ski_match:
			self._fail_check(17)  # Will go to optional_fail list
	
	def _check_18_aki_present(self) -> None:
		"""
		CHECK 18: Authority Key Identifier must be present
		Status: REQUIRED
		Source: RFC 5280 Section 4.2.1.1
		"""
		aki_match = re.search(
			r'X509v3 Authority Key Identifier:(.*?)(?=\n\s{0,4}[A-Z]|\Z)',
			self.cert_text,
			re.DOTALL
		)
		
		if not aki_match:
			self._fail_check(18)
	
	def _check_19_ski_not_equal_aki(self) -> None:
		"""
		CHECK 19: SKI must not equal AKI (self-signed detector)
		Status: CONDITIONAL (Only if both SKI and AKI present)
		Source: RFC 5280 logic
		"""
		# Extract SKI
		ski_match = re.search(
			r'X509v3 Subject Key Identifier:(.*?)(?=\n\s{0,4}[A-Z]|\Z)',
			self.cert_text,
			re.DOTALL
		)
		
		# Extract AKI
		aki_match = re.search(
			r'X509v3 Authority Key Identifier:(.*?)(?=\n\s{0,4}[A-Z]|\Z)',
			self.cert_text,
			re.DOTALL
		)
		
		# Only check if both present
		if ski_match and aki_match:
			# Extract the actual key identifier hex values
			ski_text = ski_match.group(1)
			aki_text = aki_match.group(1)
			
			# Find hex patterns (e.g., "A1:B2:C3:..." or "keyid:A1:B2:C3:...")
			ski_hex = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+)', ski_text)
			aki_hex = re.search(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+)', aki_text)
			
			if ski_hex and aki_hex:
				ski = ski_hex.group(1).upper().replace(':', '')
				aki = aki_hex.group(1).upper().replace(':', '')
				
				if ski == aki:
					self._fail_check(19)  # Self-signed!
	
	# ========================================================================
	# PHASE 6: OPERATIONAL
	# ========================================================================
	
	def _check_20_validity_period(self) -> None:
		"""
		CHECK 20: Certificate validity period must be ≤ 398 days
		Status: REQUIRED
		Source: CA/Browser Forum Ballot SC22 (Effective September 1, 2020)
		"""
		# Parse dates
		not_before_match = re.search(r'Not Before\s*:\s*(.+)', self.cert_text)
		not_after_match = re.search(r'Not After\s*:\s*(.+)', self.cert_text)
		
		if not (not_before_match and not_after_match):
			self._fail_check(20)
			return
		
		try:
			not_before = self._parse_cert_date(not_before_match.group(1))
			not_after = self._parse_cert_date(not_after_match.group(1))
			
			# Calculate validity period
			validity_period = not_after - not_before
			validity_days = validity_period.days
			
			# Must be ≤ 398 days
			if validity_days > 398:
				self._fail_check(20)
		except (ValueError, AttributeError):
			self._fail_check(20)


def validate_tls_certificate(cert_file: str, hostname: str = "") -> Tuple[List[int], List[int]]:
	"""
	Validate TLS certificate against 20-point checklist.
	
	Args:
		cert_file: Path to certificate file in TEXT format (.txt)
		hostname: Expected hostname (e.g., "www.example.com")
	
	Returns:
		Tuple of (fail_list, optional_list):
		- fail_list: List of REQUIRED check numbers that failed (1-20)
		- optional_list: List of OPTIONAL check numbers that failed (1-20)
	
	Example:
		fail_list, optional_list = validate_tls_certificate("cert.txt", "www.example.com")
		# fail_list = [2, 7, 12]      # REQUIRED: expired, hostname mismatch, no AIA
		# optional_list = [9, 13]     # OPTIONAL: Key Usage, OCSP
	"""
	# Read certificate file
	with open(cert_file, 'r') as f:
		cert_text = f.read()
	
	# Create validator and run checks
	validator = TLSValidator(cert_text, hostname)
	return validator.validate()


def main():
	"""Command-line interface for the validator."""
	if len(sys.argv) < 2:
		print("Usage: python validate_tls_cert.py <cert_file> [hostname]")
		print("\nExample:")
		print("  python validate_tls_cert.py certificate.txt www.example.com")
		sys.exit(1)
	
	cert_file = sys.argv[1]
	hostname = sys.argv[2] if len(sys.argv) > 2 else ""
	
	# Validate certificate
	fail_list, optional_fail = validate_tls_certificate(cert_file, hostname)
	
	# Print results
	print(f"\n=== TLS Certificate Validator ===")
	print(f"File: {cert_file}")
	if hostname:
		print(f"Hostname: {hostname}")
	print()
	
	total_checks = 20
	required_passed = total_checks - len(fail_list) - len(optional_fail)
	
	if not fail_list and not optional_fail:
		print("✅ RESULT: VALID")
		print(f"Score: {total_checks}/{total_checks} checks passed")
		print("This certificate meets all requirements for public trust.")
	else:
		print("❌ RESULT: INVALID")
		print(f"Score: {required_passed}/{total_checks} checks passed")
		
		if fail_list:
			print(f"\nREQUIRED checks failed: {sorted(fail_list)}")
		
		if optional_fail:
			print(f"OPTIONAL checks failed: {sorted(optional_fail)}")


if __name__ == "__main__":
	main()
