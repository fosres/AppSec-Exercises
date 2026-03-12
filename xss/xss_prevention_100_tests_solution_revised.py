"""
Exercise: XSS Prevention Framework — 90 COMPREHENSIVE TESTS
=============================================================

Cross-site scripting (XSS) remains one of the most exploited web
vulnerabilities. Your task is to build a context-aware XSS prevention
framework that correctly escapes user-controlled data before it is
rendered in five distinct output contexts.

INSTRUCTIONS:
	1. Implement all methods in XSSPrevention below
	2. Run:  python3 xss_prevention_90_tests.py
	3. Pass all 90 tests!

Key insight from Full Stack Python Security (Ch. 14, pp. 218-226):
	Input sanitization is ALWAYS the wrong approach. The correct defense
	is context-aware OUTPUT ESCAPING. A '<' is only dangerous when
	rendered as HTML — escape it at the output layer, not the input layer.

Key insight from Secure by Design (Ch. 9, pp. 247-249):
	Never echo input verbatim in error messages. Even URL-encoded
	payloads like %3Cscript%3E become XSS in browser-based log tools.

Inspired by:
	- Full Stack Python Security, Ch. 14 (Dennis Byrne, Manning 2021)
	- Secure by Design, Ch. 9 (Johnsson, Deogun, Sawano, Manning 2019)
	- OWASP XSS Prevention Cheat Sheet (https://cheatsheetseries.owasp.org)
	- Python Workout, 2nd Ed. (Reuven Lerner, Manning 2022) — OOP style
"""

from typing import Dict, List

import html
import json
import urllib.parse
from urllib.parse import urlsplit
import validators

# ==========================================================
# YOUR IMPLEMENTATION GOES HERE
# ==========================================================

class XSSPrevention:
	"""
	Context-aware XSS prevention framework.

	Implements the three-layer defense from Full Stack Python Security
	(pp. 208-226):
	  Layer 1 — Input validation (whitelist where possible)
	  Layer 2 — Context-aware output escaping  ← MOST IMPORTANT
	  Layer 3 — Response headers (CSP, X-Content-Type-Options)

	Methods:
	╔══════════════════════════════════════════════════════════════╗
	║  escape_html(text)            HTML body context             ║
	║  escape_attribute(text)       HTML attribute context        ║
	║  escape_javascript(text)      JS string literal context     ║
	║  escape_url(text)             URL query parameter context   ║
	║  build_csp_header(directives) Content-Security-Policy value ║
	║  is_safe_url(url, hosts)      Open redirect prevention      ║
	╚══════════════════════════════════════════════════════════════╝

	Rule: Never sanitize (strip/modify) input.
	      Always escape at the output layer, in the correct context.
	"""

	def escape_html(self, text: str) -> str:
		"""
		Escape text for safe insertion into an HTML body context.

		Escapes the five dangerous HTML characters per Full Stack Python
		Security Table 14.1 (p. 219):
		  &  →  &amp;   (must be first to avoid double-encoding)
		  <  →  &lt;
		  >  →  &gt;
		  "  →  &quot;
		  '  →  &#x27;

		Source:
		  Byrne, Dennis. Full Stack Python Security, Ch. 14 "Cross-site
		  scripting attacks", Table 14.1 "Special HTML characters and
		  their escape values", p. 219. Manning, 2021.

		  The technique is character substitution: replace each of the
		  five characters with its HTML named or numeric character
		  reference. Escape & first to prevent double-encoding an already
		  present entity (e.g. &amp; → &amp;amp; if done last).

		Args:
			text: Raw user-supplied string.

		Returns:
			HTML-escaped string safe for HTML body insertion.

		Example:
			>>> XSSPrevention().escape_html('<script>alert(1)</script>')
			'&lt;script&gt;alert(1)&lt;/script&gt;'
		"""
		# TODO: Implement your solution here
		#
		# Citation: Byrne, Dennis. Full Stack Python Security, Ch. 14,
		#   Table 14.1 "Special HTML characters and their escape values",
		#   p. 219. Manning, 2021.
		#
		# The five replacements (in order — & must come first):
		#   &  →  &amp;
		#   <  →  &lt;
		#   >  →  &gt;
		#   "  →  &quot;
		#   '  →  &#x27;
		return html.escape(text,quote=True)

	def escape_attribute(self, text: str) -> str:
		"""
		Escape text for safe insertion inside an HTML attribute value.

		Attribute context requires escaping quotes to prevent attribute
		breakout event-handler injection. Also escape < > & for depth.

		Source:
		  Byrne, Dennis. Full Stack Python Security, Ch. 14 §14.3.2
		  "HTML attribute quoting", p. 221. Manning, 2021.

		  The technique requires that every HTML attribute value be
		  quoted AND that the quote characters used (both " and ')
		  are escaped inside the value. Byrne demonstrates that
		  unquoted attributes allow event-handler injection without
		  any special HTML characters at all — quoting alone is
		  insufficient without escaping the quote characters themselves.

		Args:
			text: Raw user-supplied string.

		Returns:
			String safe for use as an HTML attribute value.

		Example:
			>>> XSSPrevention().escape_attribute('" onmouseover="alert(1)')
			'&quot; onmouseover=&quot;alert(1)'
		"""
		# TODO: Implement your solution here
		#
		# Citation: Byrne, Dennis. Full Stack Python Security, Ch. 14,
		#   §14.3.2 "HTML attribute quoting", p. 221. Manning, 2021.
		#
		# Key insight from p. 221: an unquoted attribute allows injection
		# without any HTML special characters at all (e.g. injecting
		# "className onmouseover=javascript:launchRocket()").
		# Quoting alone is not enough — the quote characters themselves
		# must be escaped inside the value:
		#   &  →  &amp;
		#   <  →  &lt;
		#   >  →  &gt;
		#   "  →  &quot;
		#   '  →  &#x27;
		return html.escape(text,quote=True)

	def escape_javascript(self, text: str) -> str:
		"""
		Escape text for safe insertion inside a JavaScript string literal.

		Escape order matters — backslash MUST be escaped first:
		  \\   →  \\\\
		  '   →  \\'
		  "   →  \\"
		  \\n  →  \\n   (literal backslash-n, not a newline)
		  \\r  →  \\r
		  <   →  \\u003C  (prevents </script> tag breakout)
		  >   →  \\u003E
		  &   →  \\u0026  (prevents HTML entity injection in JS block)

		Source:
		  OWASP XSS Prevention Cheat Sheet, Rule #3 "JavaScript Escape
		  Before Inserting Untrusted Data into JavaScript Data Values".
		  https://cheatsheetseries.owasp.org/cheatsheets/
		  Cross_Site_Scripting_Prevention_Cheat_Sheet.html

		  The technique uses backslash escaping for ASCII control
		  sequences (\\n, \\r, quotes, backslash) and Unicode escapes
		  (\\uXXXX notation) for characters that would allow tag breakout or HTML
		  entity injection even inside a <script> block. Unicode escapes
		  are used for < > & because a browser's HTML parser runs BEFORE
		  the JavaScript parser — a raw </script> inside a JS string
		  literal will close the script block regardless of quoting.

		Args:
			text: Raw user-supplied string.

		Returns:
			String safe for insertion inside a JS string literal.

		Example:
			>>> XSSPrevention().escape_javascript("'; alert(1); //")
			"\\\\'; alert(1); //"
		"""
		# TODO: Implement your solution here
		#
		# Citation: OWASP XSS Prevention Cheat Sheet, Rule #3
		#   "JavaScript Escape Before Inserting Untrusted Data into
		#   JavaScript Data Values."
		#   https://cheatsheetseries.owasp.org/cheatsheets/
		#   Cross_Site_Scripting_Prevention_Cheat_Sheet.html
		#
		# Escape order (backslash MUST come first to avoid corrupting
		# subsequent escape sequences):
		# Escape order matters — backslash MUST be escaped first:
		# \\   →  \\\\
		# '   →  \\'
		# "   →  \\"
		# \\n  →  \\n   (literal backslash-n, not a newline)
		# \\r  →  \\r
		# <   →  \\u003C  (prevents </script> tag breakout)
		# >   →  \\u003E
		# &   →  \\u0026  (prevents HTML entity injection in JS block)

		escape_javascript_string = ""

		i = 0

		while i < len(text):

			if text[i] == "\\":

				escape_javascript_string += "\\\\"
			
			elif text[i] == "\'":

				escape_javascript_string += "\\'"
			
			elif text[i] == '\"':

				escape_javascript_string += '\\"'
			
			elif text[i] == '\n':

				escape_javascript_string += '\\n'

			elif text[i] == '\r':

				escape_javascript_string += '\\r'

			elif text[i] == '<':

				escape_javascript_string += '\\u003C'

			elif text[i] == '>':

				escape_javascript_string += '\\u003E'

			elif text[i] == '&':

				escape_javascript_string += '\\u0026'

			else:

				escape_javascript_string += text[i]

			i += 1
		

		return escape_javascript_string 

	def escape_url(self, text: str) -> str:
		"""
		Percent-encode a string for safe use as a URL query parameter.

		Encodes all characters except RFC 3986 unreserved chars:
		  ALPHA / DIGIT / "-" / "." / "_" / "~"

		Source:
		  Berners-Lee et al. RFC 3986 "Uniform Resource Identifier
		  (URI): Generic Syntax", §2.3 "Unreserved Characters",
		  January 2005. https://tools.ietf.org/html/rfc3986#section-2.3

		  The technique is percent-encoding: convert each byte of the
		  UTF-8 representation of a character to %XX uppercase hex.
		  Only the 66 unreserved characters (A-Z a-z 0-9 - _ . ~) are
		  left unencoded. All other characters — including reserved
		  URI characters like / ? # & = + — must be encoded when they
		  appear as data inside a query parameter value.

		  For practical Python implementation guidance, see also:
		  OAuth 2 in Action, Ch. 8 p. 143 (Justin Richer & Antonio
		  Sanso, Manning 2017) — demonstrates querystring.escape()
		  as the correct output escaping technique for URL context
		  when fixing a reflected XSS vulnerability in an API endpoint.

		Args:
			text: Raw user-supplied string.

		Returns:
			Percent-encoded string safe for URL query parameters.

		Example:
			>>> XSSPrevention().escape_url('<script>')
			'%3Cscript%3E'
		"""
		# TODO: Implement your solution here
		#
		# Citation: Berners-Lee et al. RFC 3986 "Uniform Resource
		#   Identifier (URI): Generic Syntax", §2.3 "Unreserved
		#   Characters", January 2005.
		#   https://tools.ietf.org/html/rfc3986#section-2.3
		#
		# The 66 unreserved characters that must NOT be encoded:
		#   A-Z  a-z  0-9  -  _  .  ~
		# Every other byte must be percent-encoded as %XX (uppercase
		# hex) using the UTF-8 byte representation of the character.
		#
		# Practical Python hint: urllib.parse.quote(text, safe='')
		# implements this correctly — safe='' ensures even '/' is
		# encoded. See also: Richer & Sanso, OAuth 2 in Action,
		# Ch. 8, p. 143 (Manning, 2017) for a worked URL-encoding
		# example fixing reflected XSS in an API endpoint.

		return urllib.parse.quote(text, safe='', encoding=None, errors=None)

	def build_csp_header(self, directives: Dict[str, str]) -> str:
		"""
		Build a Content-Security-Policy header value from a dict.

		Each key is a directive name (e.g. 'default-src') and each value
		is the directive value (e.g. "'self'").
		- Non-empty values: formatted as "directive-name value"
		- Empty string values: formatted as "directive-name" (no trailing space)
		- Directives joined with '; '
		- Order follows input dict order (Python 3.7+)

		Source:
		  Byrne, Dennis. Full Stack Python Security, Ch. 15 "Content
		  Security Policy", §15.1 "Composing a content security policy",
		  pp. 229-235. Manning, 2021.

		  The technique is string assembly: each directive is formatted
		  as "name value" (or just "name" if valueless), then all
		  directives are joined with '; ' as required by the CSP
		  specification. Byrne shows the canonical form:
		    Content-Security-Policy: default-src 'self'; script-src 'none'
		  and notes that single quotes around keyword sources like
		  'self' and 'none' are a specification requirement, not a
		  convention (p. 230).

		Args:
			directives: Dict mapping directive name → directive value.

		Returns:
			CSP header string, or empty string if directives is empty.

		Example:
			>>> XSSPrevention().build_csp_header({'default-src': "'self'"})
			"default-src 'self'"
		"""
		# TODO: Implement your solution here
		#
		# Citation: Byrne, Dennis. Full Stack Python Security, Ch. 15
		#   "Content Security Policy", §15.1 "Composing a content
		#   security policy", pp. 229-235. Manning, 2021.
		#
		# From p. 230: "A typical policy is composed of multiple
		# directives, separated by a semicolon, with one or more
		# sources, separated by a space."
		# From p. 230: single quotes around keyword sources like
		# 'self' and 'none' are a spec requirement, not a convention.
		#
		# Assembly rules:
		#   - Non-empty value  →  "directive-name value"
		#   - Empty string val →  "directive-name"   (no trailing space)
		#   - Join all parts   →  "; ".join(parts)

		assembly = []

		for key,val in directives.items():

			if val == "":

				assembly.append(f"{key}")

			else:
				assembly.append(f"{key} {val}")

		return "; ".join(assembly)	

	def is_safe_url(
		self,
		url: str,
		allowed_hosts: List[str],
		require_https: bool = True,
	) -> bool:
		"""
		Validate a redirect URL to prevent open redirect vulnerabilities.

		Mirrors Django's url_has_allowed_host_and_scheme() (Full Stack
		Python Security, p. 204), which accepts a URL, a set of allowed
		hosts, and a require_https flag.

		A URL is SAFE if and only if:
		  - It is a relative path: starts with '/' but NOT '//'
		  - OR its hostname exactly matches an entry in allowed_hosts
		    AND (require_https is False OR the scheme is 'https')

		A URL is ALWAYS UNSAFE if it:
		  - Is an empty string
		  - Starts with '//' (protocol-relative → external redirect)
		  - Uses the 'javascript:' scheme
		  - Uses the 'data:' scheme
		  - Uses the 'vbscript:' scheme
		  - Has a hostname not in allowed_hosts
		  - Uses HTTP when require_https=True (HTTP-downgrade attack)

		Source:
		  Byrne, Dennis. Full Stack Python Security, Ch. 13 "Never trust
		  input", §13.6 "Open redirect attacks", pp. 202-205.
		  Manning, 2021.

		  The technique mirrors Django's built-in utility function
		  url_has_allowed_host_and_scheme (shown on p. 204), which
		  accepts a URL and a set of allowed hosts and returns True
		  only when the URL's hostname matches. Byrne also demonstrates
		  that protocol-relative URLs (starting with //) bypass naive
		  validators that only check for http:// or https://, and that
		  require_https=True should be set to block HTTP downgrade
		  redirects (p. 205). Byrne warns explicitly: "The default
		  value for require_https is False. You should set it to True."
		  This implementation corrects that by defaulting to True.

		Args:
			url:           URL string to validate.
			allowed_hosts: List of permitted exact hostname strings.
			require_https: If True (default), HTTP URLs are rejected
			               even when the hostname is in allowed_hosts.
			               Set to False only when HTTPS is not available,
			               e.g. in local development.

		Returns:
			True if the URL is safe for redirect, False otherwise.

		Example:
			>>> XSSPrevention().is_safe_url('/dashboard', ['example.com'])
			True
			>>> XSSPrevention().is_safe_url('https://evil.com', ['example.com'])
			False
			>>> XSSPrevention().is_safe_url('http://example.com', ['example.com'])
			False
			>>> XSSPrevention().is_safe_url('http://example.com', ['example.com'], require_https=False)
			True
		"""
		# TODO: Implement your solution here
		#
		# Citation: Byrne, Dennis. Full Stack Python Security, Ch. 13
		#   "Never trust input", §13.6 "Open redirect attacks",
		#   pp. 202-205. Manning, 2021.
		#
		# From p. 204: Django's url_has_allowed_host_and_scheme()
		# returns True only when the URL hostname matches the allowed
		# host. Mirror that logic here.
		# From p. 205: protocol-relative URLs starting with '//' bypass
		# naive validators that only check for 'http://' or 'https://'.
		# A '//' URL is NOT a safe relative path — always return False.
		# From p. 205: "The default value for require_https is False.
		# You should set it to True." This implementation defaults to
		# True, correcting Django's footgun.
		#
		# Decision tree:
		#   1. Empty string            → False
		#   2. Starts with '//'        → False  (protocol-relative)
		#   3. javascript:/
		#      data:/
		#      vbscript: scheme        → False
		#   4. Starts with '/' only    → True   (safe relative path)
		#   5. Parse scheme + hostname
		#      a. hostname not in
		#         allowed_hosts        → False
		#      b. require_https=True
		#         AND scheme != https  → False  (HTTP-downgrade attack)
		#      c. otherwise            → True
		
		if url == "":

			return False

		elif url.find("//") == 0:

			return False
		
		elif url.startswith(("javascript:","data:","vbscript:")):
	
			return False

		elif url.find("/") == 0:
	
			return True 

		spliturl = urlsplit(url)

		schema = spliturl.scheme

		hostname = spliturl.hostname

		if hostname not in allowed_hosts:

			return False

		if require_https == True and schema != "https":

			return False
		
		elif require_https == True and schema == "https":

			return True

		else:
			# Note redirect suspectible to MITM

			# since connection is bare-HTTP

			return True 

		


# ==========================================================
# TEST SUITE — 90 TESTS ACROSS 9 CATEGORIES
# ==========================================================

class Colors:
	GREEN  = '\033[92m'
	RED    = '\033[91m'
	YELLOW = '\033[93m'
	BOLD   = '\033[1m'
	END    = '\033[0m'


def run_all_tests() -> None:
	xss = XSSPrevention()
	results = []

	def check(name: str, got, expected) -> None:
		results.append((got == expected, name, got, expected))

	# ══════════════════════════════════════════════════════════
	# CATEGORY 1: HTML Body Context — 10 tests (1-10)
	# Reference: Full Stack Python Security, Table 14.1, p. 219
	# ══════════════════════════════════════════════════════════

	check(
		"Test 01 [HTML] Classic <script> tag",
		xss.escape_html("<script>alert(1)</script>"),
		"&lt;script&gt;alert(1)&lt;/script&gt;"
	)
	check(
		"Test 02 [HTML] Ampersand escape (must come before < >)",
		xss.escape_html("Tom & Jerry"),
		"Tom &amp; Jerry"
	)
	check(
		"Test 03 [HTML] Double quote",
		xss.escape_html('say "hello"'),
		"say &quot;hello&quot;"
	)
	check(
		"Test 04 [HTML] Single quote",
		xss.escape_html("it's alive"),
		"it&#x27;s alive"
	)
	check(
		"Test 05 [HTML] Greater-than sign",
		xss.escape_html("5 > 3"),
		"5 &gt; 3"
	)
	check(
		"Test 06 [HTML] Empty string",
		xss.escape_html(""),
		""
	)
	check(
		"Test 07 [HTML] Safe alphanumeric — unchanged",
		xss.escape_html("Hello World 123"),
		"Hello World 123"
	)
	check(
		"Test 08 [HTML] img onerror vector",
		xss.escape_html("<img src=x onerror=alert(1)>"),
		"&lt;img src=x onerror=alert(1)&gt;"
	)
	check(
		"Test 09 [HTML] SVG onload vector",
		xss.escape_html("<svg/onload=alert(1)>"),
		"&lt;svg/onload=alert(1)&gt;"
	)
	check(
		"Test 10 [HTML] All five dangerous chars in one string",
		xss.escape_html("<>&\"'"),
		"&lt;&gt;&amp;&quot;&#x27;"
	)

	# ══════════════════════════════════════════════════════════
	# CATEGORY 2: HTML Attribute Context — 10 tests (11-20)
	# Reference: Full Stack Python Security, p. 221
	# ══════════════════════════════════════════════════════════

	check(
		"Test 11 [ATTR] Double-quote breakout",
		xss.escape_attribute('" onmouseover="alert(1)'),
		'&quot; onmouseover=&quot;alert(1)'
	)
	check(
		"Test 12 [ATTR] Single-quote breakout",
		xss.escape_attribute("' onmouseover='alert(1)"),
		"&#x27; onmouseover=&#x27;alert(1)"
	)
	check(
		"Test 13 [ATTR] Angle brackets in attribute",
		xss.escape_attribute("<javascript:alert(1)>"),
		"&lt;javascript:alert(1)&gt;"
	)
	check(
		"Test 14 [ATTR] Empty string",
		xss.escape_attribute(""),
		""
	)
	check(
		"Test 15 [ATTR] Safe CSS class name — unchanged",
		xss.escape_attribute("btn-primary"),
		"btn-primary"
	)
	check(
		"Test 16 [ATTR] Ampersand entity injection",
		xss.escape_attribute("a&b"),
		"a&amp;b"
	)
	check(
		"Test 17 [ATTR] Full event handler injection attempt",
		xss.escape_attribute('" onfocus="alert(document.cookie)" autofocus="'),
		'&quot; onfocus=&quot;alert(document.cookie)&quot; autofocus=&quot;'
	)
	check(
		"Test 18 [ATTR] Less-than and greater-than together",
		xss.escape_attribute("3 < 5 > 2"),
		"3 &lt; 5 &gt; 2"
	)
	check(
		"Test 19 [ATTR] Numeric only — unchanged",
		xss.escape_attribute("42"),
		"42"
	)
	check(
		"Test 20 [ATTR] Mixed quotes and angle brackets",
		xss.escape_attribute("\"<tag>'val'"),
		"&quot;&lt;tag&gt;&#x27;val&#x27;"
	)

	# ══════════════════════════════════════════════════════════
	# CATEGORY 3: JavaScript String Context — 10 tests (21-30)
	# Reference: OWASP XSS Prevention Cheat Sheet Rule #3
	# ══════════════════════════════════════════════════════════

	check(
		"Test 21 [JS] Single-quote breakout",
		xss.escape_javascript("'; alert(1); //"),
		"\\'; alert(1); //"
	)
	check(
		"Test 22 [JS] Double-quote breakout",
		xss.escape_javascript('"; alert(1); //'),
		'\\"; alert(1); //'
	)
	check(
		"Test 23 [JS] Backslash must be escaped first",
		xss.escape_javascript("back\\slash"),
		"back\\\\slash"
	)
	check(
		"Test 24 [JS] Newline escaping",
		xss.escape_javascript("line1\nline2"),
		"line1\\nline2"
	)
	check(
		"Test 25 [JS] Carriage return escaping",
		xss.escape_javascript("line1\rline2"),
		"line1\\rline2"
	)
	check(
		"Test 26 [JS] </script> tag breakout via Unicode escape",
		xss.escape_javascript("</script>"),
		"\\u003C/script\\u003E"
	)
	check(
		"Test 27 [JS] Ampersand escaped to Unicode",
		xss.escape_javascript("a && b"),
		"a \\u0026\\u0026 b"
	)
	check(
		"Test 28 [JS] Empty string",
		xss.escape_javascript(""),
		""
	)
	check(
		"Test 29 [JS] Safe alphanumeric — unchanged",
		xss.escape_javascript("helloWorld123"),
		"helloWorld123"
	)
	check(
		"Test 30 [JS] Combined: quote + newline + script tag",
		xss.escape_javascript("';\nalert(1);</script>"),
		"\\';\\nalert(1);\\u003C/script\\u003E"
	)

	# ══════════════════════════════════════════════════════════
	# CATEGORY 4: URL Query Parameter Context — 10 tests (31-40)
	# Reference: RFC 3986 unreserved characters
	# ══════════════════════════════════════════════════════════

	check(
		"Test 31 [URL] Angle brackets encoded",
		xss.escape_url("<script>"),
		"%3Cscript%3E"
	)
	check(
		"Test 32 [URL] Space encoded as %20",
		xss.escape_url("hello world"),
		"hello%20world"
	)
	check(
		"Test 33 [URL] Unreserved chars unchanged",
		xss.escape_url("abc-123_def.ghi~"),
		"abc-123_def.ghi~"
	)
	check(
		"Test 34 [URL] Ampersand encoded",
		xss.escape_url("a&b=c"),
		"a%26b%3Dc"
	)
	check(
		"Test 35 [URL] Hash symbol encoded",
		xss.escape_url("title#section"),
		"title%23section"
	)
	check(
		"Test 36 [URL] Forward slash encoded",
		xss.escape_url("path/to/resource"),
		"path%2Fto%2Fresource"
	)
	check(
		"Test 37 [URL] Percent sign itself encoded (no double-encoding)",
		xss.escape_url("100%"),
		"100%25"
	)
	check(
		"Test 38 [URL] Empty string",
		xss.escape_url(""),
		""
	)
	check(
		"Test 39 [URL] Unicode character (UTF-8 percent-encoded)",
		xss.escape_url("café"),
		"caf%C3%A9"
	)
	check(
		"Test 40 [URL] Full XSS payload encoded",
		xss.escape_url("<img src=x onerror=alert(1)>"),
		"%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"
	)

	# ══════════════════════════════════════════════════════════
	# CATEGORY 5: XSS Polyglot & Bypass Attempts — 10 tests (41-50)
	# Reference: Secure by Design, pp. 247-249
	# ══════════════════════════════════════════════════════════

	# Test 41: Gareth Heyes polyglot — no raw < or > must survive
	polyglot = (
		"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )"
		"//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//"
	)
	result_41 = xss.escape_html(polyglot)
	check(
		"Test 41 [POLY] Polyglot — no raw < or > in HTML output",
		("<" not in result_41 and ">" not in result_41),
		True
	)

	# Test 42: Pre-encoded entity input — & must be escaped to &amp;
	check(
		"Test 42 [POLY] Pre-encoded &lt; should become &amp;lt;",
		xss.escape_html("&lt;script&gt;"),
		"&amp;lt;script&amp;gt;"
	)

	# Test 43: Null-byte injection — angle brackets must still be escaped
	result_43 = xss.escape_html("<scr\x00ipt>alert(1)</scr\x00ipt>")
	check(
		"Test 43 [POLY] Null-byte injection — angle brackets escaped",
		("<" not in result_43 and ">" not in result_43),
		True
	)

	# Test 44: Hex-encoded tag via %3C — % is not an HTML special char
	check(
		"Test 44 [POLY] Hex-encoded tag passthrough (% not special in HTML)",
		xss.escape_html("%3Cscript%3E"),
		"%3Cscript%3E"
	)

	# Test 45: SVG polyglot — no raw angle brackets
	result_45 = xss.escape_html("<svg><script>alert&#40;1&#41;</script></svg>")
	check(
		"Test 45 [POLY] SVG polyglot — no raw angle brackets",
		("<" not in result_45 and ">" not in result_45),
		True
	)

	# Test 46: CSS expression via attribute — no unescaped quotes
	result_46 = xss.escape_attribute('style=expression(alert(1))')
	check(
		"Test 46 [POLY] CSS expression injection — no raw quotes",
		('"' not in result_46 and "'" not in result_46),
		True
	)

	# Test 47: javascript: URL in attribute — no raw quotes
	result_47 = xss.escape_attribute("javascript:alert(1)")
	check(
		"Test 47 [POLY] javascript: URL in attribute — no raw quotes",
		('"' not in result_47 and "'" not in result_47),
		True
	)

	# Test 48: Secure by Design p.248 — verbatim echo XSS in error log
	# An encoded payload echoed verbatim in an error message can execute
	# as XSS inside a browser-based log tool if & is not escaped
	encoded_payload = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	result_48 = xss.escape_html(f"Invalid name. Got: {encoded_payload}")
	check(
		"Test 48 [POLY] Error message with encoded payload — % not special",
		("%" in result_48 and "&amp;" not in result_48),
		True
	)

	# Test 49: Unicode fullwidth angle brackets are NOT HTML special chars
	check(
		"Test 49 [POLY] Unicode fullwidth brackets passthrough",
		xss.escape_html("＜script＞"),   # U+FF1C U+FF1E
		"＜script＞"
	)

	# Test 50: Double-nested tag — no raw angle brackets at all
	result_50 = xss.escape_html("<<script>>alert(1)<</script>>")
	check(
		"Test 50 [POLY] Double-nested tag — no raw angle brackets",
		("<" not in result_50 and ">" not in result_50),
		True
	)

	# ══════════════════════════════════════════════════════════
	# CATEGORY 6: CSP Header Building — 10 tests (51-60)
	# Reference: Full Stack Python Security, Ch. 15
	# ══════════════════════════════════════════════════════════

	check(
		"Test 51 [CSP] Single default-src directive",
		xss.build_csp_header({"default-src": "'self'"}),
		"default-src 'self'"
	)
	check(
		"Test 52 [CSP] Two directives joined with '; '",
		xss.build_csp_header({
			"default-src": "'self'",
			"script-src": "'none'"
		}),
		"default-src 'self'; script-src 'none'"
	)
	check(
		"Test 53 [CSP] Three directives",
		xss.build_csp_header({
			"default-src": "'self'",
			"script-src": "'self' https://cdn.example.com",
			"style-src": "'self'"
		}),
		"default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self'"
	)
	check(
		"Test 54 [CSP] Nonce-based script-src",
		xss.build_csp_header({
			"default-src": "'none'",
			"script-src": "'nonce-abc123'",
			"connect-src": "'self'"
		}),
		"default-src 'none'; script-src 'nonce-abc123'; connect-src 'self'"
	)
	check(
		"Test 55 [CSP] Empty dict returns empty string",
		xss.build_csp_header({}),
		""
	)
	check(
		"Test 56 [CSP] Valueless directive (upgrade-insecure-requests)",
		xss.build_csp_header({
			"default-src": "'self'",
			"upgrade-insecure-requests": ""
		}),
		"default-src 'self'; upgrade-insecure-requests"
	)
	check(
		"Test 57 [CSP] img-src with data: URI",
		xss.build_csp_header({
			"default-src": "'self'",
			"img-src": "'self' data:"
		}),
		"default-src 'self'; img-src 'self' data:"
	)
	check(
		"Test 58 [CSP] report-uri directive",
		xss.build_csp_header({
			"default-src": "'self'",
			"report-uri": "/csp-report"
		}),
		"default-src 'self'; report-uri /csp-report"
	)
	result_59 = xss.build_csp_header({"script-src": "'none'"})
	check(
		"Test 59 [CSP] No trailing semicolon on single directive",
		(result_59.endswith(";") if result_59 else False),
		False
	)
	check(
		"Test 60 [CSP] Dict insertion order preserved (Python 3.7+)",
		xss.build_csp_header({
			"script-src": "'self'",
			"default-src": "'none'"
		}),
		"script-src 'self'; default-src 'none'"
	)

	# ══════════════════════════════════════════════════════════
	# CATEGORY 7: Open Redirect Prevention — 10 tests (61-70)
	# Reference: Full Stack Python Security, p. 202
	# ══════════════════════════════════════════════════════════

	check(
		"Test 61 [REDIR] Relative path /dashboard is safe",
		xss.is_safe_url("/dashboard", ["example.com"]),
		True
	)
	check(
		"Test 62 [REDIR] Allowed external HTTPS host is safe",
		xss.is_safe_url("https://example.com/home", ["example.com"]),
		True
	)
	check(
		"Test 63 [REDIR] Disallowed external host is unsafe",
		xss.is_safe_url("https://evil.com/steal", ["example.com"]),
		False
	)
	check(
		"Test 64 [REDIR] javascript: pseudo-URL always unsafe",
		xss.is_safe_url("javascript:alert(1)", ["example.com"]),
		False
	)
	check(
		"Test 65 [REDIR] Protocol-relative // always unsafe",
		xss.is_safe_url("//evil.com/path", ["example.com"]),
		False
	)
	check(
		"Test 66 [REDIR] data: URI always unsafe",
		xss.is_safe_url("data:text/html,<script>alert(1)</script>", ["example.com"]),
		False
	)
	check(
		"Test 67 [REDIR] Subdomain not in allowed_hosts is unsafe",
		xss.is_safe_url("https://evil.example.com/", ["example.com"]),
		False
	)
	check(
		"Test 68 [REDIR] Empty string is unsafe",
		xss.is_safe_url("", ["example.com"]),
		False
	)
	check(
		"Test 69 [REDIR] Relative path with query string is safe",
		xss.is_safe_url("/search?q=test&page=1", ["example.com"]),
		True
	)
	check(
		"Test 70 [REDIR] HTTP with require_https=True (default) is UNSAFE",
		xss.is_safe_url("http://example.com/page", ["example.com"]),
		False
	)

	# ══════════════════════════════════════════════════════════
	# CATEGORY 8: HTML Escaping — Depth & Edge Cases (71-80)
	# Reference: Secure by Design, pp. 247-249
	# ══════════════════════════════════════════════════════════

	# Test 71: Ampersand is escaped once — no double-encoding
	check(
		"Test 71 [HTML-EDGE] No double-encoding of existing &amp;",
		xss.escape_html("&amp;"),
		"&amp;amp;"
	)
	check(
		"Test 72 [HTML-EDGE] Whitespace and newlines preserved",
		xss.escape_html("line1\nline2\ttab"),
		"line1\nline2\ttab"
	)
	check(
		"Test 73 [HTML-EDGE] Digits and punctuation safe chars",
		xss.escape_html("price: $9.99 (sale!)"),
		"price: $9.99 (sale!)"
	)
	check(
		"Test 74 [HTML-EDGE] Script with attribute injection",
		xss.escape_html('<script src="evil.js"></script>'),
		'&lt;script src=&quot;evil.js&quot;&gt;&lt;/script&gt;'
	)
	check(
		"Test 75 [HTML-EDGE] iframe injection attempt",
		xss.escape_html('<iframe src="javascript:alert(1)"></iframe>'),
		'&lt;iframe src=&quot;javascript:alert(1)&quot;&gt;&lt;/iframe&gt;'
	)
	check(
		"Test 76 [HTML-EDGE] Template literal in input",
		xss.escape_html("${7*7}"),
		"${7*7}"  # $, {, } are not HTML special chars
	)
	check(
		"Test 77 [HTML-EDGE] Only a single less-than",
		xss.escape_html("<"),
		"&lt;"
	)
	check(
		"Test 78 [HTML-EDGE] Only a single greater-than",
		xss.escape_html(">"),
		"&gt;"
	)
	check(
		"Test 79 [HTML-EDGE] Multiple ampersands",
		xss.escape_html("A & B & C"),
		"A &amp; B &amp; C"
	)
	check(
		"Test 80 [HTML-EDGE] Long safe string unchanged",
		xss.escape_html("The quick brown fox jumps over the lazy dog"),
		"The quick brown fox jumps over the lazy dog"
	)

	# ══════════════════════════════════════════════════════════
	# CATEGORY 9: Advanced Edge Cases (81-90)
	# Reference: OWASP XSS Prevention Cheat Sheet Rules #3, #5;
	#            Full Stack Python Security, p. 205 (require_https)
	# ══════════════════════════════════════════════════════════

	# Test 81: require_https=False explicitly allows HTTP with a matching host
	# (mirrors Django's url_has_allowed_host_and_scheme require_https=False,
	#  useful only in local development — Byrne, p. 205)
	check(
		"Test 81 [REDIR-EDGE] HTTP allowed when require_https=False",
		xss.is_safe_url("http://example.com/page", ["example.com"], require_https=False),
		True
	)
	check(
		"Test 82 [JS-EDGE] Already-escaped backslash sequence",
		xss.escape_javascript("path\\\\file"),
		"path\\\\\\\\file"
	)
	check(
		"Test 83 [JS-EDGE] Both quote types in one string",
		xss.escape_javascript("""say "hello" and 'goodbye'"""),
		"""say \\"hello\\" and \\'goodbye\\'"""
	)
	check(
		"Test 84 [JS-EDGE] Backslash before quote — order matters",
		xss.escape_javascript("\\'"),
		"\\\\\\'"
	)
	check(
		"Test 85 [JS-EDGE] Greater-than only in JS context",
		xss.escape_javascript(">"),
		"\\u003E"
	)
	check(
		"Test 86 [URL-EDGE] Plus sign encoded (not a safe char)",
		xss.escape_url("a+b"),
		"a%2Bb"
	)
	check(
		"Test 87 [URL-EDGE] Question mark encoded",
		xss.escape_url("what?"),
		"what%3F"
	)
	check(
		"Test 88 [URL-EDGE] At sign encoded",
		xss.escape_url("user@example.com"),
		"user%40example.com"
	)
	check(
		"Test 89 [REDIR] vbscript: scheme always unsafe",
		xss.is_safe_url("vbscript:msgbox(1)", ["example.com"]),
		False
	)
	check(
		"Test 90 [REDIR] Multiple allowed hosts — second host matches",
		xss.is_safe_url("https://api.example.com/data", ["example.com", "api.example.com"]),
		True
	)

	# ══════════════════════════════════════════════════════════
	# CATEGORY 10: Redirect Security Edge Cases (91-100)
	# Reference: Full Stack Python Security, pp. 202-205
	#
	# These tests target two specific bugs present in naive
	# is_safe_url implementations:
	#
	# Bug A — Dangerous scheme bypass via authority component:
	#   "javascript://example.com/alert(1)" has netloc=example.com,
	#   so a validator checking only the hostname (not the scheme)
	#   returns True when require_https=False. The scheme must be
	#   rejected before hostname validation ever runs.
	#   (Byrne, Full Stack Python Security, p. 204 — scheme check
	#    must precede host check in the decision tree)
	#
	# Bug B — netloc vs hostname for port-bearing URLs:
	#   urlsplit("https://example.com:443/page").netloc == "example.com:443"
	#   which never matches "example.com" in allowed_hosts, causing
	#   a False negative. spliturl.hostname strips the port correctly.
	# ══════════════════════════════════════════════════════════

	# --- Bug A: dangerous scheme + crafted authority ---

	# Test 91: javascript:// embeds an allowed hostname in the authority
	# component. A validator using netloc-only check with require_https=False
	# returns True — the scheme must be blocked before hostname check.
	check(
		"Test 91 [REDIR-SEC] javascript:// with allowed netloc is UNSAFE",
		xss.is_safe_url("javascript://example.com/alert(1)", ["example.com"], require_https=False),
		False
	)

	# Test 92: data:// same pattern — data: scheme with allowed netloc.
	check(
		"Test 92 [REDIR-SEC] data:// with allowed netloc is UNSAFE",
		xss.is_safe_url("data://example.com/text/html,xss", ["example.com"], require_https=False),
		False
	)

	# Test 93: HTTPS with standard port 443 — netloc="example.com:443"
	# fails a naive netloc-in-allowed_hosts check; hostname="example.com" passes.
	check(
		"Test 93 [REDIR-SEC] HTTPS with port 443 and allowed host is SAFE",
		xss.is_safe_url("https://example.com:443/page", ["example.com"]),
		True
	)

	# Test 94: HTTPS with non-standard port 8443 — same netloc vs hostname bug.
	check(
		"Test 94 [REDIR-SEC] HTTPS with port 8443 and allowed host is SAFE",
		xss.is_safe_url("https://example.com:8443/page", ["example.com"]),
		True
	)

	# Test 95: evil host with port — must still be rejected even though
	# a port is present. Confirms port-stripping does not weaken host check.
	check(
		"Test 95 [REDIR-SEC] Evil host with port is UNSAFE",
		xss.is_safe_url("https://evil.com:443/page", ["example.com"]),
		False
	)

	# --- Bug A continued: case-sensitivity of scheme check ---

	# Test 96: JAVASCRIPT: (uppercase) — startswith("javascript:") is
	# case-sensitive so this bypasses a naive string check. urlsplit
	# lowercases the scheme, so the hostname check still catches it via
	# hostname=None, but the scheme must be blocked explicitly.
	check(
		"Test 96 [REDIR-SEC] JAVASCRIPT: uppercase scheme is UNSAFE",
		xss.is_safe_url("JAVASCRIPT:alert(1)", ["example.com"]),
		False
	)

	# Test 97: Javascript: mixed case — same issue as Test 96.
	check(
		"Test 97 [REDIR-SEC] Javascript: mixed-case scheme is UNSAFE",
		xss.is_safe_url("Javascript:alert(1)", ["example.com"]),
		False
	)

	# Test 98: DATA: uppercase — same case-sensitivity issue.
	check(
		"Test 98 [REDIR-SEC] DATA: uppercase scheme is UNSAFE",
		xss.is_safe_url("DATA:text/html,xss", ["example.com"]),
		False
	)

	# --- Regression: correct behaviour preserved ---

	# Test 99: HTTPS URL with no trailing slash — no path component.
	# urlsplit correctly extracts hostname without a trailing slash.
	check(
		"Test 99 [REDIR-SEC] HTTPS URL with no path is SAFE",
		xss.is_safe_url("https://example.com", ["example.com"]),
		True
	)

	# Test 100: HTTP with port and require_https=False — netloc="example.com:80"
	# fails a netloc check; hostname="example.com" correctly passes.
	check(
		"Test 100 [REDIR-SEC] HTTP with port, require_https=False is SAFE",
		xss.is_safe_url("http://example.com:80/page", ["example.com"], require_https=False),
		True
	)

	# ══════════════════════════════════════════════════════════
	# RESULTS OUTPUT
	# ══════════════════════════════════════════════════════════

	CATEGORIES = [
		("HTML Body Escaping",            1,  10),
		("HTML Attribute Escaping",       11, 20),
		("JavaScript String Escaping",    21, 30),
		("URL Parameter Escaping",        31, 40),
		("Polyglot & Bypass Attempts",    41, 50),
		("CSP Header Building",           51, 60),
		("Open Redirect Prevention",      61, 70),
		("HTML Depth & Edge Cases",       71, 80),
		("JS & URL Advanced Edge Cases",  81, 90),
		("Redirect Security Edge Cases",  91, 100),
	]

	print("\n╔" + "═" * 68 + "╗")
	print("║" + "  XSS PREVENTION FRAMEWORK — 100 COMPREHENSIVE TESTS  ".center(68) + "║")
	print("╚" + "═" * 68 + "╝\n")

	total_passed = 0
	total_failed = 0

	for cat_name, start, end in CATEGORIES:
		cat_results = results[start - 1:end]
		cat_passed  = sum(1 for r in cat_results if r[0])
		cat_failed  = 10 - cat_passed
		total_passed += cat_passed
		total_failed += cat_failed

		if cat_passed == 10:
			label_color = Colors.GREEN
		elif cat_passed >= 7:
			label_color = Colors.YELLOW
		else:
			label_color = Colors.RED

		print(f"{label_color}{Colors.BOLD}{cat_name}  ({cat_passed}/10){Colors.END}")
		for ok, name, got, expected in cat_results:
			if ok:
				print(f"  {Colors.GREEN}✅ PASS{Colors.END}  {name}")
			else:
				print(f"  {Colors.RED}❌ FAIL{Colors.END}  {name}")
				print(f"       Expected: {repr(expected)}")
				print(f"       Got:      {repr(got)}")
		print()

	score_pct = int((total_passed / 100) * 100)
	print("═" * 70)
	print(f"{Colors.BOLD}SCORE: {total_passed}/100  ({score_pct}%){Colors.END}\n")

	if total_passed == 100:
		print("╔" + "═" * 68 + "╗")
		print("║" + f"{Colors.GREEN}{Colors.BOLD}🎉 PERFECT — ALL 100 TESTS PASSED! 🎉{Colors.END}".center(82) + "║")
		print("║" + "  Your framework handles all five output contexts correctly.  ".center(68) + "║")
		print("╚" + "═" * 68 + "╝")
	elif total_passed >= 75:
		print(f"{Colors.YELLOW}Almost there! Review the failed categories above.{Colors.END}")
		print("Hint: Ensure escaping is truly context-specific —")
		print("      HTML body ≠ attribute ≠ JS string ≠ URL parameter.")
	elif total_passed >= 50:
		print(f"{Colors.YELLOW}Good progress! Key hints:{Colors.END}")
		print("  1. Escape & BEFORE < and > to avoid double-encoding.")
		print("  2. In JS context, escape \\ FIRST before quotes.")
		print("  3. CSP valueless directives must NOT have a trailing space.")
	else:
		print(f"{Colors.RED}Core hints to get started:{Colors.END}")
		print("  1. escape_html — five chars only: & < > \" '")
		print("     Read Full Stack Python Security p. 219 (Table 14.1).")
		print("  2. is_safe_url — '//' prefix is always unsafe (protocol-relative).")
		print("  3. build_csp_header — join with '; ', omit space for empty values.")


if __name__ == "__main__":
	run_all_tests()
