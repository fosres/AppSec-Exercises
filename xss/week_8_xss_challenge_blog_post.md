---
title: "Security Challenge: Build an XSS Prevention Framework in Python (90 Tests)"
published: false
description: "A LeetCode-style secure coding challenge — implement a context-aware XSS prevention framework covering HTML, attribute, JavaScript, URL, and CSP output contexts. 90 comprehensive tests. P2P AppSec Exercise Series."
tags: security, python, appsec, challenge
cover_image:
series: P2P AppSec Exercise Series
---

# Security Challenge: Build an XSS Prevention Framework in Python

**Time:** 60–90 minutes  
**Difficulty:** Intermediate  
**Skills:** Web Application Security, Output Escaping, CSP, Open Redirect Prevention, Python OOP

---

## The Hook: 22 Lines That Broke British Airways

In 2018, attackers injected 22 lines of JavaScript into British Airways' payment page. For 15 days, every customer who typed their credit card number had it silently copied and sent to an attacker-controlled server. Around 500,000 customers were affected. The UK ICO fined British Airways £20 million.

The root cause? Unsanitized content rendered in the wrong context — the textbook definition of XSS.

This challenge asks you to build the framework that prevents that.

---

## How Often Do Security Engineers Actually Deal With This?

It depends heavily on which type of Security Engineering role you're in.

**Product Security Engineers at large tech companies** — you'll *audit* output encoding regularly but *implement* it from scratch rarely. The workflow looks like this in practice:

- Code review flags a place where user-controlled data is rendered without escaping, you file a bug, and the owning developer fixes it
- You write a Semgrep rule that detects the pattern statically so it never reaches review in the first place
- You update the secure coding guidelines or developer training to explain the correct escaping approach for each context
- You evaluate whether a framework's auto-escaping is being bypassed — the Django `|safe` filter situation that Byrne calls out explicitly in *Full Stack Python Security* (pp. 219-221) is a real and common example of this

Modern web frameworks handle HTML body context automatically. What trips teams up in practice is the other four contexts: JavaScript, URL, attribute, and CSP. Those are where real vulnerabilities appear because developers know the framework covers HTML body output but forget that it doesn't cover everything else.

**Security consulting and penetration testing roles** — you encounter output encoding failures constantly, but from the attacker side. You're identifying missing or incorrect escaping in client codebases, writing proof-of-concept payloads, and documenting remediation paths. The polyglot and bypass test category in this exercise maps directly to that work.

**The real day-to-day value of this exercise** is that it forces you to understand *why* each context is different at the mechanism level — which is exactly what Security Engineers are asked in code review scenarios and system design interviews. A question like "how does Django's template engine protect against XSS and where does that protection break down?" is entirely answerable from working through this exercise. That's a far more common interview question than "implement `escape_javascript` from scratch."

So: audit output encoding — frequently. Implement it from scratch — rarely. But understanding how it works at this level is what separates engineers who understand security from engineers who have merely used security tools.

---

## Why Input Sanitization Is the Wrong Answer

Before you write a single line of code, internalize this principle from *Full Stack Python Security* (Ch. 14, p. 218, Dennis Byrne, Manning 2021):

> "Input sanitization is always a bad idea because it is too difficult to implement."

Here's why. A sanitizer has to identify malicious content across at least three interpreters simultaneously: JavaScript, HTML, and CSS. Miss one context and you're back to square one. Worse, sanitizers corrupt legitimate data — a forum where users can post code snippets would mangle every post.

The correct defense, as Byrne explains, is **context-aware output escaping**. A `<` character is *only dangerous when rendered as HTML*. Escape it at the output layer, in the correct context. Leave the input alone.

*Secure by Design* (Ch. 9, pp. 247-249, Johnsson, Deogun, Sawano, Manning 2019) adds another sharp insight: never echo input verbatim in error messages. Even a URL-encoded payload like `%3Cscript%3Ealert(1)%3C%2Fscript%3E` becomes executable XSS inside a browser-based log analysis tool that doesn't escape its output.

---

## The Five Output Contexts

XSS is not one problem — it is five problems, one per output context. Each context requires a different escaping strategy:

| Context | Example | Wrong escape | Right escape |
|---|---|---|---|
| HTML body | `<p>{{ user_bio }}</p>` | Strip `<>` | Replace `< > & " '` with entities |
| HTML attribute | `<input value="{{ name }}">` | HTML-escape only | Also escape `"` and `'` |
| JavaScript string | `var name = "{{ name }}";` | HTML-escape | Backslash-escape + Unicode for `< > &` |
| URL parameter | `href="/search?q={{ query }}"` | URL-encode only reserved chars | Percent-encode everything except RFC 3986 unreserved chars |
| CSP header | `Content-Security-Policy: ...` | N/A | Build correct directive syntax |

Apply the HTML body escaper to a JavaScript string and you will break the page. Apply the JavaScript escaper to a URL and you will corrupt the link. Context mismatch is exactly how most real XSS vulnerabilities arise.

---

## The Challenge

Implement the `XSSPrevention` class with six methods:

```python
class XSSPrevention:

	def escape_html(self, text: str) -> str:
		"""Escape for HTML body context."""
		pass

	def escape_attribute(self, text: str) -> str:
		"""Escape for HTML attribute value context."""
		pass

	def escape_javascript(self, text: str) -> str:
		"""Escape for JavaScript string literal context."""
		pass

	def escape_url(self, text: str) -> str:
		"""Percent-encode for URL query parameter context."""
		pass

	def build_csp_header(self, directives: dict) -> str:
		"""Build a Content-Security-Policy header value."""
		pass

	def is_safe_url(self, url: str, allowed_hosts: list) -> bool:
		"""Return True only if the URL is safe for redirect."""
		pass
```

No imports from third-party libraries. No Django or Flask. Pure Python.

---

## Why This Is Harder Than It Looks

### Edge Case 1: Ampersand Must Be Escaped First

If you escape `<` before `&`, you get double-encoding bugs:

```python
# WRONG order
"<b>Tom & Jerry</b>"
→ "&lt;b&gt;Tom &amp;lt; Jerry&lt;/b&gt;"  # &lt; doubled!

# CORRECT order: & first, then < >
"<b>Tom & Jerry</b>"
→ "&lt;b&gt;Tom &amp; Jerry&lt;/b&gt;"
```

*Full Stack Python Security* Table 14.1 (p. 219) lists the five characters and implies the correct replacement order.

### Edge Case 2: JavaScript Context Needs Backslash First

In JS string escaping, if you escape quotes before backslashes, you corrupt existing escape sequences:

```python
# Input: back\slash
# WRONG: escape " before \
"back\\slash" → "back\\slash"  # \ not escaped, \s survives as-is

# CORRECT: escape \ first, then quotes
"back\\slash" → "back\\\\slash"
```

### Edge Case 3: `</script>` Inside a JS Block

Even inside a `<script>` tag, a `</script>` substring in a string literal will prematurely close the script block. The fix is to escape `<` and `>` to Unicode escapes (`\u003C`, `\u003E`) so the browser never sees the raw characters:

```python
xss.escape_javascript("</script>")
# → "\\u003C/script\\u003E"
```

### Edge Case 4: Valueless CSP Directives

Some CSP directives take no value — `upgrade-insecure-requests` is the most common. Your `build_csp_header` must output `upgrade-insecure-requests` (no trailing space) when the value is an empty string, not `upgrade-insecure-requests ` (with a space).

### Edge Case 5: Protocol-Relative URLs

An open redirect validator that only checks for `http://` and `https://` will miss `//evil.com/path` — a protocol-relative URL that the browser resolves using whatever scheme the current page uses. It must always return `False`.

```python
xss.is_safe_url("//evil.com/path", ["example.com"])
# → False (protocol-relative, not a safe relative path)
```

---

## The 90-Test Gauntlet

Your implementation faces 90 deterministic tests across nine categories — ten tests per category:

| # | Category | What It Tests |
|---|---|---|
| 1–10 | HTML Body Escaping | The five dangerous HTML chars, img/svg payloads, combined cases |
| 11–20 | HTML Attribute Escaping | Quote breakout, event handler injection, edge chars |
| 21–30 | JavaScript String Escaping | Backslash order, newlines, `</script>` Unicode escape |
| 31–40 | URL Parameter Escaping | RFC 3986 unreserved chars, double-encoding, Unicode |
| 41–50 | Polyglot & Bypass Attempts | Gareth Heyes polyglot, null bytes, pre-encoded entities |
| 51–60 | CSP Header Building | Directive syntax, valueless directives, order preservation |
| 61–70 | Open Redirect Prevention | `javascript:`, `data:`, `vbscript:`, `//`, subdomain bypass |
| 71–80 | HTML Depth & Edge Cases | Double-encoding prevention, template literals, long strings |
| 81–90 | JS & URL Advanced Edge Cases | Tab preservation, at-sign encoding, multiple allowed hosts |

### Sample Output

```
╔════════════════════════════════════════════════════════════════════╗
║         XSS PREVENTION FRAMEWORK — 90 COMPREHENSIVE TESTS         ║
╚════════════════════════════════════════════════════════════════════╝

HTML Body Escaping  (10/10)
  ✅ PASS  Test 01 [HTML] Classic <script> tag
  ✅ PASS  Test 02 [HTML] Ampersand escape (must come before < >)
  ...

JavaScript String Escaping  (7/10)
  ✅ PASS  Test 21 [JS] Single-quote breakout
  ✅ PASS  Test 22 [JS] Double-quote breakout
  ❌ FAIL  Test 23 [JS] Backslash must be escaped first
       Expected: 'back\\\\slash'
       Got:      'back\\slash'
  ...

══════════════════════════════════════════════════════════════════════
SCORE: 74/90  (82%)

Almost there! Review the failed categories above.
Hint: Ensure escaping is truly context-specific —
      HTML body ≠ attribute ≠ JS string ≠ URL parameter.
```

---

## What Real-World XSS Prevention Looks Like

After you complete the exercise, compare your implementation to how production frameworks handle this:

**Django** auto-escapes HTML body context via its template engine — but it does *not* auto-escape JavaScript or URL contexts. You still need to use `escapejs` and `urlencode` template filters explicitly. (*Full Stack Python Security*, pp. 219-221)

**OWASP ESAPI** is the reference implementation of context-aware escaping for Java, and provides the mental model your implementation should follow for all six contexts.

**Content-Security-Policy** is your Layer 3 defense — even if an attacker injects a payload, a strict CSP `script-src 'nonce-{random}'` policy prevents it from executing. Your `build_csp_header` method is the foundation of that defense. (*Full Stack Python Security*, pp. 234-236)

---

## Common Mistakes

### ❌ Mistake 1: Sanitizing Instead of Escaping
Stripping `<` and `>` from input prevents legitimate use cases (code snippets, mathematical notation) and fails against encoded variants like `%3C` in URL context.

### ❌ Mistake 2: Using the Same Escaper for All Contexts
`escape_html` is not safe for JavaScript string context. `&lt;` inside a JS string literal renders as `&lt;` — it does not prevent `</script>` breakout.

### ❌ Mistake 3: Forgetting That `//` Is a Valid URL Prefix
Protocol-relative URLs like `//evil.com` are a classic open redirect bypass that trips up validators checking only for `http://evil.com`.

### ❌ Mistake 4: Adding a Trailing Space to Valueless CSP Directives
`upgrade-insecure-requests ` (with a trailing space) is a malformed CSP directive. Some browsers will ignore it silently.

### ❌ Mistake 5: Escaping `&` Last
If you run `text.replace('<', '&lt;')` before `text.replace('&', '&amp;')`, an input of `&lt;` gets double-encoded to `&amp;lt;` instead of `&amp;lt;`. Always escape `&` first.

---

## The Exercise

### Get the Challenge File

```bash
# Download from the P2P AppSec Exercises repository
git clone https://github.com/fosres/appsec-exercises
cd appsec-exercises/xss-prevention
python3 xss_prevention_90_tests.py
```

### What You'll Get
- A single Python file with the empty `XSSPrevention` class
- 90 deterministic test cases with colored pass/fail output
- Detailed failure messages showing expected vs. actual output
- Progressive hints based on your score

---

## What You'll Learn

- ✅ Why output context — not input sanitization — is the correct XSS defense
- ✅ The five HTML special characters and the correct escaping order
- ✅ Why JavaScript string context requires a different escaping strategy than HTML
- ✅ How `</script>` inside a JS string literal closes the script block prematurely
- ✅ RFC 3986 unreserved characters and percent-encoding for URL query parameters
- ✅ Content-Security-Policy directive syntax including valueless directives
- ✅ The three classes of dangerous URL schemes: `javascript:`, `data:`, `vbscript:`
- ✅ Protocol-relative URL bypass in open redirect validators

---

## For Hiring Managers

This exercise assesses:

- **Security fundamentals** — understanding of XSS at the mechanism level, not just "what is XSS"
- **Context-awareness** — recognizing that the same data requires different escaping depending on where it is rendered
- **Defensive programming** — implementing defense in depth rather than a single escaping pass
- **Python fluency** — clean, idiomatic string handling and OOP design
- **Attention to edge cases** — the polyglot and bypass test category specifically rewards candidates who think like attackers while writing defensive code

A candidate who passes all 90 tests has demonstrated the foundational secure coding knowledge expected of an Application Security Engineer at the junior-to-mid level.

---

## Level Up: After You Pass

1. **Extend the framework** — add `escape_css()` for safe CSS value insertion, another context Django's template engine does not auto-escape
2. **Build a linter** — write a Semgrep rule that detects raw string interpolation into HTML templates in Python codebases (the vulnerability your framework prevents)
3. **Integrate CSP reporting** — extend `build_csp_header` to support `report-to` groups with a JSON policy endpoint configuration
4. **Read the source** — compare your `escape_html` to Django's `django.utils.html.escape` and note what it does and does not cover

---

## Resources

- *Full Stack Python Security*, Ch. 14 — Dennis Byrne (Manning, 2021): the definitive treatment of XSS defense in Django
- *Secure by Design*, Ch. 9, pp. 247-249 — Johnsson, Deogun, Sawano (Manning, 2019): why never echoing input verbatim matters even in error messages
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — canonical escaping rules for all output contexts
- [Web Security Academy XSS Learning Path](https://portswigger.net/web-security/cross-site-scripting) — hands-on labs for the attacker's perspective
- [RFC 3986](https://tools.ietf.org/html/rfc3986#section-2.3) — unreserved character definition for URL escaping

---

*This challenge is part of the P2P AppSec Exercise Series — a collection of LeetCode-style secure coding exercises designed to curate high-quality, secure Python code for AI training datasets. The goal: train AI models to write secure code by default.*

*→ [P2P AppSec Exercises on GitHub](https://github.com/fosres/appsec-exercises)*  
---
title: "Week 8 Challenge: Build an Anti-XSS Output Encoding Framework"
published: true
description: "A LeetCode-style secure coding challenge — implement a context-aware XSS prevention framework covering HTML, attribute, JavaScript, URL, and CSP output contexts. 90 comprehensive tests. P2P AppSec Exercise Series."
tags: security, python, appsec, challenge
cover_image:
series: Security Engineering Interview Prep
---

# Security Challenge: Build an XSS Prevention Framework in Python

**Time:** 60–90 minutes  
**Difficulty:** Intermediate  
**Skills:** Web Application Security, Output Escaping, CSP, Open Redirect Prevention, Python OOP

---

## The Hook: 22 Lines That Broke British Airways

In 2018, attackers injected 22 lines of JavaScript into British Airways' payment page. For 15 days, every customer who typed their credit card number had it silently copied and sent to an attacker-controlled server. Around 500,000 customers were affected. The UK ICO fined British Airways £20 million.

The root cause? Unsanitized content rendered in the wrong context — the textbook definition of XSS.

This challenge asks you to build the framework that prevents that.

---

## How Often Do Security Engineers Actually Deal With This?

It depends heavily on which type of Security Engineering role you're in.

**Product Security Engineers at large tech companies** — you'll *audit* output encoding regularly but *implement* it from scratch rarely. The workflow looks like this in practice:

- Code review flags a place where user-controlled data is rendered without escaping, you file a bug, and the owning developer fixes it
- You write a Semgrep rule that detects the pattern statically so it never reaches review in the first place
- You update the secure coding guidelines or developer training to explain the correct escaping approach for each context
- You evaluate whether a framework's auto-escaping is being bypassed — the Django `|safe` filter situation that Byrne calls out explicitly in *Full Stack Python Security* (pp. 219-221) is a real and common example of this

Modern web frameworks handle HTML body context automatically. What trips teams up in practice is the other four contexts: JavaScript, URL, attribute, and CSP. Those are where real vulnerabilities appear because developers know the framework covers HTML body output but forget that it doesn't cover everything else.

**Security consulting and penetration testing roles** — you encounter output encoding failures constantly, but from the attacker side. You're identifying missing or incorrect escaping in client codebases, writing proof-of-concept payloads, and documenting remediation paths. The polyglot and bypass test category in this exercise maps directly to that work.

**The real day-to-day value of this exercise** is that it forces you to understand *why* each context is different at the mechanism level — which is exactly what Security Engineers are asked in code review scenarios and system design interviews. A question like "how does Django's template engine protect against XSS and where does that protection break down?" is entirely answerable from working through this exercise. That's a far more common interview question than "implement `escape_javascript` from scratch."

So: audit output encoding — frequently. Implement it from scratch — rarely. But understanding how it works at this level is what separates engineers who understand security from engineers who have merely used security tools.

---

## Why Input Sanitization Is the Wrong Answer

Before you write a single line of code, internalize this principle from *Full Stack Python Security* (Ch. 14, p. 218, Dennis Byrne, Manning 2021):

> "Input sanitization is always a bad idea because it is too difficult to implement."

Here's why. A sanitizer has to identify malicious content across at least three interpreters simultaneously: JavaScript, HTML, and CSS. Miss one context and you're back to square one. Worse, sanitizers corrupt legitimate data — a forum where users can post code snippets would mangle every post.

The correct defense, as Byrne explains, is **context-aware output escaping**. A `<` character is *only dangerous when rendered as HTML*. Escape it at the output layer, in the correct context. Leave the input alone.

*Secure by Design* (Ch. 9, pp. 247-249, Johnsson, Deogun, Sawano, Manning 2019) adds another sharp insight: never echo input verbatim in error messages. Even a URL-encoded payload like `%3Cscript%3Ealert(1)%3C%2Fscript%3E` becomes executable XSS inside a browser-based log analysis tool that doesn't escape its output.

---

## The Five Output Contexts

XSS is not one problem — it is five problems, one per output context. Each context requires a different escaping strategy:

| Context | Example | Wrong escape | Right escape |
|---|---|---|---|
| HTML body | `<p>{{ user_bio }}</p>` | Strip `<>` | Replace `< > & " '` with entities |
| HTML attribute | `<input value="{{ name }}">` | HTML-escape only | Also escape `"` and `'` |
| JavaScript string | `var name = "{{ name }}";` | HTML-escape | Backslash-escape + Unicode for `< > &` |
| URL parameter | `href="/search?q={{ query }}"` | URL-encode only reserved chars | Percent-encode everything except RFC 3986 unreserved chars |
| CSP header | `Content-Security-Policy: ...` | N/A | Build correct directive syntax |

Apply the HTML body escaper to a JavaScript string and you will break the page. Apply the JavaScript escaper to a URL and you will corrupt the link. Context mismatch is exactly how most real XSS vulnerabilities arise.

---

## The Challenge

Implement the `XSSPrevention` class with six methods:

```python
class XSSPrevention:

	def escape_html(self, text: str) -> str:
		"""Escape for HTML body context."""
		pass

	def escape_attribute(self, text: str) -> str:
		"""Escape for HTML attribute value context."""
		pass

	def escape_javascript(self, text: str) -> str:
		"""Escape for JavaScript string literal context."""
		pass

	def escape_url(self, text: str) -> str:
		"""Percent-encode for URL query parameter context."""
		pass

	def build_csp_header(self, directives: dict) -> str:
		"""Build a Content-Security-Policy header value."""
		pass

	def is_safe_url(self, url: str, allowed_hosts: list) -> bool:
		"""Return True only if the URL is safe for redirect."""
		pass
```

No imports from third-party libraries. No Django or Flask. Pure Python.

---

## Why This Is Harder Than It Looks

### Edge Case 1: Ampersand Must Be Escaped First

If you escape `<` before `&`, you get double-encoding bugs:

```python
# WRONG order
"<b>Tom & Jerry</b>"
→ "&lt;b&gt;Tom &amp;lt; Jerry&lt;/b&gt;"  # &lt; doubled!

# CORRECT order: & first, then < >
"<b>Tom & Jerry</b>"
→ "&lt;b&gt;Tom &amp; Jerry&lt;/b&gt;"
```

*Full Stack Python Security* Table 14.1 (p. 219) lists the five characters and implies the correct replacement order.

### Edge Case 2: JavaScript Context Needs Backslash First

In JS string escaping, if you escape quotes before backslashes, you corrupt existing escape sequences:

```python
# Input: back\slash
# WRONG: escape " before \
"back\\slash" → "back\\slash"  # \ not escaped, \s survives as-is

# CORRECT: escape \ first, then quotes
"back\\slash" → "back\\\\slash"
```

### Edge Case 3: `</script>` Inside a JS Block

Even inside a `<script>` tag, a `</script>` substring in a string literal will prematurely close the script block. The fix is to escape `<` and `>` to Unicode escapes (`\u003C`, `\u003E`) so the browser never sees the raw characters:

```python
xss.escape_javascript("</script>")
# → "\\u003C/script\\u003E"
```

### Edge Case 4: Valueless CSP Directives

Some CSP directives take no value — `upgrade-insecure-requests` is the most common. Your `build_csp_header` must output `upgrade-insecure-requests` (no trailing space) when the value is an empty string, not `upgrade-insecure-requests ` (with a space).

### Edge Case 5: Protocol-Relative URLs

An open redirect validator that only checks for `http://` and `https://` will miss `//evil.com/path` — a protocol-relative URL that the browser resolves using whatever scheme the current page uses. It must always return `False`.

```python
xss.is_safe_url("//evil.com/path", ["example.com"])
# → False (protocol-relative, not a safe relative path)
```

---

## The 90-Test Gauntlet

Your implementation faces 90 deterministic tests across nine categories — ten tests per category:

| # | Category | What It Tests |
|---|---|---|
| 1–10 | HTML Body Escaping | The five dangerous HTML chars, img/svg payloads, combined cases |
| 11–20 | HTML Attribute Escaping | Quote breakout, event handler injection, edge chars |
| 21–30 | JavaScript String Escaping | Backslash order, newlines, `</script>` Unicode escape |
| 31–40 | URL Parameter Escaping | RFC 3986 unreserved chars, double-encoding, Unicode |
| 41–50 | Polyglot & Bypass Attempts | Gareth Heyes polyglot, null bytes, pre-encoded entities |
| 51–60 | CSP Header Building | Directive syntax, valueless directives, order preservation |
| 61–70 | Open Redirect Prevention | `javascript:`, `data:`, `vbscript:`, `//`, subdomain bypass |
| 71–80 | HTML Depth & Edge Cases | Double-encoding prevention, template literals, long strings |
| 81–90 | JS & URL Advanced Edge Cases | Tab preservation, at-sign encoding, multiple allowed hosts |

### Sample Output

```
╔════════════════════════════════════════════════════════════════════╗
║         XSS PREVENTION FRAMEWORK — 90 COMPREHENSIVE TESTS         ║
╚════════════════════════════════════════════════════════════════════╝

HTML Body Escaping  (10/10)
  ✅ PASS  Test 01 [HTML] Classic <script> tag
  ✅ PASS  Test 02 [HTML] Ampersand escape (must come before < >)
  ...

JavaScript String Escaping  (7/10)
  ✅ PASS  Test 21 [JS] Single-quote breakout
  ✅ PASS  Test 22 [JS] Double-quote breakout
  ❌ FAIL  Test 23 [JS] Backslash must be escaped first
       Expected: 'back\\\\slash'
       Got:      'back\\slash'
  ...

══════════════════════════════════════════════════════════════════════
SCORE: 74/90  (82%)

Almost there! Review the failed categories above.
Hint: Ensure escaping is truly context-specific —
      HTML body ≠ attribute ≠ JS string ≠ URL parameter.
```

---

## What Real-World XSS Prevention Looks Like

After you complete the exercise, compare your implementation to how production frameworks handle this:

**Django** auto-escapes HTML body context via its template engine — but it does *not* auto-escape JavaScript or URL contexts. You still need to use `escapejs` and `urlencode` template filters explicitly. (*Full Stack Python Security*, pp. 219-221)

**OWASP ESAPI** is the reference implementation of context-aware escaping for Java, and provides the mental model your implementation should follow for all six contexts.

**Content-Security-Policy** is your Layer 3 defense — even if an attacker injects a payload, a strict CSP `script-src 'nonce-{random}'` policy prevents it from executing. Your `build_csp_header` method is the foundation of that defense. (*Full Stack Python Security*, pp. 234-236)

---

## Common Mistakes

### ❌ Mistake 1: Sanitizing Instead of Escaping
Stripping `<` and `>` from input prevents legitimate use cases (code snippets, mathematical notation) and fails against encoded variants like `%3C` in URL context.

### ❌ Mistake 2: Using the Same Escaper for All Contexts
`escape_html` is not safe for JavaScript string context. `&lt;` inside a JS string literal renders as `&lt;` — it does not prevent `</script>` breakout.

### ❌ Mistake 3: Forgetting That `//` Is a Valid URL Prefix
Protocol-relative URLs like `//evil.com` are a classic open redirect bypass that trips up validators checking only for `http://evil.com`.

### ❌ Mistake 4: Adding a Trailing Space to Valueless CSP Directives
`upgrade-insecure-requests ` (with a trailing space) is a malformed CSP directive. Some browsers will ignore it silently.

### ❌ Mistake 5: Escaping `&` Last
If you run `text.replace('<', '&lt;')` before `text.replace('&', '&amp;')`, an input of `&lt;` gets double-encoded to `&amp;lt;` instead of `&amp;lt;`. Always escape `&` first.

---

## The Exercise

### Get the Challenge File

```bash
# Download from the P2P AppSec Exercises repository
git clone https://github.com/fosres/appsec-exercises
cd appsec-exercises/xss-prevention
python3 xss_prevention_90_tests.py
```

### What You'll Get
- A single Python file with the empty `XSSPrevention` class
- 90 deterministic test cases with colored pass/fail output
- Detailed failure messages showing expected vs. actual output
- Progressive hints based on your score

---

## What You'll Learn

- ✅ Why output context — not input sanitization — is the correct XSS defense
- ✅ The five HTML special characters and the correct escaping order
- ✅ Why JavaScript string context requires a different escaping strategy than HTML
- ✅ How `</script>` inside a JS string literal closes the script block prematurely
- ✅ RFC 3986 unreserved characters and percent-encoding for URL query parameters
- ✅ Content-Security-Policy directive syntax including valueless directives
- ✅ The three classes of dangerous URL schemes: `javascript:`, `data:`, `vbscript:`
- ✅ Protocol-relative URL bypass in open redirect validators

---

## For Hiring Managers

This exercise assesses:

- **Security fundamentals** — understanding of XSS at the mechanism level, not just "what is XSS"
- **Context-awareness** — recognizing that the same data requires different escaping depending on where it is rendered
- **Defensive programming** — implementing defense in depth rather than a single escaping pass
- **Python fluency** — clean, idiomatic string handling and OOP design
- **Attention to edge cases** — the polyglot and bypass test category specifically rewards candidates who think like attackers while writing defensive code

A candidate who passes all 90 tests has demonstrated the foundational secure coding knowledge expected of an Application Security Engineer at the junior-to-mid level.

---

## Level Up: After You Pass

1. **Extend the framework** — add `escape_css()` for safe CSS value insertion, another context Django's template engine does not auto-escape
2. **Build a linter** — write a Semgrep rule that detects raw string interpolation into HTML templates in Python codebases (the vulnerability your framework prevents)
3. **Integrate CSP reporting** — extend `build_csp_header` to support `report-to` groups with a JSON policy endpoint configuration
4. **Read the source** — compare your `escape_html` to Django's `django.utils.html.escape` and note what it does and does not cover

---

## Resources

- *Full Stack Python Security*, Ch. 14 — Dennis Byrne (Manning, 2021): the definitive treatment of XSS defense in Django
- *Secure by Design*, Ch. 9, pp. 247-249 — Johnsson, Deogun, Sawano (Manning, 2019): why never echoing input verbatim matters even in error messages
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — canonical escaping rules for all output contexts
- [Web Security Academy XSS Learning Path](https://portswigger.net/web-security/cross-site-scripting) — hands-on labs for the attacker's perspective
- [RFC 3986](https://tools.ietf.org/html/rfc3986#section-2.3) — unreserved character definition for URL escaping

---

*This challenge is part of the P2P AppSec Exercise Series — a collection of LeetCode-style secure coding exercises designed to curate high-quality, secure Python code for AI training datasets. The goal: train AI models to write secure code by default.*

*→ [P2P AppSec Exercises on GitHub](https://github.com/fosres/appsec-exercises)*  
*→ [More challenges on dev.to/fosres](https://dev.to/fosres)*
*→ [More challenges on dev.to/fosres](https://dev.to/fosres)*
