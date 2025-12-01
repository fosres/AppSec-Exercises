**[→ Skip to the Exercise](#try-the-challenge)**

---

# Atlassian OS Path Traversal Attack

March 20, 2019. 3:47 AM. An Atlassian engineer wakes up to their phone exploding with alerts. Every Confluence server in their fleet is encrypting itself. Ransomware. Over 10,000 enterprise installations compromised worldwide.

The root cause? Two characters: `../`

The damage? North of $10 million in recovery costs. Emergency patches pushed to hundreds of thousands of servers. And here's the part that keeps me up at night: **this exact vulnerability is still shipping in production code today.**

In today's exercise you are challenged to validate if a filesystem path is vulnerable to OS Path Traversal.

---

## The Challenge

I put together 100 test cases that simulate real attacks I've seen in threat models, penetration tests, and CVE disclosures. Not toy examples. Not "could theoretically happen." These are patterns from:

- **CVE-2019-3396** (Atlassian Confluence) - The $10M disaster
- **CVE-2022-24765** (Git) - Compromised enterprise Git servers
- **Zip Slip** (Snyk, 2018) - Hit Oracle, Amazon, Spring, LinkedIn, Twitter

Your job: Write `is_safe_path()` that passes all 100 tests.

The idea is to check if `requested_path` is leads to a path outside of `base_path`.

```python
def is_safe_path(base_dir: str, requested_path: str) -> bool:
	"""
	Return True if the path is safe.
	Return False if it's a path traversal attack.
	"""
	# Your implementation here
	pass
```

Simple interface. Brutal test suite.

---

## Why This Bug Won't Die

I've been asking myself this for years. Path traversal has been in the OWASP Top 10 for over a decade. We *know* about it. Security training covers it. And yet...

### It Looks Harmless in Code Review

```python
# Looks fine, right?
@app.route('/download')
def download_file():
	filename = request.args.get('file')
	return send_file(f"/uploads/{filename}")
```

Ship it. The code reviewer nods. Nobody catches it. Then someone hits your endpoint with:

```
/download?file=../../../../etc/passwd
```

Game over.

### Simple Filters Don't Work

Early in my career, I thought I was clever:

```python
if ".." in requested_path:
	return False  # Blocked!
```

Except attackers aren't stupid. They'll send:

```python
"..%2f..%2fetc%2fpasswd"        # URL encoding
"%252e%252e%252fetc%252fpasswd"  # Double URL encoding
"....//....//etc/passwd"         # Confluence CVE-2019-3396
```

Your naive filter sees gibberish. The OS sees `../../../etc/passwd`.

### Normalization Happens at the Wrong Layer

Web framework decodes the URL. Maybe once. Maybe twice. Maybe your WAF does it too. By the time your validator sees the path, you have no idea how many transformations it's been through.

---

## What's in the Challenge

I structured this based on real attack categories I've documented:

**Classic Path Traversal (Tests 1-25)**
```python
"../../../etc/passwd"
"/etc/passwd"
"images/../../config/database.yml"
```

The basics. If you fail these, stop and read "API Security in Action" Chapter 8.

**URL Encoding Bypasses (Tests 61-75)**
```python
# Single encoding
"%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Double encoding (WAF bypass)
"%252e%252e%252fetc%252fpasswd"

# Triple encoding (paranoid attacker)
"%25252e%25252e%25252fetc%25252fpasswd"
```

From "Full Stack Python Security" Chapter 6. These are real bypass techniques from pentest reports.

**Null Byte Injection (Tests 76-80)**
```python
"images/logo.png\x00../../etc/passwd"
"file.txt\x00.php"
```

Historical attack. Python 3 blocks null bytes at the OS level, but defense-in-depth says reject them anyway.

**Linux System Files (Tests 81-85)**
```python
"../../../../proc/self/environ"      # Steal environment variables
"../../../../sys/class/net/eth0/address"  # Get MAC address
"../../../../root/.ssh/id_rsa"      # Grab SSH keys
```

Real targets from actual attacks. `/proc/self/environ` leaks database credentials, API keys, secrets. I've seen it happen.

**CVE-Inspired Patterns (Tests 91-100)**
```python
".git/../../../etc/passwd"              # CVE-2022-24765
"../../../../tmp/malicious.sh"          # Zip Slip
"..;/..;/etc/passwd"                    # CVE-2019-3396
```

Straight from disclosed vulnerabilities. If your validator doesn't catch these, you're shipping the same bugs that cost Atlassian millions.

---

## Try the Challenge

**GitHub:** [fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)

⭐ **Star the repo** if you find this useful. It helps me know what exercises to build next.

```bash
git clone https://github.com/fosres/AppSec-Exercises.git
cd AppSec-Exercises
python3 path_validator_100_tests.py
```

When you pass all 100 tests:

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                   🎉 PERFECT! ALL 100 TESTS PASSED! 🎉                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

Your path validator is PRODUCTION-READY! 🛡️

You've successfully defended against:
  ✅ Classic path traversal attacks (../, /etc/passwd)
  ✅ URL-encoded bypasses (single, double, triple encoding)
  ✅ Null byte injection attempts
  ✅ Linux system file access (/proc, /sys, /dev)
  ✅ Real-world CVE patterns (Git, Confluence, Zip Slip)
```

Then post your victory. Tag me. Let me know what surprised you.

---

## What You'll Actually Learn

Not just "how to validate paths." You'll understand:

**Why `os.path.normpath()` matters**
```python
# Before normalization
"/var/www/images/../../../etc/passwd"

# After normalization
"/etc/passwd"

# Now you can actually validate it
```

**Why string matching fails**
```python
# Naive approach
if ".." in path:
	return False

# Blocks valid files!
"file...."        # Valid filename on Linux
"config..."       # Valid filename on Linux
"my....backup"    # Valid filename on Linux
```

Yes, `"..."` is a legitimate filename on Linux. Try it: `touch ...` 

Your validator needs to understand filesystem semantics, not just do string matching.

**Why URL encoding behaves differently at different layers**

Linux kernel only recognizes `/` (ASCII 0x2F) as a path separator. URL-encoded `%2F` is just literal characters to the filesystem. But your web framework might decode it first. Then your WAF. Then... you get the idea.

This is why the tests include encoded paths that should return `True` (safe) — because Linux treats them as literal characters. Your validator runs *after* the framework has decoded them.

---

## Why I Built This

I'm building a P2P open source project to curate high-quality secure code datasets. The goal: train AI models to write secure code by default.

Current AI coding assistants generate vulnerable code because they're trained on GitHub repos full of bugs. I'm trying to change that.

This path traversal challenge is part of that effort. Every exercise I create:

- Tests real-world attack vectors
- Teaches defensive programming
- Includes production-grade solutions
- References actual CVEs and security research

**Want weekly AppSec challenges like this?**

📧 **[Join the mailing list](https://buttondown.email/fosres)**

I send:
- LeetCode-style security challenges
- Real CVE breakdowns
- Solutions with detailed explanations
- Early access to new exercises

No spam. No ads. Just practical AppSec skills for people who actually ship code.

---

## The Bigger Picture

I documented 553 security threats at Intel. That's a lot of late nights reviewing threat models, analyzing attack vectors, and writing mitigation strategies. You know what I learned?

**Most vulnerabilities are stupidly simple.**

Path traversal. SQL injection. XSS. We've known about these for 20+ years. They're in every security course. Every "Top 10" list. And they're *still* in production code.

Not because developers are bad. Because secure coding is hard when:
- You're shipping fast
- You're copying from Stack Overflow
- You're trusting AI-generated code
- You're assuming the framework handles it

It doesn't. The framework doesn't handle it. The library doesn't handle it. *You* have to handle it.

That's why I'm building these exercises. Not to lecture. Not to shame. But to give you hands-on practice with the patterns that actually matter.

---

## Resources I Used

These aren't random tests. Every single one comes from documented attacks or security research:

**Books (with specific pages):**
- 📖 "API Security in Action" by Neil Madden (Chapter 8, pp. 251-254)
- 📖 "Full Stack Python Security" by Dennis Byrne (Chapter 6, pp. 123-127)
- 📖 "Secure by Design" by Johnsson, Deogun, Sawano (Chapter 7, pp. 189-193)
- 📖 "Hacking APIs" by Corey J. Ball (Chapter 4: Common API Vulnerabilities)
- 📖 "Python Workout" by Reuven Lerner (Chapter 2: Strings)

**CVEs:**
- [CVE-2019-3396: Atlassian Confluence](https://confluence.atlassian.com/doc/confluence-security-advisory-2019-03-20-966660264.html)
- [CVE-2022-24765: Git Path Traversal](https://github.blog/2022-04-12-git-security-vulnerability-announced/)
- [Zip Slip Vulnerability (Snyk Research)](https://snyk.io/research/zip-slip-vulnerability)

**OWASP:**
- [Path Traversal Attack](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html)

I cite these because I want you to go deeper. The challenge teaches you the patterns. The books teach you why they matter.

---

## What Happens Next

### 1. Take the Challenge

Clone the repo. Run the tests. See if you can pass all 100.

### 2. ⭐ Star the Repository

If this helped you, star it: [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises)

It tells me this kind of content is valuable. And it helps other developers find it.

### 3. 📧 Join the Mailing List

[Subscribe here](https://buttondown.email/fosres) for more challenges like this.

I'm aiming for one new exercise per week. Each one focused on a different OWASP vulnerability or CVE pattern.

### 4. Share Your Results

When you complete it:
- Post your completion time in the comments
- Share what surprised you
- Tell me what CVE or vulnerability to cover next

I read every response. I use your feedback to build better exercises.

---

## Final Thoughts

Path traversal is 20+ years old. It's documented. It's well-understood. It's in the OWASP Top 10, the CWE Top 25, every security training course.

And it's *still* showing up in production.

Atlassian learned this the hard way. $10+ million in damages. 10,000+ compromised servers. Emergency patches. PR disasters.

You don't have to.

Take the challenge. Learn the patterns. Build the muscle memory. So the next time you write file handling code, you automatically think: "How could this escape the base directory?"

Because that one thought—that one validation—is the difference between shipping secure code and shipping CVE-2024-XXXXX.

Let's build a more secure internet. One validated path at a time.

---

**[Try the challenge on GitHub →](https://github.com/fosres/AppSec-Exercises)**

**[Get weekly AppSec exercises →](https://buttondown.email/fosres)**

---

*Drop a comment if you complete the challenge. I want to hear what you learned.*

