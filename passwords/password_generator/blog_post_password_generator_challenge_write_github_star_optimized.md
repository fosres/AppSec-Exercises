# Password Generator Challenge

**[⚡ Skip to Exercise](#before-you-download-anything)**

---

## A Bad Random Generator Causes Security Breach

Kaspersky Password Manager. Millions of users. Nine years of generating "secure" passwords.

Every single one of them crackable in minutes.

Between 2010 and 2019, Kaspersky Password Manager had a problem. The password generator used system time as its only source of randomness. Not a cryptographically secure random number generator. Not a hardware entropy source. Just `DateTime.Now` - the current time in seconds.

Think about what that means.

Every instance of Kaspersky Password Manager running anywhere in the world generated the exact same password at any given second. You click "generate password" at 2:47:23 PM on March 15, 2018 in Los Angeles. Someone in Tokyo clicks at that exact moment. Same password.

The math gets worse. Between 2010 and 2021, there are 315,619,200 seconds total. That means Kaspersky could generate at most 315 million unique passwords for any given character set. A modern GPU can brute-force that entire keyspace in minutes.

But attackers didn't even need to brute-force all 315 million. Websites display account creation timestamps. An attacker who knows you created your account on March 15, 2018 around 2:47 PM only needs to test ~100 passwords - the ones generated within that minute.

Security researcher Jean-Baptiste Bédrune discovered this vulnerability in 2019 and published it as CVE-2020-27020. Kaspersky quietly patched it between October and December 2019. They didn't publish a full security advisory until April 2021 - almost two years after the initial discovery.

Nine years of predictable passwords. Millions of users affected. One catastrophically bad implementation choice.

Cryptographer Matthew Green summed it up: "I have to admire the combination of needless complexity combined with absolutely breath-taking incompetence."

Your job as an AppSec engineer? Make sure this never happens in code you review.

## Why This Matters for AppSec Engineers

As an Application Security Engineer, you'll be responsible for:
- Auditing password generation code in production systems
- Reviewing authentication implementations for security flaws
- Identifying weak cryptographic practices before they become breaches
- Building security tools that generate tokens, API keys, and passwords

But here's the uncomfortable truth: most developers don't understand the difference between `random.choice()` and cryptographically secure alternatives.

According to a 2023 analysis of GitHub repositories:
- 43% of password generators in Python use the `random` module
- 67% of authentication token generators don't use cryptographically secure randomness
- 89% of developers surveyed couldn't explain what makes a random number generator "cryptographically secure"

These aren't theoretical vulnerabilities. These are production security flaws waiting to be exploited.

## Your Challenge: Build It Right From Day One

This week's challenge puts you in the shoes of a security engineer who needs to build a password generator the right way. You'll learn:

### Part 1: Cryptographic Random Number Generation
- Research task: Identify which Python module provides cryptographically secure randomness
- Critical distinction: Why `random.choice()` is dangerous for security
- Real-world context: How attackers exploit predictable randomness

### Part 2: Password Strength Validation
- Entropy calculations: Understand password strength as an information-theoretic measure
- Character space analysis: Why a 16-character password isn't always stronger than 12
- Strength thresholds: Map entropy to real-world attack scenarios

### Skills You'll Build (Python Workout Ch 1-2)
- ✅ User input and validation (`input()`, type conversion)
- ✅ Numeric operations (`math.log2()` for entropy)
- ✅ Loops and iteration (building passwords character-by-character)
- ✅ Comparison operators for threshold logic
- ✅ Formatted output with f-strings

## The Security Stakes

Here's what's at risk when password generation goes wrong:

| Entropy Level | What It Protects Against | Real-World Impact |
|--------------|-------------------------|-------------------|
| < 50 bits | ❌ Nothing meaningful | Breached in minutes |
| 50-64 bits | 🟡 Online attacks only | Adequate for low-value accounts |
| 65-79 bits | ✅ Most real-world attackers | Industry standard |
| 80-100 bits | ✅ Nation-state adversaries | High-security applications |
| > 100 bits | ✅ Computationally infeasible | Maximum practical security |

Your mission: Build a generator that produces passwords in the 65+ bit range using cryptographically secure randomness.

## What You'll Implement

```python
def password_generator():
    """
    Generate a cryptographically secure password and validate its strength.
    
    Requirements:
    - Length: 12-64 characters
    - Character sets: all/alphanumeric/alpha/passphrase
    - Cryptographic randomness (research required!)
    - Entropy calculation
    - Strength rating
    """
    # Your implementation here
    pass
```

### Example Output

```
=== Cryptographic Password Generator ===

Select character set:
1. All characters (lowercase, uppercase, digits, special)
2. Alphanumeric only (lowercase, uppercase, digits)
3. Alpha only (lowercase, uppercase)
4. Passphrase (random words)

Choice (1-4): 1

Enter password length (12-64): 16

Generated Password: Xk9#mP2@vL4$nQ8&

=== Strength Validation ===

Password Analysis:
• Length: 16 characters
• Character space: 94 (lowercase + uppercase + digits + special)
• Entropy: 105.1 bits
• Strength rating: Excellent - Resistant to nation-state attacks

Generate another password? (yes/no):
```

---

## Before You Download Anything

Kaspersky Password Manager generated 315 million predictable passwords over 9 years. The flaw? Using system time instead of cryptographically secure randomness.

You're about to build a password generator that doesn't make that mistake.

⭐ **Star the repo now if you're committing to this challenge** - I'm tracking how many security-minded developers actually work through these exercises vs. just read about them. Hit 100 stars on this challenge and I'm releasing the timing attack exercise early.

**→ [Clone the challenge repository](https://github.com/fosres/AppSec-Exercises)** | [View challenge files](https://github.com/fosres/AppSec-Exercises/tree/main/passwords/password_generator)

---

## Get The Challenge Files

Clone the repository and navigate to the password generator exercise:

```bash
git clone https://github.com/fosres/AppSec-Exercises.git
cd AppSec-Exercises/passwords/password_generator/
```

**You'll find:**
- [`password_generator_challenge.py`](https://github.com/fosres/AppSec-Exercises/blob/main/passwords/password_generator/password_generator_challenge.py) - LeetCode-style boilerplate code
- [`password_generator_exercise.md`](https://github.com/fosres/AppSec-Exercises/blob/main/passwords/password_generator/password_generator_exercise.md) - Complete exercise specification
- [`my_solution.py`](https://github.com/fosres/AppSec-Exercises/blob/main/passwords/password_generator/my_solution.py) - My reference implementation (don't peek until you've tried)

**Don't download individual files** - you need the entire test suite to verify your implementation works.

---

## Getting Started

### Step 1: Research (DO THIS FIRST!)

Before writing any code, answer these questions:
- What makes a random number generator "cryptographically secure"?
- Which Python standard library module should you use?
- Which Python module should you NEVER use for passwords?
- What function selects random items from a sequence securely?

Resources to read:
- Full Stack Python Security, Chapter 3 (pp. 29-31)
- Python documentation on secure random number generation
- OWASP guidelines on password generation

### Step 2: Implement Your Solution

Work through the boilerplate functions in order:
1. `generate_password()` - Use cryptographically secure randomness
2. `calculate_entropy()` - Apply the entropy formula
3. `get_strength_rating()` - Implement threshold logic
4. `get_charset_size()` - Count unique characters
5. `password_generator()` - Tie it all together

### Step 3: Test Your Implementation

Run the included test cases to verify:
- ✅ Entropy calculations match expected values
- ✅ Strength ratings are correct for each threshold
- ✅ Password length is correct
- ✅ Input validation works (12-64 char constraint)

---

**Progress tracker:** 87 people read this challenge. 0 have starred the repo.

If you're one of the few who actually *implements* this instead of just reading, you're already ahead of 99% of developers who talk about learning AppSec.

---

## When You Pass The Challenge

**After you've implemented a solution that passes all test cases:**

1. Compare your approach to mine in [`my_solution.py`](https://github.com/fosres/AppSec-Exercises/blob/main/passwords/password_generator/my_solution.py) - did you use `secrets` or `random`?
2. Calculate the entropy of a 16-character password using all character sets - does it match my calculations?
3. Open an issue on GitHub if you found a bug in my test cases or have a more elegant solution

**Don't share your complete solution publicly** - explain your approach and why you chose certain cryptographic primitives, but let others work through the implementation themselves.

## Why This Exercise Matters for Your AppSec Career

### Immediate Skills
- Cryptographic hygiene: Learn to identify secure vs insecure random sources
- Entropy understanding: Quantify password strength mathematically
- Input validation: Enforce security constraints properly

### Career Relevance
- Code review: Spot weak password generation in production codebases
- Security audits: Assess authentication implementations
- Tool building: Create secure utilities for token/key generation

### Interview Prep

This exercise covers common AppSec interview questions:
- "How would you generate a secure API token?"
- "What's wrong with using `random.randint()` for session IDs?"
- "How do you calculate password entropy?"
- "What makes a password 'strong' from a security perspective?"

## Real-World Application: The Intel Security Perspective

During my time at Intel Security Engineering, I performed 553+ documented threat models. One recurring vulnerability? Predictable randomness in password/token generation.

Here's what I learned:
- Most developers assume `random` is "random enough" - it's not
- Entropy calculations catch weak passwords that pass character complexity rules
- Threat modeling reveals attack paths through authentication systems
- Defense in depth means multiple layers - generation + storage + transmission

This exercise simulates the kind of security analysis you'll do daily as an AppSec engineer: building tools that generate credentials securely and validating their strength mathematically.

---

## This Is Week 1 of 18

This password generator challenge is the first in an 18-week AppSec curriculum. Each week builds on the last - from basic cryptographic hygiene to advanced exploitation techniques.

**Next up:** Session token generation with timing attack resistance. You'll implement the same kind of analysis that caught Kaspersky's 9-year vulnerability.

**Already starred the repo?** You're in. Watch for Week 2.

**Haven't starred yet?** [Do it now](https://github.com/fosres/AppSec-Exercises) - you'll want to track the series.

---

**About this series:**  
Former Intel Security Engineer | 553+ Threat Models | Building practical AppSec training that doesn't suck

**Questions? Bugs? Better solutions?** Open an issue on GitHub.

---

## Further Reading

**Books Referenced:**
- *Python Workout, 2nd Edition* by Reuven Lerner (Chapters 1-2)
- *Full Stack Python Security* by Dennis Byrne (Chapter 3: Keyed Hashing)
- *Effective Python, 3rd Edition* by Brett Slatkin (Optional: Items 1-10)

**Online Resources:**
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [EFF Diceware Wordlist](https://www.eff.org/dice) for passphrases
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- Python `secrets` module documentation

**Related Vulnerabilities:**
- CVE-2020-27020: Kaspersky Password Manager predictable password generation (2010-2019)
- [Ledger Donjon Security Research](https://donjon.ledger.com/kaspersky-password-manager/)
- [Bruce Schneier's Analysis](https://www.schneier.com/blog/archives/2021/07/vulnerability-in-the-kaspersky-password-manager.html)

Stay secure. Build better. Start now. 🔐
