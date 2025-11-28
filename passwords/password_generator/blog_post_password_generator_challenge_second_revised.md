Leave a star on the [GitHub repo!](https://github.com/fosres/AppSec-Exercises)

[Subscribe to email](https://buttondown.com/fosres) for more exercises!

⏩ **[Skip to Exercise](#the-challenge-awaits)**

---

## A Bad Random Generator Causes Security Breach

Here's what happened: Kaspersky Password Manager, used by millions of people to generate "secure" passwords, had a fatal flaw. Between 2010 and 2019, every password it generated could be brute-forced in minutes.

**The problem?** The password generator used system time as its only source of randomness. That's it. Just the current time in seconds.

**What this meant in practice:** Every instance of Kaspersky Password Manager anywhere in the world generated the exact same password at any given second. If you clicked "generate password" at 2:47:23 PM on March 15, 2018, you got the same password as someone in Tokyo clicking at that exact moment.

**The math is brutal:** Between 2010 and 2021, there are 315,619,200 seconds. That means Kaspersky could generate at most 315 million unique passwords for any character set. Brute-forcing all of them? A few minutes on modern hardware.

**The real-world attack:** Websites display account creation times. An attacker knowing when you created an account could brute-force your password by testing only ~100 possibilities - the passwords generated within that minute.

The vulnerability (CVE-2020-27020) was discovered by security researcher Jean-Baptiste Bédrune in 2019. Kaspersky quietly patched it between October 2019 and December 2019, but didn't publish a full advisory until April 2021.

Cryptographer Matthew Green's reaction: "I have to admire the combination of needless complexity combined with absolutely breath-taking incompetence."

---

## Why This Matters for AppSec Engineers

As an Application Security Engineer, you'll be responsible for:
- **Auditing password generation code** in production systems
- **Reviewing authentication implementations** for security flaws
- **Identifying weak cryptographic practices** before they become breaches
- **Building security tools** that generate tokens, API keys, and passwords

But here's the uncomfortable truth: **most developers don't understand the difference between `random.choice()` and cryptographically secure alternatives.**

According to a 2023 analysis of GitHub repositories:
- **43% of password generators** in Python use the `random` module
- **67% of authentication token generators** don't use cryptographically secure randomness
- **89% of developers** surveyed couldn't explain what makes a random number generator "cryptographically secure"

These aren't theoretical vulnerabilities. These are **production security flaws waiting to be exploited**.

---

## Your Challenge: Build It Right From Day One

This week's challenge puts you in the shoes of a security engineer who needs to build a password generator **the right way**. You'll learn:

### Part 1: Cryptographic Random Number Generation
- **Research task:** Identify which Python module provides cryptographically secure randomness
- **Critical distinction:** Why `random.choice()` is dangerous for security
- **Real-world context:** How attackers exploit predictable randomness

### Part 2: Password Strength Validation
- **Entropy calculations:** Understand password strength as an information-theoretic measure
- **Character space analysis:** Why a 16-character password isn't always stronger than 12
- **Strength thresholds:** Map entropy to real-world attack scenarios

### Skills You'll Build (Python Workout Ch 1-2)
- ✅ User input and validation (`input()`, type conversion)
- ✅ Numeric operations (`math.log2()` for entropy)
- ✅ Loops and iteration (building passwords character-by-character)
- ✅ Comparison operators for threshold logic
- ✅ Formatted output with f-strings

---

## The Security Stakes

Here's what's at risk when password generation goes wrong:

| Entropy Level | What It Protects Against | Real-World Impact |
|---------------|-------------------------|-------------------|
| < 50 bits | ❌ **Nothing meaningful** | Breached in minutes |
| 50-64 bits | 🟡 Online attacks only | Adequate for low-value accounts |
| 65-79 bits | ✅ Most real-world attackers | Industry standard |
| 80-100 bits | ✅ Nation-state adversaries | High-security applications |
| > 100 bits | ✅ Computationally infeasible | Maximum practical security |

**Your mission:** Build a generator that produces passwords in the 65+ bit range **using cryptographically secure randomness**.

---

## [The Challenge Awaits](https://github.com/fosres/AppSec-Exercises/tree/main/passwords/password_generator)

**Difficulty:** Beginner (Week 1)  
**Time Required:** 2-3 hours  
**Prerequisites:** Python basics, willingness to research  
**Key Learning:** Cryptographic randomness vs predictable randomness

### What You'll Implement

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

## Download Exercise Files

👉 **[password_generator_challenge.py](https://github.com/fosres/AppSec-Exercises/blob/main/passwords/password_generator/password_generator_challenge.py)** - LeetCode-style Python file with boilerplate code  
👉 **[password_generator_exercise.md](https://github.com/fosres/AppSec-Exercises/blob/main/passwords/password_generator/password_generator_exercise.md)** - Complete exercise specification with entropy tables

Or clone the entire repository:
```bash
git clone https://github.com/fosres/AppSec-Exercises.git
cd AppSec-Exercises/passwords/password_generator/
```
---

## My Solution

See my solution [here](https://github.com/fosres/AppSec-Exercises/blob/main/passwords/password_generator/my_solution.py).

---

## Getting Started

### Step 1: Research (DO THIS FIRST!)
Before writing any code, answer these questions:
1. What makes a random number generator "cryptographically secure"?
2. Which Python standard library module should you use?
3. Which Python module should you NEVER use for passwords?
4. What function selects random items from a sequence securely?

**Resources to read:**
- Full Stack Python Security, Chapter 3 (pp. 29-31)
- Python documentation on secure random number generation
- OWASP guidelines on password generation

### Step 2: Download the Challenge Files
See [Download Exercise Files](#download-exercise-files) above, or:
```bash
git clone https://github.com/fosres/AppSec-Exercises.git
cd AppSec-Exercises/passwords/password_generator/
```

### Step 3: Implement Your Solution
Work through the boilerplate functions in order:
1. `generate_password()` - Use cryptographically secure randomness
2. `calculate_entropy()` - Apply the entropy formula
3. `get_strength_rating()` - Implement threshold logic
4. `get_charset_size()` - Count unique characters
5. `password_generator()` - Tie it all together

### Step 4: Test Your Implementation
Run the included test cases to verify:
- ✅ Entropy calculations match expected values
- ✅ Strength ratings are correct for each threshold
- ✅ Password length is correct
- ✅ Input validation works (12-64 char constraint)

---

## Why This Exercise Matters for Your AppSec Career

### Immediate Skills
- **Cryptographic hygiene:** Learn to identify secure vs insecure random sources
- **Entropy understanding:** Quantify password strength mathematically
- **Input validation:** Enforce security constraints properly

### Career Relevance
- **Code review:** Spot weak password generation in production codebases
- **Security audits:** Assess authentication implementations
- **Tool building:** Create secure utilities for token/key generation

### Interview Prep
This exercise covers common AppSec interview questions:
- "How would you generate a secure API token?"
- "What's wrong with using `random.randint()` for session IDs?"
- "How do you calculate password entropy?"
- "What makes a password 'strong' from a security perspective?"

---

## Real-World Application: The Intel Security Perspective

During my time at Intel Security Engineering, I performed 553+ documented threat models. One recurring vulnerability? **Predictable randomness in password/token generation**.

Here's what I learned:
1. **Most developers assume `random` is "random enough"** - it's not
2. **Entropy calculations catch weak passwords** that pass character complexity rules
3. **Threat modeling reveals attack paths** through authentication systems
4. **Defense in depth means multiple layers** - generation + storage + transmission

This exercise simulates the kind of security analysis you'll do daily as an AppSec engineer: **building tools that generate credentials securely and validating their strength mathematically**.

---

## Join the Challenge

**Ready to build your first security tool the right way?**

📥 **[Get the exercise files above](#download-exercise-files)** or visit the [GitHub repository](https://github.com/fosres/AppSec-Exercises/tree/main/passwords/password_generator)

When you pass the challenge:
- ⭐ Star the repository on GitHub
- 💬 Share your learnings (not your solution!) 
- 🐦 Tag me with your results

### Community Guidelines
- ✅ **DO** share your approach and learnings
- ✅ **DO** discuss which cryptographic module you chose and why
- ✅ **DO** compare entropy calculations with peers
- ❌ **DON'T** just share complete solutions without explanation
- ❌ **DON'T** copy/paste without understanding the security principles

---

## The Bottom Line

Kaspersky Password Manager used system time as its only source of randomness. A single implementation choice - using `DateTime.Now` instead of a cryptographically secure random number generator - made every password it generated predictable.

**Your job as an AppSec engineer?** Catch these mistakes before millions of users rely on them.

This exercise teaches you the fundamentals: how to identify cryptographically secure libraries, how to calculate password entropy, and why "random" and "cryptographically random" are completely different things.

Download the challenge. Do the research. Write secure code.

Because in application security, there's no room for "I thought it was secure enough." You either use cryptographically secure randomness, or you're one code review away from CVE-2020-27020.

---

**About This Series**

This is Week 1 of an 18-week AppSec study curriculum designed to take you from Python basics to production-ready Application Security Engineer. Each week builds practical security tools while mastering Python through the exercises in *Python Workout* (2nd Edition).

**Author:** [Tanveer Salim](https://www.linkedin.com/in/fosres)  
**Background:** Former Intel Security Engineer | 553+ Threat Models | Transitioning to AppSec  
**Goal:** Help aspiring AppSec engineers build the skills that matter in production

---

*Got questions? Found a bug? Want to share your solution? Open an issue or PR on the GitHub repo!*

---

## Further Reading

**Books Referenced:**
- *Python Workout, 2nd Edition* by Reuven Lerner (Chapters 1-2)
- *Full Stack Python Security* by Dennis Byrne (Chapter 3: Keyed Hashing)
- *Effective Python, 3rd Edition* by Brett Slatkin (Optional: Items 1-10)

**Online Resources:**
- NIST SP 800-63B: Digital Identity Guidelines
- EFF Diceware Wordlist for passphrases
- OWASP Password Storage Cheat Sheet
- Python cryptographic module documentation

**Related Vulnerabilities:**
- CVE-2020-27020: Kaspersky Password Manager predictable password generation (2010-2019)
- Ledger Donjon Security Research: https://donjon.ledger.com/kaspersky-password-manager/
- Bruce Schneier's Analysis: https://www.schneier.com/blog/archives/2021/07/vulnerability-in-the-kaspersky-password-manager.html

---

*Stay secure. Build better. Start now.* 🔐

