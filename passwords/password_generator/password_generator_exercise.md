# Exercise: Cryptographic Password Generator and Strength Validator

## Challenge Description

Write a function `password_generator()` that **first generates** a cryptographically secure password using an industry-standard Python library, then **validates** its strength against security requirements. This two-phase approach reflects real-world security practice: you cannot meaningfully assess password strength without understanding how the password was generated.

**Why Generation-First Matters:**
Without knowledge of the password generation implementation, strength assessment is unreliable. A password like `Tr0ub4dor&3` might appear strong by character composition rules, but if it was selected from a small dictionary of 10,000 common passwords, it's trivially weak. Conversely, a randomly generated 12-character password from a 94-character space has ~79 bits of entropy regardless of whether it "looks" strong to pattern-matching rules.

## Part 1: Cryptographic Password Generation

Implement a password generator using a **cryptographically secure random number source**:

**Your First Task: Research**
Before writing any code, you must research and identify which Python library/module provides cryptographically secure random number generation. Consider:
- What makes a random number generator "cryptographically secure"?
- What are the security risks of using a predictable random number generator?
- Which Python standard library modules are suitable for security-critical randomness?
- Which modules should NEVER be used for password generation, and why?

**Hint:** Review the security references at the end of this exercise. Pay special attention to warnings about random number generation for security purposes.

**Generator Requirements:**
1. **Accept a length parameter: MINIMUM 12 characters, MAXIMUM 64 characters**
2. Accept a character set specification:
   - `'all'`: Lowercase + Uppercase + Digits + Special chars `!@#$%^&*()-_+=[]{}|;:,.<>?`
   - `'alphanumeric'`: Lowercase + Uppercase + Digits only
   - `'alpha'`: Lowercase + Uppercase only
   - `'passphrase'`: 4-6 random words from a word list (if available)
3. Use the appropriate cryptographic library function to select each character
4. For passphrases, use the same cryptographic function to select words and join with `-`
5. Display the generated password to the user

**⚠️ CRITICAL CONSTRAINT: All character-based passwords must be between 12-64 characters in length.**

**Critical Security Principle:**
Your choice of random number generation library will determine whether the passwords you generate are secure or trivially breakable. Research carefully before implementing.

## Part 2: Password Strength Validation

After generating the password, calculate its theoretical strength:

**Validation Metrics:**

1. **Character Space Size** (calculate based on what character types are present):
   - Lowercase only: 26
   - + Uppercase: 52
   - + Digits: 62
   - + Special chars: 94 (for the full special char set)

2. **Entropy Calculation** (bits):
   ```
   Entropy = length × log₂(character_space_size)
   ```
   Use Python's `math.log2()` function

3. **Strength Rating** (based on entropy):
   - < 50 bits: "Weak - Vulnerable to modern attacks"
   - 50-64 bits: "Moderate - Acceptable for low-security contexts"
   - 65-80 bits: "Strong - Recommended for most applications"  
   - 80-100 bits: "Very Strong - Suitable for high-security applications"
   - > 100 bits: "Excellent - Resistant to nation-state attacks"

## Example Output

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

## Constraints and Hints

1. **PASSWORD LENGTH CONSTRAINT**: Minimum 12 characters, Maximum 64 characters
2. **RESEARCH FIRST**: Identify the correct Python module for cryptographic randomness
3. Use `math.log2()` for entropy calculation (import math module)
4. Use `**` operator for exponentiation when calculating possible combinations (Chapter 2, p. 21)
5. Use f-strings for formatted output (Chapter 2, p. 8)
6. Use `for` loops to build the password character-by-character (Chapter 2, p. 8)
7. Type conversions: `int(input())` for getting numeric parameters (Chapter 2, p. 8)
8. Validate user input to ensure length is within 12-64 character range
9. Use comparison operators to determine strength rating thresholds (Chapter 2, p. 8)

**Character Space Definition:**
```python
import string

lowercase = string.ascii_lowercase  # 'abcdefghijklmnopqrstuvwxyz'
uppercase = string.ascii_uppercase  # 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
digits = string.digits              # '0123456789'
special = '!@#$%^&*()-_+=[]{}|;:,.<>?'
```

## Test Cases

Your solution should handle these scenarios correctly:

```python
# Test 1: 12-character alphanumeric password (MINIMUM LENGTH)
Character set: 'alphanumeric', Length: 12
Expected entropy: ~71 bits (12 × log₂(62))
Expected rating: "Strong"

# Test 2: 16-character full character set
Character set: 'all', Length: 16
Expected entropy: ~105 bits (16 × log₂(94))
Expected rating: "Excellent"

# Test 3: 20-character alpha-only
Character set: 'alpha', Length: 20
Expected entropy: ~114 bits (20 × log₂(52))
Expected rating: "Excellent"

# Test 4: Passphrase with 5 words
Character set: 'passphrase', Words: 5, Dictionary size: 7776 (EFF wordlist)
Expected entropy: ~64 bits (5 × log₂(7776))
Expected rating: "Strong"

# Test 5: 64-character password (MAXIMUM LENGTH)
Length: 64, Character set: 'all'
Expected entropy: ~419 bits
Expected rating: "Excellent"

# Test 6: Invalid input - length < 12
User enters: 8
Expected: Error message, prompt again

# Test 7: Invalid input - length > 64
User enters: 100
Expected: Error message, prompt again
```

## Extension Challenges (Beyond the Exercise)

1. **Diceware Implementation**: Implement true Diceware passphrase generation using the EFF long wordlist (7,776 words). Research how to simulate cryptographically secure dice rolls in Python.

2. **zxcvbn Integration**: After generating the password, run it through the `zxcvbn` library (a realistic password strength estimator) and compare your entropy calculation with its crack time estimate.

3. **NIST SP 800-63B Compliance**: Add validation that the generated password meets NIST Digital Identity Guidelines - check it's not in the "have i been pwned" database of breached passwords (simulate with a small local blocklist).

4. **Password Derivation**: Extend the generator to create a **master password**, then derive site-specific passwords using HMAC-SHA256 with the domain name as input.

---

## Password Entropy Reference Tables

Use these tables to verify your entropy calculations and strength ratings in Part 2 of the exercise. Entropy is calculated as: **Entropy (bits) = Length × log₂(Character Set Size)**

**Common Character Set Sizes:**
- **Lowercase only** (a-z): 26 characters → log₂(26) = 4.70 bits per character
- **Mixed case** (a-zA-Z): 52 characters → log₂(52) = 5.70 bits per character
- **Alphanumeric** (a-zA-Z0-9): 62 characters → log₂(62) = 5.95 bits per character
- **All printable** (a-zA-Z0-9 + special): 94 characters → log₂(94) = 6.55 bits per character
- **Diceware wordlist**: 7,776 words → log₂(7776) = 12.92 bits per word

### Minimum Length Required for Each Strength Rating

| Character Set | Weak<br>(< 50 bits) | Moderate<br>(50-64 bits) | Strong<br>(65-80 bits) | Very Strong<br>(80-100 bits) | Excellent<br>(> 100 bits) |
|---------------|---------------------|--------------------------|------------------------|------------------------------|---------------------------|
| Lowercase (26) | 1-10 chars | 11-13 chars | 14-17 chars | 18-21 chars | 22+ chars |
| Mixed Case (52) | 1-8 chars | 9-11 chars | 12-14 chars | 15-17 chars | 18+ chars |
| Alphanumeric (62) | 1-8 chars | 9-10 chars | 11-13 chars | 14-16 chars | 17+ chars |
| All Chars (94) | 1-7 chars | 8-9 chars | 10-12 chars | 13-15 chars | 16+ chars |

**Strength Rating Thresholds:**
- **Weak**: < 50 bits — Vulnerable to modern attacks
- **Moderate**: 50-64 bits — Acceptable for low-security contexts
- **Strong**: 65-80 bits — Recommended for most applications
- **Very Strong**: 80-100 bits — Suitable for high-security applications
- **Excellent**: > 100 bits — Resistant to nation-state attacks

### Passphrase Entropy (Diceware Method)

For passphrases using the EFF long wordlist (7,776 words, ~12.9 bits per word):

| Word Count | Entropy (bits) | Strength Rating | Example Length |
|------------|----------------|-----------------|----------------|
| 3 words    | 38.8 | **Weak** | ~18-24 chars |
| 4 words    | 51.7 | **Moderate** | ~24-32 chars |
| 5 words    | 64.6 | **Strong** | ~30-40 chars |
| 6 words    | 77.5 | **Strong** | ~36-48 chars |
| 7 words    | 90.4 | **Very Strong** | ~42-56 chars |
| 8 words    | 103.4 | **Excellent** | ~48-64 chars |

**Note:** Passphrase entropy assumes true random selection from the dictionary. Human-selected passphrases typically have much lower entropy due to predictable word choices.

## Example Calculations

**Example 1: 12-character alphanumeric password (MINIMUM LENGTH)**
- Character set size: 62 (a-z, A-Z, 0-9)
- Length: 12
- Entropy: 12 × log₂(62) = 12 × 5.95 = **71.5 bits**
- Rating: **Strong - Recommended for most applications**

**Example 2: 16-character password with all character types**
- Character set size: 94 (a-z, A-Z, 0-9, special)
- Length: 16
- Entropy: 16 × log₂(94) = 16 × 6.55 = **105.0 bits**
- Rating: **Excellent - Resistant to nation-state attacks**

**Example 3: 64-character password (MAXIMUM LENGTH)**
- Character set size: 94 (all characters)
- Length: 64
- Entropy: 64 × log₂(94) = 64 × 6.55 = **419.2 bits**
- Rating: **Excellent - Resistant to nation-state attacks**

## Attack Scenario Context

**What these entropy levels protect against:**
- **35 bits**: Typical online attack (rate-limited API endpoints)
- **74 bits**: Lone hacker with consumer hardware over one year
- **87 bits**: State actor with significant computing resources
- **98 bits**: All global computing power combined over one year
- **128 bits**: Theoretical maximum for common encryption methods
- **188+ bits**: Beyond computational physics limits

## Critical Security Warning

⚠️ **Entropy alone doesn't guarantee security!** Two passwords can have identical entropy, but one may be extremely weak if it appears in leaked password databases. Always check generated passwords against breach databases (e.g., Have I Been Pwned) before use.

---

## Concepts Applied from Python Workout & Security Books

**Python Workout Chapter 1-2:**
- **Numeric types** (Chapter 2, pp. 7-24): Entropy calculations, logarithms, character space arithmetic
- **Type conversion** (Chapter 2, p. 8): Converting between int, float for calculations
- **User input** (Chapter 2, p. 8): Getting configuration parameters
- **Loops** (Chapter 2, p. 8): Building password character-by-character
- **Comparisons** (Chapter 2, p. 8): Threshold checks for strength rating, input validation
- **f-strings** (Chapter 2, p. 8): Formatted output
- **Exponentiation operator** (`**`) (Chapter 2, p. 21): Understanding password space size

**Security Concepts:**
- **Cryptographically Secure Random Number Generation**: Research required to identify correct approach
- **Entropy Theory**: Understanding password strength as information-theoretic measure
- **Character Space Analysis**: How character diversity affects brute-force resistance

## Primary References

**Python Workout:**
- Python Workout, Second Edition, Chapter 2 (Numeric types), pp. 7-24 — Numeric operations, loops, type conversion
- Python Workout, Second Edition, Chapter 2, p. 8 — Random number generation reference (Table 2.1)
- Python Workout, Second Edition, Chapter 2, p. 21 — Exponentiation operator (`**`)

**Security References (READ THESE CAREFULLY):**
- Full Stack Python Security, Chapter 3 (Keyed Hashing), pp. 29-31 — Key generation, random numbers vs passphrases, cryptographic random number sources
- Full Stack Python Security, Chapter 3, p. 30 — Critical warnings about random number generation for security purposes
- Full Stack Python Security, Chapter 1 (Tools), p. 9 — Overview of security-related Python modules

**Entropy Reference Tables:**
- Ryan A. Gibson, "Table of Password Lengths for Various Character Sets and Entropies," August 20, 2023, https://ryanagibson.com/extra/password-entropies-and-character-sets/
- Omnicalculator, "Password Entropy Calculator," March 20, 2024, https://www.omnicalculator.com/other/password-entropy
- Security Centric, "Bits of Entropy - The Importance of Complex Passwords," https://www.securitycentric.com.au/blog/bits-of-entropy-the-importance-of-complex-passwords

**Additional Security Standards:**
- NIST SP 800-63B: Digital Identity Guidelines (password requirements)
- EFF Diceware Wordlist: https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases

---

## Critical Research Task

⚠️ **Before writing any code, you MUST research which Python module to use for cryptographic random number generation.** The security of every password you generate depends entirely on this choice. Reading the security references above will guide you to the correct answer.

Questions to answer through your research:
1. What makes a random number generator suitable for cryptographic use?
2. Which Python standard library module(s) are cryptographically secure?
3. Which Python module(s) should NEVER be used for security purposes, and why?
4. What specific function should you use to randomly select items from a sequence?

---

**Remember:** Complete the research phase first, then implement your solution. Compare your entropy calculations and implementation approach with the concepts from Python Workout Chapter 2. Your goal is to build fluency with Python's numeric operations while learning to identify and use cryptographically secure libraries—a critical skill for your AppSec career.
