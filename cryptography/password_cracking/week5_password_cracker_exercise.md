# Week 5 Python Security Scripting Challenge: Build Mini-Hashcat

*A LeetCode-style AppSec exercise for mastering Python dictionaries, file I/O, and password hash cracking*

---

## Introduction

Password cracking is a fundamental offensive security skill that every security engineer encounters. Whether you're performing penetration testing, incident response, or security research, understanding how attackers crack passwords helps you defend against these attacks.<sup>1</sup>

This exercise is inspired by Grace Nolan's Security Engineering interview preparation notes, which emphasize password cracking as a core coding challenge for security roles.<sup>2</sup> Real-world tools like **hashcat** can crack billions of hashes per second using GPU acceleration, but understanding the fundamentals requires building a simplified version from scratch.

In this challenge, you'll build a **mini-hashcat** that can:
- Load password hashes from a file
- Attempt dictionary attacks using wordlists
- Support multiple hash algorithms via Python's `passlib` library
- Track and report cracking statistics

This exercise combines Python dictionaries (for hash lookups), file I/O (for reading wordlists), and comprehensions (for efficient hash generation) — all Week 5 curriculum topics.<sup>3</sup>

**Security Context**: The 2012 LinkedIn breach exposed 6+ million SHA1 password hashes. Within two weeks, 90% were cracked because LinkedIn didn't use salted hashing.<sup>4</sup> The 2016 eharmony breach revealed MD5 hashes that were cracked rapidly using rainbow tables and dictionary attacks.<sup>5</sup> Understanding these attacks is critical for defensive security.

**Real-World Password Databases for Testing:**

Your password cracker can test against **actual breached databases** from real attacks. These datasets provide invaluable learning opportunities:

1. **eharmony 2012 Breach (1.5M hashes)**
   - Hash type: Unsalted MD5 (all uppercase!)
   - Available at: https://defuse.ca/files/eharmony-hashes.txt
   - CrackStation cracked 18.2% (275,860 passwords) in 23.47 hours
   - Security lessons: No salting + uppercase conversion = catastrophic weakness<sup>24</sup>

2. **CrackStation Human Passwords Wordlist (64M real passwords)**
   - Real passwords from multiple database breaches
   - Download: https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm
   - Also on Archive.org: https://archive.org/details/academictorrents_7ae809ccd7f0778328ab4b357e777040248b8c7f
   - Responsible for cracking 30% of all hashes submitted to CrackStation<sup>25</sup>

3. **LinkedIn 2012 Breach (6M SHA1 hashes, later 170M)**
   - Hash type: Unsalted SHA1
   - 90% cracked within 2 weeks
   - Security lesson: Fast hash + no salt = trivial to crack<sup>26</sup>

**Using Real Breach Data Responsibly:**

These datasets are available for **security education only**. Using them to:
- Test your password cracker implementation
- Understand real-world attack patterns
- Learn why salting and slow hashing are critical
- Study common password patterns (e.g., "password123", "123456")

**⚠️ Security Disclaimer:** These are real people's passwords from real breaches. Use this data ethically for learning purposes only. Never attempt to use these credentials for unauthorized access.

---

## Exercise 18: Password Cracker (`crack_passwords`)

**Difficulty**: ⭐⭐⭐⭐ (Advanced)

### Problem Statement

Write a function `crack_passwords(hash_file, wordlist_file, hash_type='md5_crypt')` that implements a basic password cracker. Your cracker should:

1. **Read a hash file** where each line contains: `username:hash_value`
   - Example: `alice:$1$SomeS4lt$7YvzMBkfl8cZp.wXd2aBk0`
   
2. **Read a wordlist file** where each line is a potential password
   - Example wordlist: `password`, `123456`, `qwerty`, etc.

3. **Attempt to crack each hash** by:
   - Iterating through each word in the wordlist
   - Hashing the word using the specified algorithm
   - Comparing the generated hash to each stored hash
   - Recording successful cracks

4. **Return a dictionary** mapping usernames to cracked passwords:
   ```python
   {'alice': 'password', 'bob': 'qwerty123', 'charlie': None}
   ```
   - Use `None` for uncracked passwords

5. **Support multiple hash algorithms** from `passlib`:
   - `md5_crypt` (Unix MD5, identifier `$1$`)
   - `sha256_crypt` (SHA-256 crypt, identifier `$5$`)
   - `sha512_crypt` (SHA-512 crypt, identifier `$6$`)
   - `bcrypt` (bcrypt, identifier `$2a$`, `$2b$`, `$2y$`)
   - `scrypt` (scrypt, identifier `$scrypt$`)
   - `pbkdf2_sha256` (PBKDF2 with SHA-256)
   - `argon2` (Argon2, identifier `$argon2i$`, `$argon2id$`)

6. **Print cracking statistics**:
   - Total hashes loaded
   - Total passwords cracked
   - Crack rate (percentage)
   - Time elapsed

### Input Format

**Hash file** (`hashes.txt`):
```
alice:$1$SaltHere$KqJc7iu3CeGh4uw2DxJFc1
bob:$5$rounds=5000$SaltValue$Fp6LhJKj0X.tKMLHuwQ9qz2YnLkKtVLJ8kPPQDu/Kn3
charlie:$6$OtherSal$hZ9Kp2.3EfXdJz5lWmNo8PqRsTuVwXyZaBcDeFgHiJk
mallory:$2b$12$SomeRandomSalt123456789OuZKxOjHLQaYkU3z5P4q8jlKmNoPqR
```

**Wordlist file** (`rockyou.txt`):
```
password
123456
qwerty
letmein
monkey
dragon
```

### Expected Output

```python
>>> crack_passwords('hashes.txt', 'rockyou.txt', 'auto')
[*] Loaded 4 hashes from hashes.txt
[*] Loaded 6 passwords from rockyou.txt
[*] Attempting dictionary attack...
[+] Cracked alice:password (md5_crypt)
[+] Cracked bob:123456 (sha256_crypt)
[-] charlie: Not cracked
[+] Cracked mallory:monkey (bcrypt)
[*] Results: 3/4 cracked (75.00%)
[*] Time elapsed: 0.234s

{'alice': 'password', 'bob': '123456', 'charlie': None, 'mallory': 'monkey'}
```

---

## Working It Out

This problem combines several Python concepts from Week 5:

### 1. Dictionary-Based Hash Storage

We'll use a dictionary to map usernames to their hashes for O(1) lookup speed:<sup>6</sup>

```python
# DON'T do this (inefficient):
hash_list = [('alice', '$1$...'), ('bob', '$5$...')]

# DO this (efficient):
hash_dict = {'alice': '$1$...', 'bob': '$5$...'}
```

### 2. File Reading with `dict` Comprehension

Reading the hash file can be elegantly done with a dict comprehension:<sup>7</sup>

```python
{line.split(':')[0]: line.split(':')[1].strip() 
 for line in open('hashes.txt')}
```

However, this has a problem — what if the line doesn't contain a colon? We need defensive programming.<sup>8</sup>

### 3. Hash Type Detection

The `passlib` library allows hash type auto-detection:

```python
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt, bcrypt, pbkdf2_sha256, argon2

# Auto-detect and verify:
from passlib.context import CryptContext
ctx = CryptContext(schemes=['md5_crypt', 'sha256_crypt', 'sha512_crypt', 
                             'bcrypt', 'pbkdf2_sha256', 'argon2'])

# Verify a password against a hash:
if ctx.verify('password123', stored_hash):
	print("Match!")
```

### 4. Iteration Strategy

We need to iterate through **every hash** for **every password** until we find a match. This is O(n*m) complexity where n=hashes and m=wordlist size.<sup>9</sup>

### 5. Progress Tracking

For production crackers, you'd want a progress bar. For this exercise, we'll use simple print statements.

---

## Beyond the Exercise

Once you have a working password cracker, try these enhancements:

### 1. **Add Rule-Based Mutations**
Implement password mutations like:
- Append common numbers: `password` → `password123`, `password1`
- Leetspeak: `password` → `p@ssw0rd`, `pa55word`
- Capitalization: `password` → `Password`, `PASSWORD`

**Hint**: Use string methods and dict comprehensions.<sup>16</sup>

### 2. **Implement Rainbow Table Attack**
Pre-compute hashes for your wordlist and store in a dict:

```python
rainbow_table = {hash_func(pwd): pwd for pwd in wordlist}
```

Then crack by simple lookup: `cracked = rainbow_table.get(target_hash)`

**Why this matters**: This demonstrates the space-time tradeoff in password cracking. Rainbow tables trade storage (space) for speed (time).<sup>17</sup>

### 3. **Add Salt Detection**
Parse the salt from salted hashes and display it:

```python
# md5_crypt format: $1$salt$hash
def extract_salt(hash_value):
	parts = hash_value.split('$')
	if len(parts) >= 3:
		return parts[2]  # The salt
	return None
```

**Security lesson**: Salting prevents rainbow table attacks because each password has a unique hash even if the password is the same.<sup>18</sup>

### 4. **Multi-threaded Cracking**
Use Python's `concurrent.futures` to parallelize:

```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=4) as executor:
	futures = [executor.submit(crack_hash, h) for h in hashes]
```

### 5. **Performance Metrics**
Track hashes-per-second and estimate time remaining:

```python
hashes_per_second = attempts / elapsed_time
remaining = (total_attempts - attempts) / hashes_per_second
print(f"Speed: {hashes_per_second:.0f} H/s, ETA: {remaining:.1f}s")
```

### 6. **Hash Type Auto-Detection**
Instead of requiring the user to specify the hash type, automatically detect it from the hash format:

```python
from passlib.context import CryptContext

ctx = CryptContext(schemes=['md5_crypt', 'sha256_crypt', ...])
detected_scheme = ctx.identify(hash_value)
print(f"Detected hash type: {detected_scheme}")
```

### 7. **Hybrid Attack**
Combine dictionary attack with brute force:
- Try wordlist first (fast)
- If that fails, try brute force on short passwords (4-6 chars)

### 8. **Test Against Real Breach Data**
Download the eharmony breach dataset and crack it:

```bash
# Download eharmony MD5 hashes (1.5M hashes)
wget https://defuse.ca/files/eharmony-hashes.txt

# Download CrackStation wordlist (64M passwords)
wget https://crackstation.net/files/crackstation-human-only.txt.gz
gunzip crackstation-human-only.txt.gz
```

**Challenge**: The eharmony hashes are unsalted MD5 (not passlib format), but our cracker expects salted hashes. You'll need to either:
1. Modify your cracker to support unsalted MD5 mode for historical breach analysis
2. Create a wrapper that converts unsalted MD5 to passlib's format

**Expected results**: Against the real eharmony dataset with the CrackStation wordlist, you should crack approximately 18-30% of passwords depending on your wordlist coverage (CrackStation cracked 18.2% in 23.47 hours).<sup>24</sup>

### 9. **Statistical Analysis of Cracked Passwords**
Analyze patterns in cracked passwords:

```python
def analyze_passwords(results):
	cracked = [pwd for pwd in results.values() if pwd]
	
	# Length distribution
	lengths = {}
	for pwd in cracked:
		lengths[len(pwd)] = lengths.get(len(pwd), 0) + 1
	
	# Character class analysis
	only_lower = sum(1 for p in cracked if p.islower())
	only_digits = sum(1 for p in cracked if p.isdigit())
	mixed_case = sum(1 for p in cracked if p != p.lower() and p != p.upper())
	
	print(f"Average length: {sum(len(p) for p in cracked) / len(cracked):.1f}")
	print(f"Only lowercase: {only_lower} ({only_lower/len(cracked)*100:.1f}%)")
	print(f"Only digits: {only_digits} ({only_digits/len(cracked)*100:.1f}%)")
	print(f"Mixed case: {mixed_case} ({mixed_case/len(cracked)*100:.1f}%)")
```

This demonstrates why security policies require minimum length, character diversity, and password complexity.

---

## Test Cases

This exercise includes **66 comprehensive test cases** organized into 5 categories:

1. **Basic Functionality (Tests 1-15):** Single hash cracking for each algorithm (md5_crypt, sha256_crypt, sha512_crypt, bcrypt, scrypt, pbkdf2_sha256, argon2), empty files, multiple users

2. **Edge Cases (Tests 16-30):** Special characters in passwords, Unicode support, whitespace handling, very long passwords (100+ chars), duplicate usernames

3. **Error Handling (Tests 31-45):** Missing files, invalid hash formats, malformed hashes, incorrect hash type specifications, file permission errors

4. **Advanced Algorithms (Tests 46-60):** Mixed hash types in single file, different salt lengths, bcrypt cost factors, scrypt parameter variations, performance benchmarking

5. **Real-World Scenarios (Tests 61-66):** RockYou top 10 passwords, simulated LinkedIn breach dataset, weak password pattern detection, common substitutions (l33tspeak)

Each test is designed to validate a specific aspect of the password cracker's functionality and ensure robust error handling.

---

## Key Concepts Demonstrated

### 1. **Dictionary Attack Fundamentals**
The core algorithm is simple but powerful: try every password in a wordlist against every hash until you find a match.<sup>19</sup> Real attackers use this technique with wordlists containing **billions** of common passwords.

### 2. **Salting Defense**
Notice how `passlib` automatically adds random salts to every hash. This means the same password produces different hashes each time:<sup>20</sup>

```python
>>> from passlib.hash import md5_crypt
>>> md5_crypt.hash('password')
'$1$Rx5eWCMl$VN0z8YlpPdWfFXQ3qmLEt1'
>>> md5_crypt.hash('password')  # Different!
'$1$4KJ8xPzN$gZLhC9x5F2aDpMqJk3Wiy0'
```

### 3. **Hash Function Performance**
Different hash functions have different speeds:<sup>21</sup>
- **MD5**: ~1 billion hashes/sec (INSECURE - too fast)
- **SHA-256**: ~500 million hashes/sec (INSECURE - too fast)
- **bcrypt**: ~10,000 hashes/sec (GOOD - intentionally slow)
- **scrypt**: ~5,000 hashes/sec (EXCELLENT - memory-hard + slow)
- **Argon2**: ~1,000 hashes/sec (BEST - memory-hard + slow)

### 4. **Constant-Time Comparison**
The `passlib` library uses constant-time comparison internally to prevent timing attacks (see Full Stack Python Security Chapter 3).<sup>22</sup> Never use `==` to compare hashes directly.

---

## Citations

<sup>1</sup> Grace Nolan, *Security Engineering Interview Notes*, GitHub: gracenolan/Notes, Section: "Security Coding Challenges"

<sup>2</sup> *Extended 48-Week Security Engineering Curriculum*, Week 90: Security Coding Challenges, Page 49

<sup>3</sup> Reuven M. Lerner, *Python Workout Second Edition*, Manning Publications, 2025, Chapter 5: "Dictionaries and Sets", Chapter 6: "Files", Pages 76-115

<sup>4</sup> Dennis Byrne, *Full Stack Python Security*, Manning Publications, 2021, Chapter 9: "User Password Management", Page 125 - LinkedIn breach case study

<sup>5</sup> Dennis Byrne, *Full Stack Python Security*, Manning Publications, 2021, Chapter 9: "User Password Management", Page 133 - eharmony breach case study with rainbow tables

<sup>6</sup> Reuven M. Lerner, *Python Workout Second Edition*, Manning Publications, 2025, Chapter 5: "Dictionaries and Sets", Page 76 - Dictionary as key-value storage

<sup>7</sup> Reuven M. Lerner, *Python Workout Second Edition*, Manning Publications, 2025, Chapter 8: "Comprehensions", Pages 163-177 - Dict comprehensions

<sup>8</sup> Brett Slatkin, *Effective Python Third Edition*, Addison-Wesley, 2025, Chapter 4: "Dictionaries", Item 26: "Prefer get over in and KeyError", Pages 117-121

<sup>9</sup> Corey J. Ball, *Hacking APIs*, No Starch Press, 2022, Chapter 10: "Attacking Authentication", Page 197 - JWT Crack attack algorithmic complexity

<sup>10</sup> Dennis Byrne, *Full Stack Python Security*, Manning Publications, 2021, Chapter 9: "User Password Management", Pages 130-135 - Password hashing with Argon2 and PBKDF2

<sup>11</sup> Reuven M. Lerner, *Python Workout Second Edition*, Manning Publications, 2025, Chapter 6: "Files", Page 90 - File handling with context managers

<sup>12</sup> Brett Slatkin, *Effective Python Third Edition*, Addison-Wesley, 2025, Chapter 6: "Comprehensions and Generators", Item 43: "Consider Generators Instead of Returning Lists", Pages 182-186

<sup>13</sup> Reuven M. Lerner, *Python Workout Second Edition*, Manning Publications, 2025, Chapter 8: "Comprehensions", Page 165 - Dict comprehension patterns

<sup>14</sup> Corey J. Ball, *Hacking APIs*, No Starch Press, 2022, Chapter 10: "Attacking Authentication", Pages 196-197 - Password cracking with hashcat and JWT_Tool

<sup>15</sup> Dennis Byrne, *Full Stack Python Security*, Manning Publications, 2021, Chapter 3: "Keyed Hashing", Pages 37-38 - Constant-time comparison with `hmac.compare_digest()`

<sup>16</sup> Reuven M. Lerner, *Python Workout Second Edition*, Manning Publications, 2025, Chapter 3: "Strings", Pages 26-40 - String manipulation techniques

<sup>17</sup> Dennis Byrne, *Full Stack Python Security*, Manning Publications, 2021, Chapter 9: "User Password Management", Pages 124-126 - Rainbow table attacks and space-time tradeoffs

<sup>18</sup> Dennis Byrne, *Full Stack Python Security*, Manning Publications, 2021, Chapter 9: "User Password Management", Pages 125-127 - Salted hashing defense mechanisms

<sup>19</sup> Corey J. Ball, *Hacking APIs*, No Starch Press, 2022, Chapter 10: "Attacking Authentication", Page 197 - Dictionary attacks on authentication

<sup>20</sup> Dennis Byrne, *Full Stack Python Security*, Manning Publications, 2021, Chapter 9: "User Password Management", Page 126 - Salt individualization of hash values

<sup>21</sup> Dennis Byrne, *Full Stack Python Security*, Manning Publications, 2021, Chapter 9: "User Password Management", Pages 128-130 - KDF performance comparison: PBKDF2 vs Argon2

<sup>22</sup> Dennis Byrne, *Full Stack Python Security*, Manning Publications, 2021, Chapter 3: "Keyed Hashing", Page 38 - Timing attack prevention with constant-time comparison

<sup>23</sup> Neil Madden, *API Security in Action*, Manning Publications, 2020, Chapter 3: "Securing the Natter API", Pages 72-74 - Scrypt password hashing with recommended parameters (N=32768, r=8, p=1)

<sup>24</sup> Taylor Hornby (Defuse Security), "Cracking eHarmony's Unsalted Hashes with CrackStation", June 2012, https://defuse.ca/blog/cracking-eharmonys-unsalted-hashes-with-crackstation.html - eharmony breach analysis with 1.5M MD5 hashes

<sup>25</sup> Defuse Security, "CrackStation's Password Cracking Dictionary", https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm - 64 million real passwords from database breaches

<sup>26</sup> Dennis Byrne, *Full Stack Python Security*, Manning Publications, 2021, Chapter 9: "User Password Management", Page 125 - LinkedIn 2012 breach: 6M+ SHA1 unsalted hashes, 90% cracked in 2 weeks

---

## Conclusion

Password cracking is a critical skill for both offensive and defensive security work. This exercise demonstrates:

- **Dictionary attacks** - the most common password cracking technique
- **Hash function weaknesses** - why speed is actually a vulnerability for password hashing
- **Salt importance** - how salting prevents rainbow table and hash collision attacks
- **Python security patterns** - file I/O, dictionaries, error handling, and proper hash verification

By building this mini-hashcat, you've learned the fundamentals that power real-world tools like **hashcat**, **John the Ripper**, and **Hydra**. More importantly, you understand *why* modern systems use slow, salted, memory-hard hash functions like **Argon2** and **bcrypt** - they make attacks like this exponentially more difficult.

**Next Steps:**
- Complete Week 6 (Authentication Security) exercises
- Build a complementary "password strength validator" tool
- Explore real hashcat documentation and rule-based attacks
- Study CVE-2012-1430 (LinkedIn breach) as a case study

**Questions or improvements?** Find me at https://github.com/fosres or https://dev.to/fosres

---

*This exercise is part of a 48-week Security Engineering curriculum preparing for professional Security Engineering roles.*

*Security disclaimer: This exercise is for educational purposes only. Only test password cracking on systems you own or have explicit written permission to test.*
