# Exercise 12: C Security Audit - String Concatenator

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Focus**: Integer overflow in size calculations  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a string processing utility. The engineering team has implemented a function to concatenate two strings into a newly allocated buffer.

**Your task:**
1. Identify all security vulnerabilities in the code below
2. Explain the root cause of each vulnerability
3. Propose a secure implementation

---

## Code to Review

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *concat_strings(const char *str1, const char *str2) {

	// No check if str1 or str2 are NULL pointers
	
	size_t len1 = strlen(str1);

	size_t len2 = strlen(str2);

	// Integer Overflow Vulnerability Below
	
	size_t total_size = len1 + len2 + 1;

	// No check if malloc() returns NULL 	
	
	char *result = malloc(total_size);
	
	strcpy(result, str1);
	strcat(result, str2);

	return result;
}

int main() {
	char *combined = concat_strings("Hello, ", "World!");
	
	if (combined != NULL) {
		printf("%s\n", combined);
		free(combined);
	}
	
	return 0;
}
```

**Expected behavior:**
```
Hello, World!
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `concat_strings()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `concat_strings()` function to fix all identified vulnerabilities.

Your implementation should:
- Check for integer overflow in size calculations
- Validate all inputs
- Handle malloc failure
- Prevent all buffer overflows

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *concat_strings(const char *str1, const char *str2) {

	if ( str1 == NULL  )
	{
		fprintf(stderr,"Error: str1 == NULL\n");

		return NULL;

	}
	
	if ( str2 == NULL  )
	{
		fprintf(stderr,"Error: str2 == NULL\n");

		return NULL;

	}

	
	size_t len1 = strlen(str1);

	size_t len2 = strlen(str2);
	
	// size_t total_size = len1 + len2 + 1;

	size_t total_size = 0;

	if ( __builtin_add_overflow(len1,len2,&total_size) == true )
	{
		fprintf(stderr,"Error: len1 + len2 is integer overflow\n");

		return NULL;
	}

	size_t one = 1;
	
	if ( __builtin_add_overflow(total_size,one,&total_size) == true )
	{
		fprintf(stderr,"Error: len1 + len2 + 1 is integer overflow\n");

		return NULL;
	}

	// No check if malloc() returns NULL 	
	
	char *result = malloc(total_size);

	if ( result == NULL )
	{
		fprintf(stderr,"Error: result == NULL\n");

		return NULL;
	}
	
	strcpy(result, str1);
	strcat(result, str2);

	return result;
}

int main() {
	char *combined = concat_strings("Hello, ", "World!");
	
	if (combined != NULL) {
		printf("%s\n", combined);
		free(combined);
	}
	
	return 0;
}
```

---

## Grading Rubric

### Part A: Vulnerability Identification (5 points)
- **2 points**: Identified integer overflow in size calculation
- **1 point**: Identified missing NULL pointer checks
- **1 point**: Identified missing malloc failure check
- **1 point**: Clear explanation of overflow impact

### Part B: Secure Implementation (10 points)
- **4 points**: Checks for integer overflow before allocation
- **2 points**: Validates inputs (NULL checks for str1, str2)
- **2 points**: Handles malloc failure correctly
- **1 point**: Uses safe string operations
- **1 point**: Code compiles and functions correctly

---

## Expected Knowledge

Candidates should understand:
- Integer overflow behavior in C
- size_t wrapping semantics
- Overflow detection techniques
- Defensive memory allocation

---

## Hints

Consider these questions:
- What if len1 + len2 exceeds SIZE_MAX?
- What happens when size_t addition overflows?
- What if malloc() fails?
- What if str1 or str2 is NULL?

**Critical overflow scenario:**
```c
size_t len1 = SIZE_MAX - 5;  // Very large number
size_t len2 = 10;

size_t total = len1 + len2 + 1;
// Overflow! Wraps to small number (around 6)

char *result = malloc(total);
// Allocates only 6 bytes!

strcpy(result, str1);  
// Tries to copy SIZE_MAX-5 bytes into 6-byte buffer
// MASSIVE BUFFER OVERFLOW!
```

---

## Key Bugs

### Bug #1: Integer Overflow in Size Calculation

```c
size_t total_size = len1 + len2 + 1;
//                  ^^^^^^^^^^^^^^^^
//                  Can overflow!
```

**The problem:**
```c
// size_t is unsigned
// On 64-bit: size_t max = 18,446,744,073,709,551,615 (2^64 - 1)

size_t len1 = SIZE_MAX - 10;  // Huge number
size_t len2 = 20;

size_t total = len1 + len2 + 1;
// Expected: SIZE_MAX + 11 (huge number)
// Actual: Wraps around to 10 (small number!)

char *result = malloc(10);  // Allocates only 10 bytes
strcpy(result, str1);       // Copies SIZE_MAX-10 bytes!
// MASSIVE OVERFLOW!
```

**Real-world attack:**
```
Attacker provides two very long strings where len1 + len2 overflows.
Result: malloc allocates tiny buffer, strcpy overflows it.
Impact: Heap corruption, arbitrary code execution.
```

### Bug #2: No NULL Pointer Validation

```c
char *concat_strings(const char *str1, const char *str2) {
    size_t len1 = strlen(str1);  // Crash if str1 is NULL!
    size_t len2 = strlen(str2);  // Crash if str2 is NULL!
}
```

### Bug #3: No malloc Failure Check

```c
char *result = malloc(total_size);
// What if malloc fails? Returns NULL

strcpy(result, str1);  // Crash if result is NULL!
```

---

## Time Allocation

- **5 minutes**: Identify integer overflow bug
- **10 minutes**: Write secure implementation with overflow check
- **5 minutes**: Test edge cases mentally

---

## Critical Insight: size_t Overflow

**size_t is unsigned, so it wraps on overflow:**

```c
size_t max = SIZE_MAX;  // All bits set to 1

size_t x = max + 1;
// Does NOT error!
// Wraps to 0

size_t y = max + 100;
// Wraps to 99
```

**This is DEFINED BEHAVIOR in C (unlike signed overflow):**
- Unsigned overflow wraps modulo 2^N
- No compiler warning
- Silent and dangerous

---

## Overflow Detection Techniques

### **Method 1: Check before adding**
```c
if (len1 > SIZE_MAX - len2 - 1) {
    // Overflow would occur
    return NULL;
}
size_t total = len1 + len2 + 1;
```

### **Method 2: Check after adding**
```c
size_t total = len1 + len2 + 1;
if (total < len1 || total < len2) {
    // Overflow occurred (wrapped to smaller value)
    return NULL;
}
```

### **Method 3: Use SIZE_MAX**
```c
if (len1 > SIZE_MAX - len2 - 1) {
    return NULL;
}
```

**All three methods are valid!**

---

## Why This Matters

**Real-world vulnerabilities:**
- **ImageMagick CVE-2016-3714** - Integer overflow in size calculation
- **OpenSSL CVE-2014-0160 (Heartbleed)** - Related to size handling
- **Countless heap overflow exploits** - Often from integer overflow

**Common in:**
- Image processing (width * height * bytes_per_pixel)
- Network protocols (packet_count * packet_size)
- String operations (len1 + len2 + overhead)

---

## Example Attack Scenario

**Attacker-controlled strings:**
```c
// Attacker provides:
char *str1 = <string of length SIZE_MAX - 100>;
char *str2 = <string of length 200>;

// In concat_strings:
len1 = SIZE_MAX - 100
len2 = 200
total = len1 + len2 + 1
      = SIZE_MAX - 100 + 200 + 1
      = SIZE_MAX + 101
      = 100 (after wrapping!)

malloc(100);  // Allocates 100 bytes
strcpy(result, str1);  // Copies SIZE_MAX-100 bytes!
// HEAP OVERFLOW of approximately SIZE_MAX bytes!
```

**Impact:**
- Heap corruption
- Arbitrary code execution
- Complete system compromise

---

## References

**Primary Sources**:
- CWE-190: Integer Overflow or Wraparound
- CWE-680: Integer Overflow to Buffer Overflow
- CERT C Coding Standard: INT30-C (Ensure that unsigned integer operations do not wrap)
- CERT C Coding Standard: MEM35-C (Allocate sufficient memory for an object)

**Real-world examples:**
- ImageMagick vulnerabilities
- Integer overflow leading to heap overflows
- Size calculation bugs in image/media processing

---

*This exercise tests understanding of integer overflow in size calculations - a subtle but critical vulnerability class.*
