# Exercise 9: C Security Audit - Log Message Builder

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Focus**: strncat buffer overflow + size calculation  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a logging system. The engineering team has implemented a function to build log messages by appending a user message to a timestamp prefix, using a fixed-size buffer.

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

#define LOG_BUFFER_SIZE 64


void build_log(char *buffer, const char *user_message) {
	
	const char *timestamp = "[2024-01-15 10:30:00] ";

	// No check if buffer is NULL
	
	strcpy(buffer, timestamp);

	// Possible concatenation below exceeds bounds of buffer

	// What if user_message == NULL? Below not safe.

	// Unsafe to use strncat since it will concatenate

	// up to 64 characters--which leaves no room for

	NULL-termination. 

	strncat(buffer, user_message, LOG_BUFFER_SIZE);
}

int main() {
	char log[LOG_BUFFER_SIZE];
	const char *message = "User login successful";
	
	build_log(log, message);
	printf("Log: %s\n", log);
	
	return 0;
}
```

**Expected behavior:**
```
Input: "User login successful"
Output: "Log: [2024-01-15 10:30:00] User login successful"
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `build_log()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `build_log()` function to fix all identified vulnerabilities.

Your implementation should:
- Use correct size calculations for strncat
- Validate all inputs
- Handle edge cases safely
- Prevent buffer overflows

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LOG_BUFFER_SIZE 64


void build_log(char *buffer, const char *user_message) {
	
	const char *timestamp = "[2024-01-15 10:30:00] ";

	// Possible concatenation below exceeds bounds of buffer
	
	if (user_message == NULL)
	{
		fprintf(stderr,"Error: user_message == NULL\n");

		return;
	}

	size_t len = strlen(timestamp) + strlen(user_message);

	if ( len >= LOG_BUFFER_SIZE )
	{
		fprintf(stderr,"Error: len >= LOG_BUFFER_SIZE\n");

		return;
	}

	if ( buffer == NULL )
	{
		fprintf(stderr,"Error: buffer == NULL\n");

		return;
	}

	snprintf(buffer,LOG_BUFFER_SIZE,"%s%s",timestamp,user_message);
	
}

int main() {
	char log[LOG_BUFFER_SIZE];
	const char *message = "User login successful";
	
	build_log(log, message);
	printf("Log: %s\n", log);
	
	return 0;
}
```

---

## Grading Rubric

### Part A: Vulnerability Identification (5 points)
- **2 points**: Identified strncat size miscalculation
- **1 point**: Explained why strncat(buffer, msg, LOG_BUFFER_SIZE) is wrong
- **1 point**: Identified missing NULL pointer validation
- **1 point**: Clear explanation of buffer overflow risk

### Part B: Secure Implementation (10 points)
- **4 points**: Correctly calculates remaining space for strncat
- **2 points**: Validates inputs (NULL checks)
- **2 points**: Handles edge cases (buffer too small for timestamp)
- **1 point**: Uses safe string functions correctly
- **1 point**: Code compiles and functions correctly

---

## Expected Knowledge

Candidates should understand:
- strncat behavior and size parameter meaning
- Buffer capacity vs used space calculations
- Difference between strncpy and strncat
- Safe string concatenation patterns

---

## Hints

Consider these questions:
- What does the 'n' in `strncat(dest, src, n)` mean?
- How much space is left in buffer after strcpy(buffer, timestamp)?
- What happens if user_message is 64 bytes long?
- What if the timestamp doesn't fit in the buffer?

**Critical strncat behavior:**
```c
char buf[10] = "Hi";     // buf has 2 chars + '\0', 7 bytes free
strncat(buf, "World", 10);
// Appends UP TO 10 chars from "World"
// But buf only has 7 bytes free!
// BUFFER OVERFLOW!
```

---

## Key Bugs

### Bug #1: strncat Size Miscalculation

```c
strcpy(buffer, timestamp);  // Uses 23 bytes: "[2024-01-15 10:30:00] \0"
strncat(buffer, user_message, LOG_BUFFER_SIZE);
//                             ^^^^^^^^^^^^^^^^
//                             WRONG! This is TOTAL buffer size,
//                             not REMAINING space!
```

**The bug:**
```c
// After strcpy:
//   buffer = "[2024-01-15 10:30:00] \0"
//   Used: 23 bytes
//   Remaining: 64 - 23 = 41 bytes

// strncat tries to append UP TO 64 chars
// But only 41 bytes remain!
// BUFFER OVERFLOW!
```

### Bug #2: strncat vs strncpy Confusion

**Common misconception:**
```c
strncpy(dest, src, sizeof(dest));  // n = total buffer size
strncat(dest, src, sizeof(dest));  // n = total buffer size ❌
```

**Reality:**
```c
strncpy(dest, src, sizeof(dest));     // ✓ Copies at most sizeof(dest) chars
strncat(dest, src, sizeof(dest));     // ❌ Can overflow!
strncat(dest, src, sizeof(dest) - strlen(dest) - 1);  // ✓ Correct!
```

### Bug #3: No NULL Validation

```c
void build_log(char *buffer, const char *user_message) {
    // What if buffer is NULL?
    // What if user_message is NULL?
    strcpy(buffer, timestamp);  // Crash!
}
```

---

## Time Allocation

- **5 minutes**: Identify the strncat bug
- **10 minutes**: Write secure implementation
- **5 minutes**: Test edge cases mentally

---

## Critical Insight: strncat Behavior

**strncat is NOT strncpy!**

```c
// strncpy(dest, src, n):
//   Writes AT MOST n bytes to dest
//   Replaces dest's contents

// strncat(dest, src, n):
//   Appends AT MOST n chars from src to dest
//   Adds to existing content
//   n does NOT include the null terminator
```

**The correct pattern:**
```c
char buf[100] = "Hello";

// WRONG:
strncat(buf, " World", sizeof(buf));  // Could overflow!

// RIGHT:
size_t used = strlen(buf);
size_t remaining = sizeof(buf) - used - 1;  // -1 for '\0'
strncat(buf, " World", remaining);
```

---

## Example Trace

```c
char log[64];
build_log(log, "This is a very long user message that exceeds space");

// After strcpy:
//   log = "[2024-01-15 10:30:00] " (23 chars)
//   Remaining: 64 - 23 = 41 bytes

// strncat tries to append 64 chars:
//   Writes to log[23], log[24], ..., log[86]
//   log[64] to log[86] are OUT OF BOUNDS!
//   BUFFER OVERFLOW!
```

---

## References

**Primary Sources**:
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-131: Incorrect Calculation of Buffer Size
- CERT C Coding Standard: STR31-C (Guarantee strings are null-terminated)
- *Secure by Design*, Chapter 6 - Safe string operations

**Additional Reading:**
- "strncat() is dangerous and should not be used" - Many security guides
- Modern alternative: `snprintf()` for concatenation

---

*This exercise tests understanding of strncat's dangerous behavior - a common source of buffer overflows in C code.*
