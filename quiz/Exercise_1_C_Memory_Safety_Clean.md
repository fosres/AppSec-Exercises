# Exercise 1: C Memory Safety Code Review

**Curriculum Alignment**: Week 4 - Linux Internals, Common Linux Attacks  
**Source**: *API Security in Action*, Chapter 2, pp. 47-48 (Buffer Overflow definition and RCE explanation)

**Difficulty**: Week 4 Level  
**Points**: 15 total  
**Estimated Time**: 20 minutes

---

## Scenario

You are reviewing file server code written in C. The engineering team needs a security assessment before deployment.

```c
#include <stdlib.h>
#include <string.h>

char *deserialize(const char *s) {
	size_t len = strnlen(s, 4096);
	char *b = (char *) malloc(len);
	strcpy(b, s);
	return b;
}
```

---

## Questions

### **1a. Vulnerability Identification** (5 points)

Identify ALL vulnerabilities present in this code. For each vulnerability:
- Name the vulnerability class:

1. Off-by-One: Failure to Allocate for Terminating Null-Byte  in String

2. Failure to Check for Failure of Dynamic Memory Allocation

- Explain the root cause:

The following line is the root cause for Off-By-One:

```
	strcpy(b, s);
```

The following line is the root cause of Failure of Dynamic Memory

Allocation:

```
	char *b = (char *) malloc(len);
```

3. Failure to check if string `s` is a NULL string. This can

lead to a NULL dereference attempt

- Describe potential impact

Without terminating null-byte in a string C string functions can

read data outside of the bounds of the array--leading to undefined

behavior.

Without checking for failure of dynamic memory allocation C programs

can attempt to dereference a NULL pointer. That's dangerous behavior.

Also without checking if `s` is a NULL string this can also can

lead to attempt to dereference NULL pointer.

**Hints to guide your analysis:**
- How many bytes does `strnlen(s, 4096)` return for the string "hello"?
- How many bytes does `malloc(len)` allocate?
- How many bytes does `strcpy(b, s)` write (including null terminator)?
- What happens if `malloc()` fails?
- What happens if someone passes a 5000-byte string to this function?

---

### **1c. Mitigations** (10 points)

Propose secure alternatives for this code. Address:
- Memory allocation strategy
- String handling approach  
- Input validation requirements

**Your rewritten code should:**
- Allocate the correct amount of memory for the string (including null terminator)
- Check that malloc succeeded before using the pointer
- Use safe string copying functions
- Handle edge cases (empty strings, allocation failures)

Write your complete secure implementation below:

```c
#include <stdlib.h>
#include <string.h>

char *deserialize(const char *s) {

	if ( s == NULL )
	{
		fprintf(stderr,"Error: s is NULL\n");
	
		return NULL;
	}

	size_t len = strnlen(s, 4096);

	char *b = (char *) calloc(len+1,sizeof(char));
	
	if ( b == NULL )
	{
		fprintf(stderr,"Error: failed to allocate b string\n");

		return NULL;
	}

	strncpy(b, s,len);

	return b;
}
```

---

## Expected Knowledge

By Week 4, you should understand:
- Buffer overflow mechanics (*API Security in Action*, p. 48)
- Difference between `strnlen()` and `strlen()` behavior
- Off-by-one errors in C string handling
- Why memory-safe languages prevent these issues
- NULL pointer dereference risks
- Safe string functions: `strncpy()`, `snprintf()`, `memcpy()`

---

## Grading Rubric

### 1a. Vulnerability Identification (5 points)
- **2 points**: Correctly identified off-by-one error (malloc allocates `len` bytes, strcpy writes `len+1` bytes)
- **1 point**: Identified NULL pointer dereference from unchecked malloc
- **1 point**: Identified lack of input validation
- **1 point**: Clearly explained root causes

### 1c. Mitigations (10 points)
- **3 points**: Allocates correct size: `len + 1` bytes for null terminator
- **2 points**: Checks malloc return value for NULL
- **2 points**: Uses safe string copying (not strcpy)
- **2 points**: Validates input (null checks, size limits)
- **1 point**: Code is clean, compiles, and demonstrably secure

---

## Additional Context

**Common Mistake**: Thinking this is a classic "buffer overflow where attacker sends huge string"

**Reality**: The vulnerability exists even with SMALL strings:
- Input: "hello" (5 characters)
- `strnlen("hello", 4096)` returns `5`
- `malloc(5)` allocates 5 bytes
- `strcpy(b, "hello")` writes 6 bytes (h-e-l-l-o-\0)
- **Result**: 1-byte overflow past allocated buffer

This is called an **off-by-one error** and is one of the most common C programming mistakes.

---

## References

**Primary Source**:
- *API Security in Action* by Neil Madden, Chapter 2, pp. 47-48

**Additional Reading**:
- CWE-193: Off-by-one Error (https://cwe.mitre.org/data/definitions/193.html)
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-476: NULL Pointer Dereference
- *Secure by Design*, Chapter 6 - Defensive programming patterns

---

*This exercise tests your ability to identify subtle memory safety issues that exist even when inputs appear "safe" or small.*
