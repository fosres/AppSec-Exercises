# Exercise 8: C Security Audit - Configuration Key Parser

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Focus**: strncpy null termination + buffer bounds  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a configuration file parser. The engineering team has implemented a function to extract the key from a "key=value" string into a fixed-size buffer.

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

#define MAX_KEY_SIZE 32

int parse_config_key(const char *line, char *key_buffer) {

	// No check if line is a NULL pointer.

		
	const char *equals = strchr(line, '=');
	
	if (equals == NULL) {
		return -1;
	}
	
	size_t key_len = equals - line;
	
	// No guarantee of NULL-termination below in strncpy()

	// because key_len == MAX_KEY_SIZE possible
	
	if (key_len > MAX_KEY_SIZE) {
		return -1;
	}

	// No guarantee of NULL-termination below in strncpy()

	// because key_len == MAX_KEY_SIZE possible

	// Also missing terminating NULL-byte after strncpy()
	
	strncpy(key_buffer, line, key_len);
	
	return 0;
}

int main() {
	char key[MAX_KEY_SIZE];
	const char *config = "database_host=localhost";
	
	if (parse_config_key(config, key) == 0) {
		printf("Key: %s\n", key);
	}
	
	return 0;
}
```

**Expected behavior:**
```
Input: "database_host=localhost"
Output: "Key: database_host"
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `parse_config_key()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `parse_config_key()` function to fix all identified vulnerabilities.

Your implementation should:
- Properly null-terminate the result
- Validate all inputs
- Handle edge cases safely
- Check buffer boundaries correctly

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_KEY_SIZE 32

int parse_config_key(const char *line, char *key_buffer) {

	// No check if line is a NULL pointer.

	if ( line == NULL )
	{
		fprintf(stderr,"Error: line == NULL\n");

		return -1;
	}		

	const char *equals = strchr(line, '=');
	
	if (equals == NULL) {
		return -1;
	}
	
	size_t key_len = equals - line;
	
	// No guarantee of NULL-termination below in strncpy()

	// because key_len == MAX_KEY_SIZE possible
	
	if (key_len >= MAX_KEY_SIZE) {
		return -1;
	}

	// No guarantee of NULL-termination below in strncpy()

	// because key_len == MAX_KEY_SIZE possible
	
	strncpy(key_buffer, line, key_len);

	key_buffer[key_len] = 0x00;
	
	return 0;
}

int main() {
	char key[MAX_KEY_SIZE];
	const char *config = "database_host=localhost";
	
	if (parse_config_key(config, key) == 0) {
		printf("Key: %s\n", key);
	}
	
	return 0;
}
```

---

## Grading Rubric

### Part A: Vulnerability Identification (5 points)
- **2 points**: Identified missing null termination from strncpy
- **1 point**: Identified off-by-one error in bounds check
- **1 point**: Identified missing NULL pointer validation
- **1 point**: Clear explanation of security impacts

### Part B: Secure Implementation (10 points)
- **3 points**: Correctly null-terminates the key string
- **3 points**: Fixes off-by-one error (key_len >= MAX_KEY_SIZE)
- **2 points**: Validates inputs (NULL checks)
- **1 point**: Handles edge cases correctly
- **1 point**: Code compiles and functions correctly

---

## Expected Knowledge

Candidates should understand:
- strncpy behavior with null termination
- Buffer size vs string length relationships
- Off-by-one errors in bounds checking
- Pointer arithmetic and validation

---

## Hints

Consider these questions:
- What does `strncpy(key_buffer, line, key_len)` do?
- Does strncpy ALWAYS null-terminate the destination?
- If `key_len == 32`, will the string fit in a 32-byte buffer?
- What happens if `line` is NULL?
- What happens if `key_buffer` is NULL?

**Critical strncpy behavior:**

```c
char buf[32];
strncpy(buf, "database_host", 13);  // Copies 13 bytes
// buf = "database_host" + ??? (no '\0' added!)
```

---

## Key Bugs

### Bug #1: strncpy Does NOT Always Null-Terminate

```c
strncpy(key_buffer, line, key_len);
// If key_len == 32, strncpy copies EXACTLY 32 bytes
// NO null terminator is added!
```

**Example:**
```c
char key[32];
parse_config_key("this_is_a_very_long_key_name=value", key);
// key_len = 28
// strncpy copies 28 bytes: "this_is_a_very_long_key_name"
// key[28] = ??? (uninitialized!)
// printf("%s", key) → reads past buffer!
```

### Bug #2: Off-by-One in Bounds Check

```c
if (key_len > MAX_KEY_SIZE) {  // ❌ Should be >=
    return -1;
}
```

**Why this is wrong:**
```c
// MAX_KEY_SIZE = 32
// If key_len = 32:
//   - Check passes (32 > 32 is false)
//   - strncpy copies 32 bytes
//   - No room for '\0'!
```

**A 32-character key needs 33 bytes (32 + '\0')!**

### Bug #3: No NULL Validation

```c
const char *equals = strchr(line, '=');  // What if line is NULL?
```

---

## Time Allocation

- **5 minutes**: Identify the strncpy bug and off-by-one
- **10 minutes**: Write secure implementation
- **5 minutes**: Test edge cases mentally

---

## Critical Insight: strncpy Behavior

**Common misconception:**
```c
strncpy(dest, src, n);  // People think: "Copy at most n chars, always null-terminate"
```

**Reality:**
```c
// If strlen(src) < n:
//   Copies all of src + pads rest with '\0'
//   Result IS null-terminated ✓

// If strlen(src) >= n:
//   Copies EXACTLY n bytes
//   NO '\0' is added! ❌
```

**For security, ALWAYS manually null-terminate after strncpy:**
```c
strncpy(dest, src, n);
dest[n] = '\0';  // Or dest[sizeof(dest)-1] = '\0';
```

---

## References

**Primary Sources**:
- CWE-170: Improper Null Termination
- CWE-193: Off-by-one Error
- CERT C Coding Standard: STR32-C (Null-terminate strings)
- CERT C Coding Standard: STR03-C (Do not use strncpy without explicit null termination)

---

*This exercise tests understanding of strncpy behavior and buffer size calculations - fundamental C security knowledge.*
