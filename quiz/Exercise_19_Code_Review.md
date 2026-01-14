# Exercise 19: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a string processing utility. The engineering team has implemented a function to duplicate a string with a maximum length limit.

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

char *duplicate_string(const char *src, size_t max_len) {

	// No check is src == NULL

	size_t len = strlen(src);

	if (len > max_len) {
		len = max_len;
	}

	// No check if result == NULL after calloc()

	// Off-By-One Error possible since we need space

	// for terminating NULL-byte: should be calloc(len+1,...
	
	char *result = calloc(len, sizeof(char));

	// Since src string can be truncated below does not

	gurantee NULL-termination
	
	strncpy(result, src, len);
	
	return result;
}

int main() {
	const char *original = "Hello, World!";
	char *copy = duplicate_string(original, 10);
	
	if (copy != NULL) {
		printf("Copy: %s\n", copy);
		free(copy);
	}
	
	return 0;
}
```

**Expected behavior:**
```
Copy: Hello, Wor
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `duplicate_string()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `duplicate_string()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *duplicate_string(const char *src, size_t max_len) {

	// No check is src == NULL

	if ( src == NULL )
	{
		return NULL;
	}

	size_t len = strlen(src);

	if (len > max_len) {
		len = max_len;
	}

	// No check if result == NULL after calloc()

	// Off-By-One Error possible since we need space

	// for terminating NULL-byte: should be calloc(len+1,...
	
	char *result = calloc(len+1, sizeof(char));

	if ( result == NULL )
	{
		return NULL;
	}
	// Since src string can be truncated below does not

	gurantee NULL-termination
	
	strncpy(result, src, len);

	result[len] = 0x00; // in case src is truncated this is needed
	
	return result;
}

int main() {
	const char *original = "Hello, World!";
	char *copy = duplicate_string(original, 10);
	
	if (copy != NULL) {
		printf("Copy: %s\n", copy);
		free(copy);
	}
	
	return 0;
}
```

---

## Grading Rubric

### Part A: Vulnerability Identification (5 points)
- **5 points**: Identified all security vulnerabilities with clear explanations

### Part B: Secure Implementation (10 points)
- **10 points**: Fixed all identified vulnerabilities correctly

---

## Time Allocation

- **5 minutes**: Review code and identify vulnerabilities
- **10 minutes**: Write secure implementation
- **5 minutes**: Verify your solution handles edge cases

---

*This is a realistic security code review exercise. Good luck!*
