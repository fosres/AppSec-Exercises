# Exercise 32: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a string processing utility. The engineering team has implemented a function to pad a string with spaces to a fixed width.

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

char *pad_string(const char *str, size_t width) {
	if (str == NULL || width == 0) {
		return NULL;
	}
	
	size_t len = strlen(str);
	
	if (len >= width) {
		return strdup(str);
	}

	// This should be  width + 1 (for NULL-byte) (watch out for Integer
	// Overflow)
	
	char *result = calloc(width, sizeof(char));
	
	if (result == NULL) {
		return NULL;
	}
	
	strcpy(result, str);
	
	// this is a really a bad way of trying to pad

	// no space for terminating NULL-byte since size of

	// result is width

	for (size_t i = len; i <= width; i++) {
		result[i] = ' ';
	}
	
	return result;
}

int main() {
	char *padded = pad_string("Hello", 10);
	
	if (padded != NULL) {
		printf("Padded: '%s'\n", padded);
		free(padded);
	}
	
	return 0;
}
```

**Expected behavior:**
```
Padded: 'Hello     '
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `pad_string()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `pad_string()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

char *pad_string(const char *str, size_t width) {
	if (str == NULL || width == 0) {
		return NULL;
	}
	
	size_t len = strlen(str);
	
	if (len >= width) {
		return strdup(str);
	}

	// New size of result should be  width + 1 (watch out for Integer
	// Overflow)

	size_t newsize = 0;

	if ( __builtin_add_overflow(width,1,&newsize) == true )
	{
		return NULL;
	}
	
	char *result = calloc(newsize, sizeof(char));
	
	if (result == NULL) {
		return NULL;
	}

	snprintf(result,newsize,"%s",str);

	for ( size_t i = len ; i < (newsize - 1) ; i++ )
	{
		result[i] = ' ';
	} 
	
	// strcpy(result, str);
	
	// this is a really a bad way of trying to pad

	
	return result;
}

int main() {
	char *padded = pad_string("Hello", 10);
	
	if (padded != NULL) {
		printf("Padded: '%s'\n", padded);
		free(padded);
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
