# Exercise 22: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a string utility library. The engineering team has implemented a function to create a lowercase copy of a string.

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
#include <ctype.h>

char *to_lowercase(const char *str) {
	if (str == NULL) {
		return NULL;
	}
	
	size_t len = strlen(str);
	char *result = calloc(len + 1, sizeof(char));
	
	if (result == NULL) {
		return NULL;
	}
	
	for (size_t i = 0; i < len; i++) {
		result[i] = tolower(str[i]);
	}
	
	return result;
}

int main() {
	char *lower1 = to_lowercase("HELLO");
	char *lower2 = to_lowercase("WORLD");
	
	if (lower1 != NULL && lower2 != NULL) {
		printf("%s %s\n", lower1, lower2);
	}
	
	// We need to check which of lower1 or lower2 is NOT NULL

	// and free that accordingly so below free() is not sufficient
	
	free(lower1);

	
	return 0;
}
```

**Expected behavior:**
```
hello world
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `to_lowercase()` function and `main()`. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the code to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

char *to_lowercase(const char *str) {
	if (str == NULL) {
		return NULL;
	}
	
	size_t len = strlen(str);
	char *result = calloc(len + 1, sizeof(char));
	
	if (result == NULL) {
		return NULL;
	}
	
	for (size_t i = 0; i < len; i++) {
		result[i] = tolower(str[i]);
	}
	
	return result;
}

int main() {
	char *lower1 = to_lowercase("HELLO");
	char *lower2 = to_lowercase("WORLD");
	
	if (lower1 != NULL && lower2 != NULL) {
		printf("%s %s\n", lower1, lower2);
	}
	
	// We need to check which of lower1 or lower2 is NOT NULL

	// and free that accordingly so below free() is not sufficient

	if ( lower1 != NULL )
	{
		free(lower1);
	}

	if ( lower2 != NULL )
	{
		free(lower2);
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
