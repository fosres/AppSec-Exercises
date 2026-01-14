# Exercise 23: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a data validation utility. The engineering team has implemented a function to check if all elements in an array are positive.

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
#include <stdbool.h>

bool all_positive(int *values, size_t count) {
	if (values == NULL || count == 0) {
		return false;
	}

	// result not initialized so unsafe to return as uninitialized
	
	bool result;

		
	for (size_t i = 0; i < count; i++) {

		if (values[i] <= 0) {
			result = false;
			break;
		}
	}
	
	// result not initialized above so unsafe to return as

	// uninitialized
	
	return result;
}

int main() {
	int numbers[] = {1, 2, 3, 4, 5};
	
	if (all_positive(numbers, 5)) {
		printf("All values are positive\n");
	} else {
		printf("Not all values are positive\n");
	}
	
	return 0;
}
```

**Expected behavior:**
```
All values are positive
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `all_positive()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `all_positive()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

bool all_positive(int *values, size_t count) {
	if (values == NULL || count == 0) {
		return false;
	}

	// result not initialized so unsafe to return as uninitialized
		
	for (size_t i = 0; i < count; i++) {

		if (values[i] <= 0) {
			
			return false;	
		}
	}
	
	return true;
}

int main() {
	int numbers[] = {1, 2, 3, 4, 5};
	
	if (all_positive(numbers, 5)) {
		printf("All values are positive\n");
	} else {
		printf("Not all values are positive\n");
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
