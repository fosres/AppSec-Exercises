# Exercise 31: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a data copying utility. The engineering team has implemented a function to create a copy of an integer array.

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

int *copy_array(int *source, size_t count) {
	if (source == NULL || count == 0) {
		return NULL;
	}

	// incorrect count of bytes below	
	int *result = malloc(sizeof(source));
	
	if (result == NULL) {
		return NULL;
	}
	
	// incorrect count of bytes below	

	memcpy(result, source, sizeof(source));
	
	return result;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	
	int *copy = copy_array(numbers, 5);
	
	if (copy != NULL) {
		printf("Copied array: ");
		for (int i = 0; i < 5; i++) {
			printf("%d ", copy[i]);
		}
		printf("\n");
		free(copy);
	}
	
	return 0;
}
```

**Expected behavior:**
```
Copied array: 10 20 30 40 50
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `copy_array()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `copy_array()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int *copy_array(int *source, size_t count) {
	if (source == NULL || count == 0) {
		return NULL;
	}

	// incorrect count of bytes below	

	int * result = (int*)calloc(count,sizeof(int));
	
	if (result == NULL) {
		return NULL;
	}
	
	// incorrect count of bytes below	

	memcpy(result, source,count * sizeof(int));
	
	return result;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	
	int *copy = copy_array(numbers, 5);
	
	if (copy != NULL) {
		printf("Copied array: ");
		for (int i = 0; i < 5; i++) {
			printf("%d ", copy[i]);
		}
		printf("\n");
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
