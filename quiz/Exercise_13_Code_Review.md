# Exercise 13: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a data processing library. The engineering team has implemented a function to allocate an array of integers.

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
#include <stdint.h>

int32_t *allocate_array(size_t num_elements) {

	// NO check if below multiplication causes Integer Overflow

	size_t total_bytes = num_elements * sizeof(int32_t);

	// No check if malloc() below returns NULL pointer	

	int32_t *array = malloc(total_bytes);
	
	return array;
}

int main() {
	size_t count = 1000;
	int32_t *data = allocate_array(count);
	
	if (data != NULL) {
		printf("Allocated array of %zu elements\n", count);
		free(data);
	}
	
	return 0;
}
```

**Expected behavior:**
```
Allocated array of 1000 elements
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `allocate_array()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `allocate_array()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

int32_t *allocate_array(size_t num_elements) {

	// NO check if below multiplication causes Integer Overflow

//	size_t total_bytes = num_elements * sizeof(int32_t);

	size_t total_bytes = 0;

	if ( __builtin_mul_overflow(num_elements,sizeof(int32_t),&total_bytes) ==
true )
	{
		fprintf(stderr,"Error: total_bytes calculation overflows\n");

		return NULL;
	}

	// No check if malloc() below returns NULL pointer	

	int32_t *array = malloc(total_bytes);

	if ( array == NULL )
	{
		fprintf(stderr,"Error: array allocation failed\n");

		return NULL;
	}
	
	return array;
}

int main() {
	size_t count = 1000;
	int32_t *data = allocate_array(count);
	
	if (data != NULL) {
		printf("Allocated array of %zu elements\n", count);
		free(data);
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
