# Exercise 18: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a data processing library. The engineering team has implemented a function to merge two arrays into a newly allocated array.

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

int *merge_arrays(int *array1, size_t size1, int *array2, size_t size2) {

	// No Check if array1 == NULL || array2 == NULL


	// No check if total_size == 0

	// Integer Overflow Vulnerability Below
	
	size_t total_size = size1 + size2;

	// No check if malloc() returns NULL
	
	// incorrect amount of multiplication	
	
	int *result = malloc(total_size);

	memcpy(result, array1, size1);
	memcpy(result + size1, array2, size2);
	
	return result;
}

int main() {
	int first[] = {1, 2, 3};
	int second[] = {4, 5, 6};
	
	int *merged = merge_arrays(first, 3, second, 3);
	
	if (merged != NULL) {
		printf("Merged array created\n");
		free(merged);
	}
	
	return 0;
}
```

**Expected behavior:**
```
Merged array created
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `merge_arrays()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `merge_arrays()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int *merge_arrays(int *array1, size_t size1, int *array2, size_t size2) {

	// No Check if array1 == NULL || array2 == NULL

	if ( array1 == NULL || array2 == NULL )
	{
		return NULL;
	}

	// No check if total_size == 0

	// Integer Overflow Vulnerability Below
	
	size_t total_size = 0;

	
	if ( __builtin_add_overflow(size1,size2,&total_size) == true )
	{
		return NULL;
	}

	if ( total_size == 0 )
	{
		return NULL;
	}
	// No check if malloc() returns NULL

	// incorrect amount of multiplication	
	int *result = malloc(total_size * sizeof(int));

	if ( result == NULL )
	{
		return NULL;
	}
	

	memcpy(result, array1, size1 * sizeof(int));
	memcpy(result + size1, array2, size2 * sizeof(int));
	
	return result;
}

int main() {
	int first[] = {1, 2, 3};
	int second[] = {4, 5, 6};
	
	int *merged = merge_arrays(first, 3, second, 3);
	
	if (merged != NULL) {
		printf("Merged array created\n");
		free(merged);
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
