# Exercise 26: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a data extraction utility. The engineering team has implemented a function to extract a subset of an array.

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

int *extract_range(int *source, size_t source_size, size_t start, size_t end) {
	if (source == NULL) {
		return NULL;
	}

	// No check if end <= start
	
	// No check if start  >= source_size and end <= source_size
	
	
	size_t range_size = end - start;
	
	int *result = calloc(range_size, sizeof(int));
	
	if (result == NULL) {
		return NULL;
	}
	
	memcpy(result, source + start, range_size * sizeof(int));
	
	return result;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
	
	int *subset = extract_range(numbers, 10, 2, 5);
	
	if (subset != NULL) {
		printf("Extracted: %d %d %d\n", subset[0], subset[1], subset[2]);
		free(subset);
	}
	
	return 0;
}
```

**Expected behavior:**
```
Extracted: 30 40 50
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `extract_range()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `extract_range()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int *extract_range(int *source, size_t source_size, size_t start, size_t end) {
	if (source == NULL) {
		return NULL;
	}

	// No check if end <= start

	if ( end <= start )
	{
		return NULL;
	}

	// No check if start  >= source_size and end <= source_size

	if ( end > source_size || start >= source_size )
	{
		return NULL;
	}
	
	size_t range_size = end - start;
	
	int *result = calloc(range_size, sizeof(int));
	
	if (result == NULL) {
		return NULL;
	}
	
	memcpy(result, source + start, range_size * sizeof(int));
	
	return result;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
	
	int *subset = extract_range(numbers, 10, 2, 5);
	
	if (subset != NULL) {
		printf("Extracted: %d %d %d\n", subset[0], subset[1], subset[2]);
		free(subset);
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
