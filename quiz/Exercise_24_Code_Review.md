# Exercise 24: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a data processing utility. The engineering team has implemented a function to find the maximum value in an array and return its index.

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

size_t find_max_index(int *values, size_t count) {
	if (values == NULL || count == 0) {
		return 0;
	}

	size_t max_index = 0;

	// Out-of-bounds: you can't access values[count]
	
	for (size_t i = 1; i <= count; i++) {
		if (values[i] > values[max_index]) {
			max_index = i;
		}
	}
	
	return max_index;
}

int main() {
	int numbers[] = {10, 50, 30, 20, 40};
	
	size_t max_idx = find_max_index(numbers, 5);
	
	printf("Max value is at index: %zu\n", max_idx);
	
	return 0;
}
```

**Expected behavior:**
```
Max value is at index: 1
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `find_max_index()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `find_max_index()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

size_t find_max_index(int *values, size_t count) {
	if (values == NULL || count == 0) {
		return 0;
	}
	
	size_t max_index = 0;

	// Out-of-bounds: you can't access values[count]
	
	for (size_t i = 1; i < count; i++)
	{

		if (values[i] > values[max_index])
		{
			max_index = i;
		}
	}
	
	return max_index;
}

int main() {
	int numbers[] = {10, 50, 30, 20, 40};
	
	size_t max_idx = find_max_index(numbers, 5);
	
	printf("Max value is at index: %zu\n", max_idx);
	
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
