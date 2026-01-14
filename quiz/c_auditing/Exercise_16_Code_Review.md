# Exercise 16: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a data structure library. The engineering team has implemented a function to find an element in an array.

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

// instead of int use size_t
int find_element(int *array, int array_size, int target) {

	// No check if array == NULL

	// array_size can be negative. Should be size_t

	// size_t should be used for counting elements below in loop

	// No check if array_size == 0

	for (int i = 0; i < array_size; i++) {
		if (array[i] == target) {
			return i;
		}
	}

	// instead of returning -1 return size of array	
	return -1;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	
	// index can be negative. Should be of data type size_t

	int index = find_element(numbers, 5, 30);
	
	if (index != -1) {
		printf("Found at index: %d\n", index);
	}
	
	return 0;
}
```

**Expected behavior:**
```
Found at index: 2
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `find_element()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `find_element()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// instead of int use size_t
size_t find_element(int *array, size_t array_size, int target) {

	// No check if array == NULL

	if ( array == NULL )
	{
		return array_size;
	}

	// array_size can be negative. Should be size_t

	// size_t should be used for counting elements below in loop
	
	for (size_t i = 0; i < array_size; i++) {
		if (array[i] == target) {
			return i;
		}
	}

	// instead of returning -1 return size of array	
	return array_size;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	
	// index can be negative. Should be of data type size_t

	size_t index = find_element(numbers, 5, 30);
	
	if (index != sizeof(numbers) / sizeof(int) ) {
		printf("Found at index: %zu\n", index);
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
