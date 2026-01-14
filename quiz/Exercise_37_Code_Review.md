# Exercise 37: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a data buffer utility. The engineering team has implemented a function to read data from a buffer at a specified offset.

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

int read_buffer(unsigned char *buffer, size_t buffer_size, int offset, unsigned char *output, size_t output_size) {
	if (buffer == NULL || output == NULL) {
		return -1;
	}

	// Integer Overflow Risk: use size_t for offset.

	// No reason to use a signed integer: offset can be negative

	// if using a signed integer!

	if (offset < 0 || offset >= buffer_size) {
		return -1;
	}
	
	if (output_size > buffer_size - offset) {
		return -1;
	}
	
	memcpy(output, buffer + offset, output_size);
	
	return 0;
}

int main() {
	unsigned char data[100];

	// bad habit to use a signed integer for counting

	// use size_t instead

	for (int i = 0; i < 100; i++) {
		data[i] = i;
	}
	
	unsigned char result[10];
	
	if (read_buffer(data, 100, 50, result, 10) == 0) {
		printf("Read succeeded: ");
		
		// bad habit to use a signed integer for counting

		// use size_t instead

		for (int i = 0; i < 10; i++) {
			printf("%d ", result[i]);
		}
		printf("\n");
	}
	
	return 0;
}
```

**Expected behavior:**
```
Read succeeded: 50 51 52 53 54 55 56 57 58 59
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `read_buffer()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `read_buffer()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int read_buffer(unsigned char *buffer, size_t buffer_size, size_t offset, unsigned char *output, size_t output_size) {
	if (buffer == NULL || output == NULL) {
		return -1;
	}

	// Integer Overflow Risk: use size_t for offset.

	// No reason to use a signed integer: offset can be negative

	// if using a signed integer!

	if (offset < 0 || offset >= buffer_size) {
		return -1;
	}
	
	if (output_size > buffer_size - offset) {
		return -1;
	}
	
	memcpy(output, buffer + offset, output_size);
	
	return 0;
}

int main() {

	// good habit to initialize arrays first

	unsigned char data[100] = {0};

	// bad habit to use a signed integer for counting

	// use size_t instead

	for (size_t i = 0; i < 100; i++) {
		data[i] = i;
	}

	// good habit to initialize arrays first
	
	unsigned char result[10] = {0};
	
	if (read_buffer(data, 100, 50, result, 10) == 0) {
		printf("Read succeeded: ");
		
		// bad habit to use a signed integer for counting

		// use size_t instead

		for (size_t i = 0; i < 10; i++) {
			printf("%d ", result[i]);
		}
		printf("\n");
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
