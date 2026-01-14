# Exercise 15: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a buffer processing utility. The engineering team has implemented a function to copy data from a source buffer to a destination buffer.

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

// src_len can be negative! Use size_t instead

int copy_buffer(uint8_t *dest, size_t dest_size, const uint8_t *src, int src_len) {
	
	// No NULL pointer checks for dest and src	
	
	if (src_len > dest_size) {
		return -1;
	}

	memcpy(dest, src, src_len);
	
	return 0;
}

int main() {
	uint8_t destination[64];
	uint8_t source[32] = "Hello, World!";
	
	int result = copy_buffer(destination, sizeof(destination), source, 13);
	
	if (result == 0) {
		printf("Copy successful\n");
	}
	
	return 0;
}
```

**Expected behavior:**
```
Copy successful
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `copy_buffer()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)


Rewrite the `copy_buffer()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// src_len can be negative! Use size_t instead

int copy_buffer(uint8_t *dest, size_t dest_size, const uint8_t *src,size_t src_len) {
	
	// No NULL pointer checks for dest and src	

	if ( dest == NULL || src == NULL )
	{
		return -1;
	}
	
	
	if (src_len > dest_size) {
		return -1;
	}

	memcpy(dest, src, src_len);
	
	return 0;
}

int main() {
	uint8_t destination[64];
	uint8_t source[32] = "Hello, World!";
	
	int result = copy_buffer(destination, sizeof(destination), source, 13);
	
	if (result == 0) {
		printf("Copy successful\n");
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
