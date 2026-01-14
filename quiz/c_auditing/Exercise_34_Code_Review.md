# Exercise 34: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a data serialization utility. The engineering team has implemented a function to write an array of integers to a byte buffer.

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

void write_integers(unsigned char *buffer, int *data, size_t count) {
	if (buffer == NULL || data == NULL || count == 0) {
		return;
	}

	// No check if buffer has enough space for data
	
	for (size_t i = 0; i < count; i++) {
		
		// sizeof(buffer[i]) != sizeof(data[i])

		buffer[i] = data[i];
	}
}

int main() {
	int numbers[] = {0x12345678, 0xABCDEF00, 0x11223344};
	unsigned char buffer[12];
	
	write_integers(buffer, numbers, 3);
	
	printf("Buffer contents: ");
	for (int i = 0; i < 12; i++) {
		printf("%02X ", buffer[i]);
	}
	printf("\n");
	
	return 0;
}
```

**Expected behavior:**
```
Buffer contents: 78 56 34 12 00 EF CD AB 44 33 22 11
(or similar, depending on endianness)
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `write_integers()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `write_integers()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void write_integers(unsigned char *buffer, size_t buffer_size,int *data, size_t count) {
	if (buffer == NULL || data == NULL || count == 0) {
		return;
	}

	// No check if buffer has enough space for data
	
	// There is enough space if buffer_size == count * sizeof(int)

	if ( buffer_size != count * sizeof(int) )
	{
		return;
	}

	memcpy(buffer,data,count * sizeof(int));
	
}

int main() {
	int numbers[] = {0x12345678, 0xABCDEF00, 0x11223344};
	unsigned char buffer[12];
	
	write_integers(buffer, 12 * sizeof(char),numbers, 3);
	
	printf("Buffer contents: ");
	for (int i = 0; i < 12; i++) {
		printf("%02X ", buffer[i]);
	}
	printf("\n");
	
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
