# Exercise 17: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a string utility library. The engineering team has implemented a function to reverse a string in place.

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

// No check if str == NULL
void reverse_string(char *str) {

	
	// No check if str == NULL

	size_t len = strlen(str);

	/* 
		Out-of-bounds indexing.	
	
		For example when i == 0 

		len - 0 == len. But you

		cannot index str[len]
	*/

	for (size_t i = 0; i < len; i++) {
		char temp = str[i];
		str[i] = str[len - i];
		str[len - i] = temp;
	}
}

int main() {
	char text[] = "Hello";
	reverse_string(text);
	
	printf("Reversed: %s\n", text);
	
	return 0;
}
```

**Expected behavior:**
```
Reversed: olleH
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `reverse_string()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `reverse_string()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// No check if str == NULL
void reverse_string(char *str) {

	
	// No check if str == NULL

	if ( str == NULL )
	{
		return;
	}

	size_t len = strlen(str);

	if ( len == 0 )
	{
		return;
	}

	/* 
		Out-of-bounds indexing.	
	
		For example when i == 0 

		len - 0 == len. But you

		cannot index str[len]
	*/

	for (size_t i = 0, j = len - 1 ; i < j ; i++,j--) {
		char temp = str[i];
		str[i] = str[j];
		str[j] = temp;
	}
}

int main() {
	char text[] = "Hello";
	reverse_string(text);
	
	printf("Reversed: %s\n", text);
	
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
