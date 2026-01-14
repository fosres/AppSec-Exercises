# Exercise 33: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a character counting utility. The engineering team has implemented a function to count occurrences of each letter in a string.

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
#include <ctype.h>

void count_letters(const char *text) {
	if (text == NULL) {
		return;
	}
	
	// potential for overflow: better to use size_t

	int counts[26] = {0};

	// So what if text[i] is not an alphabetic letter?

	// this can cause possible out-of-bounds indexing
	
	for (size_t i = 0; i < strlen(text); i++) {
		char c = tolower(text[i]);
		int index = c - 'a';
		counts[index]++;
	}
	
	printf("Letter frequencies:\n");
	for (int i = 0; i < 26; i++) {
		if (counts[i] > 0) {
			printf("%c: %d\n", 'a' + i, counts[i]);
		}
	}
}

int main() {
	count_letters("Hello World!");
	
	return 0;
}
```

**Expected behavior:**
```
Letter frequencies:
d: 1
e: 1
h: 1
l: 3
o: 2
r: 1
w: 1
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `count_letters()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `count_letters()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

void count_letters(const char *text) {
	if (text == NULL) {
		return;
	}

	// potential for overflow: better to use size_t
	
	size_t counts[26] = {0};

	// So what if text[i] is not an alphabetic letter?

	// this can cause possible out-of-bounds indexing
	
	for (size_t i = 0; i < strlen(text); i++) {

		if ( !isalpha(text[i]) )
		{
			continue;
		}

		char c = tolower(text[i]);

		// let's use size_t below instead of int

		size_t index = c - 'a';

		counts[index]++;
	}
	
	printf("Letter frequencies:\n");

	// let's use size_t below instead of int

	for (size_t i = 0; i < 26; i++) {
		if (counts[i] > 0) {
			printf("%c: %d\n", 'a' + i, counts[i]);
		}
	}
}

int main() {
	count_letters("Hello World!");
	
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
