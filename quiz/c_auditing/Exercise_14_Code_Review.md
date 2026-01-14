# Exercise 14: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a string processing utility. The engineering team has implemented a function to remove a prefix from a string.

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

char *remove_prefix(const char *str, size_t prefix_len) {

	// No check is str == NULL

	// No check if prefix_len == 0

	size_t str_len = strlen(str);

	// No check for Integer Underflow below

	// No check if prefix_len >= str_len

	size_t result_len = str_len - prefix_len;

	// No check if malloc() returns NULL below 
	
	char *result = malloc(result_len + 1);

	// NULL-termination in strcpy() only takes place if

	// NULL-terminating byte present in str
	
	strcpy(result, str + prefix_len);
	
	return result;
}

int main() {
	const char *text = "Hello, World!";

	char *without_prefix = remove_prefix(text, 7);
	
	if (without_prefix != NULL) {
		printf("Result: %s\n", without_prefix);
		free(without_prefix);
	}
	
	return 0;
}
```

**Expected behavior:**
```
Result: World!
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `remove_prefix()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `remove_prefix()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *remove_prefix(const char *str, size_t prefix_len) {

	if ( str == NULL )
	{
		fprintf(stderr,"Error: str == NULL\n");

		return NULL;

	}

	// No check if prefix_len == 0

	if ( prefix_len == 0 )
	{
		fprintf(stderr,"Error: prefix_len == 0\n");

		return NULL;
	}

	size_t str_len = strlen(str);

	if ( prefix_len >= str_len )
	{
		fprintf(stderr,"Error: prefix_len >= str_len\n");
	
		return NULL;
	}

	// No check for Integer Underflow below

	// No check if prefix_len >= str_len

//	size_t result_len = str_len - prefix_len;

	size_t result_len = 0;

	if ( __builtin_sub_overflow(str_len,prefix_len,&result_len) == true )
	{
		fprintf(stderr,"Error: str_len - prefix_len underflows\n");

		return NULL;
	}

	// No check if malloc() returns NULL below 
	
	char *result = malloc(result_len + 1);

	// NULL-termination in strcpy() only takes place if

	// NULL-terminating byte present in str

	if ( result == NULL )
	{
		fprintf(stderr,"result == NULL\n");

		return NULL;
	}

	snprintf(result,result_len + 1,"%s",str + prefix_len);
	
	return result;
}

int main() {
	const char *text = "Hello, World!";

	char *without_prefix = remove_prefix(text, 7);
	
	if (without_prefix != NULL) {
		printf("Result: %s\n", without_prefix);
		free(without_prefix);
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
