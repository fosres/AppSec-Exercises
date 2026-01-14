# Exercise 20: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a configuration parser. The engineering team has implemented a function to get a configuration value as a formatted string.

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

char *get_config_value(const char *key, int value) {

	// No check if key == NULL

	// Not a security vulnerability since snprintf() copies

	// at most sizeof(buffer) - 1 bytes but will mention

	// anyway:

	// possible truncation of key if too large to fit in

	// buffer before NULL-byte

	char buffer[64];
	
	snprintf(buffer, sizeof(buffer), "%s=%d", key, value);

	// buffer is popped from stack after function call

	// instance ends. You will have to use dynamic memory

	// allocation and free the buffer later!
	
	return buffer;
}

int main() {
	
	// No error checking that get_config_value returns NULL

	char *config = get_config_value("timeout", 30);
	
	printf("Config: %s\n", config);
	
	return 0;
}
```

**Expected behavior:**
```
Config: timeout=30
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `get_config_value()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `get_config_value()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

char *get_config_value(const char *key, int value) {

	if ( key == NULL )
	{
		return NULL;
	}

	// No check if key == NULL

	// Not a security vulnerability since snprintf() copies

	// at most sizeof(buffer) - 1 bytes but will mention

	// anyway:

	// possible truncation of key if too large to fit in

	// buffer before NULL-byte
	
	// buffer is popped from stack after function call

	// instance ends. You will have to use dynamic memory

	// allocation and free the buffer later!

	// Below allocation should gurantee enough space since int

	// values cannot be larger than 11 characters long

	// so total_len == 11 (len of value string at worst) + strlen(key) + 1 ('=')

	// so total_len == strlen(key) + 12

	// but alloc_len for buffer must be total_len + 1 to leave

	// space for terminating NULL-byte

	size_t total_len = 0;

	size_t twelve = 12;

	if ( __builtin_add_overflow(strlen(key),twelve,&total_len) == true )
	{
		return NULL;
	}

	size_t one = 1;

	size_t alloc_len = 0;
	
	if ( __builtin_add_overflow(total_len,one,&alloc_len) == true )
	{
		return NULL;
	}

	char * buffer = (char*)calloc(alloc_len,sizeof(char));

	if ( buffer == NULL )
	{
		return NULL;
	}

	// have to add 1 to total_len to gurantee space for NULL-byte
	
	snprintf(buffer,alloc_len, "%s=%d", key, value);
	
	return buffer;
}

int main() {
	
	// No error checking that get_config_value returns NULL

	char *config = NULL;

	if ( ( config = get_config_value("timeout",30) ) == NULL )
	{
		return 1;
	}
	
	printf("Config: %s\n", config);

	free(config);
	
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
