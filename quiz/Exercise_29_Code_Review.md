# Exercise 29: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a logging system. The engineering team has implemented a function to format log messages.

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

char *format_log_message(const char *level, const char *message) {
	if (level == NULL || message == NULL) {
		return NULL;
	}
	
	char buffer[64];

	// Below use of sprintf at risk of buffer overflow

	// Should use snprintf that uses buffer

	// capacity == strlen(level) + strlen(msg) + 3 (brackets+space) + 1	

	// In fact why are first copying to buffer?

	// We can instead first calculate the required length

	// then initialize result then copy string contents to

	// result!

	sprintf(buffer, "[%s] %s", level, message);
	
	char *result = calloc(strlen(buffer) + 1, sizeof(char));
	
	if (result == NULL) {
		return NULL;
	}

	// strcpy() at risk of buffer overflow
	
	strcpy(result, buffer);
	
	return result;
}

int main() {
	char *log1 = format_log_message("INFO", "System started");
	char *log2 = format_log_message("ERROR", "Connection failed");
	
	if (log1 != NULL) {
		printf("%s\n", log1);
		free(log1);
	}
	
	if (log2 != NULL) {
		printf("%s\n", log2);
		free(log2);
	}
	
	return 0;
}
```

**Expected behavior:**
```
[INFO] System started
[ERROR] Connection failed
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `format_log_message()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `format_log_message()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

char *format_log_message(const char *level, const char *message) {
	if (level == NULL || message == NULL) {
		return NULL;
	}
	
	// Below use of sprintf at risk of buffer overflow

	// Should use snprintf that uses buffer

	// capacity == strlen(level) + strlen(msg) + 3 (brackets+space) + 1	

	size_t capacity = 0;

	if ( __builtin_add_overflow(strlen(level),strlen(message),&capacity) == true )
	{
		return NULL;
	}

	size_t three = 3, one = 1;
	
	if ( __builtin_add_overflow(capacity,three,&capacity) == true )
	{
		return NULL;
	}
	
	if ( __builtin_add_overflow(capacity,one,&capacity) == true )
	{
		return NULL;
	}

	// assign buffer with calloc() below
	
	char * result = (char*) calloc(capacity,sizeof(char));

	if ( result == NULL )
	{
		return NULL;
	}

	// replacing sprintf() with snprintf()
	
	snprintf(result,capacity,"[%s] %s",level,message);

	return result;
}

int main() {
	char *log1 = format_log_message("INFO", "System started");
	char *log2 = format_log_message("ERROR", "Connection failed");
	
	if (log1 != NULL) {
		printf("%s\n", log1);
		free(log1);
	}
	
	if (log2 != NULL) {
		printf("%s\n", log2);
		free(log2);
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
