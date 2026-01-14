# Exercise 6: C Security Audit - Log Message Builder

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a logging system. The engineering team has implemented a function to build log messages by appending a timestamp prefix to user messages.

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

char *build_log_message(const char *prefix, const char *message) {

	// No checks if prefix nor message are NULL pointers

	size_t prefix_len = strlen(prefix);
	size_t message_len = strlen(message);

	// Off-By-One Error below: No gurantee of NULL-termination	

	// Also no check if malloc() failed

	char *log = (char *) malloc(prefix_len + message_len);

	// Dangerous string functions below	
	strcpy(log, prefix);
	strcat(log, message);
	
	return log;
}

int main() {
	const char *timestamp = "[2024-01-15] ";
	const char *user_msg = "Login successful";

	// No check if log_entry is assigned a NULL pointer
	
	char *log_entry = build_log_message(timestamp, user_msg);


	printf("%s\n", log_entry);
	
	free(log_entry);

	return 0;
}
```

**Example output:**
```
[2024-01-15] Login successful
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `build_log_message()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `build_log_message()` function to fix all identified vulnerabilities.

Your implementation should:
- Allocate the correct amount of memory
- Handle all edge cases safely
- Check for allocation failures
- Validate inputs appropriately

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *build_log_message(const char *prefix, const char *message) {

	if ( prefix == NULL )
	{
		fprintf(stderr,"Error: prefix == NULL\n");

		return NULL;
	}
	
	if ( message == NULL )
	{
		fprintf(stderr,"Error: message == NULL\n");

		return NULL;
	}

	size_t prefix_len = strlen(prefix);
	size_t message_len = strlen(message);


	char *log = (char *) calloc(prefix_len + message_len + 1,sizeof(char));

	if ( log == NULL )
	{
		fprintf(stderr,"Error: allocation of log failed\n");

		return NULL;
	}

	snprintf(log,prefix_len + message_len + 1,"%s%s",prefix,message);

	return log;
}

int main() {
	const char *timestamp = "[2024-01-15] ";
	const char *user_msg = "Login successful";
	
	char *log_entry = build_log_message(timestamp, user_msg);
	
	if ( log_entry == NULL )
	{
		fprintf(stderr,"Error: log_entry == NULL\n");	

		return 1;
	}

	printf("%s\n", log_entry);
	
	free(log_entry);
	return 0;
}
```

---

## Grading Rubric

### Part A: Vulnerability Identification (5 points)
- **2 points**: Correctly identified the off-by-one error in malloc
- **1 point**: Explained why prefix_len + message_len is insufficient
- **1 point**: Identified missing malloc validation
- **1 point**: Clear explanation of security impact (buffer overflow)

### Part B: Secure Implementation (10 points)
- **4 points**: Allocates correct memory size (prefix_len + message_len + 1)
- **2 points**: Validates malloc return value
- **2 points**: Validates inputs (NULL checks)
- **1 point**: Handles edge cases correctly
- **1 point**: Code compiles and functions correctly

---

## Expected Knowledge

Candidates should understand:
- String null termination in C
- Memory allocation sizing for strings
- Off-by-one errors in buffer allocation
- strcpy/strcat behavior
- Defensive programming practices

---

## Hints

Consider these questions:
- How many bytes does the prefix "[2024-01-15] " require? (13 characters)
- How many bytes does the message "Login successful" require? (16 characters)
- How many total bytes are needed to store both strings?
- What does strcat() need at the end of the combined string?
- What happens if malloc() fails?

---

## Key Insight

```c
strlen(prefix) + strlen(message) = ?
// prefix = "[2024-01-15] "     → 13 bytes
// message = "Login successful"  → 16 bytes
// Total: 13 + 16 = 29 bytes

malloc(29);  // Allocates 29 bytes
// But we need to store: "[2024-01-15] Login successful\0"
// That's 30 bytes! (29 characters + 1 null terminator)
```

**The bug:**
- `strlen()` returns the length WITHOUT the null terminator
- When combining two strings, you need: len1 + len2 + 1 (for final '\0')
- `malloc(prefix_len + message_len)` is missing the +1

---

## Time Allocation

Recommended time breakdown:
- **5 minutes**: Analyze the code and identify the off-by-one
- **10 minutes**: Write secure implementation
- **5 minutes**: Review and test your solution

---

## References

**Primary Sources**:
- CWE-193: Off-by-one Error
- CWE-131: Incorrect Calculation of Buffer Size
- CERT C Coding Standard: STR31-C (Guarantee strings are null-terminated)
- *API Security in Action*, Chapter 2, pp. 47-49

---

*This exercise tests fundamental C string handling and memory allocation - core knowledge for security engineering.*
