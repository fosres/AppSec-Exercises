# ACME Product Security Tech Test - Question 1

## Scenario

You are a member of the ACME Product Security Team. You are being engaged by the Software Engineering Team which is currently working on a project to develop and deploy a new web application.

---

## Question 1

The Software Engineering Team sends you the following file server code for a security review.

**Assume you can reach this code via HTTP, fully controlling the contents of `s`.**

```c
#include <stdlib.h>
#include <string.h>

char *deserialize(const char *s) {
	
	// No attempt at error-handling: if any of the

	// operations below fail it would be wise to return

	// NULL. Instead function assumes all operations

	// work without failure.

	// No check if s == NULL. This can cause the computer

	// to attempt to dereference a NULL pointer. This is

	// dangerous behavior.
	
	size_t len = strnlen(s, 4096);
	
	// Off-by-One Error:

	// forgot to add extra byte for terminal NULL-byte below

	// When adding extra byte for space in length watch

	// out for Integer Overflow Possibility

	// Failed to check if malloc() returns NULL: this can

	// cause the computer to attempt to dereference a NULL

	// pointer. This is dangerous behavior.

	char *b = (char *) malloc(len);

	// strcpy() unsafe: does not gurantee NULL-termination

	// after copying

	// Buffer Overflow: Also strcpy will attempt to copy entire

	// contents of s to b. It's possible s is longer than b.

	strcpy(b, s);
	return b;
}
```

---

### What vulnerabilities exist in the code? How would you exploit them?

Insert your answer here:

See comments in code above.

---

### What mitigations would you suggest?

Insert your answer here:

Here is the secure implementation below:


```c
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

char *deserialize(const char *s) {
	
	// No attempt at error-handling: if any of the

	// operations below fail it would be wise to return

	// NULL. Instead function assumes all operations

	// work without failure.

	// No check if s == NULL. This can cause the computer

	// to attempt to dereference a NULL pointer. This is

	// dangerous behavior.

	if ( s == NULL )
	{
		return NULL;
	}
	
	size_t len = strnlen(s, 4096);
	
	// Off-by-One Error:

	// forgot to add extra byte for terminal NULL-byte below

	// When adding extra byte for space in length watch

	// out for Integer Overflow Possibility

	// Failed to check if malloc() returns NULL: this can

	// cause the computer to attempt to dereference a NULL

	// pointer. This is dangerous behavior.

	size_t alloc_len = 0;

	if ( __builtin_add_overflow(len,1,&alloc_len) == true )
	{
		return NULL;
	}

	char *b = (char *) calloc(alloc_len,sizeof(char));

	if ( b == NULL )
	{
		return NULL;
	}

	// strcpy() unsafe: does not gurantee NULL-termination

	// after copying

	// Buffer Overflow: Also strcpy will attempt to copy entire

	// contents of s to b. It's possible s is longer than b.

	if ( snprintf(b,alloc_len,"%s",s) < 0 )
	{
		free(b);

		return NULL;	
	}

	return b;
}
```

---

**Time Limit:** Part of a 3-hour exam  
**Goal:** Correctly identify issues and suggest sensible mitigations

**Note:** Do not use Large Language Models such as ChatGPT for assistance.
