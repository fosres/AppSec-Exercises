# Exercise 25: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a resource management utility. The engineering team has implemented a function to clean up a data structure.

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

typedef struct {
	char *name;
	char *description;
} Resource;

void cleanup_resource(Resource *res) {
	if (res == NULL) {
		return;
	}
	
	if (res->name != NULL) {
		free(res->name);
	}

	// Remember res->description = res->name in main()

	// free() does not gurantee pointer is assigned

	// NULL afterwards! Double-free vulnerability below!

	// Check if res->description != res->name in addition to NULL instead
	
	if (res->description != NULL) {
		free(res->description);
	}
	
	free(res);
}

int main() {

	// No check if r == NULL

	Resource *r = calloc(1, sizeof(Resource));
	
	
	r->name = calloc(20, sizeof(char));
	
	// No check if r->name == NULL

	// Danger: below strcpy can cause a buffer overflow

	strcpy(r->name, "Config");

	// Below can easily lead to a double-free vulnerability
	
	r->description = r->name;
	
	cleanup_resource(r);
	
	return 0;
}
```

**Expected behavior:**
```
(Program exits cleanly)
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the code. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the code to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
	char *name;
	char *description;
} Resource;

void cleanup_resource(Resource *res) {
	if (res == NULL) {
		return;
	}
	
	if (res->name != NULL) {
		free(res->name);
	}

	// Remember res->description = res->name in main()

	// free() does not gurantee pointer is assigned

	// NULL afterwards! Double-free vulnerability below!

	// Check if res->description != res->name in addition to NULL
	
	if ( res->description != NULL  ) {
		free(res->description);
	}
	
	free(res);
}

int main() {

	// No check if r == NULL

	Resource *r = calloc(1, sizeof(Resource));

	if ( r == NULL )
	{
		return 1;
	}	
	
	r->name = calloc(20, sizeof(char));
	
	// No check if r->name == NULL

	if ( r->name == NULL )
	{
		cleanup_resource(r);

		return 1;
	}

	// Danger: below strcpy can cause a buffer overflow

	snprintf(r->name,20*sizeof(char),"%s","Config");

	//strcpy(r->name, "Config");

	// Below can easily lead to a double-free vulnerability
	
	r->description = calloc(20, sizeof(char));
	
	// No check if r->name == NULL

	if ( r->description == NULL )
	{
		cleanup_resource(r);

		return 1;
	}

	snprintf(r->description,20*sizeof(char),"%s",r->name);	
	
	cleanup_resource(r);
	
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
