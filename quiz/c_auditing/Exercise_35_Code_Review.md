# Exercise 35: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a permission checking system. The engineering team has implemented a function to determine access level based on user role.

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
#include <stdbool.h>

typedef enum {
	ROLE_GUEST,
	ROLE_USER,
	ROLE_ADMIN
} UserRole;

bool check_access(UserRole role, const char *resource) {
	if (resource == NULL) {
		return false;
	}
	
	bool can_access = false;

	// No breaks after each switch conditional
	
	switch (role) {
		case ROLE_GUEST:
			if (strcmp(resource, "public") == 0) {
				can_access = true;
			}
		case ROLE_USER:
			if (strcmp(resource, "documents") == 0) {
				can_access = true;
			}
		case ROLE_ADMIN:
			if (strcmp(resource, "settings") == 0) {
				can_access = true;
			}

	}
	
	return can_access;
}

int main() {
	printf("Guest accessing public: %s\n", 
		check_access(ROLE_GUEST, "public") ? "ALLOWED" : "DENIED");
	
	printf("Guest accessing settings: %s\n", 
		check_access(ROLE_GUEST, "settings") ? "ALLOWED" : "DENIED");
	
	printf("User accessing documents: %s\n", 
		check_access(ROLE_USER, "documents") ? "ALLOWED" : "DENIED");
	
	return 0;
}
```

**Expected behavior:**
```
Guest accessing public: ALLOWED
Guest accessing settings: DENIED
User accessing documents: ALLOWED
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `check_access()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `check_access()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

typedef enum {
	ROLE_GUEST,
	ROLE_USER,
	ROLE_ADMIN
} UserRole;

bool check_access(UserRole role, const char *resource) {
	if (resource == NULL) {
		return false;
	}
	
	bool can_access = false;


	// No breaks after each switch conditional
	
	switch (role) {
		case ROLE_GUEST:
			if (strcmp(resource, "public") == 0) {
				can_access = true;
			}

			break;
		case ROLE_USER:
			if (strcmp(resource, "documents") == 0) {
				can_access = true;
			}

			break;
		case ROLE_ADMIN:
			if (strcmp(resource, "settings") == 0) {
				can_access = true;
			}

			break;

		// No check if resource has invalid value

		default:
		{
			can_access = false;

			break;
		}
	}
	
	return can_access;
}

int main() {
	printf("Guest accessing public: %s\n", 
		check_access(ROLE_GUEST, "public") ? "ALLOWED" : "DENIED");
	
	printf("Guest accessing settings: %s\n", 
		check_access(ROLE_GUEST, "settings") ? "ALLOWED" : "DENIED");
	
	printf("User accessing documents: %s\n", 
		check_access(ROLE_USER, "documents") ? "ALLOWED" : "DENIED");
	
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
