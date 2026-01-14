# Exercise 27: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for an authentication system. The engineering team has implemented a function to validate user permissions.

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

bool check_permission(const char *username, const char *required_role) {
	if (username == NULL || required_role == NULL) {
		return false;
	}
	
	char *user_role = NULL;

	// supposed to be == 0	
	if (strcmp(username, "admin") = 0) {
		user_role = "admin";
	
	// supposed to be == 0	
	} else if (strcmp(username, "user") = 0) {
		user_role = "user";
	} else {
		user_role = "guest";
	}
	
	if (strcmp(user_role, required_role) == 0) {
		return true;
	}
	
	return false;
}

int main() {
	if (check_permission("admin", "admin")) {
		printf("Access granted\n");
	} else {
		printf("Access denied\n");
	}
	
	return 0;
}
```

**Expected behavior:**
```
Access granted
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `check_permission()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `check_permission()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

bool check_permission(const char *username, const char *required_role) {
	if (username == NULL || required_role == NULL) {
		return false;
	}
	
	char *user_role = NULL;

	// supposed to be == 0	
	if (strcmp(username, "admin") == 0) {
		user_role = "admin";
	
	// supposed to be == 0	
	} else if (strcmp(username, "user") == 0) {
		user_role = "user";
	} else {
		user_role = "guest";
	}
	
	if (strcmp(user_role, required_role) == 0) {
		return true;
	}
	
	return false;
}

int main() {
	if (check_permission("admin", "admin")) {
		printf("Access granted\n");
	} else {
		printf("Access denied\n");
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
