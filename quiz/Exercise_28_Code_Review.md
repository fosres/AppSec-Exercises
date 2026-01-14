# Exercise 28: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a user management system. The engineering team has implemented a function to get a user's full name.

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
	char *first_name;
	char *last_name;
	int age;
} User;

User *find_user(const char *username) {

	// No check if username == NULL

	if (strcmp(username, "john") == 0) {

		// No check if u == NULL after below calloc()

		User *u = calloc(1, sizeof(User));

		// Must first calloc() first_name and last_name

		u->first_name = "John";
		u->last_name = "Doe";
		u->age = 30;
		return u;
	}
	
	return NULL;
}

void print_user_info(const char *username) {
	
	// No check if find_user() returns NULL

	User *user = find_user(username);

	// No check if user->first_name == NULL
	
	// No check if user->last_name == NULL

	printf("Name: %s %s, Age: %d\n", 
		user->first_name, 
		user->last_name, 
		user->age);

	// Have to free user->first_name first	
	// Have to free user->last_name next
 
	free(user);
}

int main() {
	print_user_info("john");
	print_user_info("alice");
	
	return 0;
}
```

**Expected behavior:**
```
Name: John Doe, Age: 30
Name: (unknown user)
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
	char *first_name;
	char *last_name;
	int age;
} User;

User *find_user(const char *username) {
	
	// No check if username == NULL

	if ( username == NULL )
	{
		return NULL;
	}

	if (strcmp(username, "john") == 0) {
		
		// No check if u == NULL after below calloc()

		User *u = calloc(1, sizeof(User));

		if ( u == NULL )
		{
			return NULL;
		}

		// Must first calloc() first_name and last_name

		u->first_name = (char*)calloc(5,sizeof(char));

		if ( u->first_name == NULL )
		{
			free(u);

			return NULL;
		}

		snprintf(u->first_name,5*sizeof(char),"%s","John");
		
		u->last_name = (char*)calloc(4,sizeof(char));

		if ( u->last_name == NULL )
		{
			free(u->first_name);

			free(u);

			return NULL;
		}
		
		snprintf(u->last_name,4*sizeof(char),"%s","Doe");

		u->age = 30;

		return u;
	}
	
	return NULL;
}

void print_user_info(const char *username) {
	
	// No check if find_user() returns NULL

	User *user = find_user(username);

	if ( user == NULL )
	{
		return;
	}

	printf("Name: %s %s, Age: %d\n", 
		user->first_name, 
		user->last_name, 
		user->age);

	// Have to free user->first_name first	
	// Have to free user->last_name next

	free(user->first_name);

	free(user->last_name);
 
	free(user);
}

int main() {
	print_user_info("john");
	print_user_info("alice");
	
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
