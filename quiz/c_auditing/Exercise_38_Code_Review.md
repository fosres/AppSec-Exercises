# Exercise 38: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a configuration management system. The engineering team has implemented functions to load and update configuration settings.

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
	char *value;
} ConfigEntry;

ConfigEntry *create_config(const char *name, const char *value) {
	if (name == NULL || value == NULL) {
		return NULL;
	}

		
	ConfigEntry *entry = malloc(sizeof(ConfigEntry));
	if (entry == NULL) {
		return NULL;
	}

	// No check if either strdup() returns NULL below
	
	entry->name = strdup(name);
	entry->value = strdup(value);
	
	return entry;
}

// No attempt at error-handling for below function
int update_config(ConfigEntry *entry, const char *new_value) {
	if (entry == NULL || new_value == NULL) {
		return 1;
	}
	
	// No check if entry->value == NULL first before doing below

	free(entry->value);

	// No check if strdup() returns NULL

	entry->value = strdup(new_value);

	return 0;
}

void free_config(ConfigEntry *entry) {
	if (entry == NULL) {
		return;
	}

	// No attempt to check if any of the fields below point to NULL	

	// before attempting to free
	free(entry->name);
	free(entry->value);
	free(entry);
}

int main() {

	// No attempt to check if create_config returned NULL

	ConfigEntry *config = create_config("hostname", "localhost");
	
	printf("Initial: %s = %s\n", config->name, config->value);
	
	update_config(config, "server.example.com");
	
	printf("Updated: %s = %s\n", config->name, config->value);
	
	free_config(config);
	
	return 0;
}
```

**Expected behavior:**
```
Initial: hostname = localhost
Updated: hostname = server.example.com
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
	char *value;
} ConfigEntry;

ConfigEntry *create_config(const char *name, const char *value) {
	if (name == NULL || value == NULL) {
		return NULL;
	}
		
	ConfigEntry *entry = malloc(sizeof(ConfigEntry));
	if (entry == NULL) {
		return NULL;
	}

	// No check if either strdup() returns NULL below
	
	entry->name = strdup(name);

	if ( entry->name == NULL )
	{
		free(entry);

		return NULL;
	}

	entry->value = strdup(value);

	if ( entry->value == NULL )
	{
		free(entry->name);

		free(entry);

		return NULL;
	}
	
	return entry;
}

// No attempt at error-handling for below function
int update_config(ConfigEntry *entry, const char *new_value) {

	if (entry == NULL || new_value == NULL) {
		return 1;
	}
	
	// No check if entry->value == NULL first before doing below

	if ( entry->value != NULL )
	{	
		free(entry->value);
	}

	// No check if strdup() returns NULL

	entry->value = strdup(new_value);

	if ( entry->value == NULL )
	{
		return 1;
	}

	return 0;
}

void free_config(ConfigEntry *entry) {
	if (entry == NULL) {
		return;
	}
	
	// No attempt to check if any of the fields below point to NULL	

	// before attempting to free

	if ( entry->name != NULL )	
	{
		free(entry->name);
	}

	if ( entry->value != NULL )
	{
		free(entry->value);
	}

	free(entry);
}

int main() {

	// No attempt to check if create_config returned NULL

	ConfigEntry *config = create_config("hostname", "localhost");

	if ( config == NULL )
	{
		return 1;
	}
	
	printf("Initial: %s = %s\n", config->name, config->value);
	
	if ( update_config(config, "server.example.com") != 0 )
	{
		return 1;
	}
	
	printf("Updated: %s = %s\n", config->name, config->value);
	
	free_config(config);
	
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
