# Exercise 34: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a configuration parser. The engineering team has implemented a function to safely copy configuration values into a fixed-size buffer.

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
	char hostname[32];
	int port;
} Config;

void set_hostname(Config *config, const char *hostname) {
	if (config == NULL || hostname == NULL) {
		return;
	}

	// Possible Buffer Overflow: hostname may be shorter than

	// the 32 bytes required

	// No guarantee terminating NULL-byte set after copying.

	// strncpy will only copy up to terminating NULL-byte

	// in source string

	// or until the requested number of bytes is copied
	
	strncpy(config->hostname, hostname, sizeof(config->hostname));
}

int main() {
	Config config;
	config.port = 8080;
	
	set_hostname(&config, "server.example.com");
	
	printf("Hostname: %s\n", config.hostname);
	printf("Port: %d\n", config.port);
	
	return 0;
}
```

**Expected behavior:**
```
Hostname: server.example.com
Port: 8080
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
	char hostname[32];
	int port;
} Config;

void set_hostname(Config *config, const char *hostname) {
	if (config == NULL || hostname == NULL) {
		return;
	}

	// Possible Buffer Overflow: hostname may be shorter than

	// the 32 bytes required
	
	// No guarantee terminating NULL-byte set after copying.

	// strncpy will only copy up to terminating NULL-byte

	// in source string

	// or until the requested number of bytes is copied

	snprintf(config->hostname,32*sizeof(char),"%s",hostname);
	
	//strncpy(config->hostname, hostname, sizeof(config->hostname));
}

int main() {
	Config config;
	config.port = 8080;
	
	set_hostname(&config, "server.example.com");
	
	printf("Hostname: %s\n", config.hostname);
	printf("Port: %d\n", config.port);
	
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
