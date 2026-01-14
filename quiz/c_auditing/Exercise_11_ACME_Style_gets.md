# Exercise 11: C Security Audit - Password Input Reader

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Focus**: gets() buffer overflow - The most dangerous C function  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a legacy authentication system. The engineering team has implemented a function to read a password from user input into a fixed-size buffer.

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

#define PASSWORD_SIZE 64

int read_password(char *password) {
	
	// No check if password == NULL
	
	printf("Enter password: ");
	
	// gets() will read more characters than PASSWORD_SIZE - 1 
	// until newline or EOF	

	// Also there is no attempt to NULL-terminate password after

	// calling gets()
	gets(password);
	return 0;
}

int main() {
	char pass[PASSWORD_SIZE];
	
	read_password(pass);
	printf("Password length: %zu\n", strlen(pass));
	
	return 0;
}
```

**Expected behavior:**
```
Enter password: secret123
Password length: 9
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `read_password()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `read_password()` function to fix all identified vulnerabilities.

Your implementation should:
- Use a safe alternative to gets()
- Validate all inputs
- Handle edge cases safely
- Prevent buffer overflows

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PASSWORD_SIZE 64

int read_password(char *password) {
	
	// No check if password == NULL

	if ( password == NULL )
	{
		fprintf(stderr,"Error: password == NULL\n");

		return 1;
	}
	
	printf("Enter password: ");
	
	// gets() will read more characters than PASSWORD_SIZE - 1 
	// until newline or EOF	

	// Also there is no attempt to NULL-terminate password after

	// calling gets()

	size_t i = 0;

	int c = 0;

	for ( ; i < PASSWORD_SIZE - 1 ; i++ )
	{
		c = fgetc(stdin);

		if ( c == '\n' || c == EOF )
		{
			break;
		}	
		
		password[i] = c;
	}

	password[i] = 0x00;
	
	return 0;
}

int main() {
	char pass[PASSWORD_SIZE];
	
	read_password(pass);
	printf("Password length: %zu\n", strlen(pass));
	
	return 0;
}
```

---

## Grading Rubric

### Part A: Vulnerability Identification (5 points)
- **3 points**: Identified gets() as completely unsafe
- **1 point**: Explained why gets() has no bounds checking
- **1 point**: Mentioned gets() is removed from C11 standard

### Part B: Secure Implementation (10 points)
- **5 points**: Uses safe alternative (fgets, getline, or custom implementation)
- **2 points**: Validates inputs (NULL checks)
- **2 points**: Handles newline character correctly
- **1 point**: Code compiles and functions correctly

---

## Expected Knowledge

Candidates should understand:
- Why gets() is dangerous
- Safe alternatives to gets()
- Input validation best practices
- Historical context of gets() vulnerabilities

---

## Hints

Consider these questions:
- What happens if the user types more than 64 characters?
- Does gets() have ANY size checking?
- Why was gets() removed from C11?
- What is a safe replacement for gets()?

**Critical gets() fact:**
```c
char buf[64];
gets(buf);  // ABSOLUTELY NO SIZE CHECKING!
// User can type 1000 characters
// gets() writes ALL of them into 64-byte buffer
// MASSIVE BUFFER OVERFLOW!
```

---

## Key Bugs

### Bug #1: gets() is Fundamentally Unsafe

```c
char password[PASSWORD_SIZE];  // 64 bytes
gets(password);
//   ^^^^^^^^
//   IMPOSSIBLE TO USE SAFELY!
```

**The problem:**
```c
// gets() has this signature:
char *gets(char *str);

// NO SIZE PARAMETER!
// Cannot possibly know buffer size
// Reads until newline, regardless of buffer size
// ALWAYS vulnerable to buffer overflow
```

**Example:**
```
Enter password: AAAA... (1000 'A' characters)

gets() writes ALL 1000 characters into 64-byte buffer
Overflow: 936 bytes past buffer end!
Stack corruption, return address overwrite, arbitrary code execution!
```

### Bug #2: Historical Context

**gets() is so dangerous that:**
- Removed from C11 standard (2011)
- Most compilers warn or error on gets()
- CERT C: "Never use gets()"
- CWE-242: "Use of Inherently Dangerous Function"

**Morris Worm (1988):**
- First major Internet worm
- Exploited gets() overflow in fingerd
- Infected 10% of Internet
- gets() has been known dangerous for 35+ years!

---

## Time Allocation

- **5 minutes**: Identify gets() as dangerous
- **10 minutes**: Write secure implementation
- **5 minutes**: Consider alternatives

---

## Safe Alternatives to gets()

### **Option 1: fgets() (Recommended)**
```c
char buf[64];
if (fgets(buf, sizeof(buf), stdin) != NULL) {
    // Remove newline
    buf[strcspn(buf, "\n")] = '\0';
}
```

**Advantages:**
- Takes size parameter (explicit bounds)
- Standard library function
- Well-tested and reliable

### **Option 2: getline() (POSIX)**
```c
char *line = NULL;
size_t len = 0;
if (getline(&line, &len, stdin) != -1) {
    // Use line...
    free(line);
}
```

**Advantages:**
- Dynamically allocates memory
- Never overflows
- POSIX standard

### **Option 3: Custom implementation**
```c
int read_line(char *buf, size_t size) {
    int c, i = 0;
    while (i < size - 1 && (c = getchar()) != '\n' && c != EOF) {
        buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}
```

---

## Why gets() Cannot Be Fixed

**Some might suggest:**
```c
// "Just check the length first!"
// But there's NO WAY to check!
```

**gets() fundamentally cannot be used safely because:**
1. No size parameter - impossible to tell it the buffer size
2. No return value indicating overflow
3. No way to limit input before reading
4. Reads entire line regardless of buffer size

**This is why it was REMOVED from the C standard!**

---

## Compiler Warnings

**Modern compilers warn about gets():**
```
warning: the `gets' function is dangerous and should not be used.
```

**Some compilers (like gcc with glibc) replace gets() with a stub that aborts:**
```c
// In modern glibc:
char *gets(char *s) {
    abort();  // Immediately terminates program!
}
```

---

## References

**Primary Sources**:
- CWE-242: Use of Inherently Dangerous Function
- CWE-120: Buffer Copy without Checking Size of Input
- CERT C Coding Standard: STR31-C (Guarantee strings are null-terminated)
- C11 Standard: gets() removed, use fgets() instead

**Historical:**
- Morris Worm (1988) - First use of gets() exploit
- CERT Advisory CA-1988-01 - fingerd gets() overflow
- Countless exploits over 35 years

**Additional Reading:**
- "gets() is Dangerous" - Every C security guide
- ISO C11 Rationale - Why gets() was removed

---

*This exercise tests understanding of gets() - the single most dangerous function in C history.*
