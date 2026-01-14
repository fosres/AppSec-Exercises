# Exercise 10: C Security Audit - User Input Parser

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Focus**: scanf buffer overflow + input validation  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a command-line tool. The engineering team has implemented a function to read a username from user input into a fixed-size buffer.

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

#define USERNAME_SIZE 32

int read_username(char *username) {

	// No check if username == NULL
	
	printf("Enter username: ");

	// Buffer Overflow: User input can be equal to or larger than USERNAME_SIZE

	// Which leaves no room for proper NULL-termination


	scanf("%s", username);
	return 0;
}

int main() {
	char user[USERNAME_SIZE];
	
	read_username(user);
	printf("Welcome, %s!\n", user);
	
	return 0;
}
```

**Expected behavior:**
```
Enter username: alice
Welcome, alice!
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `read_username()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `read_username()` function to fix all identified vulnerabilities.

Your implementation should:
- Limit input to buffer size
- Validate all inputs
- Handle edge cases safely
- Prevent buffer overflows

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define USERNAME_SIZE 32

int read_username(char *username) {

	// No check if username == NULL

	if ( username == NULL )
	{
		fprintf(stderr,"Error: username == NULL\n");

		return -1;
	}
	
	printf("Enter username: ");

	// Buffer Overflow: User input can be equal to or larger than USERNAME_SIZE

	// Which leaves no room for proper NULL-termination

	uint8_t c = 0;

	size_t i = 0;

	for (  ; i < USERNAME_SIZE - 1 ; i++ )
	{
		c = fgetc(stdin);

		if ( c == 0x0a )
		{
			break;
		}		
		
		username[i] = c;
	}

	username[i] = 0x00;

//	scanf("%s", username);

	return 0;
}

int main() {
	char user[USERNAME_SIZE];
	
	read_username(user);
	printf("Welcome, %s!\n", user);
	
	return 0;
}
```

---

## Grading Rubric

### Part A: Vulnerability Identification (5 points)
- **2 points**: Identified unbounded scanf("%s") vulnerability
- **1 point**: Explained why scanf has no size limit
- **1 point**: Identified missing NULL pointer validation
- **1 point**: Clear explanation of buffer overflow risk

### Part B: Secure Implementation (10 points)
- **4 points**: Uses scanf with width specifier or safer alternative
- **2 points**: Validates inputs (NULL checks, return value checks)
- **2 points**: Handles edge cases (long input, whitespace)
- **1 point**: Clears input buffer after overflow
- **1 point**: Code compiles and functions correctly

---

## Expected Knowledge

Candidates should understand:
- scanf format string specifiers
- Buffer size limits for user input
- Input validation patterns
- Safe alternatives to scanf

---

## Hints

Consider these questions:
- What happens if the user types more than 32 characters?
- Does scanf("%s") check the buffer size?
- What if username is NULL?
- How do you limit scanf to read at most N characters?

**Critical scanf behavior:**
```c
char buf[10];
scanf("%s", buf);  // NO SIZE CHECKING!
// User types: "HelloWorld12345"
// scanf writes 15+ bytes into 10-byte buffer
// BUFFER OVERFLOW!
```

---

## Key Bugs

### Bug #1: Unbounded scanf

```c
char username[USERNAME_SIZE];  // 32 bytes
scanf("%s", username);
//    ^^
//    NO SIZE LIMIT!
```

**The bug:**
```c
// User input: "ThisIsAVeryLongUsernameThatExceeds32Characters"
// scanf copies ALL characters into 32-byte buffer
// Writes 48 bytes into 32-byte buffer
// BUFFER OVERFLOW!
```

**Example:**
```
Enter username: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                ^45 'A' characters
Writes to: username[0..44]
But buffer is only: username[0..31]
Overflow: 13 bytes past buffer end!
```

### Bug #2: No NULL Validation

```c
int read_username(char *username) {
    // What if username is NULL?
    scanf("%s", username);  // Crash!
}
```

### Bug #3: No Return Value Check

```c
scanf("%s", username);
// What if scanf fails? (EOF, input error)
// What if user types whitespace or nothing?
```

---

## Time Allocation

- **5 minutes**: Identify the scanf bug
- **10 minutes**: Write secure implementation
- **5 minutes**: Test edge cases mentally

---

## Critical Insight: scanf Format Specifiers

**The dangerous way (no limit):**
```c
scanf("%s", buffer);  // Reads unlimited characters!
```

**The safe way (with width limit):**
```c
char buf[32];
scanf("%31s", buf);  // Reads at most 31 chars + '\0'
//     ^^
//     Width specifier = buffer_size - 1
```

**Key points:**
- `%s` has NO size checking - reads until whitespace
- `%31s` limits to 31 characters (leaving room for '\0')
- Always use: `scanf("%[N-1]s", ...)` where N is buffer size

---

## Even Better: Use fgets Instead

**scanf has many problems:**
- Hard to handle whitespace
- Hard to clear overflow input
- Easy to misuse

**Better alternative:**
```c
char buf[32];
if (fgets(buf, sizeof(buf), stdin) != NULL) {
    // Remove newline
    buf[strcspn(buf, "\n")] = '\0';
    // Use buf...
}
```

**Why fgets is better:**
- Takes buffer size as parameter (explicit bounds)
- Includes newline in result (you can detect overflow)
- Returns NULL on error (easier error handling)

---

## References

**Primary Sources**:
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-676: Use of Potentially Dangerous Function (scanf)
- CERT C Coding Standard: INT05-C (Do not use input functions to convert character data if they cannot handle all possible inputs)
- *Secure by Design*, Chapter 6 - Safe input handling

**Additional Reading:**
- "scanf() Considered Harmful" - Security community consensus
- Modern C guidelines recommend fgets over scanf for strings

---

*This exercise tests understanding of scanf's dangerous behavior - one of the most common sources of buffer overflows in C code.*
