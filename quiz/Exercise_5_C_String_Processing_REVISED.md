# Exercise 5: C Language Security Audit - String Processing

**Curriculum Alignment**: Week 4 - Linux Internals, Common Linux Attacks  
**Source**: *Secure by Design*, Chapter 6 (Safe string handling)  
**Focus**: Pure C language vulnerabilities - Simple procedural code

**Difficulty**: Week 4 Level  
**Points**: 15 total  
**Estimated Time**: 20 minutes

---

## Scenario

You are reviewing string processing functions used in a log parser. The code manipulates strings and buffers.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// The below function attempts to get rid of leading and trailing

// whitespace characters

char *trim_whitespace(char *str) {

	// No check if str is a NULL pointer at the beginning
	
	// What if we already hit NULL byte in str while iterating below? 

	// Incomplete logic. Should check if char is whitespace

	// using isspace()

	while (*str == ' ' || *str == '\t') {
		str++;
	}
	
	size_t len = strlen(str);

	// Integer Underflow Vulnerability Below: len can underflow

	// The integer overflow can happen if the entire string

	// consists of whitespace characters.
	
	// Incomplete logic. Should check if char is whitespace

	// using isspace()

	while (len > 0 && (str[len] == ' ' || str[len] == '\t')) {
		str[len] = '\0';
		len--;
	}
	
	return str;
}

void copy_until_delimiter(char *dest, char *src, char delim, size_t dest_size) {
	size_t i = 0;

	// Can exceed capacity of dest array below

	// Assumes src_size <= dest_size -- not necessarily true
	
	while (src[i] != delim && src[i] != '\0') {
		dest[i] = src[i];
		i++;
	}
	
	dest[i] = '\0';
}

// Below function meant to copy everything after delimiter

char *extract_value(char *line) {

	// No check if colon is NOT present in line

	char *colon = strchr(line, ':');
	
	size_t value_len = strlen(colon + 1);

	// No check if malloc() below successful

	// Off-by-One error below

	char *value = (char *) malloc(value_len);

	// strcpy() dangerous!

	strcpy(value, colon + 1);
	
	return value;
}

int main() {
	char log_line[] = "timestamp:2024-01-15 10:30:00";
	
	char *trimmed = trim_whitespace(log_line);
	printf("Trimmed: %s\n", trimmed);
	
	char buffer[20];
	copy_until_delimiter(buffer, log_line, ':', sizeof(buffer));
	printf("Key: %s\n", buffer);

	// No check if extract_value() returned NULL below	
	char *value = extract_value(log_line);
	printf("Value: %s\n", value);
	free(value);
	
	return 0;
}
```

---

## Questions

### **5a. Vulnerability Identification** (5 points)

Identify ALL vulnerabilities present in this code. For each vulnerability:
- Name the vulnerability class (use CWE numbers if you know them)
- Explain the root cause
- Describe potential impact

**Focus on C language issues:**
- Buffer overflows
- Off-by-one errors
- Missing bounds checks
- Incorrect pointer usage
- Memory allocation errors

---

### **5c. Mitigations** (10 points)

Propose secure alternatives for this code. Address:
- Buffer bounds validation
- String null termination
- Memory allocation sizing
- Pointer validation

**Your rewritten code should:**
- Check buffer bounds before writing
- Validate pointers before dereferencing
- Allocate correct memory sizes
- Handle edge cases safely

Write your complete secure implementation below:

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// The below function attempts to get rid of leading and trailing

// whitespace characters


char *trim_whitespace(char *str) {
	
	if ( str == NULL )
	{
		fprintf(stderr,"Error: str == NULL\n");

		return NULL;
	}

	char *strfront = str;

	size_t slen = strlen(str);

	if ( slen == 0 )
	{
		return str;
	}

	char * strend = str + slen;

	strend--; // skip back from terminating NULL-byte

	for ( ; (strfront < strend) && (isspace(*strfront) || isspace(*strend) ) ; )
	{
		if ( isspace(*strfront) )
		{
			strfront++;
		}

		if ( isspace(*strend) )
		{
			strend--;
		}
	}

	if ( strfront == strend && isspace(*strfront) )
	{
		return NULL;
	}

	*(strend + 1) = 0x00;

	return strfront;
}


void copy_until_delimiter(char *dest, char *src, char delim, size_t dest_size) {
	size_t i = 0;

	// Can exceed capacity of dest array below

	// Assumes src_size <= dest_size -- not necessarily true

	size_t slen = strlen(src);

	if ( slen >= dest_size )
	{
		fprintf(stderr,"Error: src string too long!\n");

		return;
	}

	for ( size_t i = 0; i < slen || src[i] == delim ; i++ )
	{
		dest[i] = src[i];
	}

	dest[slen] = 0x00;
	
}

// Below function meant to copy everything after delimiter

char *extract_value(char *line) {

	// No check if colon is NOT present in line

	char *colon = strchr(line, ':');

	if ( colon == NULL )
	{
		fprintf(stderr,"Error: colon NOT found\n");

		return NULL;
	}
	
	size_t value_len = strlen(colon + 1);

	char *value = (char *) calloc(value_len+1,sizeof(char));

	if ( value == NULL )
	{
		fprintf(stderr,"allocation of value failed!\n");

		return NULL;
	}

	// strcpy() dangerous!

	memcpy(value, colon + 1,value_len);
	
	return value;
}

int main() {
	char log_line[] = "timestamp:2024-01-15 10:30:00";
	
	char *trimmed = trim_whitespace(log_line);
	printf("Trimmed: %s\n", trimmed);
	
	char buffer[20];
	copy_until_delimiter(buffer, log_line, ':', sizeof(buffer));
	printf("Key: %s\n", buffer);
	
	char *value = extract_value(log_line);

	if ( value == NULL )
	{
		fprintf(stderr,"Error: value == NULL\n");
	
		return 1;
	}
	
	printf("Value: %s\n", value);

	free(value);
	
	return 0;
}
```

---

## Expected Knowledge

By Week 4, you should understand:
- Array indexing and bounds
- Off-by-one errors in loops
- String null termination
- Buffer overflow vulnerabilities
- Safe memory allocation sizing
- Pointer validation

---

## Grading Rubric

### 5a. Vulnerability Identification (5 points)
- **1 point**: Identified off-by-one error in trim_whitespace
- **1 point**: Identified buffer overflow in copy_until_delimiter
- **1 point**: Identified off-by-one error in extract_value malloc
- **1 point**: Identified missing null pointer check
- **1 point**: Clearly explained root causes and impacts

### 5c. Mitigations (10 points)
- **3 points**: Fixes off-by-one errors correctly
- **2 points**: Adds bounds checking to copy function
- **2 points**: Fixes memory allocation size
- **2 points**: Validates pointers before use
- **1 point**: Code is clean and compiles

---

## Hints About The Vulnerabilities

This code has **SIMPLE C LANGUAGE BUGS**:

1. **Off-by-one in trim_whitespace**: `str[len]` when `len == strlen(str)`
2. **Buffer overflow in copy_until_delimiter**: No check against `dest_size`
3. **Off-by-one in extract_value**: `malloc(value_len)` missing space for `\0`
4. **Missing null check**: What if `strchr()` returns NULL?

**All straightforward C bugs - no complex patterns!**

---

## Key Bug Details

### Bug #1: Off-by-one in trim_whitespace
```c
size_t len = strlen(str);  // If str = "hi", len = 2
while (len > 0 && str[len] == ' ') {  // str[2] is '\0'!
    // Checking str[len] when len == strlen(str) is WRONG
    // Should be str[len-1]
}
```

### Bug #2: Buffer overflow in copy_until_delimiter
```c
void copy_until_delimiter(char *dest, char *src, char delim, size_t dest_size) {
    size_t i = 0;
    while (src[i] != delim && src[i] != '\0') {
        dest[i] = src[i];  // What if i >= dest_size?
        i++;
    }
}
```

### Bug #3: Off-by-one in extract_value
```c
size_t value_len = strlen(colon + 1);  // If value = "test", len = 4
char *value = (char *) malloc(value_len);  // Allocates 4 bytes
strcpy(value, colon + 1);  // Copies 5 bytes (t-e-s-t-\0)
// OFF-BY-ONE!
```

---

## References

**Primary Sources**:
- *Secure by Design*, Chapter 6 - Buffer handling
- CWE-193: Off-by-one Error
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-131: Incorrect Calculation of Buffer Size
- CWE-476: NULL Pointer Dereference

**Additional Reading**:
- CERT C Coding Standard: STR31-C (Buffer size for strings)
- CERT C Coding Standard: ARR30-C (Array indexing)
- *API Security in Action*, Chapter 2, pp. 47-49

---

*This exercise tests basic C string handling and buffer management - simple procedural code only.*
