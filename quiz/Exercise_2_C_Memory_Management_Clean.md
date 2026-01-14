# Exercise 2: C Memory Management Code Review

**Curriculum Alignment**: Week 4 - Linux Internals, Common Linux Attacks  
**Source**: *API Security in Action*, Chapter 2, pp. 47-49 (Memory safety vulnerabilities)  
**Additional Reference**: CWE-416 (Use After Free), CWE-401 (Memory Leak)

**Difficulty**: Week 4 Level  
**Points**: 15 total  
**Estimated Time**: 20 minutes

---

## Scenario

You are reviewing a configuration parser for a web server. The engineering team built a function to read and validate API keys from a configuration file.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
	char *key;
	int is_valid;
} ApiKey;

ApiKey *load_api_key(const char *filename) {
	
	// No check if filename is NULL pointer. This can cause

	// dereference of NULL pointer.

	// NO check if fopen() was successful. fopen() can return NULL
	// upon failure. This can cause dereferene of NULL pointer.
	
	FILE *fp = fopen(filename, "r");

	char buffer[256];

	// No check if malloc() was successful. This can also
	// cause dereference of NULL pointer
	
	ApiKey *api_key = (ApiKey *) malloc(sizeof(ApiKey));
	api_key->is_valid = 0;

	// Coder failed to strip newline character from buffer
	// after fgets() is called!

	if (fgets(buffer, sizeof(buffer), fp) != NULL) {

		// Its best to use strnlen() below
	
		size_t len = strlen(buffer);
		
		// Off-by-One: No room for terminating NULL byte

		// Also no check if api_key->key is NOT NULL

		// after use of malloc(). This can lead to dereference

		// of NULL pointer.

		api_key->key = (char *) malloc(len);

		// Insecure string copy function `strcpy()` below. API key

		// is only up to 255 bytes in length.

		// Also api_key is not NULL-terminated

		strcpy(api_key->key, buffer);

		api_key->is_valid = 1;
	}
	
	fclose(fp);

	return api_key;
}

void cleanup(ApiKey *api_key) {
	free(api_key->key);
	free(api_key);
}

int main() {
	
	// No check if key below is NOT NULL. This can lead to dereference

	// of NULL pointer.

	ApiKey *key = load_api_key("/etc/api.key");
	
	if (key->is_valid) {
		printf("API Key: %s\n", key->key);
	}
	
	cleanup(key); // Use-after-freeing key
	
	// Later in the program...
	if (key->is_valid) {  // Check if still valid
		printf("Using key: %s\n", key->key);
	}
	
	return 0;
}
```

---

## Questions

### **2a. Vulnerability Identification** (5 points)

Identify ALL vulnerabilities present in this code. For each vulnerability:
- Name the vulnerability class (use CWE numbers if you know them)
- Explain the root cause
- Describe potential impact

Please see comments in the above code.

---

### **2c. Mitigations** (10 points)

Propose secure alternatives for this code. Address:
- File handle error checking
- Memory allocation strategy  
- Resource cleanup
- Use-after-free prevention

**Your rewritten code should:**
- Check that `fopen()` succeeded before using the file handle
- Allocate correct amount of memory for strings (including null terminator)
- Handle the newline character from `fgets()`
- Clean up resources properly in all code paths
- Prevent use-after-free by setting pointers to NULL after freeing

Write your complete secure implementation below:

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
	char *key;
	int is_valid;
} ApiKey;

ApiKey *load_api_key(const char *filename) {

	if ( filename == NULL )
	{
		fprintf(stderr,"Error: filename is NULL\n");

		return NULL;
	}
	

	FILE *fp = NULL;

	if ( ( fp = fopen(filename, "r") ) == NULL )
	{
		fprintf(stderr,"Error: fp is NULL\n");

		return NULL;
	}

	char buffer[256];

	// For safety against failure of NULL termination

	// I will do the following:

	for ( size_t i = 0; i < 256 ; i++ )
	{
		buffer[i] = 0x00;
	}

	ApiKey *api_key = (ApiKey *) calloc(1,sizeof(ApiKey));

	if ( api_key == NULL )
	{
		fprintf(stderr,"Error: api_key is NULL\n");

		fclose(fp);

		return NULL;
	}

	api_key->is_valid = 0;

	if (fgets(buffer, sizeof(buffer), fp) != NULL) {
	
		size_t len = strnlen(buffer,255);

		if (len > 0 && buffer[len-1] == '\n') {
			
			buffer[len-1] = '\0';

			len--;
	
		}

		api_key->key = (char *) calloc(len+1,sizeof(char));

		if ( api_key->key == NULL )
		{
			fprintf(stderr,"Error: api_key->key == NULL\n");

			fclose(fp);

			free(api_key);

			return NULL;
		}

		// Insecure string copy function below. API key

		// is only up to 255 bytes in length.

		// Also api_key is not NULL-terminated

		strncpy(api_key->key, buffer,len);

		api_key->is_valid = 1;
	}
	
	fclose(fp);

	return api_key;
}

void cleanup(ApiKey *api_key) {
	free(api_key->key);
	free(api_key);
}

int main() {
	ApiKey *key = load_api_key("/etc/api.key");

	if ( key == NULL )
	{
		fprintf(stderr,"Error: key == NULL\n");

		return 1;	
	}
	
	if (key->is_valid) {
		printf("API Key: %s\n", key->key);
	}
	
	// Later in the program...
	if (key->is_valid) {  // Check if still valid
		printf("Using key: %s\n", key->key);
	}
	
	cleanup(key);

	return 0;
}
```

---

## Expected Knowledge

By Week 4, you should understand:
- File I/O error handling
- NULL pointer dereference from failed system calls
- Off-by-one errors in string handling (*API Security in Action*, p. 48)
- Use-after-free vulnerabilities (CWE-416)
- Memory leaks from missing cleanup
- Proper resource cleanup patterns (RAII-style in C)

---

## Grading Rubric

### 2a. Vulnerability Identification (5 points)
- **1 point**: Identified NULL pointer dereference from unchecked `fopen()`
- **1 point**: Identified off-by-one error in string allocation
- **1 point**: Identified use-after-free in main() after cleanup()
- **1 point**: Identified newline character handling issue from `fgets()`
- **1 point**: Clearly explained root causes and impacts

### 2c. Mitigations (10 points)
- **2 points**: Checks `fopen()` return value before use
- **2 points**: Allocates correct size (len+1 or handles newline properly)
- **2 points**: Strips newline character from `fgets()` buffer
- **2 points**: Sets pointers to NULL after freeing (prevents use-after-free)
- **2 points**: Code is clean, compiles, and handles all edge cases

---

## References

**Primary Sources**:
- *API Security in Action* by Neil Madden, Chapter 2, pp. 47-49
- CWE-416: Use After Free (https://cwe.mitre.org/data/definitions/416.html)
- CWE-476: NULL Pointer Dereference
- CWE-193: Off-by-one Error
- CWE-401: Missing Release of Memory after Effective Lifetime

**Additional Reading**:
- *Secure by Design*, Chapter 6 - Resource management patterns
- CERT C Coding Standard: MEM30-C (Do not access freed memory)
- CERT C Coding Standard: FIO04-C (Detect and handle input and output errors)

---

*This exercise tests your ability to identify memory management vulnerabilities including use-after-free, resource leaks, and proper cleanup patterns in C.*
