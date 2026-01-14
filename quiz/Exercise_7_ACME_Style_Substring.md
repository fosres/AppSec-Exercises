# Exercise 7: C Security Audit - Substring Extraction

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Focus**: Buffer bounds + String logic  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a text processing library. The engineering team has implemented a function to extract a substring from a source string given start and end positions.

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

char *extract_substring(const char *source, int start, int end) {
	/*
		No check if source is a NULL pointer.

		Integer Overflow/Underflow Vulnerability:

		Depending on signedness of `start` and `end` the 

		below calcualation of length either results in

		a negative number as the correct difference (which

		is nonsensical for a length calculation) or

		a result of integer overflow/underflow.

		There is no check if end <= strlen(source)

		There is also no check if end > start and that both

		are positive integers.

		Never use a signed integer for counting objects.

		Use an unsigned data type such as `size_t` instead.
	*/
	
	int length = end - start;

	// Off-By-One: No gurantee of sufficient space for

	// NULL-termination below in malloc() calculation

	// Also failure to check if malloc() returns NULL
	
	char *result = (char *) malloc(length);

	// What if length below is negative?	

	for (int i = 0; i < length; i++) {
		result[i] = source[start + i];
	}
	
	return result;
}

int main() {
	const char *text = "Hello, World!";
	
	// Extract "World" (positions 7-12)

	// No check if extract_substring() returns a NULL string

	char *substring = extract_substring(text, 7, 12);
	printf("Substring: %s\n", substring);
	
	free(substring);
	return 0;
}
```

**Expected behavior:**
```
Input: "Hello, World!" with start=7, end=12
Output: "World"
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `extract_substring()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `extract_substring()` function to fix all identified vulnerabilities.

Your implementation should:
- Allocate the correct amount of memory
- Validate all inputs properly
- Handle edge cases safely
- Check for allocation failures

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *extract_substring(const char *source, size_t start, size_t end) {
	
	/*
		Integer Overflow/Underflow Vulnerability:

		Depending on signedness of `start` and `end` the 

		below calcualation of length either results in

		a negative number as the correct difference (which

		is nonsensical for a length calculation) or

		a result of integer overflow/underflow.

		There is also no check if both `end` and `start`

		are positive and end > start.

		Never use a signed integer for counting objects.

		Use an unsigned data type such as `size_t` instead.
	*/

	if ( source == NULL )
	{
		fprintf(stderr,"Error: source == NULL\n");

		return NULL;
	}

	if ( end <= start )
	{
		fprintf(stderr,"Error: end <= start\n");

		return NULL;
	}
	
	if ( end > strlen(source) )
	{
		fprintf(stderr,"Error: end > strlen(source)\n");

		return NULL;
	}
	
	size_t length = end - start;

	// Off-By-One: No gurantee of sufficient space for

	// NULL-termination below in malloc() calculation

	// Also failure to check if malloc() returns NULL
	
	char *result = (char *) calloc(length+1,sizeof(char));

	if ( result == NULL )
	{
		fprintf(stderr,"Error: allocation of result failed!\n");

		return NULL;
	}

	// What if length below is negative?	

	memcpy(result,source + start,length);

	return result;
}

int main() {
	const char *text = "Hello, World!";
	
	// Extract "World" (positions 7-12)
	
	// No check if extract_substring() returns a NULL string

	char *substring = extract_substring(text, 7, 12);

	if ( substring == NULL )
	{
		fprintf(stderr,"Error: extract_substring() returns NULL\n");

		return 1;
	}
	
	printf("Substring: %s\n", substring);
	
	free(substring);

	return 0;
}
```

---

## Grading Rubric

### Part A: Vulnerability Identification (5 points)
- **1 point**: Identified missing null terminator
- **1 point**: Identified missing bounds validation (start/end vs source length)
- **1 point**: Identified missing malloc validation
- **1 point**: Identified potential negative length from bad start/end
- **1 point**: Clear explanation of security impacts

### Part B: Secure Implementation (10 points)
- **3 points**: Validates start/end against source string length
- **2 points**: Allocates correct size (length + 1 for null terminator)
- **2 points**: Null-terminates the result string
- **2 points**: Validates inputs (NULL source, malloc failure, negative length)
- **1 point**: Code compiles and handles edge cases

---

## Expected Knowledge

Candidates should understand:
- Buffer bounds validation
- String null termination
- Array indexing and boundaries
- Input validation for position parameters
- Defensive programming

---

## Hints

Consider these edge cases:
- What if `start` is negative?
- What if `end` is larger than the source string length?
- What if `start > end`?
- What happens to the result string - is it null-terminated?
- How much memory should be allocated?

**Example attack scenarios:**
```c
extract_substring("test", -5, 10);   // Negative start
extract_substring("test", 0, 100);   // end beyond string
extract_substring("test", 10, 5);    // start > end
extract_substring(NULL, 0, 5);       // NULL source
```

---

## Key Bugs

### Bug #1: Missing Null Terminator
```c
char *result = malloc(length);  // Allocates exactly 'length' bytes
for (int i = 0; i < length; i++) {
	result[i] = source[start + i];
}
return result;  // ❌ result is NOT null-terminated!
```

**When printed:**
```c
printf("%s", result);  // Reads past the allocated buffer!
```

### Bug #2: No Bounds Checking
```c
extract_substring("test", 0, 100);
// length = 100
// But source only has 4 characters!
// Reads source[4], source[5], ... source[99] → Buffer over-read!
```

### Bug #3: No Input Validation
```c
extract_substring("test", 10, 5);
// length = 5 - 10 = -5 (negative!)
// malloc(-5) → Undefined behavior or huge allocation
```

---

## Time Allocation

- **5 minutes**: Identify all vulnerabilities
- **10 minutes**: Write secure implementation
- **5 minutes**: Test edge cases mentally

---

## References

**Primary Sources**:
- CWE-170: Improper Null Termination
- CWE-125: Out-of-bounds Read
- CWE-190: Integer Overflow (negative length)
- CWE-787: Out-of-bounds Write
- CERT C Coding Standard: STR32-C (Null-terminate strings)

---

*This exercise tests buffer bounds validation and string handling logic - essential for security engineering.*
