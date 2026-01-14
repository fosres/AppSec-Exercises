# Exercise 1B: C Memory Safety Code Review - Integer Overflow

**Curriculum Alignment**: Week 4 - Linux Internals, Common Linux Attacks  
**Source**: *API Security in Action*, Chapter 2, pp. 47-49 (Integer Overflow, Buffer Overflow)  
**Additional Reference**: CWE-190 (Integer Overflow or Wraparound)

**Difficulty**: Week 4 Level  
**Points**: 15 total  
**Estimated Time**: 25 minutes

---

## Scenario

You are reviewing image processing code for a web application. The engineering team built a function to create thumbnail images from user uploads.

```c
#include <stdlib.h>
#include <string.h>

typedef struct {
	unsigned char *data;
	size_t width;
	size_t height;
} Image;

Image *create_image(size_t width, size_t height) {
	Image *img = (Image *) malloc(sizeof(Image));
	img->width = width;
	img->height = height;
	
	// Allocate buffer for RGB pixels (3 bytes per pixel)
	size_t buffer_size = width * height * 3;
	img->data = (unsigned char *) malloc(buffer_size);
	
	return img;
}

void copy_image_data(Image *img, const unsigned char *src, size_t src_len) {
	size_t required = img->width * img->height * 3;
	if (src_len >= required) {
		memcpy(img->data, src, required);
	}
}
```

---

## Questions

### **1a. Vulnerability Identification** (5 points)

Identify ALL vulnerabilities present in this code. For each vulnerability:
- Name the vulnerability class (use CWE numbers if you know them)


Integer Overflow Vulnerabilities:

```
	size_t buffer_size = width * height * 3;
	
	size_t required = img->width * img->height * 3;
```

Failure to Check for Sucessful Dynamic Memory Allocation:

```
	Image *img = (Image *) malloc(sizeof(Image));
	
	img->data = (unsigned char *) malloc(buffer_size);
```

- Explain the root cause

For Failure to Check for Successful Dynamic Memory Allocation:

Coder forgot to check if malloc() returned a NULL pointer. This

happens when dynamic memory allocation fails.

- Describe potential impact

**Hint**: There are at least 3 distinct vulnerabilities. Consider:
- What happens with very large width/height values?

Integer Overflow takes place with `size_t` data type leading to

incorrect product stored in `buffer_size` or `required`.

- What happens if malloc fails?

Explained previously: `malloc()` returns a NULL pointer. This can

cause the program to attempt to dereference a NULL pointer which

is dangerous behavior.

- What happens in the second function if calculations are inconsistent?

Less bytes are copied to `img->data` than expected.

---


### **1c. Mitigations** (5 points)

Propose secure alternatives for this code. Address:
- Integer overflow prevention strategies
- Memory allocation validation
- Safe arithmetic operations

**Your rewritten code should**:
- Check for integer overflow BEFORE allocation
- Validate malloc return values
- Use safe bounds checking
- Consider maximum reasonable image dimensions (e.g., 16384 × 16384)


```c
#include <stdlib.h>
#include <string.h>

typedef struct {
	unsigned char *data;
	size_t width;
	size_t height;
} Image;

Image *create_image(size_t width, size_t height) {
	Image *img = (Image *) calloc(sizeof(Image));

	if ( img == NULL )
	{

		fprintf(stderr,"Error: img is assigned NULL.\n");

		return NULL;
	}
	
	img->width = width;
	img->height = height;
	
	// Allocate buffer for RGB pixels (3 bytes per pixel)

	size_t w_h = 0;

	if ( __builtin_uaddll_overflow(width,height,&w_h) == true )
	{
		fprintf(stderr,"Error: Integer Overflow width * height\n");

		return NULL;
	}
	
	size_t buffer_size = 0;

	size_t triple = 3;
	
	if ( __builtin_uaddll_overflow(w_h,triple,&buffer_size) == true )
	{
		fprintf(stderr,"Error: Integer Overflow (width * height) * 3\n");

		return NULL;
	}

	img->data = (unsigned char *) malloc(buffer_size);
	
	if ( img->data == NULL )
	{

		fprintf(stderr,"Error: img->data is assigned NULL.\n");

		return NULL;
	}

	return img;
}

void copy_image_data(Image *img, const unsigned char *src, size_t src_len) {
	
	size_t w_h = 0;

	if ( __builtin_uaddll_overflow(img->width,img->height,(unsigned long long int *)&w_h) == true )
	{
		fprintf(stderr,"Error: Integer Overflow width * height\n");

		return NULL;
	}
	
	size_t required = 0;

	size_t triple = 3;
	
	if ( __builtin_uaddll_overflow(w_h,triple,(unsigned long long int *)&required) == true )
	{
		fprintf(stderr,"Error: Integer Overflow (width * height) * 3\n");

		return NULL;
	}

	img->data = (unsigned char *) malloc(buffer_size);
	
	if ( img->data == NULL )
	{

		fprintf(stderr,"Error: img->data is assigned NULL.\n");

		return NULL;
	}

	
	if (src_len >= required) {
		memcpy(img->data, src, required);
	}
}
```

---

## Expected Knowledge

By Week 4, you should understand:
- Integer overflow mechanics (*API Security in Action*, p. 47)
- Multiplication overflow: `a * b` can wrap around if result exceeds SIZE_MAX
- How integer overflow leads to undersized heap allocations
- NULL pointer dereference from failed malloc
- Why you must validate allocation success

---

## Vulnerability Reference

**CWE-190**: Integer Overflow or Wraparound  
**CWE-122**: Heap-based Buffer Overflow  
**CWE-476**: NULL Pointer Dereference

**Attack Pattern**: Integer overflow → undersized allocation → heap buffer overflow

**Example**:
```c
// If width = 0x10000000 (268,435,456) and height = 16:
size_t buffer_size = width * height * 3;
// 268435456 * 16 * 3 = 12,884,901,888 bytes
// But size_t on 32-bit systems has MAX = 4,294,967,295
// Result: Integer overflow, wraps to small value
// malloc allocates tiny buffer
// memcpy writes billions of bytes → heap corruption
```

---

## Grading Rubric

### 1a. Identification (5 points)
- **2 points**: Identified integer overflow in `width * height * 3`
- **1 point**: Identified NULL pointer dereference (malloc failures)
- **1 point**: Identified potential inconsistent calculation between functions
- **1 point**: Explained root causes clearly

### 1b. Exploitation (5 points)
- **2 points**: Correctly explained integer overflow exploitation with specific values
- **2 points**: Described realistic worst-case outcomes (heap corruption, RCE potential)
- **1 point**: Explained why failed malloc leads to crash/undefined behavior

### 1c. Mitigations (5 points)
- **2 points**: Implemented overflow-safe multiplication check
- **1 point**: Validated malloc return values
- **1 point**: Added maximum dimension limits
- **1 point**: Code compiles and is demonstrably secure

---

## Hints for Secure Implementation

**Safe multiplication check pattern**:
```c
// Check if a * b would overflow
bool multiply_would_overflow(size_t a, size_t b) {
	if (a == 0 || b == 0) return false;
	return a > SIZE_MAX / b;
}
```

**Safe allocation pattern**:
```c
if (multiply_would_overflow(width, height) || 
    multiply_would_overflow(width * height, 3)) {
	fprintf(stderr, "Error: dimensions too large\n");
	return NULL;
}
```

---

## Additional Resources

**Reading**:
- *API Security in Action*, Chapter 2, pp. 47-49 - Integer overflow vulnerabilities
- *Secure by Design*, Chapter 5 - Safe integer arithmetic
- CWE-190: https://cwe.mitre.org/data/definitions/190.html
- CERT C Coding Standard: INT30-C (Ensure unsigned integer operations do not wrap)

**Similar CVEs**:
- CVE-2016-3714 (ImageMagick): Integer overflow in image dimension handling
- CVE-2018-16509 (Ghostscript): Integer overflow in image processing

---

*This exercise tests understanding of integer overflow vulnerabilities, which are common in image processing, memory allocation, and any code handling user-controlled size parameters.*
