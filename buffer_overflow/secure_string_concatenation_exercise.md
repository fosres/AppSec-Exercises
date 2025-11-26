# Exercise: Secure String Concatenation

## Try Doing These Exercises First

Safe Size_t Addition with Overflow Detection

## Difficulty Level: Intermediate

## Exercise Overview

Write a secure function that concatenates one C string to another string, ensuring no buffer overflows can occur. Your implementation must be compliant with CERT C Coding Standard rules, particularly STR31-C (guarantee sufficient space for strings) and STR07-C (use bounds-checking interfaces when available).

## Inspiration

This exercise is inspired by common string concatenation vulnerabilities discussed in:

- **"The CERT C Coding Standard 2016"**, Rule STR31-C, pages 233-241, which covers guaranteeing storage for strings has sufficient space for character data and the null terminator
- **"The Art of Software Security Assessment"**, Chapter 8, pages 407-416, specifically the sections on `strcat()` and `strncat()` vulnerabilities
- **"Effective C, 2nd Edition"**, Chapter 7, pages 159-164, covering bounds-checking interfaces and the `strcpy_s`/`strcat_s` family of functions

## Background

String concatenation is one of the most common sources of buffer overflow vulnerabilities in C programs. The traditional `strcat()` function is dangerous because it doesn't check if the destination buffer has sufficient space. The `strncat()` function is safer but easy to misuse:

1. **Common mistake #1**: Passing the total buffer size instead of remaining space
2. **Common mistake #2**: Forgetting that `strncat()` doesn't account for the trailing null byte in its size parameter
3. **Common mistake #3**: Integer underflow when calculating remaining space

Real-world vulnerabilities from improper string concatenation include CVE-2009-0587 (Evolution Data Server) and CVE-2009-1252 (NTPd), both resulting in arbitrary code execution.

## Learning Objectives

After completing this exercise, you will be able to:

1. Correctly calculate remaining buffer space for string concatenation
2. Properly use `strncat()` with the correct size parameter
3. Implement error handling for truncation scenarios
4. Understand and apply CERT C rules STR31-C and STR07-C
5. Recognize off-by-one vulnerabilities in string operations
6. Optionally use C11 Annex K bounds-checking interfaces (`strcat_s`)

## Requirements

### Function Signature

```c
/**
 * Safely concatenates src to dest, ensuring no buffer overflow.
 * 
 * @param dest Destination buffer (must be null-terminated)
 * @param dest_size Total size of destination buffer (in bytes)
 * @param src Source string to append (must be null-terminated)
 * @return 0 on success, -1 on error (truncation or invalid parameters)
 */
int safe_strcat(char *dest, size_t dest_size, const char *src);
```

### CERT C Compliance Requirements

Your implementation MUST comply with:

1. **STR31-C**: Guarantee that storage for strings has sufficient space for character data and the null terminator
2. **STR32-C**: Do not pass a non-null-terminated character sequence to library functions
3. **STR07-C**: Use bounds-checking interfaces when available (optional for bonus points)

### Functional Requirements

1. **Null pointer validation**: Return -1 if `dest` or `src` is NULL
2. **Size validation**: Return -1 if `dest_size` is 0
3. **Overflow prevention**: Do not write beyond `dest_size` bytes
4. **Null termination guarantee**: Always ensure `dest` is null-terminated
5. **Truncation detection**: Return -1 if the concatenation would require truncation
6. **Current length validation**: Verify `dest` is already null-terminated before concatenation

## Noncompliant Code Example #1 (Classic strcat vulnerability)

```c
/* VULNERABLE - DO NOT USE */
int unsafe_concat(char *dest, size_t dest_size, const char *src) {
    strcat(dest, src);  /* No bounds checking! */
    return 0;
}

/* Usage that causes overflow: */
char buffer[32];
strcpy(buffer, "username is: ");
unsafe_concat(buffer, sizeof(buffer), very_long_username);  /* OVERFLOW! */
```

**Why this fails**: The `strcat()` function performs no bounds checking. If `src` is too long, it will write past the end of `dest`, causing a buffer overflow (STR31-C violation).

**Reference**: "The Art of Software Security Assessment", page 408

## Noncompliant Code Example #2 (Wrong strncat size)

```c
/* VULNERABLE - DO NOT USE */
int wrong_size_concat(char *dest, size_t dest_size, const char *src) {
    if (dest == NULL || src == NULL || dest_size == 0)
        return -1;
    
    strncat(dest, src, dest_size);  /* WRONG: should be remaining size! */
    return 0;
}

/* Usage that causes overflow: */
char buffer[1024];
strcpy(buffer, "username is: ");
wrong_size_concat(buffer, sizeof(buffer), username);  /* OVERFLOW! */
```

**Why this fails**: The code passes the total buffer size instead of the remaining space. After the `strcpy()`, only `1024 - 13 = 1011` bytes remain, but `strncat()` thinks it has 1024 bytes available.

**Reference**: "The Art of Software Security Assessment", pages 413-414

## Noncompliant Code Example #3 (Off-by-one error)

```c
/* VULNERABLE - DO NOT USE */
int off_by_one_concat(char *dest, size_t dest_size, const char *src) {
    size_t current_len;
    
    if (dest == NULL || src == NULL || dest_size == 0)
        return -1;
    
    current_len = strlen(dest);
    if (current_len >= dest_size)
        return -1;
    
    /* Off-by-one: doesn't account for the null byte that strncat adds! */
    strncat(dest, src, dest_size - current_len);  
    return 0;
}
```

**Why this fails**: The `strncat()` function always adds a null terminator, but the size calculation doesn't account for it. This writes one byte past the buffer end.

**Reference**: "The Art of Software Security Assessment", page 414

## Noncompliant Code Example #4 (Integer underflow risk)

```c
/* VULNERABLE - DO NOT USE */
int underflow_concat(char *dest, size_t dest_size, const char *src) {
    size_t current_len;
    
    if (dest == NULL || src == NULL || dest_size == 0)
        return -1;
    
    current_len = strlen(dest);
    
    /* If current_len >= dest_size, this underflows! */
    strncat(dest, src, dest_size - current_len - 1);
    return 0;
}
```

**Why this fails**: If `current_len >= dest_size`, the subtraction `dest_size - current_len - 1` wraps around to a huge positive number (integer underflow), causing a massive overflow.

**Reference**: "The Art of Software Security Assessment", page 414

## Test Cases

Your implementation should pass all of these test cases:

### Test 1: Normal concatenation

```c
char dest[32] = "Hello, ";
assert(safe_strcat(dest, sizeof(dest), "World!") == 0);
assert(strcmp(dest, "Hello, World!") == 0);
```

### Test 2: Exact fit (no truncation needed)

```c
char dest[16] = "12345";
assert(safe_strcat(dest, sizeof(dest), "6789012345") == 0);
assert(strcmp(dest, "123456789012345") == 0);
assert(strlen(dest) == 15);  /* dest_size - 1 */
```

### Test 3: Source too long (must detect overflow)

```c
char dest[16] = "12345";
assert(safe_strcat(dest, sizeof(dest), "67890123456") == -1);
/* dest should remain unchanged or be safely truncated */
```

### Test 4: NULL destination pointer

```c
assert(safe_strcat(NULL, 32, "test") == -1);
```

### Test 5: NULL source pointer

```c
char dest[32] = "Hello";
assert(safe_strcat(dest, sizeof(dest), NULL) == -1);
```

### Test 6: Zero buffer size

```c
char dest[32] = "Hello";
assert(safe_strcat(dest, 0, "World") == -1);
```

### Test 7: Empty source string

```c
char dest[32] = "Hello";
assert(safe_strcat(dest, sizeof(dest), "") == 0);
assert(strcmp(dest, "Hello") == 0);
```

### Test 8: Empty destination string

```c
char dest[32] = "";
assert(safe_strcat(dest, sizeof(dest), "Hello") == 0);
assert(strcmp(dest, "Hello") == 0);
```

### Test 9: Destination already full

```c
char dest[8] = "1234567";  /* 7 chars + null = full */
assert(safe_strcat(dest, sizeof(dest), "X") == -1);
```

### Test 10: Single character concatenation

```c
char dest[16] = "Hello";
assert(safe_strcat(dest, sizeof(dest), "!") == 0);
assert(strcmp(dest, "Hello!") == 0);
```

### Test 11: CVE-2009-0587 style vulnerability (integer underflow)

```c
/* Simulate scenario where strlen(dest) could equal dest_size */
char dest[8];
memset(dest, 'A', 7);
dest[7] = '\0';  /* Exactly fills buffer */
assert(safe_strcat(dest, sizeof(dest), "B") == -1);
/* Should NOT overflow despite dest being full */
```

### Test 12: Multiple concatenations

```c
char dest[32] = "A";
assert(safe_strcat(dest, sizeof(dest), "B") == 0);
assert(safe_strcat(dest, sizeof(dest), "C") == 0);
assert(safe_strcat(dest, sizeof(dest), "D") == 0);
assert(strcmp(dest, "ABCD") == 0);
```

## Hints

1. **Always validate inputs first**: Check for NULL pointers and zero size before doing anything else
2. **Get current length safely**: Use `strlen(dest)` to find how much space is already used
3. **Check for existing overflow**: If `strlen(dest) >= dest_size`, the destination is already invalid
4. **Calculate remaining space correctly**: `remaining = dest_size - strlen(dest) - 1` (the -1 is for the null terminator)
5. **Watch for underflow**: Ensure `strlen(dest) + 1 < dest_size` before calculating remaining space
6. **Check if source fits**: Use `strlen(src)` and compare against remaining space
7. **Use strncat correctly**: Pass the remaining space (not total buffer size) as the size parameter
8. **Preserve original on error**: Consider whether to leave `dest` unchanged if concatenation would fail

## Bonus Challenge #1: Use C11 Annex K (strcat_s)

If your compiler supports C11 Annex K bounds-checking interfaces, implement an alternative version using `strcat_s`:

```c
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>

int safe_strcat_s(char *dest, size_t dest_size, const char *src) {
    /* Implement using strcat_s */
    /* Reference: "Effective C, 2nd Edition", pages 162-164 */
}
```

**Advantages of `strcat_s`**:
- Runtime constraint checking built-in
- Guaranteed null termination
- Clearer interface (dest_size is total size, not remaining)

**Reference**: "Effective C, 2nd Edition", pages 162-164; "The CERT C Coding Standard", STR07-C

## Bonus Challenge #2: Implement safe_strncat_chk

Implement a version that provides truncation information to the caller:

```c
/**
 * @param truncated Optional output parameter set to true if truncation occurred
 * @return 0 on success, -1 on error
 */
int safe_strncat_chk(char *dest, size_t dest_size, const char *src, 
                     bool *truncated);
```

## Bonus Challenge #3: Variadic safe concatenation

Implement a function that safely concatenates multiple strings in one call:

```c
/**
 * Concatenates multiple strings safely.
 * The argument list must be terminated with NULL.
 * Example: safe_strcat_multi(buf, sizeof(buf), "Hello", " ", "World", NULL);
 */
int safe_strcat_multi(char *dest, size_t dest_size, ...);
```

**Reference**: "Effective C, 2nd Edition", pages 159-161 (variadic functions with memccpy)

## Real-World Context

String concatenation vulnerabilities have been responsible for numerous critical security flaws:

- **CVE-2009-1252** (NTPd): Calls to `sprintf()` allowed buffer overflow leading to arbitrary code execution
- **CVE-2009-0587** (Evolution Data Server): Unchecked arithmetic on string length caused buffer overflow
- Countless privilege escalation vulnerabilities in setuid programs
- Remote code execution in network daemons processing user input

**Statistics from The Art of Software Security Assessment** (page 407): "Bugs of this nature were once very common, but they are less common now because developers are more aware of the misuses of strcpy(); however, they still occur, particularly in closed-source applications that aren't widely distributed."

## Common Pitfalls to Avoid

1. **Using strcat() directly**: Always unsafe; no bounds checking
2. **Using strncat() with sizeof(dest)**: Should use remaining space instead
3. **Forgetting the null terminator**: `strncat()` adds one, so account for it
4. **Integer underflow**: Check bounds before subtracting from unsigned values
5. **Not validating dest is null-terminated**: `strlen()` on non-terminated strings is undefined behavior
6. **Assuming strncat() returns an error**: It doesn't; it silently truncates

## Compilation and Testing

Compile your solution with security flags enabled:

```bash
gcc -std=c11 -Wall -Wextra -Wpedantic -Werror \
    -fsanitize=address,undefined \
    -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
    -o safe_strcat safe_strcat.c

# Run with Address Sanitizer to detect buffer overflows
./safe_strcat

# Use Valgrind for additional memory safety checks
valgrind --leak-check=full ./safe_strcat
```

## Additional Resources

- **CERT C Coding Standard**: Rule STR31-C (pages 233-241), Rule STR07-C
- **The Art of Software Security Assessment**: Chapter 8, "Strings and Metacharacters" (pages 407-416)
- **Effective C, 2nd Edition**: Chapter 7, "Characters and Strings" (pages 159-164)
- **CWE-120**: Buffer Copy without Checking Size of Input ("Classic Buffer Overflow")
- **CWE-193**: Off-by-one Error
- **CWE-119**: Improper Restriction of Operations within the Bounds of a Memory Buffer

## Solution Checklist

Before submitting your solution, verify:

- [ ] All NULL pointer checks are present
- [ ] Zero-size buffer is handled
- [ ] Current length is validated before arithmetic
- [ ] Integer underflow cannot occur
- [ ] Remaining space calculation accounts for null terminator
- [ ] `strncat()` receives correct size parameter (remaining space)
- [ ] All test cases pass
- [ ] Compiles without warnings with `-Wall -Wextra -Wpedantic`
- [ ] No buffer overflows detected by AddressSanitizer
- [ ] No undefined behavior detected by UBSan

## Expected Learning Outcomes

By completing this exercise, you should now understand:

1. Why `strcat()` is fundamentally unsafe and should never be used
2. The subtle differences between total buffer size and remaining space
3. How `strncat()` actually works and why its interface is confusing
4. The importance of accounting for null terminators in size calculations
5. How integer underflow can occur with unsigned size calculations
6. Why bounds-checking interfaces like `strcat_s()` are safer alternatives
7. How real-world CVEs result from these common mistakes

Good luck, and remember: **Security is not optional; it's a requirement!**
