# Exercise: Safe Size_t Addition with Overflow Detection

## Difficulty Level: Beginner-to-Intermediate

## Exercise Overview

Write a secure function that adds two `size_t` values and returns their sum. If an integer overflow would occur, the function must detect it, print an error message to `stderr` that clearly indicates an integer overflow was detected, and exit the program with status code 136.

## Inspiration

This exercise is inspired by integer overflow vulnerabilities and detection techniques discussed in:

- **"The CERT C Coding Standard 2016"**, Rule INT30-C, pages 132-137, which covers ensuring that unsigned integer operations do not wrap
- **"Effective C, 2nd Edition"**, Chapter 3, pages 50-52, covering unsigned integer wraparound and detection techniques
- **"The Art of Software Security Assessment"**, Chapter 6, pages 229-230, discussing integer underflow/overflow in real-world vulnerabilities

## Background

The `size_t` type is an unsigned integer type used to represent the size of objects in bytes. It's commonly used as the return type of `sizeof` and as parameters to memory allocation functions like `malloc()`. Because `size_t` is unsigned, arithmetic operations on it follow **wraparound semantics** (modulo behavior) rather than causing undefined behavior like signed integer overflow.

However, **just because wraparound is well-defined doesn't mean it's safe**. Integer wraparound in size calculations has been responsible for critical vulnerabilities:

### Real-World Impact

- **CVE-2009-1385** (Linux Kernel E1000): Unchecked subtraction on length caused integer underflow, leading to buffer overflow and arbitrary code execution
- **CVE-2014-4377** (iOS 7.1): Multiplication wraparound produced insufficiently small allocation, leading to heap overflow
- **Mozilla Foundation Security Advisory 2007-01**: Multiplication of `pen->num_vertices * sizeof(cairo_pen_vertex_t)` wrapped, causing heap buffer overflow
- **Boeing 787 Generator Control Units**: Internal software counter wrapped after 248 days, causing all six power generators to enter fail-safe mode simultaneously

**From "Effective C, 2nd Edition"** (page 51): "To avoid unplanned behavior (such as having your airplane fall from the sky), it's important to check for wraparound."

## Learning Objectives

After completing this exercise, you will be able to:

1. Understand that unsigned integer wraparound is well-defined but potentially dangerous
2. Implement precondition tests to detect overflow **before** it occurs
3. Implement postcondition tests to detect overflow **after** it occurs
4. Properly use `SIZE_MAX` for overflow detection
5. Understand why naive overflow checks don't work with unsigned integers
6. Write error messages to `stderr` and exit with specific status codes
7. Apply CERT C rule INT30-C in practice

## Requirements

### Function Signature

```c
/**
 * Safely adds two size_t values, detecting overflow.
 * 
 * @param a First operand
 * @param b Second operand
 * @return Sum of a and b if no overflow occurs
 * 
 * If overflow would occur:
 * - Prints error message to stderr: "Error: Integer overflow detected in addition"
 * - Exits with status code 136
 */
size_t safe_add(size_t a, size_t b);
```

### CERT C Compliance Requirements

Your implementation MUST comply with:

1. **INT30-C**: Ensure that unsigned integer operations do not wrap (pages 132-137)
2. **INT35-C**: Use correct integer precisions (implicitly - use `size_t` correctly)

### Functional Requirements

1. **`Overflow` detection**: Detect if `a + b` would exceed `SIZE_MAX`
2. **Error reporting**: Print exactly the message `"Error: Integer overflow detected in addition\n"` to `stderr`
3. **Process termination**: Exit with status code `136` on overflow
4. **Return correct sum**: Return `a + b` when no overflow occurs
5. **No wraparound**: Never allow the addition to wrap around

### Required Headers

```c
#include <stddef.h>  // for size_t
#include <stdint.h>  // for SIZE_MAX
#include <stdio.h>   // for fprintf, stderr
#include <stdlib.h>  // for exit
```

## Why This Matters

Integer overflow in size calculations is particularly dangerous because:

1. **Memory allocation**: `malloc(size)` with wrapped size allocates too little memory
2. **Buffer operations**: `memcpy(dest, src, size)` with wrapped size copies too much data
3. **Array indexing**: Calculations like `array[i * element_size]` can wrap
4. **Security-critical code**: Any size-based access control can be bypassed

**From CERT C** (page 133): "Integer values must not be allowed to wrap, especially if they are used in any of the following ways: [...] Function arguments of type size_t or rsize_t (for example, an argument to a memory allocation function)"

## Common Mistakes to Avoid

### ❌ Mistake #1: Testing after the operation (useless test)

```c
/* WRONG - This will NEVER detect overflow! */
size_t safe_add_wrong(size_t a, size_t b) {
    size_t sum = a + b;
    if (sum > SIZE_MAX) {  /* This condition can NEVER be true! */
        fprintf(stderr, "Error: Integer overflow detected in addition\n");
        exit(136);
    }
    return sum;
}
```

**Why this fails**: If `a + b` exceeds `SIZE_MAX`, wraparound occurs **before** the comparison. The wrapped value is always ≤ `SIZE_MAX`, so the test is useless.

**Reference**: "Effective C, 2nd Edition", page 51

### ❌ Mistake #2: Testing if result is less than zero

```c
/* WRONG - Unsigned integers can never be negative! */
size_t safe_add_wrong2(size_t a, size_t b) {
    size_t sum = a + b;
    if (sum < 0) {  /* This condition can NEVER be true! */
        fprintf(stderr, "Error: Integer overflow detected in addition\n");
        exit(136);
    }
    return sum;
}
```

**Why this fails**: `size_t` is unsigned. It can never be negative. The test is always false.

**Reference**: "Effective C, 2nd Edition", page 52

### ❌ Mistake #3: Wrong precondition test

```c
/* WRONG - Incorrect comparison logic */
size_t safe_add_wrong3(size_t a, size_t b) {
    if (a + b > SIZE_MAX) {  /* Wraparound occurs BEFORE comparison! */
        fprintf(stderr, "Error: Integer overflow detected in addition\n");
        exit(136);
    }
    return a + b;
}
```

**Why this fails**: The addition `a + b` happens **before** the comparison, so wraparound can occur before you check for it.

## Noncompliant Code Example #1 (No checking)

```c
/* VULNERABLE - DO NOT USE */
size_t unsafe_add(size_t a, size_t b) {
    return a + b;  /* Wraparound can occur silently! */
}

/* Real-world usage scenario: */
size_t num_elements = get_user_input();  /* attacker-controlled */
size_t element_size = sizeof(struct element);
size_t total_size = unsafe_add(num_elements, element_size);
void *buffer = malloc(total_size);  /* May allocate TOO LITTLE memory! */
```

**Why this fails**: No overflow detection. If the sum exceeds `SIZE_MAX`, it wraps around to a small value, causing `malloc()` to allocate insufficient memory.

**Reference**: "The CERT C Coding Standard", page 133

## Noncompliant Code Example #2 (Useless postcondition test)

```c
/* VULNERABLE - DO NOT USE */
size_t wrong_postcondition(size_t a, size_t b) {
    size_t sum = a + b;
    if (sum > SIZE_MAX) {  /* Can never be true! */
        fprintf(stderr, "Error: Integer overflow detected in addition\n");
        exit(136);
    }
    return sum;
}
```

**Why this fails**: After wraparound, `sum` is always ≤ `SIZE_MAX` by definition. This test will never catch overflow.

**Reference**: "Effective C, 2nd Edition", page 51

## Compliant Solution Hint #1 (Precondition Test)

The key insight from **"Effective C"** (page 51): *"To remedy this, you can subtract sum from both sides of the inequality to form the following effective test:"*

For addition `a + b`, we want to check: `a + b > SIZE_MAX`

Rearranging to avoid wraparound: `b > SIZE_MAX - a`

This test is safe because `SIZE_MAX - a` cannot wrap (assuming `a ≤ SIZE_MAX`, which is always true).

**Reference**: "The CERT C Coding Standard", page 133

## Compliant Solution Hint #2 (Postcondition Test)

An alternative approach is to check if the result wrapped by testing if it's less than the first operand:

```c
size_t sum = a + b;
if (sum < a) {
    /* Overflow occurred! */
}
```

This works because if `a + b` wraps around, the result will be less than `a`.

**Reference**: "The CERT C Coding Standard", page 134

## Test Cases

Your implementation should pass all of these test cases:

### Test 1: Normal addition (no overflow)

```c
size_t result = safe_add(100, 200);
assert(result == 300);
```

### Test 2: Addition with zero

```c
size_t result = safe_add(42, 0);
assert(result == 42);

result = safe_add(0, 42);
assert(result == 42);
```

### Test 3: Large values (no overflow)

```c
size_t result = safe_add(SIZE_MAX / 2, SIZE_MAX / 2);
assert(result == SIZE_MAX - 1);
```

### Test 4: Maximum value plus zero

```c
size_t result = safe_add(SIZE_MAX, 0);
assert(result == SIZE_MAX);
```

### Test 5: Overflow detection (1 + SIZE_MAX)

```c
/* This should print error and exit with code 136 */
safe_add(1, SIZE_MAX);  /* Should NOT return */
```

**Expected output to stderr**: `Error: Integer overflow detected in addition\n`  
**Expected exit code**: 136

### Test 6: Overflow detection (SIZE_MAX + SIZE_MAX)

```c
/* This should print error and exit with code 136 */
safe_add(SIZE_MAX, SIZE_MAX);  /* Should NOT return */
```

**Expected output to stderr**: `Error: Integer overflow detected in addition\n`  
**Expected exit code**: 136

### Test 7: Off-by-one overflow

```c
/* SIZE_MAX/2 + SIZE_MAX/2 + 2 should overflow */
size_t half = SIZE_MAX / 2;
safe_add(half + 1, half + 1);  /* Should exit with 136 */
```

### Test 8: Boundary condition

```c
/* Maximum safe addition: SIZE_MAX - 1 + 1 = SIZE_MAX */
size_t result = safe_add(SIZE_MAX - 1, 1);
assert(result == SIZE_MAX);
```

### Test 9: CVE-2014-4377 simulation (iOS 7.1 vulnerability)

```c
/* Simulate multiplication overflow leading to small allocation */
size_t num_elements = SIZE_MAX / 10;
size_t element_size = 11;
/* This should overflow: (SIZE_MAX/10) + (SIZE_MAX/10) + ... (11 times) */
size_t total = num_elements;
for (size_t i = 1; i < element_size; i++) {
    total = safe_add(total, num_elements);  /* Should eventually overflow */
}
```

### Test 10: Mozilla SVG vulnerability simulation (MFSA 2007-01)

```c
/* Simulate pen->num_vertices * sizeof(cairo_pen_vertex_t) */
size_t num_vertices = SIZE_MAX / 100 + 1;
size_t vertex_size = 100;
size_t total = 0;
for (size_t i = 0; i < vertex_size; i++) {
    total = safe_add(total, num_vertices);  /* Should overflow and exit */
}
```

## Implementation Approaches

You can implement overflow detection using either:

### Approach A: Precondition Test (Recommended)

Check **before** the addition if it would overflow:

```c
if (/* condition that detects overflow */) {
    fprintf(stderr, "Error: Integer overflow detected in addition\n");
    exit(136);
}
return a + b;
```

### Approach B: Postcondition Test

Perform the addition, then check if it wrapped:

```c
size_t sum = a + b;
if (/* condition that detects wraparound */) {
    fprintf(stderr, "Error: Integer overflow detected in addition\n");
    exit(136);
}
return sum;
```

Both approaches are valid and compliant with CERT C INT30-C.

## Hints

1. **For precondition test**: Rearrange the inequality `a + b > SIZE_MAX` to avoid performing the potentially wrapping addition
2. **For postcondition test**: After addition, check if the result is less than one of the operands
3. **Use SIZE_MAX**: It's defined in `<stdint.h>` as the maximum value for `size_t`
4. **stderr output**: Use `fprintf(stderr, ...)` not `printf(...)`
5. **Exact error message**: Match the exact string including newline: `"Error: Integer overflow detected in addition\n"`
6. **Exit status**: Use `exit(136)` not `return` or other exit codes

## Why Exit Code 136?

Exit code 136 was specified for this exercise to simulate a custom error handling policy. In real-world systems:

- Exit codes 128+ often indicate signals (128 + signal number)
- Custom exit codes help distinguish different error conditions
- Code 136 = 128 + 8, where 8 is SIGFPE (floating-point exception), sometimes used for arithmetic errors
- This demonstrates handling arithmetic errors as fatal conditions

In production code, you might:
- Return an error status and let the caller handle it
- Use `errno` to report the error
- Log to a system logger
- Throw an exception (in C++)

## Compilation and Testing

Compile your solution with:

```bash
gcc -std=c11 -Wall -Wextra -Wpedantic -Werror \
    -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
    -o safe_add safe_add.c

# Test normal operation
./safe_add

# Test overflow detection (should exit with 136)
./safe_add; echo "Exit code: $?"
```

## Bonus Challenge #1: Generic Overflow Detection

Implement a generic function that works for any unsigned integer type using preprocessor macros:

```c
#define SAFE_ADD(type, a, b, max_val) /* implementation */

// Usage:
unsigned int x = SAFE_ADD(unsigned int, ui_a, ui_b, UINT_MAX);
size_t y = SAFE_ADD(size_t, sz_a, sz_b, SIZE_MAX);
```

## Bonus Challenge #2: Return Error Code Instead of Exit

Modify the function to return an error code instead of exiting:

```c
/**
 * @param result Output parameter for the sum (if successful)
 * @return 0 on success, -1 on overflow
 */
int safe_add_checked(size_t a, size_t b, size_t *result);
```

## Bonus Challenge #3: Support All Arithmetic Operations

Implement safe versions of all wraparound-susceptible operations:

```c
size_t safe_sub(size_t a, size_t b);  /* INT30-C compliant subtraction */
size_t safe_mul(size_t a, size_t b);  /* INT30-C compliant multiplication */
```

**Hint for subtraction**: Check if `b > a` before subtracting (see "Effective C", page 52)  
**Hint for multiplication**: Check if `a > SIZE_MAX / b` before multiplying (see CERT C, page 136)

## Real-World Application Scenarios

### Scenario 1: Memory Allocation

```c
size_t num_elements = get_user_count();
size_t element_size = sizeof(struct data);
size_t header_size = sizeof(struct header);

/* Safe calculation prevents allocation vulnerabilities */
size_t data_size = safe_mul(num_elements, element_size);
size_t total_size = safe_add(data_size, header_size);
void *buffer = malloc(total_size);
```

### Scenario 2: Buffer Operations

```c
size_t bytes_to_copy = safe_add(header_len, payload_len);
if (bytes_to_copy > buffer_size) {
    /* Handle error */
}
memcpy(dest, src, bytes_to_copy);
```

### Scenario 3: Network Protocol Parsing

```c
/* Parse packet with length field */
uint32_t packet_length = ntohl(header->length);
size_t header_size = sizeof(struct packet_header);

/* Attacker can't cause underflow by sending packet_length < header_size */
if (packet_length < header_size) {
    /* Handle error */
}

size_t payload_length = packet_length - header_size;  /* Safe */
```

## Common Real-World Patterns

### Pattern 1: Array Size Calculation

```c
/* VULNERABLE */
size_t array_size = num_elements * element_size;

/* SECURE */
size_t array_size = safe_mul(num_elements, element_size);
```

### Pattern 2: Growing Buffers

```c
/* VULNERABLE */
new_capacity = old_capacity * 2;

/* SECURE */
new_capacity = safe_mul(old_capacity, 2);
```

### Pattern 3: Offset Calculations

```c
/* VULNERABLE */
size_t offset = base + index * element_size;

/* SECURE */
size_t temp = safe_mul(index, element_size);
size_t offset = safe_add(base, temp);
```

## Additional Resources

- **CERT C Coding Standard**: Rule INT30-C (pages 132-137), Rule INT02-C (integer conversion rules)
- **Effective C, 2nd Edition**: Chapter 3, "Arithmetic Types" (pages 50-52)
- **The Art of Software Security Assessment**: Chapter 6, "C Language Issues" (pages 211-230)
- **CWE-190**: Integer Overflow or Wraparound
- **CVE-2009-1385**: Linux Kernel E1000 Integer Underflow
- **CVE-2014-4377**: iOS 7.1 multiplication overflow vulnerability
- **ISO/IEC TR 24772:2013**: Arithmetic Wrap-Around Error [FIF]

## Solution Checklist

Before submitting your solution, verify:

- [ ] Function signature exactly matches the specification
- [ ] Overflow detection works correctly (precondition OR postcondition test)
- [ ] Error message is exactly: `"Error: Integer overflow detected in addition\n"`
- [ ] Error message goes to `stderr`, not `stdout`
- [ ] Exit code is exactly 136 on overflow
- [ ] Function returns correct sum when no overflow occurs
- [ ] All test cases pass
- [ ] Compiles without warnings with `-Wall -Wextra -Wpedantic`
- [ ] No wraparound occurs in the overflow detection logic itself

## Expected Learning Outcomes

By completing this exercise, you should now understand:

1. **Wraparound is well-defined but dangerous**: Just because it's not undefined behavior doesn't mean it's safe
2. **Naive overflow checks fail**: Testing `sum > SIZE_MAX` after the addition doesn't work
3. **Precondition vs postcondition**: Two valid approaches to overflow detection
4. **Algebraic rearrangement**: How to avoid wraparound in overflow checks themselves
5. **Real-world impact**: Integer overflow has caused critical vulnerabilities in major software
6. **Defense in depth**: Overflow detection should be used whenever size calculations come from untrusted sources
7. **CERT C compliance**: How to apply INT30-C in practice

## Key Takeaway

**From CERT C** (page 137): "Integer wrap can lead to buffer overflows and the execution of arbitrary code by an attacker."

Never assume that addition of unsigned integers is safe. Always validate when working with sizes from untrusted sources or in security-critical code.

Good luck, and remember: **Wraparound is defined, but that doesn't make it safe!**
