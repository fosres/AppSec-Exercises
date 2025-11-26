# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a security exercises repository focused on teaching secure C programming practices. The exercises are designed to help developers understand and prevent common vulnerabilities, with detailed references to CERT C Coding Standard, "Effective C", and "The Art of Software Security Assessment".

## Repository Structure

```
exercises/
├── integer_overflow/          # Integer overflow detection exercises
│   └── safe_size_t_addition_exercise.md
└── buffer_overflow/           # Buffer overflow prevention exercises
    └── secure_string_concatenation_exercise.md
```

## Exercise Categories

### Integer Overflow Exercises
Located in `integer_overflow/`, these exercises focus on:
- Unsigned integer wraparound detection (CERT C INT30-C)
- Size_t arithmetic overflow prevention
- Precondition and postcondition overflow testing
- Real-world CVE scenarios (CVE-2009-1385, CVE-2014-4377)

### Buffer Overflow Exercises
Located in `buffer_overflow/`, these exercises focus on:
- Secure string operations (CERT C STR31-C, STR07-C)
- Proper use of `strncat()` and bounds-checking functions
- Off-by-one error prevention
- Integer underflow in size calculations
- Real-world CVE scenarios (CVE-2009-0587, CVE-2009-1252)

## Development Commands

### Compiling Exercise Solutions

Standard compilation with security flags:
```bash
gcc -std=c11 -Wall -Wextra -Wpedantic -Werror \
    -fsanitize=address,undefined \
    -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
    -o <output> <source>.c
```

### Testing

Run with AddressSanitizer:
```bash
./<executable>
```

Check with Valgrind:
```bash
valgrind --leak-check=full ./<executable>
```

For overflow detection tests that should exit:
```bash
./<executable>
echo "Exit code: $?"
```

## Exercise Structure

Each exercise follows a consistent format:
1. **Exercise Overview**: Difficulty level and objective
2. **Inspiration**: References to CERT C, security books, and standards
3. **Background**: Real-world context and CVE examples
4. **Requirements**: Function signatures and compliance requirements
5. **Noncompliant Examples**: Common vulnerable patterns to avoid
6. **Test Cases**: Comprehensive test suite including CVE simulations
7. **Hints**: Implementation guidance
8. **Bonus Challenges**: Advanced variations

## Important Standards and References

All exercises are based on:
- **CERT C Coding Standard 2016**: Specific rule citations (e.g., INT30-C, STR31-C)
- **Effective C, 2nd Edition**: Chapter and page references
- **The Art of Software Security Assessment**: Chapter and page references

## Key Security Principles

### Integer Overflow (size_t)
- Unsigned wraparound is well-defined but dangerous
- Never test `sum > SIZE_MAX` after the operation (always false)
- Use precondition: `b > SIZE_MAX - a`
- Or postcondition: `sum < a` indicates wraparound
- Exit code 136 used for overflow errors in exercises

### String Operations
- Never use `strcat()` directly (no bounds checking)
- `strncat(dest, src, n)` where n is remaining space, not total size
- Account for null terminator: `remaining = dest_size - strlen(dest) - 1`
- Check for integer underflow before subtraction: `strlen(dest) + 1 < dest_size`
- Validate destination is null-terminated before operations

## Exercise Dependencies

The buffer overflow exercise (`secure_string_concatenation_exercise.md`) recommends completing the integer overflow exercise (`safe_size_t_addition_exercise.md`) first, as size calculations in buffer operations require overflow detection.

## Common Vulnerabilities Covered

- **Buffer Overflow**: Off-by-one errors, incorrect size calculations
- **Integer Overflow**: Wraparound in size_t operations
- **Integer Underflow**: Unsigned subtraction leading to large values
- **Improper Null Termination**: Missing or incorrect null byte handling

## Code Architecture Notes

Exercise solutions should:
- Include all required headers: `<stddef.h>`, `<stdint.h>`, `<stdio.h>`, `<stdlib.h>`, `<string.h>`
- Validate all input parameters (NULL checks, size checks)
- Use `SIZE_MAX` for overflow detection
- Write errors to `stderr` using `fprintf()`
- Follow exact error message formats specified in exercises
- Return specific error codes or exit codes as specified
