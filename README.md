# Security Engineering Challenge Exercises

A comprehensive collection of hands-on Application Security exercises designed to sharpen your skills for production environments and security-critical roles. These challenges are grounded in real-world CVEs, industry standards, and best practices from authoritative security references.

## Overview

This repository provides practical, production-focused security exercises covering common vulnerability classes and secure coding practices. Each exercise is inspired by actual CVEs and references industry-standard security resources including the CERT C Coding Standard, "Effective C", "The Art of Software Security Assessment", and "API Security in Action".

## Target Audience

- Security Engineers preparing for production work
- Software Engineers looking to strengthen secure coding practices
- Security professionals studying real-world vulnerability patterns
- Developers preparing for Security Engineering focused technical interviews
- Students learning offensive and defensive security techniques

## Exercise Categories

### Memory Safety (C)

#### Integer Overflow
**Location**: `integer_overflow/`

Focuses on detecting and preventing unsigned integer wraparound vulnerabilities:
- Unsigned integer overflow detection (CERT C INT30-C)
- `size_t` arithmetic overflow prevention
- Precondition and postcondition testing techniques
- Real-world CVE scenarios: CVE-2009-1385 (Linux Kernel), CVE-2014-4377 (iOS 7.1)

**Difficulty**: Beginner to Intermediate

#### Buffer Overflow
**Location**: `buffer_overflow/`

Secure string operations and bounds-checking:
- Safe use of `strncat()` and bounds-checking functions
- Off-by-one error prevention
- Integer underflow in size calculations
- Proper null termination handling
- Real-world CVE scenarios: CVE-2009-0587, CVE-2009-1252

**Difficulty**: Beginner to Intermediate
**Prerequisites**: Complete integer overflow exercises first

### OS Security (Python)

#### Path Traversal Prevention
**Location**: `os_security/`

Three progressive exercises on preventing path traversal attacks:
- Unicode sandwich pattern implementation
- Encoding-based attack bypass detection (URL encoding, double encoding)
- Unicode normalization attack prevention
- Allowlist validation techniques
- Real-world CVE scenarios: CVE-2019-11510 (Pulse Secure), CVE-2021-41773 (Apache), CVE-2022-24112 (Atlassian)

**Difficulty**: Intermediate
**Time**: 2-4 hours per variant

### Cryptography & Authentication (Python)

#### Password Generation
**Location**: `passwords/password_generator/`

Cryptographically secure password generation and strength validation:
- CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) usage
- Password entropy calculation
- Character space analysis
- Security-focused password strength assessment
- Common pitfalls in random number generation

**Difficulty**: Intermediate

#### Session Security
**Location**: `session_security/jwt_token_validation/`

JWT token validation and session management:
- Token expiration validation
- Secure session handling practices
- Time-based security controls

**Difficulty**: Intermediate

### API Security (Python)

#### Rate Limiting
**Location**: `api_security/api_request_limiter/`

Implementing production-grade API rate limiting:
- Request throttling strategies
- Abuse prevention mechanisms
- API security best practices

**Difficulty**: Intermediate

### Dynamic Memory Management (C)

**Location**: `dynamic_memory_management/`

Safe memory allocation and deallocation practices:
- Proper use of malloc/free
- Memory leak prevention
- Use-after-free vulnerability prevention
- Data structure comparisons for memory management

**Difficulty**: Intermediate to Advanced

## Repository Structure

```
SecEng-Exercises/
├── README.md                      # This file
├── CLAUDE.md                      # Development guidance for AI assistants
├── integer_overflow/              # Size_t overflow detection
├── buffer_overflow/               # Secure string operations
├── os_security/                   # Path traversal prevention exercises
│   ├── os_path_traversal/
│   ├── os_path_traversal_ii/
│   └── os_path_traversal_revised/
├── passwords/                     # Password generation and validation
│   └── password_generator/
├── session_security/              # JWT and session management
│   └── jwt_token_validation/
├── api_security/                  # API security patterns
│   └── api_request_limiter/
└── dynamic_memory_management/     # Safe memory operations
```

## How to Use These Exercises

### For C Exercises

1. Read the exercise markdown file thoroughly
2. Understand the CVE context and real-world impact
3. Review noncompliant examples to understand what NOT to do
4. Implement your solution following the requirements
5. Compile with security flags:
   ```bash
   gcc -std=c11 -Wall -Wextra -Wpedantic -Werror \
       -fsanitize=address,undefined \
       -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
       -o output source.c
   ```
6. Test against provided test cases
7. Verify with AddressSanitizer and Valgrind:
   ```bash
   ./output
   valgrind --leak-check=full ./output
   ```

### For Python Exercises

1. Read the exercise README or markdown file
2. Understand the vulnerability class and attack vectors
3. Review test cases to understand requirements
4. Implement your solution
5. Run provided test suites
6. Review blog posts for detailed explanations

## Key Security Principles Covered

### Integer Safety
- Unsigned wraparound is well-defined but dangerous
- Never test overflow after the operation
- Use precondition checks: `b > SIZE_MAX - a`
- Or postcondition checks: `sum < a` indicates wraparound

### String Safety
- Never use unbounded string functions
- Account for null terminators in size calculations
- Check for integer underflow before subtraction
- Validate inputs are null-terminated

### Input Validation
- Implement allowlist validation, not blocklist
- Normalize input before validation
- Detect encoding-based bypasses
- Handle Unicode edge cases

### Cryptographic Operations
- Always use cryptographically secure random sources
- Never use predictable RNGs for security-critical operations
- Calculate and validate entropy requirements
- Understand the difference between randomness and security

## Standards and References

All exercises are based on authoritative security references:

- **CERT C Coding Standard 2016**: Specific rule citations (INT30-C, STR31-C, etc.)
- **Effective C, 2nd Edition**: Chapter and page references
- **The Art of Software Security Assessment**: Vulnerability analysis techniques
- **API Security in Action**: Modern API security patterns
- **Effective Python**: Language-specific best practices

## Real-World CVE Coverage

Exercises simulate vulnerabilities from actual CVEs:
- **CVE-2009-1385**: Linux Kernel integer underflow
- **CVE-2014-4377**: iOS multiplication wraparound
- **CVE-2009-0587, CVE-2009-1252**: String operation vulnerabilities
- **CVE-2019-11510**: Pulse Secure path traversal
- **CVE-2021-41773**: Apache HTTP Server path traversal
- **CVE-2022-24112**: Atlassian Unicode normalization bypass

## Prerequisites

### For C Exercises
- Basic C programming knowledge
- Understanding of pointers and memory
- GCC compiler with C11 support
- AddressSanitizer and Valgrind (recommended)

### For Python Exercises
- Python 3.8+
- Basic understanding of file systems and web APIs
- Familiarity with pytest (for running tests)

## Learning Path

Recommended progression for maximum learning:

1. **Start with Integer Overflow** - Foundation for size calculations
2. **Progress to Buffer Overflow** - Applies integer overflow concepts
3. **Move to Path Traversal** - Input validation and encoding
4. **Practice Password Generation** - Cryptographic operations
5. **Explore API Security** - Rate limiting and abuse prevention
6. **Advanced Memory Management** - Complex memory safety patterns

## Contributing

These exercises are designed for self-study and skill development. If you find errors or have suggestions for improvements, please open an issue or submit a pull request.

## License

These exercises are provided for educational purposes. Use them to strengthen your security skills and build safer software.

---

**Note**: Each exercise directory contains detailed instructions, test cases, hints, and often blog posts with comprehensive explanations. Read all provided materials before starting implementation.
