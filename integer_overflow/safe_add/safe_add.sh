gcc -std=c11 -Wall -Wextra -Wpedantic -Werror \
    -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
    -o /tmp/safe_add_test.o safe_add_2000_tests.c

/tmp/safe_add_test.o

: '

Expected output:

Part 1: Running 1000 safe addition tests...
Part 1 PASSED: All 1000 safe addition tests passed!

Part 2: Running 1000 overflow detection tests using fork()...
Part 2 PASSED: All 1000 overflow detection tests passed!

FINAL RESULTS: All 2000 tests PASSED!
✓ Part 1: 1000 safe addition tests - PASSED
✓ Part 2: 1000 overflow detection tests (fork + exit code) - PASSED
'
