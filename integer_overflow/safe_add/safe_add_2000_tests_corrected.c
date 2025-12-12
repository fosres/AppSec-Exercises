/**
 * Safe Size_t Addition with Overflow Detection - 2000 Test Cases
 * CORRECTED VERSION - Fixed integer division truncation bugs
 * 
 * Exercise inspired by:
 * - "The CERT C Coding Standard 2016", Rule INT30-C, pages 132-137
 * - "Effective C, 2nd Edition", Chapter 3, pages 50-52
 * - "The Art of Software Security Assessment", Chapter 6, pages 229-230
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

size_t safe_add(size_t a, size_t b)
{
	size_t c = 0;
	if ( __builtin_add_overflow(a,b,&c) == 1 )
	{
		fprintf(stderr,"Error: Integer overflow detected in addition\n");
		exit(136);
	}		
	return c;
}

void test_overflow(size_t a, size_t b) {
	pid_t pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Fork failed\n");
		exit(1);
	}
	if (pid == 0) {
		freopen("/dev/null", "w", stderr);
		safe_add(a, b);
		exit(1);
	} else {
		int status;
		waitpid(pid, &status, 0);
		assert(WIFEXITED(status));
		int exit_code = WEXITSTATUS(status);
		assert(exit_code == 136);
	}
}

int main(void) {
	size_t result;
	
	printf("======================================================================\n");
	printf("Safe size_t Addition Test Suite - 2000 Tests (CORRECTED)\n");
	printf("======================================================================\n\n");
	
	printf("Part 1: Running 1000 safe addition tests...\n");
	
	/* Basic tests */
	result = safe_add(0, 0);
	assert(result == 0);
	result = safe_add(1, 1);
	assert(result == 2);
	result = safe_add(10, 20);
	assert(result == 30);
	result = safe_add(100, 200);
	assert(result == 300);
	result = safe_add(1000, 2000);
	assert(result == 3000);
	result = safe_add(12345, 67890);
	assert(result == 80235);
	result = safe_add(0, 42);
	assert(result == 42);
	result = safe_add(42, 0);
	assert(result == 42);
	result = safe_add(SIZE_MAX - 1, 1);
	assert(result == SIZE_MAX);
	result = safe_add(SIZE_MAX - 100, 100);
	assert(result == SIZE_MAX);
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 4);
	assert(result == (SIZE_MAX / 2) + (SIZE_MAX / 4));
	result = safe_add(SIZE_MAX / 4, SIZE_MAX / 4);
	assert(result == (SIZE_MAX / 4) * 2);  // FIXED: was SIZE_MAX / 2
	result = safe_add(SIZE_MAX / 3, SIZE_MAX / 3);
	assert(result == (SIZE_MAX / 3) * 2);
	result = safe_add(SIZE_MAX / 10, SIZE_MAX / 10);
	assert(result == (SIZE_MAX / 10) * 2);  // FIXED: was SIZE_MAX / 5
	result = safe_add(123456789, 987654321);
	assert(result == 1111111110);
	result = safe_add(SIZE_MAX - 10000, 10000);
	assert(result == SIZE_MAX);
	result = safe_add(SIZE_MAX - 1000000, 1000000);
	assert(result == SIZE_MAX);
	result = safe_add(SIZE_MAX / 2 - 1, SIZE_MAX / 2 - 1);
	assert(result == (SIZE_MAX / 2 - 1) * 2);  // FIXED: was SIZE_MAX - 2
	result = safe_add(1, 2);
	assert(result == 3);
	result = safe_add(2, 3);
	assert(result == 5);
	
	/* Remaining 980 tests */
	for (size_t i = 0; i < 980; i++) {
		result = safe_add(i, i);
		assert(result == i * 2);
		
		if (i % 2 == 0 && i <= SIZE_MAX / 1000) {
			result = safe_add(SIZE_MAX / 1000 - i, i);
			assert(result == SIZE_MAX / 1000);
		}
		
		if (i < 100) {
			result = safe_add(SIZE_MAX - 10000 - i, i);
			assert(result == SIZE_MAX - 10000);
		}
	}
	
	printf("Part 1 PASSED: All 1000 safe addition tests passed!\n\n");
	
	printf("Part 2: Running 1000 overflow detection tests using fork()...\n");
	printf("(Each test spawns a child process to verify exit code 136)\n\n");
	
	/* Overflow tests */
	test_overflow(SIZE_MAX, 1);
	test_overflow(SIZE_MAX, 2);
	test_overflow(SIZE_MAX, 10);
	test_overflow(SIZE_MAX, 100);
	test_overflow(SIZE_MAX, 1000);
	test_overflow(SIZE_MAX, SIZE_MAX);
	test_overflow(1, SIZE_MAX);
	test_overflow(2, SIZE_MAX);
	test_overflow(10, SIZE_MAX);
	test_overflow(100, SIZE_MAX);
	test_overflow(1000, SIZE_MAX);
	test_overflow(SIZE_MAX - 1, 2);
	test_overflow(SIZE_MAX - 1, 3);
	test_overflow(SIZE_MAX - 10, 11);
	test_overflow(SIZE_MAX - 10, 12);
	test_overflow(SIZE_MAX - 100, 101);
	test_overflow(SIZE_MAX - 100, 102);
	test_overflow(SIZE_MAX - 1000, 1001);
	test_overflow(SIZE_MAX - 1000, 1002);
	test_overflow(SIZE_MAX / 2 + 1, SIZE_MAX / 2);
	
	/* Remaining 980 overflow tests */
	for (size_t i = 1; i < 981; i++) {
		test_overflow(SIZE_MAX - i, i + 1);
		
		if (i < 100) {
			test_overflow(SIZE_MAX / 2, SIZE_MAX / 2 + i);
			test_overflow(SIZE_MAX / 3, SIZE_MAX / 3 * 2 + i);
		}
		
		if (i % 10 == 0) {
			test_overflow(SIZE_MAX - 10000 + i, 10001);
		}
	}
	
	printf("\nPart 2 PASSED: All 1000 overflow detection tests passed!\n\n");
	
	printf("======================================================================\n");
	printf("FINAL RESULTS: All 2000 tests PASSED!\n");
	printf("======================================================================\n");
	printf("✓ Part 1: 1000 safe addition tests - PASSED\n");
	printf("✓ Part 2: 1000 overflow detection tests (fork + exit code) - PASSED\n");
	printf("\n");
	printf("safe_add() is CERT C INT30-C compliant.\n");
	printf("======================================================================\n");
	
	return 0;
}
