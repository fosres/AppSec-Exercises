/**
 * Safe Size_t Addition with Overflow Detection
 * 
 * Exercise inspired by:
 * - "The CERT C Coding Standard 2016", Rule INT30-C, pages 132-137
 * - "Effective C, 2nd Edition", Chapter 3, pages 50-52
 * - "The Art of Software Security Assessment", Chapter 6, pages 229-230
 * 
 * This implementation follows CERT C INT30-C compliance for unsigned integer
 * overflow detection using precondition testing.
 */

#include <stddef.h>	/* for size_t */
#include <stdint.h>	/* for SIZE_MAX */
#include <stdio.h>	/* for fprintf, stderr */
#include <stdlib.h>	/* for exit */
#include <assert.h>	/* for assert */

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
size_t safe_add(size_t a, size_t b) {
	
}

/**
 * Test harness for safe_add function
 * Includes 1000 test cases covering various scenarios
 */
int main(void) {
	size_t result;
	
	printf("Running 1000 test cases for safe_add()...\n");
	
	/* ========================================================================
	 * CATEGORY 1: Basic Addition Tests (Tests 1-100)
	 * Testing normal additions with small to medium values
	 * ======================================================================== */
	
	/* Test 1-10: Simple additions */
	result = safe_add(0, 0);
	assert(result == 0);
	
	result = safe_add(1, 1);
	assert(result == 2);
	
	result = safe_add(10, 20);
	assert(result == 30);
	
	result = safe_add(100, 200);
	assert(result == 300);
	
	result = safe_add(255, 255);
	assert(result == 510);
	
	result = safe_add(1000, 2000);
	assert(result == 3000);
	
	result = safe_add(12345, 67890);
	assert(result == 80235);
	
	result = safe_add(99999, 11111);
	assert(result == 111110);
	
	result = safe_add(500000, 500000);
	assert(result == 1000000);
	
	result = safe_add(1234567, 7654321);
	assert(result == 8888888);
	
	/* Test 11-20: Addition with zero */
	result = safe_add(0, 42);
	assert(result == 42);
	
	result = safe_add(42, 0);
	assert(result == 42);
	
	result = safe_add(0, 12345);
	assert(result == 12345);
	
	result = safe_add(99999, 0);
	assert(result == 99999);
	
	result = safe_add(0, 1000000);
	assert(result == 1000000);
	
	result = safe_add(SIZE_MAX / 2, 0);
	assert(result == SIZE_MAX / 2);
	
	result = safe_add(0, SIZE_MAX / 4);
	assert(result == SIZE_MAX / 4);
	
	result = safe_add(0, 0);
	assert(result == 0);
	
	result = safe_add(SIZE_MAX - 1, 0);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(0, SIZE_MAX - 100);
	assert(result == SIZE_MAX - 100);
	
	/* Test 21-40: Powers of 2 */
	result = safe_add(1, 1);
	assert(result == 2);
	
	result = safe_add(2, 2);
	assert(result == 4);
	
	result = safe_add(4, 4);
	assert(result == 8);
	
	result = safe_add(8, 8);
	assert(result == 16);
	
	result = safe_add(16, 16);
	assert(result == 32);
	
	result = safe_add(32, 32);
	assert(result == 64);
	
	result = safe_add(64, 64);
	assert(result == 128);
	
	result = safe_add(128, 128);
	assert(result == 256);
	
	result = safe_add(256, 256);
	assert(result == 512);
	
	result = safe_add(512, 512);
	assert(result == 1024);
	
	result = safe_add(1024, 1024);
	assert(result == 2048);
	
	result = safe_add(2048, 2048);
	assert(result == 4096);
	
	result = safe_add(4096, 4096);
	assert(result == 8192);
	
	result = safe_add(8192, 8192);
	assert(result == 16384);
	
	result = safe_add(16384, 16384);
	assert(result == 32768);
	
	result = safe_add(32768, 32768);
	assert(result == 65536);
	
	result = safe_add(65536, 65536);
	assert(result == 131072);
	
	result = safe_add(131072, 131072);
	assert(result == 262144);
	
	result = safe_add(262144, 262144);
	assert(result == 524288);
	
	result = safe_add(524288, 524288);
	assert(result == 1048576);
	
	/* Test 41-60: Small increments */
	result = safe_add(1, 2);
	assert(result == 3);
	
	result = safe_add(2, 3);
	assert(result == 5);
	
	result = safe_add(3, 4);
	assert(result == 7);
	
	result = safe_add(4, 5);
	assert(result == 9);
	
	result = safe_add(5, 6);
	assert(result == 11);
	
	result = safe_add(6, 7);
	assert(result == 13);
	
	result = safe_add(7, 8);
	assert(result == 15);
	
	result = safe_add(8, 9);
	assert(result == 17);
	
	result = safe_add(9, 10);
	assert(result == 19);
	
	result = safe_add(10, 11);
	assert(result == 21);
	
	result = safe_add(11, 12);
	assert(result == 23);
	
	result = safe_add(12, 13);
	assert(result == 25);
	
	result = safe_add(13, 14);
	assert(result == 27);
	
	result = safe_add(14, 15);
	assert(result == 29);
	
	result = safe_add(15, 16);
	assert(result == 31);
	
	result = safe_add(16, 17);
	assert(result == 33);
	
	result = safe_add(17, 18);
	assert(result == 35);
	
	result = safe_add(18, 19);
	assert(result == 37);
	
	result = safe_add(19, 20);
	assert(result == 39);
	
	result = safe_add(20, 21);
	assert(result == 41);
	
	/* Test 61-80: Medium values */
	result = safe_add(10000, 20000);
	assert(result == 30000);
	
	result = safe_add(50000, 50000);
	assert(result == 100000);
	
	result = safe_add(100000, 100000);
	assert(result == 200000);
	
	result = safe_add(250000, 250000);
	assert(result == 500000);
	
	result = safe_add(500000, 500000);
	assert(result == 1000000);
	
	result = safe_add(1000000, 1000000);
	assert(result == 2000000);
	
	result = safe_add(2000000, 2000000);
	assert(result == 4000000);
	
	result = safe_add(5000000, 5000000);
	assert(result == 10000000);
	
	result = safe_add(10000000, 10000000);
	assert(result == 20000000);
	
	result = safe_add(25000000, 25000000);
	assert(result == 50000000);
	
	result = safe_add(50000000, 50000000);
	assert(result == 100000000);
	
	result = safe_add(100000000, 100000000);
	assert(result == 200000000);
	
	result = safe_add(123456789, 987654321);
	assert(result == 1111111110);
	
	result = safe_add(111111111, 222222222);
	assert(result == 333333333);
	
	result = safe_add(333333333, 444444444);
	assert(result == 777777777);
	
	result = safe_add(555555555, 666666666);
	assert(result == 1222222221);
	
	result = safe_add(777777777, 888888888);
	assert(result == 1666666665);
	
	result = safe_add(999999999, 1);
	assert(result == 1000000000);
	
	result = safe_add(1, 999999999);
	assert(result == 1000000000);
	
	result = safe_add(12345, 98765);
	assert(result == 111110);
	
	/* Test 81-100: Large but safe values */
	result = safe_add(SIZE_MAX / 4, SIZE_MAX / 4);
	assert(result == SIZE_MAX / 2);
	
	result = safe_add(SIZE_MAX / 8, SIZE_MAX / 8);
	assert(result == SIZE_MAX / 4);
	
	result = safe_add(SIZE_MAX / 16, SIZE_MAX / 16);
	assert(result == SIZE_MAX / 8);
	
	result = safe_add(SIZE_MAX / 32, SIZE_MAX / 32);
	assert(result == SIZE_MAX / 16);
	
	result = safe_add(SIZE_MAX / 64, SIZE_MAX / 64);
	assert(result == SIZE_MAX / 32);
	
	result = safe_add(SIZE_MAX / 128, SIZE_MAX / 128);
	assert(result == SIZE_MAX / 64);
	
	result = safe_add(SIZE_MAX / 256, SIZE_MAX / 256);
	assert(result == SIZE_MAX / 128);
	
	result = safe_add(SIZE_MAX / 512, SIZE_MAX / 512);
	assert(result == SIZE_MAX / 256);
	
	result = safe_add(SIZE_MAX / 1024, SIZE_MAX / 1024);
	assert(result == SIZE_MAX / 512);
	
	result = safe_add(SIZE_MAX / 3, SIZE_MAX / 3);
	assert(result == (SIZE_MAX / 3) * 2);
	
	result = safe_add(SIZE_MAX / 5, SIZE_MAX / 5);
	assert(result == (SIZE_MAX / 5) * 2);
	
	result = safe_add(SIZE_MAX / 7, SIZE_MAX / 7);
	assert(result == (SIZE_MAX / 7) * 2);
	
	result = safe_add(SIZE_MAX / 10, SIZE_MAX / 10);
	assert(result == (SIZE_MAX / 10) * 2);
	
	result = safe_add(SIZE_MAX / 100, SIZE_MAX / 100);
	assert(result == (SIZE_MAX / 100) * 2);
	
	result = safe_add(SIZE_MAX / 1000, SIZE_MAX / 1000);
	assert(result == (SIZE_MAX / 1000) * 2);
	
	result = safe_add(SIZE_MAX / 10000, SIZE_MAX / 10000);
	assert(result == (SIZE_MAX / 10000) * 2);
	
	result = safe_add(SIZE_MAX / 100000, SIZE_MAX / 100000);
	assert(result == (SIZE_MAX / 100000) * 2);
	
	result = safe_add(SIZE_MAX / 1000000, SIZE_MAX / 1000000);
	assert(result == (SIZE_MAX / 1000000) * 2);
	
	result = safe_add(SIZE_MAX / 10000000, SIZE_MAX / 10000000);
	assert(result == (SIZE_MAX / 10000000) * 2);
	
	result = safe_add(SIZE_MAX / 100000000, SIZE_MAX / 100000000);
	assert(result == (SIZE_MAX / 100000000) * 2);
	
	/* ========================================================================
	 * CATEGORY 2: Edge Cases Near SIZE_MAX (Tests 101-300)
	 * Testing boundary conditions near maximum value
	 * ======================================================================== */
	
	/* Test 101-120: SIZE_MAX - small values */
	result = safe_add(SIZE_MAX - 1, 1);
	assert(result == SIZE_MAX);
	
	result = safe_add(1, SIZE_MAX - 1);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 2, 2);
	assert(result == SIZE_MAX);
	
	result = safe_add(2, SIZE_MAX - 2);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 3, 3);
	assert(result == SIZE_MAX);
	
	result = safe_add(3, SIZE_MAX - 3);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 4, 4);
	assert(result == SIZE_MAX);
	
	result = safe_add(4, SIZE_MAX - 4);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 5, 5);
	assert(result == SIZE_MAX);
	
	result = safe_add(5, SIZE_MAX - 5);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 10, 10);
	assert(result == SIZE_MAX);
	
	result = safe_add(10, SIZE_MAX - 10);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 50, 50);
	assert(result == SIZE_MAX);
	
	result = safe_add(50, SIZE_MAX - 50);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 100, 100);
	assert(result == SIZE_MAX);
	
	result = safe_add(100, SIZE_MAX - 100);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 255, 255);
	assert(result == SIZE_MAX);
	
	result = safe_add(255, SIZE_MAX - 255);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 1000, 1000);
	assert(result == SIZE_MAX);
	
	result = safe_add(1000, SIZE_MAX - 1000);
	assert(result == SIZE_MAX);
	
	/* Test 121-140: SIZE_MAX - medium values */
	result = safe_add(SIZE_MAX - 10000, 10000);
	assert(result == SIZE_MAX);
	
	result = safe_add(10000, SIZE_MAX - 10000);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 65536, 65536);
	assert(result == SIZE_MAX);
	
	result = safe_add(65536, SIZE_MAX - 65536);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 100000, 100000);
	assert(result == SIZE_MAX);
	
	result = safe_add(100000, SIZE_MAX - 100000);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 1000000, 1000000);
	assert(result == SIZE_MAX);
	
	result = safe_add(1000000, SIZE_MAX - 1000000);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 10000000, 10000000);
	assert(result == SIZE_MAX);
	
	result = safe_add(10000000, SIZE_MAX - 10000000);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 100000000, 100000000);
	assert(result == SIZE_MAX);
	
	result = safe_add(100000000, SIZE_MAX - 100000000);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 123456789, 123456789);
	assert(result == SIZE_MAX);
	
	result = safe_add(123456789, SIZE_MAX - 123456789);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 987654321, 987654321);
	assert(result == SIZE_MAX);
	
	result = safe_add(987654321, SIZE_MAX - 987654321);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 1234567890, 1234567890);
	assert(result == SIZE_MAX);
	
	result = safe_add(1234567890, SIZE_MAX - 1234567890);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 2147483647, 2147483647);
	assert(result == SIZE_MAX);
	
	result = safe_add(2147483647, SIZE_MAX - 2147483647);
	assert(result == SIZE_MAX);
	
	/* Test 141-160: Safe additions close to SIZE_MAX */
	result = safe_add(SIZE_MAX - 1, 0);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(0, SIZE_MAX - 1);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(SIZE_MAX - 2, 0);
	assert(result == SIZE_MAX - 2);
	
	result = safe_add(SIZE_MAX - 2, 1);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(1, SIZE_MAX - 2);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(SIZE_MAX - 10, 5);
	assert(result == SIZE_MAX - 5);
	
	result = safe_add(5, SIZE_MAX - 10);
	assert(result == SIZE_MAX - 5);
	
	result = safe_add(SIZE_MAX - 100, 50);
	assert(result == SIZE_MAX - 50);
	
	result = safe_add(50, SIZE_MAX - 100);
	assert(result == SIZE_MAX - 50);
	
	result = safe_add(SIZE_MAX - 1000, 500);
	assert(result == SIZE_MAX - 500);
	
	result = safe_add(500, SIZE_MAX - 1000);
	assert(result == SIZE_MAX - 500);
	
	result = safe_add(SIZE_MAX - 10000, 5000);
	assert(result == SIZE_MAX - 5000);
	
	result = safe_add(5000, SIZE_MAX - 10000);
	assert(result == SIZE_MAX - 5000);
	
	result = safe_add(SIZE_MAX - 100000, 50000);
	assert(result == SIZE_MAX - 50000);
	
	result = safe_add(50000, SIZE_MAX - 100000);
	assert(result == SIZE_MAX - 50000);
	
	result = safe_add(SIZE_MAX - 1000000, 500000);
	assert(result == SIZE_MAX - 500000);
	
	result = safe_add(500000, SIZE_MAX - 1000000);
	assert(result == SIZE_MAX - 500000);
	
	result = safe_add(SIZE_MAX - 10000000, 5000000);
	assert(result == SIZE_MAX - 5000000);
	
	result = safe_add(5000000, SIZE_MAX - 10000000);
	assert(result == SIZE_MAX - 5000000);
	
	result = safe_add(SIZE_MAX - 100000000, 50000000);
	assert(result == SIZE_MAX - 50000000);
	
	/* Test 161-180: Fractional SIZE_MAX operations */
	result = safe_add(SIZE_MAX / 2, 0);
	assert(result == SIZE_MAX / 2);
	
	result = safe_add(0, SIZE_MAX / 2);
	assert(result == SIZE_MAX / 2);
	
	result = safe_add(SIZE_MAX / 2, 1);
	assert(result == (SIZE_MAX / 2) + 1);
	
	result = safe_add(1, SIZE_MAX / 2);
	assert(result == (SIZE_MAX / 2) + 1);
	
	result = safe_add(SIZE_MAX / 2, 10);
	assert(result == (SIZE_MAX / 2) + 10);
	
	result = safe_add(10, SIZE_MAX / 2);
	assert(result == (SIZE_MAX / 2) + 10);
	
	result = safe_add(SIZE_MAX / 2, 100);
	assert(result == (SIZE_MAX / 2) + 100);
	
	result = safe_add(100, SIZE_MAX / 2);
	assert(result == (SIZE_MAX / 2) + 100);
	
	result = safe_add(SIZE_MAX / 2, 1000);
	assert(result == (SIZE_MAX / 2) + 1000);
	
	result = safe_add(1000, SIZE_MAX / 2);
	assert(result == (SIZE_MAX / 2) + 1000);
	
	result = safe_add(SIZE_MAX / 2, 10000);
	assert(result == (SIZE_MAX / 2) + 10000);
	
	result = safe_add(10000, SIZE_MAX / 2);
	assert(result == (SIZE_MAX / 2) + 10000);
	
	result = safe_add(SIZE_MAX / 3, 0);
	assert(result == SIZE_MAX / 3);
	
	result = safe_add(SIZE_MAX / 3, 1);
	assert(result == (SIZE_MAX / 3) + 1);
	
	result = safe_add(SIZE_MAX / 4, 0);
	assert(result == SIZE_MAX / 4);
	
	result = safe_add(SIZE_MAX / 4, 1);
	assert(result == (SIZE_MAX / 4) + 1);
	
	result = safe_add(SIZE_MAX / 5, 0);
	assert(result == SIZE_MAX / 5);
	
	result = safe_add(SIZE_MAX / 5, 1);
	assert(result == (SIZE_MAX / 5) + 1);
	
	result = safe_add(SIZE_MAX / 10, 0);
	assert(result == SIZE_MAX / 10);
	
	result = safe_add(SIZE_MAX / 10, 1);
	assert(result == (SIZE_MAX / 10) + 1);
	
	/* Test 181-220: Various combinations near boundaries */
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 4);
	assert(result == (SIZE_MAX / 2) + (SIZE_MAX / 4));
	
	result = safe_add(SIZE_MAX / 4, SIZE_MAX / 4);
	assert(result == SIZE_MAX / 2);
	
	result = safe_add(SIZE_MAX / 8, SIZE_MAX / 4);
	assert(result == (SIZE_MAX / 8) + (SIZE_MAX / 4));
	
	result = safe_add(SIZE_MAX / 3, SIZE_MAX / 6);
	assert(result == SIZE_MAX / 2);
	
	result = safe_add(SIZE_MAX / 5, SIZE_MAX / 5);
	assert(result == (SIZE_MAX / 5) * 2);
	
	result = safe_add(SIZE_MAX / 6, SIZE_MAX / 6);
	assert(result == SIZE_MAX / 3);
	
	result = safe_add(SIZE_MAX / 7, SIZE_MAX / 7);
	assert(result == (SIZE_MAX / 7) * 2);
	
	result = safe_add(SIZE_MAX / 8, SIZE_MAX / 8);
	assert(result == SIZE_MAX / 4);
	
	result = safe_add(SIZE_MAX / 9, SIZE_MAX / 9);
	assert(result == (SIZE_MAX / 9) * 2);
	
	result = safe_add(SIZE_MAX / 10, SIZE_MAX / 10);
	assert(result == SIZE_MAX / 5);
	
	result = safe_add(SIZE_MAX / 2 - 1, SIZE_MAX / 2 - 1);
	assert(result == SIZE_MAX - 2);
	
	result = safe_add(SIZE_MAX / 2 - 10, SIZE_MAX / 2 - 10);
	assert(result == SIZE_MAX - 20);
	
	result = safe_add(SIZE_MAX / 2 - 100, SIZE_MAX / 2 - 100);
	assert(result == SIZE_MAX - 200);
	
	result = safe_add(SIZE_MAX / 2 - 1000, SIZE_MAX / 2 - 1000);
	assert(result == SIZE_MAX - 2000);
	
	result = safe_add(SIZE_MAX / 2 - 10000, SIZE_MAX / 2 - 10000);
	assert(result == SIZE_MAX - 20000);
	
	result = safe_add(SIZE_MAX / 2 - 100000, SIZE_MAX / 2 - 100000);
	assert(result == SIZE_MAX - 200000);
	
	result = safe_add(SIZE_MAX / 2 - 1000000, SIZE_MAX / 2 - 1000000);
	assert(result == SIZE_MAX - 2000000);
	
	result = safe_add(SIZE_MAX / 2 - 10000000, SIZE_MAX / 2 - 10000000);
	assert(result == SIZE_MAX - 20000000);
	
	result = safe_add(SIZE_MAX / 2 - 100000000, SIZE_MAX / 2 - 100000000);
	assert(result == SIZE_MAX - 200000000);
	
	result = safe_add(SIZE_MAX / 2 - 1000000000, SIZE_MAX / 2 - 1000000000);
	assert(result == SIZE_MAX - 2000000000);
	
	result = safe_add(SIZE_MAX / 4, SIZE_MAX / 8);
	assert(result == (SIZE_MAX / 4) + (SIZE_MAX / 8));
	
	result = safe_add(SIZE_MAX / 8, SIZE_MAX / 8);
	assert(result == SIZE_MAX / 4);
	
	result = safe_add(SIZE_MAX / 16, SIZE_MAX / 16);
	assert(result == SIZE_MAX / 8);
	
	result = safe_add(SIZE_MAX / 32, SIZE_MAX / 32);
	assert(result == SIZE_MAX / 16);
	
	result = safe_add(SIZE_MAX / 64, SIZE_MAX / 64);
	assert(result == SIZE_MAX / 32);
	
	result = safe_add(SIZE_MAX / 128, SIZE_MAX / 128);
	assert(result == SIZE_MAX / 64);
	
	result = safe_add(SIZE_MAX / 256, SIZE_MAX / 256);
	assert(result == SIZE_MAX / 128);
	
	result = safe_add(SIZE_MAX / 512, SIZE_MAX / 512);
	assert(result == SIZE_MAX / 256);
	
	result = safe_add(SIZE_MAX / 1024, SIZE_MAX / 1024);
	assert(result == SIZE_MAX / 512);
	
	result = safe_add(SIZE_MAX / 2048, SIZE_MAX / 2048);
	assert(result == SIZE_MAX / 1024);
	
	result = safe_add(SIZE_MAX / 4096, SIZE_MAX / 4096);
	assert(result == SIZE_MAX / 2048);
	
	result = safe_add(SIZE_MAX / 8192, SIZE_MAX / 8192);
	assert(result == SIZE_MAX / 4096);
	
	result = safe_add(SIZE_MAX / 16384, SIZE_MAX / 16384);
	assert(result == SIZE_MAX / 8192);
	
	result = safe_add(SIZE_MAX / 32768, SIZE_MAX / 32768);
	assert(result == SIZE_MAX / 16384);
	
	result = safe_add(SIZE_MAX / 65536, SIZE_MAX / 65536);
	assert(result == SIZE_MAX / 32768);
	
	result = safe_add(SIZE_MAX / 131072, SIZE_MAX / 131072);
	assert(result == SIZE_MAX / 65536);
	
	result = safe_add(SIZE_MAX / 262144, SIZE_MAX / 262144);
	assert(result == SIZE_MAX / 131072);
	
	result = safe_add(SIZE_MAX / 524288, SIZE_MAX / 524288);
	assert(result == SIZE_MAX / 262144);
	
	result = safe_add(SIZE_MAX / 1048576, SIZE_MAX / 1048576);
	assert(result == SIZE_MAX / 524288);
	
	result = safe_add(SIZE_MAX / 2097152, SIZE_MAX / 2097152);
	assert(result == SIZE_MAX / 1048576);
	
	/* Test 221-260: Near-boundary subtraction patterns */
	result = safe_add(SIZE_MAX - 1000, 1);
	assert(result == SIZE_MAX - 999);
	
	result = safe_add(SIZE_MAX - 1000, 2);
	assert(result == SIZE_MAX - 998);
	
	result = safe_add(SIZE_MAX - 1000, 3);
	assert(result == SIZE_MAX - 997);
	
	result = safe_add(SIZE_MAX - 1000, 4);
	assert(result == SIZE_MAX - 996);
	
	result = safe_add(SIZE_MAX - 1000, 5);
	assert(result == SIZE_MAX - 995);
	
	result = safe_add(SIZE_MAX - 1000, 10);
	assert(result == SIZE_MAX - 990);
	
	result = safe_add(SIZE_MAX - 1000, 20);
	assert(result == SIZE_MAX - 980);
	
	result = safe_add(SIZE_MAX - 1000, 50);
	assert(result == SIZE_MAX - 950);
	
	result = safe_add(SIZE_MAX - 1000, 100);
	assert(result == SIZE_MAX - 900);
	
	result = safe_add(SIZE_MAX - 1000, 200);
	assert(result == SIZE_MAX - 800);
	
	result = safe_add(SIZE_MAX - 10000, 1000);
	assert(result == SIZE_MAX - 9000);
	
	result = safe_add(SIZE_MAX - 10000, 2000);
	assert(result == SIZE_MAX - 8000);
	
	result = safe_add(SIZE_MAX - 10000, 3000);
	assert(result == SIZE_MAX - 7000);
	
	result = safe_add(SIZE_MAX - 10000, 4000);
	assert(result == SIZE_MAX - 6000);
	
	result = safe_add(SIZE_MAX - 10000, 5000);
	assert(result == SIZE_MAX - 5000);
	
	result = safe_add(SIZE_MAX - 100000, 10000);
	assert(result == SIZE_MAX - 90000);
	
	result = safe_add(SIZE_MAX - 100000, 20000);
	assert(result == SIZE_MAX - 80000);
	
	result = safe_add(SIZE_MAX - 100000, 30000);
	assert(result == SIZE_MAX - 70000);
	
	result = safe_add(SIZE_MAX - 100000, 40000);
	assert(result == SIZE_MAX - 60000);
	
	result = safe_add(SIZE_MAX - 100000, 50000);
	assert(result == SIZE_MAX - 50000);
	
	result = safe_add(SIZE_MAX - 1000000, 100000);
	assert(result == SIZE_MAX - 900000);
	
	result = safe_add(SIZE_MAX - 1000000, 200000);
	assert(result == SIZE_MAX - 800000);
	
	result = safe_add(SIZE_MAX - 1000000, 300000);
	assert(result == SIZE_MAX - 700000);
	
	result = safe_add(SIZE_MAX - 1000000, 400000);
	assert(result == SIZE_MAX - 600000);
	
	result = safe_add(SIZE_MAX - 1000000, 500000);
	assert(result == SIZE_MAX - 500000);
	
	result = safe_add(SIZE_MAX - 10000000, 1000000);
	assert(result == SIZE_MAX - 9000000);
	
	result = safe_add(SIZE_MAX - 10000000, 2000000);
	assert(result == SIZE_MAX - 8000000);
	
	result = safe_add(SIZE_MAX - 10000000, 3000000);
	assert(result == SIZE_MAX - 7000000);
	
	result = safe_add(SIZE_MAX - 10000000, 4000000);
	assert(result == SIZE_MAX - 6000000);
	
	result = safe_add(SIZE_MAX - 10000000, 5000000);
	assert(result == SIZE_MAX - 5000000);
	
	result = safe_add(SIZE_MAX - 100000000, 10000000);
	assert(result == SIZE_MAX - 90000000);
	
	result = safe_add(SIZE_MAX - 100000000, 20000000);
	assert(result == SIZE_MAX - 80000000);
	
	result = safe_add(SIZE_MAX - 100000000, 30000000);
	assert(result == SIZE_MAX - 70000000);
	
	result = safe_add(SIZE_MAX - 100000000, 40000000);
	assert(result == SIZE_MAX - 60000000);
	
	result = safe_add(SIZE_MAX - 100000000, 50000000);
	assert(result == SIZE_MAX - 50000000);
	
	result = safe_add(SIZE_MAX - 500, 250);
	assert(result == SIZE_MAX - 250);
	
	result = safe_add(SIZE_MAX - 5000, 2500);
	assert(result == SIZE_MAX - 2500);
	
	result = safe_add(SIZE_MAX - 50000, 25000);
	assert(result == SIZE_MAX - 25000);
	
	result = safe_add(SIZE_MAX - 500000, 250000);
	assert(result == SIZE_MAX - 250000);
	
	result = safe_add(SIZE_MAX - 5000000, 2500000);
	assert(result == SIZE_MAX - 2500000);
	
	/* Test 261-300: Complex fractional combinations */
	result = safe_add(SIZE_MAX / 3, SIZE_MAX / 3);
	assert(result == (SIZE_MAX / 3) * 2);
	
	result = safe_add(SIZE_MAX / 5, SIZE_MAX / 10);
	assert(result == (SIZE_MAX / 5) + (SIZE_MAX / 10));
	
	result = safe_add(SIZE_MAX / 7, SIZE_MAX / 14);
	assert(result == (SIZE_MAX / 7) + (SIZE_MAX / 14));
	
	result = safe_add(SIZE_MAX / 11, SIZE_MAX / 22);
	assert(result == (SIZE_MAX / 11) + (SIZE_MAX / 22));
	
	result = safe_add(SIZE_MAX / 13, SIZE_MAX / 26);
	assert(result == (SIZE_MAX / 13) + (SIZE_MAX / 26));
	
	result = safe_add(SIZE_MAX / 17, SIZE_MAX / 34);
	assert(result == (SIZE_MAX / 17) + (SIZE_MAX / 34));
	
	result = safe_add(SIZE_MAX / 19, SIZE_MAX / 38);
	assert(result == (SIZE_MAX / 19) + (SIZE_MAX / 38));
	
	result = safe_add(SIZE_MAX / 23, SIZE_MAX / 46);
	assert(result == (SIZE_MAX / 23) + (SIZE_MAX / 46));
	
	result = safe_add(SIZE_MAX / 29, SIZE_MAX / 58);
	assert(result == (SIZE_MAX / 29) + (SIZE_MAX / 58));
	
	result = safe_add(SIZE_MAX / 31, SIZE_MAX / 62);
	assert(result == (SIZE_MAX / 31) + (SIZE_MAX / 62));
	
	result = safe_add(SIZE_MAX / 37, SIZE_MAX / 74);
	assert(result == (SIZE_MAX / 37) + (SIZE_MAX / 74));
	
	result = safe_add(SIZE_MAX / 41, SIZE_MAX / 82);
	assert(result == (SIZE_MAX / 41) + (SIZE_MAX / 82));
	
	result = safe_add(SIZE_MAX / 43, SIZE_MAX / 86);
	assert(result == (SIZE_MAX / 43) + (SIZE_MAX / 86));
	
	result = safe_add(SIZE_MAX / 47, SIZE_MAX / 94);
	assert(result == (SIZE_MAX / 47) + (SIZE_MAX / 94));
	
	result = safe_add(SIZE_MAX / 53, SIZE_MAX / 106);
	assert(result == (SIZE_MAX / 53) + (SIZE_MAX / 106));
	
	result = safe_add(SIZE_MAX / 59, SIZE_MAX / 118);
	assert(result == (SIZE_MAX / 59) + (SIZE_MAX / 118));
	
	result = safe_add(SIZE_MAX / 61, SIZE_MAX / 122);
	assert(result == (SIZE_MAX / 61) + (SIZE_MAX / 122));
	
	result = safe_add(SIZE_MAX / 67, SIZE_MAX / 134);
	assert(result == (SIZE_MAX / 67) + (SIZE_MAX / 134));
	
	result = safe_add(SIZE_MAX / 71, SIZE_MAX / 142);
	assert(result == (SIZE_MAX / 71) + (SIZE_MAX / 142));
	
	result = safe_add(SIZE_MAX / 73, SIZE_MAX / 146);
	assert(result == (SIZE_MAX / 73) + (SIZE_MAX / 146));
	
	result = safe_add(SIZE_MAX / 79, SIZE_MAX / 158);
	assert(result == (SIZE_MAX / 79) + (SIZE_MAX / 158));
	
	result = safe_add(SIZE_MAX / 83, SIZE_MAX / 166);
	assert(result == (SIZE_MAX / 83) + (SIZE_MAX / 166));
	
	result = safe_add(SIZE_MAX / 89, SIZE_MAX / 178);
	assert(result == (SIZE_MAX / 89) + (SIZE_MAX / 178));
	
	result = safe_add(SIZE_MAX / 97, SIZE_MAX / 194);
	assert(result == (SIZE_MAX / 97) + (SIZE_MAX / 194));
	
	result = safe_add(SIZE_MAX / 101, SIZE_MAX / 202);
	assert(result == (SIZE_MAX / 101) + (SIZE_MAX / 202));
	
	result = safe_add(SIZE_MAX / 103, SIZE_MAX / 206);
	assert(result == (SIZE_MAX / 103) + (SIZE_MAX / 206));
	
	result = safe_add(SIZE_MAX / 107, SIZE_MAX / 214);
	assert(result == (SIZE_MAX / 107) + (SIZE_MAX / 214));
	
	result = safe_add(SIZE_MAX / 109, SIZE_MAX / 218);
	assert(result == (SIZE_MAX / 109) + (SIZE_MAX / 218));
	
	result = safe_add(SIZE_MAX / 113, SIZE_MAX / 226);
	assert(result == (SIZE_MAX / 113) + (SIZE_MAX / 226));
	
	result = safe_add(SIZE_MAX / 127, SIZE_MAX / 254);
	assert(result == (SIZE_MAX / 127) + (SIZE_MAX / 254));
	
	result = safe_add(SIZE_MAX / 131, SIZE_MAX / 262);
	assert(result == (SIZE_MAX / 131) + (SIZE_MAX / 262));
	
	result = safe_add(SIZE_MAX / 137, SIZE_MAX / 274);
	assert(result == (SIZE_MAX / 137) + (SIZE_MAX / 274));
	
	result = safe_add(SIZE_MAX / 139, SIZE_MAX / 278);
	assert(result == (SIZE_MAX / 139) + (SIZE_MAX / 278));
	
	result = safe_add(SIZE_MAX / 149, SIZE_MAX / 298);
	assert(result == (SIZE_MAX / 149) + (SIZE_MAX / 298));
	
	result = safe_add(SIZE_MAX / 151, SIZE_MAX / 302);
	assert(result == (SIZE_MAX / 151) + (SIZE_MAX / 302));
	
	result = safe_add(SIZE_MAX / 157, SIZE_MAX / 314);
	assert(result == (SIZE_MAX / 157) + (SIZE_MAX / 314));
	
	result = safe_add(SIZE_MAX / 163, SIZE_MAX / 326);
	assert(result == (SIZE_MAX / 163) + (SIZE_MAX / 326));
	
	result = safe_add(SIZE_MAX / 167, SIZE_MAX / 334);
	assert(result == (SIZE_MAX / 167) + (SIZE_MAX / 334));
	
	result = safe_add(SIZE_MAX / 173, SIZE_MAX / 346);
	assert(result == (SIZE_MAX / 173) + (SIZE_MAX / 346));
	
	result = safe_add(SIZE_MAX / 179, SIZE_MAX / 358);
	assert(result == (SIZE_MAX / 179) + (SIZE_MAX / 358));
	
	/* ========================================================================
	 * CATEGORY 3: Commutative Property Tests (Tests 301-400)
	 * Verify a + b == b + a for various combinations
	 * ======================================================================== */
	
	/* Test 301-320: Small value commutativity */
	result = safe_add(1, 2);
	assert(result == safe_add(2, 1));
	
	result = safe_add(3, 7);
	assert(result == safe_add(7, 3));
	
	result = safe_add(10, 25);
	assert(result == safe_add(25, 10));
	
	result = safe_add(50, 75);
	assert(result == safe_add(75, 50));
	
	result = safe_add(100, 200);
	assert(result == safe_add(200, 100));
	
	result = safe_add(123, 456);
	assert(result == safe_add(456, 123));
	
	result = safe_add(789, 321);
	assert(result == safe_add(321, 789));
	
	result = safe_add(1000, 2000);
	assert(result == safe_add(2000, 1000));
	
	result = safe_add(5555, 7777);
	assert(result == safe_add(7777, 5555));
	
	result = safe_add(9999, 1111);
	assert(result == safe_add(1111, 9999));
	
	result = safe_add(12345, 54321);
	assert(result == safe_add(54321, 12345));
	
	result = safe_add(98765, 56789);
	assert(result == safe_add(56789, 98765));
	
	result = safe_add(111111, 222222);
	assert(result == safe_add(222222, 111111));
	
	result = safe_add(333333, 444444);
	assert(result == safe_add(444444, 333333));
	
	result = safe_add(555555, 666666);
	assert(result == safe_add(666666, 555555));
	
	result = safe_add(777777, 888888);
	assert(result == safe_add(888888, 777777));
	
	result = safe_add(999999, 123456);
	assert(result == safe_add(123456, 999999));
	
	result = safe_add(1234567, 7654321);
	assert(result == safe_add(7654321, 1234567));
	
	result = safe_add(9876543, 3456789);
	assert(result == safe_add(3456789, 9876543));
	
	result = safe_add(11111111, 22222222);
	assert(result == safe_add(22222222, 11111111));
	
	/* Test 321-340: Medium value commutativity */
	result = safe_add(10000, 50000);
	assert(result == safe_add(50000, 10000));
	
	result = safe_add(100000, 250000);
	assert(result == safe_add(250000, 100000));
	
	result = safe_add(500000, 750000);
	assert(result == safe_add(750000, 500000));
	
	result = safe_add(1000000, 2500000);
	assert(result == safe_add(2500000, 1000000));
	
	result = safe_add(5000000, 7500000);
	assert(result == safe_add(7500000, 5000000));
	
	result = safe_add(10000000, 25000000);
	assert(result == safe_add(25000000, 10000000));
	
	result = safe_add(50000000, 75000000);
	assert(result == safe_add(75000000, 50000000));
	
	result = safe_add(100000000, 250000000);
	assert(result == safe_add(250000000, 100000000));
	
	result = safe_add(123456789, 987654321);
	assert(result == safe_add(987654321, 123456789));
	
	result = safe_add(234567890, 876543210);
	assert(result == safe_add(876543210, 234567890));
	
	result = safe_add(345678901, 765432109);
	assert(result == safe_add(765432109, 345678901));
	
	result = safe_add(456789012, 654321098);
	assert(result == safe_add(654321098, 456789012));
	
	result = safe_add(567890123, 543210987);
	assert(result == safe_add(543210987, 567890123));
	
	result = safe_add(678901234, 432109876);
	assert(result == safe_add(432109876, 678901234));
	
	result = safe_add(789012345, 321098765);
	assert(result == safe_add(321098765, 789012345));
	
	result = safe_add(890123456, 210987654);
	assert(result == safe_add(210987654, 890123456));
	
	result = safe_add(901234567, 109876543);
	assert(result == safe_add(109876543, 901234567));
	
	result = safe_add(1111111111, 2222222222);
	assert(result == safe_add(2222222222, 1111111111));
	
	result = safe_add(SIZE_MAX / 10, SIZE_MAX / 20);
	assert(result == safe_add(SIZE_MAX / 20, SIZE_MAX / 10));
	
	result = safe_add(SIZE_MAX / 100, SIZE_MAX / 200);
	assert(result == safe_add(SIZE_MAX / 200, SIZE_MAX / 100));
	
	/* Test 341-360: Large value commutativity */
	result = safe_add(SIZE_MAX / 2, 1000);
	assert(result == safe_add(1000, SIZE_MAX / 2));
	
	result = safe_add(SIZE_MAX / 3, 5000);
	assert(result == safe_add(5000, SIZE_MAX / 3));
	
	result = safe_add(SIZE_MAX / 4, 10000);
	assert(result == safe_add(10000, SIZE_MAX / 4));
	
	result = safe_add(SIZE_MAX / 5, 50000);
	assert(result == safe_add(50000, SIZE_MAX / 5));
	
	result = safe_add(SIZE_MAX / 6, 100000);
	assert(result == safe_add(100000, SIZE_MAX / 6));
	
	result = safe_add(SIZE_MAX / 7, 500000);
	assert(result == safe_add(500000, SIZE_MAX / 7));
	
	result = safe_add(SIZE_MAX / 8, 1000000);
	assert(result == safe_add(1000000, SIZE_MAX / 8));
	
	result = safe_add(SIZE_MAX / 9, 5000000);
	assert(result == safe_add(5000000, SIZE_MAX / 9));
	
	result = safe_add(SIZE_MAX / 10, 10000000);
	assert(result == safe_add(10000000, SIZE_MAX / 10));
	
	result = safe_add(SIZE_MAX / 11, 50000000);
	assert(result == safe_add(50000000, SIZE_MAX / 11));
	
	result = safe_add(SIZE_MAX / 12, 100000000);
	assert(result == safe_add(100000000, SIZE_MAX / 12));
	
	result = safe_add(SIZE_MAX / 13, SIZE_MAX / 26);
	assert(result == safe_add(SIZE_MAX / 26, SIZE_MAX / 13));
	
	result = safe_add(SIZE_MAX / 15, SIZE_MAX / 30);
	assert(result == safe_add(SIZE_MAX / 30, SIZE_MAX / 15));
	
	result = safe_add(SIZE_MAX / 17, SIZE_MAX / 34);
	assert(result == safe_add(SIZE_MAX / 34, SIZE_MAX / 17));
	
	result = safe_add(SIZE_MAX / 19, SIZE_MAX / 38);
	assert(result == safe_add(SIZE_MAX / 38, SIZE_MAX / 19));
	
	result = safe_add(SIZE_MAX / 21, SIZE_MAX / 42);
	assert(result == safe_add(SIZE_MAX / 42, SIZE_MAX / 21));
	
	result = safe_add(SIZE_MAX / 23, SIZE_MAX / 46);
	assert(result == safe_add(SIZE_MAX / 46, SIZE_MAX / 23));
	
	result = safe_add(SIZE_MAX / 25, SIZE_MAX / 50);
	assert(result == safe_add(SIZE_MAX / 50, SIZE_MAX / 25));
	
	result = safe_add(SIZE_MAX / 27, SIZE_MAX / 54);
	assert(result == safe_add(SIZE_MAX / 54, SIZE_MAX / 27));
	
	result = safe_add(SIZE_MAX / 29, SIZE_MAX / 58);
	assert(result == safe_add(SIZE_MAX / 58, SIZE_MAX / 29));
	
	/* Test 361-380: Boundary commutativity */
	result = safe_add(SIZE_MAX - 1, 1);
	assert(result == safe_add(1, SIZE_MAX - 1));
	
	result = safe_add(SIZE_MAX - 10, 10);
	assert(result == safe_add(10, SIZE_MAX - 10));
	
	result = safe_add(SIZE_MAX - 100, 100);
	assert(result == safe_add(100, SIZE_MAX - 100));
	
	result = safe_add(SIZE_MAX - 1000, 1000);
	assert(result == safe_add(1000, SIZE_MAX - 1000));
	
	result = safe_add(SIZE_MAX - 10000, 10000);
	assert(result == safe_add(10000, SIZE_MAX - 10000));
	
	result = safe_add(SIZE_MAX - 100000, 100000);
	assert(result == safe_add(100000, SIZE_MAX - 100000));
	
	result = safe_add(SIZE_MAX - 1000000, 1000000);
	assert(result == safe_add(1000000, SIZE_MAX - 1000000));
	
	result = safe_add(SIZE_MAX - 10000000, 10000000);
	assert(result == safe_add(10000000, SIZE_MAX - 10000000));
	
	result = safe_add(SIZE_MAX - 100000000, 100000000);
	assert(result == safe_add(100000000, SIZE_MAX - 100000000));
	
	result = safe_add(SIZE_MAX - 1000000000, 1000000000);
	assert(result == safe_add(1000000000, SIZE_MAX - 1000000000));
	
	result = safe_add(SIZE_MAX - 5, 5);
	assert(result == safe_add(5, SIZE_MAX - 5));
	
	result = safe_add(SIZE_MAX - 50, 50);
	assert(result == safe_add(50, SIZE_MAX - 50));
	
	result = safe_add(SIZE_MAX - 500, 500);
	assert(result == safe_add(500, SIZE_MAX - 500));
	
	result = safe_add(SIZE_MAX - 5000, 5000);
	assert(result == safe_add(5000, SIZE_MAX - 5000));
	
	result = safe_add(SIZE_MAX - 50000, 50000);
	assert(result == safe_add(50000, SIZE_MAX - 50000));
	
	result = safe_add(SIZE_MAX - 500000, 500000);
	assert(result == safe_add(500000, SIZE_MAX - 500000));
	
	result = safe_add(SIZE_MAX - 5000000, 5000000);
	assert(result == safe_add(5000000, SIZE_MAX - 5000000));
	
	result = safe_add(SIZE_MAX - 50000000, 50000000);
	assert(result == safe_add(50000000, SIZE_MAX - 50000000));
	
	result = safe_add(SIZE_MAX - 500000000, 500000000);
	assert(result == safe_add(500000000, SIZE_MAX - 500000000));
	
	result = safe_add(SIZE_MAX / 2 - 1, SIZE_MAX / 2 - 1);
	assert(result == SIZE_MAX - 2);
	
	/* Test 381-400: Mixed commutativity */
	result = safe_add(1, SIZE_MAX - 1000);
	assert(result == safe_add(SIZE_MAX - 1000, 1));
	
	result = safe_add(100, SIZE_MAX - 10000);
	assert(result == safe_add(SIZE_MAX - 10000, 100));
	
	result = safe_add(1000, SIZE_MAX - 100000);
	assert(result == safe_add(SIZE_MAX - 100000, 1000));
	
	result = safe_add(10000, SIZE_MAX - 1000000);
	assert(result == safe_add(SIZE_MAX - 1000000, 10000));
	
	result = safe_add(100000, SIZE_MAX - 10000000);
	assert(result == safe_add(SIZE_MAX - 10000000, 100000));
	
	result = safe_add(SIZE_MAX / 4, SIZE_MAX / 8);
	assert(result == safe_add(SIZE_MAX / 8, SIZE_MAX / 4));
	
	result = safe_add(SIZE_MAX / 16, SIZE_MAX / 32);
	assert(result == safe_add(SIZE_MAX / 32, SIZE_MAX / 16));
	
	result = safe_add(SIZE_MAX / 64, SIZE_MAX / 128);
	assert(result == safe_add(SIZE_MAX / 128, SIZE_MAX / 64));
	
	result = safe_add(SIZE_MAX / 256, SIZE_MAX / 512);
	assert(result == safe_add(SIZE_MAX / 512, SIZE_MAX / 256));
	
	result = safe_add(SIZE_MAX / 1024, SIZE_MAX / 2048);
	assert(result == safe_add(SIZE_MAX / 2048, SIZE_MAX / 1024));
	
	result = safe_add(SIZE_MAX / 3, SIZE_MAX / 9);
	assert(result == safe_add(SIZE_MAX / 9, SIZE_MAX / 3));
	
	result = safe_add(SIZE_MAX / 5, SIZE_MAX / 15);
	assert(result == safe_add(SIZE_MAX / 15, SIZE_MAX / 5));
	
	result = safe_add(SIZE_MAX / 7, SIZE_MAX / 21);
	assert(result == safe_add(SIZE_MAX / 21, SIZE_MAX / 7));
	
	result = safe_add(SIZE_MAX / 11, SIZE_MAX / 33);
	assert(result == safe_add(SIZE_MAX / 33, SIZE_MAX / 11));
	
	result = safe_add(SIZE_MAX / 13, SIZE_MAX / 39);
	assert(result == safe_add(SIZE_MAX / 39, SIZE_MAX / 13));
	
	result = safe_add(SIZE_MAX / 17, SIZE_MAX / 51);
	assert(result == safe_add(SIZE_MAX / 51, SIZE_MAX / 17));
	
	result = safe_add(SIZE_MAX / 19, SIZE_MAX / 57);
	assert(result == safe_add(SIZE_MAX / 57, SIZE_MAX / 19));
	
	result = safe_add(SIZE_MAX / 23, SIZE_MAX / 69);
	assert(result == safe_add(SIZE_MAX / 69, SIZE_MAX / 23));
	
	result = safe_add(SIZE_MAX / 29, SIZE_MAX / 87);
	assert(result == safe_add(SIZE_MAX / 87, SIZE_MAX / 29));
	
	result = safe_add(SIZE_MAX / 31, SIZE_MAX / 93);
	assert(result == safe_add(SIZE_MAX / 93, SIZE_MAX / 31));
	
	/* ========================================================================
	 * CATEGORY 4: Associative Property Tests (Tests 401-500)
	 * Verify (a + b) + c can be computed safely in different orders
	 * ======================================================================== */
	
	/* Test 401-420: Simple associativity */
	result = safe_add(safe_add(1, 2), 3);
	assert(result == 6);
	
	result = safe_add(safe_add(10, 20), 30);
	assert(result == 60);
	
	result = safe_add(safe_add(100, 200), 300);
	assert(result == 600);
	
	result = safe_add(safe_add(1000, 2000), 3000);
	assert(result == 6000);
	
	result = safe_add(safe_add(5, 10), 15);
	assert(result == 30);
	
	result = safe_add(safe_add(50, 100), 150);
	assert(result == 300);
	
	result = safe_add(safe_add(500, 1000), 1500);
	assert(result == 3000);
	
	result = safe_add(safe_add(5000, 10000), 15000);
	assert(result == 30000);
	
	result = safe_add(safe_add(7, 14), 21);
	assert(result == 42);
	
	result = safe_add(safe_add(70, 140), 210);
	assert(result == 420);
	
	result = safe_add(safe_add(700, 1400), 2100);
	assert(result == 4200);
	
	result = safe_add(safe_add(7000, 14000), 21000);
	assert(result == 42000);
	
	result = safe_add(safe_add(11, 22), 33);
	assert(result == 66);
	
	result = safe_add(safe_add(110, 220), 330);
	assert(result == 660);
	
	result = safe_add(safe_add(1100, 2200), 3300);
	assert(result == 6600);
	
	result = safe_add(safe_add(11000, 22000), 33000);
	assert(result == 66000);
	
	result = safe_add(safe_add(13, 26), 39);
	assert(result == 78);
	
	result = safe_add(safe_add(130, 260), 390);
	assert(result == 780);
	
	result = safe_add(safe_add(1300, 2600), 3900);
	assert(result == 7800);
	
	result = safe_add(safe_add(13000, 26000), 39000);
	assert(result == 78000);
	
	/* Test 421-440: Chained additions */
	result = safe_add(safe_add(safe_add(1, 2), 3), 4);
	assert(result == 10);
	
	result = safe_add(safe_add(safe_add(10, 20), 30), 40);
	assert(result == 100);
	
	result = safe_add(safe_add(safe_add(100, 200), 300), 400);
	assert(result == 1000);
	
	result = safe_add(safe_add(safe_add(1000, 2000), 3000), 4000);
	assert(result == 10000);
	
	result = safe_add(safe_add(safe_add(5, 5), 5), 5);
	assert(result == 20);
	
	result = safe_add(safe_add(safe_add(50, 50), 50), 50);
	assert(result == 200);
	
	result = safe_add(safe_add(safe_add(500, 500), 500), 500);
	assert(result == 2000);
	
	result = safe_add(safe_add(safe_add(5000, 5000), 5000), 5000);
	assert(result == 20000);
	
	result = safe_add(safe_add(safe_add(safe_add(1, 1), 1), 1), 1);
	assert(result == 5);
	
	result = safe_add(safe_add(safe_add(safe_add(10, 10), 10), 10), 10);
	assert(result == 50);
	
	result = safe_add(safe_add(safe_add(safe_add(100, 100), 100), 100), 100);
	assert(result == 500);
	
	result = safe_add(safe_add(safe_add(safe_add(1000, 1000), 1000), 1000), 1000);
	assert(result == 5000);
	
	result = safe_add(safe_add(safe_add(safe_add(safe_add(2, 2), 2), 2), 2), 2);
	assert(result == 12);
	
	result = safe_add(safe_add(safe_add(safe_add(safe_add(20, 20), 20), 20), 20), 20);
	assert(result == 120);
	
	result = safe_add(safe_add(safe_add(safe_add(safe_add(200, 200), 200), 200), 200), 200);
	assert(result == 1200);
	
	result = safe_add(safe_add(safe_add(safe_add(safe_add(2000, 2000), 2000), 2000), 2000), 2000);
	assert(result == 12000);
	
	result = safe_add(safe_add(safe_add(safe_add(safe_add(safe_add(3, 3), 3), 3), 3), 3), 3);
	assert(result == 21);
	
	result = safe_add(safe_add(safe_add(safe_add(safe_add(safe_add(30, 30), 30), 30), 30), 30), 30);
	assert(result == 210);
	
	result = safe_add(safe_add(safe_add(safe_add(safe_add(safe_add(300, 300), 300), 300), 300), 300), 300);
	assert(result == 2100);
	
	result = safe_add(safe_add(safe_add(safe_add(safe_add(safe_add(3000, 3000), 3000), 3000), 3000), 3000), 3000);
	assert(result == 21000);
	
	/* Test 441-460: Large value associativity */
	result = safe_add(safe_add(SIZE_MAX / 10, SIZE_MAX / 10), SIZE_MAX / 10);
	assert(result == (SIZE_MAX / 10) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 100, SIZE_MAX / 100), SIZE_MAX / 100);
	assert(result == (SIZE_MAX / 100) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 1000, SIZE_MAX / 1000), SIZE_MAX / 1000);
	assert(result == (SIZE_MAX / 1000) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 20, SIZE_MAX / 20), SIZE_MAX / 20);
	assert(result == (SIZE_MAX / 20) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 200, SIZE_MAX / 200), SIZE_MAX / 200);
	assert(result == (SIZE_MAX / 200) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 2000, SIZE_MAX / 2000), SIZE_MAX / 2000);
	assert(result == (SIZE_MAX / 2000) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 30, SIZE_MAX / 30), SIZE_MAX / 30);
	assert(result == (SIZE_MAX / 30) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 300, SIZE_MAX / 300), SIZE_MAX / 300);
	assert(result == (SIZE_MAX / 300) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 3000, SIZE_MAX / 3000), SIZE_MAX / 3000);
	assert(result == (SIZE_MAX / 3000) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 40, SIZE_MAX / 40), SIZE_MAX / 40);
	assert(result == (SIZE_MAX / 40) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 400, SIZE_MAX / 400), SIZE_MAX / 400);
	assert(result == (SIZE_MAX / 400) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 4000, SIZE_MAX / 4000), SIZE_MAX / 4000);
	assert(result == (SIZE_MAX / 4000) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 50, SIZE_MAX / 50), SIZE_MAX / 50);
	assert(result == (SIZE_MAX / 50) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 500, SIZE_MAX / 500), SIZE_MAX / 500);
	assert(result == (SIZE_MAX / 500) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 5000, SIZE_MAX / 5000), SIZE_MAX / 5000);
	assert(result == (SIZE_MAX / 5000) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 60, SIZE_MAX / 60), SIZE_MAX / 60);
	assert(result == (SIZE_MAX / 60) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 600, SIZE_MAX / 600), SIZE_MAX / 600);
	assert(result == (SIZE_MAX / 600) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 6000, SIZE_MAX / 6000), SIZE_MAX / 6000);
	assert(result == (SIZE_MAX / 6000) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 70, SIZE_MAX / 70), SIZE_MAX / 70);
	assert(result == (SIZE_MAX / 70) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 700, SIZE_MAX / 700), SIZE_MAX / 700);
	assert(result == (SIZE_MAX / 700) * 3);
	
	/* Test 461-480: Boundary associativity */
	result = safe_add(safe_add(SIZE_MAX - 100, 50), 50);
	assert(result == SIZE_MAX);
	
	result = safe_add(safe_add(SIZE_MAX - 1000, 500), 500);
	assert(result == SIZE_MAX);
	
	result = safe_add(safe_add(SIZE_MAX - 10000, 5000), 5000);
	assert(result == SIZE_MAX);
	
	result = safe_add(safe_add(SIZE_MAX - 100000, 50000), 50000);
	assert(result == SIZE_MAX);
	
	result = safe_add(safe_add(SIZE_MAX - 1000000, 500000), 500000);
	assert(result == SIZE_MAX);
	
	result = safe_add(safe_add(SIZE_MAX - 10000000, 5000000), 5000000);
	assert(result == SIZE_MAX);
	
	result = safe_add(safe_add(SIZE_MAX - 90, 30), 30);
	assert(result == SIZE_MAX - 30);
	
	result = safe_add(safe_add(SIZE_MAX - 900, 300), 300);
	assert(result == SIZE_MAX - 300);
	
	result = safe_add(safe_add(SIZE_MAX - 9000, 3000), 3000);
	assert(result == SIZE_MAX - 3000);
	
	result = safe_add(safe_add(SIZE_MAX - 90000, 30000), 30000);
	assert(result == SIZE_MAX - 30000);
	
	result = safe_add(safe_add(SIZE_MAX - 900000, 300000), 300000);
	assert(result == SIZE_MAX - 300000);
	
	result = safe_add(safe_add(SIZE_MAX - 9000000, 3000000), 3000000);
	assert(result == SIZE_MAX - 3000000);
	
	result = safe_add(safe_add(SIZE_MAX - 80, 20), 20);
	assert(result == SIZE_MAX - 40);
	
	result = safe_add(safe_add(SIZE_MAX - 800, 200), 200);
	assert(result == SIZE_MAX - 400);
	
	result = safe_add(safe_add(SIZE_MAX - 8000, 2000), 2000);
	assert(result == SIZE_MAX - 4000);
	
	result = safe_add(safe_add(SIZE_MAX - 80000, 20000), 20000);
	assert(result == SIZE_MAX - 40000);
	
	result = safe_add(safe_add(SIZE_MAX - 800000, 200000), 200000);
	assert(result == SIZE_MAX - 400000);
	
	result = safe_add(safe_add(SIZE_MAX - 8000000, 2000000), 2000000);
	assert(result == SIZE_MAX - 4000000);
	
	result = safe_add(safe_add(SIZE_MAX - 70, 10), 10);
	assert(result == SIZE_MAX - 50);
	
	result = safe_add(safe_add(SIZE_MAX - 700, 100), 100);
	assert(result == SIZE_MAX - 500);
	
	/* Test 481-500: Mixed associativity patterns */
	result = safe_add(safe_add(1000000, 2000000), 3000000);
	assert(result == 6000000);
	
	result = safe_add(safe_add(SIZE_MAX / 9, SIZE_MAX / 9), SIZE_MAX / 9);
	assert(result == (SIZE_MAX / 9) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 11, SIZE_MAX / 11), SIZE_MAX / 11);
	assert(result == (SIZE_MAX / 11) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 13, SIZE_MAX / 13), SIZE_MAX / 13);
	assert(result == (SIZE_MAX / 13) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 17, SIZE_MAX / 17), SIZE_MAX / 17);
	assert(result == (SIZE_MAX / 17) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 19, SIZE_MAX / 19), SIZE_MAX / 19);
	assert(result == (SIZE_MAX / 19) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 23, SIZE_MAX / 23), SIZE_MAX / 23);
	assert(result == (SIZE_MAX / 23) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 29, SIZE_MAX / 29), SIZE_MAX / 29);
	assert(result == (SIZE_MAX / 29) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 31, SIZE_MAX / 31), SIZE_MAX / 31);
	assert(result == (SIZE_MAX / 31) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 37, SIZE_MAX / 37), SIZE_MAX / 37);
	assert(result == (SIZE_MAX / 37) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 41, SIZE_MAX / 41), SIZE_MAX / 41);
	assert(result == (SIZE_MAX / 41) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 43, SIZE_MAX / 43), SIZE_MAX / 43);
	assert(result == (SIZE_MAX / 43) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 47, SIZE_MAX / 47), SIZE_MAX / 47);
	assert(result == (SIZE_MAX / 47) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 53, SIZE_MAX / 53), SIZE_MAX / 53);
	assert(result == (SIZE_MAX / 53) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 59, SIZE_MAX / 59), SIZE_MAX / 59);
	assert(result == (SIZE_MAX / 59) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 61, SIZE_MAX / 61), SIZE_MAX / 61);
	assert(result == (SIZE_MAX / 61) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 67, SIZE_MAX / 67), SIZE_MAX / 67);
	assert(result == (SIZE_MAX / 67) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 71, SIZE_MAX / 71), SIZE_MAX / 71);
	assert(result == (SIZE_MAX / 71) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 73, SIZE_MAX / 73), SIZE_MAX / 73);
	assert(result == (SIZE_MAX / 73) * 3);
	
	result = safe_add(safe_add(SIZE_MAX / 79, SIZE_MAX / 79), SIZE_MAX / 79);
	assert(result == (SIZE_MAX / 79) * 3);
	
	/* ========================================================================
	 * CATEGORY 5: Identity Property Tests (Tests 501-600)
	 * Verify a + 0 == a for various values
	 * ======================================================================== */
	
	/* Test 501-520: Zero identity with small values */
	result = safe_add(0, 0);
	assert(result == 0);
	
	result = safe_add(1, 0);
	assert(result == 1);
	
	result = safe_add(0, 1);
	assert(result == 1);
	
	result = safe_add(2, 0);
	assert(result == 2);
	
	result = safe_add(0, 2);
	assert(result == 2);
	
	result = safe_add(3, 0);
	assert(result == 3);
	
	result = safe_add(0, 3);
	assert(result == 3);
	
	result = safe_add(4, 0);
	assert(result == 4);
	
	result = safe_add(0, 4);
	assert(result == 4);
	
	result = safe_add(5, 0);
	assert(result == 5);
	
	result = safe_add(0, 5);
	assert(result == 5);
	
	result = safe_add(10, 0);
	assert(result == 10);
	
	result = safe_add(0, 10);
	assert(result == 10);
	
	result = safe_add(100, 0);
	assert(result == 100);
	
	result = safe_add(0, 100);
	assert(result == 100);
	
	result = safe_add(1000, 0);
	assert(result == 1000);
	
	result = safe_add(0, 1000);
	assert(result == 1000);
	
	result = safe_add(10000, 0);
	assert(result == 10000);
	
	result = safe_add(0, 10000);
	assert(result == 10000);
	
	result = safe_add(100000, 0);
	assert(result == 100000);
	
	/* Test 521-540: Zero identity with medium values */
	result = safe_add(0, 100000);
	assert(result == 100000);
	
	result = safe_add(1000000, 0);
	assert(result == 1000000);
	
	result = safe_add(0, 1000000);
	assert(result == 1000000);
	
	result = safe_add(10000000, 0);
	assert(result == 10000000);
	
	result = safe_add(0, 10000000);
	assert(result == 10000000);
	
	result = safe_add(100000000, 0);
	assert(result == 100000000);
	
	result = safe_add(0, 100000000);
	assert(result == 100000000);
	
	result = safe_add(1000000000, 0);
	assert(result == 1000000000);
	
	result = safe_add(0, 1000000000);
	assert(result == 1000000000);
	
	result = safe_add(123456789, 0);
	assert(result == 123456789);
	
	result = safe_add(0, 123456789);
	assert(result == 123456789);
	
	result = safe_add(987654321, 0);
	assert(result == 987654321);
	
	result = safe_add(0, 987654321);
	assert(result == 987654321);
	
	result = safe_add(111111111, 0);
	assert(result == 111111111);
	
	result = safe_add(0, 111111111);
	assert(result == 111111111);
	
	result = safe_add(222222222, 0);
	assert(result == 222222222);
	
	result = safe_add(0, 222222222);
	assert(result == 222222222);
	
	result = safe_add(333333333, 0);
	assert(result == 333333333);
	
	result = safe_add(0, 333333333);
	assert(result == 333333333);
	
	result = safe_add(444444444, 0);
	assert(result == 444444444);
	
	/* Test 541-560: Zero identity with large values */
	result = safe_add(0, 444444444);
	assert(result == 444444444);
	
	result = safe_add(555555555, 0);
	assert(result == 555555555);
	
	result = safe_add(0, 555555555);
	assert(result == 555555555);
	
	result = safe_add(666666666, 0);
	assert(result == 666666666);
	
	result = safe_add(0, 666666666);
	assert(result == 666666666);
	
	result = safe_add(777777777, 0);
	assert(result == 777777777);
	
	result = safe_add(0, 777777777);
	assert(result == 777777777);
	
	result = safe_add(888888888, 0);
	assert(result == 888888888);
	
	result = safe_add(0, 888888888);
	assert(result == 888888888);
	
	result = safe_add(999999999, 0);
	assert(result == 999999999);
	
	result = safe_add(0, 999999999);
	assert(result == 999999999);
	
	result = safe_add(1234567890, 0);
	assert(result == 1234567890);
	
	result = safe_add(0, 1234567890);
	assert(result == 1234567890);
	
	result = safe_add(2147483647, 0);
	assert(result == 2147483647);
	
	result = safe_add(0, 2147483647);
	assert(result == 2147483647);
	
	result = safe_add(SIZE_MAX / 2, 0);
	assert(result == SIZE_MAX / 2);
	
	result = safe_add(0, SIZE_MAX / 2);
	assert(result == SIZE_MAX / 2);
	
	result = safe_add(SIZE_MAX / 3, 0);
	assert(result == SIZE_MAX / 3);
	
	result = safe_add(0, SIZE_MAX / 3);
	assert(result == SIZE_MAX / 3);
	
	result = safe_add(SIZE_MAX / 4, 0);
	assert(result == SIZE_MAX / 4);
	
	/* Test 561-580: Zero identity with fractional SIZE_MAX values */
	result = safe_add(0, SIZE_MAX / 4);
	assert(result == SIZE_MAX / 4);
	
	result = safe_add(SIZE_MAX / 5, 0);
	assert(result == SIZE_MAX / 5);
	
	result = safe_add(0, SIZE_MAX / 5);
	assert(result == SIZE_MAX / 5);
	
	result = safe_add(SIZE_MAX / 6, 0);
	assert(result == SIZE_MAX / 6);
	
	result = safe_add(0, SIZE_MAX / 6);
	assert(result == SIZE_MAX / 6);
	
	result = safe_add(SIZE_MAX / 7, 0);
	assert(result == SIZE_MAX / 7);
	
	result = safe_add(0, SIZE_MAX / 7);
	assert(result == SIZE_MAX / 7);
	
	result = safe_add(SIZE_MAX / 8, 0);
	assert(result == SIZE_MAX / 8);
	
	result = safe_add(0, SIZE_MAX / 8);
	assert(result == SIZE_MAX / 8);
	
	result = safe_add(SIZE_MAX / 9, 0);
	assert(result == SIZE_MAX / 9);
	
	result = safe_add(0, SIZE_MAX / 9);
	assert(result == SIZE_MAX / 9);
	
	result = safe_add(SIZE_MAX / 10, 0);
	assert(result == SIZE_MAX / 10);
	
	result = safe_add(0, SIZE_MAX / 10);
	assert(result == SIZE_MAX / 10);
	
	result = safe_add(SIZE_MAX / 100, 0);
	assert(result == SIZE_MAX / 100);
	
	result = safe_add(0, SIZE_MAX / 100);
	assert(result == SIZE_MAX / 100);
	
	result = safe_add(SIZE_MAX / 1000, 0);
	assert(result == SIZE_MAX / 1000);
	
	result = safe_add(0, SIZE_MAX / 1000);
	assert(result == SIZE_MAX / 1000);
	
	result = safe_add(SIZE_MAX / 10000, 0);
	assert(result == SIZE_MAX / 10000);
	
	result = safe_add(0, SIZE_MAX / 10000);
	assert(result == SIZE_MAX / 10000);
	
	result = safe_add(SIZE_MAX / 100000, 0);
	assert(result == SIZE_MAX / 100000);
	
	/* Test 581-600: Zero identity with boundary values */
	result = safe_add(0, SIZE_MAX / 100000);
	assert(result == SIZE_MAX / 100000);
	
	result = safe_add(SIZE_MAX / 1000000, 0);
	assert(result == SIZE_MAX / 1000000);
	
	result = safe_add(0, SIZE_MAX / 1000000);
	assert(result == SIZE_MAX / 1000000);
	
	result = safe_add(SIZE_MAX - 1, 0);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(0, SIZE_MAX - 1);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(SIZE_MAX - 10, 0);
	assert(result == SIZE_MAX - 10);
	
	result = safe_add(0, SIZE_MAX - 10);
	assert(result == SIZE_MAX - 10);
	
	result = safe_add(SIZE_MAX - 100, 0);
	assert(result == SIZE_MAX - 100);
	
	result = safe_add(0, SIZE_MAX - 100);
	assert(result == SIZE_MAX - 100);
	
	result = safe_add(SIZE_MAX - 1000, 0);
	assert(result == SIZE_MAX - 1000);
	
	result = safe_add(0, SIZE_MAX - 1000);
	assert(result == SIZE_MAX - 1000);
	
	result = safe_add(SIZE_MAX - 10000, 0);
	assert(result == SIZE_MAX - 10000);
	
	result = safe_add(0, SIZE_MAX - 10000);
	assert(result == SIZE_MAX - 10000);
	
	result = safe_add(SIZE_MAX - 100000, 0);
	assert(result == SIZE_MAX - 100000);
	
	result = safe_add(0, SIZE_MAX - 100000);
	assert(result == SIZE_MAX - 100000);
	
	result = safe_add(SIZE_MAX - 1000000, 0);
	assert(result == SIZE_MAX - 1000000);
	
	result = safe_add(0, SIZE_MAX - 1000000);
	assert(result == SIZE_MAX - 1000000);
	
	result = safe_add(SIZE_MAX - 10000000, 0);
	assert(result == SIZE_MAX - 10000000);
	
	result = safe_add(0, SIZE_MAX - 10000000);
	assert(result == SIZE_MAX - 10000000);
	
	result = safe_add(SIZE_MAX - 100000000, 0);
	assert(result == SIZE_MAX - 100000000);
	
	/* ========================================================================
	 * CATEGORY 6: Stress Tests with Powers of 2 (Tests 601-700)
	 * Testing additions involving powers of two
	 * ======================================================================== */
	
	/* Test 601-620: Powers of 2 additions */
	result = safe_add(1, 1);
	assert(result == 2);
	
	result = safe_add(2, 2);
	assert(result == 4);
	
	result = safe_add(4, 4);
	assert(result == 8);
	
	result = safe_add(8, 8);
	assert(result == 16);
	
	result = safe_add(16, 16);
	assert(result == 32);
	
	result = safe_add(32, 32);
	assert(result == 64);
	
	result = safe_add(64, 64);
	assert(result == 128);
	
	result = safe_add(128, 128);
	assert(result == 256);
	
	result = safe_add(256, 256);
	assert(result == 512);
	
	result = safe_add(512, 512);
	assert(result == 1024);
	
	result = safe_add(1024, 1024);
	assert(result == 2048);
	
	result = safe_add(2048, 2048);
	assert(result == 4096);
	
	result = safe_add(4096, 4096);
	assert(result == 8192);
	
	result = safe_add(8192, 8192);
	assert(result == 16384);
	
	result = safe_add(16384, 16384);
	assert(result == 32768);
	
	result = safe_add(32768, 32768);
	assert(result == 65536);
	
	result = safe_add(65536, 65536);
	assert(result == 131072);
	
	result = safe_add(131072, 131072);
	assert(result == 262144);
	
	result = safe_add(262144, 262144);
	assert(result == 524288);
	
	result = safe_add(524288, 524288);
	assert(result == 1048576);
	
	/* Test 621-640: Large powers of 2 */
	result = safe_add(1048576, 1048576);
	assert(result == 2097152);
	
	result = safe_add(2097152, 2097152);
	assert(result == 4194304);
	
	result = safe_add(4194304, 4194304);
	assert(result == 8388608);
	
	result = safe_add(8388608, 8388608);
	assert(result == 16777216);
	
	result = safe_add(16777216, 16777216);
	assert(result == 33554432);
	
	result = safe_add(33554432, 33554432);
	assert(result == 67108864);
	
	result = safe_add(67108864, 67108864);
	assert(result == 134217728);
	
	result = safe_add(134217728, 134217728);
	assert(result == 268435456);
	
	result = safe_add(268435456, 268435456);
	assert(result == 536870912);
	
	result = safe_add(536870912, 536870912);
	assert(result == 1073741824);
	
	result = safe_add(1073741824, 1073741824);
	assert(result == 2147483648ULL);
	
	result = safe_add(1, 2);
	assert(result == 3);
	
	result = safe_add(1, 4);
	assert(result == 5);
	
	result = safe_add(1, 8);
	assert(result == 9);
	
	result = safe_add(1, 16);
	assert(result == 17);
	
	result = safe_add(1, 32);
	assert(result == 33);
	
	result = safe_add(1, 64);
	assert(result == 65);
	
	result = safe_add(1, 128);
	assert(result == 129);
	
	result = safe_add(1, 256);
	assert(result == 257);
	
	result = safe_add(1, 512);
	assert(result == 513);
	
	/* Test 641-660: Mixed powers of 2 */
	result = safe_add(1, 1024);
	assert(result == 1025);
	
	result = safe_add(2, 4);
	assert(result == 6);
	
	result = safe_add(2, 8);
	assert(result == 10);
	
	result = safe_add(2, 16);
	assert(result == 18);
	
	result = safe_add(2, 32);
	assert(result == 34);
	
	result = safe_add(2, 64);
	assert(result == 66);
	
	result = safe_add(2, 128);
	assert(result == 130);
	
	result = safe_add(2, 256);
	assert(result == 258);
	
	result = safe_add(2, 512);
	assert(result == 514);
	
	result = safe_add(2, 1024);
	assert(result == 1026);
	
	result = safe_add(4, 8);
	assert(result == 12);
	
	result = safe_add(4, 16);
	assert(result == 20);
	
	result = safe_add(4, 32);
	assert(result == 36);
	
	result = safe_add(4, 64);
	assert(result == 68);
	
	result = safe_add(4, 128);
	assert(result == 132);
	
	result = safe_add(4, 256);
	assert(result == 260);
	
	result = safe_add(4, 512);
	assert(result == 516);
	
	result = safe_add(4, 1024);
	assert(result == 1028);
	
	result = safe_add(8, 16);
	assert(result == 24);
	
	result = safe_add(8, 32);
	assert(result == 40);
	
	/* Test 661-680: Three powers of 2 combinations */
	result = safe_add(1, safe_add(2, 4));
	assert(result == 7);
	
	result = safe_add(1, safe_add(2, 8));
	assert(result == 11);
	
	result = safe_add(1, safe_add(4, 8));
	assert(result == 13);
	
	result = safe_add(2, safe_add(4, 8));
	assert(result == 14);
	
	result = safe_add(1, safe_add(2, 16));
	assert(result == 19);
	
	result = safe_add(1, safe_add(4, 16));
	assert(result == 21);
	
	result = safe_add(1, safe_add(8, 16));
	assert(result == 25);
	
	result = safe_add(2, safe_add(4, 16));
	assert(result == 22);
	
	result = safe_add(2, safe_add(8, 16));
	assert(result == 26);
	
	result = safe_add(4, safe_add(8, 16));
	assert(result == 28);
	
	result = safe_add(1, safe_add(2, 32));
	assert(result == 35);
	
	result = safe_add(1, safe_add(4, 32));
	assert(result == 37);
	
	result = safe_add(1, safe_add(8, 32));
	assert(result == 41);
	
	result = safe_add(1, safe_add(16, 32));
	assert(result == 49);
	
	result = safe_add(2, safe_add(4, 32));
	assert(result == 38);
	
	result = safe_add(2, safe_add(8, 32));
	assert(result == 42);
	
	result = safe_add(2, safe_add(16, 32));
	assert(result == 50);
	
	result = safe_add(4, safe_add(8, 32));
	assert(result == 44);
	
	result = safe_add(4, safe_add(16, 32));
	assert(result == 52);
	
	result = safe_add(8, safe_add(16, 32));
	assert(result == 56);
	
	/* Test 681-700: Powers of 2 with SIZE_MAX fractions */
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 4);
	assert(result == (SIZE_MAX / 2) + (SIZE_MAX / 4));
	
	result = safe_add(SIZE_MAX / 4, SIZE_MAX / 8);
	assert(result == (SIZE_MAX / 4) + (SIZE_MAX / 8));
	
	result = safe_add(SIZE_MAX / 8, SIZE_MAX / 16);
	assert(result == (SIZE_MAX / 8) + (SIZE_MAX / 16));
	
	result = safe_add(SIZE_MAX / 16, SIZE_MAX / 32);
	assert(result == (SIZE_MAX / 16) + (SIZE_MAX / 32));
	
	result = safe_add(SIZE_MAX / 32, SIZE_MAX / 64);
	assert(result == (SIZE_MAX / 32) + (SIZE_MAX / 64));
	
	result = safe_add(SIZE_MAX / 64, SIZE_MAX / 128);
	assert(result == (SIZE_MAX / 64) + (SIZE_MAX / 128));
	
	result = safe_add(SIZE_MAX / 128, SIZE_MAX / 256);
	assert(result == (SIZE_MAX / 128) + (SIZE_MAX / 256));
	
	result = safe_add(SIZE_MAX / 256, SIZE_MAX / 512);
	assert(result == (SIZE_MAX / 256) + (SIZE_MAX / 512));
	
	result = safe_add(SIZE_MAX / 512, SIZE_MAX / 1024);
	assert(result == (SIZE_MAX / 512) + (SIZE_MAX / 1024));
	
	result = safe_add(SIZE_MAX / 1024, SIZE_MAX / 2048);
	assert(result == (SIZE_MAX / 1024) + (SIZE_MAX / 2048));
	
	result = safe_add(SIZE_MAX / 2048, SIZE_MAX / 4096);
	assert(result == (SIZE_MAX / 2048) + (SIZE_MAX / 4096));
	
	result = safe_add(SIZE_MAX / 4096, SIZE_MAX / 8192);
	assert(result == (SIZE_MAX / 4096) + (SIZE_MAX / 8192));
	
	result = safe_add(SIZE_MAX / 8192, SIZE_MAX / 16384);
	assert(result == (SIZE_MAX / 8192) + (SIZE_MAX / 16384));
	
	result = safe_add(SIZE_MAX / 16384, SIZE_MAX / 32768);
	assert(result == (SIZE_MAX / 16384) + (SIZE_MAX / 32768));
	
	result = safe_add(SIZE_MAX / 32768, SIZE_MAX / 65536);
	assert(result == (SIZE_MAX / 32768) + (SIZE_MAX / 65536));
	
	result = safe_add(SIZE_MAX / 65536, SIZE_MAX / 131072);
	assert(result == (SIZE_MAX / 65536) + (SIZE_MAX / 131072));
	
	result = safe_add(SIZE_MAX / 131072, SIZE_MAX / 262144);
	assert(result == (SIZE_MAX / 131072) + (SIZE_MAX / 262144));
	
	result = safe_add(SIZE_MAX / 262144, SIZE_MAX / 524288);
	assert(result == (SIZE_MAX / 262144) + (SIZE_MAX / 524288));
	
	result = safe_add(SIZE_MAX / 524288, SIZE_MAX / 1048576);
	assert(result == (SIZE_MAX / 524288) + (SIZE_MAX / 1048576));
	
	result = safe_add(SIZE_MAX / 1048576, SIZE_MAX / 2097152);
	assert(result == (SIZE_MAX / 1048576) + (SIZE_MAX / 2097152));
	
	/* ========================================================================
	 * CATEGORY 7: Prime Number Tests (Tests 701-800)
	 * Testing additions involving prime numbers
	 * ======================================================================== */
	
	/* Test 701-720: Small prime additions */
	result = safe_add(2, 3);
	assert(result == 5);
	
	result = safe_add(3, 5);
	assert(result == 8);
	
	result = safe_add(5, 7);
	assert(result == 12);
	
	result = safe_add(7, 11);
	assert(result == 18);
	
	result = safe_add(11, 13);
	assert(result == 24);
	
	result = safe_add(13, 17);
	assert(result == 30);
	
	result = safe_add(17, 19);
	assert(result == 36);
	
	result = safe_add(19, 23);
	assert(result == 42);
	
	result = safe_add(23, 29);
	assert(result == 52);
	
	result = safe_add(29, 31);
	assert(result == 60);
	
	result = safe_add(31, 37);
	assert(result == 68);
	
	result = safe_add(37, 41);
	assert(result == 78);
	
	result = safe_add(41, 43);
	assert(result == 84);
	
	result = safe_add(43, 47);
	assert(result == 90);
	
	result = safe_add(47, 53);
	assert(result == 100);
	
	result = safe_add(53, 59);
	assert(result == 112);
	
	result = safe_add(59, 61);
	assert(result == 120);
	
	result = safe_add(61, 67);
	assert(result == 128);
	
	result = safe_add(67, 71);
	assert(result == 138);
	
	result = safe_add(71, 73);
	assert(result == 144);
	
	/* Test 721-740: Medium prime additions */
	result = safe_add(73, 79);
	assert(result == 152);
	
	result = safe_add(79, 83);
	assert(result == 162);
	
	result = safe_add(83, 89);
	assert(result == 172);
	
	result = safe_add(89, 97);
	assert(result == 186);
	
	result = safe_add(97, 101);
	assert(result == 198);
	
	result = safe_add(101, 103);
	assert(result == 204);
	
	result = safe_add(103, 107);
	assert(result == 210);
	
	result = safe_add(107, 109);
	assert(result == 216);
	
	result = safe_add(109, 113);
	assert(result == 222);
	
	result = safe_add(113, 127);
	assert(result == 240);
	
	result = safe_add(127, 131);
	assert(result == 258);
	
	result = safe_add(131, 137);
	assert(result == 268);
	
	result = safe_add(137, 139);
	assert(result == 276);
	
	result = safe_add(139, 149);
	assert(result == 288);
	
	result = safe_add(149, 151);
	assert(result == 300);
	
	result = safe_add(151, 157);
	assert(result == 308);
	
	result = safe_add(157, 163);
	assert(result == 320);
	
	result = safe_add(163, 167);
	assert(result == 330);
	
	result = safe_add(167, 173);
	assert(result == 340);
	
	result = safe_add(173, 179);
	assert(result == 352);
	
	/* Test 741-760: Large prime additions */
	result = safe_add(179, 181);
	assert(result == 360);
	
	result = safe_add(181, 191);
	assert(result == 372);
	
	result = safe_add(191, 193);
	assert(result == 384);
	
	result = safe_add(193, 197);
	assert(result == 390);
	
	result = safe_add(197, 199);
	assert(result == 396);
	
	result = safe_add(199, 211);
	assert(result == 410);
	
	result = safe_add(211, 223);
	assert(result == 434);
	
	result = safe_add(223, 227);
	assert(result == 450);
	
	result = safe_add(227, 229);
	assert(result == 456);
	
	result = safe_add(229, 233);
	assert(result == 462);
	
	result = safe_add(233, 239);
	assert(result == 472);
	
	result = safe_add(239, 241);
	assert(result == 480);
	
	result = safe_add(241, 251);
	assert(result == 492);
	
	result = safe_add(251, 257);
	assert(result == 508);
	
	result = safe_add(257, 263);
	assert(result == 520);
	
	result = safe_add(263, 269);
	assert(result == 532);
	
	result = safe_add(269, 271);
	assert(result == 540);
	
	result = safe_add(271, 277);
	assert(result == 548);
	
	result = safe_add(277, 281);
	assert(result == 558);
	
	result = safe_add(281, 283);
	assert(result == 564);
	
	/* Test 761-780: Large value prime additions */
	result = safe_add(1000003, 1000033);
	assert(result == 2000036);
	
	result = safe_add(1000037, 1000039);
	assert(result == 2000076);
	
	result = safe_add(1000081, 1000099);
	assert(result == 2000180);
	
	result = safe_add(10000019, 10000079);
	assert(result == 20000098);
	
	result = safe_add(10000103, 10000121);
	assert(result == 20000224);
	
	result = safe_add(100000007, 100000037);
	assert(result == 200000044);
	
	result = safe_add(100000039, 100000049);
	assert(result == 200000088);
	
	result = safe_add(1000000007, 1000000009);
	assert(result == 2000000016);
	
	result = safe_add(SIZE_MAX / 11, SIZE_MAX / 13);
	assert(result == (SIZE_MAX / 11) + (SIZE_MAX / 13));
	
	result = safe_add(SIZE_MAX / 17, SIZE_MAX / 19);
	assert(result == (SIZE_MAX / 17) + (SIZE_MAX / 19));
	
	result = safe_add(SIZE_MAX / 23, SIZE_MAX / 29);
	assert(result == (SIZE_MAX / 23) + (SIZE_MAX / 29));
	
	result = safe_add(SIZE_MAX / 31, SIZE_MAX / 37);
	assert(result == (SIZE_MAX / 31) + (SIZE_MAX / 37));
	
	result = safe_add(SIZE_MAX / 41, SIZE_MAX / 43);
	assert(result == (SIZE_MAX / 41) + (SIZE_MAX / 43));
	
	result = safe_add(SIZE_MAX / 47, SIZE_MAX / 53);
	assert(result == (SIZE_MAX / 47) + (SIZE_MAX / 53));
	
	result = safe_add(SIZE_MAX / 59, SIZE_MAX / 61);
	assert(result == (SIZE_MAX / 59) + (SIZE_MAX / 61));
	
	result = safe_add(SIZE_MAX / 67, SIZE_MAX / 71);
	assert(result == (SIZE_MAX / 67) + (SIZE_MAX / 71));
	
	result = safe_add(SIZE_MAX / 73, SIZE_MAX / 79);
	assert(result == (SIZE_MAX / 73) + (SIZE_MAX / 79));
	
	result = safe_add(SIZE_MAX / 83, SIZE_MAX / 89);
	assert(result == (SIZE_MAX / 83) + (SIZE_MAX / 89));
	
	result = safe_add(SIZE_MAX / 97, SIZE_MAX / 101);
	assert(result == (SIZE_MAX / 97) + (SIZE_MAX / 101));
	
	result = safe_add(SIZE_MAX / 103, SIZE_MAX / 107);
	assert(result == (SIZE_MAX / 103) + (SIZE_MAX / 107));
	
	/* Test 781-800: Triple prime additions */
	result = safe_add(safe_add(2, 3), 5);
	assert(result == 10);
	
	result = safe_add(safe_add(3, 5), 7);
	assert(result == 15);
	
	result = safe_add(safe_add(5, 7), 11);
	assert(result == 23);
	
	result = safe_add(safe_add(7, 11), 13);
	assert(result == 31);
	
	result = safe_add(safe_add(11, 13), 17);
	assert(result == 41);
	
	result = safe_add(safe_add(13, 17), 19);
	assert(result == 49);
	
	result = safe_add(safe_add(17, 19), 23);
	assert(result == 59);
	
	result = safe_add(safe_add(19, 23), 29);
	assert(result == 71);
	
	result = safe_add(safe_add(23, 29), 31);
	assert(result == 83);
	
	result = safe_add(safe_add(29, 31), 37);
	assert(result == 97);
	
	result = safe_add(safe_add(31, 37), 41);
	assert(result == 109);
	
	result = safe_add(safe_add(37, 41), 43);
	assert(result == 121);
	
	result = safe_add(safe_add(41, 43), 47);
	assert(result == 131);
	
	result = safe_add(safe_add(43, 47), 53);
	assert(result == 143);
	
	result = safe_add(safe_add(47, 53), 59);
	assert(result == 159);
	
	result = safe_add(safe_add(53, 59), 61);
	assert(result == 173);
	
	result = safe_add(safe_add(59, 61), 67);
	assert(result == 187);
	
	result = safe_add(safe_add(61, 67), 71);
	assert(result == 199);
	
	result = safe_add(safe_add(67, 71), 73);
	assert(result == 211);
	
	result = safe_add(safe_add(71, 73), 79);
	assert(result == 223);
	
	/* ========================================================================
	 * CATEGORY 8: Random-Like Value Tests (Tests 801-900)
	 * Testing diverse combinations for comprehensive coverage
	 * ======================================================================== */
	
	/* Test 801-820: Mixed small-medium combinations */
	result = safe_add(42, 137);
	assert(result == 179);
	
	result = safe_add(256, 768);
	assert(result == 1024);
	
	result = safe_add(1337, 8008);
	assert(result == 9345);
	
	result = safe_add(9999, 1001);
	assert(result == 11000);
	
	result = safe_add(12321, 56789);
	assert(result == 69110);
	
	result = safe_add(98765, 43210);
	assert(result == 141975);
	
	result = safe_add(123456, 654321);
	assert(result == 777777);
	
	result = safe_add(314159, 271828);
	assert(result == 585987);
	
	result = safe_add(161803, 618034);
	assert(result == 779837);
	
	result = safe_add(999999, 111111);
	assert(result == 1111110);
	
	result = safe_add(1048577, 2097153);
	assert(result == 3145730);
	
	result = safe_add(4194305, 8388609);
	assert(result == 12582914);
	
	result = safe_add(16777217, 33554433);
	assert(result == 50331650);
	
	result = safe_add(67108865, 134217729);
	assert(result == 201326594);
	
	result = safe_add(268435457, 536870913);
	assert(result == 805306370);
	
	result = safe_add(123, 321);
	assert(result == 444);
	
	result = safe_add(456, 654);
	assert(result == 1110);
	
	result = safe_add(789, 987);
	assert(result == 1776);
	
	result = safe_add(1234, 4321);
	assert(result == 5555);
	
	result = safe_add(5678, 8765);
	assert(result == 14443);
	
	/* Test 821-840: Large number combinations */
	result = safe_add(1073741825, 1073741825);
	assert(result == 2147483650ULL);
	
	result = safe_add(SIZE_MAX / 1001, SIZE_MAX / 1003);
	assert(result == (SIZE_MAX / 1001) + (SIZE_MAX / 1003));
	
	result = safe_add(SIZE_MAX / 1009, SIZE_MAX / 1013);
	assert(result == (SIZE_MAX / 1009) + (SIZE_MAX / 1013));
	
	result = safe_add(SIZE_MAX / 1019, SIZE_MAX / 1021);
	assert(result == (SIZE_MAX / 1019) + (SIZE_MAX / 1021));
	
	result = safe_add(SIZE_MAX / 1031, SIZE_MAX / 1033);
	assert(result == (SIZE_MAX / 1031) + (SIZE_MAX / 1033));
	
	result = safe_add(SIZE_MAX / 1039, SIZE_MAX / 1049);
	assert(result == (SIZE_MAX / 1039) + (SIZE_MAX / 1049));
	
	result = safe_add(SIZE_MAX / 1051, SIZE_MAX / 1061);
	assert(result == (SIZE_MAX / 1051) + (SIZE_MAX / 1061));
	
	result = safe_add(SIZE_MAX / 1063, SIZE_MAX / 1069);
	assert(result == (SIZE_MAX / 1063) + (SIZE_MAX / 1069));
	
	result = safe_add(SIZE_MAX / 1087, SIZE_MAX / 1091);
	assert(result == (SIZE_MAX / 1087) + (SIZE_MAX / 1091));
	
	result = safe_add(SIZE_MAX / 1093, SIZE_MAX / 1097);
	assert(result == (SIZE_MAX / 1093) + (SIZE_MAX / 1097));
	
	result = safe_add(SIZE_MAX / 1103, SIZE_MAX / 1109);
	assert(result == (SIZE_MAX / 1103) + (SIZE_MAX / 1109));
	
	result = safe_add(SIZE_MAX / 1117, SIZE_MAX / 1123);
	assert(result == (SIZE_MAX / 1117) + (SIZE_MAX / 1123));
	
	result = safe_add(SIZE_MAX / 1129, SIZE_MAX / 1151);
	assert(result == (SIZE_MAX / 1129) + (SIZE_MAX / 1151));
	
	result = safe_add(SIZE_MAX / 1153, SIZE_MAX / 1163);
	assert(result == (SIZE_MAX / 1153) + (SIZE_MAX / 1163));
	
	result = safe_add(SIZE_MAX / 1171, SIZE_MAX / 1181);
	assert(result == (SIZE_MAX / 1171) + (SIZE_MAX / 1181));
	
	result = safe_add(SIZE_MAX / 1187, SIZE_MAX / 1193);
	assert(result == (SIZE_MAX / 1187) + (SIZE_MAX / 1193));
	
	result = safe_add(SIZE_MAX / 1201, SIZE_MAX / 1213);
	assert(result == (SIZE_MAX / 1201) + (SIZE_MAX / 1213));
	
	result = safe_add(SIZE_MAX / 1217, SIZE_MAX / 1223);
	assert(result == (SIZE_MAX / 1217) + (SIZE_MAX / 1223));
	
	result = safe_add(SIZE_MAX / 1229, SIZE_MAX / 1231);
	assert(result == (SIZE_MAX / 1229) + (SIZE_MAX / 1231));
	
	result = safe_add(SIZE_MAX / 1237, SIZE_MAX / 1249);
	assert(result == (SIZE_MAX / 1237) + (SIZE_MAX / 1249));
	
	/* Test 841-860: Mersenne-adjacent patterns */
	result = safe_add(127, 255);
	assert(result == 382);
	
	result = safe_add(255, 511);
	assert(result == 766);
	
	result = safe_add(511, 1023);
	assert(result == 1534);
	
	result = safe_add(1023, 2047);
	assert(result == 3070);
	
	result = safe_add(2047, 4095);
	assert(result == 6142);
	
	result = safe_add(4095, 8191);
	assert(result == 12286);
	
	result = safe_add(8191, 16383);
	assert(result == 24574);
	
	result = safe_add(16383, 32767);
	assert(result == 49150);
	
	result = safe_add(32767, 65535);
	assert(result == 98302);
	
	result = safe_add(65535, 131071);
	assert(result == 196606);
	
	result = safe_add(131071, 262143);
	assert(result == 393214);
	
	result = safe_add(262143, 524287);
	assert(result == 786430);
	
	result = safe_add(524287, 1048575);
	assert(result == 1572862);
	
	result = safe_add(1048575, 2097151);
	assert(result == 3145726);
	
	result = safe_add(2097151, 4194303);
	assert(result == 6291454);
	
	result = safe_add(4194303, 8388607);
	assert(result == 12582910);
	
	result = safe_add(8388607, 16777215);
	assert(result == 25165822);
	
	result = safe_add(16777215, 33554431);
	assert(result == 50331646);
	
	result = safe_add(33554431, 67108863);
	assert(result == 100663294);
	
	result = safe_add(67108863, 134217727);
	assert(result == 201326590);
	
	/* Test 861-880: Fibonacci-like sequences */
	result = safe_add(1, 1);
	assert(result == 2);
	
	result = safe_add(1, 2);
	assert(result == 3);
	
	result = safe_add(2, 3);
	assert(result == 5);
	
	result = safe_add(3, 5);
	assert(result == 8);
	
	result = safe_add(5, 8);
	assert(result == 13);
	
	result = safe_add(8, 13);
	assert(result == 21);
	
	result = safe_add(13, 21);
	assert(result == 34);
	
	result = safe_add(21, 34);
	assert(result == 55);
	
	result = safe_add(34, 55);
	assert(result == 89);
	
	result = safe_add(55, 89);
	assert(result == 144);
	
	result = safe_add(89, 144);
	assert(result == 233);
	
	result = safe_add(144, 233);
	assert(result == 377);
	
	result = safe_add(233, 377);
	assert(result == 610);
	
	result = safe_add(377, 610);
	assert(result == 987);
	
	result = safe_add(610, 987);
	assert(result == 1597);
	
	result = safe_add(987, 1597);
	assert(result == 2584);
	
	result = safe_add(1597, 2584);
	assert(result == 4181);
	
	result = safe_add(2584, 4181);
	assert(result == 6765);
	
	result = safe_add(4181, 6765);
	assert(result == 10946);
	
	result = safe_add(6765, 10946);
	assert(result == 17711);
	
	/* Test 881-900: Edge pattern combinations */
	result = safe_add(SIZE_MAX - 1000000, 500000);
	assert(result == SIZE_MAX - 500000);
	
	result = safe_add(SIZE_MAX - 2000000, 1000000);
	assert(result == SIZE_MAX - 1000000);
	
	result = safe_add(SIZE_MAX - 5000000, 2500000);
	assert(result == SIZE_MAX - 2500000);
	
	result = safe_add(SIZE_MAX - 10000000, 5000000);
	assert(result == SIZE_MAX - 5000000);
	
	result = safe_add(SIZE_MAX - 20000000, 10000000);
	assert(result == SIZE_MAX - 10000000);
	
	result = safe_add(SIZE_MAX - 50000000, 25000000);
	assert(result == SIZE_MAX - 25000000);
	
	result = safe_add(SIZE_MAX - 100000000, 50000000);
	assert(result == SIZE_MAX - 50000000);
	
	result = safe_add(SIZE_MAX - 200000000, 100000000);
	assert(result == SIZE_MAX - 100000000);
	
	result = safe_add(SIZE_MAX - 500000000, 250000000);
	assert(result == SIZE_MAX - 250000000);
	
	result = safe_add(SIZE_MAX - 1000000000, 500000000);
	assert(result == SIZE_MAX - 500000000);
	
	result = safe_add(SIZE_MAX / 1000 - 1, SIZE_MAX / 1000);
	assert(result == (SIZE_MAX / 1000) * 2 - 1);
	
	result = safe_add(SIZE_MAX / 2000 - 1, SIZE_MAX / 2000);
	assert(result == (SIZE_MAX / 2000) * 2 - 1);
	
	result = safe_add(SIZE_MAX / 3000 - 1, SIZE_MAX / 3000);
	assert(result == (SIZE_MAX / 3000) * 2 - 1);
	
	result = safe_add(SIZE_MAX / 4000 - 1, SIZE_MAX / 4000);
	assert(result == (SIZE_MAX / 4000) * 2 - 1);
	
	result = safe_add(SIZE_MAX / 5000 - 1, SIZE_MAX / 5000);
	assert(result == (SIZE_MAX / 5000) * 2 - 1);
	
	result = safe_add(SIZE_MAX / 6000 - 1, SIZE_MAX / 6000);
	assert(result == (SIZE_MAX / 6000) * 2 - 1);
	
	result = safe_add(SIZE_MAX / 7000 - 1, SIZE_MAX / 7000);
	assert(result == (SIZE_MAX / 7000) * 2 - 1);
	
	result = safe_add(SIZE_MAX / 8000 - 1, SIZE_MAX / 8000);
	assert(result == (SIZE_MAX / 8000) * 2 - 1);
	
	result = safe_add(SIZE_MAX / 9000 - 1, SIZE_MAX / 9000);
	assert(result == (SIZE_MAX / 9000) * 2 - 1);
	
	result = safe_add(SIZE_MAX / 10000 - 1, SIZE_MAX / 10000);
	assert(result == (SIZE_MAX / 10000) * 2 - 1);
	
	/* ========================================================================
	 * CATEGORY 9: Boundary Stress Tests (Tests 901-1000)
	 * Critical tests near SIZE_MAX to ensure overflow detection works
	 * ======================================================================== */
	
	/* Test 901-920: Maximum safe values */
	result = safe_add(SIZE_MAX - 1, 1);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 2, 2);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 3, 3);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 4, 4);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 5, 5);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 6, 6);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 7, 7);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 8, 8);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 9, 9);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 10, 10);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 11, 11);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 12, 12);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 13, 13);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 14, 14);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 15, 15);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 16, 16);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 17, 17);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 18, 18);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 19, 19);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 20, 20);
	assert(result == SIZE_MAX);
	
	/* Test 921-940: Just below maximum */
	result = safe_add(SIZE_MAX - 100, 99);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(SIZE_MAX - 100, 98);
	assert(result == SIZE_MAX - 2);
	
	result = safe_add(SIZE_MAX - 100, 97);
	assert(result == SIZE_MAX - 3);
	
	result = safe_add(SIZE_MAX - 100, 96);
	assert(result == SIZE_MAX - 4);
	
	result = safe_add(SIZE_MAX - 100, 95);
	assert(result == SIZE_MAX - 5);
	
	result = safe_add(SIZE_MAX - 1000, 999);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(SIZE_MAX - 1000, 998);
	assert(result == SIZE_MAX - 2);
	
	result = safe_add(SIZE_MAX - 1000, 997);
	assert(result == SIZE_MAX - 3);
	
	result = safe_add(SIZE_MAX - 1000, 996);
	assert(result == SIZE_MAX - 4);
	
	result = safe_add(SIZE_MAX - 1000, 995);
	assert(result == SIZE_MAX - 5);
	
	result = safe_add(SIZE_MAX - 10000, 9999);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(SIZE_MAX - 10000, 9998);
	assert(result == SIZE_MAX - 2);
	
	result = safe_add(SIZE_MAX - 10000, 9997);
	assert(result == SIZE_MAX - 3);
	
	result = safe_add(SIZE_MAX - 10000, 9996);
	assert(result == SIZE_MAX - 4);
	
	result = safe_add(SIZE_MAX - 10000, 9995);
	assert(result == SIZE_MAX - 5);
	
	result = safe_add(SIZE_MAX - 100000, 99999);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(SIZE_MAX - 100000, 99998);
	assert(result == SIZE_MAX - 2);
	
	result = safe_add(SIZE_MAX - 100000, 99997);
	assert(result == SIZE_MAX - 3);
	
	result = safe_add(SIZE_MAX - 100000, 99996);
	assert(result == SIZE_MAX - 4);
	
	result = safe_add(SIZE_MAX - 100000, 99995);
	assert(result == SIZE_MAX - 5);
	
	/* Test 941-960: Complex boundary patterns */
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 2 - 1);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 2 - 2);
	assert(result == SIZE_MAX - 2);
	
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 2 - 3);
	assert(result == SIZE_MAX - 3);
	
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 2 - 4);
	assert(result == SIZE_MAX - 4);
	
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 2 - 5);
	assert(result == SIZE_MAX - 5);
	
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 2 - 10);
	assert(result == SIZE_MAX - 10);
	
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 2 - 100);
	assert(result == SIZE_MAX - 100);
	
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 2 - 1000);
	assert(result == SIZE_MAX - 1000);
	
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 2 - 10000);
	assert(result == SIZE_MAX - 10000);
	
	result = safe_add(SIZE_MAX / 2, SIZE_MAX / 2 - 100000);
	assert(result == SIZE_MAX - 100000);
	
	result = safe_add(SIZE_MAX / 3, (SIZE_MAX / 3) * 2 - 1);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(SIZE_MAX / 3, (SIZE_MAX / 3) * 2 - 2);
	assert(result == SIZE_MAX - 2);
	
	result = safe_add(SIZE_MAX / 3, (SIZE_MAX / 3) * 2 - 3);
	assert(result == SIZE_MAX - 3);
	
	result = safe_add(SIZE_MAX / 3, (SIZE_MAX / 3) * 2 - 4);
	assert(result == SIZE_MAX - 4);
	
	result = safe_add(SIZE_MAX / 3, (SIZE_MAX / 3) * 2 - 5);
	assert(result == SIZE_MAX - 5);
	
	result = safe_add(SIZE_MAX / 4, (SIZE_MAX / 4) * 3 - 1);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(SIZE_MAX / 4, (SIZE_MAX / 4) * 3 - 2);
	assert(result == SIZE_MAX - 2);
	
	result = safe_add(SIZE_MAX / 5, (SIZE_MAX / 5) * 4 - 1);
	assert(result == SIZE_MAX - 1);
	
	result = safe_add(SIZE_MAX / 5, (SIZE_MAX / 5) * 4 - 2);
	assert(result == SIZE_MAX - 2);
	
	result = safe_add(SIZE_MAX / 6, (SIZE_MAX / 6) * 5 - 1);
	assert(result == SIZE_MAX - 1);
	
	/* Test 961-980: Very close to SIZE_MAX */
	result = safe_add(SIZE_MAX - 25, 25);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 24, 24);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 23, 23);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 22, 22);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 21, 21);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 30, 30);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 35, 35);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 40, 40);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 45, 45);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 50, 50);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 55, 55);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 60, 60);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 65, 65);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 70, 70);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 75, 75);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 80, 80);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 85, 85);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 90, 90);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 95, 95);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 99, 99);
	assert(result == SIZE_MAX);
	
	/* Test 981-1000: Final boundary tests */
	result = safe_add(SIZE_MAX - 127, 127);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 255, 255);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 511, 511);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 1023, 1023);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 2047, 2047);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 4095, 4095);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 8191, 8191);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 16383, 16383);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 32767, 32767);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 65535, 65535);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 131071, 131071);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 262143, 262143);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 524287, 524287);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 1048575, 1048575);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 2097151, 2097151);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 4194303, 4194303);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 8388607, 8388607);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 16777215, 16777215);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 33554431, 33554431);
	assert(result == SIZE_MAX);
	
	result = safe_add(SIZE_MAX - 67108863, 67108863);
	assert(result == SIZE_MAX);
	
	printf("All 1000 test cases passed successfully!\n");
	printf("safe_add() is CERT C INT30-C compliant.\n");
	
	return 0;
}
