# Exercise 30: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a matrix operations utility. The engineering team has implemented a function to access elements in a 2D matrix stored as a 1D array.

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

int get_matrix_element(int *matrix, size_t rows, size_t cols, size_t row, size_t col) {
	if (matrix == NULL) {
		return -1;
	}

	// No checks for potential out-of-bounds error below!
	
	size_t index = row * cols + col;
	
	return matrix[index];
}

int main() {
	int matrix[3][4] = {
		{1, 2, 3, 4},
		{5, 6, 7, 8},
		{9, 10, 11, 12}
	};

	// No attempt at error handling below
	
	printf("Element at (1, 2): %d\n", get_matrix_element((int*)matrix, 3, 4, 1, 2));
	printf("Element at (2, 3): %d\n", get_matrix_element((int*)matrix, 3, 4, 2, 3));
	
	return 0;
}
```

**Expected behavior:**
```
Element at (1, 2): 7
Element at (2, 3): 12
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `get_matrix_element()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `get_matrix_element()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

int get_matrix_element(int * matrix, size_t rows, size_t cols, size_t row, size_t col) {
	if (matrix == NULL || row >= rows || col >= cols) {
		return -1;
	}
	
	size_t index = 0; 

	if ( __builtin_mul_overflow(row,cols,&index) ==  true)
	{
		return -1;
	}
	
	if ( __builtin_add_overflow(index,col,&index) ==  true)
	{
		return -1;
	}
	
	return matrix[index];
}

int main() {
	int matrix[3][4] = {
		{1, 2, 3, 4},
		{5, 6, 7, 8},
		{9, 10, 11, 12}
	};

	int result = get_matrix_element((int*)matrix, 3, 4, 1, 2);

	if ( result != -1 )
	{
		printf("Element at (1, 2): %d\n",result);

	}

	result = get_matrix_element((int*)matrix, 3, 4, 2, 3);

	if ( result != -1 )
	{
		printf("Element at (2, 3): %d\n",result);

	}	
	
	return 0;
}
```

---

## Grading Rubric

### Part A: Vulnerability Identification (5 points)
- **5 points**: Identified all security vulnerabilities with clear explanations

### Part B: Secure Implementation (10 points)
- **10 points**: Fixed all identified vulnerabilities correctly

---

## Time Allocation

- **5 minutes**: Review code and identify vulnerabilities
- **10 minutes**: Write secure implementation
- **5 minutes**: Verify your solution handles edge cases

---

*This is a realistic security code review exercise. Good luck!*
