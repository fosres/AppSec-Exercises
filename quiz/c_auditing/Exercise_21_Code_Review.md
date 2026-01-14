# Exercise 21: C Security Audit - Code Review

**Inspired by**: ACME Product Security Tech Test  
**Difficulty**: Week 4 Level  
**Time Limit**: 20 minutes  
**Points**: 15 total

---

## Scenario

You are reviewing code for a data processing utility. The engineering team has implemented a function to compute the average of an array of integers.

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

double compute_average(int *values, size_t count) {

	// No check if values == NULL

	// Problem: sum is of type int but the return data

	// type is double

	int sum = 0;

	// Problem no check if count == 0. You cannot divide by zero.

	
	for (size_t i = 0; i < count; i++) {

		// risk of Integer Overflow below

		sum += values[i];
	}

	// Problem: count is of type size_t whereas sum

	// is of type int
	
	return sum / count;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	
	double avg = compute_average(numbers, 5);
	
	printf("Average: %.2f\n", avg);
	
	return 0;
}
```

**Expected behavior:**
```
Average: 30.00
```

---

## Questions

### Part A: Vulnerability Identification (5 points)

Identify ALL security vulnerabilities in the `compute_average()` function. For each vulnerability:
- Name the vulnerability class
- Explain the root cause
- Describe the potential security impact

Write your analysis below:

```
[Your answer here]
```

---

### Part B: Secure Implementation (10 points)

Rewrite the `compute_average()` function to fix all identified vulnerabilities.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

double compute_average(int *values, size_t count) {

	// No check if values == NULL

	if ( values == NULL )
	{
		return 0.0;
	}
	
	// Problem no check if count == 0. You cannot divide by zero.

	if ( count == 0 )
	{
		return 0.0;
	}

	// Problem: sum is of type int but the return data

	// type is double

	// sum is of type double

	double sum = 0;
	
	for (size_t i = 0; i < count; i++) {

		// risk of Integer Overflow below

		sum += values[i];
	}

	// Problem: count is of type size_t whereas sum

	// is of type int
	
	return sum / count;
}

int main() {
	int numbers[] = {10, 20, 30, 40, 50};
	
	double avg = compute_average(numbers, 5);
	
	printf("Average: %.2f\n", avg);
	
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
