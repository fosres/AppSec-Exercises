"""
Exercise 17: How many different numbers?
Source: Python Workout, Second Edition by Reuven M. Lerner
Chapter: 5 - Dictionaries and sets
Section: 5.6 Exercise 17 - How many different numbers?
Pages: 87-89 (PDF lines 3169-3240)

Description:
Write a function called how_many_different_numbers that takes a single list of integers
and returns the number of different integers it contains.

Example from the book (page 87):
	numbers = [1, 2, 3, 1, 2, 3, 4, 1]
	print(how_many_different_numbers(numbers))  # Returns: 4

The list contains 7 elements total, but only 4 different values (1, 2, 3, 4).

Key Concepts from the book (pages 87-88):
- Sets automatically enforce uniqueness (like dict keys are guaranteed unique)
- Converting a list to a set removes all duplicates
- Can create sets with: set(list), set.add(), set.update(), or {*list} syntax
- The solution uses set(numbers) to get unique elements, then len() to count them
"""

def how_many_different_numbers(numbers: list[int]) -> int:
	"""
	Count the number of different/unique integers in a list.
	
	Args:
		numbers: List of integers (may contain duplicates)
	
	Returns:
		Integer count of unique values in the list
	"""
	# TODO: Implement this function
	final_set = set()

	final_set.update(numbers)

	return len(final_set)

# ========================================================================
# TEST CASES
# ========================================================================

def test_how_many_different_numbers():
	"""Run all test cases for how_many_different_numbers function"""
	
	test_cases = [
		# Test 1-5: Basic cases from the book (page 87)
		([1, 2, 3, 1, 2, 3, 4, 1], 4),  # Example from the book
		([1, 2, 3, 4, 5], 5),  # No duplicates
		([1, 1, 1, 1], 1),  # All same value
		([1, 2, 1, 2], 2),  # Two different values
		([5, 4, 3, 2, 1], 5),  # No duplicates, descending
		
		# Test 6-10: Empty and single element lists
		([], 0),  # Empty list
		([1], 1),  # Single element
		([42], 1),  # Single different element
		([0], 1),  # Single zero
		([-1], 1),  # Single negative
		
		# Test 11-15: Lists with no duplicates
		([1, 2], 2),
		([1, 2, 3], 3),
		([10, 20, 30, 40], 4),
		([100, 200, 300, 400, 500], 5),
		(list(range(10)), 10),  # [0, 1, 2, ..., 9]
		
		# Test 16-20: Lists with all duplicates
		([5, 5], 1),
		([7, 7, 7], 1),
		([0, 0, 0, 0], 1),
		([99, 99, 99, 99, 99], 1),
		([-5, -5, -5], 1),
		
		# Test 21-25: Lists with some duplicates (patterns)
		([1, 2, 2, 3], 3),
		([1, 1, 2, 2, 3, 3], 3),
		([1, 2, 3, 3, 3], 3),
		([5, 5, 5, 6, 6, 7], 3),
		([10, 20, 10, 30, 20], 3),
		
		# Test 26-30: Negative numbers
		([-1, -2, -3], 3),
		([-1, -1, -1], 1),
		([-5, -4, -3, -2, -1], 5),
		([-10, -10, -20, -20], 2),
		([-1, 0, 1], 3),
		
		# Test 31-35: Mixed positive and negative
		([-1, 1], 2),
		([-5, -4, 0, 4, 5], 5),
		([-10, -5, 0, 5, 10], 5),
		([-3, -2, -1, 0, 1, 2, 3], 7),
		([-100, 0, 100, -100, 0, 100], 3),
		
		# Test 36-40: Zero handling
		([0, 0, 0], 1),
		([0, 1, 2], 3),
		([0, 0, 1, 1, 2, 2], 3),
		([-1, 0, 1, 0], 3),
		([0], 1),
		
		# Test 41-45: Large numbers
		([1000000, 2000000, 3000000], 3),
		([999999, 999999], 1),
		([123456, 234567, 345678, 123456], 3),
		([10**6, 10**7, 10**8], 3),
		([2**10, 2**20, 2**30], 3),
		
		# Test 46-50: Repeating patterns
		([1, 2, 1, 2, 1, 2], 2),
		([1, 2, 3, 1, 2, 3, 1, 2, 3], 3),
		([5, 10, 5, 10, 5, 10, 5], 2),
		([7, 8, 9, 7, 8, 9], 3),
		([100, 200, 100, 200, 100], 2),
		
		# Test 51-55: Consecutive duplicates
		([1, 1, 2, 2, 3, 3], 3),
		([5, 5, 5, 6, 6, 6], 2),
		([10, 10, 20, 20, 30, 30, 40, 40], 4),
		([1, 1, 1, 2, 3, 3, 3], 3),
		([7, 8, 8, 8, 9, 9], 3),
		
		# Test 56-60: Scattered duplicates
		([1, 3, 5, 1, 7, 3, 9], 5),
		([2, 4, 6, 8, 2, 4, 6, 8], 4),
		([10, 20, 30, 10, 40, 20, 50], 5),
		([5, 15, 25, 5, 35, 15, 45], 5),
		([100, 200, 300, 100, 400, 200], 4),
		
		# Test 61-65: Many duplicates of few values
		([1, 1, 1, 1, 1, 1, 1, 2], 2),
		([1, 1, 1, 1, 2, 2, 2, 2], 2),
		([5, 5, 5, 5, 5, 10, 10, 10, 10, 10], 2),
		([7, 7, 7, 8, 8, 8, 9, 9, 9], 3),
		([1]*10 + [2]*10, 2),
		
		# Test 66-70: Ordered sequences
		([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 10),
		([10, 9, 8, 7, 6, 5, 4, 3, 2, 1], 10),
		(list(range(0, 100, 10)), 10),  # [0, 10, 20, ..., 90]
		(list(range(1, 11)), 10),  # [1, 2, 3, ..., 10]
		(list(range(-5, 6)), 11),  # [-5, -4, ..., 4, 5]
		
		# Test 71-75: Complex patterns
		([1, 2, 3, 2, 1, 3, 2, 1], 3),
		([10, 20, 30, 20, 10, 30, 20], 3),
		([5, 5, 10, 10, 15, 15, 5, 10, 15], 3),
		([1, 3, 5, 7, 9, 1, 3, 5, 7, 9], 5),
		([2, 4, 6, 8, 10, 2, 4, 6, 8, 10], 5),
		
		# Test 76-80: Large lists
		(list(range(50)), 50),  # [0, 1, 2, ..., 49]
		([i % 5 for i in range(50)], 5),  # Cycles 0-4 ten times
		([i // 5 for i in range(50)], 10),  # Each value appears 5 times
		([1]*100 + [2]*100 + [3]*100, 3),  # Three values, 100 each
		(list(range(100)) + list(range(100)), 100),  # 0-99 twice
		
		# Test 81-85: Edge cases with specific patterns
		([42, 42, 42, 42, 42], 1),  # All same (answer to everything!)
		([-1, -1, 0, 0, 1, 1], 3),  # Symmetric around zero
		([10, 10, 20, 30, 30], 3),  # Duplicates at edges
		([1, 2, 3, 4, 5, 1], 5),  # First element repeated at end
		([5, 4, 3, 2, 1, 5, 4, 3, 2, 1], 5),  # Descending pattern repeated
		
		# Test 86-90: More complex scenarios
		([i for i in range(20) for _ in range(3)], 20),  # Each value 3 times
		([i % 10 for i in range(100)], 10),  # Cycles 0-9 ten times
		(sorted([5, 3, 8, 3, 1, 9, 5, 2, 8, 1]), 6),  # Sorted with duplicates
		([1, 1, 2, 2, 3, 3, 4, 4, 5, 5], 5),  # Pairs
		([10, 5, 10, 5, 10, 5], 2),  # Alternating
		
		# Test 91-95: Prime numbers and special sequences
		([2, 3, 5, 7, 11, 13, 17, 19], 8),  # First 8 primes
		([1, 1, 2, 3, 5, 8, 13, 21], 7),  # Fibonacci (with duplicate 1) - Fixed: only 7 unique values
		([1, 4, 9, 16, 25, 36], 6),  # Perfect squares
		([2, 4, 8, 16, 32, 64], 6),  # Powers of 2
		([1, 10, 100, 1000, 10000], 5),  # Powers of 10
		
		# Test 96-100: Stress tests
		(list(range(1000)), 1000),  # Large unique list
		([42] * 1000, 1),  # Large list, one value
		([i % 100 for i in range(10000)], 100),  # Very large list, 100 unique
		(list(range(-500, 501)), 1001),  # Large range including negatives
		([i for i in range(50)] + [i for i in range(50)], 50),  # Large list with exact duplicates
	]
	
	passed = 0
	failed = 0
	
	for i, (numbers, expected) in enumerate(test_cases, 1):
		try:
			result = how_many_different_numbers(numbers)
			if result == expected:
				passed += 1
				print(f"✓ Test {i} passed")
			else:
				failed += 1
				print(f"✗ Test {i} failed")
				print(f"  Input: how_many_different_numbers({numbers if len(numbers) <= 10 else f'{numbers[:5]}...{numbers[-5:]} (length {len(numbers)})'})") 
				print(f"  Expected: {expected}")
				print(f"  Got: {result}")
		except Exception as e:
			failed += 1
			print(f"✗ Test {i} raised exception: {e}")
			print(f"  Input: how_many_different_numbers({numbers if len(numbers) <= 10 else f'{numbers[:5]}...{numbers[-5:]} (length {len(numbers)})'})")
	
	print(f"\n{'='*60}")
	print(f"Results: {passed} passed, {failed} failed out of {len(test_cases)} tests")
	print(f"{'='*60}")
	
	return passed == len(test_cases)


if __name__ == '__main__':
	test_how_many_different_numbers()
