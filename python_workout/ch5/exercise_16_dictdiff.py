"""
Exercise 16: Dictdiff
Source: Python Workout, Second Edition by Reuven M. Lerner
Chapter: 5 - Dictionaries and sets
Section: 5.5 Exercise 16 - Dictdiff
Pages: 81-86 (PDF lines 3039-3165)

Description:
Write a function, dictdiff, that takes two dicts as arguments. The function returns a
new dict that expresses the difference between the two dicts.

If there are no differences between the dicts, dictdiff returns an empty dict. For each
key-value pair that differs, the return value of dictdiff will have a key-value pair in which
the value is a list containing the values from the two different dicts. If one of the dicts
doesn't contain that key, it should contain None.

Example usage from the book:
	d1 = {'a':1, 'b':2, 'c':3}
	d2 = {'a':1, 'b':2, 'c':4}
	print(dictdiff(d1, d1))  # Returns: {}
	print(dictdiff(d1, d2))  # Returns: {'c': [3, 4]}
	
	d3 = {'a':1, 'b':2, 'd':3}
	d4 = {'a':1, 'b':2, 'c':4}
	print(dictdiff(d3, d4))  # Returns: {'c': [None, 4], 'd': [3, None]}
	
	d5 = {'a':1, 'b':2, 'd':4}
	print(dictdiff(d1, d5))  # Returns: {'c': [3, None], 'd': [None, 4]}

Key Concepts from the book (pages 82-86):
- Using dict.keys() | operator for set union to get all unique keys
- Using dict.get() with None default to handle missing keys elegantly
- Efficient iteration by combining keys from both dicts into a single set
"""

def dictdiff(first, second):
	"""
	Compare two dictionaries and return their differences.
	
	Args:
		first: First dictionary to compare
		second: Second dictionary to compare
	
	Returns:
		Dictionary where each key maps to [first_value, second_value] for differing entries.
		Returns empty dict if no differences found.
	"""
	# TODO: Implement this function
	
	output = {}
	
	for key,val in first.items():

		if key not in second:
			output[key] = [val,None]

		elif key in second and val != second[key]:
			output[key] = [val,second[key]]

	for key,val in second.items():

		if key not in first:
			output.update({key : [None,val]})
			output[key] = [None,val]

		elif key in first and val != first[key]:
			output[key] = [first[key],val]

	return output

# ========================================================================
# TEST CASES
# ========================================================================

def test_dictdiff():
	"""Run all test cases for dictdiff function"""
	
	test_cases = [
		# Basic cases from the book (pages 82-86)
		# Test 1-4: Examples directly from the book
		({'a':1, 'b':2, 'c':3}, {'a':1, 'b':2, 'c':3}, {}),
		({'a':1, 'b':2, 'c':3}, {'a':1, 'b':2, 'c':4}, {'c': [3, 4]}),
		({'a':1, 'b':2, 'd':3}, {'a':1, 'b':2, 'c':4}, {'c': [None, 4], 'd': [3, None]}),
		({'a':1, 'b':2, 'c':3}, {'a':1, 'b':2, 'd':4}, {'c': [3, None], 'd': [None, 4]}),
		
		# Test 5-10: Empty dictionaries
		({}, {}, {}),
		({}, {'a': 1}, {'a': [None, 1]}),
		({'a': 1}, {}, {'a': [1, None]}),
		({}, {'a': 1, 'b': 2}, {'a': [None, 1], 'b': [None, 2]}),
		({'a': 1, 'b': 2}, {}, {'a': [1, None], 'b': [2, None]}),
		({}, {'x': 100, 'y': 200, 'z': 300}, {'x': [None, 100], 'y': [None, 200], 'z': [None, 300]}),
		
		# Test 11-15: Single key differences
		({'key': 'value1'}, {'key': 'value2'}, {'key': ['value1', 'value2']}),
		({'x': 10}, {'x': 20}, {'x': [10, 20]}),
		({'name': 'Alice'}, {'name': 'Bob'}, {'name': ['Alice', 'Bob']}),
		({'count': 0}, {'count': 1}, {'count': [0, 1]}),
		({'flag': True}, {'flag': False}, {'flag': [True, False]}),
		
		# Test 16-20: Multiple key differences
		({'a': 1, 'b': 2}, {'a': 10, 'b': 20}, {'a': [1, 10], 'b': [2, 20]}),
		({'x': 1, 'y': 2, 'z': 3}, {'x': 10, 'y': 20, 'z': 30}, {'x': [1, 10], 'y': [2, 20], 'z': [3, 30]}),
		({'name': 'Alice', 'age': 30}, {'name': 'Bob', 'age': 25}, {'name': ['Alice', 'Bob'], 'age': [30, 25]}),
		({'a': 1, 'b': 2, 'c': 3, 'd': 4}, {'a': 10, 'b': 20, 'c': 30, 'd': 40}, {'a': [1, 10], 'b': [2, 20], 'c': [3, 30], 'd': [4, 40]}),
		({'p': 100, 'q': 200, 'r': 300}, {'p': 111, 'q': 222, 'r': 333}, {'p': [100, 111], 'q': [200, 222], 'r': [300, 333]}),
		
		# Test 21-25: Partial overlaps
		({'a': 1, 'b': 2, 'c': 3}, {'a': 1, 'b': 20, 'c': 3}, {'b': [2, 20]}),
		({'x': 10, 'y': 20, 'z': 30}, {'x': 10, 'y': 20, 'z': 300}, {'z': [30, 300]}),
		({'name': 'Alice', 'age': 30, 'city': 'NYC'}, {'name': 'Alice', 'age': 31, 'city': 'NYC'}, {'age': [30, 31]}),
		({'a': 1, 'b': 2, 'c': 3, 'd': 4, 'e': 5}, {'a': 1, 'b': 20, 'c': 3, 'd': 40, 'e': 5}, {'b': [2, 20], 'd': [4, 40]}),
		({'id': 123, 'status': 'active', 'score': 100}, {'id': 123, 'status': 'inactive', 'score': 100}, {'status': ['active', 'inactive']}),
		
		# Test 26-30: Keys only in first dict
		({'unique': 1}, {}, {'unique': [1, None]}),
		({'a': 1, 'unique': 2}, {'a': 1}, {'unique': [2, None]}),
		({'x': 10, 'y': 20}, {'x': 10}, {'y': [20, None]}),
		({'p': 1, 'q': 2, 'r': 3}, {'p': 1}, {'q': [2, None], 'r': [3, None]}),
		({'name': 'Alice', 'email': 'alice@example.com'}, {'name': 'Alice'}, {'email': ['alice@example.com', None]}),
		
		# Test 31-35: Keys only in second dict
		({}, {'new': 1}, {'new': [None, 1]}),
		({'a': 1}, {'a': 1, 'new': 2}, {'new': [None, 2]}),
		({'x': 10}, {'x': 10, 'y': 20}, {'y': [None, 20]}),
		({'p': 1}, {'p': 1, 'q': 2, 'r': 3}, {'q': [None, 2], 'r': [None, 3]}),
		({'name': 'Alice'}, {'name': 'Alice', 'phone': '555-1234'}, {'phone': [None, '555-1234']}),
		
		# Test 36-40: Mixed scenarios (different values + unique keys)
		({'a': 1, 'b': 2}, {'a': 10, 'c': 3}, {'a': [1, 10], 'b': [2, None], 'c': [None, 3]}),
		({'x': 10, 'y': 20}, {'x': 100, 'z': 30}, {'x': [10, 100], 'y': [20, None], 'z': [None, 30]}),
		({'name': 'Alice', 'age': 30}, {'name': 'Bob', 'city': 'NYC'}, {'name': ['Alice', 'Bob'], 'age': [30, None], 'city': [None, 'NYC']}),
		({'a': 1, 'b': 2, 'c': 3}, {'b': 20, 'c': 30, 'd': 4}, {'a': [1, None], 'b': [2, 20], 'c': [3, 30], 'd': [None, 4]}),
		({'p': 100, 'q': 200}, {'q': 222, 'r': 300, 's': 400}, {'p': [100, None], 'q': [200, 222], 'r': [None, 300], 's': [None, 400]}),
		
		# Test 41-45: Different value types (strings)
		({'key': 'hello'}, {'key': 'world'}, {'key': ['hello', 'world']}),
		({'greeting': 'hi', 'farewell': 'bye'}, {'greeting': 'hello', 'farewell': 'goodbye'}, {'greeting': ['hi', 'hello'], 'farewell': ['bye', 'goodbye']}),
		({'name': 'Alice'}, {'name': 'alice'}, {'name': ['Alice', 'alice']}),
		({'msg': ''}, {'msg': 'text'}, {'msg': ['', 'text']}),
		({'a': 'alpha', 'b': 'beta'}, {'a': 'ALPHA', 'b': 'BETA'}, {'a': ['alpha', 'ALPHA'], 'b': ['beta', 'BETA']}),
		
		# Test 46-50: Different value types (numbers - int and float)
		({'x': 1}, {'x': 1.0}, {}),  # 1 == 1.0 in Python
		({'val': 5}, {'val': 5.5}, {'val': [5, 5.5]}),
		({'num': 0}, {'num': -0}, {}),  # 0 == -0
		({'price': 10.99}, {'price': 10.999}, {'price': [10.99, 10.999]}),
		({'a': 3.14}, {'a': 3.141}, {'a': [3.14, 3.141]}),
		
		# Test 51-55: Different value types (booleans)
		({'active': True}, {'active': False}, {'active': [True, False]}),
		({'flag1': True, 'flag2': False}, {'flag1': False, 'flag2': True}, {'flag1': [True, False], 'flag2': [False, True]}),
		({'enabled': True}, {'enabled': 1}, {}),  # True == 1 in Python
		({'disabled': False}, {'disabled': 0}, {}),  # False == 0 in Python
		({'bool_val': True}, {'bool_val': None}, {'bool_val': [True, None]}),
		
		# Test 56-60: Different value types (None)
		({'val': None}, {'val': 0}, {'val': [None, 0]}),
		({'x': None}, {'x': ''}, {'x': [None, '']}),
		({'y': None}, {'y': False}, {'y': [None, False]}),
		({'data': None}, {'data': []}, {'data': [None, []]}),
		({'info': None}, {'info': None}, {}),
		
		# Test 61-65: Lists as values
		({'items': [1, 2, 3]}, {'items': [1, 2, 3]}, {}),
		({'items': [1, 2, 3]}, {'items': [1, 2, 4]}, {'items': [[1, 2, 3], [1, 2, 4]]}),
		({'data': []}, {'data': [1]}, {'data': [[], [1]]}),
		({'nums': [1, 2]}, {'nums': [2, 1]}, {'nums': [[1, 2], [2, 1]]}),
		({'arr': [1, [2, 3]]}, {'arr': [1, [2, 4]]}, {'arr': [[1, [2, 3]], [1, [2, 4]]]}),
		
		# Test 66-70: Tuples as values
		({'point': (1, 2)}, {'point': (1, 2)}, {}),
		({'point': (1, 2)}, {'point': (1, 3)}, {'point': [(1, 2), (1, 3)]}),
		({'coords': (0, 0)}, {'coords': (0, 0, 0)}, {'coords': [(0, 0), (0, 0, 0)]}),
		({'tuple_val': ()}, {'tuple_val': (1,)}, {'tuple_val': [(), (1,)]}),
		({'nested': (1, (2, 3))}, {'nested': (1, (2, 4))}, {'nested': [(1, (2, 3)), (1, (2, 4))]}),
		
		# Test 71-75: Dictionaries as values (nested dicts)
		({'config': {'a': 1}}, {'config': {'a': 1}}, {}),
		({'config': {'a': 1}}, {'config': {'a': 2}}, {'config': [{'a': 1}, {'a': 2}]}),
		({'settings': {'x': 10, 'y': 20}}, {'settings': {'x': 10, 'y': 30}}, {'settings': [{'x': 10, 'y': 20}, {'x': 10, 'y': 30}]}),
		({'data': {}}, {'data': {'key': 'value'}}, {'data': [{}, {'key': 'value'}]}),
		({'nested': {'inner': {'deep': 1}}}, {'nested': {'inner': {'deep': 2}}}, {'nested': [{'inner': {'deep': 1}}, {'inner': {'deep': 2}}]}),
		
		# Test 76-80: Large dictionaries and stress tests
		({str(i): i for i in range(10)}, {str(i): i for i in range(10)}, {}),
		({str(i): i for i in range(10)}, {str(i): i+1 for i in range(10)}, {str(i): [i, i+1] for i in range(10)}),
		({f'key_{i}': i for i in range(5)}, {f'key_{i}': i*2 for i in range(5)}, {f'key_{i}': [i, i*2] for i in range(1, 5)}),  # Fixed: excludes key_0 where 0*2=0
		({'a': 1, 'b': 2, 'c': 3, 'd': 4, 'e': 5, 'f': 6, 'g': 7, 'h': 8}, {'a': 1, 'b': 2, 'c': 3, 'd': 4, 'i': 9, 'j': 10, 'k': 11, 'l': 12}, {'e': [5, None], 'f': [6, None], 'g': [7, None], 'h': [8, None], 'i': [None, 9], 'j': [None, 10], 'k': [None, 11], 'l': [None, 12]}),
		({chr(65+i): i for i in range(26)}, {chr(65+i): i*2 for i in range(26)}, {chr(65+i): [i, i*2] for i in range(1, 26)}),  # Fixed: excludes 'A' where 0*2=0
	]
	
	passed = 0
	failed = 0
	
	for i, (first, second, expected) in enumerate(test_cases, 1):
		try:
			result = dictdiff(first, second)
			if result == expected:
				passed += 1
				print(f"✓ Test {i} passed")
			else:
				failed += 1
				print(f"✗ Test {i} failed")
				print(f"  Input: dictdiff({first}, {second})")
				print(f"  Expected: {expected}")
				print(f"  Got: {result}")
		except Exception as e:
			failed += 1
			print(f"✗ Test {i} raised exception: {e}")
			print(f"  Input: dictdiff({first}, {second})")
	
	print(f"\n{'='*60}")
	print(f"Results: {passed} passed, {failed} failed out of {len(test_cases)} tests")
	print(f"{'='*60}")
	
	return passed == len(test_cases)


if __name__ == '__main__':
	test_dictdiff()
