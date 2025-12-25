def mysum(*args):
	if len(args) == 0:
		return None

	result = args[0]

	for arg in args[1:]:
		result += arg

	return result

print(mysum([1,2,3],[4,5,6]))
	
