def flatten(lst: list[list[int]]):

	return [x for ls in lst for x in ls]

print(flatten([[1,2],[3,4]]))
