def firstlast(lst: list):

	if len(lst) < 2:
		raise ValueError("List too small. Aborting.")

	return lst[0:1] + lst[-1:]

print(firstlast("string"))
