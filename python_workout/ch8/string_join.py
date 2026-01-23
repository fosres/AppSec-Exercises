def join_numbers(lst: list[int]) -> str:

	return ",".join(str(x) for x in lst)

print(join_numbers([10,20,30]))
