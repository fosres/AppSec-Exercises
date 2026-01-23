def flip_dict(table: dict) -> dict:

	return { val : key for key,val in table.items()}

print(flip_dict({1 : 2, 3 : 4}))
