def sum_numbers(string: str):

	return sum([int(x) for x in string.split() if x.isdigit()]) 

print(sum_numbers("10 abc 20 de44 30 55fg 40"))
