def rainfall():
	rainfall_map = {}

	user_input = input("")

	i = 0

	city = ""

	while user_input != "":
		
		if i % 2 == 0 and user_input not in rainfall_map:
			
			rainfall_map.update({user_input : 0})
			
			city = user_input

		elif i % 2 != 0:
			
			try:
				rainfall_map[city] += int(user_input)

				city = ""

			except ValueError:

				print("Failed to convert rainfall amount to int. Try again")
				user_input = input("")

				continue
		
		i += 1
		
		user_input = input("")

	for city, rainfall in rainfall_map.items():
		print(f"{city}: {rainfall}")

def main():
	rainfall()

if __name__ == "__main__":
	main()
