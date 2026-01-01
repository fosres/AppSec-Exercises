def restaurant():
	
	MENU = {
		"sandwich" : 10,

		"soup" : 8,

		"curry" : 20,

		"burger" : 15,

		"burrito": 8,

		"wings": 9,

		"fried chicken" : 10,

		"sushi" : 10,

		"smoked salmon" : 20,

		"lobster" : 50,

		"pizza" : 6
	}

	total_charge = 0

	user_input = input("Order: ").strip()

	while user_input != "":
		
		if user_input in MENU:	
			total_charge += MENU[user_input]

			print(f"{user_input} costs {MENU[user_input]},total is {total_charge}")

		elif user_input not in MENU:

			print(f"Sorry we do not serve {user_input}.")

			print("\nPlease make a valid order.")

		user_input = input("Order: ").strip()

	print(f"Your total is {total_charge}")

def main():
	restaurant()

if __name__ == "__main__":
	main()	
