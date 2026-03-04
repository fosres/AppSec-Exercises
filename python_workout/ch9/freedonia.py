import logging

def calculate_tax(charge: int,city: str,hour: int):

	if not isinstance(charge,int):

		raise Exception("Invalid value for charge")
	
	if not isinstance(city,str):

		raise Exception("Invalid value for city")
	
	if not isinstance(hour,int):

		raise Exception("Invalid value for hour")

	city_tax = 0

	if city == 'Chico':

		city_tax = 0.5		

	elif city == 'Groucho':
		
		city_tax = 0.7

	elif city == 'Harpo':
		
		city_tax = 0.5

	elif city == 'Zeppo':
		
		city_tax = 0.4

	else:

		raise Exception("Invalid city")

	if hour < 0 or hour > 24:

		raise Exception("hour is invalid")	
		

	return charge * city_tax * (hour / 24.0) + charge

