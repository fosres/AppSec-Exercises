from scoop import Scoop
from bowl import Bowl

class BigBowl(Bowl):

	def __init__(self):

		super().__init__()

		self.maxsize = 5

if __name__=="__main__":

	first_scoop = Scoop("cookie dough")

	second_scoop = Scoop("butterfinger")

	third_scoop = Scoop("strawberry")
	
	fourth_scoop = Scoop("mint chip")
	
	fifth_scoop = Scoop("peanut butter")
	
	sixth_scoop = Scoop("matcha")

	big_bowl = BigBowl()

	big_bowl.add_scoops(first_scoop,second_scoop,third_scoop,fourth_scoop,fifth_scoop,sixth_scoop)

	for scoop in big_bowl.bowl:

		print(f"{scoop.flavor}")
	
