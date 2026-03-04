from scoop import Scoop

class Bowl:

	def __init__(self):

		self.bowl = []

		self.maxsize = 3

	def add_scoops(self,*args):

		for arg in args:

			if len(self.bowl) == self.maxsize:

				return

			self.bowl.append(arg)


if __name__=="__main__":
	
	first_scoop = Scoop("butterfinger")

	second_scoop = Scoop("cookie dough")

	third_scoop = Scoop("strawberry")
	
	fourth_scoop = Scoop("mint chip")

	bowl = Bowl()

	bowl.add_scoops(first_scoop,second_scoop,third_scoop,fourth_scoop)

	for scoop in bowl.bowl:

		print(f"{scoop.flavor}")
