from animals import Animals

class Parrot(Animals):

	def __init__(self,color):

		super().__init__("parrot",2,color)


if __name__=="__main__":

	parrot = Parrot("red")

	print(parrot)
