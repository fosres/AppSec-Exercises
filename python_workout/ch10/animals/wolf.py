from animals import Animals

class Wolf(Animals):

	def __init__(self,color):

		super().__init__("wolf",4,color)


if __name__=="__main__":

	wolf = Wolf("gray")

	print(wolf)
