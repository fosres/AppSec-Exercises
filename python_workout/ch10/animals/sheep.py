from animals import Animals

class Sheep(Animals):

	def __init__(self,color):

		super().__init__("sheep",4,color)


if __name__=="__main__":

	sheep = Sheep("gray")

	print(sheep)
