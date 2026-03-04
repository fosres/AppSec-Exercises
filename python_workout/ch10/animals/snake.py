from animals import Animals

class Snake(Animals):

	def __init__(self,color):

		super().__init__("snake",0,color)


if __name__=="__main__":

	snake = Snake("green")

	print(snake)
