from animals import Animals

class Wolf(Animals):

	def __init__(self,color):

		super().__init__("wolf",4,color)

	def __repr__(self):

		table = {}

		table["species"] = self.species

		table["legs"] = self.legs

		table["color"] = self.color

		return f"{table}"

if __name__=="__main__":

	wolf = Wolf("gray")

	print(wolf)
