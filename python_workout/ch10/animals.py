class Animals:

	def __init__(self,species,legs,color):

		self.species = species

		self.legs = legs

		self.color = color

	def __repr__(self):

		return f"{self.species},{self.legs},{self.color}"

if __name__=="__main__":

	animal = Animals("cat",4,"tabby")

	print(animal)

	
