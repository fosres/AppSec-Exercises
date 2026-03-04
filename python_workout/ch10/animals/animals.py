import json

class Animals:

	def __init__(self,species,legs,color):

		self.species = species

		self.legs = legs

		self.color = color

	def __repr__(self):

		table = {}

		table["species"] = self.species

		table["legs"] = self.legs

		table["color"] = self.color

		json_struct = json.dumps(table,indent=4)

		return f"{json_struct}"

if __name__=="__main__":

	animal = Animals("cat",4,"tabby")

	print(animal)

	
