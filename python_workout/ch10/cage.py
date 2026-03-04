from animals import Animals
from sheep import Sheep
from wolf import Wolf
from parrot import Parrot
from snake import Snake

class Cage:

	def __init__(self,id_num: int):

		self.id = id_num

		self.lst = []

	def add_animals(self,*args):

		for arg in args:

			self.lst.append(arg)

	def __repr__(self):

		table = {}

		table["id"] = self.id

		table["animal_list"] = self.lst

		return f"{table}"

if __name__=="__main__":

	wolf = Wolf("black")

	sheep = Sheep("light brown")

	cage1 = Cage(1)

	cage1.add_animals(wolf,sheep)

	print(cage1)
