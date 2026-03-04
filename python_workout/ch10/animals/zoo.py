import json

from animals import Animals
from sheep import Sheep
from wolf import Wolf
from parrot import Parrot
from snake import Snake
from cage import Cage

class Zoo:

	def __init__(self):

		self.cage_lst = []

	def add_cages(self,*args):

		for arg in args:

			self.cage_lst.append(arg)

	def animals_by_color(self,color: str):
			
		same_color_lst = []

		for cage in self.cage_lst:

			animal_lst = cage.lst

			for animal in animal_lst:

				if animal.color == color:

					same_color_lst.append(animal)

		return same_color_lst

	
	def animals_by_legs(self,legs: int):
			
		same_legs_lst = []

		for cage in self.cage_lst:

			animal_lst = cage.lst

			for animal in animal_lst:

				if animal.legs == legs:

					same_legs_lst.append(animal)

		return same_legs_lst

	
	def animals_by_legs(self,legs: int):
			
		same_legs_lst = []

		for cage in self.cage_lst:

			animal_lst = cage.lst

			for animal in animal_lst:

				if animal.legs == legs:

					same_legs_lst.append(animal)

		return same_legs_lst

	def number_of_legs(self):

		num_legs = 0

		for cage in self.cage_lst:

			animal_lst = cage.lst

			for animal in animal_lst:

				num_legs += animal.legs

		return num_legs	

				

	def __repr__(self):

		zoo_str = ""

		for cage in self.cage_lst:

			# zoo_str += f"{cage}\n\n"
			
			zoo_str += f"{cage}" + "\n\n"

		return zoo_str

if __name__=="__main__":

	wolf = Wolf("black")

	sheep = Sheep("light brown")

	snake = Snake("black")

	parrot = Parrot("red")

	cage1 = Cage(1)

	cage1.add_animals(wolf,sheep)

	cage2 = Cage(2)

	cage2.add_animals(snake,parrot)

	z = Zoo()

	z.add_cages(cage1,cage2)

	print(z)

	# print(z.animals_by_color("black"))
	
	# print(z.animals_by_legs(4))
	
	print(z.number_of_legs())

