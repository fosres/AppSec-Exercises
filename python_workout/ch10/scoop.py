class Scoop:

	def __init__(self,flavor: str):

		self.flavor = flavor[:]

	def __repr__(self):

		return f"{self.flavor}"

def create_scoops():

	choco = Scoop("chocolate")

	vanilla = Scoop("vanilla")

	persimmon = Scoop("persimmon")

	return [choco,vanilla,persimmon]

if __name__=="__main__":

	scoops = create_scoops()

	print(scoops)

	for scoop in scoops:

		print(f"flavor: {scoop.flavor}")

		
