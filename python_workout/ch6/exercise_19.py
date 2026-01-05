import sys

def main():
	
	table = {}

	if len(sys.argv) != 2:

		print("Error: Improper number of arguments. Aborting")

		exit(1)

	try:
		file = open(sys.argv[1],'r')
	
	except FileNotFoundError:
		
		print(f"Error: File {sys.argv[1]} not found\nAborting.")

		exit(2)

	for line in file:

		if line.strip()[0] == '#':

			continue

		lst = line.split(":")

		table[lst[0]] = lst[2]

	file.close()

	print(table)

if __name__ == "__main__":
	main()

