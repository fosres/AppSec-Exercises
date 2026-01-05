import sys

def main():

	if len(sys.argv) != 2:

		print("Error: Improper args. Aborting.")

		exit(1)

	with open(sys.argv[1],'r') as file:

		for line in file:

			print(line[::-1].strip())

if __name__=="__main__":
	main()
